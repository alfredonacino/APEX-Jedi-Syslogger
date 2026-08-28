#!/usr/bin/env node
/*
 * auth.js — password + TOTP two-factor authentication for the backend.
 *
 * Zero dependencies, like the rest of the project: password hashing is Node's
 * scrypt, the second factor is RFC 6238 TOTP built on core `crypto`. Anything an
 * authenticator app can scan (Google Authenticator, Aegis, 1Password, Bitwarden)
 * works, because the shared secret is plain Base32 in an otpauth:// URI.
 *
 * Multi-user: auth.json next to this file (mode 0600, gitignored) holds every
 * account — credentials, its own TOTP secret, a role, and that user's saved Log
 * Collector settings, so a session resumes where the last one left off and two
 * people testing at once never collide. Created on first start with the
 * documented default admin; a v1 single-user file is migrated in place on load.
 *
 * Sessions are in memory: a restart signs everyone out, which is the safer
 * default for a tool with no session store to keep consistent.
 */
'use strict';
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const STORE = path.join(__dirname, 'auth.json');

// Documented defaults — README §Signing in and DOCUMENTATION.md §11 repeat these
// verbatim. Change them together if they ever change.
const DEFAULT_USER = 'admin';
const DEFAULT_PASSWORD = 'APEXjedi2026!';

const ISSUER = 'APEX JediSyslogger';
const STORE_VERSION = 2;
const HISTORY_MAX = 12;   // most recently used first; older receivers fall off
const SESSION_TTL_MS = 8 * 60 * 60 * 1000;   // 8 hours
const PENDING_TTL_MS = 3 * 60 * 1000;        // password step → code step
const MAX_FAILS = 5;
const LOCKOUT_MS = 5 * 60 * 1000;
const COOKIE = 'jedi_sid';

// ---- Credential store ------------------------------------------------------

function hashPassword(password, salt) {
  const s = salt || crypto.randomBytes(16).toString('hex');
  // N=16384 is scrypt's default cost: ~100 ms here, and the login path is not hot.
  return { salt: s, hash: crypto.scryptSync(password, s, 64).toString('hex') };
}

// Every account carries its own second factor and its own collector.
function newUser(name, password, role) {
  const { salt, hash } = hashPassword(password || DEFAULT_PASSWORD);
  return {
    id: crypto.randomBytes(8).toString('hex'),
    user: name,
    role: role === 'admin' ? 'admin' : 'user',
    salt,
    hash,
    // 20 random bytes = 160 bits, what RFC 4226 recommends for a TOTP secret.
    totpSecret: base32Encode(crypto.randomBytes(20)),
    totpConfirmed: false,   // flips once a code from the enrolled app verifies
    lastTotpStep: 0,        // replay guard: a code is good for one login only
    passwordIsDefault: !password,
    created: new Date().toISOString(),
    collector: defaultCollector(),
    collectorHistory: [],
  };
}

function defaultCollector() {
  return {
    ip: '10.0.0.100', port: 514, proto: 'udp',
    hec: { token: '', index: '', sourcetype: 'syslog', ssl: true, insecure: true },
  };
}

function newStore() {
  return { version: STORE_VERSION, users: [newUser(DEFAULT_USER, null, 'admin')] };
}

// A v1 file is one flat user object. Carry it over whole — the password hash and
// an already-enrolled TOTP secret have to survive, or upgrading would lock the
// only account out of its own install.
function migrate(raw) {
  if (raw && Array.isArray(raw.users)) return raw;
  if (raw && raw.user && raw.hash && raw.totpSecret) {
    console.log('  ⟲ auth.json: migrating the single-user file to the multi-user format');
    const carried = newUser(raw.user, 'placeholder', 'admin');
    return { version: STORE_VERSION, users: [Object.assign(carried, raw, { id: carried.id, role: 'admin' })] };
  }
  return null;
}

function load() {
  let raw = null, rawText = null;
  try {
    rawText = fs.readFileSync(STORE, 'utf8');
    raw = JSON.parse(rawText);
  } catch (e) {
    if (e.code !== 'ENOENT') console.log(`  ⚠ auth.json unreadable (${e.code || e.message}) — recreating it`);
  }
  const store = migrate(raw);
  if (!store) {
    if (raw) console.log('  ⚠ auth.json is incomplete — recreating it with the defaults');
    const fresh = newStore();
    save(fresh);
    return fresh;
  }
  // Backfill anything an older file predates, then persist the upgrade.
  store.version = STORE_VERSION;
  for (const u of store.users) {
    if (!u.id) u.id = crypto.randomBytes(8).toString('hex');
    if (!u.role) u.role = 'admin';
    if (!u.collector) u.collector = defaultCollector();
    if (!Array.isArray(u.collectorHistory)) u.collectorHistory = [];
  }
  // Compare against the text that was read, not against `raw` — for a file that
  // is already current, migrate() hands back that same object, so comparing the
  // two would compare it with itself and a backfill would never reach disk.
  if (serialise(store) !== rawText) save(store);
  return store;
}

const serialise = (store) => JSON.stringify(store, null, 2) + '\n';

function save(store) {
  fs.writeFileSync(STORE, serialise(store), { mode: 0o600 });
  try { fs.chmodSync(STORE, 0o600); } catch (e) {}   // enforce it on an existing file
}

// ---- Base32 (RFC 4648) — what authenticator apps expect the secret in -------

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Encode(buf) {
  let bits = 0, value = 0, out = '';
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) { out += B32[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}

function base32Decode(str) {
  let bits = 0, value = 0;
  const out = [];
  for (const c of String(str).replace(/[\s=-]/g, '').toUpperCase()) {
    const idx = B32.indexOf(c);
    if (idx < 0) throw new Error(`invalid Base32 character "${c}" in the TOTP secret`);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 255); bits -= 8; }
  }
  return Buffer.from(out);
}

// ---- TOTP (RFC 6238: HMAC-SHA1, 6 digits, 30-second step) ------------------

function totpAt(secret, step) {
  const counter = Buffer.alloc(8);
  counter.writeUInt32BE(Math.floor(step / 0x100000000), 0);
  counter.writeUInt32BE(step % 0x100000000, 4);
  const mac = crypto.createHmac('sha1', base32Decode(secret)).update(counter).digest();
  const off = mac[mac.length - 1] & 0x0f;   // dynamic truncation
  const bin = ((mac[off] & 0x7f) << 24) | (mac[off + 1] << 16) | (mac[off + 2] << 8) | mac[off + 3];
  return String(bin % 1000000).padStart(6, '0');
}

function currentStep(now) { return Math.floor((now || Date.now()) / 1000 / 30); }

// Accept the neighbouring steps too: phone clocks drift, and a code typed at
// second 29 would otherwise be rejected the moment it is submitted.
function totpMatches(secret, code, step) {
  const given = String(code || '').replace(/\D/g, '');
  if (given.length !== 6) return null;
  for (let d = -1; d <= 1; d++) {
    const expected = totpAt(secret, step + d);
    // Both are 6 ASCII digits, so the lengths always match here.
    if (crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(given))) return step + d;
  }
  return null;
}

// algorithm=SHA1, digits=6 and period=30 are the Key Uri Format's defaults, so
// spelling them out only makes the QR a version larger — and a larger symbol at
// the same size on screen is a harder one to scan.
function otpauthUri(u) {
  const label = encodeURIComponent(`${ISSUER}:${u.user}`);
  return `otpauth://totp/${label}?secret=${u.totpSecret}&issuer=${encodeURIComponent(ISSUER)}`;
}

// Grouped in fours — the shape every authenticator's manual-entry field expects.
function prettySecret(secret) { return secret.replace(/(.{4})/g, '$1 ').trim(); }

// ---- Sessions, pending logins, lockout -------------------------------------

const sessions = new Map();   // sid   → { userId, expires }
const pending = new Map();    // token → { userId, user, expires }
const fails = new Map();      // username → { count, until }

function sweep(map, now) {
  for (const [k, v] of map) if (v.expires <= now) map.delete(k);
}

function newToken() { return crypto.randomBytes(32).toString('hex'); }

function lockoutLeft(user, now) {
  const f = fails.get(user);
  if (!f || !f.until || f.until <= now) return 0;
  return Math.ceil((f.until - now) / 1000);
}

function noteFailure(user, now) {
  const f = fails.get(user) || { count: 0, until: 0 };
  f.count++;
  if (f.count >= MAX_FAILS) { f.until = now + LOCKOUT_MS; f.count = 0; }
  fails.set(user, f);
}

function clearFailures(user) { fails.delete(user); }

// ---- Public API used by server.js ------------------------------------------

const USERNAME_RE = /^[a-z0-9][a-z0-9._-]{2,31}$/i;
const MIN_PASSWORD = 8;

// What a caller outside this module is allowed to see about an account: never
// the hash, the salt, or the TOTP secret.
function publicUser(u) {
  return {
    id: u.id,
    user: u.user,
    role: u.role,
    totpConfirmed: !!u.totpConfirmed,
    passwordIsDefault: !!u.passwordIsDefault,
    created: u.created,
  };
}

// Accept only what the collector panel can actually use, and coerce it — this
// comes straight off the wire.
function cleanCollector(raw) {
  const c = raw || {};
  const hec = c.hec || {};
  const port = parseInt(c.port, 10);
  const proto = String(c.proto || 'udp').toLowerCase();
  return {
    ip: String(c.ip || '').trim().slice(0, 253),
    port: port > 0 && port < 65536 ? port : 514,
    proto: ['udp', 'tcp', 'hec'].includes(proto) ? proto : 'udp',
    hec: {
      token: String(hec.token || '').trim().slice(0, 256),
      index: String(hec.index || '').trim().slice(0, 128),
      sourcetype: String(hec.sourcetype || 'syslog').trim().slice(0, 128) || 'syslog',
      ssl: hec.ssl !== false,
      insecure: hec.insecure !== false,
    },
  };
}

class Auth {
  constructor(enabled) {
    this.enabled = enabled !== false;
    this.store = this.enabled ? load() : null;
  }

  get users() { return this.store ? this.store.users : []; }
  byId(id) { return this.users.find((u) => u.id === id) || null; }
  byName(name) { return this.users.find((u) => u.user.toLowerCase() === String(name || '').toLowerCase()) || null; }
  admins() { return this.users.filter((u) => u.role === 'admin'); }
  list() { return this.users.map(publicUser); }

  enrolmentFor(u) {
    return { secret: u.totpSecret, pretty: prettySecret(u.totpSecret), uri: otpauthUri(u) };
  }

  // Step 1 — username + password. Returns what the client must do next.
  login(username, password) {
    const now = Date.now();
    sweep(pending, now);
    const name = String(username || '').trim();
    const left = lockoutLeft(name.toLowerCase(), now);
    if (left) return { ok: false, locked: true, retryAfter: left, error: `Too many failed attempts — locked for ${left}s` };

    const u = this.byName(name);
    // Hash against a decoy salt for an unknown user so a wrong name and a wrong
    // password cost the same time, and answer both with one message.
    const salt = u ? u.salt : 'unknown-user-constant-salt';
    const given = hashPassword(String(password || ''), salt);
    const target = u ? u.hash : given.hash.replace(/./g, '0');
    const passOk = u != null &&
      crypto.timingSafeEqual(Buffer.from(given.hash, 'hex'), Buffer.from(target, 'hex'));
    if (!passOk) {
      noteFailure(name.toLowerCase(), now);
      return { ok: false, error: 'Invalid username or password' };
    }

    const token = newToken();
    pending.set(token, { userId: u.id, user: u.user, expires: now + PENDING_TTL_MS });
    return u.totpConfirmed
      ? { ok: true, stage: 'totp', pending: token }
      : Object.assign({ ok: true, stage: 'enrol', pending: token }, this.enrolmentFor(u));
  }

  // Step 2 — the six-digit code. On the first success the enrolment is sealed.
  verifyTotp(token, code) {
    const now = Date.now();
    sweep(pending, now);
    const p = pending.get(token);
    if (!p) return { ok: false, expired: true, error: 'Sign-in timed out — start again' };
    const u = this.byId(p.userId);
    if (!u) { pending.delete(token); return { ok: false, expired: true, error: 'That account no longer exists' }; }
    const left = lockoutLeft(u.user.toLowerCase(), now);
    if (left) return { ok: false, locked: true, retryAfter: left, error: `Too many failed attempts — locked for ${left}s` };

    const step = totpMatches(u.totpSecret, code, currentStep(now));
    if (step == null) {
      noteFailure(u.user.toLowerCase(), now);
      return { ok: false, error: 'That code is not valid right now' };
    }
    // A code is single-use: replaying one from the same 30-second step is not a
    // second factor, it is a copied string.
    if (step <= u.lastTotpStep) return { ok: false, error: 'That code was already used — wait for the next one' };

    pending.delete(token);
    clearFailures(u.user.toLowerCase());
    u.lastTotpStep = step;
    if (!u.totpConfirmed) u.totpConfirmed = true;
    save(this.store);

    const sid = newToken();
    sessions.set(sid, { userId: u.id, expires: now + SESSION_TTL_MS });
    return { ok: true, sid, user: u.user, role: u.role, expires: now + SESSION_TTL_MS };
  }

  sessionFor(cookieHeader) {
    if (!this.enabled) return { user: null, anonymous: true };
    const now = Date.now();
    sweep(sessions, now);
    const sid = readCookie(cookieHeader, COOKIE);
    if (!sid) return null;
    const s = sessions.get(sid);
    if (!s) return null;
    const u = this.byId(s.userId);
    // The account was deleted mid-session; the cookie is worthless now.
    if (!u) { sessions.delete(sid); return null; }
    return { sid, account: u, userId: u.id, user: u.user, role: u.role, expires: s.expires };
  }

  logout(cookieHeader) {
    const sid = readCookie(cookieHeader, COOKIE);
    if (sid) sessions.delete(sid);
  }

  // Drop every live session for one account — after a password change, a role
  // change, or a deletion, the old cookie must stop working.
  revokeSessionsFor(userId, keepSid) {
    for (const [sid, s] of sessions) if (s.userId === userId && sid !== keepSid) sessions.delete(sid);
    for (const [tok, p] of pending) if (p.userId === userId) pending.delete(tok);
  }

  // ---- User management (admin) ---------------------------------------------

  createUser(name, password, role) {
    const clean = String(name || '').trim();
    if (!USERNAME_RE.test(clean)) {
      return { ok: false, error: 'Username must be 3–32 characters: letters, digits, dot, dash or underscore' };
    }
    if (this.byName(clean)) return { ok: false, error: `"${clean}" already exists` };
    if (String(password || '').length < MIN_PASSWORD) {
      return { ok: false, error: `Password must be at least ${MIN_PASSWORD} characters` };
    }
    const u = newUser(clean, String(password), role);
    this.store.users.push(u);
    save(this.store);
    return { ok: true, user: publicUser(u) };
  }

  deleteUser(id, actingId) {
    const u = this.byId(id);
    if (!u) return { ok: false, error: 'No such user' };
    if (u.id === actingId) return { ok: false, error: 'You cannot delete the account you are signed in as' };
    if (u.role === 'admin' && this.admins().length === 1) {
      return { ok: false, error: 'That is the only admin — promote someone else first' };
    }
    this.store.users = this.store.users.filter((x) => x.id !== id);
    save(this.store);
    this.revokeSessionsFor(id);
    return { ok: true };
  }

  setRole(id, role, actingId) {
    const u = this.byId(id);
    if (!u) return { ok: false, error: 'No such user' };
    const next = role === 'admin' ? 'admin' : 'user';
    if (u.role === 'admin' && next !== 'admin' && this.admins().length === 1) {
      return { ok: false, error: 'That is the only admin — promote someone else first' };
    }
    if (u.id === actingId && next !== 'admin') {
      return { ok: false, error: 'You cannot remove your own admin rights' };
    }
    u.role = next;
    save(this.store);
    return { ok: true, user: publicUser(u) };
  }

  // Used by an admin resetting someone else, and by the CLI.
  setPassword(id, password) {
    const u = this.byId(id);
    if (!u) return { ok: false, error: 'No such user' };
    if (String(password || '').length < MIN_PASSWORD) {
      return { ok: false, error: `Password must be at least ${MIN_PASSWORD} characters` };
    }
    Object.assign(u, hashPassword(String(password)), { passwordIsDefault: false });
    save(this.store);
    this.revokeSessionsFor(id);
    return { ok: true };
  }

  // Does this password belong to this account? Used to re-confirm before a change
  // that a borrowed session should not be able to make on its own.
  verifyPassword(id, password) {
    const u = this.byId(id);
    if (!u) return false;
    const given = hashPassword(String(password || ''), u.salt);
    return crypto.timingSafeEqual(Buffer.from(given.hash, 'hex'), Buffer.from(u.hash, 'hex'));
  }

  // Changing your own password means proving you know the current one — a stolen
  // session should not be able to lock the owner out of their own account.
  changeOwnPassword(id, current, next, keepSid) {
    const u = this.byId(id);
    if (!u) return { ok: false, error: 'No such user' };
    if (!this.verifyPassword(id, current)) {
      return { ok: false, error: 'That is not your current password' };
    }
    if (String(next || '').length < MIN_PASSWORD) {
      return { ok: false, error: `Password must be at least ${MIN_PASSWORD} characters` };
    }
    Object.assign(u, hashPassword(String(next)), { passwordIsDefault: false });
    save(this.store);
    // Every other session for this account dies; the one doing the change stays.
    this.revokeSessionsFor(id, keepSid);
    return { ok: true };
  }

  // Re-enrol: a new secret, unconfirmed, so the next sign-in shows the QR again.
  resetTotp(id) {
    const u = this.byId(id);
    if (!u) return { ok: false, error: 'No such user' };
    Object.assign(u, {
      totpSecret: base32Encode(crypto.randomBytes(20)),
      totpConfirmed: false,
      lastTotpStep: 0,
    });
    save(this.store);
    return Object.assign({ ok: true }, this.enrolmentFor(u));
  }

  // ---- Per-user Log Collector ----------------------------------------------

  getCollector(id) {
    const u = this.byId(id);
    return u ? (u.collector || defaultCollector()) : defaultCollector();
  }

  setCollector(id, cfg) {
    const u = this.byId(id);
    if (!u) return { ok: false, error: 'No such user' };
    u.collector = cleanCollector(cfg);
    save(this.store);
    return { ok: true, collector: u.collector };
  }

  // ---- Collector history ---------------------------------------------------
  // The receivers this user has actually used, most recent first, so a past
  // destination can be picked back up without retyping it.

  getHistory(id) {
    const u = this.byId(id);
    return u && Array.isArray(u.collectorHistory) ? u.collectorHistory : [];
  }

  // One entry per destination: setting the same host/port/protocol again updates
  // that entry (a re-issued HEC token, a new index) instead of piling up copies.
  rememberCollector(id, cfg) {
    const u = this.byId(id);
    if (!u) return { ok: false, error: 'No such user' };
    const c = cleanCollector(cfg);
    if (!c.ip) return { ok: false, error: 'Set a collector address first' };
    const key = `${c.proto}://${c.ip}:${c.port}`;
    const now = new Date().toISOString();
    const list = Array.isArray(u.collectorHistory) ? u.collectorHistory : [];
    const found = list.find((e) => e.key === key);
    const entry = Object.assign({}, c, {
      key,
      id: found ? found.id : crypto.randomBytes(6).toString('hex'),
      firstUsed: found ? found.firstUsed : now,
      lastUsed: now,
      uses: (found ? found.uses : 0) + 1,
    });
    u.collectorHistory = [entry].concat(list.filter((e) => e.key !== key)).slice(0, HISTORY_MAX);
    save(this.store);
    return { ok: true, history: u.collectorHistory };
  }

  forgetCollector(id, entryId) {
    const u = this.byId(id);
    if (!u) return { ok: false, error: 'No such user' };
    const list = Array.isArray(u.collectorHistory) ? u.collectorHistory : [];
    if (!list.some((e) => e.id === entryId)) return { ok: false, error: 'No such entry' };
    u.collectorHistory = list.filter((e) => e.id !== entryId);
    save(this.store);
    return { ok: true, history: u.collectorHistory };
  }

  clearHistory(id) {
    const u = this.byId(id);
    if (!u) return { ok: false, error: 'No such user' };
    u.collectorHistory = [];
    save(this.store);
    return { ok: true, history: [] };
  }
}

// `Set-Cookie` without Secure: the app is plain HTTP by default, and a Secure
// cookie would simply never be stored. Behind a TLS proxy, set JEDI_SECURE_COOKIE=1.
function sessionCookie(sid, secure) {
  const bits = [`${COOKIE}=${sid}`, 'HttpOnly', 'SameSite=Strict', 'Path=/', `Max-Age=${SESSION_TTL_MS / 1000}`];
  if (secure) bits.push('Secure');
  return bits.join('; ');
}

function clearCookie() { return `${COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0`; }

function readCookie(header, name) {
  if (!header) return null;
  for (const part of String(header).split(';')) {
    const eq = part.indexOf('=');
    if (eq < 0) continue;
    if (part.slice(0, eq).trim() === name) return part.slice(eq + 1).trim();
  }
  return null;
}

module.exports = {
  Auth, sessionCookie, clearCookie, readCookie, otpauthUri, prettySecret, publicUser,
  defaultCollector, cleanCollector,
  DEFAULT_USER, DEFAULT_PASSWORD, MIN_PASSWORD, STORE, ISSUER, HISTORY_MAX,
  // exported for the self-test in `node auth.js --selftest`
  base32Encode, base32Decode, totpAt, currentStep,
};

// ---- Self-test -------------------------------------------------------------
// `node auth.js --selftest` checks the Base32 and TOTP primitives against the
// vectors in RFC 4648 and RFC 6238, so a refactor here cannot silently start
// producing codes no authenticator agrees with.
if (require.main === module && process.argv.includes('--selftest')) {
  let failed = 0;
  const eq = (label, got, want) => {
    const ok = got === want;
    if (!ok) failed++;
    console.log(`${ok ? '  ✓' : '  ✗'} ${label}${ok ? '' : `  got ${got}, want ${want}`}`);
  };

  console.log('\n  Base32 (RFC 4648 §10)');
  [['', ''], ['f', 'MY'], ['fo', 'MZXQ'], ['foo', 'MZXW6'], ['foob', 'MZXW6YQ'],
    ['fooba', 'MZXW6YTB'], ['foobar', 'MZXW6YTBOI']].forEach(([plain, b32]) => {
    eq(`encode("${plain}")`, base32Encode(Buffer.from(plain)), b32);
    eq(`decode("${b32}")`, base32Decode(b32).toString(), plain);
  });

  console.log('\n  TOTP (RFC 6238 test vectors, SHA-1 / 6 digits)');
  // The RFC's seed is the ASCII "12345678901234567890".
  const seed = base32Encode(Buffer.from('12345678901234567890'));
  [{ t: 59, want: '287082' }, { t: 1111111109, want: '081804' }, { t: 1111111111, want: '050471' },
    { t: 1234567890, want: '005924' }, { t: 2000000000, want: '279037' },
    { t: 20000000000, want: '353130' }].forEach(({ t, want }) => {
    eq(`T=${t}`, totpAt(seed, Math.floor(t / 30)), want);
  });

  console.log(failed ? `\n  ${failed} check(s) FAILED\n` : '\n  all checks passed\n');
  process.exit(failed ? 1 : 0);
}
