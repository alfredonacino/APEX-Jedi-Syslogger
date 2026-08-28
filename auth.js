#!/usr/bin/env node
/*
 * auth.js — password + TOTP two-factor authentication for the backend.
 *
 * Zero dependencies, like the rest of the project: password hashing is Node's
 * scrypt, the second factor is RFC 6238 TOTP built on core `crypto`. Anything an
 * authenticator app can scan (Google Authenticator, Aegis, 1Password, Bitwarden)
 * works, because the shared secret is plain Base32 in an otpauth:// URI.
 *
 * Credentials live in auth.json next to this file (mode 0600, gitignored). It is
 * created on first start with the documented defaults; the console prints them,
 * plus the freshly generated TOTP secret to enrol.
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

function newStore(password) {
  const { salt, hash } = hashPassword(password || DEFAULT_PASSWORD);
  return {
    user: DEFAULT_USER,
    salt,
    hash,
    // 20 random bytes = 160 bits, what RFC 4226 recommends for a TOTP secret.
    totpSecret: base32Encode(crypto.randomBytes(20)),
    totpConfirmed: false,   // flips once a code from the enrolled app verifies
    lastTotpStep: 0,        // replay guard: a code is good for one login only
    passwordIsDefault: !password,
    created: new Date().toISOString(),
  };
}

function load() {
  try {
    const s = JSON.parse(fs.readFileSync(STORE, 'utf8'));
    if (s && s.user && s.hash && s.totpSecret) return s;
    console.log('  ⚠ auth.json is incomplete — recreating it with the defaults');
  } catch (e) {
    if (e.code !== 'ENOENT') console.log(`  ⚠ auth.json unreadable (${e.code || e.message}) — recreating it`);
  }
  const fresh = newStore(null);
  save(fresh);
  return fresh;
}

function save(store) {
  fs.writeFileSync(STORE, JSON.stringify(store, null, 2) + '\n', { mode: 0o600 });
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
function otpauthUri(store) {
  const label = encodeURIComponent(`${ISSUER}:${store.user}`);
  return `otpauth://totp/${label}?secret=${store.totpSecret}&issuer=${encodeURIComponent(ISSUER)}`;
}

// Grouped in fours — the shape every authenticator's manual-entry field expects.
function prettySecret(secret) { return secret.replace(/(.{4})/g, '$1 ').trim(); }

// ---- Sessions, pending logins, lockout -------------------------------------

const sessions = new Map();   // token → { user, expires }
const pending = new Map();    // token → { user, expires, enrolling }
const fails = new Map();      // user → { count, until }

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

class Auth {
  constructor(enabled) {
    this.enabled = enabled !== false;
    this.store = this.enabled ? load() : null;
  }

  get user() { return this.store ? this.store.user : null; }
  get passwordIsDefault() { return !!(this.store && this.store.passwordIsDefault); }
  get totpConfirmed() { return !!(this.store && this.store.totpConfirmed); }
  get enrolment() {
    return { secret: this.store.totpSecret, pretty: prettySecret(this.store.totpSecret), uri: otpauthUri(this.store) };
  }

  // Step 1 — username + password. Returns what the client must do next.
  login(username, password) {
    const now = Date.now();
    sweep(pending, now);
    const user = String(username || '').trim();
    const left = lockoutLeft(user, now);
    if (left) return { ok: false, locked: true, retryAfter: left, error: `Too many failed attempts — locked for ${left}s` };

    const s = this.store;
    const userOk = user.length === s.user.length &&
      crypto.timingSafeEqual(Buffer.from(user), Buffer.from(s.user));
    const given = hashPassword(String(password || ''), s.salt);
    const passOk = crypto.timingSafeEqual(Buffer.from(given.hash, 'hex'), Buffer.from(s.hash, 'hex'));
    if (!userOk || !passOk) {
      noteFailure(user, now);
      return { ok: false, error: 'Invalid username or password' };
    }

    const token = newToken();
    const enrolling = !s.totpConfirmed;
    pending.set(token, { user: s.user, expires: now + PENDING_TTL_MS, enrolling });
    return enrolling
      ? { ok: true, stage: 'enrol', pending: token, ...this.enrolment }
      : { ok: true, stage: 'totp', pending: token };
  }

  // Step 2 — the six-digit code. On the first success the enrolment is sealed.
  verifyTotp(token, code) {
    const now = Date.now();
    sweep(pending, now);
    const p = pending.get(token);
    if (!p) return { ok: false, expired: true, error: 'Sign-in timed out — start again' };
    const left = lockoutLeft(p.user, now);
    if (left) return { ok: false, locked: true, retryAfter: left, error: `Too many failed attempts — locked for ${left}s` };

    const s = this.store;
    const step = totpMatches(s.totpSecret, code, currentStep(now));
    if (step == null) {
      noteFailure(p.user, now);
      return { ok: false, error: 'That code is not valid right now' };
    }
    // A code is single-use: replaying one from the same 30-second step is not a
    // second factor, it is a copied string.
    if (step <= s.lastTotpStep) return { ok: false, error: 'That code was already used — wait for the next one' };

    pending.delete(token);
    clearFailures(p.user);
    s.lastTotpStep = step;
    if (!s.totpConfirmed) s.totpConfirmed = true;
    save(s);

    const sid = newToken();
    sessions.set(sid, { user: s.user, expires: now + SESSION_TTL_MS });
    return { ok: true, sid, user: s.user, expires: now + SESSION_TTL_MS };
  }

  sessionFor(cookieHeader) {
    if (!this.enabled) return { user: null, anonymous: true };
    const now = Date.now();
    sweep(sessions, now);
    const sid = readCookie(cookieHeader, COOKIE);
    if (!sid) return null;
    const s = sessions.get(sid);
    return s ? { user: s.user, expires: s.expires, sid } : null;
  }

  logout(cookieHeader) {
    const sid = readCookie(cookieHeader, COOKIE);
    if (sid) sessions.delete(sid);
  }

  setPassword(password) {
    const { salt, hash } = hashPassword(password);
    Object.assign(this.store, { salt, hash, passwordIsDefault: false });
    save(this.store);
  }

  // Re-enrol: a new secret, unconfirmed, so the next login shows the QR/secret
  // again. Used when the authenticator device is lost.
  resetTotp() {
    Object.assign(this.store, {
      totpSecret: base32Encode(crypto.randomBytes(20)),
      totpConfirmed: false,
      lastTotpStep: 0,
    });
    save(this.store);
    return this.enrolment;
  }

  // Wipe every live session — used after a credential change.
  revokeAllSessions() { sessions.clear(); pending.clear(); }
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
  Auth, sessionCookie, clearCookie, readCookie, otpauthUri, prettySecret,
  DEFAULT_USER, DEFAULT_PASSWORD, STORE, ISSUER,
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
