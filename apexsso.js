/*
 * apexsso.js — verifying the ApexBuild single-sign-on ticket.
 *
 * WHY THIS EXISTS
 *
 * Standalone, this app asks for a password and a six-digit code, because it can
 * put real syslog on your network and should not answer to anyone who can reach
 * the port. Inside ApexBuild that question has already been answered: the shell
 * signed the person in, and it is the shell that *starts* this process. Asking
 * again is not a second factor, it is a second password to forget.
 *
 * THE TICKET
 *
 * The shell hands every module a shared signing key in its environment at
 * launch — no key distribution, because the parent is the issuer — and appends
 * a one-time ticket to the URL it frames:
 *
 *     v1.<base64url payload>.<base64url HMAC-SHA256>
 *
 *     payload = {"sub":"alfredo","name":"Alfredo","role":"admin",
 *                "aud":"jedisyslogger","iat":…,"exp":…,"jti":"…","iss":"apexbuild"}
 *
 * Four things make it safe to put in a URL, and all four are checked below:
 *
 *   HMAC  over the exact bytes signed, compared in constant time, *before* the
 *         payload is parsed — until the MAC agrees, the payload is hostile input.
 *   aud   bound to one module id. A ticket for the terminal is not a ticket for
 *         this app; a module that accepts any audience hands every other
 *         module's tickets a way in.
 *   exp   seconds, not hours. It only has to survive one frame load.
 *   jti   single use. The shell will not mint the same one twice and this
 *         refuses a repeat.
 *
 * This is the Node counterpart of the suite's `apexbuild/sso.py`. The checks and
 * their order are deliberately identical — that file says it is written once
 * because getting it slightly wrong is the whole risk, and this is the same code
 * in another language rather than a fresh interpretation of the idea.
 *
 * WHAT IT IS NOT
 *
 * Not OAuth, not OIDC, not a bearer token for an API. It is a first-hop
 * assertion between two processes that share a parent and a machine. The trust
 * boundary is still "whoever can reach loopback".
 *
 * Self-test:  node apexsso.js --selftest
 */
'use strict';

const crypto = require('crypto');

const VERSION = 'v1';
const ENV_KEY = 'APEX_SSO_KEY';
const ENV_MODULE = 'APEX_MODULE_ID';
const QUERY_PARAM = 'apex_sso';
const LEEWAY_S = 5;          // clock slack, both directions
const SEEN_KEEP_S = 60;      // how long a spent jti is remembered past its expiry

const b64url = (buf) => Buffer.from(buf).toString('base64url');
const unb64url = (str) => Buffer.from(str, 'base64url');

class Verifier {
  /**
   * @param {string} key       the shared key, base64url, from APEX_SSO_KEY
   * @param {string} audience  this module's id — the only `aud` accepted
   */
  constructor(key, audience) {
    this.key = key ? unb64url(key) : null;
    this.audience = String(audience || '');
    this.seen = new Map();   // jti -> exp, so a replay is refused
  }

  /** The verified payload, or throws. Never returns unverified claims. */
  verify(ticket) {
    if (!this.key || !this.key.length) throw new Error('no signing key configured');
    if (!this.audience) throw new Error('no module id configured');
    const parts = String(ticket || '').split('.');
    if (parts.length !== 3) throw new Error('malformed ticket');
    const [version, body, mac] = parts;
    if (version !== VERSION) throw new Error(`unsupported ticket version "${version}"`);

    // Signature first, always. Everything after this line is attacker-supplied
    // until the MAC has said otherwise, so nothing is parsed before it.
    const expected = crypto.createHmac('sha256', this.key).update(`${version}.${body}`, 'ascii').digest();
    const given = unb64url(mac);
    // timingSafeEqual throws on a length mismatch, so the length is compared
    // first — a wrong-length MAC is not a secret worth hiding the timing of.
    if (given.length !== expected.length || !crypto.timingSafeEqual(expected, given)) {
      throw new Error('bad signature');
    }

    let payload;
    try { payload = JSON.parse(unb64url(body).toString('utf8')); }
    catch (e) { throw new Error('malformed payload'); }
    if (!payload || typeof payload !== 'object') throw new Error('malformed payload');

    const now = Date.now() / 1000;
    // The most important check after the signature.
    if (payload.aud !== this.audience) {
      throw new Error(`ticket is for "${payload.aud}", not "${this.audience}"`);
    }
    if (now > Number(payload.exp || 0) + LEEWAY_S) throw new Error('ticket has expired');
    if (now < Number(payload.iat || 0) - LEEWAY_S) throw new Error('ticket is from the future');
    if (!payload.sub) throw new Error('ticket names no subject');

    const jti = payload.jti;
    if (!jti) throw new Error('ticket has no id');
    this._prune(now);
    if (this.seen.has(jti)) throw new Error('ticket has already been used');
    this.seen.set(jti, Number(payload.exp || 0));

    return payload;
  }

  _prune(now) {
    for (const [jti, exp] of this.seen) if (exp < now - SEEN_KEEP_S) this.seen.delete(jti);
  }
}

/**
 * A Verifier from the environment, or null when this app was started on its own.
 *
 * null is the normal case, and the reason the standalone sign-in has to stay
 * exactly where it is: an app with no shell above it has nobody to trust.
 *
 * The audience is passed in rather than read from APEX_MODULE_ID on purpose.
 * It is the one check that keeps another module's tickets out, so it is a
 * constant in this repository — not something the environment gets a vote on.
 * A disagreement is worth a line on stderr: it means the suite has this module
 * registered under a different id, and every ticket is about to be refused.
 */
function fromEnvironment(audience) {
  const key = process.env[ENV_KEY] || '';
  if (!key) return null;
  const declared = process.env[ENV_MODULE] || '';
  if (declared && declared !== audience) {
    console.error(`  ⚠ ApexBuild calls this module "${declared}" but it verifies tickets for "${audience}" — single sign-on will refuse every ticket until apexmodule.toml and the suite agree`);
  }
  return new Verifier(key, audience);
}

/**
 * Mint a ticket. The shell does this in Python; this exists so the self-test
 * and `node apexsso.js --selftest` can exercise the verifier without one.
 */
function mint(key, user, audience, ttl = 30) {
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    aud: audience,
    exp: now + Math.max(5, ttl),
    iat: now,
    iss: 'apexbuild',
    jti: crypto.randomBytes(9).toString('base64url'),
    name: user.display_name || user.username,
    role: user.role || 'user',
    sub: user.username,
  };
  const body = b64url(Buffer.from(JSON.stringify(payload), 'utf8'));
  const signed = `${VERSION}.${body}`;
  const mac = crypto.createHmac('sha256', unb64url(key)).update(signed, 'ascii').digest();
  return `${signed}.${b64url(mac)}`;
}

module.exports = { Verifier, fromEnvironment, mint, QUERY_PARAM, ENV_KEY, ENV_MODULE, VERSION };

// ---- Self-test -------------------------------------------------------------
// Exercises every rejection path, because the only interesting thing a verifier
// can do wrong is accept something.
if (require.main === module && process.argv.includes('--selftest')) {
  let failed = 0;
  const ok = (label, cond) => { if (!cond) { failed++; console.error(`FAIL ${label}`); } else console.log(`ok   ${label}`); };
  const throws = (label, fn, match) => {
    try { fn(); failed++; console.error(`FAIL ${label} — it was accepted`); }
    catch (e) {
      if (match && !match.test(e.message)) { failed++; console.error(`FAIL ${label} — wrong reason: ${e.message}`); }
      else console.log(`ok   ${label} (${e.message})`);
    }
  };

  const key = crypto.randomBytes(32).toString('base64url');
  const user = { username: 'alfredo', display_name: 'Alfredo', role: 'admin' };
  const V = () => new Verifier(key, 'jedisyslogger');

  const good = mint(key, user, 'jedisyslogger');
  const claims = V().verify(good);
  ok('a valid ticket verifies', claims.sub === 'alfredo' && claims.role === 'admin');

  const replay = V();
  replay.verify(good);
  throws('a replayed ticket is refused', () => replay.verify(good), /already been used/);

  throws('a ticket for another module is refused',
    () => V().verify(mint(key, user, 'terminal')), /not "jedisyslogger"/);

  throws('a ticket signed with another key is refused',
    () => V().verify(mint(crypto.randomBytes(32).toString('base64url'), user, 'jedisyslogger')), /bad signature/);

  throws('an expired ticket is refused', () => {
    const now = Math.floor(Date.now() / 1000);
    const payload = { aud: 'jedisyslogger', exp: now - 60, iat: now - 120, jti: 'old', sub: 'alfredo', role: 'admin' };
    const body = b64url(Buffer.from(JSON.stringify(payload)));
    const mac = crypto.createHmac('sha256', unb64url(key)).update(`v1.${body}`, 'ascii').digest();
    V().verify(`v1.${body}.${b64url(mac)}`);
  }, /expired/);

  throws('a tampered payload is refused', () => {
    const [v, body, mac] = good.split('.');
    const claim = JSON.parse(unb64url(body).toString());
    claim.role = 'admin'; claim.sub = 'attacker';
    V().verify(`${v}.${b64url(Buffer.from(JSON.stringify(claim)))}.${mac}`);
  }, /bad signature/);

  throws('an unsigned "none"-style ticket is refused', () => {
    const [, body] = good.split('.');
    V().verify(`v1.${body}.`);
  }, /bad signature/);

  throws('a truncated ticket is refused', () => V().verify('v1.abc'), /malformed/);
  throws('an unknown version is refused', () => {
    const [, body, mac] = good.split('.');
    V().verify(`v2.${body}.${mac}`);
  }, /unsupported ticket version/);

  throws('a verifier with no key refuses everything',
    () => new Verifier('', 'jedisyslogger').verify(good), /no signing key/);

  ok('no shell in the environment means no verifier',
    (() => { const k = process.env.APEX_SSO_KEY; delete process.env.APEX_SSO_KEY;
             const v = fromEnvironment('jedisyslogger'); if (k) process.env.APEX_SSO_KEY = k; return v === null; })());

  console.log(failed ? `\n${failed} check(s) failed` : '\n  all checks passed\n');
  process.exit(failed ? 1 : 0);
}
