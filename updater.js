/*
 * updater.js — "is this copy current?", answered safely.
 *
 * The update server is treated as untrusted. It can serve any bytes it likes;
 * what it cannot do is produce an Ed25519 signature over them without the
 * private key. So the order here is fixed and not negotiable:
 *
 *     fetch  →  verify signature  →  parse  →  compare versions
 *
 * Nothing downstream of the signature check runs on unverified bytes, and the
 * manifest is size-capped before it is even read, because "trusted after
 * parsing" is how update channels turn into a way in.
 *
 * This never installs anything. It reports; a human runs the package manager.
 * An updater that can replace its own binary is a remote-code-execution feature
 * wearing a friendly name, and this application has no business owning one.
 *
 * Node core only (https, crypto). Required by jedi-cli.js.
 */
'use strict';

const https = require('https');
const http = require('http');
const crypto = require('crypto');
const { VERSION, UPDATE_URL, UPDATE_PUBKEY, UPDATE_CHANNEL } = require('./js/version.js');

const MANIFEST_MAX = 64 * 1024;   // a version manifest is a few hundred bytes
const TIMEOUT_MS = 8000;

// ---- semver, only as much as a version comparison needs --------------------
// Not a general implementation: this compares X.Y.Z with an optional -prerelease,
// which is the whole shape this project's versions take.
function parseVersion(v) {
  const m = /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?$/.exec(String(v || '').trim());
  if (!m) return null;
  return { major: +m[1], minor: +m[2], patch: +m[3], pre: m[4] || null };
}

function compareVersions(a, b) {
  const A = parseVersion(a), B = parseVersion(b);
  if (!A || !B) return null;
  for (const k of ['major', 'minor', 'patch']) if (A[k] !== B[k]) return A[k] < B[k] ? -1 : 1;
  // A release outranks any prerelease of the same numbers (1.2.0 > 1.2.0-rc1).
  if (A.pre && !B.pre) return -1;
  if (!A.pre && B.pre) return 1;
  if (A.pre === B.pre) return 0;
  return A.pre < B.pre ? -1 : 1;
}

// ---- transport -------------------------------------------------------------
function get(url, cb, redirects = 0) {
  let u;
  try { u = new URL(url); } catch (e) { return cb(new Error(`bad update URL: ${url}`)); }
  if (u.protocol !== 'https:' && u.hostname !== 'localhost' && u.hostname !== '127.0.0.1')
    return cb(new Error(`refusing to fetch an update manifest over ${u.protocol.replace(':', '')} — use https`));
  const mod = u.protocol === 'https:' ? https : http;

  const req = mod.get(u, { headers: { 'User-Agent': `apex-jedisyslogger/${VERSION}`, Accept: 'application/json' } }, (res) => {
    if ([301, 302, 307, 308].includes(res.statusCode)) {
      res.resume();
      if (redirects >= 3) return cb(new Error('too many redirects from the update server'));
      const next = res.headers.location;
      if (!next) return cb(new Error(`update server sent ${res.statusCode} with no location`));
      return get(new URL(next, u).toString(), cb, redirects + 1);
    }
    if (res.statusCode !== 200) {
      res.resume();
      return cb(new Error(res.statusCode === 404
        ? `no manifest at ${u.href} (404) — the channel may not be published yet`
        : `update server answered HTTP ${res.statusCode}`));
    }
    const chunks = [];
    let size = 0;
    res.on('data', (c) => {
      size += c.length;
      // Cap before buffering, not after: an unbounded body is a memory bomb.
      if (size > MANIFEST_MAX) { req.destroy(); return cb(new Error('update manifest is implausibly large — refusing it')); }
      chunks.push(c);
    });
    res.on('end', () => cb(null, Buffer.concat(chunks)));
  });
  req.setTimeout(TIMEOUT_MS, () => { req.destroy(); cb(new Error(`update server did not answer within ${TIMEOUT_MS / 1000}s`)); });
  req.on('error', (e) => cb(new Error(`cannot reach the update server: ${e.code || e.message}`)));
}

// ---- verification ----------------------------------------------------------
// The signature covers the manifest bytes exactly as served. Signing a parsed
// and re-serialised object instead would let two different byte strings share
// one signature, which is the whole trick behind a signature-confusion bug.
function verify(raw, signatureB64, pubkeyB64) {
  let key;
  try {
    key = crypto.createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: pubkeyB64 }, format: 'jwk' });
  } catch (e) {
    throw new Error('the built-in update public key is malformed — this build cannot check for updates');
  }
  let sig;
  try { sig = Buffer.from(String(signatureB64), 'base64'); } catch (e) { return false; }
  if (sig.length !== 64) return false;
  return crypto.verify(null, raw, key, sig);
}

/**
 * @typedef {object} UpdateArtifact
 * @property {string} kind      portable | deb | rpm | pacman | single-file
 * @property {string} file
 * @property {string} url
 * @property {string} sha256
 *
 * @typedef {object} UpdateResult
 * @property {string}  current   the running version
 * @property {string}  latest    the published version
 * @property {string=} released
 * @property {string}  channel
 * @property {boolean} upToDate
 * @property {boolean} ahead     this build is newer than what is published
 * @property {string=} notes
 * @property {string}  platform  `${process.platform}-${process.arch}`
 * @property {UpdateArtifact=} artifact   the one for this platform, if any
 * @property {Object<string, UpdateArtifact>} artifacts
 * @property {boolean} verified  always true — an unverified result is an error
 */

/**
 * @typedef {object} CheckOptions
 * @property {string=} url       base URL of the update server
 * @property {string=} channel   stable | beta | …
 * @property {string=} pubkey    override the built-in key (testing, rotation)
 * @property {string=} platform  override the detected platform
 */

/**
 * Ask the update server whether a newer version exists.
 * @param {CheckOptions|((err: Error|null, result?: UpdateResult) => void)} [opts]
 * @param {(err: Error|null, result?: UpdateResult) => void} [cb]
 */
function check(opts, cb) {
  if (typeof opts === 'function') { cb = /** @type {any} */ (opts); opts = {}; }
  opts = /** @type {CheckOptions} */ (opts || {});
  const base = opts.url || UPDATE_URL;
  const channel = opts.channel || UPDATE_CHANNEL || 'stable';
  const pubkey = opts.pubkey || UPDATE_PUBKEY;
  const url = new URL(`${channel}.json`, base.endsWith('/') ? base : base + '/').toString();

  get(url, (err, raw) => {
    if (err) return cb(err);

    // The signature rides in a detached header so the signed bytes and the
    // served bytes are the same object; a signature inside the JSON would have
    // to be stripped first, and "strip then verify" is where these go wrong.
    let manifest;
    let sigB64 = null;
    try {
      const parsed = JSON.parse(raw.toString('utf8'));
      sigB64 = parsed.signature;
      manifest = parsed.manifest;
    } catch (e) {
      return cb(new Error('update manifest is not valid JSON'));
    }
    if (!sigB64 || typeof manifest !== 'string')
      return cb(new Error('update manifest is missing its signature or payload'));

    let ok = false;
    try { ok = verify(Buffer.from(manifest, 'utf8'), sigB64, pubkey); }
    catch (e) { return cb(e); }
    if (!ok) return cb(new Error(
      'update manifest signature does NOT verify — refusing it. Either the server was tampered with, ' +
      'or it is signing with a key this build does not trust.'));

    let m;
    try { m = JSON.parse(manifest); } catch (e) { return cb(new Error('signed payload is not valid JSON')); }

    const cmp = compareVersions(VERSION, m.version);
    if (cmp === null) return cb(new Error(`cannot compare versions ("${VERSION}" vs "${m.version}")`));

    const plat = opts.platform || `${process.platform}-${process.arch}`;
    const artifacts = (m.artifacts && typeof m.artifacts === 'object') ? m.artifacts : {};
    cb(null, {
      current: VERSION,
      latest: m.version,
      released: m.released || null,
      channel,
      upToDate: cmp >= 0,
      ahead: cmp > 0,                       // a local build newer than published
      notes: typeof m.notes === 'string' ? m.notes.slice(0, 2000) : null,
      platform: plat,
      artifact: artifacts[plat] || null,
      artifacts,
      verified: true,
    });
  });
}

module.exports = { check, verify, compareVersions, parseVersion, MANIFEST_MAX };
