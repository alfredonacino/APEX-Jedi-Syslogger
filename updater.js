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
const fs = require('fs');
const os = require('os');
const path = require('path');
const { VERSION, UPDATE_URL, UPDATE_PUBKEY, UPDATE_CHANNEL, UPDATE_APP } = require('./js/version.js');

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
// The store is not anonymous: every read wants an application token. It is a
// *read* credential, not a signing key — it cannot forge a release, because the
// manifest still has to verify against the public key compiled into this build.
// Kept out of argv all the same, for the same reason as every other secret here.
function readToken() {
  if (process.env.APEX_TOKEN) return process.env.APEX_TOKEN.trim();
  const files = [
    process.env.APEX_TOKEN_FILE,
    path.join(os.homedir(), '.config', 'apex-jedisyslogger', 'apex.token'),
  ].filter(Boolean);
  for (const f of files) {
    try { if (fs.existsSync(f)) return fs.readFileSync(f, 'utf8').trim(); } catch (e) { /* unreadable is "absent" */ }
  }
  return null;
}

function get(url, cb, redirects = 0, token = null) {
  let u;
  try { u = new URL(url); } catch (e) { return cb(new Error(`bad update URL: ${url}`)); }
  if (u.protocol !== 'https:' && u.hostname !== 'localhost' && u.hostname !== '127.0.0.1')
    return cb(new Error(`refusing to fetch an update manifest over ${u.protocol.replace(':', '')} — use https`));
  const mod = u.protocol === 'https:' ? https : http;

  const headers = { 'User-Agent': `apex-jedisyslogger/${VERSION}`, Accept: 'application/json' };
  if (token) headers.Authorization = `Bearer ${token}`;
  const req = mod.get(u, { headers }, (res) => {
    if ([301, 302, 307, 308].includes(res.statusCode)) {
      res.resume();
      if (redirects >= 3) return cb(new Error('too many redirects from the update server'));
      const next = res.headers.location;
      if (!next) return cb(new Error(`update server sent ${res.statusCode} with no location`));
      return get(new URL(next, u).toString(), cb, redirects + 1, token);
    }
    if (res.statusCode !== 200) {
      res.resume();
      if (res.statusCode === 401 || res.statusCode === 403) return cb(new Error(
        'the update store requires a read token. Put one in ~/.config/apex-jedisyslogger/apex.token ' +
        '(chmod 600) or set $APEX_TOKEN. It only grants reads — a release still has to carry a ' +
        'signature this build can verify.'));
      return cb(new Error(res.statusCode === 404
        ? `no release channel at ${u.href} (404) — nothing published yet?`
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

// ---- picking a build -------------------------------------------------------
// The store records each artefact's platform/arch/format, using "any" (and
// "all", Debian's spelling) where a file genuinely serves everything — the
// tarball really does run on Linux and macOS on either CPU. Score compatibility
// rather than string-matching, so a universal file is a match and a foreign one
// is never offered.
function scoreArtifact(a, platform, arch) {
  const p = String(a.platform || 'any').toLowerCase();
  const r = String(a.arch || 'any').toLowerCase();
  const anyP = p === 'any' || p === 'all' || p === '';
  const anyA = r === 'any' || r === 'all' || r === '';
  if (!anyP && p !== platform) return -1;
  if (!anyA && r !== arch) return -1;
  let score = (anyP ? 1 : 2) + (anyA ? 1 : 2);
  // Among equally compatible files prefer the one that needs no package
  // manager, because we cannot know which one installed this copy.
  const fmt = String(a.format || '').toLowerCase();
  if ((platform === 'win32' && fmt === 'zip') || (platform !== 'win32' && fmt === 'tar.gz')) score += 2;
  return score;
}

function pickArtifact(artifacts, platform, arch) {
  const scored = artifacts
    .map((a) => ({ a, s: scoreArtifact(a, platform, arch) }))
    .filter((x) => x.s >= 0)
    .sort((x, y) => y.s - x.s);
  return scored.length ? scored[0].a : null;
}

// Canonical JSON — keys sorted at every depth, no incidental whitespace. This
// must match packaging/sign.js exactly: it is the only agreement between the
// two halves about which bytes the signature covers.
function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === 'object')
    return Object.keys(value).sort().reduce((o, k) => { o[k] = canonical(value[k]); return o; }, {});
  return value;
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
 * @property {string} filename
 * @property {number} size
 * @property {string} sha256
 * @property {string} platform  any | linux | darwin | win32
 * @property {string} arch      any | all | x64 | arm64
 * @property {string} format    tar.gz | zip | deb | rpm | pacman | js
 * @property {string} url
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
 * @property {UpdateArtifact=} artifact   the best one for this platform, if any
 * @property {UpdateArtifact[]} artifacts
 * @property {boolean} verified  did a signature actually verify (see below)
 * @property {boolean=} authenticated  whether a read token was presented
 */

/**
 * @typedef {object} CheckOptions
 * @property {string=} url       base URL of the update server
 * @property {string=} channel   stable | beta | …
 * @property {string=} pubkey    override the built-in key (testing, rotation)
 * @property {string=} app       override the application slug
 * @property {string=} token     read token; otherwise env/config file
 * @property {string=} platformName  override the detected platform
 * @property {string=} archName      override the detected architecture
 */

/**
 * Ask the update server whether a newer version exists.
 * @param {CheckOptions|((err: Error|null, result?: UpdateResult) => void)} [opts]
 * @param {(err: Error|null, result?: UpdateResult) => void} [cb]
 */
function check(opts, cb) {
  if (typeof opts === 'function') { cb = /** @type {any} */ (opts); opts = {}; }
  opts = /** @type {CheckOptions} */ (opts || {});
  const origin = String(opts.url || UPDATE_URL).replace(/\/+$/, '');
  const channel = opts.channel || UPDATE_CHANNEL || 'stable';
  const pubkey = opts.pubkey || UPDATE_PUBKEY;
  const app = opts.app || UPDATE_APP;
  const platform = opts.platformName || process.platform;
  const arch = opts.archName || process.arch;
  const token = opts.token || readToken();

  const q = new URLSearchParams({ version: VERSION, channel, platform, arch });
  const url = `${origin}/api/v1/apps/${encodeURIComponent(app)}/check?${q}`;

  get(url, (err, raw) => {
    if (err) return cb(err);

    let answer;
    try { answer = JSON.parse(raw.toString('utf8')); }
    catch (e) { return cb(new Error('the update server did not return JSON')); }

    const latest = answer && answer.latest;
    const m = latest && latest.manifest;
    // The store returns a signed manifest only when it is offering an upgrade.
    // For "you are current" there is nothing to verify, so say so plainly rather
    // than reporting a verified result we did not check: an unsigned "no update
    // for you" is exactly what a store would say if it wanted to freeze a fleet
    // on an old version.
    if (!m || typeof m !== 'object') {
      const known = (answer && answer.latest_known) || VERSION;
      const c = compareVersions(VERSION, known);
      return cb(null, {
        current: VERSION, latest: known, released: null, channel,
        upToDate: c === null ? true : c >= 0, ahead: c !== null && c > 0, notes: null,
        platform: `${platform}-${arch}`, artifact: null, artifacts: [],
        verified: false, authenticated: !!token,
      });
    }

    // Everything below this line is checked before it is believed. The server's
    // own `update_available` is deliberately ignored: it is unsigned, and a
    // store that has been tampered with would happily assert anything.
    const sig = m.signature;
    const body = Object.assign({}, m);
    delete body.signature;
    let ok = false;
    try { ok = verify(Buffer.from(JSON.stringify(canonical(body)), 'utf8'), sig, pubkey); }
    catch (e) { return cb(e); }
    if (!ok) return cb(new Error(
      'the published manifest signature does NOT verify — refusing it. Either the store was ' +
      'tampered with, or it is signing with a key this build does not trust.'));

    if (m.app && app && m.app !== app)
      return cb(new Error(`the manifest is for "${m.app}", not "${app}" — refusing it`));

    const cmp = compareVersions(VERSION, m.version);
    if (cmp === null) return cb(new Error(`cannot compare versions ("${VERSION}" vs "${m.version}")`));

    const artifacts = Array.isArray(m.artifacts) ? m.artifacts : [];
    // The store serves builds from one authenticated route; building the URL
    // here rather than signing it in means moving or mirroring the store does
    // not invalidate every published signature.
    const withUrl = (a) => a && Object.assign({}, a, {
      url: `${origin}/api/v1/apps/${encodeURIComponent(app)}/releases/` +
           `${encodeURIComponent(m.version)}/artifacts/${encodeURIComponent(a.filename)}/download`,
    });

    cb(null, {
      current: VERSION,
      latest: m.version,
      released: m.released || (latest && latest.published_at) || null,
      channel,
      upToDate: cmp >= 0,
      ahead: cmp > 0,
      notes: typeof m.notes === 'string' ? m.notes.slice(0, 2000) : null,
      platform: `${platform}-${arch}`,
      artifact: withUrl(pickArtifact(artifacts, platform, arch)),
      artifacts: artifacts.map(withUrl),
      verified: true,
      authenticated: !!token,
    });
  }, 0, token);
}

module.exports = { check, verify, compareVersions, parseVersion, pickArtifact, MANIFEST_MAX };
