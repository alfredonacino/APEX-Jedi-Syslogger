#!/usr/bin/env node
/*
 * sign.js — build and sign the update manifest.
 *
 *   node packaging/sign.js                    sign dist/ into dist/publish/
 *   node packaging/sign.js --notes "..."      add release notes to the manifest
 *   node packaging/sign.js --base-url URL     where the artefacts will be served
 *
 * THE PRIVATE KEY IS NEVER READ FROM THE COMMAND LINE, and never lives in this
 * repository. A key on argv is visible in `ps`, in shell history and in CI logs.
 * It comes from one of, in order:
 *
 *     $JEDI_PUBLISH_KEY                        (base64url, 32-byte Ed25519 seed)
 *     $JEDI_PUBLISH_KEY_FILE                   (path to a file containing it)
 *     ~/.config/apex-jedisyslogger/publish.key (mode 600)
 *
 * Before it signs anything it derives the public key from that private key and
 * checks it against UPDATE_PUBKEY in js/version.js. A manifest signed with the
 * wrong key verifies nowhere and would silently break the channel for everyone,
 * so that mismatch is fatal here rather than discovered in the field.
 */
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

const ROOT = path.resolve(__dirname, '..');
const { VERSION, RELEASED, UPDATE_PUBKEY, UPDATE_CHANNEL, UPDATE_APP } = require('../js/version.js');

const argv = process.argv.slice(2);
const flag = (name, def) => {
  const i = argv.indexOf(`--${name}`);
  return i === -1 ? def : (argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[i + 1] : true);
};

function die(msg, hint) {
  process.stderr.write(`sign: ${msg}\n`);
  if (hint) process.stderr.write(`      ${hint}\n`);
  process.exit(1);
}

// ---- the private key, from anywhere except argv ----------------------------
function loadPrivateKey() {
  const inline = process.env.JEDI_PUBLISH_KEY;
  if (inline) return { value: inline.trim(), from: '$JEDI_PUBLISH_KEY' };

  const candidates = [
    process.env.JEDI_PUBLISH_KEY_FILE,
    path.join(os.homedir(), '.config', 'apex-jedisyslogger', 'publish.key'),
  ].filter(Boolean);

  for (const file of candidates) {
    if (!fs.existsSync(file)) continue;
    const st = fs.statSync(file);
    // A signing key readable by the whole machine is not a signing key.
    if (process.platform !== 'win32' && (st.mode & 0o077)) {
      die(`${file} is readable by other users (mode ${(st.mode & 0o777).toString(8)})`,
          `fix it with: chmod 600 "${file}"`);
    }
    return { value: fs.readFileSync(file, 'utf8').trim(), from: file };
  }

  die('no publishing key found', [
    'set one of:',
    '  export JEDI_PUBLISH_KEY=<base64url seed>          (not recommended: lands in shell history)',
    '  export JEDI_PUBLISH_KEY_FILE=/path/to/publish.key',
    `  ${path.join(os.homedir(), '.config/apex-jedisyslogger/publish.key')}   (chmod 600)`,
  ].join('\n      '));
}

function keyPair() {
  const { value, from } = loadPrivateKey();
  // Only for key rotation and for testing the channel against a throwaway key.
  // It is deliberately noisy: signing against anything other than the key in
  // js/version.js produces a manifest no shipped build will accept.
  const expected = String(flag('expect-pubkey', '') || '') || UPDATE_PUBKEY;
  if (expected !== UPDATE_PUBKEY)
    process.stderr.write(`\n  !! --expect-pubkey overrides the shipped key.\n` +
                         `     Manifests signed this way will NOT verify in released builds.\n\n`);
  if (!/^[A-Za-z0-9_-]{43}$/.test(value))
    die(`the key in ${from} is not a 32-byte base64url value`,
        'expected 43 base64url characters, as produced by `node packaging/sign.js --generate`');

  let priv;
  try {
    priv = crypto.createPrivateKey({
      key: { kty: 'OKP', crv: 'Ed25519', d: value, x: expected }, format: 'jwk',
    });
  } catch (e) {
    die(`the key in ${from} is not a usable Ed25519 seed (${e.message})`);
  }

  // Derive rather than trust: this is the check that stops a manifest being
  // published under a key no shipped build will accept.
  const derived = crypto.createPublicKey(priv).export({ format: 'jwk' }).x;
  if (derived !== expected) {
    die('the private key does not match the public key builds trust',
        `key derives ${derived}\n      builds trust ${expected}\n` +
        '      Publishing this would break updates for every installed copy.');
  }
  return { priv, from, expected };
}

// ---- artefacts -------------------------------------------------------------
// What each file is, in the store's own vocabulary. "any" where a file really
// does serve everything: the tarball runs on Linux and macOS on either CPU, and
// claiming linux-x64 to look tidy would hide it from every Mac.
function describe(file) {
  if (/\.deb$/.test(file)) return { platform: 'linux', arch: 'all', format: 'deb' };
  if (/\.rpm$/.test(file)) return { platform: 'linux', arch: 'noarch', format: 'rpm' };
  if (/\.pkg\.tar\.(zst|xz)$/.test(file)) return { platform: 'linux', arch: 'any', format: 'pacman' };
  if (/-windows\.zip$/.test(file)) return { platform: 'win32', arch: 'any', format: 'zip' };
  if (/-macos\.tar\.gz$/.test(file)) return { platform: 'darwin', arch: 'any', format: 'tar.gz' };
  if (/-linux\.tar\.gz$/.test(file)) return { platform: 'linux', arch: 'any', format: 'tar.gz' };
  if (/^jedi-[\d.]+\.js$/.test(file)) return { platform: 'any', arch: 'any', format: 'js' };
  // Anything unlabelled is universal — say so rather than guessing a platform.
  if (/\.zip$/.test(file)) return { platform: 'win32', arch: 'any', format: 'zip' };
  if (/\.tar\.gz$/.test(file)) return { platform: 'any', arch: 'any', format: 'tar.gz' };
  return { platform: 'any', arch: 'any', format: 'bin' };
}

// The bytes a signature covers come from updater.js, imported rather than
// reimplemented. A signer and a verifier that each define "canonical" for
// themselves will agree right up until they do not, which is precisely the bug
// this import exists to make impossible.
const { canonicalBytes } = require('../updater.js');

function sha256(file) {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

// ---- main ------------------------------------------------------------------
if (argv.includes('--generate')) {
  // Offered so nobody is ever tempted to reuse a key that has been pasted somewhere.
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const pub = publicKey.export({ format: 'jwk' }).x;
  const priv = privateKey.export({ format: 'jwk' }).d;
  process.stderr.write(
    '\nNew Ed25519 publishing keypair.\n\n' +
    `  public  (goes in js/version.js as UPDATE_PUBKEY)\n    ${pub}\n\n` +
    '  private (never commit, never paste, never put on a command line)\n' +
    `    write it to ~/.config/apex-jedisyslogger/publish.key with mode 600\n\n`);
  process.stdout.write(priv + '\n');   // stdout only, so it can be redirected straight to a file
  process.exit(0);
}

const DIST = path.join(ROOT, 'dist');
if (!fs.existsSync(DIST)) die('dist/ does not exist', 'run ./packaging/build.sh first');

const baseUrl = String(flag('base-url', `https://atlasupdate.cybercontrol.tech/${VERSION}/`));
const channel = String(flag('channel', UPDATE_CHANNEL || 'stable'));
const notes = flag('notes', null);

// Only this version's artefacts. dist/ accumulates across builds, and a
// manifest that says 1.1.0 while pointing at the 1.0.0 tarball is worse than no
// manifest — every client would verify the signature, trust it, and download
// the wrong thing.
const files = fs.readdirSync(DIST).filter((f) => {
  const st = fs.statSync(path.join(DIST, f));
  if (!st.isFile() || f === 'SHA256SUMS' || f.endsWith('.json') || f.endsWith('.sig')) return false;
  if (!f.includes(VERSION)) {
    process.stderr.write(`  skipping ${f} — not version ${VERSION}\n`);
    return false;
  }
  return true;
});
if (!files.length) die(`dist/ has no artefacts for version ${VERSION}`, 'run ./packaging/build.sh first');

// Artefacts older than the code they were built from are a trap: sign them and
// you publish a manifest the shipped client cannot verify, because the verifier
// inside the package predates the signer that produced it. That happened once —
// updater.js was fixed between the build and the signature — so it is checked
// rather than remembered.
(function refuseStaleArtefacts() {
  const sources = ['js', 'jedi-cli.js', 'desktop.js', 'server.js', 'auth.js', 'forward.js', 'updater.js']
    .map((f) => path.join(ROOT, f));
  const newestSource = (function walk(targets, newest = 0) {
    for (const t of targets) {
      let st; try { st = fs.statSync(t); } catch (e) { continue; }
      if (st.isDirectory()) newest = walk(fs.readdirSync(t).map((f) => path.join(t, f)), newest);
      else newest = Math.max(newest, st.mtimeMs);
    }
    return newest;
  })(sources);
  const oldest = Math.min(...files.map((f) => fs.statSync(path.join(DIST, f)).mtimeMs));
  if (oldest < newestSource) {
    const stale = files.filter((f) => fs.statSync(path.join(DIST, f)).mtimeMs < newestSource);
    die('the built artefacts are older than the source they were built from',
      `stale: ${stale.join(', ')}\n      run ./packaging/build.sh again before signing`);
  }
})();

const { priv, from, expected } = keyPair();

const artifacts = files.sort().map((f) => Object.assign(
  { filename: f, size: fs.statSync(path.join(DIST, f)).size, sha256: sha256(path.join(DIST, f)) },
  describe(f)));

// The document, minus its own signature. `app` is in here on purpose: the store
// checks the signed manifest names the app it is being attached to, so a
// manifest cannot be replayed onto a different application.
const doc = {
  app: String(flag('app', UPDATE_APP)),
  name: 'APEX JediSyslogger',
  version: VERSION,
  released: RELEASED,
  channel,
  artifacts,
};
if (typeof notes === 'string') doc.notes = notes;

const signedBytes = canonicalBytes(doc);
const signature = crypto.sign(null, signedBytes, priv).toString('base64');

// Verify our own output before publishing it, using the public key a shipped
// build would use — not the one we just derived from the private half.
const check = crypto.verify(null, signedBytes,
  crypto.createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: expected }, format: 'jwk' }),
  Buffer.from(signature, 'base64'));
if (!check) die('self-check failed: the signature does not verify against the expected public key');

const payload = JSON.stringify(doc, null, 2);

const outDir = path.join(DIST, 'publish');
fs.mkdirSync(outDir, { recursive: true });
// One self-contained document, signature included — the shape the store's
// "attach signed manifest" endpoint takes, and the shape its paste field wants.
fs.writeFileSync(path.join(outDir, `${channel}.json`), JSON.stringify(Object.assign({}, doc, { signature }), null, 2) + '\n');
for (const a of artifacts) fs.copyFileSync(path.join(DIST, a.filename), path.join(outDir, a.filename));

// A written checklist, not just terminal output: whoever uploads may not be
// whoever signed, and "where does each file go" is the step that gets it wrong.
const manifestUrl = require('../js/version.js').UPDATE_URL;
fs.writeFileSync(path.join(outDir, 'UPLOAD.txt'), [
  `APEX JediSyslogger ${VERSION} — upload checklist`,
  ``,
  `Every file in this directory goes to the Apex Update Server. Two rules:`,
  ``,
  `  Publish with:  node packaging/publish.js`,
  ``,
  `  or by hand: attach ${channel}.json to release ${VERSION} of app "${doc.app}"`,
  `  and publish it to the ${channel} channel. Clients read the manifest from`,
  `       ${manifestUrl}`,
  `  which must be readable WITHOUT signing in — it is signed, so it does not`,
  `  need to be secret, and a login page served in its place is what an update`,
  `  check would receive.`,
  ``,
  `  Artefacts:`,
  ...artifacts.map((a) => `       ${a.filename.padEnd(38)} ${a.platform}/${a.arch}/${a.format}`),
  ``,
  `Files in this directory:`,
  ...fs.readdirSync(outDir).filter((f) => f !== 'UPLOAD.txt').sort()
    .map((f) => `  ${f.padEnd(46)} ${fs.statSync(path.join(outDir, f)).size} bytes`),
  ``,
  `Checksums are inside the signed manifest, so a corrupted upload is detected`,
  `by clients, not just by you.`,
  ``,
  `Afterwards, verify from outside:`,
  `  ./packaging/verify-published.sh`,
  ``,
].join('\n'));

process.stderr.write(`\n  signed with the key from ${from}\n`);
process.stderr.write(`  self-check: signature verifies against UPDATE_PUBKEY\n\n`);
process.stderr.write(`  dist/publish/${channel}.json — ${artifacts.length} artefacts, ${signedBytes.length} signed bytes\n`);
for (const a of artifacts)
  process.stderr.write(`    ${a.filename.padEnd(38)} ${a.platform}/${a.arch}/${a.format}\n`);
process.stderr.write(`\n  publish with:  node packaging/publish.js\n\n`);
