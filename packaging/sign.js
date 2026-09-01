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
const { VERSION, RELEASED, UPDATE_PUBKEY, UPDATE_CHANNEL } = require('../js/version.js');

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
// Which file serves which platform. The keys are `${process.platform}-${process.arch}`
// so a running build can look itself up without guessing.
function artifactMap(files, baseUrl) {
  const find = (re) => files.find((f) => re.test(f)) || null;
  const url = (f) => (f ? new URL(f, baseUrl.endsWith('/') ? baseUrl : baseUrl + '/').toString() : null);
  const portable = find(/\.tar\.gz$/);
  const zip = find(/\.zip$/);
  const single = find(/^jedi-[\d.]+\.js$/);
  const deb = find(/\.deb$/);
  const rpm = find(/\.rpm$/);
  const arch = find(/\.pkg\.tar\.(zst|xz)$/);

  const entry = (file, kind) => (file ? { kind, file, url: url(file), sha256: null } : null);
  const map = {
    'linux-x64': entry(portable, 'portable'),
    'linux-arm64': entry(portable, 'portable'),
    'darwin-arm64': entry(portable, 'portable'),
    'darwin-x64': entry(portable, 'portable'),
    'win32-x64': entry(zip, 'portable'),
    'win32-arm64': entry(zip, 'portable'),
  };
  // Native packages are additional, not a replacement: a Debian box can take
  // either, and the manifest should say so.
  const extra = { debian: entry(deb, 'deb'), redhat: entry(rpm, 'rpm'), arch: entry(arch, 'pacman'), any: entry(single, 'single-file') };
  for (const [k, v] of Object.entries(extra)) if (v) map[k] = v;
  for (const k of Object.keys(map)) if (!map[k]) delete map[k];
  return map;
}

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

const { priv, from, expected } = keyPair();

const artifacts = artifactMap(files, baseUrl);
for (const a of Object.values(artifacts)) a.sha256 = sha256(path.join(DIST, a.file));

// The signed payload is a string, and it is what gets hashed. Serialise once,
// sign those exact bytes, and never re-serialise on the way out.
const payload = JSON.stringify({
  name: 'APEX JediSyslogger',
  version: VERSION,
  released: RELEASED,
  channel,
  notes: typeof notes === 'string' ? notes : undefined,
  artifacts,
}, null, 2);

const signature = crypto.sign(null, Buffer.from(payload, 'utf8'), priv).toString('base64');

// Verify our own output before publishing it, with the public key a shipped
// build would use — not the one we just derived.
const check = crypto.verify(null, Buffer.from(payload, 'utf8'),
  crypto.createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: expected }, format: 'jwk' }),
  Buffer.from(signature, 'base64'));
if (!check) die('self-check failed: the signature does not verify against the expected public key');

const outDir = path.join(DIST, 'publish');
fs.mkdirSync(outDir, { recursive: true });
fs.writeFileSync(path.join(outDir, `${channel}.json`), JSON.stringify({ manifest: payload, signature }, null, 2) + '\n');
for (const a of Object.values(artifacts)) fs.copyFileSync(path.join(DIST, a.file), path.join(outDir, a.file));

process.stderr.write(`\n  signed with the key from ${from}\n`);
process.stderr.write(`  self-check: signature verifies against UPDATE_PUBKEY\n\n`);
process.stderr.write(`  dist/publish/${channel}.json  → ${new URL(`${channel}.json`, 'https://atlasupdate.cybercontrol.tech/')}\n`);
for (const [plat, a] of Object.entries(artifacts))
  process.stderr.write(`    ${plat.padEnd(14)} ${a.file}\n`);
process.stderr.write(`\n  upload dist/publish/ to the web root, keeping ${channel}.json at the top level.\n\n`);
