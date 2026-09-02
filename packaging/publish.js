#!/usr/bin/env node
/*
 * publish.js — push a signed release to the Apex Update Server.
 *
 *   node packaging/publish.js                 publish dist/publish/ to the default channel
 *   node packaging/publish.js --dry-run       show what would happen, touch nothing
 *   node packaging/publish.js --channel beta
 *
 * The server's flow is four calls, and the order is the point: artefacts land in
 * staging, and only attaching the signed manifest turns them into a release.
 *
 *   POST   /api/v1/apps/{slug}/releases                      create
 *   PUT    /api/v1/apps/{slug}/releases/{v}/artifacts/{file} upload, raw body
 *   POST   /api/v1/apps/{slug}/releases/{v}/manifest         attach the signature
 *   POST   /api/v1/apps/{slug}/releases/{v}/publish          make it the channel's latest
 *
 * The API token is never accepted on the command line — argv is visible in `ps`,
 * in shell history and in CI logs. It comes from $APEX_TOKEN, $APEX_TOKEN_FILE,
 * or ~/.config/apex-jedisyslogger/apex.token (mode 600).
 *
 * Node core only.
 */
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const https = require('https');
const crypto = require('crypto');

const ROOT = path.resolve(__dirname, '..');
const { VERSION, UPDATE_APP, UPDATE_CHANNEL, UPDATE_URL } = require('../js/version.js');

const argv = process.argv.slice(2);
const flag = (n, d) => { const i = argv.indexOf(`--${n}`); return i === -1 ? d : (argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[i + 1] : true); };
const DRY = argv.includes('--dry-run');
const CHANNEL = String(flag('channel', UPDATE_CHANNEL || 'stable'));
const SLUG = String(flag('app', UPDATE_APP));
const HOST = new URL(UPDATE_URL).origin;

function die(msg, hint) {
  process.stderr.write(`publish: ${msg}\n`);
  if (hint) process.stderr.write(`         ${hint}\n`);
  process.exit(1);
}

function token() {
  if (process.env.APEX_TOKEN) return process.env.APEX_TOKEN.trim();
  const files = [process.env.APEX_TOKEN_FILE, path.join(os.homedir(), '.config', 'apex-jedisyslogger', 'apex.token')].filter(Boolean);
  for (const f of files) {
    if (!fs.existsSync(f)) continue;
    if (process.platform !== 'win32' && (fs.statSync(f).mode & 0o077))
      die(`${f} is readable by other users`, `chmod 600 "${f}"`);
    return fs.readFileSync(f, 'utf8').trim();
  }
  die('no API token found', 'set $APEX_TOKEN_FILE or write ~/.config/apex-jedisyslogger/apex.token (chmod 600)');
}
const TOKEN = DRY ? 'dry-run' : token();

// ---- transport -------------------------------------------------------------
function request(method, urlPath, { body = null, json = null, headers = {}, stream = null } = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(urlPath, HOST);
    const h = Object.assign({
      Authorization: `Bearer ${TOKEN}`,
      Accept: 'application/json',
      'User-Agent': `apex-jedisyslogger-publisher/${VERSION}`,
    }, headers);
    if (json !== null) { body = Buffer.from(JSON.stringify(json)); h['Content-Type'] = 'application/json'; }
    if (body) h['Content-Length'] = body.length;
    if (stream) { h['Content-Type'] = 'application/octet-stream'; h['Content-Length'] = fs.statSync(stream).size; }

    const req = https.request(u, { method, headers: h }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let parsed = null;
        try { parsed = JSON.parse(text); } catch (e) { /* not json */ }
        resolve({ status: res.statusCode, body: parsed, text });
      });
    });
    req.setTimeout(120000, () => { req.destroy(); reject(new Error(`${method} ${u.pathname} timed out`)); });
    req.on('error', reject);
    if (stream) fs.createReadStream(stream).pipe(req);
    else req.end(body || undefined);
  });
}

const ok = (r) => r.status >= 200 && r.status < 300;
function explain(r) {
  const d = r.body && (r.body.detail || r.body.error || r.body.message);
  return `HTTP ${r.status}${d ? ` — ${typeof d === 'string' ? d : JSON.stringify(d)}` : ''}`;
}

// ---- what each artefact is -------------------------------------------------
// Taken from the signed manifest rather than re-derived from the filename. The
// labels the store indexes and the labels covered by the signature are then the
// same labels, and there is one place that decides them: packaging/sign.js.
function describe(manifest, file) {
  const a = (manifest.artifacts || []).find((x) => x.filename === file);
  if (!a) die(`${file} is in dist/publish but not in the signed manifest`, 're-run sign.js');
  return { platform: a.platform, arch: a.arch, format: a.format };
}

const sha256 = (f) => crypto.createHash('sha256').update(fs.readFileSync(f)).digest('hex');

// ---- main ------------------------------------------------------------------
(async () => {
  const dir = path.join(ROOT, 'dist', 'publish');
  const envelopePath = path.join(dir, `${CHANNEL}.json`);
  if (!fs.existsSync(envelopePath))
    die(`${path.relative(ROOT, envelopePath)} not found`, 'run ./packaging/build.sh then node packaging/sign.js');

  const manifest = JSON.parse(fs.readFileSync(envelopePath, 'utf8'));
  if (!manifest.signature) die('the manifest has no signature', 'run node packaging/sign.js');
  if (manifest.version !== VERSION)
    die(`the signed manifest is for ${manifest.version} but the tree is ${VERSION}`, 're-run sign.js');
  if (manifest.app !== SLUG)
    die(`the signed manifest names app "${manifest.app}" but we are publishing to "${SLUG}"`);

  const files = fs.readdirSync(dir).filter((f) => f !== `${CHANNEL}.json` && f !== 'UPLOAD.txt');

  process.stderr.write(`\n  ${HOST}\n  app ${SLUG} · version ${VERSION} · channel ${CHANNEL}${DRY ? '  (DRY RUN)' : ''}\n\n`);

  if (DRY) {
    for (const f of files) {
      const d = describe(manifest, f);
      process.stderr.write(`  would PUT   ${f}  [${d.platform}/${d.arch}/${d.format}]\n`);
    }
    process.stderr.write(`  would POST  the signed manifest (${manifest.artifacts.length} artefacts)\n`);
    process.stderr.write(`  would POST  publish to ${CHANNEL}\n\n`);
    return;
  }

  // Fail fast on a bad or wrongly-scoped token, before anything is created.
  const who = await request('GET', '/api/v1/token');
  if (!ok(who)) die(`the API token was rejected: ${explain(who)}`);
  const scopes = (who.body && who.body.scopes) || [];
  for (const need of ['upload', 'publish'])
    if (!scopes.includes(need)) die(`this token lacks the "${need}" scope (has: ${scopes.join(', ') || 'none'})`);
  if (who.body.app && who.body.app !== SLUG)
    die(`this token is scoped to app "${who.body.app}", not "${SLUG}"`);
  process.stderr.write(`  token "${who.body.name}" ok — ${scopes.join(', ')}\n`);

  // 1. create
  let r = await request('POST', `/api/v1/apps/${SLUG}/releases`, {
    json: { version: VERSION, channel: CHANNEL, notes: manifest.notes || '' },
  });
  if (ok(r)) process.stderr.write(`  created release ${VERSION}\n`);
  else if (r.status === 409 || /exists/i.test(r.text)) process.stderr.write(`  release ${VERSION} already exists — continuing\n`);
  else die(`could not create the release: ${explain(r)}`);

  // 2. artefacts
  for (const f of files) {
    const full = path.join(dir, f);
    const d = describe(manifest, f);
    const digest = sha256(full);
    r = await request('PUT', `/api/v1/apps/${SLUG}/releases/${encodeURIComponent(VERSION)}/artifacts/${encodeURIComponent(f)}`, {
      stream: full,
      headers: { 'X-Apex-Platform': d.platform, 'X-Apex-Arch': d.arch, 'X-Apex-Format': d.format, 'X-Apex-Sha256': digest },
    });
    if (!ok(r)) die(`upload of ${f} failed: ${explain(r)}`);
    const size = (fs.statSync(full).size / 1024).toFixed(0);
    process.stderr.write(`  uploaded ${f.padEnd(40)} ${size.padStart(5)} KB  ${digest.slice(0, 12)}…\n`);
  }

  // 3. attach the signature — this is what makes it a release
  r = await request('POST', `/api/v1/apps/${SLUG}/releases/${encodeURIComponent(VERSION)}/manifest`, { json: manifest });
  if (!ok(r)) die(`attaching the signed manifest failed: ${explain(r)}`,
    'if the server rejected the signature, the private key does not match the app\'s publisher_key');
  process.stderr.write(`  attached the signed manifest\n`);

  // 4. publish
  r = await request('POST', `/api/v1/apps/${SLUG}/releases/${encodeURIComponent(VERSION)}/publish`, { json: { channel: CHANNEL } });
  if (!ok(r)) die(`publish failed: ${explain(r)}`);
  process.stderr.write(`  published to ${CHANNEL}\n\n  verify with:  ./packaging/verify-published.sh\n\n`);
})().catch((e) => die(e.message));
