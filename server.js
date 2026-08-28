#!/usr/bin/env node
/*
 * server.js — APEX_JediSyslogger companion backend (zero dependencies).
 *
 * Why this exists: a browser page cannot open raw UDP/TCP sockets, so it can
 * never send real syslog to a collector on its own. This tiny Node server does
 * two jobs:
 *   1. Serves the static web app.
 *   2. Exposes POST /forward — the browser posts the generated raw syslog
 *      lines here and this process relays them as REAL UDP or TCP syslog
 *      datagrams to the collector IP:port you configured in the UI, or as
 *      Splunk HTTP Event Collector (HEC) events when the protocol is "hec".
 *   3. Gates all of it behind a password + TOTP two-factor sign-in, with
 *      multiple accounts, per-user Log Collector settings, and a management
 *      API for admins (auth.js).
 *
 * Run:  node server.js            (then open http://localhost:8099)
 *       PORT=9000 node server.js
 *       node server.js --help     (credential management)
 */
'use strict';
const http = require('http');
const https = require('https');
const dgram = require('dgram');
const net = require('net');
const fs = require('fs');
const path = require('path');
const authlib = require('./auth');
const qrlib = require('./js/qr.js');

const ROOT = __dirname;
const PORT = parseInt(process.env.PORT, 10) || 8099;

// Auth is on unless explicitly disabled. JEDI_AUTH=off restores the old
// no-sign-in behaviour for a throwaway local run.
const AUTH_ON = String(process.env.JEDI_AUTH || '').toLowerCase() !== 'off';
const SECURE_COOKIE = process.env.JEDI_SECURE_COOKIE === '1';

const MIME = {
  '.html': 'text/html; charset=utf-8', '.css': 'text/css', '.js': 'text/javascript',
  '.json': 'application/json', '.log': 'text/plain', '.txt': 'text/plain',
  '.svg': 'image/svg+xml', '.ico': 'image/x-icon', '.map': 'application/json',
};

let totalForwarded = 0;

// Set once the listener starts; the CLI paths below never touch it.
let auth = null;

// Reachable without a session: the sign-in page, the stylesheet it needs, and
// the endpoints that hand out a session in the first place.
const PUBLIC_PATHS = new Set(['/login.html', '/js/login.js', '/js/qr.js', '/css/styles.css', '/auth/login', '/auth/totp', '/auth/logout', '/auth/session']);

const server = http.createServer((req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }

  const urlPath = req.url.split('?')[0];

  if (req.method === 'POST' && urlPath === '/auth/login') return handleLogin(req, res);
  if (req.method === 'POST' && urlPath === '/auth/totp') return handleTotp(req, res);
  if (req.method === 'POST' && urlPath === '/auth/logout') return handleLogout(req, res);
  if (req.method === 'GET' && urlPath === '/auth/session') return handleSession(req, res);

  const session = AUTH_ON ? auth.sessionFor(req.headers.cookie) : { user: null, anonymous: true };
  if (AUTH_ON && !session && !PUBLIC_PATHS.has(urlPath)) return denyAnonymous(req, res, urlPath);
  // Already signed in? The sign-in page has nothing left to offer.
  if (AUTH_ON && session && urlPath === '/login.html') { res.writeHead(302, { Location: '/' }); return res.end(); }

  if (urlPath.startsWith('/api/')) return handleApi(req, res, urlPath, session);
  if (req.method === 'POST' && urlPath === '/forward') return handleForward(req, res);
  if (req.method === 'POST' && urlPath === '/test') return handleTest(req, res);
  if (req.method === 'GET' && urlPath === '/status') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ ok: true, backend: 'jedisyslogger', forwarded: totalForwarded }));
  }
  return serveStatic(req, res);
});

// A browser navigating to a page gets sent to the sign-in form; anything else
// (fetch, curl, the forwarding relay) gets a JSON 401 it can act on.
function denyAnonymous(req, res, urlPath) {
  if (String(req.headers.accept || '').includes('text/html')) {
    res.writeHead(302, { Location: `/login.html?next=${encodeURIComponent(urlPath)}` });
    return res.end();
  }
  return sendJson(res, 401, { ok: false, error: 'not signed in — reload the page and sign in again' });
}

// ---- Sign-in endpoints -----------------------------------------------------

function readJson(req, res, limit, cb) {
  let body = '';
  req.on('data', (c) => { body += c; if (body.length > limit) req.destroy(); });
  req.on('end', () => {
    try { cb(JSON.parse(body || '{}')); }
    catch (e) { sendJson(res, 400, { ok: false, error: 'bad json' }); }
  });
}

// Step 1: username + password. A correct password does not sign you in on its
// own — it returns a short-lived token for the second factor.
function handleLogin(req, res) {
  readJson(req, res, 1e5, (p) => {
    if (!AUTH_ON) return sendJson(res, 200, { ok: true, stage: 'done', authRequired: false });
    const r = auth.login(p.user, p.pass);
    console.log(`  🔑 sign-in attempt for "${String(p.user || '').slice(0, 40)}" → ${r.ok ? r.stage : 'DENIED (' + r.error + ')'}`);
    sendJson(res, r.ok ? 200 : (r.locked ? 429 : 401), r);
  });
}

// Step 2: the six-digit code. Only this hands out the session cookie.
function handleTotp(req, res) {
  readJson(req, res, 1e5, (p) => {
    if (!AUTH_ON) return sendJson(res, 200, { ok: true, authRequired: false });
    const r = auth.verifyTotp(p.pending, p.code);
    if (!r.ok) {
      console.log(`  🔑 second factor DENIED (${r.error})`);
      return sendJson(res, r.locked ? 429 : 401, r);
    }
    console.log(`  🔑 "${r.user}" signed in (session valid ${Math.round((r.expires - Date.now()) / 3600000)}h)`);
    res.setHeader('Set-Cookie', authlib.sessionCookie(r.sid, SECURE_COOKIE));
    // The session id travels in the HttpOnly cookie only, never in the body.
    sendJson(res, 200, { ok: true, user: r.user, expires: r.expires });
  });
}

function handleLogout(req, res) {
  if (AUTH_ON) auth.logout(req.headers.cookie);
  res.setHeader('Set-Cookie', authlib.clearCookie());
  sendJson(res, 200, { ok: true });
}

function handleSession(req, res) {
  if (!AUTH_ON) return sendJson(res, 200, { ok: true, authRequired: false, user: null });
  const s = auth.sessionFor(req.headers.cookie);
  sendJson(res, 200, {
    ok: true, authRequired: true,
    user: s ? s.user : null, role: s ? s.role : null, expires: s ? s.expires : null,
    // Only someone already signed in is told the password is still the default.
    passwordIsDefault: s ? !!s.account.passwordIsDefault : undefined,
  });
}

// ---- Profile and user management -------------------------------------------
// Everything under /api needs a session; the /api/users/* half needs an admin.
function handleApi(req, res, urlPath, session) {
  if (!AUTH_ON) return sendJson(res, 501, { ok: false, error: 'user management needs the sign-in enabled (JEDI_AUTH is off)' });
  if (!session) return sendJson(res, 401, { ok: false, error: 'not signed in' });
  const me = session.account;
  const isAdmin = me.role === 'admin';
  const body = (cb) => readJson(req, res, 1e5, cb);

  // — own profile —
  if (req.method === 'GET' && urlPath === '/api/profile') {
    return sendJson(res, 200, {
      ok: true,
      profile: authlib.publicUser(me),
      collector: auth.getCollector(me.id),
      userCount: auth.users.length,
    });
  }

  // The collector panel writes here on every edit, so a session resumes with the
  // destination the last one was pointed at.
  if (req.method === 'PUT' && urlPath === '/api/profile/collector') {
    return body((p) => {
      const r = auth.setCollector(me.id, p.collector || p);
      sendJson(res, r.ok ? 200 : 400, r);
    });
  }

  if (req.method === 'POST' && urlPath === '/api/profile/password') {
    return body((p) => {
      const r = auth.changeOwnPassword(me.id, p.current, p.next, session.sid);
      if (r.ok) console.log(`  🔑 "${me.user}" changed their own password`);
      sendJson(res, r.ok ? 200 : 400, r);
    });
  }

  // Re-enrolling your own second factor also asks for the password: the point of
  // the factor is lost if a borrowed session can silently swap it.
  if (req.method === 'POST' && urlPath === '/api/profile/totp') {
    return body((p) => {
      if (!auth.verifyPassword(me.id, p.password)) {
        return sendJson(res, 400, { ok: false, error: 'Enter your current password to reset the second factor' });
      }
      const r = auth.resetTotp(me.id);
      console.log(`  🔑 "${me.user}" reset their own second factor`);
      sendJson(res, 200, r);
    });
  }

  // — user management —
  if (urlPath.startsWith('/api/users')) {
    if (!isAdmin) return sendJson(res, 403, { ok: false, error: 'That needs an admin account' });

    if (req.method === 'GET' && urlPath === '/api/users') {
      return sendJson(res, 200, { ok: true, users: auth.list(), me: me.id });
    }
    if (req.method === 'POST' && urlPath === '/api/users') {
      return body((p) => {
        const r = auth.createUser(p.user, p.password, p.role);
        if (r.ok) console.log(`  🔑 "${me.user}" created the account "${r.user.user}" (${r.user.role})`);
        sendJson(res, r.ok ? 200 : 400, r);
      });
    }

    // /api/users/<id>[/password|/totp|/role]
    const parts = urlPath.split('/').filter(Boolean);   // ['api','users',id,action?]
    const id = parts[2];
    const action = parts[3];
    const target = id ? auth.byId(id) : null;
    if (!target) return sendJson(res, 404, { ok: false, error: 'No such user' });

    if (req.method === 'DELETE' && !action) {
      const r = auth.deleteUser(id, me.id);
      if (r.ok) console.log(`  🔑 "${me.user}" deleted the account "${target.user}"`);
      return sendJson(res, r.ok ? 200 : 400, r);
    }
    if (req.method === 'POST' && action === 'password') {
      return body((p) => {
        const r = auth.setPassword(id, p.password);
        if (r.ok) console.log(`  🔑 "${me.user}" set a new password for "${target.user}"`);
        sendJson(res, r.ok ? 200 : 400, r);
      });
    }
    if (req.method === 'POST' && action === 'totp') {
      const r = auth.resetTotp(id);
      console.log(`  🔑 "${me.user}" reset the second factor for "${target.user}"`);
      // An admin resetting someone else is told nothing secret: that user enrols
      // from the QR their own next sign-in shows them.
      return sendJson(res, 200, { ok: r.ok, user: target.user });
    }
    if (req.method === 'POST' && action === 'role') {
      return body((p) => {
        const r = auth.setRole(id, p.role, me.id);
        if (r.ok) console.log(`  🔑 "${me.user}" made "${target.user}" a ${r.user.role}`);
        sendJson(res, r.ok ? 200 : 400, r);
      });
    }
  }

  sendJson(res, 404, { ok: false, error: `no such endpoint: ${req.method} ${urlPath}` });
}

function handleForward(req, res) {
  let body = '';
  req.on('data', (c) => { body += c; if (body.length > 8e6) req.destroy(); });
  req.on('end', () => {
    let p;
    try { p = JSON.parse(body); } catch (e) { res.writeHead(400); return res.end('{"ok":false,"error":"bad json"}'); }
    const lines = Array.isArray(p.lines) ? p.lines : [];
    const events = Array.isArray(p.events) ? p.events : [];
    const proto = (p.proto || 'udp').toLowerCase();
    const done = (err, sent) => {
      totalForwarded += sent;
      const dest = proto === 'hec' ? hecUrl(p) : `${p.ip}:${parseInt(p.port, 10) || 514}/${proto}`;
      const unit = proto === 'hec' ? 'event(s)' : 'line(s)';
      if (err) console.log(`  ✗ forward FAILED to ${dest}: ${err.message || err}`);
      else console.log(`  → forwarded ${sent} ${unit} to ${dest}${proto === 'udp' ? ' (UDP: no delivery confirmation)' : ''}`);
      res.writeHead(err ? 502 : 200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: !err, sent, total: totalForwarded, error: err ? String(err.message || err) : null }));
    };
    if (proto === 'hec') return forwardHec(p, events, done);
    forwardLines(p.ip, p.port, proto, lines, done);
  });
}

// ---- Connectivity test ----------------------------------------------------
// Probe whether the configured collector IP:port is reachable. TCP gives a
// definitive answer (connect succeeds/refused/times out). UDP is connectionless
// so we send a probe and watch for an ICMP port-unreachable (surfaced as an
// ECONNREFUSED error on a connected UDP socket, works on Linux).
function handleTest(req, res) {
  let body = '';
  req.on('data', (c) => { body += c; if (body.length > 1e5) req.destroy(); });
  req.on('end', () => {
    let p; try { p = JSON.parse(body); } catch (e) { return sendJson(res, 400, { ok: false, reachable: false, message: 'bad json' }); }
    const ip = (p.ip || '').trim();
    const proto = (p.proto || 'udp').toLowerCase();
    const port = parseInt(p.port, 10) || (proto === 'hec' ? 8088 : 514);
    if (!ip) return sendJson(res, 400, { ok: false, reachable: false, message: 'no collector IP set' });
    const done = (r) => { console.log(`  ⟲ test ${ip}:${port}/${proto} → ${r.reachable ? 'OK' : (r.warn ? 'inconclusive' : 'FAIL')}: ${r.message}`); sendJson(res, 200, r); };
    if (proto === 'hec') testHec(p, done);
    else if (proto === 'tcp') testTcp(ip, port, done);
    else testUdp(ip, port, done);
  });
}

function errMessage(e, ip, port, proto) {
  const map = {
    ECONNREFUSED: `Connection refused — ${ip} is reachable but nothing is listening on ${proto.toUpperCase()} ${port}`,
    ETIMEDOUT: `Timed out — a firewall or routing is dropping traffic to ${ip}:${port}`,
    EHOSTUNREACH: `Host unreachable — no route to ${ip}`,
    ENETUNREACH: `Network unreachable — no route to ${ip}`,
    ENOTFOUND: `Cannot resolve host "${ip}"`,
    EACCES: `Permission denied for ${ip}:${port}`,
  };
  return map[e && e.code] || `${proto.toUpperCase()} error ${(e && (e.code || e.message)) || 'unknown'} for ${ip}:${port}`;
}

function testTcp(ip, port, cb) {
  const start = Date.now();
  const socket = net.connect(port, ip);
  let done = false;
  const fin = (r) => { if (done) return; done = true; try { socket.destroy(); } catch (e) {} cb(Object.assign({ proto: 'tcp', ms: Date.now() - start }, r)); };
  socket.setTimeout(4000);
  socket.on('connect', () => fin({ ok: true, reachable: true, message: `TCP connect to ${ip}:${port} succeeded — host reachable and port open` }));
  socket.on('timeout', () => fin({ ok: false, reachable: false, code: 'ETIMEDOUT', message: `TCP connect to ${ip}:${port} timed out — likely a firewall dropping traffic` }));
  socket.on('error', (e) => fin({ ok: false, reachable: false, code: e.code, message: errMessage(e, ip, port, 'tcp') }));
}

function testUdp(ip, port, cb) {
  const start = Date.now();
  const sock = dgram.createSocket('udp4');
  let done = false, timer = null;
  const fin = (r) => { if (done) return; done = true; if (timer) clearTimeout(timer); try { sock.close(); } catch (e) {} cb(Object.assign({ proto: 'udp', ms: Date.now() - start }, r)); };
  sock.on('error', (e) => {
    if (e.code === 'ECONNREFUSED') fin({ ok: false, reachable: false, code: e.code, message: `ICMP port-unreachable from ${ip} — nothing listening on UDP ${port}` });
    else fin({ ok: false, reachable: false, code: e.code, message: errMessage(e, ip, port, 'udp') });
  });
  try {
    sock.connect(port, ip, () => {
      sock.send(Buffer.from('<14>jedisyslogger connectivity probe'), (e) => { if (e) fin({ ok: false, reachable: false, code: e.code, message: errMessage(e, ip, port, 'udp') }); });
      timer = setTimeout(() => fin({ ok: true, reachable: null, warn: true, message: `UDP probe sent to ${ip}:${port} — no ICMP error (port is open OR filtered; UDP cannot confirm receipt). Switch to TCP to verify, or run tcpdump on the collector.` }), 1500);
    });
  } catch (e) { fin({ ok: false, reachable: false, code: e.code, message: errMessage(e, ip, port, 'udp') }); }
}

function sendJson(res, code, obj) { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(obj)); }

// Relay raw syslog lines to the collector over UDP (fire-and-forget) or TCP
// (newline-framed, RFC 6587 non-transparent framing).
function forwardLines(ip, port, proto, lines, cb) {
  port = parseInt(port, 10) || 514;
  if (!ip || !lines.length) return cb(null, 0);

  if (proto === 'tcp') {
    const socket = net.connect(port, ip);
    let done = false;
    const finish = (err, n) => { if (done) return; done = true; try { socket.destroy(); } catch (e) {} cb(err, n); };
    socket.setTimeout(4000);
    socket.on('connect', () => {
      socket.write(lines.map((l) => l + '\n').join(''), () => finish(null, lines.length));
    });
    socket.on('timeout', () => finish(new Error('tcp connect/write timeout'), 0));
    socket.on('error', (e) => finish(e, 0));
    return;
  }

  // UDP: one datagram per line.
  const sock = dgram.createSocket('udp4');
  let sent = 0, failed = null, pending = lines.length;
  const done = () => { try { sock.close(); } catch (e) {} cb(failed && sent === 0 ? failed : null, sent); };
  sock.on('error', (e) => { if (!failed) failed = e; });
  lines.forEach((line) => {
    sock.send(Buffer.from(line, 'utf8'), port, ip, (e) => {
      if (e) { if (!failed) failed = e; } else { sent++; }
      if (--pending === 0) done();
    });
  });
}

// ---- Splunk HTTP Event Collector (HEC) ------------------------------------
// HEC is not syslog: it is an HTTP(S) POST to /services/collector/event with an
// "Authorization: Splunk <token>" header and a body of concatenated JSON
// envelopes — {time, host, source, sourcetype, index, event}. Splunk answers
// 200 {"text":"Success","code":0}, or a code that says exactly what is wrong.
// Any SIEM that speaks the HEC API (Splunk, Cribl, Splunk Cloud) accepts this.
const HEC_PATH = '/services/collector/event';

const HEC_CODES = {
  1: 'token disabled', 2: 'token is required', 3: 'invalid authorization',
  4: 'invalid token', 5: 'no data', 6: 'invalid data format', 7: 'incorrect index',
  8: 'internal server error', 9: 'server is busy', 10: 'data channel is missing',
  11: 'invalid data channel', 12: 'event field is required', 13: 'event field cannot be blank',
  14: 'ACK is disabled', 15: 'error in handling indexed fields',
  16: 'query string authorization is not enabled',
};

function hecUrl(p) {
  const cfg = p.hec || {};
  return `${cfg.ssl === false ? 'http' : 'https'}://${p.ip}:${parseInt(p.port, 10) || 8088}${HEC_PATH}`;
}

// One HEC envelope per generated line. The raw syslog line goes in `event` as a
// string so Splunk indexes it verbatim; undefined keys are dropped by stringify,
// so a blank index/host simply falls back to the token's defaults.
function hecEnvelope(cfg, e) {
  return JSON.stringify({
    time: typeof e.time === 'number' ? e.time : undefined,
    host: e.host || undefined,
    source: 'jedisyslogger',
    sourcetype: cfg.sourcetype || 'syslog',
    index: cfg.index || undefined,
    event: e.raw,
  });
}

// TLS and HTTP mistakes are the two ways HEC setup goes wrong; name both.
function hecError(e, ip, port, cfg) {
  const code = (e && e.code) || '';
  const msg = (e && e.message) || '';
  if (code === 'EPROTO' || /wrong version number/i.test(msg))
    return new Error(`TLS handshake failed at ${ip}:${port} — that port is plain HTTP; untick HTTPS`);
  if (/SELF_SIGNED|UNABLE_TO_VERIFY|CERT_HAS_EXPIRED|ALTNAME/.test(code))
    return new Error(`TLS certificate rejected (${code}) — tick "skip cert" to accept Splunk's self-signed certificate`);
  if (code === 'ECONNRESET' && cfg.ssl === false)
    return new Error(`Connection reset by ${ip}:${port} — HEC is probably expecting HTTPS; tick HTTPS`);
  return new Error(errMessage(e, ip, port, cfg.ssl === false ? 'http' : 'https'));
}

function hecPost(p, body, cb) {
  const cfg = p.hec || {};
  const ip = (p.ip || '').trim();
  const port = parseInt(p.port, 10) || 8088;
  if (!ip) return cb(new Error('no collector host set'));
  if (!cfg.token) return cb(new Error('HEC token required — create one under Settings › Data inputs › HTTP Event Collector'));
  const mod = cfg.ssl === false ? http : https;
  const opts = {
    host: ip, port, path: HEC_PATH, method: 'POST',
    headers: {
      Authorization: `Splunk ${cfg.token}`,
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(body),
    },
  };
  // Splunk ships a self-signed HEC certificate, so verification is opt-in.
  if (mod === https) opts.rejectUnauthorized = cfg.insecure === false;
  let done = false;
  const fin = (err, r) => { if (done) return; done = true; cb(err, r); };
  const request = mod.request(opts, (resp) => {
    let out = '';
    resp.on('data', (c) => { out += c; if (out.length > 1e5) resp.destroy(); });
    resp.on('end', () => {
      let j = null; try { j = JSON.parse(out); } catch (e) {}
      const code = j && typeof j.code === 'number' ? j.code : null;
      if (resp.statusCode === 200 && (code === 0 || code === null)) return fin(null, { text: (j && j.text) || 'Success', code });
      const why = (j && j.text) || HEC_CODES[code] || `HTTP ${resp.statusCode}`;
      fin(new Error(`Splunk HEC rejected the batch — ${why}${code != null ? ` (code ${code})` : ''}`));
    });
  });
  request.setTimeout(8000, () => { request.destroy(); fin(new Error(`HEC request to ${ip}:${port} timed out`)); });
  request.on('error', (e) => fin(hecError(e, ip, port, cfg)));
  request.end(body);
}

function forwardHec(p, events, cb) {
  if (!events.length) return cb(null, 0);
  const body = events.map((e) => hecEnvelope(p.hec || {}, e)).join('\n');
  hecPost(p, body, (err) => cb(err, err ? 0 : events.length));
}

// The HEC probe is a real (indexed) test event, so unlike the TCP/UDP probes it
// also proves the token, the index and the TLS settings are right.
function testHec(p, cb) {
  const start = Date.now();
  const cfg = p.hec || {};
  const probe = { time: Date.now() / 1000, host: 'jedisyslogger', raw: '<14>jedisyslogger HEC connectivity probe' };
  hecPost(p, hecEnvelope(cfg, probe), (err, r) => {
    const ms = Date.now() - start;
    if (err) return cb({ ok: false, reachable: false, proto: 'hec', ms, message: err.message });
    cb({
      ok: true, reachable: true, proto: 'hec', ms, code: r.code,
      message: `HEC accepted a test event at ${hecUrl(p)} — token valid, indexing into ` +
        `${cfg.index || "the token's default index"} as sourcetype ${cfg.sourcetype || 'syslog'}`,
    });
  });
}

// Files that must never be served, however the request is spelled: auth.json
// holds the password hash and the TOTP secret, and a dotfile is never app content.
const PRIVATE_FILES = new Set(['auth.json']);

function serveStatic(req, res) {
  let urlPath = decodeURIComponent(req.url.split('?')[0]);
  if (urlPath === '/') urlPath = '/index.html';
  const filePath = path.normalize(path.join(ROOT, urlPath));
  if (!filePath.startsWith(ROOT)) { res.writeHead(403); return res.end('forbidden'); }
  const base = path.basename(filePath);
  if (PRIVATE_FILES.has(base) || base.startsWith('.')) { res.writeHead(403); return res.end('forbidden'); }
  fs.readFile(filePath, (err, data) => {
    if (err) { res.writeHead(404, { 'Content-Type': 'text/plain' }); return res.end('not found'); }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(filePath).toLowerCase()] || 'application/octet-stream' });
    res.end(data);
  });
}

// ---- Credential management CLI --------------------------------------------
// Returns true when it handled an argument, so the caller knows not to listen.
function runCli(argv) {
  const has = (f) => argv.includes(f);
  if (!argv.length) return false;

  // Non-flag arguments that follow a flag, e.g. --set-password alice hunter2222
  const after = (flag) => {
    const out = [];
    for (let i = argv.indexOf(flag) + 1; i < argv.length && !argv[i].startsWith('--'); i++) out.push(argv[i]);
    return out;
  };
  const fail = (msg) => { console.log(`\n  ✗ ${msg}\n`); process.exitCode = 1; return true; };

  if (has('--help') || has('-h')) {
    console.log(`
  APEX JediSyslogger — backend

    node server.js                             serve the app on ${PORT} (PORT=n to change)
    node server.js --list-users                every account, its role and 2FA state
    node server.js --add-user <name> <pw> [--admin]
    node server.js --delete-user <name>
    node server.js --set-password [user] <pw>  replace a password (default: the first admin)
    node server.js --reset-2fa [user]          issue a new TOTP secret (lost authenticator)
    node server.js --reset-auth                wipe every account back to the default admin
    node auth.js   --selftest                  check the Base32/TOTP maths against the RFCs
    node js/qr.js  --selftest                  check the QR encoder against ISO/IEC 18004

  JEDI_AUTH=off          run with no sign-in at all (local throwaway use)
  JEDI_SECURE_COOKIE=1   add Secure to the session cookie (behind a TLS proxy)

  Users are also managed in the app: sign in as an admin and open Account.
`);
    return true;
  }

  if (has('--reset-auth')) {
    try { fs.unlinkSync(authlib.STORE); } catch (e) {}
    const a = new authlib.Auth(true);
    console.log(`\n  ✓ every account wiped; back to the documented default admin`);
    printAccounts(a, true);
    return true;
  }

  const a = new authlib.Auth(true);
  const firstAdmin = () => a.admins()[0] || a.users[0];

  if (has('--list-users')) { printAccounts(a, false); return true; }

  if (has('--add-user')) {
    const [name, pw, ...rest] = after('--add-user');
    if (!name || !pw) return fail(`usage: node server.js --add-user <name> '<password>' [--admin]`);
    const r = a.createUser(name, pw, has('--admin') || rest.includes('admin') ? 'admin' : 'user');
    if (!r.ok) return fail(r.error);
    console.log(`\n  ✓ created "${r.user.user}" (${r.user.role}) — they enrol their own second factor on first sign-in`);
    console.log(`    Restart the server to apply it.\n`);
    return true;
  }

  if (has('--delete-user')) {
    const [name] = after('--delete-user');
    if (!name) return fail(`usage: node server.js --delete-user <name>`);
    const u = a.byName(name);
    if (!u) return fail(`no such user: ${name}`);
    const r = a.deleteUser(u.id, null);
    if (!r.ok) return fail(r.error);
    console.log(`\n  ✓ deleted "${u.user}"`);
    console.log(`    Restart the server to apply it.\n`);
    return true;
  }

  if (has('--set-password')) {
    const args = after('--set-password');
    // One argument is the password for the first admin; two name the user too.
    const [name, pw] = args.length >= 2 ? args : [null, args[0]];
    if (!pw) return fail(`usage: node server.js --set-password [user] '<new password>'`);
    const u = name ? a.byName(name) : firstAdmin();
    if (!u) return fail(`no such user: ${name}`);
    const r = a.setPassword(u.id, pw);
    if (!r.ok) return fail(r.error);
    console.log(`\n  ✓ password updated for "${u.user}"`);
    console.log(`    Restart the server to apply it — a running process keeps the old`);
    console.log(`    credentials in memory, and its open sessions stay valid until then.\n`);
    return true;
  }

  if (has('--reset-2fa')) {
    const [name] = after('--reset-2fa');
    const u = name ? a.byName(name) : firstAdmin();
    if (!u) return fail(`no such user: ${name}`);
    const e = a.resetTotp(u.id);
    console.log(`\n  ✓ new TOTP secret issued for "${u.user}" — the old authenticator entry is dead`);
    printEnrolment(e);
    return true;
  }

  if (has('--show-auth')) { printAccounts(a, false); return true; }

  return fail(`unknown option: ${argv.find((x) => x.startsWith('--')) || argv[0]} — try --help`);
}

function printEnrolment(e) {
  console.log(`\n    Scan this with your authenticator app:\n`);
  // Black ink on a forced white background, so it scans whatever the terminal
  // theme is — and it survives into the pm2 log for a headless install.
  try {
    console.log(qrlib.toAnsi(qrlib.encode(e.uri), { indent: '      ' }));
  } catch (err) {
    console.log(`      ${e.uri}`);
  }
  console.log(`
    …or enter it by hand:

      account   ${authlib.ISSUER}
      secret    ${e.pretty}
      type      time-based, SHA-1, 6 digits, 30 seconds
`);
}

function printAccounts(a, showDefaultPassword) {
  const pad = (s, n) => String(s).padEnd(n);
  console.log(`\n    ${pad('user', 20)}${pad('role', 8)}${pad('password', 22)}second factor`);
  console.log(`    ${'─'.repeat(66)}`);
  for (const u of a.list()) {
    console.log(`    ${pad(u.user, 20)}${pad(u.role, 8)}` +
      `${pad(u.passwordIsDefault ? 'DEFAULT — change it' : 'set', 22)}` +
      `${u.totpConfirmed ? 'enrolled' : 'not enrolled yet'}`);
  }
  console.log(`\n    stored in ${authlib.STORE}`);
  if (showDefaultPassword) console.log(`    default password: ${authlib.DEFAULT_PASSWORD}`);
  console.log('');
  // Anyone still unenrolled needs their secret, and a headless install has no
  // other way to see it.
  for (const p of a.list()) {
    if (p.totpConfirmed) continue;
    const u = a.byId(p.id);
    console.log(`    "${u.user}" has no second factor yet:`);
    printEnrolment(a.enrolmentFor(u));
  }
}

// A credential-management argument runs and exits; otherwise, serve.
if (!runCli(process.argv.slice(2))) start();

function start() {
  auth = new authlib.Auth(AUTH_ON);
  server.listen(PORT, () => {
    console.log(`\n  ⚔️  APEX JediSyslogger running → http://localhost:${PORT}`);
    console.log(`      POST /forward relays syslog to your configured collector (UDP/TCP/Splunk HEC).`);
    if (!AUTH_ON) {
      console.log(`      🔓 JEDI_AUTH=off — NO SIGN-IN REQUIRED, anyone who can reach this port is in.`);
      console.log(`      Press Ctrl+C to stop.\n`);
      return;
    }
    const accounts = auth.list();
    const admins = accounts.filter((u) => u.role === 'admin').length;
    console.log(`      🔒 Sign-in required: ${accounts.length} account(s), ${admins} admin(s),` +
      ` each with a 6-digit authenticator code.`);
    const stale = accounts.filter((u) => u.passwordIsDefault);
    if (stale.length) {
      console.log(`      ⚠  Still on the documented default password (${authlib.DEFAULT_PASSWORD}):` +
        ` ${stale.map((u) => `"${u.user}"`).join(', ')}`);
      console.log(`         Change it in the app (Account) or:  node server.js --set-password '<new password>'`);
    }
    // A headless install has no other way to see an enrolment secret.
    for (const p of accounts.filter((u) => !u.totpConfirmed)) {
      console.log(`      ⚠  "${p.user}" has no second factor yet — enrol on the next sign-in, or now:`);
      printEnrolment(auth.enrolmentFor(auth.byId(p.id)));
    }
    console.log(`      Press Ctrl+C to stop.\n`);
  });
}
