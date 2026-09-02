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
 *   4. Serves over HTTPS when a certificate and key are present — passwords and
 *      authenticator codes should not cross a network in the clear.
 *
 * Run:  node server.js            (then open http://localhost:8099)
 *       PORT=9000 node server.js
 *       node server.js --help     (credential management)
 */
'use strict';
const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const authlib = require('./auth');
const qrlib = require('./js/qr.js');
// The relays and probes live in forward.js so the terminal app (jedi-cli.js)
// sends over exactly the same code paths this server does.
const { forwardLines, forwardHec, testTcp, testUdp, testHec, hecUrl } = require('./forward.js');
const { VERSION } = require('./js/version.js');

const ROOT = __dirname;
const PORT = process.env.PORT !== undefined ? parseInt(process.env.PORT, 10) : 8099;
// Desktop mode: the app is a window on this machine, not a service on a network.
// It binds to loopback, picks its own port, and hands the window a one-shot
// ticket instead of a sign-in page — the person is already sitting at the
// machine that holds the credential store.
const DESKTOP = process.env.JEDI_DESKTOP === '1';
const BIND = process.env.JEDI_BIND || (DESKTOP ? '127.0.0.1' : undefined);
// Regenerated per launch, single use, never written anywhere.
let launchTicket = DESKTOP ? require('crypto').randomBytes(32).toString('base64url') : null;
// Liveness. The window is the application, so the *page* says whether it is
// still there — not the browser process, which may have handed our URL to an
// already-running instance and exited a millisecond later.
const BEAT_GRACE_MS = 15000;
let lastBeat = 0;
let beatSeen = false;

// Auth is on unless explicitly disabled. JEDI_AUTH=off restores the old
// no-sign-in behaviour for a throwaway local run.
const AUTH_ON = String(process.env.JEDI_AUTH || '').toLowerCase() !== 'off';

// TLS: point these at a certificate and key, or drop them in certs/ next to this
// file. With both present the listener is HTTPS; with neither it is plain HTTP,
// exactly as before.
const TLS_CERT = process.env.JEDI_TLS_CERT || path.join(ROOT, 'certs', 'server.crt');
const TLS_KEY = process.env.JEDI_TLS_KEY || path.join(ROOT, 'certs', 'server.key');
// Optional second listener that does nothing but bounce http:// to https://.
const REDIRECT_PORT = parseInt(process.env.JEDI_HTTP_REDIRECT_PORT, 10) || 0;

let tls = null;                 // the loaded key pair, or null for plain HTTP
// A Secure cookie is never stored over plain HTTP, so it can only be set once
// TLS is actually on. JEDI_SECURE_COOKIE forces it for a TLS proxy in front.
let SECURE_COOKIE = process.env.JEDI_SECURE_COOKIE === '1';

function loadTls() {
  try {
    if (!fs.existsSync(TLS_CERT) || !fs.existsSync(TLS_KEY)) return null;
    return { cert: fs.readFileSync(TLS_CERT), key: fs.readFileSync(TLS_KEY) };
  } catch (e) {
    console.log(`  ⚠ TLS files unreadable (${e.code || e.message}) — serving plain HTTP instead`);
    return null;
  }
}

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
// Reachable before a session exists, but only in desktop mode, where the server
// is bound to loopback and the ticket was minted by this very process.
if (DESKTOP) PUBLIC_PATHS.add('/launch');

// Spend the launch ticket for a session. Loopback-only and single-use: the
// ticket is minted in memory at startup, printed to this process's own stdout
// for its launcher to read, and burned the first time it is presented.
function handleLaunch(req, res, url) {
  const given = url.searchParams.get('t') || '';
  const ok = launchTicket && given.length === launchTicket.length &&
    require('crypto').timingSafeEqual(Buffer.from(given), Buffer.from(launchTicket));
  launchTicket = null;                       // one shot, valid or not
  if (!ok) {
    res.writeHead(403, { 'Content-Type': 'text/plain' });
    return res.end('This launch link has already been used. Close the window and start the app again.\n');
  }
  if (!AUTH_ON) { res.writeHead(302, { Location: '/' }); return res.end(); }
  const admin = auth.admins()[0] || auth.list()[0];
  if (!admin) {
    res.writeHead(500, { 'Content-Type': 'text/plain' });
    return res.end('No account exists to open a session for.\n');
  }
  const s = auth.openSession(auth.byId(admin.id));
  res.writeHead(302, { Location: '/', 'Set-Cookie': authlib.sessionCookie(s.sid, SECURE_COOKIE) });
  res.end();
}

function handleRequest(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }

  const urlPath = req.url.split('?')[0];

  if (req.method === 'POST' && urlPath === '/auth/login') return handleLogin(req, res);
  if (req.method === 'POST' && urlPath === '/auth/totp') return handleTotp(req, res);
  if (req.method === 'POST' && urlPath === '/auth/logout') return handleLogout(req, res);
  if (req.method === 'GET' && urlPath === '/auth/session') return handleSession(req, res);
  if (DESKTOP && req.method === 'GET' && urlPath === '/launch')
    return handleLaunch(req, res, new URL(req.url, 'http://localhost'));

  const session = AUTH_ON ? auth.sessionFor(req.headers.cookie) : { user: null, anonymous: true };
  if (AUTH_ON && !session && !PUBLIC_PATHS.has(urlPath)) return denyAnonymous(req, res, urlPath);
  // Already signed in? The sign-in page has nothing left to offer.
  if (AUTH_ON && session && urlPath === '/login.html') { res.writeHead(302, { Location: '/' }); return res.end(); }

  // Behind the session gate on purpose: only the window that holds a session
  // can keep the backend alive.
  if (DESKTOP && urlPath === '/desktop/ping') {
    lastBeat = Date.now(); beatSeen = true;
    res.writeHead(204); return res.end();
  }
  // Sent by the page as it goes away. Not an immediate exit: a reload fires the
  // same event, and the reloaded page pings again well inside the grace left here.
  if (DESKTOP && urlPath === '/desktop/bye') {
    if (beatSeen) lastBeat = Date.now() - (BEAT_GRACE_MS - 3000);
    res.writeHead(204); return res.end();
  }
  if (urlPath.startsWith('/api/')) return handleApi(req, res, urlPath, session);
  if (req.method === 'POST' && urlPath === '/forward') return handleForward(req, res);
  if (req.method === 'POST' && urlPath === '/test') return handleTest(req, res);
  if (req.method === 'GET' && urlPath === '/status') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ ok: true, backend: 'jedisyslogger', forwarded: totalForwarded }));
  }
  return serveStatic(req, res);
}

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
    desktop: DESKTOP,
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
      history: auth.getHistory(me.id),
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

  // — collector history —
  // Written on a deliberate act (Test, switching forwarding on, or Save), never
  // on every keystroke, so the list stays a record of receivers actually used.
  if (req.method === 'GET' && urlPath === '/api/profile/history') {
    return sendJson(res, 200, { ok: true, history: auth.getHistory(me.id) });
  }
  if (req.method === 'POST' && urlPath === '/api/profile/history') {
    return body((p) => {
      const r = auth.rememberCollector(me.id, p.collector || p);
      sendJson(res, r.ok ? 200 : 400, r);
    });
  }
  if (req.method === 'DELETE' && urlPath === '/api/profile/history') {
    const r = auth.clearHistory(me.id);
    return sendJson(res, 200, r);
  }
  if (req.method === 'DELETE' && urlPath.startsWith('/api/profile/history/')) {
    const r = auth.forgetCollector(me.id, urlPath.split('/')[4]);
    return sendJson(res, r.ok ? 200 : 404, r);
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

function sendJson(res, code, obj) { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(obj)); }

// Files that must never be served, however the request is spelled: auth.json
// holds the password hash and the TOTP secret, and a dotfile is never app content.
const PRIVATE_FILES = new Set(['auth.json']);
const PRIVATE_DIRS = new Set(['certs']);

function serveStatic(req, res) {
  let urlPath = decodeURIComponent(req.url.split('?')[0]);
  if (urlPath === '/') urlPath = '/index.html';
  const filePath = path.normalize(path.join(ROOT, urlPath));
  if (!filePath.startsWith(ROOT)) { res.writeHead(403); return res.end('forbidden'); }
  const base = path.basename(filePath);
  if (PRIVATE_FILES.has(base) || base.startsWith('.')) { res.writeHead(403); return res.end('forbidden'); }
  // The TLS private key lives under the served root; never hand it out.
  if (path.relative(ROOT, filePath).split(path.sep).some((seg) => PRIVATE_DIRS.has(seg))) {
    res.writeHead(403);
    return res.end('forbidden');
  }
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

  JEDI_AUTH=off               run with no sign-in at all (local throwaway use)
  JEDI_TLS_CERT / _KEY        certificate and key (default: certs/server.crt|.key)
  JEDI_HTTP_REDIRECT_PORT=n   also listen on n and bounce http:// to https://
  JEDI_SECURE_COOKIE=1        force Secure on the cookie (TLS proxy in front)

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
  // Desktop mode stays on plain HTTP. The socket is bound to loopback, so
  // nothing crosses a network to protect, and a self-signed certificate would
  // greet every launch with a browser warning — training people to click
  // through exactly the dialog that matters. JEDI_TLS_FORCE=1 overrides.
  tls = (DESKTOP && process.env.JEDI_TLS_FORCE !== '1') ? null : loadTls();
  if (tls) SECURE_COOKIE = true;   // the cookie can finally carry it
  const scheme = tls ? 'https' : 'http';
  const server = tls ? https.createServer(tls, handleRequest) : http.createServer(handleRequest);
  if (tls && REDIRECT_PORT) startRedirector();

  // Desktop mode must never be reachable from the network: the launch ticket
  // trades itself for an admin session, and that is only defensible because
  // nothing off this machine can present it.
  if (DESKTOP && BIND !== '127.0.0.1' && BIND !== '::1' && BIND !== 'localhost') {
    console.error(`  refusing to run desktop mode bound to ${BIND} — it would expose the launch ticket`);
    process.exit(1);
  }

  server.listen(PORT, BIND, () => {
    const port = server.address().port;
    if (DESKTOP) {
      // The launcher parses this line. The ticket is in it, so it goes to our
      // own stdout and nowhere else — not argv, not the environment, not a file.
      console.log(`JEDI_DESKTOP_URL=${scheme}://127.0.0.1:${port}/launch?t=${launchTicket}`);
      // Once the page has checked in, its silence means the window is gone.
      // Armed only after the first beat, so a browser that never renders leaves
      // the backend running rather than being killed by a timer it never fed.
      const watchdog = /** @type {any} */ (setInterval(() => {
        if (!beatSeen || Date.now() - lastBeat <= BEAT_GRACE_MS) return;
        console.log('  window closed — stopping.');
        process.exit(0);
      }, 3000));
      if (watchdog && typeof watchdog.unref === 'function') watchdog.unref();
    }
    console.log(`\n  ⚔️  APEX JediSyslogger v${VERSION} running → ${scheme}://localhost:${port}`);
    if (tls) {
      console.log(`      🔐 TLS on — certificate ${TLS_CERT}`);
      if (REDIRECT_PORT) console.log(`         http://…:${REDIRECT_PORT} redirects here.`);
    } else {
      console.log(`      🔓 Plain HTTP — passwords and authenticator codes cross the`);
      console.log(`         network in the clear. See "HTTPS" in README.md.`);
    }
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

// Anyone who bookmarked the http:// URL lands on a TLS port and gets a protocol
// error, not a page. This gives them somewhere to land instead.
function startRedirector() {
  http.createServer((req, res) => {
    const host = String(req.headers.host || '').replace(/:\d+$/, '');
    res.writeHead(301, { Location: `https://${host}:${PORT}${req.url}` });
    res.end();
  }).listen(REDIRECT_PORT, () => {
    console.log(`      ↪ http://…:${REDIRECT_PORT} → https://…:${PORT}`);
  });
}
