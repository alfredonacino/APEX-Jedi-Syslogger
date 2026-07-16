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
 *      datagrams to the collector IP:port you configured in the UI.
 *
 * Run:  node server.js            (then open http://localhost:8099)
 *       PORT=9000 node server.js
 */
'use strict';
const http = require('http');
const dgram = require('dgram');
const net = require('net');
const fs = require('fs');
const path = require('path');

const ROOT = __dirname;
const PORT = parseInt(process.env.PORT, 10) || 8099;

const MIME = {
  '.html': 'text/html; charset=utf-8', '.css': 'text/css', '.js': 'text/javascript',
  '.json': 'application/json', '.log': 'text/plain', '.txt': 'text/plain',
  '.svg': 'image/svg+xml', '.ico': 'image/x-icon', '.map': 'application/json',
};

let totalForwarded = 0;

const server = http.createServer((req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }

  if (req.method === 'POST' && req.url === '/forward') return handleForward(req, res);
  if (req.method === 'POST' && req.url === '/test') return handleTest(req, res);
  if (req.method === 'GET' && req.url === '/status') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ ok: true, backend: 'jedisyslogger', forwarded: totalForwarded }));
  }
  return serveStatic(req, res);
});

function handleForward(req, res) {
  let body = '';
  req.on('data', (c) => { body += c; if (body.length > 8e6) req.destroy(); });
  req.on('end', () => {
    let p;
    try { p = JSON.parse(body); } catch (e) { res.writeHead(400); return res.end('{"ok":false,"error":"bad json"}'); }
    const lines = Array.isArray(p.lines) ? p.lines : [];
    const proto = (p.proto || 'udp').toLowerCase();
    forwardLines(p.ip, p.port, proto, lines, (err, sent) => {
      totalForwarded += sent;
      const dest = `${p.ip}:${parseInt(p.port, 10) || 514}/${proto}`;
      if (err) console.log(`  ✗ forward FAILED to ${dest}: ${err.message || err}`);
      else console.log(`  → forwarded ${sent} line(s) to ${dest}${proto === 'udp' ? ' (UDP: no delivery confirmation)' : ''}`);
      res.writeHead(err ? 502 : 200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: !err, sent, total: totalForwarded, error: err ? String(err.message || err) : null }));
    });
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
    const port = parseInt(p.port, 10) || 514;
    const proto = (p.proto || 'udp').toLowerCase();
    if (!ip) return sendJson(res, 400, { ok: false, reachable: false, message: 'no collector IP set' });
    const done = (r) => { console.log(`  ⟲ test ${ip}:${port}/${proto} → ${r.reachable ? 'OK' : (r.warn ? 'inconclusive' : 'FAIL')}: ${r.message}`); sendJson(res, 200, r); };
    if (proto === 'tcp') testTcp(ip, port, done); else testUdp(ip, port, done);
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

function serveStatic(req, res) {
  let urlPath = decodeURIComponent(req.url.split('?')[0]);
  if (urlPath === '/') urlPath = '/index.html';
  const filePath = path.normalize(path.join(ROOT, urlPath));
  if (!filePath.startsWith(ROOT)) { res.writeHead(403); return res.end('forbidden'); }
  fs.readFile(filePath, (err, data) => {
    if (err) { res.writeHead(404, { 'Content-Type': 'text/plain' }); return res.end('not found'); }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(filePath).toLowerCase()] || 'application/octet-stream' });
    res.end(data);
  });
}

server.listen(PORT, () => {
  console.log(`\n  ⚔️  APEX JediSyslogger running → http://localhost:${PORT}`);
  console.log(`      POST /forward relays syslog to your configured collector (UDP/TCP).`);
  console.log(`      Press Ctrl+C to stop.\n`);
});
