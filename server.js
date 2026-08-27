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
 *
 * Run:  node server.js            (then open http://localhost:8099)
 *       PORT=9000 node server.js
 */
'use strict';
const http = require('http');
const https = require('https');
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
  console.log(`      POST /forward relays syslog to your configured collector (UDP/TCP/Splunk HEC).`);
  console.log(`      Press Ctrl+C to stop.\n`);
});
