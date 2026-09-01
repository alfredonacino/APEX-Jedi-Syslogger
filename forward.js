/*
 * forward.js — the wire. Everything that puts a generated log line onto the
 * network lives here: the UDP/TCP syslog relays, the Splunk HEC poster, and the
 * three connectivity probes behind them.
 *
 * It is required by both `server.js` (which relays what the browser generates)
 * and `jedi-cli.js` (which generates and sends in one process, with no browser
 * anywhere). One copy, so a transport cannot behave differently depending on
 * which front end you happened to run. Node core only — http, https, dgram, net.
 */
'use strict';

const http = require('http');
const https = require('https');
const dgram = require('dgram');
const net = require('net');

// Turn a Node socket error into something an operator can act on. The code
// alone ("ECONNREFUSED") says nothing about which end is at fault.
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

module.exports = {
  errMessage, forwardLines, forwardHec, testTcp, testUdp, testHec, hecUrl, hecEnvelope, HEC_PATH,
};
