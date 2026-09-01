#!/usr/bin/env node
/*
 * jedi-cli.js — APEX JediSyslogger without a browser.
 *
 * The same engine the dashboard runs: js/data.js, js/syslogger.js and
 * js/jedi.js are require()d here exactly as the pages load them, so a scenario
 * that raises an alert in the browser raises the same alert in this terminal.
 * There is no second implementation to keep in step.
 *
 * Two faces:
 *   • a live dashboard, when stdout is a terminal and no one asked otherwise
 *   • flags, for servers — generate, forward, inject, replay, print, exit
 *
 * Node core only: no dependencies, no build step, nothing to install. Runs
 * wherever Node 18+ runs — macOS (Intel and Apple silicon), Windows, and any
 * Linux distribution.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const readline = require('readline');

const { VERSION, NAME } = require('./js/version.js');
const JS = require('./js/data.js');
require('./js/syslogger.js');
require('./js/jedi.js');
const { Syslogger, Jedi } = JS;
const wire = require('./forward.js');

// ── Arguments ────────────────────────────────────────────────────────────
// A hand-rolled parser rather than a dependency: the grammar is `command
// [args] --flag [value]`, and everything unknown is an error rather than a
// silent no-op, because a mistyped --forward should not look like success.
const FLAGS_WITH_VALUE = new Set([
  'eps', 'format', 'forward', 'duration', 'max', 'appliance', 'source',
  'hec-token', 'hec-index', 'hec-sourcetype', 'filter', 'every',
]);
const BOOL_FLAGS = new Set([
  'json', 'quiet', 'loop', 'test', 'ascii', 'no-color', 'color', 'help',
  'version', 'hec-plain', 'hec-verify', 'raw', 'no-detect',
]);

function parseArgs(argv) {
  const out = { _: [], flags: {} };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--') { out._.push(...argv.slice(i + 1)); break; }
    if (a.startsWith('--')) {
      let [name, inline] = a.slice(2).split(/=(.*)/s);
      if (FLAGS_WITH_VALUE.has(name)) {
        const v = inline !== undefined ? inline : argv[++i];
        if (v === undefined) fail(`--${name} needs a value`);
        out.flags[name] = v;
      } else if (BOOL_FLAGS.has(name)) {
        out.flags[name] = inline === undefined ? true : inline !== 'false';
      } else fail(`unknown option --${name}  (try: jedi help)`);
    } else if (a.startsWith('-') && a.length > 1 && a !== '-') {
      const short = { h: 'help', v: 'version', q: 'quiet', j: 'json', e: 'eps', f: 'forward' };
      const name = short[a.slice(1)];
      if (!name) fail(`unknown option ${a}  (try: jedi help)`);
      if (FLAGS_WITH_VALUE.has(name)) out.flags[name] = argv[++i]; else out.flags[name] = true;
    } else out._.push(a);
  }
  return out;
}

function fail(msg, code = 2) { process.stderr.write(`jedi: ${msg}\n`); process.exit(code); }

// ── Colour ───────────────────────────────────────────────────────────────
// Honours NO_COLOR (https://no-color.org) and falls back to plain text the
// moment stdout stops being a terminal, so a redirect into a file stays clean.
const COLOR = (() => {
  const argv = process.argv;
  if (argv.includes('--no-color') || process.env.NO_COLOR !== undefined) return false;
  if (argv.includes('--color')) return true;
  if (process.env.TERM === 'dumb') return false;
  return !!process.stdout.isTTY;
})();
const esc = (code) => (COLOR ? `\x1b[${code}m` : '');
const C = {
  reset: esc(0), bold: esc(1), dim: esc(2), rev: esc(7),
  red: esc(38 + ';5;203'), orange: esc('38;5;215'), yellow: esc('38;5;222'),
  green: esc('38;5;114'), cyan: esc('38;5;80'), blue: esc('38;5;75'),
  grey: esc('38;5;245'), white: esc('38;5;253'), magenta: esc('38;5;176'),
};
const SEV_COLOR = { critical: C.red, high: C.orange, medium: C.yellow, low: C.blue };
const SEV_TAG = { critical: 'CRIT', high: 'HIGH', medium: 'MED ', low: 'LOW ' };
// A stable colour per source, hashed rather than tabled — the table of source
// colours lives in js/ui.js, which is browser-only and must not be dragged in.
const SRC_PALETTE = [81, 114, 176, 215, 222, 80, 75, 203, 141, 108, 180, 117];
function srcColor(s) {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) >>> 0;
  return esc(`38;5;${SRC_PALETTE[h % SRC_PALETTE.length]}`);
}

// ── Terminal geometry ────────────────────────────────────────────────────
const ASCII = process.argv.includes('--ascii') || process.platform === 'win32' && !process.env.WT_SESSION;
const BOX = ASCII
  ? { h: '-', v: '|', tl: '+', tr: '+', bl: '+', br: '+', lt: '+', rt: '+', bar: '#', empty: '.' }
  : { h: '─', v: '│', tl: '┌', tr: '┐', bl: '└', br: '┘', lt: '├', rt: '┤', bar: '▉', empty: '░' };

const ANSI_RE = /\x1b\[[0-9;]*m/g;
const vislen = (s) => s.replace(ANSI_RE, '').length;
function fit(s, w) {
  if (vislen(s) <= w) return s + ' '.repeat(w - vislen(s));
  // Truncate on visible characters, keeping escape sequences intact.
  let out = '', seen = 0, i = 0;
  while (i < s.length && seen < w - 1) {
    if (s[i] === '\x1b') { const m = /^\x1b\[[0-9;]*m/.exec(s.slice(i)); if (m) { out += m[0]; i += m[0].length; continue; } }
    out += s[i++]; seen++;
  }
  return out + '…'.slice(0, ASCII ? 0 : 1) + (ASCII ? '>' : '') + C.reset;
}
const size = () => ({
  cols: Math.max(60, process.stdout.columns || 100),
  rows: Math.max(18, process.stdout.rows || 30),
});

// ── Forwarding ───────────────────────────────────────────────────────────
// The CLI sends straight onto the wire through forward.js. The browser cannot
// open a socket and has to POST to server.js first; here there is no server in
// the path at all, which is the main reason to run this build on a collector.
function parseTarget(url) {
  const m = /^(udp|tcp|hec|hec\+http):\/\/([^\s/:]+)(?::(\d+))?\/?$/i.exec(String(url).trim());
  if (!m) fail(`--forward wants udp://host:port, tcp://host:port or hec://host:port (got "${url}")`);
  const proto = m[1].toLowerCase();
  const def = proto.startsWith('hec') ? 8088 : 514;
  return {
    proto: proto.startsWith('hec') ? 'hec' : proto,
    ip: m[2],
    port: parseInt(m[3], 10) || def,
    // hec:// is TLS, hec+http:// is not. --hec-plain forces plain either way.
    ssl: proto !== 'hec+http',
  };
}

function target(flags) {
  const t = parseTarget(flags.forward);
  if (flags['hec-plain']) t.ssl = false;
  return t;
}

class Forwarder {
  constructor(target, hec) {
    this.t = target;
    this.hec = hec;
    this.queue = [];
    this.sent = 0;
    this.error = null;
    this.busy = false;
    // Node's Timeout, not the DOM's number: unref so a queued batch never
    // keeps a one-shot run alive after its work is done.
    this.timer = /** @type {any} */ (setInterval(() => this.flush(), 500));
    if (this.timer && typeof this.timer.unref === 'function') this.timer.unref();
  }
  push(ev) { if (this.queue.length < 20000) this.queue.push(ev); }
  flush(cb) {
    if (this.busy || !this.queue.length) return cb && cb();
    const batch = this.queue.splice(0, 500);
    this.busy = true;
    const done = (err, n) => {
      this.busy = false;
      if (err) this.error = err.message; else { this.error = null; this.sent += n; }
      if (cb) cb();
    };
    if (this.t.proto === 'hec') {
      const p = { ip: this.t.ip, port: this.t.port, hec: Object.assign({ ssl: this.t.ssl }, this.hec) };
      wire.forwardHec(p, batch.map((e) => ({ raw: e.raw, host: e.host, ts: e.ts })), done);
    } else {
      wire.forwardLines(this.t.ip, this.t.port, this.t.proto, batch.map((e) => e.raw), done);
    }
  }
  // Drain before exit, so a one-shot run does not lose its last batch.
  drain(cb) {
    const step = () => (this.queue.length || this.busy) ? this.flush(() => setTimeout(step, 60)) : cb();
    step();
  }
  stop() { clearInterval(this.timer); }
}

// Deliberately no `ssl` key: the --forward scheme decides that (hec:// is TLS,
// hec+http:// is not), and a second source of truth here would override the URL
// depending on which way round the two objects were merged.
function hecConfig(flags) {
  return {
    token: flags['hec-token'] || process.env.JEDI_HEC_TOKEN || '',
    index: flags['hec-index'] || '',
    sourcetype: flags['hec-sourcetype'] || 'syslog',
    insecure: !flags['hec-verify'],
  };
}

// ── Engine ───────────────────────────────────────────────────────────────
function buildEngine(flags, onEvent) {
  const jedi = new Jedi();
  const detect = !flags['no-detect'];
  const syslogger = new Syslogger((ev) => {
    const alerts = detect ? jedi.ingest(ev) : [];
    onEvent(ev, alerts);
  });
  if (flags.eps !== undefined) {
    const n = Number(flags.eps);
    if (!Number.isFinite(n) || n < 0 || n > 5000) fail('--eps wants a number between 0 and 5000');
    syslogger.setEps(n);
  }
  if (flags.format) {
    if (!['rfc3164', 'rfc5424'].includes(flags.format)) fail('--format wants rfc3164 or rfc5424');
    syslogger.setFormat(flags.format);
  }
  if (flags.max) syslogger.setMaxEvents(Number(flags.max));
  const sources = flags.appliance || flags.source;
  if (sources) {
    const ids = String(sources).split(',').map((s) => s.trim()).filter(Boolean);
    const known = new Set(Syslogger.scenarioList().filter((s) => s.category === 'appliance').map((s) => s.id));
    const bad = ids.filter((i) => !known.has(i));
    if (bad.length) fail(`unknown appliance source(s): ${bad.join(', ')}  (try: jedi list appliances)`);
    syslogger.setApplianceSources(ids);
  }
  return { syslogger, jedi };
}

const scenarios = () => Syslogger.scenarioList();
function resolveScenario(id) {
  const all = scenarios();
  const hit = all.find((s) => s.id === id);
  if (hit) return hit;
  const near = all.filter((s) => s.id.includes(id) || s.label.toLowerCase().includes(id.toLowerCase()));
  if (near.length === 1) return near[0];
  if (near.length > 1) fail(`"${id}" matches ${near.length} scenarios: ${near.slice(0, 6).map((s) => s.id).join(', ')}${near.length > 6 ? ' …' : ''}`);
  return fail(`unknown scenario "${id}"  (try: jedi list scenarios)`);
}

// ── Commands ─────────────────────────────────────────────────────────────
function cmdList(what, flags) {
  const all = scenarios();
  const kind = (what || 'all').toLowerCase();
  const rows = [];
  if (/^(all|scenarios?|attacks?)$/.test(kind))
    rows.push(...all.filter((s) => s.category !== 'appliance').map((s) => ({ kind: 'attack', ...s })));
  if (/^(all|appliances?|sources?)$/.test(kind))
    rows.push(...all.filter((s) => s.category === 'appliance').map((s) => ({ kind: 'appliance', ...s })));
  if (/^rules?$/.test(kind)) {
    const rules = new Jedi().rules.map((r) => ({ id: r.id, name: r.name, severity: r.severity, technique: r.technique }));
    if (flags.json) return void process.stdout.write(JSON.stringify(rules, null, 2) + '\n');
    for (const r of rules) process.stdout.write(`${C.bold}${r.id.padEnd(28)}${C.reset}${r.name.padEnd(38)}${C.grey}${r.technique}${C.reset}\n`);
    process.stderr.write(`\n${rules.length} detection rules\n`);
    return;
  }
  if (!rows.length) fail(`list what? try: scenarios | appliances | rules`);
  if (flags.json) return void process.stdout.write(JSON.stringify(rows, null, 2) + '\n');
  for (const r of rows) {
    const badge = r.kind === 'appliance' && r.transport !== 'native'
      ? `${C.magenta}[${r.transport}]${C.reset}` : '';
    process.stdout.write(`${C.bold}${r.id.padEnd(28)}${C.reset}${r.label.padEnd(34)}${badge}\n`);
  }
  const a = rows.filter((r) => r.kind === 'attack').length, p = rows.length - a;
  process.stderr.write(`\n${a ? `${a} attack scenarios` : ''}${a && p ? ', ' : ''}${p ? `${p} appliance sources` : ''}\n`);
}

function cmdTest(flags) {
  if (!flags.forward) fail('--test needs --forward udp://host:port (the target to probe)');
  const t = parseTarget(flags.forward);
  if (flags['hec-plain']) t.ssl = false;
  const done = (r) => {
    const mark = r.reachable ? `${C.green}OK  ${C.reset}` : (r.warn ? `${C.yellow}????${C.reset}` : `${C.red}FAIL${C.reset}`);
    if (flags.json) process.stdout.write(JSON.stringify(r) + '\n');
    else process.stdout.write(`${mark} ${t.proto}://${t.ip}:${t.port} (${r.ms} ms)\n     ${r.message}\n`);
    process.exit(r.reachable === false ? 1 : 0);
  };
  if (t.proto === 'hec') wire.testHec({ ip: t.ip, port: t.port, hec: Object.assign({ ssl: t.ssl }, hecConfig(flags)) }, done);
  else if (t.proto === 'tcp') wire.testTcp(t.ip, t.port, done);
  else wire.testUdp(t.ip, t.port, done);
}

// One-shot: inject scenarios, report what the engine made of them, exit.
function cmdAttack(ids, flags, category) {
  if (!ids.length) fail(`which one? try: jedi list ${category === 'appliance' ? 'appliances' : 'scenarios'}`);
  const picked = ids.map(resolveScenario);
  const fwd = flags.forward ? new Forwarder(target(flags), hecConfig(flags)) : null;
  const results = [];
  let pending = picked.length;

  const runOne = (s) => {
    const events = [];
    const alerts = [];
    let last = Date.now();
    const { syslogger } = buildEngine(flags, (ev, fired) => {
      events.push(ev);
      alerts.push(...fired);
      last = Date.now();
      if (fwd) fwd.push(ev);
    });
    syslogger.injectScenario(s.id);
    // injectScenario spreads the burst 30–90 ms per event, and a burst can be
    // twenty events long — so wait for the stream to go quiet rather than for a
    // fixed time, or a long scenario gets truncated and its rule never fires.
    const started = Date.now();
    const settled = setInterval(() => {
      if (Date.now() - last < 300 && Date.now() - started < 15000) return;
      clearInterval(settled);
      results.push({ scenario: s.id, label: s.label, category: s.category || 'attack', events: events.length, raw: events.map((e) => e.raw), alerts });
      if (--pending === 0) finish();
    }, 100);
  };

  const finish = () => {
    const emit = () => {
      if (flags.json) {
        process.stdout.write(JSON.stringify(results.map((r) => ({
          scenario: r.scenario, label: r.label, category: r.category, events: r.events,
          alerts: r.alerts.map(alertJson),
        })), null, 2) + '\n');
      } else if (flags.raw) {
        for (const r of results) for (const line of r.raw) process.stdout.write(line + '\n');
      } else {
        for (const r of results) {
          process.stdout.write(`\n${C.bold}${r.label}${C.reset} ${C.grey}(${r.scenario}) — ${r.events} events${C.reset}\n`);
          if (!r.alerts.length) process.stdout.write(`  ${C.yellow}no detection fired${C.reset}\n`);
          for (const a of r.alerts) {
            process.stdout.write(`  ${SEV_COLOR[a.severity]}${SEV_TAG[a.severity]}${C.reset} ${a.name} ${C.grey}· ${a.technique}${C.reset}\n`);
            process.stdout.write(`       ${a.message}\n`);
          }
        }
        const n = results.reduce((s, r) => s + r.alerts.length, 0);
        process.stderr.write(`\n${results.length} scenario(s), ${results.reduce((s, r) => s + r.events, 0)} events, ${n} alert(s)` +
          (fwd ? `, ${fwd.sent} forwarded` : '') + '\n');
      }
      if (fwd && fwd.error) { process.stderr.write(`forwarding failed: ${fwd.error}\n`); process.exit(1); }
      process.exit(0);
    };
    if (fwd) fwd.drain(emit); else emit();
  };

  picked.forEach(runOne);
}

const alertJson = (a) => ({
  ts: new Date(a.ts).toISOString(), rule: a.ruleId, name: a.name, severity: a.severity,
  tactic: a.tactic, technique: a.technique, message: a.message, srcIp: a.srcIp, host: a.host,
  evidence: a.evidence,
});
const eventJson = (e) => ({
  ts: new Date(e.ts).toISOString(), srcType: e.srcType, host: e.host, severity: e.severity,
  program: e.program, srcIp: e.srcIp, raw: e.raw,
});

// Headless run: stream to stdout (or nowhere) and forward. This is the mode a
// server runs under systemd.
function cmdQuiet(flags, replayFile) {
  const fwd = flags.forward ? new Forwarder(target(flags), hecConfig(flags)) : null;
  let events = 0, alerts = 0;
  const { syslogger, jedi } = buildEngine(flags, (ev, fired) => {
    events++; alerts += fired.length;
    if (fwd) fwd.push(ev);
    if (flags.json) {
      process.stdout.write(JSON.stringify({ t: 'event', ...eventJson(ev) }) + '\n');
      for (const a of fired) process.stdout.write(JSON.stringify({ t: 'alert', ...alertJson(a) }) + '\n');
    } else if (flags.raw) {
      process.stdout.write(ev.raw + '\n');
    } else {
      for (const a of fired) process.stdout.write(
        `${SEV_COLOR[a.severity]}${SEV_TAG[a.severity]}${C.reset} ${new Date(a.ts).toISOString()} ${a.name} — ${a.message}\n`);
    }
  });
  if (replayFile) loadReplay(syslogger, replayFile, flags);

  const stop = (why) => {
    syslogger.stop();
    const bye = () => {
      process.stderr.write(`\n${events} events, ${alerts} alerts${fwd ? `, ${fwd.sent} forwarded` : ''}${why ? ` (${why})` : ''}\n`);
      if (fwd && fwd.error) {
        process.stderr.write(`forwarding failed: ${fwd.error}\n`);
        process.exit(1);
      }
      process.exit(0);
    };
    if (fwd) fwd.drain(bye); else bye();
  };
  syslogger.onStop = (reason) => stop(reason);
  process.on('SIGINT', () => stop('interrupted'));
  process.on('SIGTERM', () => stop('terminated'));
  if (flags.duration) setTimeout(() => stop(`${flags.duration}s elapsed`), Number(flags.duration) * 1000);
  syslogger.start();
  scheduleAttacks(syslogger, flags);
}

// Fire a scenario on a cadence, so an unattended feed still exercises the rules
// rather than emitting nothing but baseline noise. Shared by both faces.
function scheduleAttacks(syslogger, flags, onFire) {
  if (!flags.every) return null;
  const secs = Number(flags.every);
  if (!Number.isFinite(secs) || secs < 1) fail('--every wants a number of seconds (how often to inject one)');
  const pool = scenarios().filter((s) => s.category !== 'appliance');
  return setInterval(() => {
    const s = pool[Math.floor(Math.random() * pool.length)];
    syslogger.injectScenario(s.id);
    if (onFire) onFire(s);
  }, secs * 1000);
}

function loadReplay(syslogger, file, flags) {
  let text;
  try { text = fs.readFileSync(file, 'utf8'); }
  catch (e) { fail(`cannot read ${file}: ${e.code === 'ENOENT' ? 'no such file' : e.message}`); }
  const lines = text.split(/\r?\n/).filter((l) => l.trim());
  if (!lines.length) fail(`${file} has no lines to replay`);
  syslogger.loadFile(lines, path.basename(file));
  syslogger.setFileMode(true);
  syslogger.setLoop(!!flags.loop);
  return lines.length;
}

// ── Live dashboard ───────────────────────────────────────────────────────
function cmdDashboard(flags, replayFile) {
  const fwd = flags.forward ? new Forwarder(target(flags), hecConfig(flags)) : null;
  const stream = [];
  const { syslogger, jedi } = buildEngine(flags, (ev, fired) => {
    stream.unshift(ev);
    if (stream.length > 300) stream.pop();
    if (fwd) fwd.push(ev);
  });
  let replayed = 0;
  if (replayFile) replayed = loadReplay(syslogger, replayFile, flags);

  let picker = null;      // { query, index, list }
  let message = '';
  let messageUntil = 0;
  const note = (m, ms = 2500) => { message = m; messageUntil = Date.now() + ms; };

  const out = process.stdout;
  const enter = () => { out.write('\x1b[?1049h\x1b[?25l'); };
  const leave = () => { out.write('\x1b[?25h\x1b[?1049l'); };

  function render() {
    const { cols, rows } = size();
    const W = cols - 2;
    const L = [];
    const row = (s) => BOX.v + fit(s, W) + BOX.v;
    // Rules with a label. Width is measured from the pieces rather than
    // arithmetic on the label length, which is how borders end up one column
    // out and the right edge of the frame goes ragged.
    const rule = (left, label, right, width) => {
      const head = BOX[left] + BOX.h + (label ? ` ${label} ` : '');
      return head + BOX.h.repeat(Math.max(0, width - vislen(head) - 1)) + BOX[right];
    };
    const title = (t) => rule('lt', t, 'rt', W + 2);

    // Header
    const st = syslogger.running ? `${C.green}RUNNING${C.reset}` : `${C.grey}STOPPED${C.reset}`;
    const mode = syslogger.fileMode ? `REPLAY ${syslogger.fileName}` : (syslogger.applianceSources.length ? `${syslogger.applianceSources.length} appliance src` : 'baseline mix');
    L.push(rule('tl', `${NAME} v${VERSION}`, 'tr', W + 2));
    L.push(row(` ${C.grey}${mode}${C.reset}  ${C.dim}|${C.reset}  ${syslogger.eps} eps set  ${C.dim}|${C.reset}  ${jedi.eps()} eps live  ${C.dim}|${C.reset}  ${st}`));

    // KPIs + threat level
    const th = jedi.threatLevel();
    const thc = { low: C.green, moderate: C.yellow, high: C.orange, severe: C.red, critical: C.red }[th.key] || C.white;
    const meter = BOX.bar.repeat(th.n) + BOX.empty.repeat(5 - th.n);
    const sev = jedi.alertSeverityCounts;
    L.push(title('OVERVIEW'));
    L.push(row(` EVENTS ${C.bold}${jedi.totalEvents.toLocaleString()}${C.reset}   ALERTS ${C.bold}${jedi.totalAlerts}${C.reset}   ` +
      `${SEV_COLOR.critical}${sev.critical} crit${C.reset} ${SEV_COLOR.high}${sev.high} high${C.reset} ${SEV_COLOR.medium}${sev.medium} med${C.reset}   ` +
      `THREAT ${thc}${meter} ${th.label}${C.reset}`));

    // Panes: stream on top, detections below, sized to the window.
    const chrome = 4 /*header+overview*/ + 2 /*two pane titles*/ + 2 /*footer+bottom*/ + 1;
    const detRows = Math.max(3, Math.min(8, Math.floor((rows - chrome) * 0.4)));
    const strRows = Math.max(3, rows - chrome - detRows);

    L.push(title('STREAM'));
    const filter = (flags.filter || '').toLowerCase();
    const shown = filter ? stream.filter((e) => (e.raw || '').toLowerCase().includes(filter)) : stream;
    for (let i = 0; i < strRows; i++) {
      const e = shown[i];
      if (!e) { L.push(row('')); continue; }
      const t = new Date(e.ts).toTimeString().slice(0, 8);
      const sc = srcColor(e.srcType || '?');
      const sevc = e.severity <= 2 ? C.red : e.severity <= 4 ? C.orange : C.grey;
      L.push(row(` ${C.grey}${t}${C.reset} ${sc}${(e.srcType || '?').padEnd(11).slice(0, 11)}${C.reset} ${sevc}${(e.message || e.raw || '').replace(/\s+/g, ' ')}${C.reset}`));
    }

    L.push(title('DETECTIONS'));
    for (let i = 0; i < detRows; i++) {
      const a = jedi.alerts[i];
      if (!a) { L.push(row('')); continue; }
      const t = new Date(a.ts).toTimeString().slice(0, 8);
      L.push(row(` ${SEV_COLOR[a.severity]}${SEV_TAG[a.severity]}${C.reset} ${C.grey}${t}${C.reset} ${C.bold}${a.name}${C.reset} ${C.grey}· ${a.technique}${C.reset}  ${a.message}`));
    }

    // Footer
    let foot;
    if (Date.now() < messageUntil) foot = ` ${C.yellow}${message}${C.reset}`;
    else if (fwd) foot = ` ${C.cyan}→ ${fwd.t.proto}://${fwd.t.ip}:${fwd.t.port}${C.reset} ${fwd.sent} sent` +
      (fwd.error ? `  ${C.red}${fwd.error}${C.reset}` : '') + `   ${C.dim}[s]tart [a]ttack [+/-]eps [r]eset [q]uit${C.reset}`;
    else foot = ` ${C.dim}[s]tart/stop  [a]ttack  [x]appliance  [+/-]eps  [r]eset  [c]lear  [q]uit${C.reset}`;
    L.push(rule('lt', '', 'rt', W + 2));
    L.push(row(foot));
    L.push(rule('bl', '', 'br', W + 2));

    // The picker floats over the frame rather than replacing it, so you can
    // still see the stream you are about to attack.
    if (picker) {
      const listRows = Math.max(1, Math.min(12, picker.list.length));
      const top = 4;
      const pw = Math.min(W - 2, 66);              // every overlay row is exactly pw wide
      const body = (s) => BOX.v + fit(s, pw - 2) + BOX.v;
      const ov = [];
      ov.push(rule('tl', picker.title, 'tr', pw));
      ov.push(body(` ${C.cyan}/${C.reset}${picker.query}${C.dim}${ASCII ? '_' : '▏'}${C.reset}`));
      for (let i = 0; i < listRows; i++) {
        const s = picker.list[picker.offset + i];
        if (!s) { ov.push(body('')); continue; }
        const on = picker.offset + i === picker.index;
        ov.push(body(`${on ? C.rev : ''} ${s.label.padEnd(34).slice(0, 34)} ${C.grey}${s.id}${C.reset}${on ? C.rev : ''}${on ? C.reset : ''}`));
      }
      ov.push(body(` ${C.dim}${ASCII ? '^v' : '↑↓'} move · enter fire · esc cancel · ${picker.list.length} match${C.reset}`));
      ov.push(rule('bl', '', 'br', pw));
      // Opaque, and inset one column so the frame keeps its own borders. Never
      // splice the row underneath: slicing a coloured string by visible width
      // cuts an escape sequence in half and tears the frame.
      ov.forEach((o, i) => {
        if (top + i >= L.length) return;
        L[top + i] = BOX.v + ' ' + o + ' '.repeat(Math.max(0, W - 1 - vislen(o))) + BOX.v;
      });
    }

    out.write('\x1b[H' + L.slice(0, rows).map((l) => l + '\x1b[K').join('\n') + '\x1b[J');
  }

  // ── Keys ──
  function openPicker(kind) {
    const list = scenarios().filter((s) => kind === 'appliance' ? s.category === 'appliance' : s.category !== 'appliance');
    picker = { kind, title: kind === 'appliance' ? 'APPLIANCE SOURCE' : 'ATTACK SCENARIO', all: list, list, query: '', index: 0, offset: 0 };
  }
  function pickerKey(str, key) {
    const name = key && key.name;
    if (name === 'escape' || (key && key.ctrl && name === 'c')) { picker = null; return; }
    if (name === 'return') {
      const s = picker.list[picker.index];
      picker = null;
      if (!s) return;
      syslogger.injectScenario(s.id);
      note(`injected ${s.label}`);
      return;
    }
    if (name === 'up') picker.index = Math.max(0, picker.index - 1);
    else if (name === 'down') picker.index = Math.min(picker.list.length - 1, picker.index + 1);
    else if (name === 'backspace') picker.query = picker.query.slice(0, -1);
    else if (str && str.length === 1 && str >= ' ') picker.query += str;
    else return;
    if (name !== 'up' && name !== 'down') {
      const q = picker.query.toLowerCase();
      picker.list = picker.all.filter((s) => s.id.includes(q) || s.label.toLowerCase().includes(q));
      picker.index = 0;
    }
    const visible = 12;
    if (picker.index < picker.offset) picker.offset = picker.index;
    if (picker.index >= picker.offset + visible) picker.offset = picker.index - visible + 1;
  }

  function onKey(str, key) {
    if (picker) { pickerKey(str, key); return render(); }
    const k = (key && key.name) || str;
    if (key && key.ctrl && k === 'c') return quit();
    switch (k) {
      case 'q': return quit();
      case 's': syslogger.running ? syslogger.stop() : syslogger.start(); break;
      case 'a': openPicker('attack'); break;
      case 'x': openPicker('appliance'); break;
      case 'r': jedi.reset(); syslogger.resetCounters(); stream.length = 0; note('counters reset'); break;
      case 'c': jedi.alerts = []; note('detections cleared'); break;
      case '+': case '=': syslogger.setEps(Math.min(200, syslogger.eps + 1)); break;
      case '-': syslogger.setEps(Math.max(0, syslogger.eps - 1)); break;
      case 'f': note(fwd ? `forwarding to ${fwd.t.ip}:${fwd.t.port}` : 'start with --forward udp://host:port to send'); break;
      case '?': note('s start/stop · a attack · x appliance · +/- eps · r reset · c clear · q quit', 5000); break;
      default: return;
    }
    render();
  }

  let ticker = null, autoAttack = null;
  function quit() {
    if (ticker) clearInterval(ticker);
    if (autoAttack) clearInterval(autoAttack);
    syslogger.stop();
    leave();
    if (process.stdin.isTTY) process.stdin.setRawMode(false);
    const bye = () => {
      process.stdout.write(`${NAME} v${VERSION} — ${jedi.totalEvents.toLocaleString()} events, ${jedi.totalAlerts} alerts` +
        (fwd ? `, ${fwd.sent} forwarded to ${fwd.t.proto}://${fwd.t.ip}:${fwd.t.port}` : '') + '\n');
      process.exit(0);
    };
    if (fwd) fwd.drain(bye); else bye();
  }

  readline.emitKeypressEvents(process.stdin);
  if (process.stdin.isTTY) process.stdin.setRawMode(true);
  process.stdin.on('keypress', onKey);
  process.on('SIGINT', quit);
  process.stdout.on('resize', render);
  syslogger.onStop = (reason) => note(`stopped: ${reason}`, 6000);

  enter();
  if (replayFile) note(`replaying ${replayed} lines from ${path.basename(replayFile)}`);
  syslogger.start();
  autoAttack = scheduleAttacks(syslogger, flags, (s) => note(`auto: ${s.label}`));
  render();
  ticker = setInterval(render, 250);
}

// ── Help ─────────────────────────────────────────────────────────────────
function help() {
  const b = (s) => `${C.bold}${s}${C.reset}`;
  process.stdout.write(`
${b(NAME)} v${VERSION} — SIEM log-ingestion simulator, terminal build

${b('USAGE')}
  jedi [command] [options]

${b('COMMANDS')}
  run                        live dashboard (the default)
  attack <scenario…>         inject scenarios, print what fired, exit
  appliance <source…>        emit one burst from an appliance source, exit
  replay <file>              replay a log file through the engine
  list [scenarios|appliances|rules]
  version | help

${b('OPTIONS')}
  --eps N                    baseline events per second (default 8)
  --format rfc3164|rfc5424   generic-source syslog format
  --appliance id,id          scope the stream to these appliance sources
  --forward URL              send live: udp://host:514, tcp://host:514,
                             hec://host:8088, hec+http://host:8088
  --hec-token T              Splunk HEC token (or JEDI_HEC_TOKEN)
  --hec-index I              --hec-sourcetype S  --hec-plain  --hec-verify
  --test                     probe the --forward target and exit
  --duration S               run for S seconds, then stop
  --max N                    stop after N events
  --every S                  inject a random scenario every S seconds
  --loop                     loop a replayed file
  --quiet                    no dashboard: alerts to stdout
  --raw                      print raw syslog lines instead of alerts
  --json                     machine-readable output (NDJSON when streaming)
  --no-detect                generate only, run no detection rules
  --ascii --no-color         plain output for limited terminals

${b('EXAMPLES')}
  jedi                                       live dashboard
  jedi --forward udp://10.0.0.50:514 --eps 20 --quiet
  jedi --forward tcp://10.0.0.50:514 --test
  jedi attack m365-mail-exfil --json | jq '.[0].alerts'
  jedi attack exchange-proxynotshell --raw   the wire lines, nothing else
  jedi appliance defender entra              one burst from each
  jedi replay /var/log/syslog --loop --forward hec://splunk:8088 --hec-token …
  jedi list appliances

The same engine as the web dashboard (js/data.js, js/syslogger.js, js/jedi.js),
so detections are identical. Version is shared: this build and the web app are
both v${VERSION}.
`);
}

// ── Main ─────────────────────────────────────────────────────────────────
function main() {
  const { _: args, flags } = parseArgs(process.argv.slice(2));
  if (flags.version) return void process.stdout.write(`${NAME} ${VERSION}\n`);
  if (flags.help || args[0] === 'help') return help();

  const cmd = args[0] && !args[0].includes('.') && !args[0].includes('/') ? args[0] : null;
  const rest = args.slice(cmd ? 1 : 0);

  if (flags.test) return cmdTest(flags);

  switch (cmd) {
    case 'version': return void process.stdout.write(`${NAME} ${VERSION}\n`);
    case 'list': return cmdList(rest[0], flags);
    case 'attack': return cmdAttack(rest, flags, 'attack');
    case 'appliance': return cmdAttack(rest, flags, 'appliance');
    case 'replay': {
      if (!rest[0]) fail('replay needs a file path');
      return startRun(flags, rest[0]);
    }
    case 'run': case null: case undefined: return startRun(flags, rest[0] || null);
    default: fail(`unknown command "${cmd}"  (try: jedi help)`);
  }
}

function startRun(flags, file) {
  // A dashboard needs a terminal. Piped or redirected, fall back to the
  // headless mode rather than spraying escape codes into a file.
  const interactive = process.stdout.isTTY && process.stdin.isTTY && !flags.quiet && !flags.json && !flags.raw;
  if (interactive) cmdDashboard(flags, file);
  else cmdQuiet(flags, file);
}

main();
