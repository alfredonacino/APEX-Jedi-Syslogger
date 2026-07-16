# CLAUDE.md

Guidance for Claude Code when working in this repository.

## What this is

**APEX JediSyslogger** — a browser-based **SIEM log-ingestion simulator** for
detection-engineering practice. Two halves:

- **Syslogger** (`js/syslogger.js`) — a synthetic log source. Emits benign
  baseline syslog (RFC 3164 / RFC 5424) plus **12 native appliance formats**, at a
  configurable events-per-second, and injects **26 attack scenarios** on demand.
  Also replays uploaded log files.
- **Jedi** (`js/jedi.js`) — a miniature SIEM engine. Ingests every event, keeps
  rolling stats, and runs a stateful, **MITRE ATT&CK-tagged** detection-rule
  engine that raises alerts and a DEFCON-style threat level.

The dashboard runs entirely in the browser. `server.js` is an **optional
zero-dependency Node backend** that serves the app and relays generated logs as
real UDP/TCP syslog to an external collector.

## Running / verifying

```bash
node server.js                 # serves app + enables forwarding/test → http://localhost:8099
PORT=9000 node server.js       # custom port
python3 -m http.server 8080    # static-only (no forwarding/test)
```

- **Requires Node.js only** — no `package.json`, no `npm install`, no build step.
  The backend uses only Node core modules (`http`, `dgram`, `net`, `fs`, `path`).
- To verify a change, load the app and click the relevant **Attack ›** /
  **Appliance logs ›** button, or **Start Ingestion** — every scenario is wired to
  a detection, so the corresponding alert should appear in **Detections**.
- Live forwarding to a real IP **requires** `node server.js` — a browser page
  cannot open raw UDP/TCP sockets.

## Architecture & load order

Plain IIFEs attaching to a global `JS` namespace — no modules, no bundler. Scripts
must load in this order (see `index.html`):

```
data.js  →  syslogger.js  →  jedi.js  →  ui.js
```

| File | Responsibility |
|------|----------------|
| `index.html` | Markup / panel scaffold |
| `css/styles.css` | Dark SIEM theme, responsive layout |
| `js/data.js` | RNG helpers, host/user/threat-intel pools, RFC 3164/5424 + `VENDOR_FORMATTERS` |
| `js/syslogger.js` | `BASELINE` generators, `SCENARIOS` (attacks) + `APPLIANCE` sources, file replay, forward queue |
| `js/jedi.js` | `makeRules()` detection rules, `Correlator`, stats, threat level |
| `js/ui.js` | Dashboard rendering, charts, config wiring, event drawer |
| `server.js` | Optional backend: static host + `POST /forward` relay + `POST /test` probe |
| `samples/sample.log` | Example mixed-format log for the file-replay demo |

Every generated/parsed log is normalised into an **event object** before Jedi sees
it (see DOCUMENTATION.md §3). Detection rules read those fields; `threatSig` on an
event drives the appliance-threat rule.

## Where things live (for common edits)

- **Add / change an attack scenario** → `SCENARIOS` or `MORE_ATTACKS` in
  `js/syslogger.js`. Each is `{ label, category, build() }` returning an array of
  event partials. Make it emit content a rule matches (or set `threatSig`).
- **Add / change an appliance format** → a generator in `APPLIANCE`
  (`js/syslogger.js`) **and** a formatter in `VENDOR_FORMATTERS` (`js/data.js`).
- **Add / change a detection rule** → push a rule object into `makeRules()`
  (`js/jedi.js`). Use `ctx.window()` / `ctx.windowSet()` / `ctx.cooldown()` for
  stateful correlation.
- **Add a benign log source** → a builder in `BASELINE` (`js/syslogger.js`) + a
  `SOURCE_META` entry in `js/ui.js`.
- **Threat-intel indicators** (known-bad IPs/domains) → `THREAT_INTEL` in
  `js/data.js`.

## Conventions

- No external dependencies anywhere — keep it that way (browser + Node core only).
- Match the surrounding style: terse, comment-light, `const`/arrow functions,
  template literals. Each module is a single IIFE.
- Counts are load-bearing in the docs: there are **26 attacks** and **20 appliance
  formats** (18 native syslog + 2 agent-relayed). If you add or remove one, update
  the counts and tables in `README.md` (§Attack scenarios / §Appliance log formats)
  **and** `DOCUMENTATION.md` (§5 / §6).
- Appliance entries declare `transport: 'agent' | 'api'` when the product does not
  speak syslog natively (`snare`, `auditd` today; AWS/Okta would be `'api'`).
  Default is `'native'`; the UI badges non-native sources and reports transport on
  the button's hover title. Don't present an agent/API source as native syslog.
- Reuse a rule rather than cloning it when a new source carries the same telemetry:
  `snare` is Windows Event Log over an agent, so it feeds the existing
  `windows-threat` rule. Check `makeRules()` before adding a near-duplicate.
- A burst should raise **one** alert, not one per line. Either tag only the final
  event with `threatSig`, or let a stateful rule correlate the burst.
- The RFC 3164 / 5424 toggle affects only the generic sources; appliance events
  always use their native vendor format.

## Docs

- `README.md` — quickstart, install on a new machine, run, detection-rule and
  scenario/appliance summaries.
- `DOCUMENTATION.md` — full reference: architecture, event model, every scenario &
  rule, vendor formats, HTTP API, configuration, deployment, troubleshooting.

---

Created By: **Alfredo Nacino** · [www.alfredonacino.com](https://www.alfredonacino.com) · alfredo@nacino.net
