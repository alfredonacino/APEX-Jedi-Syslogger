# APEX_JediSyslogger — Technical Documentation

A browser-based **SIEM log-ingestion simulator** with an optional zero-dependency
Node backend for real syslog forwarding. This document is the full reference:
architecture, data model, every scenario and detection rule, the vendor log
formats, the HTTP API, configuration, and deployment.

- [1. Overview](#1-overview)
- [2. Architecture](#2-architecture)
- [3. Event data model](#3-event-data-model)
- [4. The Syslogger (log source)](#4-the-syslogger-log-source)
- [5. Attack scenarios](#5-attack-scenarios)
- [6. Appliance log formats](#6-appliance-log-formats)
- [7. The Jedi SIEM engine](#7-the-jedi-siem-engine)
- [8. Detection rules](#8-detection-rules)
- [9. File replay](#9-file-replay)
- [10. Live forwarding & the backend API](#10-live-forwarding--the-backend-api)
- [11. Connectivity test](#11-connectivity-test)
- [12. Configuration reference](#12-configuration-reference)
- [13. Deployment](#13-deployment)
- [14. Extending the app](#14-extending-the-app)
- [15. Troubleshooting](#15-troubleshooting)

---

## 1. Overview

APEX_JediSyslogger generates synthetic security telemetry and analyses it in real
time, so you can practise **detection engineering** without a live environment. It
has two halves:

| Component     | Role |
|---------------|------|
| **Syslogger** | Synthetic log source — emits RFC 3164 / RFC 5424 syslog and 12 native appliance formats, at a configurable rate, with 26 injectable attack scenarios and file replay. |
| **Jedi**      | Miniature SIEM — parses every event, keeps rolling stats, and runs a stateful, MITRE ATT&CK-tagged detection-rule engine. |

Everything renders in the browser. The optional `server.js` backend serves the
app **and** relays generated logs as real UDP/TCP syslog to an external collector.

All traffic is synthetic. Nothing leaves the browser unless you explicitly enable
**Forward live** (which requires the backend).

---

## 2. Architecture

```
┌──────────────────────── Browser ────────────────────────┐
│                                                          │
│  Syslogger ──emit(event)──▶ Jedi.ingest(event)           │
│  (js/syslogger.js)          (js/jedi.js)                 │
│      │                          │                        │
│      │ raw line                 │ stats + alerts         │
│      ▼                          ▼                        │
│  fwd queue ······▶ POST /forward   UI render (js/ui.js)  │
│                          │         dashboard / stream    │
└──────────────────────────┼──────────────────────────────┘
                           │  (only when "Forward live" is on)
                           ▼
              ┌──────── server.js (Node) ────────┐
              │  /forward → UDP/TCP syslog ───────┼──▶ Collector / SIEM
              │  /test    → reachability probe    │    (Splunk, Graylog,
              │  static file host                 │     Wazuh, rsyslog…)
              └───────────────────────────────────┘
```

**Files**

| File | Responsibility |
|------|----------------|
| `index.html` | Markup / panel scaffold |
| `css/styles.css` | Dark SIEM theme, responsive layout |
| `js/data.js` | Random helpers, host/user/threat-intel pools, RFC 3164/5424 + vendor line formatters |
| `js/syslogger.js` | Baseline generators, attack scenarios, appliance sources, file replay, forward queue |
| `js/jedi.js` | Parsing, correlation windows, detection rules, stats, threat level |
| `js/ui.js` | Dashboard rendering, charts, config wiring, drawer |
| `server.js` | Optional backend: static host + `/forward` relay + `/test` probe |
| `samples/sample.log` | Example mixed-format log for the file-replay demo |

The three engine modules are plain IIFEs that attach to a global `JS` namespace —
no build step, no bundler, no npm dependencies. Load order is data → syslogger →
jedi → ui.

---

## 3. Event data model

Every generated or parsed log is normalised into an **event object** before Jedi
sees it. Common fields:

| Field | Meaning |
|-------|---------|
| `id` | Random unique id |
| `ts` | Epoch ms timestamp |
| `srcType` | Source category (`firewall`, `ssh`, `web`, `dns`, `vpn`, `windows`, `mail`, appliance vendors, `file`) |
| `host` / `hostIp` | Device name / management IP |
| `facility` / `severity` | Syslog numeric facility (0–23) and severity (0–7) |
| `program` / `pid` | Process / tag |
| `srcIp` / `dstIp` / `srcPort` / `dstPort` / `proto` | Network 5-tuple (where relevant) |
| `action` | `ALLOW` / `DENY` / `accept` / `dropped` / etc. |
| `bytes` | Flow size |
| `user`, `eventId`, `url`, `method`, `status`, `domain` | Source-specific fields |
| `vendor` | Appliance vendor key (drives the native raw formatter) |
| `threatSig` / `threatSev` | Appliance IPS/WAF signature + severity (drives detection) |
| `message` | Human-readable summary shown in the stream |
| `raw` | The exact wire line (RFC 3164/5424 or vendor format), shown in the drawer |
| `collector` | The configured `ip:port` destination label |

Syslog severity mapping (lower = more severe): `0 emerg, 1 alert, 2 crit,
3 err, 4 warning, 5 notice, 6 info, 7 debug`.

---

## 4. The Syslogger (log source)

`Syslogger(sink)` emits events to a `sink` callback (Jedi's `ingest`).

**Baseline traffic** — a weighted mix of benign events from firewall, web, ssh,
dns, windows, and vpn, produced on a 100 ms tick at the configured **events per
second** (0–60). Fractional rates accumulate so e.g. 0.5 eps emits one event
every two seconds.

**Key methods**

| Method | Purpose |
|--------|---------|
| `start()` / `stop()` | Run/pause the baseline generator |
| `setEps(n)` | Baseline rate |
| `setFormat('rfc3164' \| 'rfc5424')` | Wire format for the generic sources |
| `injectScenario(id)` | Fire an attack/appliance burst (works even while stopped) |
| `setMaxEvents(n \| null)` | Total volume cap (auto-stops at the cap) |
| `setCollector(ip, port)` | Forwarding/test destination |
| `loadFile(lines, name)` / `setFileMode(bool)` / `setLoop(bool)` | File replay |
| `setForwarding(bool)` / `setForwardProto('udp' \| 'tcp')` | Live forwarding |

The **RFC 3164** vs **RFC 5424** toggle only affects the generic sources;
appliance events always use their native vendor format.

---

## 5. Attack scenarios

26 scenarios under **Attack ›**. Each produces a burst of events crafted to trip a
detection rule, so every button demonstrably lights up the dashboard.

| Scenario | Emits | Fires rule | ATT&CK |
|----------|-------|------------|--------|
| SSH Brute Force | `sshd` failed-password burst (+ occasional success) | ssh-bruteforce, brute-success | T1110 / T1078 |
| Port Scan | firewall DENY across many ports | port-scan | T1046 |
| SQL Injection | web requests with SQLi payloads | sql-injection | T1190 |
| C2 Beacon | internal → known-bad IP | c2-beacon | T1071 |
| Data Exfiltration | large outbound flow | data-exfil | T1048 |
| DNS Tunneling | long TXT queries to bad domain | dns-tunneling | T1071.004 |
| Privilege Escalation | `sudo … USER=root` / Win 4672 | priv-esc | T1068 |
| Malware / IDS Hit | Suricata/ET signature | ids-malware | T1204 |
| Log4Shell RCE | `${jndi:ldap://…}` in HTTP | web-exploit | T1190 |
| XSS Injection | `<script>` / `onerror=` in URL | web-exploit | T1059 |
| Path Traversal / LFI | `../../etc/passwd` | web-exploit | T1083 |
| Web Shell | POST to `shell.php?cmd=` | web-exploit | T1505.003 |
| Vuln Scan | many paths, scanner UA (sqlmap/Nikto) | web-exploit | T1595 |
| Reverse Shell | `bash -i >& /dev/tcp/…` | reverse-shell | T1059 |
| Malicious PowerShell | `powershell -enc <base64>` (4688) | susp-powershell | T1059.001 |
| RDP Brute Force | Windows 4625 LogonType 10 burst | windows-threat | T1110 |
| Password Spray | 4625 across many accounts, one password | windows-threat | T1110.003 |
| Kerberoasting | 4769 RC4 service-ticket requests | windows-threat | T1558.003 |
| DCSync | 4662 replication rights | windows-threat | T1003.006 |
| New Admin Account | 4720 + 4732 (added to Administrators) | windows-threat | T1136 |
| Audit Log Cleared | 1102 | windows-threat | T1070.001 |
| Pass-the-Hash | 4624 LogonType 9 / NTLM | windows-threat | T1550.002 |
| Ransomware | `vssadmin delete shadows`, mass `.locked` | ransomware | T1486 |
| Cryptomining | DNS + `stratum+tcp://pool` | cryptomining | T1496 |
| SYN Flood (DDoS) | firewall SYN-flood deny burst | dos-flood | T1498 |
| Phishing Email | mail log, SPF/DKIM/DMARC fail + risky attachment | phishing | T1566 |

---

## 6. Appliance log formats

12 sources under **Appliance logs ›**, each emitting the vendor's **real wire
format** (still wrapped in a syslog PRI header). Each burst mixes benign traffic
with one malicious event that trips a detection.

| Appliance | Format | Example shape |
|-----------|--------|---------------|
| Palo Alto (PAN-OS) | CSV | `1,<time>,<serial>,THREAT,vulnerability,…,tcp,reset-both,"…(91991)",…,critical` |
| FortiGate (FortiOS) | `key=value` | `date=… time=… devname="FGT60F" type="utm" subtype="ips" action="dropped" attack="…"` |
| Cisco ASA | `%ASA-level-id` | `%ASA-4-106023: Deny tcp src outside:… dst inside:…` |
| Check Point | `key=value;` | `product="…"; action="Drop"; src=…; dst=…; rule="…"` |
| Sophos XG | `key=value` | `device="SFW" log_component="IPS" signature="…" action="Deny"` |
| pfSense | filterlog CSV | `filterlog[pid]: 5,,,…,em0,match,block,in,4,…,tcp,…,SRC,DST,SPT,DPT` |
| Juniper SRX | RT_FLOW | `RT_FLOW: RT_FLOW_SESSION_DENY: session denied SRC/SPT->DST/DPT …` |
| SonicWall | `id/sn key=value` | `id=firewall sn=… m=82 msg="…" src=…:… dst=…:…` |
| Zscaler ZIA | NSS `key=value` | `zscalernss: … url="…" action="Blocked" threatname="…"` |
| F5 BIG-IP ASM | `key=value` | `ASM:…,policy_name="…",violations="SQL-Injection",request_status="blocked"` |
| CEF (generic) | ArcSight CEF | `CEF:0\|Vendor\|Product\|1.0\|SigID\|Name\|Sev\|src=… dst=… act=…` |
| LEEF (generic) | QRadar LEEF | `LEEF:2.0\|Vendor\|Product\|2.0\|EventID\|<tab-separated key=value>` |

Detection of appliance threats is uniform: any event carrying a `threatSig` fires
the **appliance-threat** rule, which maps the signature text to an ATT&CK
technique. Firewall-style appliances instead route their malicious event through
the generic **c2-beacon** rule (internal host → threat-intel IP).

---

## 7. The Jedi SIEM engine

`Jedi.ingest(event)`:

1. Updates counters — total events, per-severity, per-source, timeline buckets.
2. Adds the event to a capped recent-events ring (default 400).
3. Runs every detection rule; each hit becomes an **alert** (capped at 200).

**Rolling metrics**

- **EPS** — events in a trailing 3 s window.
- **Timeline** — per-second buckets of events and alerts (last ~120 s), drawn on
  the canvas chart.
- **Threat level** — sum of the last 2 minutes of alert severities
  (critical = 4, high = 3, medium = 2, low = 1) mapped to
  `GUARDED → ELEVATED → HIGH → SEVERE → CRITICAL`.

**Correlator** — a small stateful helper shared by the rules:

| Primitive | Use |
|-----------|-----|
| `window(ns, key, ms, now)` | Sliding array of timestamps within `ms` |
| `windowSet(ns, key, ms, now, value)` | Sliding set of distinct values (e.g. ports, users) |
| `cooldown(ns, key, ms, now)` | True at most once per `ms` — throttles repeat alerts |

---

## 8. Detection rules

Each rule returns `null` (no match) or an alert `{severity, tactic, technique,
message, srcIp, host, evidence}`. Correlating rules use the primitives above.

| Rule id | Name | Trigger | ATT&CK |
|---------|------|---------|--------|
| `ssh-bruteforce` | SSH Brute-Force | ≥ 8 failed `sshd` logins / IP / 60 s | T1110 |
| `brute-success` | Login After Brute Force | `Accepted password` after a failure burst | T1078 |
| `port-scan` | Horizontal Port Scan | ≥ 15 distinct denied dst ports / IP / 30 s | T1046 |
| `sql-injection` | SQL Injection | SQLi regex in an HTTP request | T1190 |
| `c2-beacon` | C2 / Known-Bad Destination | internal host → threat-intel IP | T1071 |
| `data-exfil` | Large Outbound Transfer | outbound flow > 100 MB | T1048 |
| `dns-tunneling` | DNS Tunneling | long DNS label / known-bad domain | T1071.004 |
| `priv-esc` | Privilege Escalation | `sudo … USER=root` / Win 4672 | T1068 |
| `ids-malware` | IDS Malware Signature | Suricata/ET trojan/exploit | T1204 |
| `appliance-threat` | Appliance IPS / WAF Signature | any `threatSig` present | T1190 (by signature) |
| `web-exploit` | Web Application Attack | Log4Shell / XSS / traversal / web shell / scanner UA | T1190·T1059·T1083·T1505.003·T1595 |
| `windows-threat` | Windows Security Event | 4625 brute/spray, 4769 RC4, 4662 repl, 4732/4720, 1102, 4624 PtH | T1110·T1558.003·T1003.006·T1136·T1070.001·T1550.002 |
| `reverse-shell` | Reverse Shell | `/dev/tcp/`, `nc -e`, `bash -i >&` | T1059 |
| `susp-powershell` | Suspicious PowerShell | `-enc` / `FromBase64String` / hidden window | T1059.001 |
| `cryptomining` | Cryptomining | `stratum+tcp` / known pool | T1496 |
| `ransomware` | Ransomware Behavior | shadow-copy deletion / mass `.locked` | T1486 |
| `dos-flood` | DoS / Flood | flood markers, or ≥ 40 blocks to one host / 5 s | T1498 |
| `phishing` | Phishing Email | SPF/DKIM/DMARC fail + risky attachment | T1566 |

---

## 9. File replay

Load a `.log` / `.txt` / `.csv` / `.json` file in **File replay**, tick **use as
source** and (optionally) **loop**. Each line is parsed best-effort into an event:

- A leading `<PRI>` sets facility/severity; the rest becomes the message.
- Host is extracted from an RFC 3164 or ISO-8601 timestamp prefix if present.
- The first two IPs found populate `srcIp` / `dstIp`, so IP-based rules still fire.
- The original line is preserved verbatim as `raw`.

While active, file lines replace the synthetic baseline and are emitted at the
configured EPS, looping when they reach the end (if **loop** is on). File events
are also forwarded and count toward the volume cap like any other event.

---

## 10. Live forwarding & the backend API

A browser cannot open raw UDP/TCP sockets, so **forwarding requires `server.js`.**
When **Forward live** is on, the browser batches raw lines and POSTs them every
500 ms; the backend emits them to the collector.

### Endpoints

| Method & path | Body | Response | Purpose |
|---------------|------|----------|---------|
| `POST /forward` | `{ip, port, proto, lines[]}` | `{ok, sent, total, error}` | Relay lines as UDP (fire-and-forget) or TCP (newline-framed, RFC 6587) |
| `POST /test` | `{ip, port, proto}` | `{ok, reachable, warn, ms, code, message}` | Reachability probe (see §11) |
| `GET /status` | — | `{ok, backend, forwarded}` | Health / counter |
| `GET /*` | — | file | Static host for the app |

The backend logs every relay to its console:
`→ forwarded N line(s) to <ip>:<port>/udp (UDP: no delivery confirmation)`.

**UDP is fire-and-forget** — a rising "sent" count means packets left the host,
not that the SIEM received them. Use TCP or the Test button to confirm delivery.

---

## 11. Connectivity test

The **Test** button probes the configured `IP:port` via `POST /test`.

| Protocol | Behaviour |
|----------|-----------|
| **TCP** | Real connect. `✓ reachable and port open`, `✗ Connection refused` (ECONNREFUSED), or `✗ timed out` (firewall). Definitive. |
| **UDP** | Connected-UDP probe. `✗ ICMP port-unreachable` if nothing is listening (Linux). An open/filtered port is inconclusive (`◐`) because UDP has no ack. |

Result colouring: green = reachable, amber = inconclusive (UDP open/filtered),
red = failed (with the exact error code).

---

## 12. Configuration reference

All controls live in the header and the **Source & delivery configuration** bar.

| Control | Effect |
|---------|--------|
| Start / Stop Ingestion | Run/pause baseline generation |
| Rate slider | 0–60 baseline events per second |
| RFC 3164 / RFC 5424 | Wire format for generic sources |
| Reset | Clear all state, counters, stream, and alerts |
| Log collector `IP : port` + `UDP/TCP` | Forwarding/test destination |
| **Test** | Probe reachability of that destination |
| **Forward live** | Relay generated logs as real syslog (needs backend) |
| Volume limit — Unlimited / Limit to N | Total-event cap; auto-stops at N |
| File replay — Choose file / loop / use as source | Replay an uploaded log file |
| Stream filter / pause | Filter the live stream; freeze it |

`PORT` env var overrides the backend's listen port (default **8099**).

---

## 13. Deployment

The app is a static site plus a zero-dependency Node backend. **Requirement on the
target: Node.js** (no `npm install`).

### Copy the files

```bash
rsync -av --exclude '.git' --exclude 'node_modules' \
  ./ alfreddgreat@172.26.250.20:/home/alfreddgreat/APEX_JediSyslogger/
```

### Run it

```bash
cd /home/alfreddgreat/APEX_JediSyslogger
node server.js                       # foreground, port 8099
PORT=80 node server.js               # privileged port (needs root/setcap)
nohup node server.js > apex.log 2>&1 &   # detached
```

Then browse to `http://172.26.250.20:8099`.

### Run as a systemd service (recommended)

`/etc/systemd/system/apex-jedisyslogger.service`:

```ini
[Unit]
Description=APEX_JediSyslogger SIEM log simulator
After=network.target

[Service]
Type=simple
User=alfreddgreat
WorkingDirectory=/home/alfreddgreat/APEX_JediSyslogger
Environment=PORT=8099
ExecStart=/usr/bin/node server.js
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now apex-jedisyslogger
sudo systemctl status apex-jedisyslogger
```

### Firewall

Open the dashboard port to your clients, and — if forwarding — allow egress to
the collector:

```bash
sudo ufw allow 8099/tcp             # dashboard
sudo ufw allow out 514/udp          # syslog egress (adjust to your collector)
```

---

## 14. Extending the app

- **New generic log source** — add a builder to `BASELINE` in `js/syslogger.js`
  and a `SOURCE_META` colour/label in `js/ui.js`.
- **New appliance format** — add a formatter to `VENDOR_FORMATTERS` in
  `js/data.js` and a generator to `APPLIANCE` in `js/syslogger.js`.
- **New attack scenario** — add an entry to `MORE_ATTACKS` (or `SCENARIOS`) in
  `js/syslogger.js`; set `threatSig` or emit content a rule matches.
- **New detection rule** — push a rule object into `makeRules()` in `js/jedi.js`.
  Use `ctx.window()` / `ctx.windowSet()` / `ctx.cooldown()` for correlation.

Every scenario should be wired to at least one rule — the headless harness pattern
(load `js/*` under a stubbed `window`, inject each scenario, assert alerts fire) is
the quickest way to verify coverage.

---

## 15. Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| "Forward live" green but SIEM sees nothing | UDP is fire-and-forget. Click **Test** or switch to TCP; run `tcpdump -n port 514` on the collector. |
| Test shows `Connection refused` | Host reachable, nothing listening on that port/proto — enable the SIEM's syslog input. |
| Test shows `timed out` | Firewall/routing dropping traffic between the hosts. |
| Forwarding foot says "backend not running" | You opened the app statically (python/`file://`). Serve it with `node server.js`. |
| Port 8099 in use | `PORT=9000 node server.js`. |
| Nothing happens on Start | Rate slider at 0, or a volume cap already reached — check the volume foot. |
