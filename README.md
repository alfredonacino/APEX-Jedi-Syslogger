# ⚔️ APEX JediSyslogger

A browser-based **SIEM log-ingestion simulator** for security / detection-engineering
practice. It has two halves:

| Component     | Role |
|---------------|------|
| **Syslogger** | A synthetic log source. Emits realistic **RFC 3164** and **RFC 5424** syslog plus **41 appliance formats** (firewalls and NGFW, IDS/NDR, proxies, DNS/DDI, mail and email security, VPN gateways, a PAM vault, hypervisor, backup, and cloud/SaaS control planes — Palo Alto, FortiGate, Cisco ASA/FTD/IOS/ISE/ESA/Meraki/Umbrella, Check Point, Sophos, pfSense, Juniper SRX, SonicWall, Zscaler, F5 BIG-IP ASM, NetScaler, Ivanti Connect Secure, Snort 3, Suricata, Zeek, HAProxy, Squid, BIND 9, Infoblox NIOS, Postfix, CyberArk, Veeam, VMware ESXi, Windows Event Log via Snare, Sysmon, Linux auditd, AWS CloudTrail, Azure Activity, Microsoft 365, Entra ID, Okta, CrowdStrike, Kubernetes audit, and generic CEF/LEEF) from simulated infrastructure at a configurable *events-per-second*, injects **60 attack scenarios** on demand, and can replay a log file in a loop. |
| **Jedi**      | A miniature SIEM engine. Ingests every event, keeps rolling statistics, and runs a **stateful detection-rule engine** that raises **MITRE ATT&CK-tagged** alerts. |

The dashboard runs entirely in the browser. An optional **zero-dependency Node
backend** (`server.js`) lets it forward the generated logs as **real UDP/TCP
syslog** — or as **Splunk HEC** events over HTTP(S) — to an actual collector, and
test connectivity to it. The backend is behind a **password + two-factor sign-in**
(see [Signing in](#signing-in)) — it can put real traffic on your network, so it
does not answer to just anyone who can reach the port.

> 📖 **Full technical reference:** [DOCUMENTATION.md](DOCUMENTATION.md) — architecture,
> every scenario & detection rule, the HTTP API, log formats, and deployment.

![APEX JediSyslogger dashboard — live event stream, MITRE ATT&CK detections, and threat level](images/apex_jedisyslogger.png)

## Install on a new machine

The app is a static web front-end plus an optional **zero-dependency Node
backend**. The only thing the target machine needs is **Node.js** — there is no
`npm install` and no build step.

**1. Install Node.js** — version 14 or newer (any current LTS). From your package
manager or <https://nodejs.org>. Verify:

```bash
node --version
```

**2. Get the code** — clone it, or download an archive if you don't have git:

```bash
# Option A — clone with git
git clone https://github.com/alfredonacino/APEX-Jedi-Syslogger.git
cd APEX-Jedi-Syslogger

# Option B — download a tarball (no git required)
curl -L -o apex.tar.gz \
  "https://github.com/alfredonacino/APEX-Jedi-Syslogger/archive/refs/heads/main.tar.gz"
tar xzf apex.tar.gz && cd APEX-Jedi-Syslogger-main
```

*(Or on GitHub: **Code ▾ → Download ZIP**, then unpack it.)*

**3. Start it** and open the dashboard in a browser:

```bash
node server.js                 # serves the app on http://localhost:8099
```

That's the entire install. For a custom port, a systemd service, or firewall
rules see [Run it](#run-it) below and
[DOCUMENTATION.md §14](DOCUMENTATION.md#14-deployment).

## Run it

```bash
# Recommended — serves the app AND enables live forwarding + the connectivity test
node server.js                 # then browse to http://localhost:8099
PORT=9000 node server.js       # custom port

# Static-only (no forwarding / no connectivity test)
python3 -m http.server 8080    # then browse to http://localhost:8080
xdg-open index.html            # or just open the file (file://)
```

> **Forwarding to a real IP requires `node server.js`.** A browser page cannot
> open raw UDP/TCP sockets, so it can never send syslog on its own — the Node
> process is what actually emits the packets. HEC forwarding goes through the
> same backend, which keeps the token out of the browser's cross-origin path.

The first start prints the sign-in credentials and a two-factor secret — read on.

## Signing in

`node server.js` gates the whole app behind a **password plus a six-digit
authenticator code** (TOTP, RFC 6238). The first start writes `auth.json` next to
`server.js` (mode `0600`, gitignored) and prints what you need:

| | Default |
|---|---|
| **Username** | `admin` |
| **Password** | `APEXjedi2026!` |
| **Second factor** | a fresh random TOTP secret, printed on first start |

**The password above is published in this README, so it is not a secret.** Change
it before anyone else can reach the port:

```bash
node server.js --set-password 'something only you know'   # then restart the server
```

### Enrolling the second factor

The TOTP secret is generated per install — it is *not* a documented default, so
nobody can derive it from these docs. Enrol it once:

1. Start the backend and sign in at `http://localhost:8099/` with the username and
   password. A correct password alone does **not** sign you in; it moves you to
   the second step.
2. The first sign-in shows the **enrolment screen with a QR code**. Scan it with
   Google Authenticator, Aegis, 1Password, Bitwarden, or anything else that does
   time-based codes. Can't scan? Expand **Can't scan it?** for the Base32 secret to
   type in — time-based, SHA-1, 6 digits, 30 seconds.
3. Type the code the app shows. That seals the enrolment: from then on the secret
   is never displayed again, and every sign-in needs a live code.

The console prints the same QR — as text, using half-block characters — at every
start until it is enrolled, so a headless install is enrolled by scanning its
terminal (or its `apex.log`) without opening the UI.

The QR is generated in-process by `js/qr.js`, a small QR encoder written for this
(no dependencies, here as everywhere). `node js/qr.js --selftest` checks it
against the format and version tables in ISO/IEC 18004.

### Managing credentials

```bash
node server.js --show-auth              # who can sign in, and whether 2FA is enrolled
node server.js --set-password '<pw>'    # replace the password (min 8 characters)
node server.js --reset-2fa              # new TOTP secret — for a lost authenticator
node server.js --reset-auth             # back to the documented defaults + a new secret
node auth.js   --selftest               # check the Base32/TOTP maths against the RFCs
```

Each of these edits `auth.json` and exits. **Restart the backend afterwards** — a
running process holds the credentials in memory.

### What is enforced, and what is not

| | |
|---|---|
| **Password** | scrypt, per-install random salt. Never stored or logged in the clear. |
| **Second factor** | TOTP, ±1 step of clock tolerance, and a used code cannot be replayed. |
| **Brute force** | 5 failed attempts locks that account for 5 minutes — the correct password is refused during the lockout too. |
| **Session** | An `HttpOnly`, `SameSite=Strict` cookie, valid 8 hours. Held in memory, so a backend restart signs everyone out. |
| **Coverage** | Every route: the dashboard, the assets, `/forward`, `/test`, `/status`. `auth.json` itself is never served. |

Two things it deliberately does not do:

- **Static hosting has no sign-in.** `python3 -m http.server` just serves files;
  there is no process to check a session. Only `node server.js` enforces anything.
- **The session cookie is not `Secure`** — the app speaks plain HTTP, and a
  `Secure` cookie would simply never be stored. Behind a TLS proxy, set
  `JEDI_SECURE_COOKIE=1`. On an untrusted network, put it behind HTTPS.

To turn sign-in off for a throwaway local run: `JEDI_AUTH=off node server.js`.
The banner says so in the clear when you do.

## Deploy to a server

```bash
# from the project directory, copy to the target host
rsync -av --exclude '.git' --exclude 'apex.log' --exclude 'auth.json' \
  ./ alfreddgreat@172.26.250.20:/home/alfreddgreat/APEX_JediSyslogger/

# on the server
cd /home/alfreddgreat/APEX_JediSyslogger
node server.js                                    # foreground
setsid node server.js </dev/null >apex.log 2>&1 & # detached
```

Requires **Node.js** on the target (no npm install — zero dependencies). Then
browse to `http://<server-ip>:8099` and sign in. See
[DOCUMENTATION.md §14](DOCUMENTATION.md#14-deployment) for a systemd unit and
firewall notes.

> **Never copy `auth.json` between hosts** — hence the `--exclude` above. Each
> install generates its own password hash and TOTP secret on first start; copying
> one over means both machines share a second factor, and a `--delete` sync would
> silently wipe the target's credentials. The server's own first start prints the
> secret to enrol; watch its console (`apex.log` when detached).

> **Use `setsid`, not `nohup`, when starting it over SSH** — a plain `nohup … &`
> keeps the session's stdout attached and hangs the SSH channel.

Updating an existing deployment is just the `rsync`: static files are served from
disk, so a UI/rule change needs **no restart**. Only a change to `server.js`
itself does.

## Using it

1. **Start Ingestion** — begins benign baseline traffic. Drag the **Rate** slider
   (0–60 eps) to change volume.
2. **Attack ›** — inject a burst of malicious activity and watch **Detections**
   correlate it. **Appliance logs ›** — emit any of the 41 sources in its real
   wire format, from firewalls (Palo Alto, FortiGate, Cisco ASA/FTD) to an IDS
   (Snort), network monitoring (Zeek), a load balancer (HAProxy), DNS (BIND 9),
   mail (Postfix), agent-relayed hosts (Windows via Snare, Sysmon, Linux auditd)
   and API-relayed cloud/SaaS (AWS CloudTrail, Okta). An appliance button stays
   **selected** and takes over the live stream: while any appliance is selected,
   ingestion emits **only** those sources — no generic firewall/web/DNS noise.
   Click it again (or **clear**) to hand the stream back to the baseline mix.
3. Toggle **RFC 3164 / RFC 5424** for the generic sources. Click any event to see
   the **raw line + parsed fields** (appliance events keep their vendor format).
4. **Filter** the live stream, **pause** it, or **Reset** all state.

### Source & delivery configuration

| Control | What it does |
|---------|--------------|
| **Log collector (receiver)** | Destination `IP : port` (or hostname) + protocol — **UDP**, **TCP**, or **HEC** — that logs are forwarded/tested against. |
| **HEC settings** | Shown when the protocol is **HEC**: the Splunk **token**, an optional **index** (blank = the token's default), the **sourcetype** (default `syslog`), **HTTPS** on/off, and **skip cert** to accept Splunk's self-signed certificate. Picking HEC swaps the port to **8088**. |
| **Test** | Probes reachability of that IP:port. TCP = real connect (open / refused / timeout). UDP = ICMP probe (detects "nothing listening"; open ports are inconclusive by nature). HEC posts a real test event, so it also validates the token, index and TLS settings. |
| **Forward live** | Relays every generated log line to the collector via the Node backend. The status line shows a live count; UDP is *sent* (fire-and-forget, no delivery ack), TCP is *delivered*, HEC is *indexed* (Splunk acks every batch). |
| **Volume limit** | **Unlimited**, or cap the total number of logs to an integer — ingestion auto-stops at the cap. |
| **File replay** | Load a `.log`/`.txt`/`.csv` file; enable **use as source** to replay its lines (each parsed into an event), **loop** to repeat endlessly. See `samples/sample.log`. |

## Live forwarding & troubleshooting

`Forward live` → the browser posts batches to `POST /forward`, and the backend
emits them to your collector. Because **UDP is fire-and-forget**, a rising
"sent" count means packets *left your machine* — not that the SIEM received them.
(TCP and HEC both ack, so their counts are real deliveries.) If your SIEM shows
nothing:

1. **Click Test** (or switch to **TCP**). TCP gives a definitive answer:
   *connect succeeded* (reachable + listening), *connection refused* (nothing on
   that port), or *timeout* (firewall/routing).
2. **Watch the `node server.js` console** — it logs every forward:
   `→ forwarded N line(s) to <IP>:<port>/udp`.
3. **`sudo tcpdump -n -i any port 514` on the collector.** Packets seen but not
   ingested → the SIEM's syslog input isn't configured for that port/proto.
   No packets → a firewall between the hosts (port 514 also needs root on the receiver).

### Sending to Splunk HEC

Prefer HEC over syslog when the target is Splunk: it is acknowledged per batch,
carries `host`/`sourcetype`/`index` per event, and needs no root or port 514.

1. In Splunk: **Settings › Data inputs › HTTP Event Collector › New Token**, then
   **Global Settings › All Tokens: Enabled** (HEC listens on **8088**).
2. In the config bar: protocol **HEC**, the Splunk host, the token, and an index
   the token may write to. Leave **HTTPS** and **skip cert** ticked for a stock
   Splunk (its HEC certificate is self-signed); untick HTTPS only if you disabled
   SSL on the input.
3. Click **Test** — it posts a real event and reports Splunk's own answer
   (`Invalid token`, `Incorrect index`, a TLS mismatch, …), so a green result
   means the next batch will index.
4. Verify in Splunk: `index=<your index> sourcetype=syslog source=jedisyslogger`.

Each line is sent as one HEC envelope — the raw syslog line in `event`, with the
generating host, the configured sourcetype/index and the event's own timestamp.
Batches go to `/services/collector/event` every 500 ms, up to 1000 events each.

## Detection rules

| Rule | Trigger | ATT&CK |
|------|---------|--------|
| SSH Brute-Force | ≥ 8 failed `sshd` logins from one IP / 60s | T1110 |
| Login After Brute Force | `Accepted password` following a failure burst | T1078 |
| Horizontal Port Scan | ≥ 15 distinct denied dst ports from one IP / 30s | T1046 |
| SQL Injection | SQLi patterns in an HTTP request | T1190 |
| C2 / Known-Bad Destination | Internal host → threat-intel IP | T1071 |
| Large Outbound Transfer | Outbound flow > 100 MB | T1048 |
| DNS Tunneling | Very long DNS label / known-bad domain (BIND, Infoblox, Umbrella) | T1071.004 |
| Privilege Escalation | `sudo … USER=root` / Windows EventID 4672 | T1068 |
| IDS Malware Signature | Suricata/ET trojan / exploit hit | T1204 |
| Web Application Attack | Log4Shell / XSS / traversal / web shell / scanner UA / metadata SSRF | T1190 · T1059 · T1083 · T1505.003 · T1595 · T1552.005 |
| Windows Security Event | RDP brute / spray / Kerberoasting / AS-REP roast / Golden Ticket / DCSync / new admin / log-clear / PtH / PsExec | T1110 · T1558.001 · T1558.003 · T1558.004 · T1003.006 · T1136 · T1070.001 · T1550.002 · T1021.002 |
| Credential Dumping (LSASS) | Sysmon 10 handle into `lsass.exe` with dump rights, or a known dumper | T1003.001 |
| Persistence Mechanism Created | `CurrentVersion\Run` write, scheduled task, or service install | T1547.001 · T1053.005 · T1543.003 |
| LOLBin Download / Proxy Execution | `certutil -urlcache`, `bitsadmin /transfer`, `mshta http…`, `regsvr32 /i:http` | T1105 · T1218 |
| Security Tooling Disabled | Defender real-time protection off, AMSI patched, exclusion added | T1562.001 |
| Active Directory Enumeration | SharpHound / AdFind on disk, or ≥ 10 LDAP object reads / account / 60s | T1087.002 |
| Cloud Control-Plane Abuse | CloudTrail `StopLogging`, IAM key/admin-policy creation, public S3; Azure diagnostic-settings delete, Owner role assignment, `listKeys`, key-vault policy write; Microsoft 365 external forwarding rule | T1562.008 · T1098.001 · T1098.003 · T1530 · T1078.004 · T1552.001 · T1555 · T1114.003 |
| Identity Provider Threat | Okta sign-ins from 2 countries / hour, MFA factor or policy change | T1078.004 · T1098.003 |
| MFA Push Bombing | ≥ 6 rejected Okta push prompts / user / 5 min, and the approval that follows | T1621 |
| Reverse Shell | `/dev/tcp/`, `nc -e`, `bash -i >&` | T1059 |
| Suspicious PowerShell | `powershell -enc` / `FromBase64String` / hidden window | T1059.001 |
| Cryptomining | `stratum+tcp` / known mining pool | T1496 |
| Ransomware | shadow-copy deletion / mass `.locked` rename, or backup repository / job deletion and immutability disabled | T1486 · T1490 |
| DoS / Flood | SYN-flood markers or a volumetric block burst to one host | T1498 |
| Phishing Email | SPF/DKIM/DMARC fail + risky attachment, or the email gateway's own verdict | T1566 |
| RADIUS / 802.1X Brute Force | ≥ 6 Cisco ISE `5400` auth failures from one MAC / 60s | T1110 |
| Root Shell From Unprivileged Login | auditd `SYSCALL`, `auid` set & ≠0, `uid=0`, `key="rootshell"` | T1548 |
| Appliance IPS / WAF Signature | any appliance threat/violation signature | T1190 (mapped by signature) |
| Process Injection | Sysmon 10 access with `CreateRemoteThread` rights | T1055 |
| Credentials From Password Store | Browser `Login Data` + `Local State` read together, or ≥ 4 CyberArk safes checked out by one holder / 2 min | T1555.003 · T1555.005 |
| Masquerading System Binary | A `System32` binary name running from a user-writable path | T1036.005 |
| Unmanaged Remote Access Tool | AnyDesk / ScreenConnect-class binary calling out | T1219 |
| Sandbox / VM Evasion | VM-artefact probing before the payload runs | T1497 |
| Covert C2 Channel | Proxy `CONNECT` to Tor ports, or a fixed-cadence pull loop against trusted SaaS | T1090.003 · T1102.002 |
| Exfiltration to Cloud Storage | `PUT`/`POST` > 100 MB to Dropbox / Mega / transfer.sh | T1567.002 |
| Network Device Config Tampering | Cisco IOS config removing `logging host` or an ACL | T1562.004 |
| VPN / Gateway Credential Stuffing | ≥ 6 distinct accounts tried from one IP / 2 min (NetScaler, Ivanti) | T1110.004 |
| Hypervisor Tampering | ESXi lockdown off, SSH enabled, or `esxcli vm process kill` | T1562.001 |
| Kubernetes Cluster Abuse | Privileged / `hostPID` pod create, or anonymous `pods/exec` | T1611 |
| Remote Execution (WMI / WinRM) | Connect to 135 / 5985 followed by a remote process create | T1047 · T1021.006 |

**Scenarios** — 60 attacks (`Attack ›`) and 41 appliance formats (`Appliance logs ›`).
Every scenario is wired to a detection, so each button demonstrably lights up the
dashboard. The **Threat Level** meter aggregates recent alerts (last 2 min) weighted
by severity, DEFCON-style: `GUARDED → ELEVATED → HIGH → SEVERE → CRITICAL`.

## Attack scenarios (60)

Injected from the **Attack ›** menu; each button fires a burst built to trip a
detection. Full detail — burst sizes, payloads, and the rule each one fires — is
in [DOCUMENTATION.md §5](DOCUMENTATION.md#5-attack-scenarios).

- **Network / recon** — Port Scan · SYN Flood (DDoS) · C2 Beacon · DNS Tunneling · Data Exfiltration · Cryptomining · Tor Egress · C2 over Trusted SaaS · Network Config Tampering
- **Web application** — SQL Injection · Log4Shell RCE · XSS Injection · Path Traversal / LFI · Web Shell · Vuln Scan · SSRF → Cloud Metadata
- **Credential / identity** — SSH Brute Force · RDP Brute Force · Password Spray · Kerberoasting · AS-REP Roasting · Golden Ticket · DCSync · Pass-the-Hash · LSASS Credential Dump · Browser Credential Theft · ADCS Certificate Theft (ESC1)
- **Endpoint / execution** — Reverse Shell · Malicious PowerShell · Privilege Escalation · Malware / IDS Hit · Ransomware · LOLBin Download (certutil) · Process Injection · Remote Access Tool Install
- **Persistence / evasion** — New Admin Account · Audit Log Cleared · Scheduled Task Persistence · Run-Key Persistence · Defender Disabled · Masquerading (fake svchost) · Sandbox / VM Evasion · GPO Modification
- **Discovery / lateral movement** — BloodHound AD Recon · PsExec Lateral Movement · WMI Lateral Movement
- **Cloud control plane** — Cloud Logging Disabled · Cloud IAM Backdoor · Cloud Privilege Escalation · S3 Bucket Exposed · Exfil to Cloud Storage · Container Escape (K8s) · ESXi Ransomware Prep
- **Identity provider** — Impossible Travel · MFA Fatigue (Push Bombing) · Legacy Auth MFA Bypass · OAuth Consent Phishing
- **Gateway / edge** — Citrix Gateway Exploit · VPN Credential Stuffing
- **Email** — Phishing Email

## Appliance log formats (41)

Injected from the **Appliance logs ›** menu — each event is rendered in the
vendor's real wire format (syslog `<PRI>` + native payload). Full example lines
and detection mapping: [DOCUMENTATION.md §6](DOCUMENTATION.md#6-appliance-log-formats).

| Appliance | Format | Detection |
|-----------|--------|-----------|
| Palo Alto (PAN-OS) | CSV | `appliance-threat` |
| FortiGate (FortiOS) | `key=value` | `appliance-threat` |
| Cisco ASA | `%ASA-lvl-id` | `c2-beacon` |
| Check Point | `key=value;` | `c2-beacon` |
| Sophos XG | `key=value` | `appliance-threat` |
| pfSense | filterlog CSV | `c2-beacon` |
| Juniper SRX | RT_FLOW | `c2-beacon` |
| SonicWall | `id/sn key=value` | `appliance-threat` |
| Zscaler ZIA | NSS `key=value` | `appliance-threat` |
| F5 BIG-IP ASM | `key=value` (WAF) | `appliance-threat` |
| Cisco FTD (Firepower) | `%FTD-lvl-id` + `Key: Value` | `appliance-threat` |
| Cisco ISE (RADIUS) | segmented + `key=value` | `radius-brute` |
| Snort 3 (IDS) | `[gid:sid:rev]` tokens | `appliance-threat` |
| HAProxy | positional + termination flags | `appliance-threat` |
| BIND 9 (DNS) | `named` query log | `dns-tunneling` |
| Postfix (mail) | prose + `key=<value>` | `appliance-threat` |
| Windows Event Log (Snare) `agent` | TAB-delimited `MSWinEventLog` | `windows-threat` |
| Sysmon (Windows) `agent` | NXLog `key=value` | `cred-dumping` |
| Linux auditd `agent` | `type=… msg=audit(ts:serial)` | `auditd-rootshell` |
| Zeek (NSM) `agent` | TAB-separated `conn` / `dns` / `ssl` | `c2-beacon` |
| AWS CloudTrail `api` | JSON record | `cloud-threat` |
| Okta System Log `api` | JSON record | `mfa-fatigue` |
| Cisco IOS (switch/router) | `%FAC-sev-MNEM` | `net-config-change` |
| Cisco Meraki (MX) | epoch + `security_event` | `appliance-threat` |
| Citrix NetScaler (Gateway) | `ns 0-PPE-0 : module EVENT` | `vpn-brute` |
| Squid (proxy) | native access log | `covert-c2` |
| VMware ESXi | `Hostd` / `Vpxa` | `hypervisor-threat` |
| Suricata (EVE JSON) | EVE JSON | `appliance-threat` |
| Cisco Secure Email (ESA) | CEF consolidated event | `phishing` |
| CyberArk Vault (EPV) | CEF | `password-store-theft` |
| Ivanti Connect Secure (VPN) | `user(realm)[roles] - CODE:` | `vpn-brute` |
| Infoblox NIOS (DDI) | ISC `named` / `dhcpd` | `dns-tunneling` |
| Veeam Backup & Replication | RFC 5424 + structured data | `ransomware` |
| Cisco Umbrella (DNS) `api` | quoted CSV | `dns-tunneling` |
| Azure Activity Log `api` | Activity Log JSON | `cloud-threat` |
| Microsoft 365 audit `api` | unified-audit JSON | `cloud-threat` |
| Microsoft Entra ID `api` | `SigninLogs` JSON | `identity-threat` |
| CrowdStrike Falcon `api` | `DetectionSummaryEvent` JSON | `appliance-threat` |
| Kubernetes audit `api` | `audit.k8s.io/v1` JSON | `k8s-threat` |
| CEF (generic) | ArcSight CEF | `appliance-threat` |
| LEEF (generic) | QRadar LEEF | `appliance-threat` |

Appliances carrying an IPS/WAF signature fire **`appliance-threat`**; the pure
firewalls (Cisco ASA, Check Point, pfSense, Juniper) route their malicious event
through **`c2-beacon`** (internal host → threat-intel IP) instead — as does **Zeek**,
whose `conn.log` beacon to a known-bad IP is the same shape of evidence. The rest are
**correlation-driven** rather than signature-driven — the burst *is* the signal, so
they carry no signature and alert **once** rather than once per line: **Cisco ISE**
(RADIUS rejects counted by `radius-brute`), **NetScaler** and **Ivanti Connect
Secure** (accounts tried from one address, counted by `vpn-brute`), **Snare** (a 4625
burst counted by `windows-threat`), **Okta** (rejected push prompts counted by
`mfa-fatigue`), **CyberArk** (safes checked out by one holder, counted by
`password-store-theft`), **auditd** (`auditd-rootshell`), **Sysmon** (a handle request
into LSASS caught by `cred-dumping`), and **BIND 9**, **Infoblox** and **Umbrella**
(DGA-length and known-bad queries caught by `dns-tunneling`).

**Transport matters.** 29 sources are **native syslog** — the device emits the format
itself. Twelve are not, and say so with a badge on their button:

- `agent` — **Snare** (Windows has no syslog; the agent relays the Event Log),
  **Sysmon** (its own Windows channel, relayed by NXLog), **auditd** (needs the
  `audisp-syslog` plugin), and **Zeek** (writes log *files*; Filebeat ships them).
- `api` — **AWS CloudTrail** (records land in S3/EventBridge), **Azure Activity**
  and **Microsoft 365** (Event Hub / Management Activity API), **Entra ID**
  (`SigninLogs` via Graph), **Okta** (the System Log is polled from
  `/api/v1/logs`), **Cisco Umbrella** (CSV into a managed S3 bucket),
  **CrowdStrike** (the Falcon SIEM Connector) and **Kubernetes audit** (a file or
  webhook from the API server). None of them speaks syslog at all; a
  connector re-emits their JSON.

Presenting these as native syslog devices would teach something false, so the
dashboard badges them and every button reports its transport on hover.

Snare is Windows Event Log over a different wire format, so it reuses the existing
`windows-threat` rule — same event IDs (4624/4625/4688), no duplicate rule.

## Project layout

```
index.html        markup + panel scaffold
login.html        password + two-factor sign-in page
css/styles.css    dark SIEM theme
js/data.js        data pools, RNG, RFC 3164/5424 + vendor line formatting
js/syslogger.js   log generator, appliance sources, scenarios, file replay, forwarding
js/jedi.js        SIEM engine: parsing, correlation, detection rules
js/ui.js          dashboard rendering + wiring
js/login.js       the two-step sign-in flow
js/qr.js          QR encoder for the 2FA enrolment code (browser + console)
auth.js           password (scrypt) + TOTP two-factor, sessions, lockout
auth.json         generated per install: password hash + TOTP secret (0600, gitignored)
server.js         optional Node backend: static host + /forward relay (UDP/TCP/HEC) + /test probe
samples/sample.log  example mixed-format log for the file-replay demo
jsconfig.json     editor typecheck settings (no install needed, ships nothing)
types/globals.d.ts  ambient declarations for window.JS and Node globals
```

## Extending it

- **Add a log source**: add a builder to `BASELINE` in `syslogger.js` and a
  `SOURCE_META` entry in `ui.js`.
- **Add an appliance format**: add a formatter to `VENDOR_FORMATTERS` in `data.js`
  and an entry to `APPLIANCE` in `syslogger.js`. If the product doesn't speak
  syslog natively, set `transport: 'agent'` or `'api'` so it isn't presented as a
  native syslog device.
- **Add a detection**: push a rule object into `makeRules()` in `jedi.js`. Use
  `ctx.window()` / `ctx.windowSet()` / `ctx.cooldown()` for stateful correlation.
  Check the existing rules first — a source carrying telemetry another rule already
  reads should reuse it (Snare reuses `windows-threat`) rather than clone it.
- **Add a scenario**: add an entry to `SCENARIOS` in `syslogger.js`. Make a burst
  raise **one** alert, not one per line: tag only its final event with `threatSig`,
  or let a stateful rule correlate it.

Counts are load-bearing here and in `DOCUMENTATION.md` — update them when adding
or removing a scenario, format, or rule.

---

Created By: **Alfredo Nacino** · [www.alfredonacino.com](https://www.alfredonacino.com) · alfredo@nacino.net
