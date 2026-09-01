# Connecting real sources — agents and API connectors

APEX JediSyslogger emits **42 appliance formats**. Twenty-nine of them are native
syslog: the device opens a socket to your collector and that is the whole
integration. The other thirteen **cannot do that**, and this is the guide to the
part that is left.

- **`agent`** (4 sources) — the telemetry exists on the host, but nothing puts it
  on the wire. A forwarding agent has to read it and send it.
- **`api`** (9 sources) — the product has no socket at all. A connector
  authenticates, polls or subscribes, and re-emits the JSON.

The simulator badges these on their buttons for exactly this reason: a source
that cannot reach a collector on its own must not be practised on as though it
could. Everything below is the real configuration — what you would actually
deploy — with the simulator used at the end to prove the path works before the
real feed is pointed at it.

> Sizing, retention and licence tiers change; the field names, endpoints and
> permission names below are the stable part. Check the vendor's current docs
> for quotas and portal menu paths before a production rollout.

**Contents**

1. [The three transports](#1-the-three-transports)
2. [Agent-relayed sources](#2-agent-relayed-sources)
3. [API-relayed sources](#3-api-relayed-sources)
4. [Microsoft 365 and the rest of the Microsoft estate](#4-microsoft-365-and-the-rest-of-the-microsoft-estate)
5. [Least-privilege permission reference](#5-least-privilege-permission-reference)
6. [Proving the path with this simulator](#6-proving-the-path-with-this-simulator)
7. [Field mapping cheat-sheet](#7-field-mapping-cheat-sheet)
8. [Troubleshooting](#8-troubleshooting)

---

## 1. The three transports

| | **native** | **agent** | **api** |
|---|---|---|---|
| Who sends | the device | a process on the host | a connector you run |
| Wire | UDP/TCP 514, TLS 6514 | UDP/TCP/TLS, or Beats/HTTP | HTTPS poll, webhook, or a broker |
| Config lives | on the device | in the agent's config file | in an identity (app registration / API token) |
| Fails by | packet loss | agent stopped, file rotated | token expired, quota exhausted, checkpoint lost |
| Latency | milliseconds | seconds | **minutes to hours** |
| Ordering | roughly ordered | roughly ordered | **not ordered** — sort on the record's own timestamp |
| Delivery | at-most-once (UDP) | at-least-once | **at-least-once — deduplicate on the record id** |

The last three rows are the ones that catch people. An API feed is a *batch*
feed wearing a stream's clothes: records arrive late, out of order, and
sometimes twice. Correlation rules with tight windows that work beautifully on
syslog quietly stop firing on an API source unless they key on the record's own
timestamp rather than on ingest time.

**The three sizing questions**, before any of the config below:

1. **Volume** — events/second at peak, not average. Sysmon on a busy fleet is the
   single loudest source most organisations ever turn on.
2. **Retention on the source side** — how long the product holds data you have not
   collected yet. This is the size of your outage budget: Office 365's unified
   audit content is available for **7 days**, so a connector that has been down
   for eight loses data permanently.
3. **Filtering point** — filter at the agent, not at the SIEM. Bytes you never
   ship cost nothing.

---

## 2. Agent-relayed sources

### 2.1 Windows Event Log — Snare or NXLog

Windows has no syslog client. An agent subscribes to the Event Log channels and
renders each record onto the wire. The simulator's `snare` source shows the
TAB-delimited `MSWinEventLog` format that both agents produce.

**Snare** (`Snare Agent > Network Configuration`, or `SnareCore` registry):

```ini
[Network]
Destination=10.0.0.50          ; the collector
DestPort=514
Syslog=1                       ; wrap in a syslog <PRI> header
SyslogFacility=13              ; log_audit
SyslogPriority=5               ; notice
Protocol=TCP                   ; UDP loses events under load — use TCP or TLS

[Objectives]
; Only what a detection actually reads. The Security channel alone is large;
; sending every channel from every host is how a SIEM licence gets burned.
Objective=1,Security,*,4624 4625 4648 4662 4672 4688 4697 4698 4720 4732 4768 4769 4776 5136 5140 5145 1102
Objective=2,System,*,7045 7040
```

**NXLog Community Edition** (`nxlog.conf`) — the same job, plus Sysmon in one
pass:

```apache
<Extension _syslog>
    Module      xm_syslog
</Extension>

<Input eventlog>
    Module      im_msvistalog
    # Subscribe with an XPath query so the filtering happens in Windows, before
    # the record is ever rendered — an order of magnitude cheaper than dropping
    # it in the agent.
    <QueryXML>
        <QueryList>
            <Query Id="0">
                <Select Path="Security">*[System[(EventID=4624 or EventID=4625 or EventID=4648 or EventID=4672 or EventID=4688 or EventID=4698 or EventID=4720 or EventID=4732 or EventID=4769 or EventID=5136 or EventID=1102)]]</Select>
                <Select Path="Microsoft-Windows-Sysmon/Operational">*</Select>
                <Select Path="System">*[System[Provider[@Name='Service Control Manager'] and (EventID=7045)]]</Select>
            </Query>
        </QueryList>
    </QueryXML>
</Input>

<Output collector>
    Module      om_tcp                 # om_ssl for TLS — see §2.5
    Host        10.0.0.50
    Port        514
    Exec        to_syslog_bsd();       # or to_syslog_ietf() for RFC 5424
</Output>

<Route eventlog_to_collector>
    Path        eventlog => collector
</Route>
```

**Do not** send the Security channel unfiltered from every workstation "so we
have it". Decide which event IDs your rules read — the list above is what the
simulator's `windows-threat`, `ad-recon` and `persistence-mech` rules key on —
and add to it when a rule needs more.

### 2.2 Sysmon

Sysmon is two installs, not one: the driver, and the configuration that decides
what it records. Out of the box it logs almost nothing useful; with a bad config
it logs everything and drowns you.

```powershell
# Install (elevated). -accepteula avoids the interactive prompt.
.\Sysmon64.exe -accepteula -i sysmonconfig.xml

# Update the config later without reinstalling the driver:
.\Sysmon64.exe -c sysmonconfig.xml
```

Start from a curated, community-maintained baseline config rather than an empty
one, then tune. The event IDs the simulator's rules read:

| ID | Event | Rule that reads it |
|----|-------|--------------------|
| 1 | Process create | `susp-powershell`, `lolbin-abuse`, `masquerading`, `sandbox-evasion`, `lateral-exec` |
| 3 | Network connect | `remote-access-tool`, `lateral-exec`, `c2-beacon` |
| 10 | Process access | `cred-dumping` (handle into `lsass.exe`), `process-injection` |
| 11 | File create | `persistence-mech`, `password-store-theft` |
| 13 | Registry value set | `persistence-mech` (Run keys) |

Sysmon writes to `Microsoft-Windows-Sysmon/Operational`, so it rides the same
agent as the Security channel — one agent, two channels (see the NXLog
`QueryXML` above). Keep the **raw event text**: the rules match on command lines
and `GrantedAccess` values, so an agent that ships only a summary line breaks
every one of them.

### 2.3 Linux auditd

The kernel audit subsystem writes to its own socket. `audisp-syslog` is the
plugin that copies each record to syslog.

```bash
# /etc/audit/plugins.d/syslog.conf   (audit 3.x; audit 2.x: /etc/audisp/plugins.d/)
active = yes
direction = out
path = /sbin/audisp-syslog
type = always
args = LOG_LOCAL6
format = string
```

```bash
# /etc/audit/rules.d/detect.rules — rules are useless without keys: the `key=`
# is what a detection matches on, and what makes the record readable a year later.
-a always,exit -F arch=b64 -S execve -F euid=0 -F auid>=1000 -F auid!=4294967295 -k rootshell
-w /etc/passwd  -p wa -k identity
-w /etc/shadow  -p wa -k identity
-w /etc/sudoers -p wa -k privesc
-w /var/log/auth.log -p wa -k logtamper
```

```bash
systemctl restart auditd     # NOT `systemctl reload` on some distros — auditd
                             # is deliberately awkward to reconfigure live
augenrules --load
```

Then in `rsyslog`, route `local6` on to the collector:

```
# /etc/rsyslog.d/60-audit-forward.conf
local6.*  action(type="omfwd" target="10.0.0.50" port="514" protocol="tcp"
                 queue.type="linkedlist" queue.filename="auditfwd"
                 queue.maxdiskspace="1g" action.resumeRetryCount="-1")
```

The disk-backed queue is the point: it is what stops a collector restart from
losing the audit trail.

### 2.4 Zeek

Zeek writes log **files** — one per path (`conn.log`, `dns.log`, `ssl.log`,
`notice.log`) — under `/opt/zeek/logs/current`. A shipper reads them.

```yaml
# filebeat.yml — TSV, one file per Zeek log path
filebeat.inputs:
  - type: filestream
    id: zeek
    paths:
      - /opt/zeek/logs/current/conn.log
      - /opt/zeek/logs/current/dns.log
      - /opt/zeek/logs/current/ssl.log
      - /opt/zeek/logs/current/notice.log
output.logstash:
  hosts: ["10.0.0.50:5044"]
```

Or with rsyslog, no Beats stack required:

```
module(load="imfile")
input(type="imfile" File="/opt/zeek/logs/current/conn.log"
      Tag="zeek_conn:" Severity="info" Facility="local6"
      PersistStateInterval="200")
```

Two things bite here. Zeek **rotates hourly** into a dated directory, so a
shipper that follows an inode rather than a path silently stops at the top of the
hour — `filestream`/`imfile` follow the path, which is what you want. And if you
run Zeek in JSON mode (`@load policy/tuning/json-logs`), the field names change
completely; pick one and keep the parsers matched to it.

### 2.5 What actually goes wrong with agents

- **UDP silently truncates and drops.** RFC 3164 receivers may cut the message at
  1024 bytes, which decapitates exactly the long Sysmon command lines your rules
  match on. Use TCP, and raise the receiver's max message size (`rsyslog`:
  `$MaxMessageSize 64k`, *before* any module loads).
- **No queue means no data during a collector restart.** Every agent above can
  spool to disk. Turn it on; size it for your longest expected outage.
- **Clock skew makes correlation windows lie.** Every rule in the engine is time
  windowed. NTP on every source is not optional.
- **The agent stops and nothing tells you.** Alert on *silence*: a source that has
  sent nothing for an hour is an incident, and it is the single most valuable
  detection you will write.
- **TLS**: `om_ssl` (NXLog), `omfwd` with `StreamDriver="gtls"` (rsyslog), port
  6514 by convention. Certificate expiry takes a feed down as effectively as a
  firewall rule — monitor it.

---

## 3. API-relayed sources

### 3.1 Every API connector is the same six steps

```
   ┌──────────────┐  1. authenticate (client credentials / API token)
   │  connector   │  2. subscribe or list content since <checkpoint>
   │  (yours, or  │  3. page through the results
   │   the        │  4. fetch each content blob
   │   vendor's)  │  5. normalise → your event model, then ship
   └──────────────┘  6. persist the new checkpoint — only after a successful ship
```

Step 6 is the one that gets written last and matters most. Persist the
checkpoint **after** the batch is safely handed off, never before: crash between
the two and you would rather re-send a batch (deduplicated on the record id)
than lose one.

A connector needs, at minimum:

- **A durable checkpoint** — a timestamp or a continuation token on disk, not in
  memory.
- **Backoff** — honour `Retry-After` / HTTP 429; a tight retry loop against a
  throttled API is how a tenant-wide quota gets exhausted for everyone else.
- **Dedupe** — every API source can hand you the same record twice.
- **Its own health signal** — last successful poll, records shipped, current lag.

### 3.2 Non-Microsoft API sources

| Source | How to get the data | Auth | Notes |
|--------|--------------------|------|-------|
| **AWS CloudTrail** | Trail → S3 bucket; bucket → SNS/SQS → your collector reads the object. (EventBridge for near-real-time.) | IAM role for the collector, `s3:GetObject` on the trail prefix + `sqs:ReceiveMessage` | Make it a **multi-region, organisation** trail with log-file validation on. Delivery is typically minutes, not seconds. |
| **Okta System Log** | `GET /api/v1/logs?since=<ISO8601>&limit=1000`, poll every 30–60 s | API token (`SSWS`), or an OAuth service app with scope `okta.logs.read` | Page with the `Link: …; rel="next"` header and **store that next link as the checkpoint** — it is more reliable than re-deriving a `since`. |
| **CrowdStrike Falcon** | Falcon SIEM Connector daemon consumes the Event Streams API and writes syslog/CEF/JSON locally | API client with the *Event streams: read* scope | Only **one** consumer per app id per stream — a second connector using the same credentials steals the offset. FDR (S3/SQS) is the bulk-telemetry alternative. |
| **Cisco Umbrella** | Managed (or self-managed) S3 bucket receives gzipped CSV; or the Reporting API v2 | Bucket keys from the Umbrella dashboard, or an API key/secret | The CSV column order is versioned — pin the parser to the documented schema version. |
| **Kubernetes audit** | API server `--audit-policy-file` + `--audit-log-path` (file → Filebeat/Fluent Bit), or `--audit-webhook-config-file` | RBAC on the collecting side; the file is on the control plane | An audit policy at `RequestResponse` for everything will bury you. Log `Metadata` broadly, `RequestResponse` only for `secrets`, `pods/exec` and RBAC objects. |

---

## 4. Microsoft 365 and the rest of the Microsoft estate

Microsoft is the reason this document exists. Five separate products, five
different feeds, five different permission models — and **none of them speaks
syslog**. This section is the one to read before promising anyone "we ingest
Office 365".

| Product | Feed | The record you get |
|---------|------|--------------------|
| Office 365 (Exchange Online, SharePoint, OneDrive, Teams, Purview, Power Automate) | Office 365 Management Activity API | unified audit `AuditData` JSON |
| Microsoft Entra ID | Diagnostic settings → Event Hub, or Graph | `SignInLogs` / `AuditLogs` JSON |
| Microsoft Defender for Endpoint / Defender XDR | Streaming API → Event Hub, or the alerts API | `AlertInfo` / `AlertEvidence` JSON |
| Azure (control plane) | Activity log → diagnostic setting → Event Hub | Activity Log JSON |
| Windows / Sysmon on the endpoint | *agent* — see [§2](#2-agent-relayed-sources) | Event Log records |

### 4.1 Office 365 unified audit log

**One API carries every Office workload.** Exchange Online, SharePoint, OneDrive,
Teams, Power Automate, Purview/eDiscovery and the Entra sign-ins visible to
Office all arrive as records on the same feed, distinguished by two fields —
`Workload` and `Operation`. That single fact shapes every detection you write
against it.

**Step 1 — turn the audit log on.** New tenants have it on; older ones may not,
and a tenant where it was switched off records nothing at all, retroactively.

```powershell
Connect-ExchangeOnline
Get-AdminAuditLogConfig | Select-Object UnifiedAuditLogIngestionEnabled
Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true
```

Mailbox auditing is separate and is what produces `MailItemsAccessed`:

```powershell
Get-OrganizationConfig | Select-Object AuditDisabled     # must be False
Set-Mailbox -Identity user@corp.example -AuditEnabled $true
```

> `MailItemsAccessed` — the record the `m365-mail-exfil` scenario is built on —
> requires the mailbox to hold the licence tier that includes advanced auditing.
> Without it you can prove a mailbox was compromised but not what was read.

**Step 2 — register the application.** Entra ID → App registrations → New
registration → Certificates & secrets (a certificate beats a client secret; a
secret that expires takes the feed down silently). Then API permissions →
**Office 365 Management APIs** → *Application* permissions → `ActivityFeed.Read`
(add `ActivityFeed.ReadDlp` only if you collect DLP events) → **Grant admin
consent**. Application permissions with no consent produce a 401 that reads like
a credential problem and is not one.

**Step 3 — start a subscription per content type.** Nothing is collected until
you do; this is the step people miss.

```http
POST https://manage.office.com/api/v1.0/{tenantId}/activity/feed/subscriptions/start
     ?contentType=Audit.Exchange&PublisherIdentifier={tenantId}
Authorization: Bearer {token}
```

Content types: `Audit.AzureActiveDirectory`, `Audit.Exchange`,
`Audit.SharePoint`, `Audit.General` (Teams, Power Automate, eDiscovery, and the
rest), `DLP.All`.

**Step 4 — poll for content, then fetch each blob.** The list call returns
*pointers*, not records:

```http
GET https://manage.office.com/api/v1.0/{tenantId}/activity/feed/subscriptions/content
    ?contentType=Audit.General&startTime=2026-09-01T00:00:00&endTime=2026-09-01T01:00:00
→ [ { "contentUri": "https://manage.office.com/.../content/2026...", "contentId": "...",
      "contentCreated": "...", "contentExpiration": "..." }, … ]

GET {contentUri}      → the array of audit records
```

Follow the `NextPageUri` response header until it is absent. A minimal
zero-dependency poll loop, in the same spirit as this project's `server.js`:

```js
// token via client credentials, scope https://manage.office.com/.default
async function poll(contentType, since) {
  let url = `https://manage.office.com/api/v1.0/${TENANT}/activity/feed/subscriptions/content`
          + `?contentType=${contentType}&startTime=${since}&PublisherIdentifier=${TENANT}`;
  const blobs = [];
  while (url) {
    const res = await get(url);                       // adds the bearer token
    if (res.status === 429) { await sleep(retryAfter(res)); continue; }
    blobs.push(...JSON.parse(res.body));
    url = res.headers.nextpageuri || null;            // header, not a body field
  }
  for (const b of blobs) {
    const records = JSON.parse((await get(b.contentUri)).body);
    await ship(records.map(normalise));               // your event model
  }
  return blobs.length ? maxCreationTime(blobs) : since;   // the new checkpoint
}
```

**What will surprise you:**

- **Latency is minutes at best, and Microsoft's published availability target is
  measured in hours.** Do not build a detection that assumes an Office 365 record
  arrives before the attacker's next move.
- **Content is retained for 7 days.** A connector down for longer has lost data
  that cannot be recovered from the API.
- **Records arrive out of order and can repeat.** Sort on `CreationTime`,
  deduplicate on `Id`.
- **The schema is a union.** Only the common fields (`CreationTime`, `Id`,
  `Operation`, `OrganizationId`, `RecordType`, `UserId`, `Workload`, `ClientIP`)
  are always present; `SiteUrl`, `TargetUserOrGroupName`, `Parameters`,
  `OperationProperties` and the rest appear only for the workloads that emit
  them. The simulator's `m365` formatter reproduces exactly this — compare the
  raw line of an `m365-sharepoint-download` event with an `m365-transport-rule`
  one.
- **`startTime`/`endTime` must span 24 hours or less**, and both are UTC.

**The operations worth alerting on** — each is a scenario in this simulator:

| Workload | Operation | Why | Scenario |
|----------|-----------|-----|----------|
| Exchange | `New-InboxRule` / `Set-InboxRule` with `ForwardTo`, especially with `DeleteMessage` | mailbox theft that survives a password reset | `m365` (appliance) |
| Exchange | `New-TransportRule` with `BlindCopyTo`, or `SetSCL -1` | the whole tenant's mail, invisible in any user's Outlook | `m365-transport-rule` |
| Exchange | `MailItemsAccessed` with `MailAccessType: Sync` at volume | a mailbox being pulled down wholesale | `m365-mail-exfil` |
| Exchange | `Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled False` | the last thing the audit log records | `m365-audit-disabled` |
| SharePoint | `FileDownloaded` / `FileSyncDownloadedFull` at volume | every event legitimate; only the rate is the signal | `m365-sharepoint-download` |
| OneDrive | `AnonymousLinkCreated`, `SharingInvitationCreated` to an external address | a URL that needs no account | `m365-anon-sharing` |
| Teams | `MemberAdded` (external guest), `TeamSettingChanged` (`AllowGuestUser`) | an outsider inside a private team, with its history | `m365-teams-external` |
| SecurityComplianceCenter | `SearchCreated` / `SearchExported` across all mailboxes | eDiscovery is a supported, audited exfiltration tool | `m365-ediscovery` |
| MicrosoftFlow | `CreateFlow` wiring Outlook to an HTTP connector | a forwarding rule that does not live in the mailbox | `m365-power-automate` |

### 4.2 Microsoft Entra ID

Two categories, one connector — and they are **different record shapes**:

- **`SignInLogs`** — who authenticated, from where, with what, and what
  Conditional Access decided.
- **`AuditLogs`** — what changed in the directory: MFA methods, Conditional
  Access policies, role assignments, applications.

Most teams collect the first and forget the second. The second is where account
takeover becomes *persistence* — a rogue authenticator registered
(`entra-mfa-tamper`), a Conditional Access policy quietly set to report-only
(`entra-ca-tamper`).

**The recommended path — diagnostic settings → Event Hub:**

Entra ID → Monitoring → Diagnostic settings → Add. Select the categories you
need (`SignInLogs`, `AuditLogs`, `NonInteractiveUserSignInLogs`,
`ServicePrincipalSignInLogs`, `ManagedIdentitySignInLogs`, `ProvisioningLogs`,
`RiskyUsers`, `UserRiskEvents`) and stream to an Event Hub. Your collector needs
the **Azure Event Hubs Data Receiver** role on that namespace.

Non-interactive and service-principal sign-ins are separate categories and are
frequently *far* larger than the interactive ones. Turn them on deliberately.

**The API path** — Graph, when an Event Hub is not available:

```http
GET https://graph.microsoft.com/v1.0/auditLogs/signIns?$filter=createdDateTime ge 2026-09-01T00:00:00Z
GET https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?$filter=activityDateTime ge 2026-09-01T00:00:00Z
```

Application permissions `AuditLog.Read.All` **and** `Directory.Read.All` (Graph
requires both for sign-ins). Page with `@odata.nextLink`. Sign-in log access
requires an Entra ID P1 licence or better; audit logs do not.

Expect a few minutes of latency, and note that `SignInLogs` retention in the
service itself is 7 or 30 days depending on licence — the Event Hub or your SIEM
is the long-term copy.

### 4.3 Microsoft Defender for Endpoint / Defender XDR

Defender is an EDR: what it emits is a **verdict**, not raw telemetry. The
technique is already named in `AttackTechniques`, which is why the simulator's
`appliance-threat` rule prefers the sensor's own ATT&CK mapping over re-deriving
one from the alert title.

**Streaming API (recommended for volume):** Microsoft Defender portal → Settings
→ Microsoft Defender XDR → Streaming API → Add. Choose an **Event Hub** (or a
storage account) and select the event types. `AlertInfo` + `AlertEvidence` give
you the alerts; `DeviceProcessEvents`, `DeviceNetworkEvents`,
`DeviceRegistryEvents` and friends give you the hunting telemetry — and are
enormous. Start with alerts, add telemetry tables one at a time with a volume
measurement between each.

Configuring it needs Global Administrator or Security Administrator; the
collector needs *Azure Event Hubs Data Receiver* on the namespace.

**Alerts API (small volume, simple):**

```http
GET https://api.securitycenter.microsoft.com/api/alerts?$filter=alertCreationTime ge 2026-09-01T00:00:00Z
```

App registration → **WindowsDefenderATP** → Application permission `Alert.Read.All`
→ admin consent; token scope `https://api.securitycenter.microsoft.com/.default`.
The Graph equivalent is `GET /v1.0/security/alerts_v2` with `SecurityAlert.Read.All`,
which also covers Defender for Office, Identity and Cloud Apps in one feed.

Defender is not a substitute for Sysmon and Sysmon is not a substitute for
Defender: one tells you what a sensor concluded, the other tells you what
happened. The simulator ships both (`defender` and `sysmon`) so the difference is
visible side by side — compare a `defender` burst with an `lsass-dump` one.

**Tamper alerts are the ones to wire first.** `mde-tamper` fires the
`security-tooling-disabled` rule from Defender's own alert titles ("Tamper
protection was turned off", "sensor stopped"), which is the telemetry you get
*after* an attacker has taken away the telemetry you were relying on.

### 4.4 Azure Activity Log

Monitor → Activity log → Export activity logs → add a diagnostic setting per
subscription → stream to the same Event Hub. Categories: `Administrative`,
`Security`, `Policy`, `ServiceHealth`, `ResourceHealth`, `Alert`, `Autoscale`,
`Recommendation`. `Administrative` is the one that carries role assignments,
`listKeys`, key-vault policy changes and diagnostic-setting deletion — the four
things the simulator's `azure` source and `cloud-threat` rule are built around.

One diagnostic setting per subscription. A management-group-level policy that
creates them automatically is the only way this stays true as subscriptions are
added.

### 4.5 A note on Microsoft licensing

Several of the records above exist only at certain licence tiers —
`MailItemsAccessed` and long audit retention, Entra sign-in logs via API,
Defender's advanced hunting tables. It is worth confirming which of your
detections depend on a record your tenant is not actually entitled to *before*
the rule is written, not after it silently never fires.

---

## 5. Least-privilege permission reference

| Source | Identity | Permission / role | Consent needed |
|--------|----------|------------------|----------------|
| Office 365 unified audit | Entra app registration | Office 365 Management APIs → `ActivityFeed.Read` (application) | admin consent |
| Office 365 DLP events | same | `ActivityFeed.ReadDlp` (application) | admin consent |
| Entra sign-in / audit logs (Graph) | Entra app registration | `AuditLog.Read.All` + `Directory.Read.All` (application) | admin consent |
| Entra logs (Event Hub) | collector's managed identity or SP | **Azure Event Hubs Data Receiver** on the namespace | RBAC assignment |
| Defender for Endpoint alerts | Entra app registration | WindowsDefenderATP → `Alert.Read.All` (application) | admin consent |
| Defender XDR streaming | portal setting + collector identity | configure: Global/Security Admin · read: Event Hubs Data Receiver | RBAC assignment |
| Azure Activity Log | diagnostic setting + collector identity | configure: Monitoring Contributor · read: Event Hubs Data Receiver | RBAC assignment |
| AWS CloudTrail | IAM role for the collector | `s3:GetObject` on the trail prefix, `sqs:ReceiveMessage`/`DeleteMessage` | — |
| Okta System Log | API token, or OAuth service app | `okta.logs.read` | admin |
| CrowdStrike Falcon | API client | *Event streams: read* | Falcon admin |
| Cisco Umbrella | bucket keys or API key/secret | read on the log bucket | Umbrella admin |

Rules that hold for all of them:

- **Read-only, always.** No connector needs write access to anything.
- **A certificate over a client secret** where the product supports it; where it
  does not, put the secret expiry in the same calendar the TLS certificates are
  in. An expired credential is the single most common cause of a feed that "just
  stopped".
- **One identity per connector.** Shared credentials make revocation an outage
  and make the audit trail useless.
- **The connector's own activity is logged too.** Baseline it, so a stolen
  connector credential used from somewhere else stands out.

---

## 6. Proving the path with this simulator

The point of the simulator is that you can test the collector, the parser and the
rule **before** any of the above is finished — and then again afterwards, to
prove the real feed produces the same result.

**From a terminal, on the collector itself** — no browser, no backend, and the
fastest way to answer "can this box reach that collector at all":

```bash
jedi --forward tcp://10.0.0.50:514 --test        # probe: exit 1 if unreachable
jedi appliance m365 --forward tcp://10.0.0.50:514 --raw   # one real burst
jedi --forward udp://10.0.0.50:514 --eps 20 --every 30 --quiet   # sustained
```

The terminal build sends the datagram itself, so what you are testing is the
path from *that host* — not from the machine running a browser. See
[README.md § Terminal build](README.md#terminal-build).

**Or from the dashboard, end to end:**

1. Run the backend — a browser page cannot open a raw socket:
   `node server.js` → <http://localhost:8099> (see `README.md` for sign-in).
2. **Log Collector** panel → set the protocol (UDP / TCP / Splunk HEC), the host
   and the port of your real collector → **Test**. A green result means the
   packet path and any firewall in between are good.
3. Turn **Forward live** on.
4. Click the appliance source you are onboarding under **Appliance logs ›** —
   `Microsoft 365 audit`, `Microsoft Entra ID`, `Defender for Endpoint` — and
   the live stream narrows to just that source, in its real wire format.
5. Confirm your collector parses it: the fields in [§7](#7-field-mapping-cheat-sheet)
   should land in the right places, not in a catch-all "message" blob.

**Test the detection:**

6. Fire the matching scenario under **Attack ›** (for example
   `Exchange Transport Rule Tamper`), and confirm the alert appears in
   **Detections** here — then confirm your own SIEM raised the equivalent one
   from the forwarded copy. If it did not, the gap is in your parser or your
   rule, and you have found it without waiting for a real attacker.

**Test the failure modes**, which is where the value actually is:

- Stop the collector for a minute with forwarding on — does anything alert on the
  silence?
- Point the forwarder at a wrong port — does the connectivity test tell you
  clearly, or does data disappear quietly?
- Send an appliance burst at 60 EPS — does your UDP path drop it? (It will.)

---

## 7. Field mapping cheat-sheet

What the product calls it → what the detection needs. If your parser fills these,
the rules in `js/jedi.js` (and their equivalents in your own SIEM) work.

| Event model | Office 365 | Entra ID | Defender XDR | CloudTrail | Okta |
|-------------|-----------|----------|--------------|------------|------|
| timestamp | `CreationTime` | `time` / `activityDateTime` | `Timestamp` | `eventTime` | `published` |
| user | `UserId` | `properties.userPrincipalName` / `initiatedBy.user` | `AccountName` | `userIdentity.arn` | `actor.alternateId` |
| source IP | `ClientIP` / `ActorIpAddress` | `properties.ipAddress` | `RemoteIP` | `sourceIPAddress` | `client.ipAddress` |
| host | *(the connector)* | *(the connector)* | `DeviceName` | *(the account)* | *(the connector)* |
| action | `Operation` | `activityDisplayName` | `Title` | `eventName` | `eventType` |
| product area | `Workload` | `category` | `Category` | `eventSource` | — |
| outcome | `ResultStatus` | `resultType` / `status.errorCode` | `Status` | `errorCode` | `outcome.result` |
| object | `ObjectId` | `targetResources[].displayName` | `FileName` / `FolderPath` | `requestParameters` | `target[]` |
| dedupe key | `Id` | `properties.id` | `AlertId` | `eventID` | `uuid` |

Two mappings people get wrong:

- **`host`.** For every API source the syslog `host` is *the connector*, not the
  machine the event happened on. Grouping alerts by `host` on an API feed groups
  everything onto one box. Use `DeviceName` / `ObjectId` / the resource id.
- **The timestamp.** Ingest time and event time differ by minutes to hours on API
  feeds. Correlate on the record's own timestamp or your windows are fiction.

---

## 8. Troubleshooting

| Symptom | Usual cause |
|---------|-------------|
| 401 from an Office 365 / Graph / Defender API with a token that looks fine | *Application* permission granted but **admin consent** never clicked |
| The subscription call succeeds, `/content` is always empty | subscription never `start`ed for that `contentType`, or the unified audit log is off in the tenant |
| Records stop at exactly the same time every day | client secret expired; certificate expired; token cache pinned to a stale credential |
| Duplicate alerts from an API source | no dedupe on the record id — API delivery is at-least-once |
| Correlation rules fire on syslog but never on the API feed | rule keyed on ingest time; API records arrive late and out of order |
| A gap of hours with no error anywhere | connector restarted and re-read its checkpoint from *memory*; persist it to disk |
| Windows command lines truncated mid-string | UDP + a 1024-byte receiver limit — move to TCP and raise the max message size |
| Zeek logs stop at the top of every hour | shipper following an inode through the hourly rotation instead of the path |
| auditd records missing after a config change | rules loaded but `auditd` not restarted, or the `audisp-syslog` plugin left `active = no` |
| Feed "works" but the SIEM shows one host | the API source's syslog host is the connector — map the device from the record body (see §7) |
| Everything arrives, nothing alerts | the parser dropped the field the rule reads; check a raw line against §7 before touching the rule |

---

Created By: **Alfredo Nacino** · [www.alfredonacino.com](https://www.alfredonacino.com) · alfredo@nacino.net
