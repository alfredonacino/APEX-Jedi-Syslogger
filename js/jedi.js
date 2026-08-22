/*
 * jedi.js — the "Jedi" SIEM analysis engine.
 * Ingests events from the Syslogger, maintains rolling statistics, and runs a
 * stateful detection-rule engine that raises MITRE ATT&CK-tagged alerts.
 */
(function (global) {
  'use strict';
  const { THREAT_INTEL } = global.JS;

  const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1 };

  // ---- Detection rules ------------------------------------------------------
  // Correlating rules keep per-source-IP sliding windows; pattern rules fire on
  // a single event. `ctx` carries the shared correlation state + an emit() hook.
  function makeRules() {
    return [
      {
        id: 'ssh-bruteforce', name: 'SSH Brute-Force Attempt', severity: 'high',
        tactic: 'Credential Access', technique: 'T1110 · Brute Force',
        run(ev, ctx) {
          if (ev.program !== 'sshd' || !/Failed password/i.test(ev.message)) return;
          const key = ev.srcIp;
          const w = ctx.window('bruteforce', key, 60000, ev.ts);
          w.push(ev.ts);
          if (w.length >= 8 && ctx.cooldown('bruteforce', key, 60000, ev.ts)) {
            return {
              severity: THREAT_INTEL.ips.includes(key) ? 'critical' : 'high',
              message: `${w.length} failed SSH logins from ${key} on ${ev.host} within 60s`,
              srcIp: key, host: ev.host,
              evidence: [`user=${ev.user}`, `attempts=${w.length}`, ev.message],
            };
          }
        },
      },
      {
        id: 'brute-success', name: 'Successful Login After Brute Force', severity: 'critical',
        tactic: 'Initial Access', technique: 'T1078 · Valid Accounts',
        run(ev, ctx) {
          if (ev.program !== 'sshd' || !/Accepted password/i.test(ev.message)) return;
          const w = ctx.peek('bruteforce', ev.srcIp);
          if (w && w.length >= 6) {
            return {
              severity: 'critical',
              message: `Login ACCEPTED for ${ev.user} from ${ev.srcIp} after ${w.length} failures — likely compromised`,
              srcIp: ev.srcIp, host: ev.host, evidence: [ev.message],
            };
          }
        },
      },
      {
        id: 'port-scan', name: 'Horizontal Port Scan', severity: 'medium',
        tactic: 'Reconnaissance', technique: 'T1046 · Network Service Discovery',
        run(ev, ctx) {
          if (ev.srcType !== 'firewall' || ev.action !== 'DENY') return;
          const key = ev.srcIp;
          const ports = ctx.windowSet('portscan', key, 30000, ev.ts, ev.dstPort);
          if (ports.size >= 15 && ctx.cooldown('portscan', key, 30000, ev.ts)) {
            return {
              severity: THREAT_INTEL.ips.includes(key) ? 'high' : 'medium',
              message: `Port scan from ${key}: ${ports.size} distinct ports hit on ${ev.dstIp} in 30s`,
              srcIp: key, host: ev.host, evidence: [`unique_ports=${ports.size}`, ev.message],
            };
          }
        },
      },
      {
        id: 'sql-injection', name: 'SQL Injection Attempt', severity: 'high',
        tactic: 'Initial Access', technique: 'T1190 · Exploit Public-Facing Application',
        run(ev) {
          if (ev.srcType !== 'web' || !ev.url) return;
          const u = decodeURIComponent(ev.url).toLowerCase();
          if (/(\bunion\b.*\bselect\b|'\s*or\s*'?\d|--|;\s*drop\s+table|sleep\(|\bor\b\s+1=1)/i.test(u)) {
            return {
              severity: 'high',
              message: `SQLi pattern in HTTP request to ${ev.host}: ${ev.url}`,
              srcIp: ev.srcIp, host: ev.host, evidence: [ev.message],
            };
          }
        },
      },
      {
        id: 'c2-beacon', name: 'C2 / Known-Bad Destination', severity: 'critical',
        tactic: 'Command and Control', technique: 'T1071 · Application Layer Protocol',
        run(ev, ctx) {
          const dst = ev.dstIp;
          if (!dst || !THREAT_INTEL.ips.includes(dst)) return;
          // Only alert on outbound (internal -> known-bad) connections.
          if (!/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ev.srcIp || '')) return;
          const key = `${ev.srcIp}->${dst}`;
          if (!ctx.cooldown('c2', key, 20000, ev.ts)) return;
          return {
            severity: 'critical',
            message: `Internal host ${ev.srcIp} contacted known-bad IP ${dst} (threat intel match)`,
            srcIp: ev.srcIp, host: ev.host, evidence: [`dst=${dst}`, ev.message],
          };
        },
      },
      {
        id: 'data-exfil', name: 'Large Outbound Transfer', severity: 'high',
        tactic: 'Exfiltration', technique: 'T1048 · Exfiltration Over Alternative Protocol',
        run(ev) {
          if (ev.srcType !== 'firewall' || ev.action !== 'ALLOW') return;
          const MB = 100 * 1024 * 1024;
          if ((ev.bytes || 0) < MB) return;
          const mb = Math.round(ev.bytes / (1024 * 1024));
          return {
            severity: mb > 500 ? 'critical' : 'high',
            message: `Large outbound flow: ${mb} MB from ${ev.srcIp} to ${ev.dstIp}`,
            srcIp: ev.srcIp, host: ev.host, evidence: [`bytes=${ev.bytes}`, ev.message],
          };
        },
      },
      {
        id: 'dns-tunneling', name: 'Possible DNS Tunneling', severity: 'medium',
        tactic: 'Exfiltration', technique: 'T1071.004 · DNS',
        run(ev) {
          if (!/^(dns|bind|infoblox|umbrella)$/.test(ev.srcType) || !ev.domain) return;
          const label = ev.domain.split('.')[0] || '';
          const isBadDomain = THREAT_INTEL.domains.some((d) => ev.domain.endsWith(d));
          if (label.length >= 40 || isBadDomain) {
            return {
              severity: isBadDomain ? 'high' : 'medium',
              message: `Suspicious DNS query (len=${label.length}) from ${ev.srcIp}: ${ev.domain.slice(0, 60)}…`,
              srcIp: ev.srcIp, host: ev.host, evidence: [ev.message],
            };
          }
        },
      },
      {
        id: 'priv-esc', name: 'Privilege Escalation', severity: 'high',
        tactic: 'Privilege Escalation', technique: 'T1068 · Exploitation for Priv Esc',
        run(ev) {
          const priv = /USER=root ; COMMAND=\/bin\/bash/i.test(ev.message) ||
            (ev.eventId === 4672 && /SeDebugPrivilege/i.test(ev.message));
          if (!priv) return;
          return {
            severity: 'high',
            message: `Privilege escalation on ${ev.host} by ${ev.user || 'unknown'}`,
            srcIp: ev.srcIp || ev.hostIp, host: ev.host, evidence: [ev.message],
          };
        },
      },
      {
        id: 'ids-malware', name: 'IDS Malware Signature', severity: 'critical',
        tactic: 'Execution', technique: 'T1204 · User Execution',
        run(ev) {
          if (ev.srcType !== 'ids') return;
          if (!/(TROJAN|MALWARE|EXPLOIT|Beacon|CVE-)/i.test(ev.message)) return;
          const sig = (ev.message.match(/ET [A-Z]+ [^\[]+/) || [ev.message])[0].trim();
          return {
            severity: 'critical',
            message: `IDS alert: ${sig}`,
            srcIp: ev.srcIp, host: ev.host, evidence: [ev.message],
          };
        },
      },
      {
        id: 'auditd-rootshell', name: 'Root Shell From Unprivileged Login', severity: 'high',
        tactic: 'Privilege Escalation', technique: 'T1548 · Abuse Elevation Control Mechanism',
        run(ev) {
          if (ev.srcType !== 'auditd' || ev.auditType !== 'SYSCALL') return;
          // auid is the login identity and survives su/sudo; uid is who the syscall
          // runs as. auid set, non-root, but uid=0 means an unprivileged login is
          // executing as root. Legitimate sudo looks like this too, which is why
          // the audit rule key (set by a local watch) is required to narrow it.
          const unset = 4294967295; // auid = -1 when no login session (daemons)
          if (ev.uid !== 0 || ev.auid == null || ev.auid === 0 || ev.auid === unset) return;
          if (!/key="rootshell"/.test(ev.auditBody || '')) return;
          return {
            severity: 'high',
            message: `Root shell from unprivileged login on ${ev.host}: auid=${ev.auid} running uid=0 (${ev.comm})`,
            srcIp: ev.hostIp, host: ev.host,
            evidence: [`auid=${ev.auid}`, `uid=${ev.uid}`, `comm=${ev.comm}`, ev.raw || ev.message],
          };
        },
      },
      {
        id: 'radius-brute', name: 'RADIUS / 802.1X Brute Force', severity: 'high',
        tactic: 'Credential Access', technique: 'T1110 · Brute Force',
        run(ev, ctx) {
          if (ev.srcType !== 'ciscoise' || ev.msgCode !== 5400) return;
          // Key on the supplicant MAC — one endpoint guessing many passwords.
          const key = ev.mac || ev.srcIp;
          const w = ctx.window('radiusbrute', key, 60000, ev.ts);
          w.push(ev.ts);
          if (w.length >= 6 && ctx.cooldown('radiusbrute', key, 60000, ev.ts)) {
            return {
              severity: 'high',
              message: `${w.length} failed 802.1X/RADIUS auths for ${ev.user} via ${ev.nasName} (${key}) within 60s`,
              srcIp: ev.srcIp, host: ev.host,
              evidence: [`user=${ev.user}`, `attempts=${w.length}`, `nas=${ev.nasName}`, ev.failReason],
            };
          }
        },
      },
      {
        id: 'appliance-threat', name: 'Appliance IPS / WAF Signature', severity: 'high',
        tactic: 'Initial Access', technique: 'T1190 · Exploit Public-Facing Application',
        run(ev) {
          const sig = ev.threatSig;
          if (!sig) return;
          const sev = ev.threatSev || 'high';
          // Refine ATT&CK mapping from the signature text.
          let technique = 'T1190 · Exploit Public-Facing Application', tactic = 'Initial Access';
          if (/brute|password/i.test(sig)) { technique = 'T1110 · Brute Force'; tactic = 'Credential Access'; }
          else if (/scan|recon/i.test(sig)) { technique = 'T1046 · Network Service Discovery'; tactic = 'Reconnaissance'; }
          else if (/beacon|cobalt|c2|backdoor|botnet/i.test(sig)) { technique = 'T1071 · Application Layer Protocol'; tactic = 'Command and Control'; }
          else if (/xss|cross-site/i.test(sig)) { technique = 'T1059 · Command and Scripting Interpreter'; tactic = 'Execution'; }
          else if (/malware|trojan|virus|eicar|emotet|ransom|phishing/i.test(sig)) { technique = 'T1204 · User Execution'; tactic = 'Execution'; }
          else if (/exfil|data loss|data exfiltration/i.test(sig)) { technique = 'T1048 · Exfiltration'; tactic = 'Exfiltration'; }
          // Most signatures come off a flow, but an endpoint agent's verdict has no
          // src/dst pair — name the host instead of printing "undefined → undefined".
          const where = ev.srcIp && ev.dstIp ? `${ev.srcIp} → ${ev.dstIp}` : `on ${ev.host}`;
          return {
            severity: sev, tactic, technique,
            message: `${(ev.vendor || 'appliance').toUpperCase()} signature: ${sig} (${where})`,
            srcIp: ev.srcIp || ev.hostIp, host: ev.host, evidence: [ev.raw || ev.message],
          };
        },
      },
      {
        id: 'web-exploit', name: 'Web Application Attack', severity: 'high',
        tactic: 'Initial Access', technique: 'T1190 · Exploit Public-Facing Application',
        run(ev) {
          if (ev.srcType !== 'web' || !ev.url) return;
          const u = decodeURIComponent(ev.url).toLowerCase();
          const ua = (ev.message || '').toLowerCase();
          let sig, technique = 'T1190 · Exploit Public-Facing Application', tactic = 'Initial Access', sev = 'high';
          if (/\$\{jndi:/i.test(ev.url)) { sig = 'Log4Shell JNDI injection (CVE-2021-44228)'; sev = 'critical'; }
          else if (/<script>|onerror=|javascript:|%3cscript/i.test(u)) { sig = 'Cross-Site Scripting (XSS)'; technique = 'T1059 · Command and Scripting Interpreter'; tactic = 'Execution'; }
          else if (/\.\.(\/|%2f)|\/etc\/passwd|\/etc\/shadow|win\.ini|boot\.ini/i.test(u)) { sig = 'Path Traversal / LFI'; technique = 'T1083 · File and Directory Discovery'; tactic = 'Discovery'; }
          // The link-local metadata address is only reachable from the instance
          // itself, so a request carrying it is the app fetching on someone's behalf.
          else if (/169\.254\.169\.254|\/latest\/meta-data|metadata\.google\.internal|\/computemetadata\//i.test(u)) { sig = 'SSRF to cloud instance metadata'; technique = 'T1552.005 · Cloud Instance Metadata API'; tactic = 'Credential Access'; sev = 'critical'; }
          else if (/\.(php|asp|aspx|jsp)\?cmd=|shell\.(php|aspx)|c99\.php|r57\.php|webshell/i.test(u)) { sig = 'Web Shell activity'; technique = 'T1505.003 · Web Shell'; tactic = 'Persistence'; sev = 'critical'; }
          else if (/nikto|sqlmap|nmap|masscan|acunetix|nessus|dirbuster|gobuster/i.test(ua)) { sig = 'Vulnerability scanner'; technique = 'T1595 · Active Scanning'; tactic = 'Reconnaissance'; sev = 'medium'; }
          if (!sig) return;
          return { severity: sev, tactic, technique, message: `${sig}: ${ev.url.slice(0, 80)}`, srcIp: ev.srcIp, host: ev.host, evidence: [ev.message] };
        },
      },
      {
        id: 'windows-threat', name: 'Windows Security Event', severity: 'high',
        tactic: 'Credential Access', technique: 'T1078 · Valid Accounts',
        run(ev, ctx) {
          // 'snare' is the same Windows Event Log over an agent — same event IDs,
          // different wire format, so it reuses this rule rather than cloning it.
          if (ev.srcType !== 'windows' && ev.srcType !== 'snare') return;
          const m = ev.message || '', eid = ev.eventId;
          if (eid === 4625) {
            const users = ctx.windowSet('winspray', ev.srcIp || 'x', 60000, ev.ts, ev.user);
            if (users.size >= 8 && ctx.cooldown('winspray', ev.srcIp || 'x', 60000, ev.ts))
              return { severity: 'high', tactic: 'Credential Access', technique: 'T1110.003 · Password Spraying', message: `Password spray from ${ev.srcIp}: ${users.size} accounts tried`, srcIp: ev.srcIp, host: ev.host, evidence: [m] };
            const w = ctx.window('winbrute', ev.srcIp || ev.user, 60000, ev.ts); w.push(ev.ts);
            if (w.length >= 8 && ctx.cooldown('winbrute', ev.srcIp || ev.user, 60000, ev.ts))
              return { severity: 'high', tactic: 'Credential Access', technique: 'T1110 · Brute Force', message: `${w.length} failed Windows logons from ${ev.srcIp} on ${ev.host}`, srcIp: ev.srcIp, host: ev.host, evidence: [m] };
            return;
          }
          // A forged TGT never passed through the DC, so the service-ticket request
          // it produces carries no account domain.
          if (eid === 4769 && /account domain:\s*-/i.test(m)) return { severity: 'critical', tactic: 'Credential Access', technique: 'T1558.001 · Golden Ticket', message: `Forged Kerberos ticket used on ${ev.host}: service ticket requested with a blank account domain`, srcIp: ev.srcIp, host: ev.host, evidence: [m] };
          // Pre-auth type 0 means the DC handed out an RC4 AS-REP to an unauthenticated
          // caller — crackable offline, and it logs no failure. One alert per host.
          if (eid === 4768 && /pre-authentication type:\s*0\b/i.test(m) && /0x17|rc4/i.test(m)) {
            if (!ctx.cooldown('asrep', ev.host, 30000, ev.ts)) return;
            return { severity: 'high', tactic: 'Credential Access', technique: 'T1558.004 · AS-REP Roasting', message: `AS-REP roasting on ${ev.host}: TGT issued without pre-authentication for ${ev.user || 'an account'}`, srcIp: ev.srcIp, host: ev.host, evidence: [m] };
          }
          if (eid === 7045 && /psexesvc|paexec|remcom|csexec/i.test(m)) return { severity: 'high', tactic: 'Lateral Movement', technique: 'T1021.002 · SMB / Windows Admin Shares', message: `Remote-execution service installed on ${ev.host} by ${ev.user || 'unknown'}`, srcIp: ev.srcIp, host: ev.host, evidence: [m] };
          // A GPO is code that runs everywhere it is linked, so an edit to one is
          // domain-wide execution. One alert per object per burst.
          if (eid === 5136 && /groupPolicyContainer/i.test(m)) {
            if (!ctx.cooldown('gpo', ev.host, 30000, ev.ts)) return;
            return { severity: 'high', tactic: 'Privilege Escalation', technique: 'T1484.001 · Group Policy Modification', message: `Group Policy Object modified on ${ev.host} by ${ev.user || 'unknown'}`, srcIp: ev.srcIp, host: ev.host, evidence: [m] };
          }
          // A template that lets the requester name the subject issues a cert *as*
          // anyone. The certificate then outlives any password reset.
          if ((eid === 4886 || eid === 4887) && /SAN:upn=|SubjectAltName=/i.test(m)) {
            const target = (m.match(/(?:SAN:upn=|SubjectAltName=)(\S+)/i) || [, 'another principal'])[1];
            if (!ctx.cooldown('adcs', `${ev.host}:${ev.user}`, 30000, ev.ts)) return;
            return { severity: 'critical', tactic: 'Credential Access', technique: 'T1649 · Steal or Forge Authentication Certificates', message: `ADCS abuse on ${ev.host}: ${ev.user || 'a user'} requested a certificate for ${target}`, srcIp: ev.srcIp, host: ev.host, evidence: [m] };
          }
          if (eid === 1102 || /audit log was cleared/i.test(m)) return { severity: 'high', tactic: 'Defense Evasion', technique: 'T1070.001 · Clear Windows Event Logs', message: `Security audit log cleared on ${ev.host}`, srcIp: ev.srcIp, host: ev.host, evidence: [m] };
          if (eid === 4732 || /added to.*(administrators|domain admins)/i.test(m)) return { severity: 'high', tactic: 'Persistence', technique: 'T1136 · Create Account', message: `Account added to a privileged group on ${ev.host}: ${ev.user || ''}`, srcIp: ev.srcIp, host: ev.host, evidence: [m] };
          if (eid === 4720) return { severity: 'medium', tactic: 'Persistence', technique: 'T1136 · Create Account', message: `New user account created on ${ev.host}: ${ev.user || ''}`, srcIp: ev.srcIp, host: ev.host, evidence: [m] };
          if (eid === 4769 && /0x17|rc4/i.test(m)) return { severity: 'high', tactic: 'Credential Access', technique: 'T1558.003 · Kerberoasting', message: `Kerberoasting: RC4 service-ticket request for ${ev.user || 'service'} on ${ev.host}`, srcIp: ev.srcIp, host: ev.host, evidence: [m] };
          if (eid === 4662 && /replicat|1131f6a/i.test(m)) return { severity: 'critical', tactic: 'Credential Access', technique: 'T1003.006 · DCSync', message: `DCSync / replication rights used on ${ev.host} by ${ev.user || ''}`, srcIp: ev.srcIp, host: ev.host, evidence: [m] };
          if (eid === 4624 && /logontype=9|pass-the-hash/i.test(m)) return { severity: 'high', tactic: 'Lateral Movement', technique: 'T1550.002 · Pass-the-Hash', message: `Possible Pass-the-Hash logon on ${ev.host} (${ev.user || ''})`, srcIp: ev.srcIp, host: ev.host, evidence: [m] };
          return;
        },
      },
      {
        // Sysmon telemetry is process-level, so these rules read the message text
        // rather than a source type — the same behaviour shows up in a 4688
        // command line as in a Sysmon 1, and both should alert.
        id: 'cred-dumping', name: 'Credential Dumping (LSASS)', severity: 'critical',
        tactic: 'Credential Access', technique: 'T1003.001 · LSASS Memory',
        run(ev, ctx) {
          const m = ev.message || '';
          // Sysmon 10 is a handle request into another process: lsass as the target
          // plus dump-capable access rights is the signal, whatever opened it.
          const lsass = ev.eventId === 10 && /lsass\.exe/i.test(m) && /0x1010|0x1410|0x1438|0x143a/i.test(m);
          const tooling = /comsvcs\.dll.*minidump|procdump[^"]*(-|\/)ma[^"]*lsass|mimikatz|sekurlsa::|nanodump|dumpert/i.test(m);
          if (!lsass && !tooling) return;
          if (!ctx.cooldown('lsass', ev.host, 30000, ev.ts)) return;
          return {
            severity: 'critical',
            message: `LSASS credential dumping on ${ev.host}: ${m.slice(0, 90)}`,
            srcIp: ev.srcIp || ev.hostIp, host: ev.host, evidence: [ev.raw || m],
          };
        },
      },
      {
        id: 'persistence-mech', name: 'Persistence Mechanism Created', severity: 'high',
        tactic: 'Persistence', technique: 'T1547.001 · Registry Run Keys',
        run(ev, ctx) {
          const m = ev.message || '';
          let technique;
          if (/currentversion\\run(once)?\\/i.test(m)) technique = 'T1547.001 · Registry Run Keys / Startup Folder';
          else if (ev.eventId === 4698 || /schtasks(\.exe)? +\/create|register-scheduledtask/i.test(m)) technique = 'T1053.005 · Scheduled Task';
          // PsExec-style service installs are lateral movement, not persistence —
          // windows-threat owns those, so they are excluded here.
          else if ((ev.eventId === 7045 || /sc(\.exe)? +create /i.test(m)) && !/psexesvc|paexec|remcom|csexec/i.test(m)) technique = 'T1543.003 · Windows Service';
          if (!technique) return;
          if (!ctx.cooldown('persist', `${ev.host}:${technique}`, 30000, ev.ts)) return;
          return {
            severity: 'high', technique,
            message: `Persistence created on ${ev.host}: ${m.slice(0, 90)}`,
            srcIp: ev.srcIp || ev.hostIp, host: ev.host, evidence: [ev.raw || m],
          };
        },
      },
      {
        id: 'lolbin-abuse', name: 'LOLBin Download / Proxy Execution', severity: 'high',
        tactic: 'Command and Control', technique: 'T1105 · Ingress Tool Transfer',
        run(ev, ctx) {
          const m = ev.message || '';
          let tactic, technique;
          if (/certutil(\.exe)?[^"]*-(urlcache|decode)|bitsadmin(\.exe)?[^"]*\/transfer/i.test(m)) {
            tactic = 'Command and Control'; technique = 'T1105 · Ingress Tool Transfer';
          } else if (/mshta(\.exe)? +(http|javascript:)|regsvr32(\.exe)?[^"]*\/i:http|rundll32(\.exe)?[^"]*javascript:/i.test(m)) {
            tactic = 'Defense Evasion'; technique = 'T1218 · System Binary Proxy Execution';
          }
          if (!technique) return;
          if (!ctx.cooldown('lolbin', ev.host, 30000, ev.ts)) return;
          return {
            severity: 'high', tactic, technique,
            message: `Signed-binary abuse on ${ev.host}: ${m.slice(0, 90)}`,
            srcIp: ev.srcIp || ev.hostIp, host: ev.host, evidence: [ev.raw || m],
          };
        },
      },
      {
        id: 'security-tooling-disabled', name: 'Security Tooling Disabled', severity: 'high',
        tactic: 'Defense Evasion', technique: 'T1562.001 · Disable or Modify Tools',
        run(ev, ctx) {
          const m = ev.message || '';
          if (!/disablerealtimemonitoring|disableantispyware|disableioavprotection|mppreference[^"]*-exclusion|amsiinitfailed|amsiscanbuffer|net(\.exe)? +stop +(windefend|sense)|sc(\.exe)? +(config|delete) +(windefend|sysmon)/i.test(m)) return;
          if (!ctx.cooldown('sectool', ev.host, 30000, ev.ts)) return;
          return {
            severity: 'high',
            message: `Endpoint protection tampered with on ${ev.host}: ${m.slice(0, 90)}`,
            srcIp: ev.srcIp || ev.hostIp, host: ev.host, evidence: [ev.raw || m],
          };
        },
      },
      {
        id: 'ad-recon', name: 'Active Directory Enumeration', severity: 'high',
        tactic: 'Discovery', technique: 'T1087.002 · Domain Account Discovery',
        run(ev, ctx) {
          const m = ev.message || '', key = ev.host || 'ad';
          if (/sharphound|bloodhound|adfind(\.exe)?|get-domain(user|computer|group)|get-net(user|computer|session)/i.test(m)) {
            if (!ctx.cooldown('adrecon', key, 30000, ev.ts)) return;
            return {
              severity: 'high',
              message: `AD enumeration tooling on ${ev.host}: ${m.slice(0, 90)}`,
              srcIp: ev.srcIp || ev.hostIp, host: ev.host, evidence: [ev.raw || m],
            };
          }
          // Or the collector's footprint with no tool name on disk: a burst of
          // directory object reads by one account inside a minute.
          if (ev.eventId !== 4662 || !/directory service object/i.test(m)) return;
          const w = ctx.window('adenum', `${key}:${ev.user}`, 60000, ev.ts); w.push(ev.ts);
          if (w.length >= 10 && ctx.cooldown('adrecon', key, 30000, ev.ts))
            return {
              severity: 'medium',
              message: `LDAP enumeration burst on ${ev.host}: ${w.length} directory object reads by ${ev.user} in 60s`,
              srcIp: ev.srcIp || ev.hostIp, host: ev.host, evidence: [`reads=${w.length}`, m],
            };
        },
      },
      {
        id: 'cloud-threat', name: 'Cloud Control-Plane Abuse', severity: 'high',
        tactic: 'Defense Evasion', technique: 'T1562.008 · Disable Cloud Logs',
        run(ev, ctx) {
          // Three schemas, one behaviour: the AWS, Azure and Microsoft 365 control
          // planes get abused the same way, so they share this rule rather than
          // each getting a near-identical clone.
          if (ev.srcType === 'azure') {
            const op = ev.operationName || '';
            const props = JSON.stringify(ev.azProperties || {});
            let sev = 'high', tactic, technique, what;
            if (/INSIGHTS\/DIAGNOSTICSETTINGS\/DELETE/.test(op)) {
              sev = 'critical'; tactic = 'Defense Evasion'; technique = 'T1562.008 · Disable or Modify Cloud Logs';
              what = 'subscription audit logging deleted';
            } else if (/ROLEASSIGNMENTS\/WRITE/.test(op) && /Owner|User Access Administrator/.test(props)) {
              sev = 'critical'; tactic = 'Privilege Escalation'; technique = 'T1098.003 · Additional Cloud Roles';
              what = 'privileged role assigned';
            } else if (/LISTKEYS\/ACTION/.test(op)) {
              tactic = 'Credential Access'; technique = 'T1552.001 · Credentials In Files';
              what = 'storage account keys listed';
            } else if (/KEYVAULT\/VAULTS\/WRITE/.test(op)) {
              tactic = 'Credential Access'; technique = 'T1555 · Credentials from Password Stores';
              what = 'key vault access policy rewritten';
            }
            if (!technique || !ctx.cooldown('cloud', `${ev.tenantId}:${technique}`, 30000, ev.ts)) return;
            return {
              severity: sev, tactic, technique,
              message: `Azure: ${what} (${op}) by ${ev.user} from ${ev.srcIp}`,
              srcIp: ev.srcIp, host: ev.host, evidence: [`operation=${op}`, ev.raw || ev.message],
            };
          }
          if (ev.srcType === 'm365') {
            const op = ev.operation || '';
            const params = JSON.stringify(ev.parameters || []);
            if (!/^(New|Set)-InboxRule$/.test(op) || !/ForwardTo|ForwardAsAttachmentTo|RedirectTo/.test(params)) return;
            if (!ctx.cooldown('cloud', `${ev.user}:inboxrule`, 30000, ev.ts)) return;
            // Deleting the forwarded copy is what keeps the owner from noticing.
            const hides = /"DeleteMessage","Value":"True"/.test(params);
            return {
              severity: hides ? 'critical' : 'high', tactic: 'Collection',
              technique: 'T1114.003 · Email Forwarding Rule',
              message: `Microsoft 365: forwarding rule created on ${ev.user}'s mailbox from ${ev.srcIp}` +
                (hides ? ' — forwarded mail is deleted from the mailbox' : ''),
              srcIp: ev.srcIp, host: ev.host, evidence: [`operation=${op}`, ev.raw || ev.message],
            };
          }
          if (ev.srcType !== 'cloudtrail') return;
          const n = ev.eventName || '';
          // Nested policy documents come back from JSON.stringify with escaped
          // quotes; strip the backslashes so a policy body reads like a plain param.
          const p = JSON.stringify(ev.requestParameters || {}).replace(/\\/g, '');
          const who = ev.arn || ev.user || 'unknown';
          let sev = 'high', tactic, technique, what;
          if (/^(StopLogging|DeleteTrail|PutEventSelectors|DeleteDetector|DeleteFlowLogs)$/.test(n)) {
            sev = 'critical'; tactic = 'Defense Evasion'; technique = 'T1562.008 · Disable or Modify Cloud Logs';
            what = `audit logging disabled (${n})`;
          } else if (/^(CreateAccessKey|CreateLoginProfile|CreateUser|UpdateAccessKey)$/.test(n)) {
            tactic = 'Persistence'; technique = 'T1098.001 · Additional Cloud Credentials';
            what = `new IAM credential path (${n})`;
          } else if (/^(AttachUserPolicy|AttachRolePolicy|PutUserPolicy|PutRolePolicy)$/.test(n) && /AdministratorAccess|"Action":"\*"/.test(p)) {
            sev = 'critical'; tactic = 'Privilege Escalation'; technique = 'T1098.003 · Additional Cloud Roles';
            what = `administrator policy attached (${n})`;
          } else if (/^(PutBucketAcl|PutBucketPolicy|PutObjectAcl|PutPublicAccessBlock)$/.test(n) &&
                     /AllUsers|public-read|"Principal":"\*"|"BlockPublicAcls":false/.test(p)) {
            sev = 'critical'; tactic = 'Collection'; technique = 'T1530 · Data from Cloud Storage Object';
            what = `storage opened to the public (${n})`;
          } else if (n === 'ConsoleLogin' && /root/i.test(ev.identityType || '')) {
            tactic = 'Initial Access'; technique = 'T1078.004 · Cloud Accounts';
            what = 'root account console login';
          }
          if (!technique) return;
          // One alert per technique per account — an attacker's clean-up is a
          // sequence of calls, not one.
          if (!ctx.cooldown('cloud', `${ev.accountId}:${technique}`, 30000, ev.ts)) return;
          return {
            severity: sev, tactic, technique,
            message: `AWS ${ev.region}: ${what} by ${who} from ${ev.srcIp}`,
            srcIp: ev.srcIp, host: ev.host,
            evidence: [`eventName=${n}`, `userIdentity=${who}`, ev.raw || ev.message],
          };
        },
      },
      {
        id: 'identity-threat', name: 'Identity Provider Threat', severity: 'high',
        tactic: 'Initial Access', technique: 'T1078.004 · Cloud Accounts',
        run(ev, ctx) {
          // Entra ID is the same telemetry in a different schema, so it feeds this
          // rule rather than a cloned one — the branches below read whichever of
          // the two field sets is present.
          if (ev.srcType === 'entra') {
            const who = ev.user || 'unknown';
            let hit;
            if (ev.oauthConsent) {
              hit = {
                severity: 'high', tactic: 'Persistence', technique: 'T1528 · Steal Application Access Token',
                message: `OAuth consent granted to third-party app "${ev.appName}" by ${who}: ${ev.consentScopes}`,
                srcIp: ev.srcIp, host: ev.host, evidence: [`scopes=${ev.consentScopes}`, ev.raw || ev.message],
              };
            // Legacy protocols cannot present an MFA challenge, so Conditional
            // Access reports notApplied and a password alone gets in.
            } else if (ev.errorCode === 0 && /IMAP4|POP3|SMTP Auth|Other clients/i.test(ev.clientApp || '') && ev.caStatus === 'notApplied') {
              hit = {
                severity: 'high', tactic: 'Defense Evasion', technique: 'T1078.004 · Cloud Accounts',
                message: `Legacy-auth MFA bypass: ${who} signed in via ${ev.clientApp} from ${ev.srcIp} (${ev.countryCode}), Conditional Access notApplied`,
                srcIp: ev.srcIp, host: ev.host,
                evidence: [`clientApp=${ev.clientApp}`, `risk=${ev.riskLevel}`, ev.raw || ev.message],
              };
            } else if (ev.errorCode === 0 && ev.countryCode) {
              const geo = ctx.windowSet('idpgeo', who, 3600000, ev.ts, ev.countryCode);
              if (geo.size >= 2) hit = {
                severity: 'high',
                message: `Impossible travel for ${who}: successful sign-ins from ${[...geo].join(' and ')} within the hour`,
                srcIp: ev.srcIp, host: ev.host, evidence: [`countries=${[...geo].join(', ')}`, ev.raw || ev.message],
              };
            }
            // A consent grant is followed by the token being used, and both are
            // reportable on their own — one shared cooldown keeps the pair to a
            // single alert per user.
            if (!hit || !ctx.cooldown('entra', who, 60000, ev.ts)) return;
            return hit;
          }
          if (ev.srcType !== 'okta') return;
          const t = ev.oktaEventType || '', who = ev.user || 'unknown';
          if (/user\.account\.privilege\.grant|group\.user_membership\.add|user\.mfa\.factor\.deactivate|policy\.lifecycle\.(update|delete)/.test(t))
            return {
              severity: 'high', tactic: 'Persistence', technique: 'T1098.003 · Additional Cloud Roles',
              message: `Okta security setting changed for ${who}: ${t}`,
              srcIp: ev.srcIp, host: ev.host, evidence: [ev.raw || ev.message],
            };
          // Impossible travel: two successful sign-ins from different countries
          // inside an hour. Both succeed — only the geography is anomalous.
          if (!/user\.session\.start/.test(t) || ev.outcome !== 'SUCCESS' || !ev.country) return;
          const seen = ctx.windowSet('idpgeo', who, 3600000, ev.ts, ev.country);
          if (seen.size >= 2 && ctx.cooldown('idpgeo', who, 60000, ev.ts))
            return {
              severity: 'high',
              message: `Impossible travel for ${who}: successful sign-ins from ${[...seen].join(' and ')} within the hour`,
              srcIp: ev.srcIp, host: ev.host,
              evidence: [`countries=${[...seen].join(', ')}`, ev.raw || ev.message],
            };
        },
      },
      {
        id: 'mfa-fatigue', name: 'MFA Push Bombing', severity: 'high',
        tactic: 'Credential Access', technique: 'T1621 · Multi-Factor Authentication Request Generation',
        run(ev, ctx) {
          if (ev.srcType !== 'okta' || ev.factor !== 'push') return;
          const who = ev.user || 'unknown';
          if (ev.outcome === 'FAILURE') {
            const w = ctx.window('mfapush', who, 300000, ev.ts); w.push(ev.ts);
            if (w.length >= 6 && ctx.cooldown('mfapush', who, 60000, ev.ts))
              return {
                severity: 'high',
                message: `MFA push bombing: ${w.length} prompts rejected by ${who} in 5 min, all from ${ev.srcIp} (${ev.country})`,
                srcIp: ev.srcIp, host: ev.host, evidence: [`rejected=${w.length}`, ev.raw || ev.message],
              };
            return;
          }
          // The prompt is finally approved — the user gave in and the attacker is in.
          const w = ctx.peek('mfapush', who);
          if (ev.outcome === 'SUCCESS' && w && w.length >= 5 && ctx.cooldown('mfaok', who, 60000, ev.ts))
            return {
              severity: 'critical', tactic: 'Initial Access',
              message: `MFA fatigue succeeded: ${who} approved a push from ${ev.srcIp} after ${w.length} rejections`,
              srcIp: ev.srcIp, host: ev.host, evidence: [ev.raw || ev.message],
            };
        },
      },
      {
        id: 'process-injection', name: 'Process Injection', severity: 'critical',
        tactic: 'Defense Evasion', technique: 'T1055 · Process Injection',
        run(ev, ctx) {
          const m = ev.message || '';
          // Sysmon 8 is a thread created in *another* process. Legitimate software
          // almost never does it; the start function names the injection style.
          const remoteThread = ev.eventId === 8 && /LoadLibrary|RtlCreateUserThread|SetThreadContext|start(ing)?function/i.test(m);
          // 0x1F3FFF is PROCESS_ALL_ACCESS — read, write and execute in one handle.
          const fullAccess = ev.eventId === 10 && /0x1f3fff|0x1fffff/i.test(m);
          const hollowing = /process hollow|NtUnmapViewOfSection|WriteProcessMemory.*svchost/i.test(m);
          if (!remoteThread && !fullAccess && !hollowing) return;
          if (!ctx.cooldown('inject', ev.host, 30000, ev.ts)) return;
          return {
            severity: 'critical',
            message: `Process injection on ${ev.host}: ${m.slice(0, 90)}`,
            srcIp: ev.srcIp || ev.hostIp, host: ev.host, evidence: [ev.raw || m],
          };
        },
      },
      {
        id: 'password-store-theft', name: 'Credentials From Password Store', severity: 'high',
        tactic: 'Credential Access', technique: 'T1555.003 · Credentials from Web Browsers',
        run(ev, ctx) {
          const m = ev.message || '';
          // A PAM vault is the same objective by a sanctioned route: each checkout
          // is authorised on its own, so the signal is one holder sweeping safes.
          if (ev.srcType === 'cyberark') {
            if (ev.act !== 'Retrieve password') return;
            const safes = ctx.windowSet('pamsafes', ev.user, 120000, ev.ts, ev.safe);
            if (safes.size < 4 || !ctx.cooldown('pamsafes', ev.user, 60000, ev.ts)) return;
            return {
              severity: 'critical', tactic: 'Credential Access', technique: 'T1555.005 · Password Managers',
              message: `${ev.user} checked out ${safes.size} privileged safes from the vault in 2 min from ${ev.srcIp}`,
              srcIp: ev.srcIp, host: ev.host,
              evidence: [`safes=${Array.from(safes).join(',')}`, `app=${ev.app || ''}`, ev.raw || m],
            };
          }
          // The password DB alone is useless — it is encrypted with a key in Local
          // State. Reading both is what turns a file copy into a credential theft.
          if (!/login data|local state|logins\.json|key4\.db|signons\.sqlite|cookies\.sqlite|vault\\|credential(s)? ?manager/i.test(m)) return;
          if (!ctx.cooldown('pwstore', ev.host, 30000, ev.ts)) return;
          return {
            severity: 'high',
            message: `Browser credential store accessed on ${ev.host}: ${m.slice(0, 90)}`,
            srcIp: ev.srcIp || ev.hostIp, host: ev.host, evidence: [ev.raw || m],
          };
        },
      },
      {
        id: 'masquerading', name: 'Masquerading System Binary', severity: 'high',
        tactic: 'Defense Evasion', technique: 'T1036.005 · Match Legitimate Name or Location',
        run(ev, ctx) {
          const m = ev.message || '';
          // These names only ever run from System32. Anywhere else is an imposter
          // trading on a name an analyst reads past. The directory and the file
          // name must be adjacent — a user-writable path elsewhere on the line
          // belongs to some other binary, and matching that is a false positive.
          if (!/(?:users\\public|programdata|appdata\\local\\temp|\\temp|\\downloads)\\[^\\"]*\b(?:svchost|lsass|csrss|services|winlogon|smss|taskhostw|spoolsv)\.exe/i.test(m)) return;
          if (!ctx.cooldown('masq', ev.host, 30000, ev.ts)) return;
          return {
            severity: 'high',
            message: `System binary name running from the wrong path on ${ev.host}: ${m.slice(0, 90)}`,
            srcIp: ev.srcIp || ev.hostIp, host: ev.host, evidence: [ev.raw || m],
          };
        },
      },
      {
        id: 'remote-access-tool', name: 'Unmanaged Remote Access Tool', severity: 'high',
        tactic: 'Command and Control', technique: 'T1219 · Remote Access Software',
        run(ev, ctx) {
          const m = ev.message || '';
          // Signed, legitimate software — the finding is that it is here at all,
          // outside the managed deployment path.
          if (!/screenconnect|connectwise|anydesk|teamviewer|atera|splashtop|logmein|remoteutilities|ngrok|rustdesk/i.test(m)) return;
          if (!ctx.cooldown('rat', ev.host, 30000, ev.ts)) return;
          return {
            severity: 'high',
            message: `Remote access tool on ${ev.host}: ${m.slice(0, 90)}`,
            srcIp: ev.srcIp || ev.hostIp, host: ev.host, evidence: [ev.raw || m],
          };
        },
      },
      {
        id: 'sandbox-evasion', name: 'Sandbox / VM Evasion', severity: 'medium',
        tactic: 'Defense Evasion', technique: 'T1497 · Virtualization / Sandbox Evasion',
        run(ev, ctx) {
          const m = ev.message || '';
          // Individually these are ordinary commands; run back to back by one
          // parent they are a payload deciding whether it is being watched.
          const probe = /win32_computersystem get model|virtualbox guest additions|vmware\\tools|\bvboxservice\b|sbiedll|computersystemproduct get uuid/i.test(m) ||
            /ping -n \d{2,} 127\.0\.0\.1|timeout \/t \d{2,}/i.test(m);
          if (!probe) return;
          const w = ctx.window('vmprobe', ev.host, 60000, ev.ts); w.push(ev.ts);
          if (w.length < 2 || !ctx.cooldown('vmprobe', ev.host, 30000, ev.ts)) return;
          return {
            severity: 'medium',
            message: `Sandbox evasion checks on ${ev.host}: ${w.length} environment probes in 60s`,
            srcIp: ev.srcIp || ev.hostIp, host: ev.host, evidence: [`probes=${w.length}`, ev.raw || m],
          };
        },
      },
      {
        id: 'covert-c2', name: 'Covert C2 Channel', severity: 'high',
        tactic: 'Command and Control', technique: 'T1090.003 · Multi-hop Proxy',
        run(ev, ctx) {
          // Tor: a CONNECT tunnel to an OR port. The destination has no reputation
          // to check, which is the point of using it.
          if (ev.torExit || /:(9001|9030|9051)\b/.test(ev.url || '')) {
            const w = ctx.window('tor', ev.srcIp, 120000, ev.ts); w.push(ev.ts);
            if (w.length >= 3 && ctx.cooldown('tor', ev.srcIp, 60000, ev.ts))
              return {
                severity: 'high', tactic: 'Command and Control', technique: 'T1090.003 · Multi-hop Proxy',
                message: `Tor egress from ${ev.srcIp}: ${w.length} CONNECT tunnels to onion-router ports in 2 min`,
                srcIp: ev.srcIp, host: ev.host, evidence: [`tunnels=${w.length}`, ev.raw || ev.message],
              };
            return;
          }
          // C2 through a high-reputation service. Destination reputation says
          // nothing here, so the regular cadence and uniform size are the signal.
          if (!ev.beaconTo) return;
          const key = `${ev.srcIp}->${ev.beaconTo}`;
          const w = ctx.window('saasc2', key, 300000, ev.ts); w.push(ev.ts);
          if (w.length >= 5 && ctx.cooldown('saasc2', key, 60000, ev.ts))
            return {
              severity: 'high', tactic: 'Command and Control', technique: 'T1102.002 · Bidirectional Communication',
              message: `Beaconing to trusted service ${ev.beaconTo} from ${ev.srcIp}: ${w.length} near-identical requests`,
              srcIp: ev.srcIp, host: ev.host,
              evidence: [`requests=${w.length}`, `service=${ev.beaconTo}`, ev.raw || ev.message],
            };
        },
      },
      {
        id: 'cloud-exfil', name: 'Exfiltration to Cloud Storage', severity: 'high',
        tactic: 'Exfiltration', technique: 'T1567.002 · Exfiltration to Cloud Storage',
        run(ev) {
          if (!/^(PUT|POST)$/i.test(ev.method || '')) return;
          if (!/mega\.nz|anonfiles|transfer\.sh|dropbox|wetransfer|gofile\.io|file\.io|pcloud|box\.com/i.test(ev.url || '')) return;
          const MB = 100 * 1024 * 1024;
          if ((ev.bytes || 0) < MB) return;
          const mb = Math.round(ev.bytes / (1024 * 1024));
          return {
            severity: mb > 1000 ? 'critical' : 'high',
            message: `${mb} MB uploaded from ${ev.srcIp} to ${(ev.url || '').slice(0, 60)}`,
            srcIp: ev.srcIp, host: ev.host, evidence: [`bytes=${ev.bytes}`, `user=${ev.user}`, ev.raw || ev.message],
          };
        },
      },
      {
        id: 'net-config-change', name: 'Network Device Config Tampering', severity: 'high',
        tactic: 'Defense Evasion', technique: 'T1562.004 · Disable or Modify System Firewall',
        run(ev, ctx) {
          if (ev.srcType !== 'ciscoios' || ev.mnemonic !== 'CONFIG_I') return;
          const m = ev.message || '';
          // Ordinary config changes come from the management network. These two
          // things do not: an external source, or an edit that removes a control.
          const strips = /no (ip )?access-(group|list)|no logging|no snmp-server|no service password|no aaa/i.test(m);
          const external = THREAT_INTEL.ips.includes(ev.srcIp) ||
            (ev.srcIp && !/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ev.srcIp));
          if (!strips && !external) return;
          if (!ctx.cooldown('netcfg', ev.host, 30000, ev.ts)) return;
          return {
            severity: strips ? 'critical' : 'high',
            message: `Config change on ${ev.host} by ${ev.user || 'unknown'} from ${ev.srcIp}: ${m.slice(0, 80)}`,
            srcIp: ev.srcIp, host: ev.host, evidence: [`mnemonic=${ev.mnemonic}`, ev.raw || m],
          };
        },
      },
      {
        id: 'vpn-brute', name: 'VPN / Gateway Credential Stuffing', severity: 'high',
        tactic: 'Credential Access', technique: 'T1110.004 · Credential Stuffing',
        run(ev, ctx) {
          // NetScaler and Connect Secure are the same gateway story in different
          // wire formats, so both feed this rule.
          if (!/^(citrix|ivanti)$/.test(ev.srcType) || ev.nsEvent !== 'LOGIN_FAILED') return;
          // Key on the source: one address trying many accounts is a dump being
          // replayed, which is a different shape from one account being guessed.
          const users = ctx.windowSet('vpnstuff', ev.srcIp, 120000, ev.ts, ev.user);
          if (users.size >= 6 && ctx.cooldown('vpnstuff', ev.srcIp, 60000, ev.ts))
            return {
              severity: THREAT_INTEL.ips.includes(ev.srcIp) ? 'critical' : 'high',
              message: `Credential stuffing against the VPN gateway from ${ev.srcIp}: ${users.size} accounts tried in 2 min`,
              srcIp: ev.srcIp, host: ev.host,
              evidence: [`accounts=${users.size}`,
                ev.srcType === 'ivanti' ? `realm=${ev.realm}` : `vserver=${ev.dstIp || ''}`, ev.raw || ev.message],
            };
        },
      },
      {
        id: 'hypervisor-threat', name: 'Hypervisor Tampering', severity: 'critical',
        tactic: 'Defense Evasion', technique: 'T1562.001 · Disable or Modify Tools',
        run(ev, ctx) {
          if (ev.srcType !== 'esxi') return;
          const m = ev.message || '';
          let technique, tactic = 'Defense Evasion', sev = 'high';
          if (/lockdown mode disabled|ssh session was opened/i.test(m)) technique = 'T1562.001 · Disable or Modify Tools';
          else if (/esxcli vm process kill|is powered off by/i.test(m)) { technique = 'T1489 · Service Stop'; tactic = 'Impact'; sev = 'critical'; }
          else if (/vim-cmd hostsvc\/|vmfs\/volumes.*\.encrypted|datastore.*encrypt/i.test(m)) { technique = 'T1486 · Data Encrypted for Impact'; tactic = 'Impact'; sev = 'critical'; }
          if (!technique) return;
          // Encrypting the datastore takes every guest at once, so management-plane
          // tampering on a hypervisor is graded above the same act on one server.
          // The prep is a sequence, so the cooldown keys on the host alone.
          if (!ctx.cooldown('esxi', ev.host, 30000, ev.ts)) return;
          return {
            severity: sev, tactic, technique,
            message: `ESXi management plane touched on ${ev.host}: ${m.replace(/^Event \d+ : /, '').slice(0, 90)}`,
            srcIp: ev.srcIp || ev.hostIp, host: ev.host, evidence: [ev.raw || m],
          };
        },
      },
      {
        id: 'k8s-threat', name: 'Kubernetes Cluster Abuse', severity: 'critical',
        tactic: 'Privilege Escalation', technique: 'T1611 · Escape to Host',
        run(ev, ctx) {
          if (ev.srcType !== 'k8saudit') return;
          const m = ev.message || '', uri = ev.requestUri || '';
          let technique, tactic = 'Privilege Escalation', sev = 'critical', what;
          if (ev.privileged || /privileged:true|hostpid:true|hostnetwork:true|hostpath:\//i.test(m)) {
            technique = 'T1611 · Escape to Host'; what = `privileged pod ${ev.objectName} created in ${ev.namespace}`;
          } else if (/\/exec\b/.test(uri) || ev.k8sResource === 'pods/exec') {
            technique = 'T1609 · Container Administration Command'; tactic = 'Execution';
            what = `exec into ${ev.objectName} in ${ev.namespace}`;
            sev = /nsenter|--mount|\/bin\/sh|\/bin\/bash/i.test(uri + m) ? 'critical' : 'high';
          } else if (ev.k8sResource === 'secrets' && /^(get|list)$/.test(ev.verb || '')) {
            technique = 'T1552.007 · Container API'; tactic = 'Credential Access'; sev = 'high';
            what = `secret ${ev.objectName} read from ${ev.namespace}`;
          }
          if (!technique) return;
          // An unauthenticated or default service account doing any of this is
          // worse than a named operator doing it.
          const anon = /system:anonymous|system:unauthenticated|serviceaccount:default:default/i.test(ev.user || '');
          // An escape is a chain — create the pod, exec into it, then read a token
          // out of kube-system. The namespace changes along the way but the caller
          // does not, so the cooldown keys on the source.
          if (!ctx.cooldown('k8s', ev.srcIp || ev.namespace, 30000, ev.ts)) return;
          return {
            severity: sev, tactic, technique,
            message: `Kubernetes: ${what} by ${ev.user}${anon ? ' (unauthenticated / default service account)' : ''}`,
            srcIp: ev.srcIp, host: ev.host,
            evidence: [`verb=${ev.verb}`, `uri=${uri.slice(0, 80)}`, ev.raw || m],
          };
        },
      },
      {
        id: 'lateral-exec', name: 'Remote Execution (WMI / WinRM)', severity: 'high',
        tactic: 'Lateral Movement', technique: 'T1047 · Windows Management Instrumentation',
        run(ev, ctx) {
          const m = ev.message || '';
          let technique;
          if (/wmic(\.exe)?[^"]*\/node:|Invoke-WmiMethod|Win32_Process.*[Cc]reate/i.test(m)) technique = 'T1047 · Windows Management Instrumentation';
          else if (/Enter-PSSession|Invoke-Command[^"]*-ComputerName|winrs(\.exe)? +-r:/i.test(m)) technique = 'T1021.006 · Windows Remote Management';
          if (!technique) return;
          if (!ctx.cooldown('lateralexec', ev.host, 30000, ev.ts)) return;
          return {
            severity: 'high', technique,
            message: `Remote execution from ${ev.host}: ${m.slice(0, 90)}`,
            srcIp: ev.srcIp || ev.hostIp, host: ev.host, evidence: [ev.raw || m],
          };
        },
      },
      {
        id: 'reverse-shell', name: 'Reverse Shell', severity: 'critical',
        tactic: 'Execution', technique: 'T1059 · Command and Scripting Interpreter',
        run(ev) {
          const m = ev.message || '';
          if (/\/dev\/tcp\/|nc -e |ncat .*-e|mkfifo .*\/bin\/sh|socat .*exec|bash -i >&/i.test(m))
            return { severity: 'critical', message: `Reverse shell on ${ev.host}: ${m.slice(0, 90)}`, srcIp: ev.srcIp || ev.hostIp, host: ev.host, evidence: [m] };
        },
      },
      {
        id: 'susp-powershell', name: 'Suspicious PowerShell', severity: 'high',
        tactic: 'Execution', technique: 'T1059.001 · PowerShell',
        run(ev) {
          const m = ev.message || '';
          if (/powershell(\.exe)?[^"]*-(enc|encodedcommand)|frombase64string|-nop -w hidden|iex ?\(|downloadstring/i.test(m))
            return { severity: 'high', message: `Obfuscated PowerShell on ${ev.host}`, srcIp: ev.srcIp || ev.hostIp, host: ev.host, evidence: [m] };
        },
      },
      {
        id: 'cryptomining', name: 'Cryptomining Activity', severity: 'medium',
        tactic: 'Impact', technique: 'T1496 · Resource Hijacking',
        run(ev) {
          const t = `${ev.message || ''} ${ev.domain || ''}`;
          if (/stratum\+tcp|minexmr|nanopool|xmrpool|supportxmr|monerohash|cryptonight|coinhive/i.test(t))
            return { severity: 'medium', message: `Cryptomining traffic from ${ev.srcIp}`, srcIp: ev.srcIp, host: ev.host, evidence: [ev.message] };
        },
      },
      {
        id: 'ransomware', name: 'Ransomware Behavior', severity: 'critical',
        tactic: 'Impact', technique: 'T1486 · Data Encrypted for Impact',
        run(ev) {
          const m = ev.message || '';
          // The backup platform sees the prelude rather than the encryption:
          // restore points are destroyed or unlocked before anything is encrypted.
          if (/backup (repository|job) "[^"]*" has been deleted|immutability has been disabled/i.test(m))
            return {
              severity: 'critical', tactic: 'Impact', technique: 'T1490 · Inhibit System Recovery',
              message: `Backup destruction on ${ev.host}: ${m.slice(0, 90)}`,
              srcIp: ev.srcIp || ev.hostIp, host: ev.host, evidence: [ev.raw || m],
            };
          if (/vssadmin.*delete shadows|shadowcopy delete|recoveryenabled no|\.locked|\.encrypted|ransom|decrypt_instructions/i.test(m))
            return { severity: 'critical', message: `Ransomware indicators on ${ev.host}: ${m.slice(0, 80)}`, srcIp: ev.srcIp || ev.hostIp, host: ev.host, evidence: [m] };
        },
      },
      {
        id: 'dos-flood', name: 'DoS / Flood', severity: 'high',
        tactic: 'Impact', technique: 'T1498 · Network Denial of Service',
        run(ev, ctx) {
          if (ev.srcType !== 'firewall') return;
          if (/flood|ddos/i.test(ev.message || ''))
            return { severity: 'high', message: `DoS/flood detected targeting ${ev.dstIp}`, srcIp: ev.srcIp, host: ev.host, evidence: [ev.message] };
          if (ev.action !== 'DENY') return;
          const w = ctx.window('dos', ev.dstIp, 5000, ev.ts); w.push(ev.ts);
          if (w.length >= 40 && ctx.cooldown('dos', ev.dstIp, 15000, ev.ts))
            return { severity: 'high', message: `Possible DoS: ${w.length} blocked flows to ${ev.dstIp} in 5s`, srcIp: ev.srcIp, host: ev.host, evidence: [ev.message] };
        },
      },
      {
        id: 'phishing', name: 'Phishing Email', severity: 'medium',
        tactic: 'Initial Access', technique: 'T1566 · Phishing',
        run(ev) {
          // The MTA and the security gateway describe the same message; the
          // gateway just arrives with its own verdicts already attached.
          if (ev.srcType !== 'mail' && ev.srcType !== 'ciscoesa') return;
          const m = ev.message || '';
          if (ev.phish || /phish|suspicious message|spf=fail.*dmarc=fail|attachment="[^"]*\.(exe|scr|js|vbs|iso|lnk|docm)"/i.test(m))
            return { severity: ev.threatSev || 'medium', message: `Phishing indicators: ${m.slice(0, 90)}`, srcIp: ev.srcIp, host: ev.host, evidence: [m] };
        },
      },
    ];
  }

  // Correlation state: named sliding windows keyed by identifier.
  class Correlator {
    constructor() { this.windows = new Map(); this.cooldowns = new Map(); }
    _key(ns, id) { return `${ns}:${id}`; }

    window(ns, id, ms, now) {
      const k = this._key(ns, id);
      let arr = this.windows.get(k);
      if (!arr) { arr = []; this.windows.set(k, arr); }
      while (arr.length && now - arr[0] > ms) arr.shift();
      return arr;
    }
    peek(ns, id) { return this.windows.get(this._key(ns, id)); }

    windowSet(ns, id, ms, now, value) {
      const k = this._key(ns, id);
      let entry = this.windows.get(k);
      if (!entry) { entry = []; this.windows.set(k, entry); }
      entry.push({ t: now, v: value });
      while (entry.length && now - entry[0].t > ms) entry.shift();
      return new Set(entry.map((e) => e.v));
    }

    // Returns true at most once per `ms` per key — throttles repeat alerts.
    cooldown(ns, id, ms, now) {
      const k = this._key(ns, id);
      const last = this.cooldowns.get(k) || 0;
      if (now - last < ms) return false;
      this.cooldowns.set(k, now);
      return true;
    }
  }

  // ---- Jedi engine ----------------------------------------------------------
  class Jedi {
    constructor(opts = {}) {
      this.rules = makeRules();
      this.corr = new Correlator();
      this.maxEvents = opts.maxEvents || 400;
      this.maxAlerts = opts.maxAlerts || 200;
      this.reset();
    }

    reset() {
      this.events = [];
      this.alerts = [];
      this.totalEvents = 0;
      this.totalAlerts = 0;
      this.bySeverity = [0, 0, 0, 0, 0, 0, 0, 0]; // syslog severity 0-7
      this.bySource = {};
      this.byRule = {};
      this.alertSeverityCounts = { critical: 0, high: 0, medium: 0, low: 0 };
      this._epsWindow = [];       // timestamps of recent ingests
      this._timeline = [];        // { t, count, alerts } per second bucket
      this.corr = new Correlator();
    }

    ingest(ev) {
      this.totalEvents++;
      this.bySeverity[ev.severity]++;
      this.bySource[ev.srcType] = (this.bySource[ev.srcType] || 0) + 1;

      this.events.unshift(ev);
      if (this.events.length > this.maxEvents) this.events.pop();

      const now = ev.ts;
      this._epsWindow.push(now);
      this._bucket(now, 1, 0);

      // Run detection rules.
      const fired = [];
      for (const rule of this.rules) {
        let hit;
        try { hit = rule.run(ev, this.corr); } catch (e) { hit = null; }
        if (hit) {
          const alert = this._raise(rule, ev, hit);
          fired.push(alert);
        }
      }
      return fired;
    }

    _raise(rule, ev, hit) {
      const severity = hit.severity || rule.severity;
      const alert = {
        id: global.JS.rand.id(),
        ts: ev.ts,
        ruleId: rule.id,
        name: rule.name,
        severity,
        tactic: hit.tactic || rule.tactic,
        technique: hit.technique || rule.technique,
        message: hit.message,
        srcIp: hit.srcIp,
        host: hit.host,
        evidence: hit.evidence || [ev.message],
        sourceEvent: ev,
      };
      this.totalAlerts++;
      this.alertSeverityCounts[severity]++;
      this.byRule[rule.id] = (this.byRule[rule.id] || 0) + 1;
      this.alerts.unshift(alert);
      if (this.alerts.length > this.maxAlerts) this.alerts.pop();
      this._bucket(ev.ts, 0, 1);
      return alert;
    }

    _bucket(ts, count, alerts) {
      const sec = Math.floor(ts / 1000);
      const last = this._timeline[this._timeline.length - 1];
      if (last && last.t === sec) {
        last.count += count; last.alerts += alerts;
      } else {
        this._timeline.push({ t: sec, count, alerts });
        if (this._timeline.length > 120) this._timeline.shift();
      }
    }

    // Events per second over the trailing `ms` window.
    eps(ms = 3000) {
      const cutoff = Date.now() - ms;
      while (this._epsWindow.length && this._epsWindow[0] < cutoff) this._epsWindow.shift();
      return +(this._epsWindow.length / (ms / 1000)).toFixed(1);
    }

    // Aggregate threat level from recent alerts (last 2 min), weighted by severity.
    threatLevel() {
      const cutoff = Date.now() - 120000;
      let score = 0;
      for (const a of this.alerts) {
        if (a.ts < cutoff) break;
        score += SEV_RANK[a.severity] || 1;
      }
      const levels = [
        { min: 0,  key: 'low',      label: 'GUARDED',   n: 1 },
        { min: 3,  key: 'moderate', label: 'ELEVATED',  n: 2 },
        { min: 8,  key: 'high',     label: 'HIGH',      n: 3 },
        { min: 16, key: 'severe',   label: 'SEVERE',    n: 4 },
        { min: 28, key: 'critical', label: 'CRITICAL',  n: 5 },
      ];
      let chosen = levels[0];
      for (const l of levels) if (score >= l.min) chosen = l;
      return { score, ...chosen };
    }

    timeline() { return this._timeline; }
  }

  global.JS.Jedi = Jedi;
})(window);
