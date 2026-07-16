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
          if ((ev.srcType !== 'dns' && ev.srcType !== 'bind') || !ev.domain) return;
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
          return {
            severity: sev, tactic, technique,
            message: `${(ev.vendor || 'appliance').toUpperCase()} signature: ${sig} (${ev.srcIp} → ${ev.dstIp})`,
            srcIp: ev.srcIp, host: ev.host, evidence: [ev.raw || ev.message],
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
          if (ev.srcType !== 'mail') return;
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
