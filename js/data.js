/*
 * data.js — shared data pools, RNG helpers, and syslog formatting.
 * Exposes a global `JS` (Jedi Syslogger) namespace consumed by the other scripts.
 * No modules / no build step so the app runs straight off the filesystem.
 */
(function (global) {
  'use strict';

  // ---- Random helpers -------------------------------------------------------
  const rand = {
    int(min, max) { return Math.floor(Math.random() * (max - min + 1)) + min; },
    float(min, max) { return Math.random() * (max - min) + min; },
    pick(arr) { return arr[Math.floor(Math.random() * arr.length)]; },
    chance(p) { return Math.random() < p; },
    id() { return Math.random().toString(36).slice(2, 10); },
    ip() { return `${rand.int(1, 223)}.${rand.int(0, 255)}.${rand.int(0, 255)}.${rand.int(1, 254)}`; },
    internalIp() {
      return rand.pick([
        () => `10.${rand.int(0, 40)}.${rand.int(0, 255)}.${rand.int(1, 254)}`,
        () => `192.168.${rand.int(0, 20)}.${rand.int(1, 254)}`,
        () => `172.${rand.int(16, 31)}.${rand.int(0, 255)}.${rand.int(1, 254)}`,
      ])();
    },
  };

  // ---- Syslog severities & facilities --------------------------------------
  // RFC 5424 numeric severities (lower == more severe).
  const SEVERITY = [
    { code: 0, key: 'emerg',   label: 'Emergency' },
    { code: 1, key: 'alert',   label: 'Alert' },
    { code: 2, key: 'crit',    label: 'Critical' },
    { code: 3, key: 'err',     label: 'Error' },
    { code: 4, key: 'warning', label: 'Warning' },
    { code: 5, key: 'notice',  label: 'Notice' },
    { code: 6, key: 'info',    label: 'Informational' },
    { code: 7, key: 'debug',   label: 'Debug' },
  ];

  const FACILITY = {
    kern: 0, user: 1, mail: 2, daemon: 3, auth: 4, syslog: 5,
    authpriv: 10, ftp: 11, local0: 16, local1: 17, local2: 18,
    local3: 19, local4: 20, local5: 21, local6: 22, local7: 23,
  };

  // ---- Simulated infrastructure --------------------------------------------
  const HOSTS = {
    firewall: [{ name: 'fw-edge-01', ip: '10.0.0.1' }, { name: 'fw-dmz-02', ip: '10.0.0.2' }],
    ssh:      [{ name: 'srv-web-01', ip: '10.10.1.11' }, { name: 'srv-app-02', ip: '10.10.1.12' }, { name: 'srv-db-01', ip: '10.10.2.21' }],
    web:      [{ name: 'srv-web-01', ip: '10.10.1.11' }, { name: 'srv-web-02', ip: '10.10.1.13' }],
    ids:      [{ name: 'ids-sensor-01', ip: '10.0.0.9' }],
    dns:      [{ name: 'dns-01', ip: '10.10.0.53' }],
    vpn:      [{ name: 'vpn-gw-01', ip: '10.0.0.5' }],
    windows:  [{ name: 'WIN-DC01', ip: '10.10.3.10' }, { name: 'WIN-FS02', ip: '10.10.3.20' }],
    mail:     [{ name: 'mail-gw-01', ip: '10.10.0.25' }],
  };

  const USERS = ['jdoe', 'asmith', 'root', 'admin', 'svc_backup', 'mchen', 'operator', 'kwalsh', 'postgres', 'www-data'];
  const BAD_USERS = ['root', 'admin', 'test', 'oracle', 'ubuntu', 'guest', 'user', 'ftpuser', 'pi', 'administrator'];
  const URLS = ['/', '/index.html', '/login', '/api/v1/users', '/dashboard', '/assets/app.js', '/api/v1/orders', '/health', '/search?q=laptop', '/cart'];
  const AGENTS = ['Mozilla/5.0 (Windows NT 10.0; Win64; x64)', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15)', 'curl/7.88.1', 'python-requests/2.31.0'];
  const DOMAINS = ['update.example.com', 'cdn.assets.net', 'api.partner.io', 'mail.corp.local', 'ntp.pool.org'];

  // Threat intel — indicators the Jedi engine treats as known-bad.
  const THREAT_INTEL = {
    ips: ['185.220.101.44', '45.83.193.12', '193.36.119.7', '91.219.236.19', '5.188.206.130'],
    domains: ['kx7z2q-c2.badnet.ru', 'exfil-node.dark-pool.su', 'beacon.malware-cdn.top'],
    countries: ['RU', 'CN', 'KP', 'IR', 'BR', 'NG'],
  };

  // ---- Syslog line formatting ----------------------------------------------
  const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  const pad = (n, w = 2) => String(n).padStart(w, '0');

  function bsdTimestamp(d) {
    // RFC 3164: "Mmm _d hh:mm:ss" (day space-padded to width 2)
    const day = String(d.getDate()).padStart(2, ' ');
    return `${MONTHS[d.getMonth()]} ${day} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  }

  function isoTimestamp(d) {
    const tz = -d.getTimezoneOffset();
    const sign = tz >= 0 ? '+' : '-';
    const tzh = pad(Math.floor(Math.abs(tz) / 60));
    const tzm = pad(Math.abs(tz) % 60);
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T` +
      `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${pad(d.getMilliseconds(), 3)}${sign}${tzh}:${tzm}`;
  }

  function panTimestamp(d) {
    return `${d.getFullYear()}/${pad(d.getMonth() + 1)}/${pad(d.getDate())} ` +
      `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  }

  // Vendor-specific wire formats for common security appliances. Each takes a
  // fully-populated event and returns the raw line exactly as the device would
  // emit it over syslog (PRI header + native payload). The RFC 3164/5424 toggle
  // does not apply to these — real appliances have fixed formats.
  const VENDOR_FORMATTERS = {
    // Palo Alto PAN-OS — comma-separated value (CSV) log.
    paloalto(ev) {
      const pri = ev.facility * 8 + ev.severity;
      const d = new Date(ev.ts);
      const t = panTimestamp(d);
      const f = [
        '1', t, ev.serial, ev.panType, ev.subtype, '0', t,
        ev.srcIp, ev.dstIp, '0.0.0.0', '0.0.0.0',
        ev.rule, '', '', ev.app, 'vsys1', ev.fromZone, ev.toZone,
        'ethernet1/1', 'ethernet1/2', 'forward-log', t, ev.sessionId, '1',
        ev.srcPort, ev.dstPort, '0', '0', '0x0', ev.proto, ev.action,
      ];
      if (ev.panType === 'THREAT') {
        f.push(`"${ev.threatName}(${ev.threatId})"`, ev.category, ev.panSeverity, 'client-to-server');
      } else {
        f.push(String(ev.bytes || 0), '10', '5');
      }
      return `<${pri}>${bsdTimestamp(d)} ${ev.host} ${f.join(',')}`;
    },
    // Fortinet FortiOS (FortiGate) — key=value pairs.
    fortigate(ev) {
      const pri = ev.facility * 8 + ev.severity;
      const d = new Date(ev.ts);
      const date = `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
      const time = `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
      const kv = [
        `date=${date}`, `time=${time}`, `devname="${ev.devname}"`, `devid="${ev.devid}"`,
        `logid="${ev.logid}"`, `type="${ev.ftType}"`, `subtype="${ev.subtype}"`, `level="${ev.level}"`,
        `vd="root"`, `srcip=${ev.srcIp}`, `srcport=${ev.srcPort}`, `dstip=${ev.dstIp}`, `dstport=${ev.dstPort}`,
        `proto=${ev.protoNum}`, `action="${ev.action}"`, `policyid=${ev.policyid}`, `service="${ev.service}"`,
      ];
      if (ev.ftType === 'utm') {
        kv.push(`attack="${ev.attack}"`, `attackid=${ev.attackId}`, `severity="${ev.level}"`, `msg="${ev.message}"`);
      } else {
        kv.push(`sentbyte=${ev.sentbyte}`, `rcvdbyte=${ev.rcvdbyte}`, `duration=${ev.duration || 1}`);
      }
      return `<${pri}>${kv.join(' ')}`;
    },
    // Cisco ASA — %ASA-level-msgid.
    ciscoasa(ev) {
      const pri = ev.facility * 8 + ev.severity;
      const d = new Date(ev.ts);
      return `<${pri}>${bsdTimestamp(d)} ${ev.host} : %ASA-${ev.severity}-${ev.msgId}: ${ev.message}`;
    },
    // Check Point — semicolon-separated key=value.
    checkpoint(ev) {
      const pri = ev.facility * 8 + ev.severity;
      const d = new Date(ev.ts);
      const kv = [
        `product="${ev.product}"`, `action="${ev.action}"`, `orig=${ev.host}`,
        `src=${ev.srcIp}`, `dst=${ev.dstIp}`, `proto=${ev.proto}`,
        `s_port=${ev.srcPort}`, `service=${ev.dstPort}`, `rule="${ev.rule}"`,
      ];
      return `<${pri}>${bsdTimestamp(d)} ${ev.host} CheckPoint[${rand.int(1000, 9999)}]: ${kv.join('; ')}`;
    },
    // Sophos XG Firewall — key=value.
    sophos(ev) {
      const pri = ev.facility * 8 + ev.severity;
      const d = new Date(ev.ts);
      const date = `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
      const time = `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
      const kv = [
        `device="SFW"`, `date=${date}`, `time=${time}`, `timezone="UTC"`, `device_name="${ev.host}"`,
        `log_type="${ev.threatSig ? 'IDP' : 'Firewall'}"`, `log_component="${ev.threatSig ? 'IPS' : 'Firewall Rule'}"`,
        `log_subtype="${ev.action === 'Deny' ? 'Denied' : 'Allowed'}"`, `priority=${ev.priority || 'Information'}`,
        `fw_rule_id=${ev.ruleId || 1}`, `src_ip=${ev.srcIp}`, `dst_ip=${ev.dstIp}`, `protocol="${(ev.proto || 'tcp').toUpperCase()}"`,
        `src_port=${ev.srcPort}`, `dst_port=${ev.dstPort}`, `action="${ev.action}"`,
      ];
      if (ev.threatSig) kv.push(`signature="${ev.threatSig}"`, `signature_id=${ev.threatId || rand.int(10000, 99999)}`);
      return `<${pri}>${bsdTimestamp(d)} ${ev.host} ${kv.join(' ')}`;
    },
    // pfSense filterlog — CSV.
    pfsense(ev) {
      const pri = ev.facility * 8 + ev.severity;
      const d = new Date(ev.ts);
      const f = [
        ev.ruleId || 5, '', '', '1000000103', ev.iface || 'em0', 'match',
        ev.action === 'block' ? 'block' : 'pass', ev.direction || 'in', '4', '0x0', '', '64',
        rand.int(1, 65535), '0', 'DF', ev.protoNum || 6, (ev.proto || 'tcp'),
        '60', ev.srcIp, ev.dstIp, ev.srcPort, ev.dstPort,
      ];
      return `<${pri}>${bsdTimestamp(d)} ${ev.host} filterlog[${rand.int(200, 9999)}]: ${f.join(',')}`;
    },
    // Juniper SRX — RT_FLOW structured syslog.
    juniper(ev) {
      const pri = ev.facility * 8 + ev.severity;
      const d = new Date(ev.ts);
      const evt = ev.action === 'deny' ? 'RT_FLOW_SESSION_DENY' : 'RT_FLOW_SESSION_CREATE';
      const msg = `${evt}: session ${ev.action === 'deny' ? 'denied' : 'created'} ${ev.srcIp}/${ev.srcPort}->${ev.dstIp}/${ev.dstPort} 0x0 ` +
        `${ev.service || 'junos-https'} ${ev.proto || 'tcp'} ${ev.policy || 'default-permit'} ${ev.fromZone || 'trust'} ${ev.toZone || 'untrust'}`;
      return `<${pri}>${bsdTimestamp(d)} ${ev.host} RT_FLOW: ${msg}`;
    },
    // SonicWall — id/sn key=value.
    sonicwall(ev) {
      const pri = ev.facility * 8 + ev.severity;
      const d = new Date(ev.ts);
      const time = `"${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}"`;
      const kv = [
        `id=firewall`, `sn=${ev.serial || '0006B1123456'}`, `time=${time}`, `fw=${ev.hostIp || '10.0.0.1'}`,
        `pri=${ev.severity}`, `c=${ev.category || 32}`, `m=${ev.msgId || 82}`, `msg="${ev.message}"`,
        `src=${ev.srcIp}:${ev.srcPort}`, `dst=${ev.dstIp}:${ev.dstPort}`, `proto=${ev.proto || 'tcp'}`,
      ];
      return `<${pri}>${bsdTimestamp(d)} ${ev.host} ${kv.join(' ')}`;
    },
    // Zscaler Internet Access — web-proxy key=value (NSS feed).
    zscaler(ev) {
      const pri = ev.facility * 8 + ev.severity;
      const d = new Date(ev.ts);
      const kv = [
        `datetime="${isoTimestamp(d)}"`, `user=${ev.user || 'anon'}`, `department="Corp"`, `url="${ev.url}"`,
        `action="${ev.action}"`, `urlcategory="${ev.category || 'General'}"`, `urlclass="${ev.urlClass || 'Business'}"`,
        `reqmethod=${ev.method || 'GET'}`, `respcode=${ev.status || 200}`, `clientip=${ev.srcIp}`, `serverip=${ev.dstIp}`,
      ];
      if (ev.threatSig) kv.push(`threatname="${ev.threatSig}"`, `threatclass="Malware"`);
      return `<${pri}>${bsdTimestamp(d)} ${ev.host} zscalernss: ${kv.join(' ')}`;
    },
    // F5 BIG-IP ASM — WAF log (comma key=value).
    f5(ev) {
      const pri = ev.facility * 8 + ev.severity;
      const d = new Date(ev.ts);
      const kv = [
        `ASM:unit_hostname="${ev.host}"`, `management_ip_address="${ev.hostIp || '10.0.0.5'}"`,
        `web_application_name="/Common/${ev.app || 'app'}"`, `policy_name="/Common/${ev.policy || 'waf_policy'}"`,
        `violations="${ev.threatSig || 'None'}"`, `support_id="${rand.int(1e9, 9e9)}"`,
        `request_status="${ev.action || 'blocked'}"`, `response_code="${ev.status || 0}"`,
        `ip_client="${ev.srcIp}"`, `method="${ev.method || 'GET'}"`, `uri="${ev.url || '/'}"`, `severity="${ev.sevName || 'Critical'}"`,
      ];
      return `<${pri}>${bsdTimestamp(d)} ${ev.host} ${kv.join(',')}`;
    },
    // Generic CEF (ArcSight Common Event Format).
    cef(ev) {
      const pri = ev.facility * 8 + ev.severity;
      const d = new Date(ev.ts);
      const ext = [`src=${ev.srcIp}`, `dst=${ev.dstIp}`, `spt=${ev.srcPort}`, `dpt=${ev.dstPort}`,
        `proto=${(ev.proto || 'TCP').toUpperCase()}`, `act=${ev.action || 'blocked'}`].join(' ');
      const name = ev.threatSig || ev.message || 'Network Event';
      const sev = ev.cefSev != null ? ev.cefSev : 8;
      return `<${pri}>${bsdTimestamp(d)} ${ev.host} CEF:0|${ev.vendorName || 'Security'}|${ev.productName || 'ThreatManager'}|1.0|${ev.sigId || 100}|${name}|${sev}|${ext}`;
    },
    // Generic LEEF (QRadar Log Event Extended Format), tab-delimited.
    leef(ev) {
      const pri = ev.facility * 8 + ev.severity;
      const d = new Date(ev.ts);
      const T = '\t';
      const attrs = [`cat=${ev.leefCat || 'attack'}`, `src=${ev.srcIp}`, `dst=${ev.dstIp}`, `srcPort=${ev.srcPort}`,
        `dstPort=${ev.dstPort}`, `proto=${ev.proto || 'tcp'}`, `sev=${ev.leefSev != null ? ev.leefSev : 8}`,
        `action=${ev.action || 'blocked'}`].join(T);
      return `<${pri}>${bsdTimestamp(d)} ${ev.host} LEEF:2.0|${ev.vendorName || 'Lancope'}|${ev.productName || 'StealthWatch'}|2.0|${ev.threatSig || ev.message || 'Event'}|${attrs}`;
    },
  };

  // Build the raw syslog wire line for an event in the requested format.
  function formatSyslog(ev, format) {
    const pri = ev.facility * 8 + ev.severity;
    const d = new Date(ev.ts);
    const tag = ev.pid ? `${ev.program}[${ev.pid}]` : ev.program;
    if (format === 'rfc5424') {
      const procid = ev.pid || '-';
      const msgid = ev.msgid || '-';
      const sd = ev.structuredData || '-';
      return `<${pri}>1 ${isoTimestamp(d)} ${ev.host} ${ev.program} ${procid} ${msgid} ${sd} ${ev.message}`;
    }
    // default RFC 3164 (BSD)
    return `<${pri}>${bsdTimestamp(d)} ${ev.host} ${tag}: ${ev.message}`;
  }

  global.JS = {
    rand, SEVERITY, FACILITY, HOSTS, USERS, BAD_USERS, URLS, AGENTS,
    DOMAINS, THREAT_INTEL, formatSyslog, isoTimestamp, bsdTimestamp, VENDOR_FORMATTERS,
  };
})(window);
