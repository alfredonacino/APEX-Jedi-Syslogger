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
    hex(n) { let s = ''; for (let i = 0; i < n; i++) s += '0123456789abcdef'[rand.int(0, 15)]; return s; },
    // RFC 4122 v4 shape — CloudTrail eventID, Okta uuid, Sysmon ProcessGuid.
    uuid() { return `${rand.hex(8)}-${rand.hex(4)}-4${rand.hex(3)}-${'89ab'[rand.int(0, 3)]}${rand.hex(3)}-${rand.hex(12)}`; },
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

  function tzOffset(d) {
    const tz = -d.getTimezoneOffset();
    const sign = tz >= 0 ? '+' : '-';
    return `${sign}${pad(Math.floor(Math.abs(tz) / 60))}:${pad(Math.abs(tz) % 60)}`;
  }

  // HAProxy accept-date: "06/Feb/2009:12:14:14.655"
  function haproxyTimestamp(d) {
    return `${pad(d.getDate())}/${MONTHS[d.getMonth()]}/${d.getFullYear()}:` +
      `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${pad(d.getMilliseconds(), 3)}`;
  }

  // Cisco ISE payload clock: "2025-12-09 17:30:23.365 +01:00"
  function iseTimestamp(d) {
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ` +
      `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${pad(d.getMilliseconds(), 3)} ${tzOffset(d)}`;
  }

  // Cisco FTD header clock: "Apr 14 2019 12:52:31"
  function ftdTimestamp(d) {
    return `${MONTHS[d.getMonth()]} ${pad(d.getDate())} ${d.getFullYear()} ` +
      `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  }

  // Cloud/SaaS API clocks are UTC ISO-8601 with a trailing Z. CloudTrail drops
  // the milliseconds; the Okta System Log keeps them.
  function utcTimestamp(d, ms) {
    const s = d.toISOString();
    return ms ? s : s.replace(/\.\d{3}Z$/, 'Z');
  }

  // Zeek writes epoch seconds with microsecond precision.
  function zeekTimestamp(d) { return (d.getTime() / 1000).toFixed(6); }

  // Suricata EVE: ISO-8601 with microseconds and a colon-less offset.
  function eveTimestamp(d) {
    const tz = -d.getTimezoneOffset();
    const sign = tz >= 0 ? '+' : '-';
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T` +
      `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${pad(d.getMilliseconds(), 3)}000` +
      `${sign}${pad(Math.floor(Math.abs(tz) / 60))}${pad(Math.abs(tz) % 60)}`;
  }

  // NetScaler payload clock: "08/13/2026:14:22:41"
  function citrixTimestamp(d) {
    return `${pad(d.getMonth() + 1)}/${pad(d.getDate())}/${d.getFullYear()}:` +
      `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  }

  // Snare agent clock: "Tue Apr 06 15:40:08 2021"
  const DAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
  function snareTimestamp(d) {
    return `${DAYS[d.getDay()]} ${MONTHS[d.getMonth()]} ${pad(d.getDate())} ` +
      `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())} ${d.getFullYear()}`;
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
    // Cisco Secure Firewall Threat Defense (FTD) — %FTD-sev-msgid + "Key: Value".
    ciscoftd(ev) {
      const pri = ev.facility * 8 + ev.severity;
      const d = new Date(ev.ts);
      const f = ev.ftdMsgId === '430001'
        ? [`Protocol: ${ev.proto}`, `SrcIP: ${ev.srcIp}`, `DstIP: ${ev.dstIp}`,
          `SrcPort: ${ev.srcPort}`, `DstPort: ${ev.dstPort}`, `Message: "${ev.sigName}"`,
          `Classification: ${ev.classification}`, `Priority: ${ev.priority}`,
          `GID: ${ev.gid}`, `SID: ${ev.sid}`, `InlineResult: ${ev.action}`]
        : [`AccessControlRuleAction: ${ev.action}`, `SrcIP: ${ev.srcIp}`, `DstIP: ${ev.dstIp}`,
          `SrcPort: ${ev.srcPort}`, `DstPort: ${ev.dstPort}`, `Protocol: ${ev.proto}`,
          `IngressZone: ${ev.fromZone}`, `EgressZone: ${ev.toZone}`, `ACPolicy: ${ev.policy}`,
          `AccessControlRuleName: ${ev.rule}`];
      return `<${pri}>${ftdTimestamp(d)} ${ev.host} %FTD-${ev.severity}-${ev.ftdMsgId}: ${f.join(', ')}`;
    },
    // Cisco ISE — category + segmented header (msg_id total_seg seg_num) + comma key=value.
    // Long ISE messages are split across datagrams; segNum/totalSeg model that.
    ciscoise(ev) {
      const pri = ev.facility * 8 + ev.severity;
      const d = new Date(ev.ts);
      const kv = [
        `ConfigVersionId=${ev.configVersion}`, `Device IP Address=${ev.nasIp}`,
        `DestinationIPAddress=${ev.hostIp}`, `DestinationPort=1812`,
        `UserName=${ev.user}`, `Protocol=Radius`, `NetworkDeviceName=${ev.nasName}`,
        `NAS-IP-Address=${ev.nasIp}`, `Service-Type=Framed`, `Calling-Station-ID=${ev.mac}`,
        `NAS-Port-Type=${ev.portType}`,
      ];
      if (ev.failReason) kv.push(`FailureReason=${ev.failReason}`);
      return `<${pri}>${bsdTimestamp(d)} ${ev.host} ${ev.iseCategory} ${pad(ev.iseSeq, 10)} ` +
        `${ev.totalSeg} ${ev.segNum} ${iseTimestamp(d)} ${pad(ev.iseId, 10)} ${ev.msgCode} ` +
        `${ev.iseSev} ${ev.iseDesc}, ${kv.join(', ')}`;
    },
    // Snort 3 (alert_syslog) — bracketed [gid:sid:rev] tokens.
    // ICMP alerts carry no ports, so the endpoint pair drops them.
    snort(ev) {
      const pri = ev.facility * 8 + ev.severity;
      const d = new Date(ev.ts);
      const proto = (ev.proto || 'tcp').toUpperCase();
      const pair = proto === 'ICMP'
        ? `${ev.srcIp} -> ${ev.dstIp}`
        : `${ev.srcIp}:${ev.srcPort} -> ${ev.dstIp}:${ev.dstPort}`;
      return `<${pri}>${bsdTimestamp(d)} ${ev.host} snort[${ev.pid}]: [${ev.gid}:${ev.sid}:${ev.rev}] ` +
        `"${ev.sigName}" [Classification: ${ev.classification}] [Priority: ${ev.priority}] {${proto}} ${pair}`;
    },
    // HAProxy — positional; slash-delimited timer/conn tuples + termination state.
    // HAProxy has no log file: syslog is its only output.
    haproxy(ev) {
      const pri = ev.facility * 8 + ev.severity;
      const d = new Date(ev.ts);
      return `<${pri}>${bsdTimestamp(d)} ${ev.host} haproxy[${ev.pid}]: ${ev.srcIp}:${ev.srcPort} ` +
        `[${haproxyTimestamp(d)}] ${ev.frontend} ${ev.backend}/${ev.server} ${ev.timers} ` +
        `${ev.status} ${ev.bytes} - - ${ev.termState} ${ev.conns} 0/0 {${ev.reqHeaders || ''}} {} ` +
        `"${ev.method} ${ev.url} HTTP/1.1"`;
    },
    // BIND 9 named query log — client handle + trailing flag chars (+ RD, E EDNS, T TCP, D DNSSEC).
    bind(ev) {
      const pri = ev.facility * 8 + ev.severity;
      const d = new Date(ev.ts);
      return `<${pri}>${bsdTimestamp(d)} ${ev.host} named[${ev.pid}]: client @0x${ev.clientHandle} ` +
        `${ev.srcIp}#${ev.srcPort} (${ev.domain}): query: ${ev.domain} IN ${ev.qtype} ${ev.qflags}`;
    },
    // Postfix — free-text prose with key=<value> angle-bracket pairs (mail facility).
    postfix(ev) {
      const pri = ev.facility * 8 + ev.severity;
      const d = new Date(ev.ts);
      const tail = `from=<${ev.from}> to=<${ev.to}> proto=SMTP helo=<${ev.helo}>`;
      const body = ev.pfAction === 'reject'
        ? `NOQUEUE: reject: RCPT from ${ev.clientHost}[${ev.srcIp}]: ${ev.smtpCode} ${ev.pfReason}; ${tail}`
        : `${ev.queueId}: to=<${ev.to}>, relay=${ev.relay}, delay=${ev.delay}, dsn=2.0.0, status=sent (250 2.0.0 OK)`;
      return `<${pri}>${bsdTimestamp(d)} ${ev.host} postfix/${ev.pfProc}[${ev.pid}]: ${body}`;
    },
    // Snare / NXLog Windows Event Log — TAB-delimited, literal MSWinEventLog marker.
    // Windows speaks no syslog: this is what a Snare or NXLog agent relays.
    snare(ev) {
      const pri = ev.facility * 8 + ev.severity;
      const d = new Date(ev.ts);
      const T = '\t';
      const f = [
        'MSWinEventLog', ev.criticality, ev.logName, ev.snareCounter, snareTimestamp(d),
        ev.eventId, ev.sourceName, ev.user || 'N/A', ev.sidType || 'N/A', ev.logType,
        ev.host, ev.categoryStr || 'N/A', '', ev.message, ev.snareCounter,
      ];
      return `<${pri}>${bsdTimestamp(d)} ${ev.host} ${f.join(T)}`;
    },
    // Linux auditd, relayed by the audisp-syslog plugin. Every record of one event
    // shares the audit(epoch:serial) stamp, so SYSCALL/EXECVE/PATH lines arrive as
    // separate syslog messages a collector must stitch back together.
    auditd(ev) {
      const pri = ev.facility * 8 + ev.severity;
      const d = new Date(ev.ts);
      // auditTs is fixed at build time, not per-line: every record of one event
      // must carry a byte-identical audit(epoch:serial) for the collector to join on.
      const stamp = `audit(${(ev.auditTs / 1000).toFixed(3)}:${ev.auditSerial})`;
      return `<${pri}>${bsdTimestamp(d)} ${ev.host} audispd[${ev.pid}]: type=${ev.auditType} msg=${stamp}: ${ev.auditBody}`;
    },
    // Cisco IOS / IOS-XE — the syslog daemon's RFC 3164 header, then the device's
    // own sequence number and uptime clock, then %FACILITY-SEVERITY-MNEMONIC.
    // The mnemonic is the join key: %SYS-5-CONFIG_I is a config change wherever
    // it appears, on any IOS platform.
    ciscoios(ev) {
      const pri = ev.facility * 8 + ev.severity;
      const d = new Date(ev.ts);
      return `<${pri}>${bsdTimestamp(d)} ${ev.host} ${pad(ev.seq, 6)}: *${bsdTimestamp(d)}.${pad(d.getMilliseconds(), 3)}: ` +
        `%${ev.iosFacility}-${ev.severity}-${ev.mnemonic}: ${ev.message}`;
    },
    // Cisco Meraki — RFC 5424 version digit, then a high-precision epoch instead
    // of a date, the device name, and a message type that decides the field list.
    meraki(ev) {
      const pri = ev.facility * 8 + ev.severity;
      return `<${pri}>1 ${(ev.ts / 1000).toFixed(9)} ${ev.host} ${ev.merakiType} ${(ev.merakiFields || []).join(' ')}`;
    },
    // Citrix NetScaler (ADC / Gateway) — RFC 3164 header, then NetScaler's own
    // clock, node id, and "MODULE EVENT msgid 0 : body" quadruple.
    citrix(ev) {
      const pri = ev.facility * 8 + ev.severity;
      const d = new Date(ev.ts);
      return `<${pri}>${bsdTimestamp(d)} ${ev.hostIp} ${citrixTimestamp(d)} ns 0-PPE-0 : ` +
        `default ${ev.nsModule} ${ev.nsEvent} ${ev.nsMsgId} 0 : ${ev.message}`;
    },
    // Squid — the native access.log line, relayed over syslog. Positional:
    // time elapsed client code/status bytes method URL user peerstatus/peerhost type.
    squid(ev) {
      const pri = ev.facility * 8 + ev.severity;
      const d = new Date(ev.ts);
      const f = [
        (ev.ts / 1000).toFixed(3), String(ev.elapsed).padStart(6), ev.srcIp,
        `${ev.squidCode}/${ev.status}`, ev.bytes, ev.method, ev.url,
        ev.user || '-', `${ev.peerStatus || 'NONE'}/${ev.peerHost || '-'}`, ev.contentType || '-',
      ];
      return `<${pri}>${bsdTimestamp(d)} ${ev.host} squid[${ev.pid}]: ${f.join(' ')}`;
    },
    // VMware ESXi — ISO-8601 UTC, then the daemon, level, and a bracketed
    // Originator block carrying the subsystem, operation id and acting user.
    esxi(ev) {
      const pri = ev.facility * 8 + ev.severity;
      const d = new Date(ev.ts);
      return `<${pri}>${utcTimestamp(d, true)} ${ev.host} ${ev.daemon}: ${ev.esxLevel} ${ev.daemon.toLowerCase()}[${ev.pid}] ` +
        `[Originator@6876 sub=${ev.esxSub} opID=${ev.opId} user=${ev.user}] ${ev.message}`;
    },
    // Suricata EVE — JSON, one object per event. Suricata can write EVE straight
    // to syslog (`filetype: syslog`), which is what this models; the alert object
    // is only present on event_type "alert".
    suricata(ev) {
      const pri = ev.facility * 8 + ev.severity;
      const d = new Date(ev.ts);
      const rec = {
        timestamp: eveTimestamp(d), flow_id: ev.flowId, in_iface: ev.iface || 'eth0',
        event_type: ev.eveType, src_ip: ev.srcIp, src_port: ev.srcPort,
        dest_ip: ev.dstIp, dest_port: ev.dstPort, proto: (ev.proto || 'TCP').toUpperCase(),
        alert: ev.eveType === 'alert' ? {
          action: ev.action, gid: ev.gid, signature_id: ev.sid, rev: ev.rev,
          signature: ev.sigName, category: ev.classification, severity: ev.priority,
        } : undefined,
        app_proto: ev.appProto,
        flow: ev.eveType === 'flow' ? { pkts_toserver: ev.pktsOut, pkts_toclient: ev.pktsIn, bytes_toserver: ev.bytesOut, bytes_toclient: ev.bytesIn, state: ev.flowState } : undefined,
      };
      return `<${pri}>${bsdTimestamp(d)} ${ev.host} suricata[${ev.pid}]: ${JSON.stringify(rec)}`;
    },
    // Sysmon, relayed by NXLog's key=value output. Sysmon writes to its own
    // Windows channel (Microsoft-Windows-Sysmon/Operational), so an agent is what
    // puts it on the wire. Field sets differ per event ID, so the per-ID fields
    // ride along pre-rendered in `sysmonFields` and the formatter only supplies
    // the header fields every Sysmon record carries.
    sysmon(ev) {
      const pri = ev.facility * 8 + ev.severity;
      const d = new Date(ev.ts);
      const kv = [
        `EventID=${ev.eventId}`, `EventType="${ev.sysmonType}"`, `UtcTime="${utcTimestamp(d, true)}"`,
        `Computer="${ev.host}"`, `ProcessGuid="{${ev.processGuid}}"`, `ProcessId=${ev.processId}`,
        `Image="${ev.image}"`, `User="${ev.userDomain}"`,
      ].concat(ev.sysmonFields || []);
      return `<${pri}>${bsdTimestamp(d)} ${ev.host} Sysmon[${ev.pid}]: ${kv.join(' ')}`;
    },
    // Zeek — TAB-separated data lines. Zeek writes log files rather than syslog,
    // so a shipper (Filebeat / rsyslog imfile) is what puts them on the wire. Each
    // log path has its own positional field list, so the tag carries the path and
    // the generator supplies the already-ordered fields.
    zeek(ev) {
      const pri = ev.facility * 8 + ev.severity;
      const d = new Date(ev.ts);
      return `<${pri}>${bsdTimestamp(d)} ${ev.host} zeek_${ev.zeekPath}: ` +
        [zeekTimestamp(d), ev.uid].concat(ev.zeekFields || []).join('\t');
    },
    // Cisco Secure Email Gateway (ESA) — consolidated log event in CEF. From
    // AsyncOS 13 the whole mail pipeline (injection → verdicts → delivery) lands
    // on one line keyed by MID/ICID/DCID instead of a dozen correlated entries.
    ciscoesa(ev) {
      const pri = ev.facility * 8 + ev.severity;
      const d = new Date(ev.ts);
      const ext = [
        `deviceExternalId=${ev.serial}`, `ESAMID=${ev.mid}`, `ESAICID=${ev.icid}`, `ESADCID=${ev.dcid}`,
        `src=${ev.srcIp}`, `suser=${ev.mailFrom}`, `duser=${ev.rcptTo}`,
        `ESAFriendlyFrom="${ev.friendlyFrom}"`, `ESASubject="${ev.subject}"`,
        `ESASPFVerdict=${ev.spf}`, `ESADMARCVerdict=${ev.dmarc}`,
        `ESAASVerdict=${ev.asVerdict}`, `ESAAVVerdict=${ev.avVerdict}`, `ESAAMPVerdict=${ev.ampVerdict}`,
        `ESAFinalActionTaken=${ev.finalAction}`,
      ];
      if (ev.attachment) ext.push(`fname="${ev.attachment}"`);
      return `<${pri}>${bsdTimestamp(d)} ${ev.host} esa-sll: CEF:0|Cisco|C600V Email Security Virtual Appliance|15.5.1|` +
        `ESA_CONSOLIDATED_LOG_EVENT|Consolidated Log Event|${ev.cefSev != null ? ev.cefSev : 5}|${ext.join(' ')}`;
    },
    // CyberArk Vault (EPV) — the vault writes XML audit records; an XSL translator
    // converts them to CEF before they reach syslog, so the cs<n>Label pairs are
    // fixed by that translator, not chosen per event.
    cyberark(ev) {
      const pri = ev.facility * 8 + ev.severity;
      const d = new Date(ev.ts);
      const ext = [
        `act="${ev.act}"`, `suser=${ev.user}`, `fname=${ev.fname || ''}`, `dvc=${ev.hostIp}`,
        `shost=${ev.srcIp}`, `dhost=${ev.targetHost || ''}`, `duser=${ev.targetUser || ''}`,
        `externalId=${ev.recordId}`, `app=${ev.app || ''}`, `reason=${ev.reason || ''}`,
        `cs1Label="Affected User Name" cs1=${ev.targetUser || ''}`,
        `cs2Label="Safe Name" cs2="${ev.safe}"`,
        `cs3Label="Device Type" cs3=${ev.deviceType || ''}`,
        `cs4Label="Database" cs4=`, `cs5Label="Other info" cs5="${ev.otherInfo || ''}"`,
        `cn1Label="Request Id" cn1=`, `cn2Label="Ticket Id" cn2=`, `msg=${ev.message}`,
      ];
      return `<${pri}>${bsdTimestamp(d)} ${ev.hostIp} CEF:0|Cyber-Ark|Vault|12.6|${ev.actionCode}|${ev.act}|` +
        `${ev.cefSev != null ? ev.cefSev : 5}|${ext.join(' ')}`;
    },
    // Ivanti Connect Secure (ex-Pulse Connect Secure) — the appliance's own log
    // shape: an event code (AUT…/VPN…) followed by the message, prefixed by the
    // source address and the user's realm and roles.
    ivanti(ev) {
      const pri = ev.facility * 8 + ev.severity;
      const d = new Date(ev.ts);
      const stamp = `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ` +
        `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
      const who = ev.user ? `${ev.user}(${ev.realm})[${ev.roles || ''}]` : '-';
      return `<${pri}>${bsdTimestamp(d)} ${ev.host} ics: ${stamp} - ${ev.host} - [${ev.srcIp}] ${who} - ` +
        `${ev.icsCode}: ${ev.message}`;
    },
    // Infoblox NIOS — the grid member runs stock ISC daemons, so DNS lands as a
    // named query line and DHCP as a dhcpd lease line. Both are plain BSD syslog.
    infoblox(ev) {
      const pri = ev.facility * 8 + ev.severity;
      const d = new Date(ev.ts);
      const body = ev.program === 'named'
        ? `client @0x${ev.clientHandle} ${ev.srcIp}#${ev.srcPort} (${ev.domain}): query: ${ev.domain} IN ${ev.qtype} ${ev.qflags} (${ev.hostIp})`
        : ev.message;
      return `<${pri}>${bsdTimestamp(d)} ${ev.host} ${ev.program}[${ev.pid}]: ${body}`;
    },
    // Veeam Backup & Replication — every Windows event log entry is mirrored to
    // syslog as RFC 5424 with the event id carried in structured data.
    veeam(ev) {
      const pri = ev.facility * 8 + ev.severity;
      const d = new Date(ev.ts);
      const sd = `[origin enterpriseId="31023"][categoryId="${ev.categoryId}" instanceId="${ev.instanceId}" ` +
        `OibID="${ev.oibId || ''}" RepositoryID="${ev.repoId || ''}" Description="${ev.message}"]`;
      return `<${pri}>1 ${isoTimestamp(d)} ${ev.host} Veeam_MP - - ${sd} ${ev.message}`;
    },
    // AWS CloudTrail — JSON record. AWS emits no syslog at all: CloudTrail writes
    // records to S3 / EventBridge and a connector re-emits them, so the payload is
    // the verbatim JSON a collector would receive. Undefined fields are dropped by
    // JSON.stringify, which is also how CloudTrail omits inapplicable keys.
    cloudtrail(ev) {
      const pri = ev.facility * 8 + ev.severity;
      const d = new Date(ev.ts);
      const rec = {
        eventVersion: '1.09',
        userIdentity: {
          type: ev.identityType, principalId: ev.principalId, arn: ev.arn,
          accountId: ev.accountId, userName: ev.user,
        },
        eventTime: utcTimestamp(d), eventSource: ev.eventSource, eventName: ev.eventName,
        awsRegion: ev.region, sourceIPAddress: ev.srcIp, userAgent: ev.userAgent,
        requestParameters: ev.requestParameters || null,
        responseElements: ev.responseElements || null,
        errorCode: ev.errorCode, errorMessage: ev.errorMessage,
        eventID: ev.eventUuid, eventType: 'AwsApiCall', readOnly: !!ev.readOnly,
        managementEvent: true, recipientAccountId: ev.accountId,
      };
      return `<${pri}>${bsdTimestamp(d)} ${ev.host} aws_cloudtrail: ${JSON.stringify(rec)}`;
    },
    // Okta System Log — JSON, polled from /api/v1/logs by a connector and
    // re-emitted; Okta ships nothing over syslog itself.
    okta(ev) {
      const pri = ev.facility * 8 + ev.severity;
      const d = new Date(ev.ts);
      const rec = {
        uuid: ev.eventUuid, published: utcTimestamp(d, true), eventType: ev.oktaEventType,
        version: '0', severity: ev.oktaSeverity, displayMessage: ev.displayMessage,
        actor: { id: ev.actorId, type: 'User', alternateId: ev.user, displayName: ev.displayName },
        client: {
          userAgent: { rawUserAgent: ev.userAgent, os: ev.clientOs, browser: ev.browser },
          zone: 'null', device: 'Computer', ipAddress: ev.srcIp,
          geographicalContext: { city: ev.city, country: ev.country, geolocation: { lat: ev.lat, lon: ev.lon } },
        },
        outcome: { result: ev.outcome, reason: ev.outcomeReason },
        authenticationContext: { authenticationProvider: 'OKTA_AUTHENTICATION_PROVIDER', credentialType: ev.credType || 'PASSWORD' },
        securityContext: { asNumber: ev.asn || 0, isProxy: !!ev.isProxy },
        target: ev.oktaTarget || null,
      };
      return `<${pri}>${bsdTimestamp(d)} ${ev.host} okta_systemlog: ${JSON.stringify(rec)}`;
    },
    // Microsoft Entra ID sign-in log — the SigninLogs schema, pulled through
    // Graph or an Event Hub by a connector. `status.errorCode` 0 is a success;
    // `clientAppUsed` is what exposes legacy protocols that bypass MFA.
    entra(ev) {
      const pri = ev.facility * 8 + ev.severity;
      const d = new Date(ev.ts);
      // One connector carries two categories: SignInLogs (who authenticated) and
      // AuditLogs (what changed in the directory). Only the second has
      // targetResources / modifiedProperties, so it gets its own shape.
      if (ev.entraCategory === 'AuditLogs') {
        const rec = {
          time: utcTimestamp(d, true), resourceId: `/tenants/${ev.tenantId}/providers/Microsoft.aadiam`,
          operationName: ev.auditOperation, category: 'AuditLogs', tenantId: ev.tenantId,
          resultType: ev.auditResult || 'success', resultDescription: ev.resultDescription,
          properties: {
            id: ev.eventUuid, activityDateTime: utcTimestamp(d, true),
            activityDisplayName: ev.auditOperation, category: ev.auditCategory,
            loggedByService: ev.loggedBy, operationType: ev.operationType,
            result: ev.auditResult || 'success',
            initiatedBy: { user: { id: ev.actorId, userPrincipalName: ev.user, ipAddress: ev.srcIp } },
            targetResources: [{
              type: ev.targetType, displayName: ev.targetName,
              userPrincipalName: ev.targetUpn || null, id: ev.targetId,
              modifiedProperties: ev.modified || [],
            }],
          },
        };
        return `<${pri}>${bsdTimestamp(d)} ${ev.host} entra_audit: ${JSON.stringify(rec)}`;
      }
      const rec = {
        time: utcTimestamp(d, true), resourceId: `/tenants/${ev.tenantId}/providers/Microsoft.aadiam`,
        operationName: 'Sign-in activity', category: 'SignInLogs', tenantId: ev.tenantId,
        resultType: String(ev.errorCode), resultDescription: ev.resultDescription,
        properties: {
          id: ev.eventUuid, createdDateTime: utcTimestamp(d, true),
          userPrincipalName: ev.user, userDisplayName: ev.displayName, userId: ev.actorId,
          appDisplayName: ev.appName, appId: ev.appId, clientAppUsed: ev.clientApp,
          ipAddress: ev.srcIp, isInteractive: ev.interactive !== false,
          conditionalAccessStatus: ev.caStatus, riskLevelAggregated: ev.riskLevel,
          riskDetail: ev.riskDetail, riskState: ev.riskState,
          authenticationRequirement: ev.authRequirement,
          location: { city: ev.city, countryOrRegion: ev.countryCode, geoCoordinates: { latitude: ev.lat, longitude: ev.lon } },
          deviceDetail: { operatingSystem: ev.clientOs, browser: ev.browser, isCompliant: !!ev.compliant },
          status: { errorCode: ev.errorCode, failureReason: ev.failureReason },
        },
      };
      return `<${pri}>${bsdTimestamp(d)} ${ev.host} entra_signin: ${JSON.stringify(rec)}`;
    },
    // CrowdStrike Falcon — a DetectionSummaryEvent from the Falcon SIEM Connector /
    // Event Streams API. Unlike raw telemetry this is a *verdict*: the sensor has
    // already named the tactic, technique and what it did about it.
    crowdstrike(ev) {
      const pri = ev.facility * 8 + ev.severity;
      const d = new Date(ev.ts);
      const rec = {
        metadata: {
          customerIDString: ev.customerId, offset: ev.offset, eventType: 'DetectionSummaryEvent',
          eventCreationTime: ev.ts, version: '1.0',
        },
        event: {
          DetectName: ev.detectName, DetectDescription: ev.detectDesc,
          Severity: ev.csSeverity, SeverityName: ev.csSeverityName,
          Tactic: ev.csTactic, Technique: ev.csTechnique, Objective: ev.csObjective,
          ComputerName: ev.host, UserName: ev.user, SensorId: ev.sensorId,
          FileName: ev.fileName, FilePath: ev.filePath, CommandLine: ev.cmdLine,
          SHA256String: ev.sha256, ParentImageFileName: ev.parentImage,
          LocalIP: ev.hostIp, PatternDispositionDescription: ev.disposition,
          FalconHostLink: `https://falcon.crowdstrike.com/activity/detections/detail/${ev.sensorId}`,
        },
      };
      return `<${pri}>${bsdTimestamp(d)} ${ev.host} falcon_siem: ${JSON.stringify(rec)}`;
    },
    // Microsoft Defender for Endpoint — an alert as the Defender XDR streaming
    // API hands it to an Event Hub (the AlertInfo/AlertEvidence shape, also what
    // the Graph security API returns). Like Falcon this is a verdict: the
    // technique is already named, so the raw command line stays in the JSON and
    // out of `message` where a behavioural rule would re-detect it.
    defender(ev) {
      const pri = ev.facility * 8 + ev.severity;
      const d = new Date(ev.ts);
      const rec = {
        Timestamp: utcTimestamp(d, true), AlertId: ev.alertId, Title: ev.alertTitle,
        Description: ev.alertDesc, Category: ev.mdeCategory, Severity: ev.mdeSeverity,
        ServiceSource: 'Microsoft Defender for Endpoint', DetectionSource: ev.detectionSource,
        AttackTechniques: ev.techniques || [], Status: ev.alertStatus || 'New',
        DeviceId: ev.deviceId, DeviceName: ev.host, DeviceLocalIP: ev.hostIp,
        AccountDomain: 'CORP', AccountName: ev.user,
        FileName: ev.fileName || null, FolderPath: ev.filePath || null, SHA256: ev.sha256 || null,
        ProcessCommandLine: ev.cmdLine || null, RemoteIP: ev.remoteIp || null, RemoteUrl: ev.remoteUrl || null,
        RemediationAction: ev.remediation || 'None',
        AlertLink: `https://security.microsoft.com/alerts/${ev.alertId}`,
      };
      return `<${pri}>${bsdTimestamp(d)} ${ev.host} defender_xdr: ${JSON.stringify(rec)}`;
    },
    // Kubernetes API-server audit event (audit.k8s.io/v1). The whole detection
    // surface is `verb` + `objectRef` + `user.username`, with the RBAC verdict in
    // annotations — a request can be logged and still have been denied.
    k8saudit(ev) {
      const pri = ev.facility * 8 + ev.severity;
      const d = new Date(ev.ts);
      const rec = {
        kind: 'Event', apiVersion: 'audit.k8s.io/v1', level: ev.auditLevel || 'RequestResponse',
        auditID: ev.eventUuid, stage: 'ResponseComplete',
        requestURI: ev.requestUri, verb: ev.verb,
        user: { username: ev.user, groups: ev.groups || ['system:authenticated'] },
        sourceIPs: [ev.srcIp], userAgent: ev.userAgent,
        objectRef: { resource: ev.k8sResource, namespace: ev.namespace, name: ev.objectName, apiVersion: 'v1' },
        responseStatus: { code: ev.status },
        requestReceivedTimestamp: utcTimestamp(d, true), stageTimestamp: utcTimestamp(d, true),
        annotations: {
          'authorization.k8s.io/decision': ev.rbacDecision || 'allow',
          'authorization.k8s.io/reason': ev.rbacReason || '',
        },
      };
      return `<${pri}>${bsdTimestamp(d)} ${ev.host} kube-apiserver: ${JSON.stringify(rec)}`;
    },
    // Generic CEF (ArcSight Common Event Format).
    // Cisco Umbrella — DNS resolver logs delivered as CSV to a managed S3 bucket
    // (or pulled from the Reporting API); nothing is emitted over syslog, so this
    // is what a connector re-emits, quoted field for quoted field.
    umbrella(ev) {
      const pri = ev.facility * 8 + ev.severity;
      const d = new Date(ev.ts);
      const stamp = `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ` +
        `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`;
      const f = [
        stamp, ev.identity, ev.identities, ev.srcIp, ev.externalIp, ev.action,
        ev.queryType, ev.responseCode, `${ev.domain}.`, ev.categories,
        ev.identityType, ev.identityTypes, ev.blockedCategories || '',
      ];
      return `<${pri}>${bsdTimestamp(d)} ${ev.host} umbrella_dns: ${f.map((v) => `"${v}"`).join(',')}`;
    },
    // Azure Activity Log — the subscription control plane, read through an Event
    // Hub or the Monitor API. `operationName` is the RBAC action in upper case.
    azure(ev) {
      const pri = ev.facility * 8 + ev.severity;
      const d = new Date(ev.ts);
      const rec = {
        time: utcTimestamp(d, true), resourceId: ev.resourceId,
        operationName: ev.operationName, category: 'Administrative',
        resultType: ev.resultType, resultSignature: ev.resultSignature,
        durationMs: ev.durationMs, callerIpAddress: ev.srcIp, correlationId: ev.correlationId,
        identity: {
          authorization: { scope: ev.scope, action: ev.action, evidence: { role: ev.role } },
          claims: { name: ev.user, ipaddr: ev.srcIp },
        },
        level: ev.level, location: ev.region, tenantId: ev.tenantId,
        properties: ev.azProperties || null,
      };
      return `<${pri}>${bsdTimestamp(d)} ${ev.host} azure_activity: ${JSON.stringify(rec)}`;
    },
    // Microsoft 365 unified audit log — one AuditData record per activity, pulled
    // from the Office 365 Management Activity API. Which key carries the address
    // depends on the workload, so ClientIP and ActorIpAddress both appear.
    m365(ev) {
      const pri = ev.facility * 8 + ev.severity;
      const d = new Date(ev.ts);
      const rec = {
        CreationTime: utcTimestamp(d).replace(/Z$/, ''), Id: ev.eventUuid,
        Operation: ev.operation, OrganizationId: ev.tenantId, RecordType: ev.recordType,
        ResultStatus: ev.resultStatus, UserKey: ev.userKey, UserType: 0, Version: 1,
        Workload: ev.workload, ClientIP: ev.srcIp, ActorIpAddress: ev.srcIp,
        UserId: ev.user, ObjectId: ev.objectId, Parameters: ev.parameters || null,
        MailboxOwnerUPN: ev.mailboxOwner, ClientAppId: ev.appId,
      };
      // The unified audit schema is a union, not a fixed record: every workload
      // bolts its own properties onto the common ones, so emit only what this
      // record actually carries.
      if (ev.clientInfo) rec.ClientInfoString = ev.clientInfo;
      if (ev.mailAccessType) {
        rec.OperationProperties = [{ Name: 'MailAccessType', Value: ev.mailAccessType }, { Name: 'IsThrottled', Value: 'False' }];
        rec.Folders = (ev.folders || []).map((f) => ({ Path: `\\${f}`, FolderItems: [{ InternetMessageId: `<${rand.hex(16)}@corp.example>` }] }));
      }
      if (ev.siteUrl) {
        rec.SiteUrl = ev.siteUrl; rec.SourceRelativeUrl = ev.relativeUrl;
        rec.SourceFileName = ev.fileName; rec.SourceFileExtension = (ev.fileName || '').split('.').pop();
        rec.ItemType = ev.itemType || 'File'; rec.EventSource = 'SharePoint'; rec.UserAgent = ev.userAgent;
      }
      if (ev.targetUser) { rec.TargetUserOrGroupName = ev.targetUser; rec.TargetUserOrGroupType = ev.targetUserType || 'Guest'; }
      if (ev.teamName) { rec.TeamName = ev.teamName; rec.ChannelName = ev.channelName || null; rec.TeamGuid = ev.teamGuid; }
      if (ev.flowConnectors) { rec.FlowConnectorNames = ev.flowConnectors; rec.FlowDetailsUrl = `https://make.powerautomate.com/manage/flows/${ev.flowId}/details`; }
      if (ev.searchQuery) { rec.Query = ev.searchQuery; rec.SearchName = ev.searchName; rec.ExchangeLocations = ev.searchLocations; }
      return `<${pri}>${bsdTimestamp(d)} ${ev.host} o365_audit: ${JSON.stringify(rec)}`;
    },
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

  // Additive, so load order between this file and version.js does not matter.
  global.JS = Object.assign(global.JS || {}, {
    rand, SEVERITY, FACILITY, HOSTS, USERS, BAD_USERS, URLS, AGENTS,
    DOMAINS, THREAT_INTEL, formatSyslog, isoTimestamp, bsdTimestamp, utcTimestamp, VENDOR_FORMATTERS,
  });
  // The terminal app (jedi-cli.js) require()s the same engine the browser runs,
  // so the two can never drift apart. Nothing here touches the DOM.
  if (typeof module === 'object' && module.exports) module.exports = global.JS;
})(typeof window !== 'undefined' ? window : globalThis);
