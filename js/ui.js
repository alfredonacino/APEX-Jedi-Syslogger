/*
 * ui.js — wires the Syslogger source to the Jedi engine and renders the
 * dashboard. Vanilla DOM; a single ~10fps render loop keeps the UI cheap.
 */
(function (global) {
  'use strict';
  const { Syslogger, Jedi, SEVERITY, rand } = global.JS;

  // `any` returns on purpose: these resolve to canvases, inputs and plain
  // elements alike, and every call site knows which it asked for.
  /** @type {(sel: string, root?: ParentNode) => any} */
  const $ = (sel, root = document) => root.querySelector(sel);
  /** @type {(sel: string, root?: ParentNode) => any[]} */
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
  const el = (tag, cls, text) => { const n = document.createElement(tag); if (cls) n.className = cls; if (text != null) n.textContent = text; return n; };

  const SEV_ABBR = ['EMER', 'ALRT', 'CRIT', 'ERR', 'WARN', 'NOTE', 'INFO', 'DBG'];
  const SOURCE_META = {
    firewall:   { color: '#38bdf8', label: 'firewall' },
    ssh:        { color: '#4ade80', label: 'ssh/auth' },
    web:        { color: '#a78bfa', label: 'web' },
    ids:        { color: '#ff3b5c', label: 'ids' },
    dns:        { color: '#fbbf24', label: 'dns' },
    vpn:        { color: '#22d3ee', label: 'vpn' },
    windows:    { color: '#60a5fa', label: 'windows' },
    paloalto:   { color: '#fa582d', label: 'paloalto' },
    fortigate:  { color: '#ee2e24', label: 'fortigate' },
    ciscoasa:   { color: '#1ba0d7', label: 'cisco asa' },
    checkpoint: { color: '#e6007e', label: 'checkpt' },
    sophos:     { color: '#0a6cff', label: 'sophos' },
    pfsense:    { color: '#c9333a', label: 'pfsense' },
    juniper:    { color: '#84b135', label: 'juniper' },
    sonicwall:  { color: '#ff7a00', label: 'sonicwall' },
    zscaler:    { color: '#0093d0', label: 'zscaler' },
    f5:         { color: '#e4002b', label: 'f5 asm' },
    ciscoftd:   { color: '#00bceb', label: 'cisco ftd' },
    ciscoise:   { color: '#0d5eaf', label: 'cisco ise' },
    snort:      { color: '#ff6699', label: 'snort' },
    haproxy:    { color: '#63b32e', label: 'haproxy' },
    bind:       { color: '#d4a017', label: 'bind dns' },
    postfix:    { color: '#d19bf0', label: 'postfix' },
    snare:      { color: '#7db8f7', label: 'snare/win' },
    auditd:     { color: '#f59e0b', label: 'auditd' },
    sysmon:     { color: '#ff8ac9', label: 'sysmon' },
    zeek:       { color: '#7fd1ae', label: 'zeek' },
    cloudtrail: { color: '#ff9900', label: 'cloudtrail' },
    okta:       { color: '#6366f1', label: 'okta' },
    ciscoios:   { color: '#5aa9dd', label: 'cisco ios' },
    meraki:     { color: '#67c9a8', label: 'meraki' },
    citrix:     { color: '#b0204a', label: 'netscaler' },
    squid:      { color: '#9aa8c7', label: 'squid' },
    esxi:       { color: '#8bc34a', label: 'esxi' },
    suricata:   { color: '#e05c2b', label: 'suricata' },
    entra:      { color: '#3b7fd4', label: 'entra id' },
    crowdstrike:{ color: '#fc0032', label: 'crowdstrike' },
    defender:   { color: '#00a4ef', label: 'defender' },
    k8saudit:   { color: '#326ce5', label: 'k8s audit' },
    ciscoesa:   { color: '#31c9d6', label: 'cisco esa' },
    cyberark:   { color: '#0b8f5a', label: 'cyberark' },
    ivanti:     { color: '#c8102e', label: 'ivanti vpn' },
    infoblox:   { color: '#0aa5a5', label: 'infoblox' },
    veeam:      { color: '#00b336', label: 'veeam' },
    umbrella:   { color: '#4fb3ff', label: 'umbrella' },
    azure:      { color: '#0089d6', label: 'azure' },
    m365:       { color: '#eb3c00', label: 'm365 audit' },
    cef:        { color: '#7c9cff', label: 'cef' },
    leef:       { color: '#22c1a6', label: 'leef' },
    mail:       { color: '#c084fc', label: 'mail' },
    file:       { color: '#94a3b8', label: 'file' },
  };

  // How each appliance's logs actually reach a collector in the real world.
  const TRANSPORT_NOTE = {
    native: 'native syslog, emitted by the device itself',
    agent: 'needs a forwarding agent — not native syslog',
    api: 'API/webhook only, re-emitted by a connector — not native syslog',
  };

  // ── State ────────────────────────────────────────────────────────────
  const jedi = new Jedi();
  const syslogger = new Syslogger((ev) => jedi.ingest(ev));
  let pendingRows = [];      // events waiting to be painted into the stream
  let filterText = '';
  let paused = false;
  const eventIndex = new Map(); // id -> event (for drawer lookups)

  // ── Boot ─────────────────────────────────────────────────────────────
  function init() {
    // One version for the dashboard, the terminal build and the packages; it
    // lives in js/version.js and nothing hard-codes a copy of it.
    const ver = $('#app-version');
    if (ver && global.JS.VERSION) { ver.textContent = `v${global.JS.VERSION}`; ver.title = `released ${global.JS.RELEASED}`; }
    buildScenarioButtons();
    buildSeverityRows();
    wireControls();
    wireConfig();
    wireAuth();
    requestAnimationFrame(renderLoop);
    setInterval(renderStream, 250);   // stream paints on its own cadence
  }

  function wireControls() {
    const toggle = $('#btn-toggle');
    toggle.addEventListener('click', () => {
      if (syslogger.running) {
        syslogger.stop();
        toggle.classList.remove('running');
        toggle.setAttribute('aria-pressed', 'false');
        $('#btn-toggle-label').textContent = 'Start Ingestion';
      } else {
        syslogger.start();
        toggle.classList.add('running');
        toggle.setAttribute('aria-pressed', 'true');
        $('#btn-toggle-label').textContent = 'Stop Ingestion';
      }
    });

    const slider = $('#eps-slider');
    slider.addEventListener('input', () => {
      syslogger.setEps(+slider.value);
      $('#eps-value').textContent = slider.value;
    });

    $$('.fmt').forEach((b) => b.addEventListener('click', () => {
      $$('.fmt').forEach((x) => x.classList.remove('active'));
      b.classList.add('active');
      syslogger.setFormat(b.dataset.fmt);
    }));

    $('#btn-reset').addEventListener('click', () => {
      jedi.reset(); syslogger.resetCounters(); pendingRows = []; eventIndex.clear();
      lastRenderedId = null;
      $('#event-stream').innerHTML = '';
      $('#alerts-list').innerHTML = '';
      clearSelection('attack'); clearSelection('appliance');
      renderKPIs(); renderAlerts(); renderSources(); renderSeverity(); drawTimeline(); renderVolume();
    });

    $('#btn-clear-alerts').addEventListener('click', () => {
      jedi.alerts = []; renderAlerts();
    });

    $('#stream-filter').addEventListener('input', (e) => { filterText = e.target.value.toLowerCase().trim(); });
    $('#stream-pause').addEventListener('change', (e) => { paused = e.target.checked; });

    $('#drawer-close').addEventListener('click', closeDrawer);
    $('#drawer').addEventListener('click', (e) => { if (e.target.id === 'drawer') closeDrawer(); });
    document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeDrawer(); });
  }

  function buildScenarioButtons() {
    const attackWrap = $('#scenario-buttons');
    const applianceWrap = $('#appliance-buttons');
    Syslogger.scenarioList().forEach((s) => {
      const isAppliance = s.category === 'appliance';
      const b = el('button', isAppliance ? 'scn-btn scn-appliance' : 'scn-btn', s.label);
      b.dataset.id = s.id;
      b.setAttribute('aria-pressed', 'false');
      b.title = isAppliance
        ? `Emit ${s.label} logs and limit the live stream to this source — ${TRANSPORT_NOTE[s.transport] || s.transport}`
        : 'Inject this scenario — marks it as selected';
      // Mark sources that only reach a collector via an agent or an API connector,
      // so they don't read as native syslog devices.
      if (isAppliance && s.transport !== 'native') {
        b.appendChild(el('span', 'scn-transport', s.transport));
      }
      b.addEventListener('click', () => {
        // Attacks fire once per click. Appliances toggle: while any are selected
        // the live stream carries only those sources (see updateSelectedCounts),
        // so a second click hands the stream back. Clear via the per-group
        // "clear" link or a global Reset.
        const on = isAppliance ? !b.classList.contains('selected') : true;
        if (on) syslogger.injectScenario(s.id);
        b.classList.toggle('selected', on);
        b.setAttribute('aria-pressed', String(on));
        updateSelectedCounts();
        b.animate([{ transform: 'scale(1)' }, { transform: 'scale(.92)' }, { transform: 'scale(1)' }], { duration: 180 });
      });
      (isAppliance ? applianceWrap : attackWrap).appendChild(b);
    });
    wireScenarioGroups();
    updateSelectedCounts();
  }

  // Collapse/expand each scenario group and clear its selection marks.
  function wireScenarioGroups() {
    $$('.scenario-title').forEach((title) => {
      title.addEventListener('click', () => {
        const line = title.closest('.scn-line');
        const collapsed = line.classList.toggle('collapsed');
        title.setAttribute('aria-expanded', String(!collapsed));
      });
    });
    $$('.scn-clear').forEach((clear) => {
      clear.addEventListener('click', () => clearSelection(clear.dataset.for));
    });
  }

  function groupWrap(key) { return key === 'appliance' ? $('#appliance-buttons') : $('#scenario-buttons'); }

  function clearSelection(key) {
    $$('.scn-btn.selected', groupWrap(key)).forEach((b) => {
      b.classList.remove('selected');
      b.setAttribute('aria-pressed', 'false');
    });
    updateSelectedCounts();
  }

  // Refresh the "N selected" badge + show/hide the clear link for each group,
  // and point the live stream at the selected appliances (none = baseline mix).
  function updateSelectedCounts() {
    ['attack', 'appliance'].forEach((key) => {
      const sel = $$('.scn-btn.selected', groupWrap(key));
      const n = sel.length;
      const badge = $(`.scn-selected[data-for="${key}"]`);
      const clear = $(`.scn-clear[data-for="${key}"]`);
      if (badge) {
        badge.textContent = n ? (key === 'appliance' ? `${n} selected · stream only` : `${n} selected`) : '';
        badge.title = n && key === 'appliance' ? 'the live stream carries only these sources' : '';
        badge.hidden = n === 0;
      }
      if (clear) clear.hidden = n === 0;
      if (key === 'appliance') syslogger.setApplianceSources(sel.map((b) => b.dataset.id));
    });
  }

  // ── Source & delivery configuration ──────────────────────────────────
  function wireConfig() {
    const ipEl = $('#cfg-ip'), portEl = $('#cfg-port');
    const applyCollector = () => {
      const ip = ipEl.value.trim(), port = portEl.value.trim() || '514';
      syslogger.setCollector(ip, port);
      // An IPv4 literal or a hostname — HEC endpoints are usually named
      // (splunk.example.com, http-inputs-*.splunkcloud.com), and the backend
      // resolves a name for UDP/TCP forwarding just the same.
      const ok = /^(\d{1,3}\.){3}\d{1,3}$/.test(ip) || /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/i.test(ip);
      ipEl.classList.toggle('invalid', !ok);
      saveCollector();
    };
    ipEl.addEventListener('input', applyCollector);
    portEl.addEventListener('input', applyCollector);
    applyCollector();

    const maxEl = $('#cfg-max');
    const applyVolume = () => {
      if ($('#vol-limit').checked) {
        maxEl.disabled = false;
        syslogger.setMaxEvents(Math.max(1, parseInt(maxEl.value, 10) || 1));
      } else {
        maxEl.disabled = true;
        syslogger.setMaxEvents(null);
      }
      renderVolume();
    };
    $('#vol-unlimited').addEventListener('change', applyVolume);
    $('#vol-limit').addEventListener('change', applyVolume);
    maxEl.addEventListener('input', applyVolume);

    $('#cfg-loop').addEventListener('change', (e) => syslogger.setLoop(e.target.checked));
    $('#cfg-usefile').addEventListener('change', (e) => syslogger.setFileMode(e.target.checked));

    const hecEls = ['token', 'index', 'sourcetype', 'tls', 'insecure'].map((k) => $('#cfg-hec-' + k));
    const applyHec = () => { syslogger.setHec(readHec()); saveCollector(); };
    hecEls.forEach((el) => { el.addEventListener('input', applyHec); el.addEventListener('change', applyHec); });
    applyHec();

    $('#cfg-proto').addEventListener('change', (e) => {
      const proto = e.target.value;
      syslogger.setForwardProto(proto);
      // HEC is HTTP on 8088, not syslog on 514 — swap the port whenever it is
      // still the other mode's default, so the common case needs no typing.
      if (proto === 'hec' && portEl.value.trim() === '514') portEl.value = '8088';
      if (proto !== 'hec' && portEl.value.trim() === '8088') portEl.value = '514';
      $('#cfg-hec-row').hidden = proto !== 'hec';
      applyCollector();
      saveCollector();
    });
    $('#cfg-forward').addEventListener('change', (e) => {
      syslogger.setForwarding(e.target.checked);
      // Switching forwarding on is a deliberate use of this receiver, so it earns
      // a place in the history.
      if (e.target.checked) rememberCollector();
      renderForward();
    });
    $('#cfg-test').addEventListener('click', runConnectivityTest);

    $('#cfg-hist-use').addEventListener('click', useHistoryEntry);
    $('#cfg-hist-save').addEventListener('click', () => rememberCollector(true));
    $('#cfg-hist-del').addEventListener('click', forgetHistoryEntry);
    $('#cfg-history').addEventListener('dblclick', useHistoryEntry);

    $('#cfg-file').addEventListener('change', (e) => {
      const file = e.target.files && e.target.files[0];
      if (!file) return;
      const reader = new FileReader();
      reader.onload = () => {
        const lines = String(reader.result).split(/\r?\n/).filter((l) => l.trim().length);
        syslogger.loadFile(lines, file.name);
        $('#file-foot').textContent = `${lines.length.toLocaleString()} lines · ${file.name}`;
        $('#cfg-usefile').disabled = false;
      };
      reader.onerror = () => { $('#file-foot').textContent = 'could not read file'; };
      reader.readAsText(file);
    });

    // If the volume cap or EOF auto-stops the source, reflect it in the UI.
    syslogger.onStop = () => { syncToggle(); renderVolume(); };
  }

  // ── Sign-in state ────────────────────────────────────────────────────
  // The backend gates the whole app, so reaching this code already means a valid
  // session (or JEDI_AUTH=off). This only surfaces who that is, and offers the
  // way out.
  // Beat while the window lives; say goodbye as it closes so the backend stops
  // promptly instead of waiting out the grace period. A reload also fires
  // pagehide, which is why the goodbye shortens the grace rather than ending it.
  function startDesktopHeartbeat() {
    const beat = () => fetch('/desktop/ping').catch(() => {});
    beat();
    setInterval(beat, 5000);
    window.addEventListener('pagehide', () => {
      if (navigator.sendBeacon) navigator.sendBeacon('/desktop/bye');
    });
  }

  async function wireAuth() {
    const badge = $('#auth-badge');
    $('#btn-logout').addEventListener('click', async () => {
      try { await fetch('/auth/logout', { method: 'POST' }); } catch (e) {}
      location.href = '/login.html';
    });
    try {
      const s = await (await fetch('/auth/session')).json();
      // Desktop build: this page IS the application window, so it is what tells
      // the backend it is still open. The browser process cannot be trusted to
      // say so — it may have handed the URL to an already-running instance and
      // exited immediately.
      if (s.desktop) startDesktopHeartbeat();
      if (!s.authRequired || !s.user) return;   // auth disabled, or served statically
      const who = `signed in as <span class="auth-who">${escapeHtml(s.user)}</span>`;
      // A documented default password is a published password — say so, loudly.
      const warn = s.passwordIsDefault
        ? ` <span class="auth-warn" title="This install still uses the documented default password. Change it on the host: node server.js --set-password '<new password>'">⚠ default password</span>`
        : '';
      $('#auth-user').innerHTML = who + warn;
      badge.hidden = false;
      loadCollector();
    } catch (e) {
      // Static hosting has no /auth/session — leave the badge hidden.
    }
  }

  // ── The collector lives in the signed-in user's profile ──────────────
  // Each account keeps its own destination, so two people testing at once do not
  // overwrite each other, and a session resumes where the last one left off.
  let collectorLoaded = false;   // stays false until the saved values are in place
  let collectorTimer = null;

  function saveCollector() {
    if (!collectorLoaded) return;   // never save back what we just applied
    clearTimeout(collectorTimer);
    collectorTimer = setTimeout(() => {
      fetch('/api/profile/collector', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          collector: {
            ip: $('#cfg-ip').value.trim(),
            port: $('#cfg-port').value.trim(),
            proto: $('#cfg-proto').value,
            hec: readHec(),
          },
        }),
      }).catch(() => {});   // a dropped save is not worth interrupting the run for
    }, 600);
  }

  // ── Collector history ────────────────────────────────────────────────
  // Every receiver this account has actually used, newest first, so an earlier
  // destination can be picked back up without retyping it.
  let history = [];

  function currentCollector() {
    return {
      ip: $('#cfg-ip').value.trim(),
      port: $('#cfg-port').value.trim(),
      proto: $('#cfg-proto').value,
      hec: readHec(),
    };
  }

  // "3m ago" beats a timestamp in a control this narrow.
  function ago(iso) {
    const secs = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
    if (secs < 90) return 'just now';
    const mins = secs / 60;
    if (mins < 60) return `${Math.round(mins)}m ago`;
    if (mins < 60 * 24) return `${Math.round(mins / 60)}h ago`;
    return `${Math.round(mins / 60 / 24)}d ago`;
  }

  function renderHistory() {
    const row = $('#cfg-hist-row'), sel = $('#cfg-history');
    if (!collectorLoaded) { row.hidden = true; return; }   // no profile to store one in
    row.hidden = false;
    const keep = sel.value;
    sel.innerHTML = '';
    if (!history.length) {
      sel.appendChild(new Option('no saved receivers yet', ''));
      sel.disabled = true;
      $('#cfg-hist-use').disabled = true;
      $('#cfg-hist-del').disabled = true;
      return;
    }
    sel.disabled = false;
    $('#cfg-hist-use').disabled = false;
    $('#cfg-hist-del').disabled = false;
    // The list is newest-first, so recency is in the order — the label stays short
    // enough to read whole, and the detail lives in the tooltip.
    for (const e of history) {
      const opt = new Option(`${e.proto.toUpperCase()} · ${e.ip}:${e.port}`, e.id);
      const detail = e.proto === 'hec'
        ? `${e.hec.ssl ? 'https' : 'http'}://${e.ip}:${e.port}/services/collector` +
          ` · sourcetype ${e.hec.sourcetype}${e.hec.index ? ` · index ${e.hec.index}` : ''}` +
          `${e.hec.token ? ' · token saved' : ' · no token'}`
        : `${e.ip}:${e.port}/${e.proto}`;
      opt.title = `${detail} · used ${e.uses}× · last ${ago(e.lastUsed)}`;
      sel.appendChild(opt);
    }
    if (keep && history.some((e) => e.id === keep)) sel.value = keep;
  }

  // Record the panel as it stands. Called on Test, on switching forwarding on,
  // and from the Save button — never on a keystroke, or the list would fill with
  // half-typed addresses.
  async function rememberCollector(announce) {
    if (!collectorLoaded) return;
    const collector = currentCollector();
    if (!collector.ip) {
      if (announce) flashTest('✗ enter a collector address first', 'test-fail');
      return;
    }
    try {
      const d = await (await fetch('/api/profile/history', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ collector }),
      })).json();
      if (d && d.ok) {
        history = d.history;
        renderHistory();
        if (announce) flashTest(`✓ saved ${collector.proto.toUpperCase()} · ${collector.ip}:${collector.port} to the history`, 'test-ok');
      }
    } catch (e) { /* the run matters more than the bookkeeping */ }
  }

  // Put a past receiver back in the panel — the "rerun" path.
  function useHistoryEntry() {
    const id = $('#cfg-history').value;
    const e = history.find((x) => x.id === id);
    if (!e) return;
    applyCollectorValues(e);
    saveCollector();
    flashTest(`✓ loaded ${e.proto.toUpperCase()} · ${e.ip}:${e.port} — Test it or start ingesting`, 'test-ok');
  }

  async function forgetHistoryEntry() {
    const id = $('#cfg-history').value;
    const e = history.find((x) => x.id === id);
    if (!e) return;
    try {
      const d = await (await fetch(`/api/profile/history/${id}`, { method: 'DELETE' })).json();
      if (d && d.ok) {
        history = d.history;
        renderHistory();
        flashTest(`forgot ${e.proto.toUpperCase()} · ${e.ip}:${e.port}`, '');
      }
    } catch (err) { /* nothing worth interrupting the run for */ }
  }

  // The collector panel has one status line; history messages borrow it.
  function flashTest(text, cls) {
    const out = $('#test-result');
    out.className = 'cfg-foot test-result ' + (cls || '');
    out.textContent = text;
  }

  // Drive the panel's own listeners rather than reaching past them, so the
  // syslogger and the profile stay in step.
  function applyCollectorValues(c) {
    const fire = (node, type) => node.dispatchEvent(new Event(type, { bubbles: true }));
    // Protocol first: its handler may swap the port default, and the value we are
    // applying has to be the one that survives.
    $('#cfg-proto').value = c.proto || 'udp';
    fire($('#cfg-proto'), 'change');
    $('#cfg-ip').value = c.ip || '';
    $('#cfg-port').value = String(c.port || 514);
    fire($('#cfg-ip'), 'input');
    fire($('#cfg-port'), 'input');
    const hec = c.hec || {};
    $('#cfg-hec-token').value = hec.token || '';
    $('#cfg-hec-index').value = hec.index || '';
    $('#cfg-hec-sourcetype').value = hec.sourcetype || 'syslog';
    $('#cfg-hec-tls').checked = hec.ssl !== false;
    $('#cfg-hec-insecure').checked = hec.insecure !== false;
    fire($('#cfg-hec-token'), 'input');
  }

  async function loadCollector() {
    let d = null;
    try {
      d = await (await fetch('/api/profile')).json();
    } catch (e) { /* static hosting, or JEDI_AUTH=off — nothing to resume */ }
    if (!d || !d.ok || !d.collector) return;
    applyCollectorValues(d.collector);
    collectorLoaded = true;
    history = d.history || [];
    renderHistory();
  }

  // Current Splunk HEC settings, read straight off the config bar.
  function readHec() {
    return {
      token: $('#cfg-hec-token').value.trim(),
      index: $('#cfg-hec-index').value.trim(),
      sourcetype: $('#cfg-hec-sourcetype').value.trim() || 'syslog',
      ssl: $('#cfg-hec-tls').checked,
      insecure: $('#cfg-hec-insecure').checked,
    };
  }

  // Probe reachability of the configured collector IP:port via the backend.
  // For HEC the probe is a real test event, so it also validates the token.
  async function runConnectivityTest() {
    const btn = $('#cfg-test'), out = $('#test-result');
    const ip = $('#cfg-ip').value.trim(), proto = $('#cfg-proto').value;
    const port = $('#cfg-port').value.trim() || (proto === 'hec' ? '8088' : '514');
    if (!ip) { out.className = 'cfg-foot test-result test-fail'; out.textContent = '✗ enter a collector IP first'; return; }
    const body = { ip, port, proto };
    if (proto === 'hec') {
      body.hec = readHec();
      if (!body.hec.token) { out.className = 'cfg-foot test-result test-fail'; out.textContent = '✗ enter the Splunk HEC token first'; return; }
    }
    btn.disabled = true;
    out.className = 'cfg-foot test-result testing';
    out.textContent = `testing ${ip}:${port}/${proto} …`;
    try {
      const r = await fetch('/test', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
      const d = await r.json();
      const cls = d.reachable ? 'test-ok' : (d.warn ? 'test-warn' : 'test-fail');
      const icon = d.reachable ? '✓ ' : (d.warn ? '◐ ' : '✗ ');
      out.className = 'cfg-foot test-result ' + cls;
      out.textContent = icon + (d.message || d.error || 'the backend refused the probe') + (d.ms != null ? ` (${d.ms} ms)` : '');
      // Testing a receiver is using it; remember it either way, since a failed
      // probe is exactly the destination you come back to.
      rememberCollector();
    } catch (e) {
      out.className = 'cfg-foot test-result test-fail';
      out.textContent = '✗ backend not reachable — start it with: node server.js';
    } finally {
      btn.disabled = false;
    }
  }

  // Keep the Start/Stop button in sync with the engine (it may auto-stop).
  function syncToggle() {
    const btn = $('#btn-toggle');
    const running = syslogger.running;
    if (btn.classList.contains('running') !== running) {
      btn.classList.toggle('running', running);
      btn.setAttribute('aria-pressed', String(running));
      $('#btn-toggle-label').textContent = running ? 'Stop Ingestion' : 'Start Ingestion';
    }
  }

  function renderVolume() {
    const foot = $('#vol-foot');
    const emitted = syslogger.emitted.toLocaleString();
    if (syslogger.maxEvents == null) {
      foot.textContent = `${emitted} emitted · no limit`;
    } else {
      const reached = syslogger.emitted >= syslogger.maxEvents;
      foot.textContent = `${emitted} / ${syslogger.maxEvents.toLocaleString()}${reached ? ' · limit reached' : ''}`;
    }
  }

  function renderForward() {
    const foot = $('#fwd-foot');
    if (!syslogger.forwarding) {
      foot.textContent = 'simulation only (no backend)';
      foot.classList.remove('fwd-live', 'fwd-err');
      return;
    }
    if (syslogger.forwardError) {
      foot.textContent = `⚠ ${syslogger.forwardError}`;
      foot.classList.remove('fwd-live'); foot.classList.add('fwd-err');
    } else {
      const proto = syslogger.forwardProto;
      const dest = proto === 'hec'
        ? `${syslogger.hec.ssl ? 'https' : 'http'}://${syslogger.collectorIp}:${syslogger.collectorPort}/services/collector`
        : `${syslogger.collectorIp}:${syslogger.collectorPort}/${proto}`;
      const n = syslogger.forwardedCount.toLocaleString();
      // UDP is fire-and-forget: "sent" means emitted by the backend, not confirmed received.
      // TCP and HEC both ack — HEC answers each batch with Splunk's {"code":0}.
      const note = proto === 'udp' ? ` sent (UDP: no delivery ack)`
        : proto === 'hec' ? ` indexed (HEC ack)` : ` delivered (TCP)`;
      foot.textContent = `● live → ${dest} · ${n}${note}`;
      foot.classList.add('fwd-live'); foot.classList.remove('fwd-err');
    }
  }

  // ── Main render loop (~10 fps for metrics + charts) ──────────────────
  let lastMetrics = 0;
  function renderLoop(ts) {
    if (ts - lastMetrics > 100) {
      renderKPIs();
      renderSeverity();
      renderSources();
      drawTimeline();
      renderAlerts();
      renderVolume();
      renderForward();
      syncToggle();
      lastMetrics = ts;
    }
    requestAnimationFrame(renderLoop);
  }

  // ── KPIs ─────────────────────────────────────────────────────────────
  let lastAlertCount = 0;
  function renderKPIs() {
    $('#kpi-events').textContent = jedi.totalEvents.toLocaleString();
    const sources = Object.keys(jedi.bySource).length;
    $('#kpi-events-foot').textContent = `across ${sources} source${sources === 1 ? '' : 's'}`;
    $('#kpi-eps').innerHTML = `${jedi.eps().toFixed(1)}<small>eps</small>`;

    const c = jedi.alertSeverityCounts;
    $('#kpi-alerts').textContent = jedi.totalAlerts.toLocaleString();
    $('#kpi-alerts-foot').textContent = `${c.critical} critical · ${c.high} high`;

    const t = jedi.threatLevel();
    const tk = $('#threat-kpi');
    tk.dataset.level = t.key;
    $('#kpi-threat').textContent = t.label;
    const bar = $('#defcon-bar');
    if (bar.childElementCount !== 5) { bar.innerHTML = ''; for (let i = 0; i < 5; i++) bar.appendChild(el('i')); }
    const palette = ['#4d9dff', '#4d9dff', '#ffb020', '#ff7849', '#ff3b5c'];
    [...bar.children].forEach((seg, i) => { seg.style.background = i < t.n ? palette[Math.min(t.n - 1, 4)] : 'var(--border-2)'; });
  }

  // ── Severity distribution ────────────────────────────────────────────
  function buildSeverityRows() {
    const wrap = $('#severity-bars');
    // Collapse to the buckets that actually occur in generated traffic.
    ['crit', 'err', 'warning', 'notice', 'info'].forEach((key) => {
      const sev = SEVERITY.find((s) => s.key === key);
      const row = el('div', 'bar-row');
      row.dataset.sev = sev.code;
      row.innerHTML = `<span class="bar-label">${sev.label}</span>
        <span class="bar-track"><span class="bar-fill" style="background:var(--sev-${sev.code})"></span></span>
        <span class="bar-val">0</span>`;
      wrap.appendChild(row);
    });
  }
  function renderSeverity() {
    const counts = jedi.bySeverity;
    const max = Math.max(1, ...counts);
    $$('#severity-bars .bar-row').forEach((row) => {
      const code = +row.dataset.sev;
      // "crit" row aggregates emerg/alert/crit (0-2).
      const val = code === 2 ? counts[0] + counts[1] + counts[2] : counts[code];
      $('.bar-fill', row).style.width = `${(val / max) * 100}%`;
      $('.bar-val', row).textContent = val.toLocaleString();
    });
  }

  // ── Source distribution ──────────────────────────────────────────────
  function renderSources() {
    const wrap = $('#source-bars');
    const entries = Object.entries(jedi.bySource).sort((a, b) => b[1] - a[1]);
    const max = Math.max(1, ...entries.map((e) => e[1]));
    // Reconcile rows without full teardown to avoid flicker.
    const seen = new Set();
    entries.forEach(([src, val]) => {
      seen.add(src);
      let row = $(`[data-src="${src}"]`, wrap);
      if (!row) {
        row = el('div', 'bar-row'); row.dataset.src = src;
        const meta = SOURCE_META[src] || { color: '#8a97b4', label: src };
        row.innerHTML = `<span class="bar-label">${meta.label}</span>
          <span class="bar-track"><span class="bar-fill" style="background:${meta.color}"></span></span>
          <span class="bar-val">0</span>`;
        wrap.appendChild(row);
      }
      $('.bar-fill', row).style.width = `${(val / max) * 100}%`;
      $('.bar-val', row).textContent = val.toLocaleString();
    });
    $$('.bar-row', wrap).forEach((r) => { if (!seen.has(r.dataset.src)) r.remove(); });
    if (!entries.length && !$('.empty-state', wrap)) {
      wrap.appendChild(el('div', 'empty-state', 'No events yet — press Start.'));
    } else if (entries.length) {
      const empty = $('.empty-state', wrap); if (empty) empty.remove();
    }
  }

  // ── Timeline chart (canvas) ──────────────────────────────────────────
  const canvas = $('#timeline-canvas');
  const cctx = canvas.getContext('2d');
  function drawTimeline() {
    const dpr = window.devicePixelRatio || 1;
    const w = canvas.clientWidth, h = canvas.clientHeight || 150;
    if (canvas.width !== w * dpr || canvas.height !== h * dpr) { canvas.width = w * dpr; canvas.height = h * dpr; }
    cctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    cctx.clearRect(0, 0, w, h);

    const data = jedi.timeline();
    const pad = { l: 4, r: 4, t: 8, b: 4 };
    const gw = w - pad.l - pad.r, gh = h - pad.t - pad.b;

    // gridlines
    cctx.strokeStyle = 'rgba(38,55,88,.5)'; cctx.lineWidth = 1;
    for (let i = 0; i <= 3; i++) { const y = pad.t + (gh / 3) * i; cctx.beginPath(); cctx.moveTo(pad.l, y); cctx.lineTo(w - pad.r, y); cctx.stroke(); }
    if (data.length < 2) return;

    const N = 60; // show last 60 buckets
    const slice = data.slice(-N);
    const maxCount = Math.max(4, ...slice.map((d) => d.count));
    const x = (i) => pad.l + (gw * i) / (N - 1);
    const y = (v) => pad.t + gh - (gh * v) / maxCount;

    // events area (blue)
    cctx.beginPath();
    slice.forEach((d, i) => { const px = x(i), py = y(d.count); i ? cctx.lineTo(px, py) : cctx.moveTo(px, py); });
    const grad = cctx.createLinearGradient(0, pad.t, 0, h);
    grad.addColorStop(0, 'rgba(56,189,248,.35)'); grad.addColorStop(1, 'rgba(56,189,248,0)');
    cctx.lineTo(x(slice.length - 1), pad.t + gh); cctx.lineTo(x(0), pad.t + gh); cctx.closePath();
    cctx.fillStyle = grad; cctx.fill();

    cctx.beginPath();
    slice.forEach((d, i) => { const px = x(i), py = y(d.count); i ? cctx.lineTo(px, py) : cctx.moveTo(px, py); });
    cctx.strokeStyle = '#38bdf8'; cctx.lineWidth = 1.6; cctx.stroke();

    // alerts (red bars)
    slice.forEach((d, i) => {
      if (!d.alerts) return;
      const px = x(i), py = y(d.alerts);
      cctx.strokeStyle = '#ff3b5c'; cctx.lineWidth = 2;
      cctx.beginPath(); cctx.moveTo(px, pad.t + gh); cctx.lineTo(px, py); cctx.stroke();
      cctx.fillStyle = '#ff3b5c'; cctx.beginPath(); cctx.arc(px, py, 2.4, 0, Math.PI * 2); cctx.fill();
    });
  }

  // ── Live event stream ────────────────────────────────────────────────
  let lastRenderedId = null;
  function renderStream() {
    if (paused) return;
    const stream = $('#event-stream');
    // Collect events newer than the last one we painted.
    const fresh = [];
    for (const ev of jedi.events) {
      if (ev.id === lastRenderedId) break;
      fresh.push(ev);
    }
    if (!fresh.length) return;
    lastRenderedId = jedi.events[0].id;

    // Keep the view pinned to the newest rows unless the user scrolled down to inspect.
    const pinned = stream.scrollTop <= 4;
    const frag = document.createDocumentFragment();
    // `fresh` is newest-first; keep that order so the newest row lands on top.
    fresh.forEach((ev) => {
      eventIndex.set(ev.id, ev);
      if (filterText && !rowMatches(ev, filterText)) return;
      frag.appendChild(buildRow(ev));
    });
    stream.insertBefore(frag, stream.firstChild);

    // Trim DOM to a sane size.
    while (stream.childElementCount > 250) stream.removeChild(stream.lastChild);
    if (pinned) stream.scrollTop = 0;
  }

  function rowMatches(ev, q) {
    return (ev.host + ' ' + ev.srcType + ' ' + (ev.srcIp || '') + ' ' + ev.message).toLowerCase().includes(q);
  }

  function buildRow(ev) {
    const row = el('div', `event-row sev-${ev.severity}`);
    row.dataset.id = ev.id;
    const d = new Date(ev.ts);
    const time = `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}:${String(d.getSeconds()).padStart(2, '0')}`;
    row.appendChild(el('span', 'ev-time', time));
    row.appendChild(el('span', 'ev-sev', SEV_ABBR[ev.severity]));
    row.appendChild(el('span', 'ev-source', (SOURCE_META[ev.srcType] || {}).label || ev.srcType));
    row.appendChild(el('span', 'ev-host', ev.host));
    row.appendChild(el('span', 'ev-msg', ev.message));
    row.addEventListener('click', () => openDrawer(ev));
    return row;
  }

  // ── Alerts panel ─────────────────────────────────────────────────────
  let renderedAlertIds = new Set();
  function renderAlerts() {
    const list = $('#alerts-list');
    $('#alerts-count').textContent = jedi.alerts.length;
    if (!jedi.alerts.length) {
      if (!$('.empty-state', list)) {
        list.innerHTML = '';
        list.appendChild(el('div', 'empty-state', '🛡️ No detections yet.\nInject a scenario to trigger the rules.'));
        renderedAlertIds = new Set();
      }
      return;
    }
    const empty = $('.empty-state', list); if (empty) empty.remove();

    // Prepend any newly-raised alerts.
    const toAdd = [];
    for (const a of jedi.alerts) { if (renderedAlertIds.has(a.id)) break; toAdd.push(a); }
    toAdd.reverse().forEach((a) => {
      renderedAlertIds.add(a.id);
      list.insertBefore(buildAlertCard(a), list.firstChild);
    });
    while (list.childElementCount > jedi.maxAlerts) { const rm = list.lastChild; renderedAlertIds.delete(rm.dataset.id); list.removeChild(rm); }
  }

  function buildAlertCard(a) {
    const card = el('div', `alert-card sev-${a.severity}`);
    card.dataset.id = a.id;
    const d = new Date(a.ts);
    const time = `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}:${String(d.getSeconds()).padStart(2, '0')}`;
    card.innerHTML = `
      <div class="alert-top">
        <span class="alert-name">${escapeHtml(a.name)}</span>
        <span class="alert-sev-tag">${a.severity}</span>
      </div>
      <div class="alert-msg">${escapeHtml(a.message)}</div>
      <div class="alert-meta">
        <span class="mitre-tag">${escapeHtml(a.technique)}</span>
        <span class="tactic-tag">${escapeHtml(a.tactic)}</span>
        <span class="alert-time">${time}${a.srcIp ? ' · src ' + escapeHtml(a.srcIp) : ''}</span>
      </div>`;
    card.addEventListener('click', () => openDrawer(a.sourceEvent, a));
    return card;
  }

  // ── Detail drawer ────────────────────────────────────────────────────
  function openDrawer(ev, alert) {
    if (!ev) return;
    $('#drawer-title').textContent = alert ? `${alert.name}` : 'Event detail';
    $('#drawer-raw').textContent = ev.raw;
    const fields = $('#drawer-fields');
    fields.innerHTML = '';
    const rows = [
      ['timestamp', new Date(ev.ts).toISOString()],
      ['source_type', ev.srcType],
      ['host', ev.host],
      ['facility', ev.facility],
      ['severity', `${ev.severity} (${SEVERITY[ev.severity].label})`],
      ['program', ev.program],
      ['pid', ev.pid || '—'],
      ['src_ip', ev.srcIp || '—'],
      ['dst_ip', ev.dstIp || '—'],
      ['dst_port', ev.dstPort || '—'],
      ['user', ev.user || '—'],
      ['action', ev.action || '—'],
      ['bytes', ev.bytes != null ? ev.bytes.toLocaleString() : '—'],
      ['event_id', ev.eventId || '—'],
      ['vendor', ev.vendor || '—'],
      ['collector', ev.collector || '—'],
    ];
    if (ev.threatName) rows.push(['pan_threat', `${ev.threatName} (${ev.threatId})`]);
    if (ev.attack) rows.push(['fortigate_attack', `${ev.attack} (${ev.attackId})`]);
    // The Microsoft feeds all key on one field the generic rows above don't carry.
    if (ev.operation) rows.push(['m365_operation', `${ev.operation} (${ev.workload})`]);
    if (ev.auditOperation) rows.push(['entra_activity', ev.auditOperation]);
    if (ev.alertTitle) rows.push(['defender_alert', `${ev.alertTitle} [${ev.mdeSeverity}]`]);
    if (alert) {
      rows.unshift(['⚠ detection', `${alert.name} [${alert.severity}]`]);
      rows.push(['mitre', alert.technique]);
      rows.push(['evidence', (alert.evidence || []).join('\n')]);
    }
    rows.forEach(([k, v]) => {
      if (v === '—' && !['src_ip', 'user'].includes(k)) return; // hide empty rows to reduce noise
      const tr = document.createElement('tr');
      tr.innerHTML = `<td>${k}</td><td>${escapeHtml(String(v))}</td>`;
      fields.appendChild(tr);
    });
    $('#drawer').hidden = false;
  }
  function closeDrawer() { $('#drawer').hidden = true; }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }

  document.addEventListener('DOMContentLoaded', init);
})(window);
