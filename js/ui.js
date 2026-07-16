/*
 * ui.js — wires the Syslogger source to the Jedi engine and renders the
 * dashboard. Vanilla DOM; a single ~10fps render loop keeps the UI cheap.
 */
(function (global) {
  'use strict';
  const { Syslogger, Jedi, SEVERITY, rand } = global.JS;

  const $ = (sel) => document.querySelector(sel);
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
    buildScenarioButtons();
    buildSeverityRows();
    wireControls();
    wireConfig();
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

    document.querySelectorAll('.fmt').forEach((b) => b.addEventListener('click', () => {
      document.querySelectorAll('.fmt').forEach((x) => x.classList.remove('active'));
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
        ? `Emit ${s.label} logs — ${TRANSPORT_NOTE[s.transport] || s.transport}`
        : 'Inject this scenario — marks it as selected';
      b.addEventListener('click', () => {
        // Fire the scenario and mark this button as selected so it's clear
        // which attacks / appliance logs have been chosen. Clear via the
        // per-group "clear" link or a global Reset.
        syslogger.injectScenario(s.id);
        b.classList.add('selected');
        b.setAttribute('aria-pressed', 'true');
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
    document.querySelectorAll('.scenario-title').forEach((title) => {
      title.addEventListener('click', () => {
        const line = title.closest('.scn-line');
        const collapsed = line.classList.toggle('collapsed');
        title.setAttribute('aria-expanded', String(!collapsed));
      });
    });
    document.querySelectorAll('.scn-clear').forEach((clear) => {
      clear.addEventListener('click', () => clearSelection(clear.dataset.for));
    });
  }

  function groupWrap(key) { return key === 'appliance' ? $('#appliance-buttons') : $('#scenario-buttons'); }

  function clearSelection(key) {
    groupWrap(key).querySelectorAll('.scn-btn.selected').forEach((b) => {
      b.classList.remove('selected');
      b.setAttribute('aria-pressed', 'false');
    });
    updateSelectedCounts();
  }

  // Refresh the "N selected" badge + show/hide the clear link for each group.
  function updateSelectedCounts() {
    ['attack', 'appliance'].forEach((key) => {
      const n = groupWrap(key).querySelectorAll('.scn-btn.selected').length;
      const badge = document.querySelector(`.scn-selected[data-for="${key}"]`);
      const clear = document.querySelector(`.scn-clear[data-for="${key}"]`);
      if (badge) { badge.textContent = n ? `${n} selected` : ''; badge.hidden = n === 0; }
      if (clear) clear.hidden = n === 0;
    });
  }

  // ── Source & delivery configuration ──────────────────────────────────
  function wireConfig() {
    const ipEl = $('#cfg-ip'), portEl = $('#cfg-port');
    const applyCollector = () => {
      const ip = ipEl.value.trim(), port = portEl.value.trim() || '514';
      syslogger.setCollector(ip, port);
      const ok = /^(\d{1,3}\.){3}\d{1,3}$/.test(ip);
      ipEl.classList.toggle('invalid', !ok);
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

    $('#cfg-proto').addEventListener('change', (e) => syslogger.setForwardProto(e.target.value));
    $('#cfg-forward').addEventListener('change', (e) => { syslogger.setForwarding(e.target.checked); renderForward(); });
    $('#cfg-test').addEventListener('click', runConnectivityTest);

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

  // Probe reachability of the configured collector IP:port via the backend.
  async function runConnectivityTest() {
    const btn = $('#cfg-test'), out = $('#test-result');
    const ip = $('#cfg-ip').value.trim(), port = $('#cfg-port').value.trim() || '514', proto = $('#cfg-proto').value;
    if (!ip) { out.className = 'cfg-foot test-result test-fail'; out.textContent = '✗ enter a collector IP first'; return; }
    btn.disabled = true;
    out.className = 'cfg-foot test-result testing';
    out.textContent = `testing ${ip}:${port}/${proto} …`;
    try {
      const r = await fetch('/test', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ip, port, proto }) });
      const d = await r.json();
      const cls = d.reachable ? 'test-ok' : (d.warn ? 'test-warn' : 'test-fail');
      const icon = d.reachable ? '✓ ' : (d.warn ? '◐ ' : '✗ ');
      out.className = 'cfg-foot test-result ' + cls;
      out.textContent = icon + d.message + (d.ms != null ? ` (${d.ms} ms)` : '');
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
      const dest = `${syslogger.collectorIp}:${syslogger.collectorPort}/${syslogger.forwardProto}`;
      const n = syslogger.forwardedCount.toLocaleString();
      // UDP is fire-and-forget: "sent" means emitted by the backend, not confirmed received.
      const note = syslogger.forwardProto === 'udp' ? ` sent (UDP: no delivery ack)` : ` delivered (TCP)`;
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
    document.querySelectorAll('#severity-bars .bar-row').forEach((row) => {
      const code = +row.dataset.sev;
      // "crit" row aggregates emerg/alert/crit (0-2).
      const val = code === 2 ? counts[0] + counts[1] + counts[2] : counts[code];
      row.querySelector('.bar-fill').style.width = `${(val / max) * 100}%`;
      row.querySelector('.bar-val').textContent = val.toLocaleString();
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
      let row = wrap.querySelector(`[data-src="${src}"]`);
      if (!row) {
        row = el('div', 'bar-row'); row.dataset.src = src;
        const meta = SOURCE_META[src] || { color: '#8a97b4', label: src };
        row.innerHTML = `<span class="bar-label">${meta.label}</span>
          <span class="bar-track"><span class="bar-fill" style="background:${meta.color}"></span></span>
          <span class="bar-val">0</span>`;
        wrap.appendChild(row);
      }
      row.querySelector('.bar-fill').style.width = `${(val / max) * 100}%`;
      row.querySelector('.bar-val').textContent = val.toLocaleString();
    });
    wrap.querySelectorAll('.bar-row').forEach((r) => { if (!seen.has(r.dataset.src)) r.remove(); });
    if (!entries.length && !wrap.querySelector('.empty-state')) {
      wrap.appendChild(el('div', 'empty-state', 'No events yet — press Start.'));
    } else if (entries.length) {
      const empty = wrap.querySelector('.empty-state'); if (empty) empty.remove();
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
      if (!list.querySelector('.empty-state')) {
        list.innerHTML = '';
        list.appendChild(el('div', 'empty-state', '🛡️ No detections yet.\nInject a scenario to trigger the rules.'));
        renderedAlertIds = new Set();
      }
      return;
    }
    const empty = list.querySelector('.empty-state'); if (empty) empty.remove();

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
