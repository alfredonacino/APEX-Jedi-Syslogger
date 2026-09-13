/*
 * toast.js — neon alert popups and the full-screen critical klaxon.
 *
 * Every detection Jedi raises arrives here. Severity picks the neon tone,
 * criticals stay on screen until dismissed (and can raise a klaxon over the
 * whole dashboard), and everything else fades on a timer with a glowing
 * progress rail. Browser-only, like ui.js: the terminal build has its own
 * ANSI notion of an alert.
 */
(function (global) {
  'use strict';

  /** @type {(sel: string, root?: ParentNode) => any} */
  const $ = (sel, root = document) => root.querySelector(sel);

  const MAX_VISIBLE = 3;   // a detection message is wordy; 4 fills the screen
  // Criticals never time out — a 0 means "until someone dismisses it".
  const LIFETIME = { critical: 0, high: 16000, medium: 12000, low: 9000, info: 6000, ok: 6000 };
  const RANK = { low: 0, medium: 1, high: 2, critical: 3 };

  const PREF_KEY = 'jedi.alertPrefs';
  const DEFAULT_PREFS = {
    popups: true,        // show corner popups at all
    klaxon: true,        // full-screen overlay for criticals
    sound: false,        // synthesised chirp on critical
    minSeverity: 'low',  // low | medium | high | critical
  };

  const prefs = loadPrefs();

  function loadPrefs() {
    try {
      return Object.assign({}, DEFAULT_PREFS, JSON.parse(localStorage.getItem(PREF_KEY) || '{}'));
    } catch { return Object.assign({}, DEFAULT_PREFS); }
  }

  function savePrefs(patch) {
    Object.assign(prefs, patch);
    try { localStorage.setItem(PREF_KEY, JSON.stringify(prefs)); }
    catch { /* private browsing: keep the in-memory copy */ }
    return prefs;
  }

  let queued = [];
  let moreNode = null;
  const handlers = { inspect: null, unseen: null };

  /** Wire up what the popup buttons do. Called once by ui.js. */
  function configure(opts) {
    handlers.inspect = opts.onInspect || null;
    handlers.unseen = opts.onUnseen || null;
  }

  const stack = () => $('#toast-stack');
  const visible = () => Array.from(stack().querySelectorAll('.toast'));

  function el(tag, cls, text) {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  }

  function dismiss(node) {
    if (!node || node.dataset.closing) return;
    node.dataset.closing = '1';
    node.classList.add('out');
    node.addEventListener('animationend', () => { node.remove(); drain(); }, { once: true });
    // The animationend never fires if the tab is hidden; sweep up regardless.
    setTimeout(() => { if (node.isConnected) { node.remove(); drain(); } }, 420);
  }

  function drain() {
    while (queued.length && visible().length < MAX_VISIBLE) build(queued.shift());
    renderMore();
  }

  function renderMore() {
    if (!queued.length) { if (moreNode) { moreNode.remove(); moreNode = null; } return; }
    const label = `+${queued.length} more detection${queued.length === 1 ? '' : 's'} — show`;
    if (!moreNode) {
      moreNode = el('button', 'toast-more', label);
      moreNode.addEventListener('click', () => {
        const batch = queued.splice(0, MAX_VISIBLE);
        visible().slice(0, batch.length).forEach(dismiss);
        batch.forEach(build);
        renderMore();
      });
    } else {
      moreNode.textContent = label;
    }
    stack().appendChild(moreNode);   // always last in the stack
  }

  function where(a) {
    return [a.host, a.srcIp && `src ${a.srcIp}`].filter(Boolean).join(' · ');
  }

  function build(alert) {
    const sev = alert.severity || 'low';
    const node = el('div', `toast sev-${sev}`);
    node.setAttribute('role', sev === 'critical' ? 'alert' : 'status');
    node.dataset.id = alert.id || '';

    const close = el('button', 'toast-x', '×');
    close.title = 'Dismiss';
    close.addEventListener('click', () => dismiss(node));

    const top = el('div', 'toast-top');
    top.appendChild(el('span', 'toast-sev', sev));
    const loc = el('span', 'toast-where', where(alert));
    loc.title = where(alert);
    top.appendChild(loc);
    top.appendChild(close);
    node.appendChild(top);

    node.appendChild(el('h4', null, alert.name || 'Detection'));
    if (alert.message) node.appendChild(el('p', null, alert.message));

    const meta = el('div', 'toast-meta');
    if (alert.technique) meta.appendChild(el('span', 'mitre-tag', alert.technique));
    if (alert.tactic) meta.appendChild(el('span', 'tactic-tag', alert.tactic));
    if (meta.childElementCount) node.appendChild(meta);

    if (alert.sourceEvent && handlers.inspect) {
      const acts = el('div', 'toast-actions');
      const inspect = el('button', 'btn btn-sm btn-primary', 'Inspect');
      inspect.addEventListener('click', () => { handlers.inspect(alert); dismiss(node); });
      acts.appendChild(inspect);
      node.appendChild(acts);
    }

    const life = LIFETIME[sev] != null ? LIFETIME[sev] : 9000;
    if (life > 0) {
      const rail = el('div', 'toast-life');
      rail.style.animationDuration = `${life}ms`;
      node.appendChild(rail);
      let timer = setTimeout(() => dismiss(node), life);
      // Hovering pauses the countdown so a long message stays readable.
      node.addEventListener('mouseenter', () => {
        clearTimeout(timer);
        rail.style.animationPlayState = 'paused';
      });
      node.addEventListener('mouseleave', () => {
        rail.style.animationPlayState = 'running';
        const left = Math.max(1200, life * (rail.offsetWidth / Math.max(1, node.offsetWidth)));
        timer = setTimeout(() => dismiss(node), left);
      });
    }

    stack().appendChild(node);
    renderMore();
    return node;
  }

  /** Entry point: one raised detection → one popup. */
  function notifyAlert(alert) {
    const sev = alert.severity || 'low';
    if (sev === 'critical') {
      if (prefs.sound) chirp();
      if (prefs.klaxon) showKlaxon(alert);
    }
    if (!prefs.popups) return;
    if (RANK[sev] < RANK[prefs.minSeverity]) return;

    if (visible().length >= MAX_VISIBLE) { queued.push(alert); renderMore(); return; }
    build(alert);
  }

  /** Plain app notices ("collector saved", "test failed"), same neon treatment. */
  function notice(message, kind = 'info', title = '') {
    const node = el('div', `toast sev-${kind === 'error' ? 'critical' : kind === 'ok' ? 'ok' : 'info'}`);
    node.setAttribute('role', 'status');
    const close = el('button', 'toast-x', '×');
    close.addEventListener('click', () => dismiss(node));
    const top = el('div', 'toast-top');
    top.appendChild(el('span', 'toast-sev', kind === 'error' ? 'error' : 'jedi'));
    top.appendChild(el('span', 'toast-where'));
    top.appendChild(close);
    node.appendChild(top);
    if (title) node.appendChild(el('h4', null, title));
    node.appendChild(el('p', null, message));
    const life = kind === 'error' ? 12000 : 6000;
    const rail = el('div', 'toast-life');
    rail.style.animationDuration = `${life}ms`;
    node.appendChild(rail);
    setTimeout(() => dismiss(node), life);
    stack().appendChild(node);
    renderMore();
  }

  function clearToasts() {
    queued = [];
    visible().forEach(dismiss);
    renderMore();
    hideKlaxon();
  }

  // ── Full-screen critical klaxon ───────────────────────────────────────
  let klaxonAlert = null;
  let backlog = [];

  function showKlaxon(alert) {
    const box = $('#klaxon');
    if (!box.hidden && klaxonAlert) {
      // Already shouting about something: list the newcomer underneath.
      if (!backlog.some((a) => a.id === alert.id)) { backlog.push(alert); renderBacklog(); }
      return;
    }
    klaxonAlert = alert;
    backlog = [];
    $('#klaxon-sev').textContent = alert.severity || 'critical';
    $('#klaxon-rule').textContent = alert.ruleId || '';
    $('#klaxon-title').textContent = alert.name || 'Critical detection';
    $('#klaxon-msg').textContent = alert.message || '';
    const meta = $('#klaxon-meta');
    meta.innerHTML = '';
    if (alert.technique) meta.appendChild(el('span', 'mitre-tag', alert.technique));
    if (alert.tactic) meta.appendChild(el('span', 'tactic-tag', alert.tactic));
    if (alert.host) meta.appendChild(el('span', 'tactic-tag', alert.host));
    if (alert.srcIp) meta.appendChild(el('span', 'mitre-tag', `src ${alert.srcIp}`));
    renderBacklog();
    box.hidden = false;
  }

  function renderBacklog() {
    const box = $('#klaxon-more');
    if (!backlog.length) { box.hidden = true; box.innerHTML = ''; return; }
    box.innerHTML = '';
    box.appendChild(el('b', null,
      `${backlog.length} more critical detection${backlog.length === 1 ? '' : 's'} while this was open:`));
    backlog.slice(0, 6).forEach((a) => box.appendChild(el('div', null, `• ${a.name}`)));
    box.hidden = false;
  }

  function hideKlaxon() {
    const box = $('#klaxon');
    if (box) box.hidden = true;
    klaxonAlert = null;
    backlog = [];
  }

  function initKlaxon() {
    const box = $('#klaxon');
    if (!box) return;
    $('#klaxon-close').addEventListener('click', hideKlaxon);
    $('#klaxon-view').addEventListener('click', () => {
      if (klaxonAlert && handlers.inspect) handlers.inspect(klaxonAlert);
      hideKlaxon();
    });
    $('#klaxon-mute').addEventListener('click', () => {
      savePrefs({ klaxon: false });
      if (handlers.unseen) handlers.unseen();
      notice('Full-screen klaxon off — popups still fire. Turn it back on under 🔔.', 'info');
      hideKlaxon();
    });
    box.addEventListener('click', (e) => { if (e.target === box) hideKlaxon(); });
    document.addEventListener('keydown', (e) => { if (e.key === 'Escape') hideKlaxon(); });
  }

  // ── Optional audio cue ────────────────────────────────────────────────
  let audioCtx = null;
  function chirp() {
    try {
      const Ctor = window.AudioContext || /** @type {any} */ (window).webkitAudioContext;
      audioCtx = audioCtx || new Ctor();
      if (audioCtx.state === 'suspended') audioCtx.resume();
      const now = audioCtx.currentTime;
      // Two short descending blips: attention-getting without being a siren.
      [880, 620].forEach((freq, i) => {
        const osc = audioCtx.createOscillator();
        const gain = audioCtx.createGain();
        osc.type = 'square';
        osc.frequency.value = freq;
        gain.gain.setValueAtTime(0.0001, now + i * 0.16);
        gain.gain.exponentialRampToValueAtTime(0.07, now + i * 0.16 + 0.02);
        gain.gain.exponentialRampToValueAtTime(0.0001, now + i * 0.16 + 0.14);
        osc.connect(gain).connect(audioCtx.destination);
        osc.start(now + i * 0.16);
        osc.stop(now + i * 0.16 + 0.16);
      });
    } catch { /* audio is a nicety; never let it break alerting */ }
  }

  /** A fake critical, for checking the popup path without waiting for one. */
  function testPopup() {
    notifyAlert({
      id: `demo-${Date.now()}`,
      ts: Date.now(),
      ruleId: 'ssh-bruteforce',
      name: 'Successful Login After Brute Force',
      severity: 'critical',
      tactic: 'Initial Access',
      technique: 'T1078 · Valid Accounts',
      message: 'Login ACCEPTED for svc_backup from 185.220.101.44 after 31 failures — likely compromised',
      srcIp: '185.220.101.44',
      host: 'bastion-01',
      evidence: [],
      sourceEvent: null,
    });
  }

  global.JS = global.JS || {};
  global.JS.Toast = {
    configure, notifyAlert, notice, clearToasts,
    initKlaxon, hideKlaxon, testPopup,
    prefs, savePrefs,
  };
})(window);
