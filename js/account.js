/*
 * account.js — the Account page: your own profile, your saved Log Collector, and
 * (for admins) the user list.
 *
 * Every write goes through /api, which re-checks the session and the role on the
 * server. Nothing here is a permission boundary; hiding the Users card from a
 * non-admin is a courtesy, not the control.
 */
(function () {
  'use strict';
  const $ = (sel) => document.querySelector(sel);
  const el = (tag, cls, text) => {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  };

  let me = null;   // { id, user, role, … }

  const say = (node, text, cls) => { node.textContent = text; node.className = 'note ' + (cls || 'info'); };

  async function api(method, url, body) {
    const opts = { method, headers: { 'Content-Type': 'application/json' } };
    if (body !== undefined) opts.body = JSON.stringify(body);
    const r = await fetch(url, opts);
    if (r.status === 401) { location.href = '/login.html'; throw new Error('signed out'); }
    let data = {};
    try { data = await r.json(); } catch (e) {}
    return { status: r.status, data };
  }

  // ── My profile ───────────────────────────────────────────────────────
  async function loadProfile() {
    const { data } = await api('GET', '/api/profile');
    if (!data.ok) return;
    me = data.profile;
    $('#my-name').textContent = me.user;
    const role = $('#my-role');
    role.textContent = me.role;
    role.className = 'pill ' + (me.role === 'admin' ? 'pill-admin' : 'pill-user');
    $('#my-2fa').textContent = me.totpConfirmed ? 'enrolled' : 'not enrolled yet';
    $('#my-created').textContent = new Date(me.created).toLocaleString();
    if (me.passwordIsDefault) {
      say($('#pw-note'), '⚠ This account still uses the documented default password. Change it now.', 'err');
    }
    renderCollector(data.collector);
    if (me.role === 'admin') { $('#users-card').classList.remove('hidden'); loadUsers(); }
  }

  $('#form-password').addEventListener('submit', async (e) => {
    e.preventDefault();
    const note = $('#pw-note');
    const next = $('#pw-next').value;
    if (next !== $('#pw-again').value) return say(note, 'The two new passwords do not match', 'err');
    $('#pw-go').disabled = true;
    say(note, 'saving…', 'info');
    try {
      const { data } = await api('POST', '/api/profile/password', { current: $('#pw-current').value, next });
      if (data.ok) {
        say(note, '✓ Password changed. Your other sessions were signed out.', 'ok');
        $('#form-password').reset();
      } else say(note, data.error || 'Could not change the password', 'err');
    } catch (err) { say(note, 'Cannot reach the backend', 'err'); }
    $('#pw-go').disabled = false;
  });

  $('#form-totp').addEventListener('submit', async (e) => {
    e.preventDefault();
    const note = $('#totp-note');
    $('#totp-go').disabled = true;
    say(note, 'issuing a new secret…', 'info');
    try {
      const { data } = await api('POST', '/api/profile/totp', { password: $('#totp-pw').value });
      if (data.ok) {
        say(note, '✓ New secret issued — the old authenticator entry no longer works.', 'ok');
        $('#totp-pw').value = '';
        $('#my-2fa').textContent = 'not enrolled yet';
        $('#totp-enrol').classList.remove('hidden');
        $('#totp-secret').textContent = data.pretty;
        drawQr($('#totp-qr'), data.uri);
      } else say(note, data.error || 'Could not reset the second factor', 'err');
    } catch (err) { say(note, 'Cannot reach the backend', 'err'); }
    $('#totp-go').disabled = false;
  });

  function drawQr(box, uri) {
    const qr = window.JS && window.JS.qr;
    if (!uri || !qr) { box.textContent = uri || ''; return; }
    try {
      box.innerHTML = qr.toSvg(qr.encode(uri), { label: 'Two-factor enrolment QR code' });
    } catch (err) {
      box.textContent = uri;
    }
  }

  // ── My log collector ─────────────────────────────────────────────────
  function renderCollector(c) {
    const hec = (c && c.hec) || {};
    $('#col-dest').textContent = `${c.ip || '—'}:${c.port}`;
    $('#col-proto').textContent = c.proto === 'hec' ? 'Splunk HEC (HTTP Event Collector)' : c.proto.toUpperCase();
    $('#col-token').textContent = hec.token ? `saved (${hec.token.length} characters)` : 'not set';
    $('#col-index').textContent = hec.index || "the token's default";
    $('#col-stype').textContent = hec.sourcetype || 'syslog';
    $('#col-tls').textContent = c.proto === 'hec'
      ? `${hec.ssl ? 'HTTPS' : 'plain HTTP'}${hec.ssl && hec.insecure ? ', certificate not verified' : ''}`
      : 'not applicable';
  }

  $('#col-reset').addEventListener('click', async () => {
    const note = $('#col-note');
    say(note, 'resetting…', 'info');
    const fresh = {
      ip: '10.0.0.100', port: 514, proto: 'udp',
      hec: { token: '', index: '', sourcetype: 'syslog', ssl: true, insecure: true },
    };
    try {
      const { data } = await api('PUT', '/api/profile/collector', { collector: fresh });
      if (data.ok) { renderCollector(data.collector); say(note, '✓ Back to the defaults. Reload the dashboard to pick it up.', 'ok'); }
      else say(note, data.error || 'Could not save', 'err');
    } catch (err) { say(note, 'Cannot reach the backend', 'err'); }
  });

  // ── Users (admin) ────────────────────────────────────────────────────
  async function loadUsers() {
    const { data } = await api('GET', '/api/users');
    if (!data.ok) return;
    const body = $('#users-body');
    body.innerHTML = '';
    for (const u of data.users) {
      const tr = el('tr');
      if (u.id === data.me) tr.className = 'me';

      tr.appendChild(el('td', 'name', u.user));

      const role = el('td');
      role.appendChild(el('span', 'pill ' + (u.role === 'admin' ? 'pill-admin' : 'pill-user'), u.role));
      tr.appendChild(role);

      const pw = el('td');
      pw.appendChild(u.passwordIsDefault
        ? el('span', 'pill pill-warn', 'default')
        : el('span', 'pill pill-ok', 'set'));
      tr.appendChild(pw);

      const tf = el('td');
      tf.appendChild(u.totpConfirmed
        ? el('span', 'pill pill-ok', 'enrolled')
        : el('span', 'pill pill-warn', 'pending'));
      tr.appendChild(tf);

      const mine = u.id === data.me;
      const lastAdmin = u.role === 'admin' && data.users.filter((x) => x.role === 'admin').length === 1;
      const acts = el('td', 'acts');
      acts.appendChild(button('btn-go', 'Set password', () => setPassword(u)));
      acts.appendChild(button('btn-warn', 'Reset 2FA', () => resetTotp(u)));
      // The server refuses these two on your own account and on the last admin;
      // there is no point offering a button that can only fail.
      acts.appendChild(disable(
        button('btn-warn', u.role === 'admin' ? 'Make user' : 'Make admin',
          () => setRole(u, u.role === 'admin' ? 'user' : 'admin')),
        mine ? 'You cannot change your own role' : lastAdmin ? 'This is the only admin' : null));
      acts.appendChild(disable(
        button('btn-danger', 'Delete', () => remove(u)),
        mine ? 'You cannot delete the account you are signed in as' : lastAdmin ? 'This is the only admin' : null));
      tr.appendChild(acts);

      body.appendChild(tr);
    }
  }

  // Grey out an action with the reason on hover, rather than letting it fail.
  function disable(btn, why) {
    if (why) { btn.disabled = true; btn.title = why; }
    return btn;
  }

  function button(cls, label, onClick) {
    const b = el('button', cls, label);
    b.type = 'button';
    b.addEventListener('click', onClick);
    return b;
  }

  const note = () => $('#users-note');

  async function setPassword(u) {
    const pw = prompt(`New password for "${u.user}" (at least 8 characters):`);
    if (pw == null) return;
    const { data } = await api('POST', `/api/users/${u.id}/password`, { password: pw });
    if (data.ok) { say(note(), `✓ New password set for "${u.user}" — their sessions were signed out.`, 'ok'); loadUsers(); }
    else say(note(), data.error || 'Could not set the password', 'err');
  }

  async function resetTotp(u) {
    if (!confirm(`Reset the second factor for "${u.user}"?\n\nTheir current authenticator entry stops working, and they enrol a new one from the QR shown at their next sign-in.`)) return;
    const { data } = await api('POST', `/api/users/${u.id}/totp`);
    if (data.ok) { say(note(), `✓ "${u.user}" will enrol a new authenticator at their next sign-in.`, 'ok'); loadUsers(); }
    else say(note(), data.error || 'Could not reset the second factor', 'err');
  }

  async function setRole(u, role) {
    const { data } = await api('POST', `/api/users/${u.id}/role`, { role });
    if (data.ok) { say(note(), `✓ "${u.user}" is now a ${role}.`, 'ok'); loadUsers(); }
    else say(note(), data.error || 'Could not change the role', 'err');
  }

  async function remove(u) {
    if (!confirm(`Delete "${u.user}"?\n\nTheir saved Log Collector settings go with them. This cannot be undone.`)) return;
    const { data } = await api('DELETE', `/api/users/${u.id}`);
    if (data.ok) { say(note(), `✓ Deleted "${u.user}".`, 'ok'); loadUsers(); }
    else say(note(), data.error || 'Could not delete that account', 'err');
  }

  $('#form-newuser').addEventListener('submit', async (e) => {
    e.preventDefault();
    $('#nu-go').disabled = true;
    say($('#nu-note'), 'creating…', 'info');
    try {
      const { data } = await api('POST', '/api/users', {
        user: $('#nu-name').value, password: $('#nu-pass').value, role: $('#nu-role').value,
      });
      if (data.ok) {
        say($('#nu-note'), `✓ Created "${data.user.user}". Give them the password — they enrol their own authenticator on first sign-in.`, 'ok');
        $('#form-newuser').reset();
        loadUsers();
      } else say($('#nu-note'), data.error || 'Could not create the account', 'err');
    } catch (err) { say($('#nu-note'), 'Cannot reach the backend', 'err'); }
    $('#nu-go').disabled = false;
  });

  loadProfile().catch(() => {});
})();
