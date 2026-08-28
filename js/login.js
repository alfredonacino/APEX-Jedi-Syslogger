/*
 * login.js — the two-step sign-in on login.html.
 *
 * Step 1 posts the password and gets back a short-lived token, never a session.
 * Step 2 posts that token plus the authenticator code, and only that hands out
 * the session cookie (HttpOnly — this script never sees it).
 */
(function () {
  'use strict';
  const $ = (sel) => document.querySelector(sel);

  const formPassword = $('#form-password');
  const formCode = $('#form-code');
  const msgPassword = $('#msg-password');
  const msgCode = $('#msg-code');

  let pendingToken = null;

  const say = (node, text, cls) => { node.textContent = text; node.className = 'msg ' + (cls || 'info'); };

  // Only ever bounce back to a path on this origin: "?next=" comes from the URL
  // bar, so an absolute or protocol-relative value would be an open redirect.
  function safeNext() {
    const raw = new URLSearchParams(location.search).get('next') || '/';
    return /^\/(?!\/)/.test(raw) ? raw : '/';
  }

  async function post(url, body) {
    const r = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    let data = {};
    try { data = await r.json(); } catch (e) {}
    return { status: r.status, data };
  }

  function showCodeStep(res) {
    formPassword.classList.add('hidden');
    formCode.classList.remove('hidden');
    if (res.stage === 'enrol') {
      $('#code-title').textContent = 'Set up two-factor';
      $('#code-hint').textContent = 'Two-factor is not enrolled yet. Scan the code below with your authenticator, then enter the six digits it shows to finish.';
      $('#enrol-box').classList.remove('hidden');
      $('#enrol-secret').textContent = res.pretty || res.secret || '';
      showQr(res.uri);
      $('#signin-foot').textContent = 'The secret is shown until enrolment completes. After that, only node server.js --reset-2fa can issue a new one.';
    }
    $('#f-code').focus();
  }

  // The URI is the only thing that has to reach the authenticator, and a QR is
  // the one form of it nobody has to retype. If the encoder is missing or the URI
  // will not fit a symbol, fall back to showing the URI itself.
  function showQr(uri) {
    const box = document.querySelector('#enrol-qr');
    const qr = window.JS && window.JS.qr;
    if (!uri || !qr) { box.textContent = uri || ''; return; }
    try {
      box.innerHTML = qr.toSvg(qr.encode(uri), { label: 'Two-factor enrolment QR code' });
    } catch (err) {
      box.textContent = uri;
    }
  }

  formPassword.addEventListener('submit', async (e) => {
    e.preventDefault();
    const btn = $('#btn-password');
    btn.disabled = true;
    say(msgPassword, 'checking…', 'info');
    try {
      const { status, data } = await post('/auth/login', { user: $('#f-user').value, pass: $('#f-pass').value });
      if (status === 200 && data.ok) {
        // JEDI_AUTH=off — the backend is not gating anything.
        if (data.stage === 'done') { location.replace(safeNext()); return; }
        pendingToken = data.pending;
        say(msgPassword, '', 'info');
        showCodeStep(data);
      } else {
        say(msgPassword, data.error || `Sign-in failed (HTTP ${status})`, 'err');
        $('#f-pass').value = '';
        $('#f-pass').focus();
      }
    } catch (err) {
      say(msgPassword, 'Cannot reach the backend — is node server.js running?', 'err');
    } finally {
      btn.disabled = false;
    }
  });

  formCode.addEventListener('submit', async (e) => {
    e.preventDefault();
    const btn = $('#btn-code');
    btn.disabled = true;
    say(msgCode, 'verifying…', 'info');
    try {
      const { status, data } = await post('/auth/totp', { pending: pendingToken, code: $('#f-code').value });
      if (status === 200 && data.ok) {
        say(msgCode, 'Signed in — loading the dashboard…', 'ok');
        location.replace(safeNext());
        return;
      }
      say(msgCode, data.error || `Verification failed (HTTP ${status})`, 'err');
      $('#f-code').value = '';
      $('#f-code').focus();
      // The token behind the password step is gone; the password must be re-entered.
      if (data.expired) {
        pendingToken = null;
        formCode.classList.add('hidden');
        formPassword.classList.remove('hidden');
        say(msgPassword, data.error, 'err');
        $('#f-pass').focus();
      }
    } catch (err) {
      say(msgCode, 'Cannot reach the backend — is node server.js running?', 'err');
    } finally {
      btn.disabled = false;
    }
  });

  // Digits only, so a pasted "123 456" still verifies.
  $('#f-code').addEventListener('input', (e) => {
    const cleaned = e.target.value.replace(/\D/g, '').slice(0, 6);
    if (cleaned !== e.target.value) e.target.value = cleaned;
  });
})();
