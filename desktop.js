#!/usr/bin/env node
/*
 * desktop.js — run APEX JediSyslogger as a desktop application.
 *
 *   jedi desktop            open the app in its own window
 *   jedi desktop --debug    keep the server's log on this terminal
 *
 * There is no web server to start, no URL to type and no sign-in. This starts
 * the backend on loopback with an ephemeral port, spends a one-shot launch
 * ticket for a session, and opens a chromeless window pointed at it. Closing
 * the window stops the backend.
 *
 * What this is not: a bundled browser engine. It renders in a Chromium-family
 * browser already installed on the machine, run in app mode — no address bar,
 * no tabs, its own window and its own profile directory. That is a deliberate
 * trade: Electron would make the window ours at the cost of ~200 MB per
 * platform, an npm toolchain, and a build per operating system, none of which
 * this project has or wants. If no such browser exists we fall back to the
 * default one and say so, rather than pretending.
 *
 * Node core only.
 */
'use strict';

const { spawn } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const ROOT = __dirname;
const { VERSION, NAME } = require('./js/version.js');

const DEBUG = process.argv.includes('--debug');
const log = (msg) => process.stderr.write(`  ${msg}\n`);

// ── Where the window keeps its profile ───────────────────────────────────
// A directory of its own, so the app window is a separate browser process we
// can wait on, and so it never touches the profile someone browses with.
function profileDir() {
  const home = os.homedir();
  if (process.platform === 'win32')
    return path.join(process.env.LOCALAPPDATA || path.join(home, 'AppData', 'Local'), 'apex-jedisyslogger', 'window');
  if (process.platform === 'darwin')
    return path.join(home, 'Library', 'Application Support', 'apex-jedisyslogger', 'window');
  return path.join(process.env.XDG_DATA_HOME || path.join(home, '.local', 'share'), 'apex-jedisyslogger', 'window');
}

// ── Finding something that can render a window ───────────────────────────
const CANDIDATES = {
  linux: ['chromium', 'chromium-browser', 'google-chrome', 'google-chrome-stable',
    'brave-browser', 'brave', 'microsoft-edge', 'microsoft-edge-stable', 'vivaldi-stable', 'vivaldi'],
  darwin: [
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
    '/Applications/Chromium.app/Contents/MacOS/Chromium',
    '/Applications/Brave Browser.app/Contents/MacOS/Brave Browser',
    '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge',
  ],
  win32: [
    'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
    'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
    'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
    'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe',
    'C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe',
  ],
};

function onPath(cmd) {
  const dirs = (process.env.PATH || '').split(path.delimiter);
  for (const d of dirs) {
    const f = path.join(d, cmd);
    try { if (fs.existsSync(f) && (fs.statSync(f).mode & 0o111)) return f; } catch (e) { /* unreadable */ }
  }
  return null;
}

function findBrowser() {
  const list = CANDIDATES[process.platform] || CANDIDATES.linux;
  for (const c of list) {
    if (c.includes(path.sep) || c.includes('/')) { if (fs.existsSync(c)) return c; }
    else { const p = onPath(c); if (p) return p; }
  }
  if (process.env.JEDI_BROWSER && fs.existsSync(process.env.JEDI_BROWSER)) return process.env.JEDI_BROWSER;
  return null;
}

// The last resort: hand the URL to whatever opens links. It becomes a tab in
// the user's ordinary browser, which is not a desktop app — so say so.
function openDefault(url) {
  const cmd = process.platform === 'darwin' ? 'open'
    : process.platform === 'win32' ? 'cmd' : 'xdg-open';
  const args = process.platform === 'win32' ? ['/c', 'start', '', url] : [url];
  try { spawn(cmd, args, { detached: true, stdio: 'ignore' }).unref(); return true; }
  catch (e) { return false; }
}

// ── Main ─────────────────────────────────────────────────────────────────
function main() {
  const serverPath = path.join(ROOT, 'server.js');
  if (!fs.existsSync(serverPath)) {
    log(`cannot find server.js next to ${path.basename(__filename)} — is the installation complete?`);
    process.exit(1);
  }

  const child = spawn(process.execPath, [serverPath], {
    cwd: ROOT,
    env: Object.assign({}, process.env, { JEDI_DESKTOP: '1', PORT: '0' }),
    stdio: ['ignore', 'pipe', DEBUG ? 'inherit' : 'pipe'],
  });

  let started = false;
  let buffer = '';
  let window = null;
  let shuttingDown = false;

  const shutdown = (code) => {
    if (shuttingDown) return;
    shuttingDown = true;
    try { if (window && !window.killed) window.kill(); } catch (e) { /* already gone */ }
    try { child.kill(); } catch (e) { /* already gone */ }
    process.exit(code || 0);
  };

  child.stdout.on('data', (chunk) => {
    buffer += chunk.toString();
    if (DEBUG) process.stderr.write(chunk);
    if (started) return;
    const m = /JEDI_DESKTOP_URL=(\S+)/.exec(buffer);
    if (!m) return;
    started = true;
    openWindow(m[1]);
  });

  if (!DEBUG && child.stderr) child.stderr.on('data', (c) => { buffer += c.toString(); });

  child.on('exit', (code) => {
    if (!started) {
      log(`the backend stopped before it was ready (exit ${code}).`);
      if (!DEBUG) process.stderr.write(buffer.split('\n').slice(-12).join('\n') + '\n');
      log('run `jedi desktop --debug` to see the whole log.');
    }
    shutdown(code || 0);
  });

  function openWindow(url) {
    const browser = findBrowser();
    const shown = url.replace(/\?t=.*/, '');
    if (!browser) {
      log(`no Chromium-family browser found, so this cannot open as its own window.`);
      log(`Opening ${shown} in your default browser instead — it will be an ordinary tab.`);
      log(`Install Chromium, Chrome, Brave or Edge for the desktop window, or set JEDI_BROWSER.`);
      if (!openDefault(url)) log(`could not open a browser at all. Visit: ${url}`);
      log(`Press Ctrl+C to stop.`);
      return;
    }
    const dir = profileDir();
    try { fs.mkdirSync(dir, { recursive: true }); } catch (e) { /* falls back below */ }
    const args = [
      `--app=${url}`,
      `--user-data-dir=${dir}`,
      '--no-first-run',
      '--no-default-browser-check',
      '--disable-background-networking',
      // The window is the application; nothing here should phone home or nag.
      '--disable-features=Translate,MediaRouter,OptimizationHints',
      '--window-size=1440,900',
    ];
    // Without this the taskbar files the window under Chromium and the .desktop
    // entry's icon never attaches to it. Linux/X11 and XWayland only; harmless
    // elsewhere, but Chrome on macOS and Windows rejects unknown flags loudly,
    // so keep it where it means something.
    if (process.platform === 'linux') args.push('--class=APEX-JediSyslogger');
    log(`${NAME} ${VERSION}`);
    log(`window: ${path.basename(browser)}   backend: ${shown.replace('/launch', '')}`);
    log(`close the window to stop.`);
    window = spawn(browser, args, { stdio: 'ignore' });
    window.on('exit', () => shutdown(0));
    window.on('error', (e) => {
      log(`could not start ${browser}: ${e.message}`);
      if (!openDefault(url)) log(`visit: ${url}`);
    });
  }

  process.on('SIGINT', () => shutdown(0));
  process.on('SIGTERM', () => shutdown(0));
}

if (require.main === module) main();
module.exports = { findBrowser, profileDir };
