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
// Below this, a browser exit means "handed off", not "window closed".
const HANDOFF_MS = 5000;
// If no page ever checks in, something rendered nothing; do not wait forever.
const FIRST_BEAT_MS = 90000;
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

// ── Reporting a failure that nobody can see ──────────────────────────────
// Launched from a menu, a Dock or a Start Menu shortcut there is no terminal,
// so a message on stderr goes nowhere and the app just "closes right away".
// Everything that can end the launch early comes through here: it leaves a log
// on disk and puts a dialog on screen when there is no console to read.
function dataDir() {
  return path.dirname(profileDir());
}

function reportFailure(summary, detail) {
  const dir = dataDir();
  let logPath = null;
  // Every install writes to the same per-user log, so it has to say which one
  // wrote it. Without that, a log from one copy reads exactly like a log from
  // another — including one left behind by a test.
  let store = '(not resolved)';
  try { store = require('./auth.js').STORE; } catch (e) { /* auth.js may be what failed */ }
  const header = [
    new Date().toISOString(),
    `${NAME} ${VERSION}`,
    `install:  ${ROOT}`,
    `launcher: ${__filename}`,
    `node:     ${process.version} (${process.execPath})`,
    `store:    ${store}`,
    `platform: ${process.platform}-${process.arch}`,
  ].join('\n');
  try {
    fs.mkdirSync(dir, { recursive: true });
    logPath = path.join(dir, 'last-launch.log');
    fs.writeFileSync(logPath, `${header}\n\n${summary}\n\n${detail || ''}\n`);
  } catch (e) { /* a log we cannot write is not worth failing over */ }

  process.stderr.write(`\n  ${summary}\n${detail ? '\n' + detail + '\n' : ''}`);
  if (logPath) process.stderr.write(`\n  written to ${logPath}\n`);

  // With a terminal attached the text above is enough.
  if (process.stderr.isTTY) return;

  const body = `${summary}\n\n${logPath ? 'Details: ' + logPath : ''}`;
  try {
    if (process.platform === 'darwin') {
      spawn('osascript', ['-e', `display alert "${NAME}" message ${JSON.stringify(body)}`], { stdio: 'ignore' });
    } else if (process.platform === 'win32') {
      spawn('mshta', [`javascript:alert(${JSON.stringify(body)});close();`], { stdio: 'ignore' });
    } else {
      const gui = onPath('zenity') ? ['zenity', ['--error', '--no-wrap', `--text=${body}`]]
        : onPath('kdialog') ? ['kdialog', ['--error', body]]
        : null;
      if (gui) spawn(gui[0], gui[1], { stdio: 'ignore' });
    }
  } catch (e) { /* no dialog available; the log stands */ }
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

function resolveBrowser(c) {
  if (c.includes(path.sep) || c.includes('/')) return fs.existsSync(c) ? c : null;
  return onPath(c);
}

function findBrowser() {
  // JEDI_BROWSER first: it is the override we tell people to reach for when the
  // window does not appear, and behind the candidate list it could only ever
  // take effect on a machine with no browser at all — where it is least needed.
  if (process.env.JEDI_BROWSER) {
    const chosen = resolveBrowser(process.env.JEDI_BROWSER);
    if (chosen) return chosen;
    log(`JEDI_BROWSER=${process.env.JEDI_BROWSER} is not an executable — looking for one instead.`);
  }
  const list = CANDIDATES[process.platform] || CANDIDATES.linux;
  for (const c of list) {
    const found = resolveBrowser(c);
    if (found) return found;
  }
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
    // reportFailure, not log(): launched from a menu entry there is no terminal
    // to read, and an incomplete install would otherwise look like nothing
    // happened at all. The single-file build lands here too — it carries the
    // engine, but not the server, the page or the stylesheet.
    reportFailure(`${NAME} could not start: the installation is incomplete.`,
      `No server.js in ${ROOT}\n\n` +
      `Install the full application (package, or the portable archive) and run\n` +
      `'jedi desktop' from there. The single-file build is the terminal app only.`);
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
      reportFailure(
        `${NAME} could not start (the backend exited with code ${code}).`,
        `Common causes:\n` +
        `  • Node.js 18 or newer is required — this ran ${process.version}\n` +
        `  • the install directory is read-only (it needs to write auth.json)\n` +
        `  • another copy is already running\n\n` +
        `Backend output:\n${buffer.split('\n').slice(-15).join('\n')}`);
    }
    shutdown(code || 0);
  });

  child.on('error', (e) => {
    reportFailure(`${NAME} could not start Node.js.`, e.message);
    shutdown(1);
  });

  function openWindow(url) {
    const browser = findBrowser();
    const shown = url.replace(/\?t=.*/, '');
    if (!browser) {
      log(`no Chromium-family browser found, so this cannot open as its own window.`);
      log(`Opening ${shown} in your default browser instead — it will be an ordinary tab.`);
      log(`Install Chromium, Chrome, Brave or Edge for the desktop window, or set JEDI_BROWSER.`);
      if (!openDefault(url))
        reportFailure(`${NAME} could not open a browser.`,
          `No Chromium, Chrome, Brave or Edge was found, and the system could not\n` +
          `open a default browser either.\n\nOpen this address manually:\n${url}`);
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
    const openedAt = Date.now();
    // Nothing has rendered if the page never checks in. Say so rather than
    // sitting at a prompt that looks like it is working.
    const idleWarn = /** @type {any} */ (setTimeout(() => {
      if (shuttingDown) return;
      const url = shown.replace('/launch', '');
      require('http').get(`${url}/status`, (r) => r.resume())
        .on('error', () => {});
      log(`still no window after ${FIRST_BEAT_MS / 1000}s. If nothing appeared, run`);
      log(`  jedi desktop --debug        to see the backend log, or`);
      log(`  JEDI_BROWSER=/path/to/browser jedi desktop`);
    }, FIRST_BEAT_MS));
    if (idleWarn && typeof idleWarn.unref === 'function') idleWarn.unref();
    window = spawn(browser, args, { stdio: 'ignore' });
    window.on('exit', () => {
      // A browser that exits immediately did not close a window — it handed our
      // URL to an instance that was already running (a profile already in use, a
      // Snap or Flatpak wrapper, Chrome already open on Windows or macOS) and
      // then quit. Treating that as "the user closed the app" is what made the
      // window vanish the moment it appeared. The window is still there; it just
      // belongs to another process now, so let the page's own heartbeat decide.
      if (Date.now() - openedAt < HANDOFF_MS) {
        window = null;
        log(`the window opened in an existing browser process — watching the app instead of that process.`);
        return;
      }
      shutdown(0);
    });
    window.on('error', (e) => {
      // The browser we found will not run. Fall back before giving up, and only
      // complain if that fails too.
      if (!openDefault(url))
        reportFailure(`${NAME} could not open a window.`,
          `Tried: ${browser}\n${e.message}\n\nOpen this address manually:\n${url}`);
    });
  }

  process.on('SIGINT', () => shutdown(0));
  process.on('SIGTERM', () => shutdown(0));
}


if (require.main === module) main();
// main is exported because `jedi desktop` reaches this file through require():
// the guard above is false then, so the CLI has to call it.
module.exports = { main, findBrowser, profileDir, HANDOFF_MS, FIRST_BEAT_MS };
