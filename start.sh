#!/usr/bin/env bash
#
# APEX JediSyslogger launcher.
#
#   ./start.sh                 start the web app in the foreground (Ctrl-C to stop)
#   ./start.sh -d              start it in the background
#   ./start.sh stop            stop the background instance
#   ./start.sh restart         restart the background instance
#   ./start.sh status          is it running, and is it answering?
#   ./start.sh logs [-f]       show (or follow) the background log
#   ./start.sh desktop         run it as the desktop app (loopback, own window)
#   ./start.sh cli [args…]     run the terminal build (bin/jedi)
#
# Node is the only requirement — there is nothing to install and no build step.
# Any option this script does not recognise is passed through to the app.

set -euo pipefail

cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RUNDIR=".run"
HOST="${JEDI_BIND:-0.0.0.0}"
PORT="${PORT:-8099}"
OPEN_BROWSER=1
DAEMON=0
COMMAND="start"
PASSTHROUGH=()

# ---------------------------------------------------------------- output --

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  C_DIM=$'\033[2m'; C_B=$'\033[1m'; C_OK=$'\033[32m'; C_WARN=$'\033[33m'
  C_ERR=$'\033[31m'; C_CY=$'\033[36m'; C_0=$'\033[0m'
else
  C_DIM=""; C_B=""; C_OK=""; C_WARN=""; C_ERR=""; C_CY=""; C_0=""
fi

say()  { printf '%s\n' "$*"; }
info() { printf '%s>%s %s\n' "$C_CY" "$C_0" "$*"; }
ok()   { printf '%s✓%s %s\n' "$C_OK" "$C_0" "$*"; }
warn() { printf '%s!%s %s\n' "$C_WARN" "$C_0" "$*"; }
die()  { printf '%s✗%s %s\n' "$C_ERR" "$C_0" "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
APEX JediSyslogger launcher.

  ./start.sh                 start the web app in the foreground (Ctrl-C to stop)
  ./start.sh -d              start it in the background
  ./start.sh stop            stop the background instance
  ./start.sh restart         restart the background instance
  ./start.sh status          is it running, and is it answering?
  ./start.sh logs [-f]       show (or follow) the background log
  ./start.sh desktop         run it as the desktop app (loopback, own window)
  ./start.sh cli [args…]     run the terminal build (bin/jedi)

Launcher options:
  --port PORT              bind port (default 8099)
  --host HOST              bind address (default 0.0.0.0; 127.0.0.1 = this machine only)
  --no-auth                run with no sign-in at all (local throwaway use)
  --no-browser             do not open a browser window
  -d, --daemon             run in the background, logging to .run/
  -h, --help               this text

Everything else is passed through: `./start.sh cli attack ssh-brute --json`.
EOF
}

# ------------------------------------------------------------- arguments --

while [ $# -gt 0 ]; do
  case "$1" in
    start|stop|restart|status|logs|desktop|cli)
      COMMAND="$1"; shift
      # Everything after `cli` belongs to the terminal build, flags included.
      if [ "$COMMAND" = "cli" ]; then PASSTHROUGH+=("$@"); break; fi ;;
    -d|--daemon)   DAEMON=1; shift ;;
    --no-browser)  OPEN_BROWSER=0; shift ;;
    --no-auth)     export JEDI_AUTH=off; shift ;;
    --port)        PORT="${2:?--port needs a value}"; shift 2 ;;
    --port=*)      PORT="${1#*=}"; shift ;;
    --host)        HOST="${2:?--host needs a value}"; shift 2 ;;
    --host=*)      HOST="${1#*=}"; shift ;;
    -h|--help)     usage; exit 0 ;;
    *)             PASSTHROUGH+=("$1"); shift ;;
  esac
done

command -v node >/dev/null 2>&1 || die "Node.js is required but was not found on PATH (https://nodejs.org)."

# Runtime files are per-port, so `--port 8100` is a distinct instance rather than
# being mistaken for the one already running on the default port.
mkdir -p "$RUNDIR"
PIDFILE="$RUNDIR/jedi-$PORT.pid"
LOGFILE="$RUNDIR/jedi-$PORT.log"

# Hints have to name the port when it is not the default, or copy-pasting them
# would act on a different instance.
if [ "$PORT" = "8099" ]; then PORT_HINT=""; else PORT_HINT=" --port $PORT"; fi

# 0.0.0.0 is not somewhere you can browse to, and the app serves HTTPS whenever
# a certificate is present (see the TLS section of DOCUMENTATION.md).
case "$HOST" in
  0.0.0.0|::|"") BROWSE_HOST="localhost" ;;
  *)             BROWSE_HOST="$HOST" ;;
esac
if [ -f "${JEDI_TLS_CERT:-certs/server.crt}" ] && [ -f "${JEDI_TLS_KEY:-certs/server.key}" ]; then
  SCHEME="https"
else
  SCHEME="http"
fi
URL="$SCHEME://$BROWSE_HOST:$PORT"

export PORT
export JEDI_BIND="$HOST"

# ------------------------------------------------------------- processes --

running_pid() {
  [ -f "$PIDFILE" ] || return 1
  local pid
  pid="$(cat "$PIDFILE" 2>/dev/null || true)"
  [ -n "$pid" ] || return 1
  # Only claim it is ours. A recycled pid, or somebody else's node, must never
  # be reported as ours — and must never be killed by `stop`.
  if kill -0 "$pid" 2>/dev/null && ps -p "$pid" -o args= 2>/dev/null | grep -q "[s]erver.js"; then
    printf '%s' "$pid"
    return 0
  fi
  rm -f "$PIDFILE"
  return 1
}

port_busy() {
  (exec 3<>"/dev/tcp/$BROWSE_HOST/$PORT") 2>/dev/null && exec 3<&- 3>&- && return 0
  return 1
}

# /auth/session is the one route that answers before you have signed in.
answering() {
  if command -v curl >/dev/null 2>&1; then
    curl -fsS -k -m 2 "$URL/auth/session" >/dev/null 2>&1
  else
    port_busy
  fi
}

wait_until_up() {
  local i
  for ((i = 0; i < 80; i++)); do
    answering && return 0
    # If a backgrounded server died on startup, stop waiting and show why.
    if [ "$DAEMON" = "1" ] && [ -f "$PIDFILE" ] && ! running_pid >/dev/null; then return 1; fi
    sleep 0.25
  done
  return 1
}

open_browser() {
  [ "$OPEN_BROWSER" = "1" ] || return 0
  local opener="" candidate
  for candidate in xdg-open open gio; do
    command -v "$candidate" >/dev/null 2>&1 && { opener="$candidate"; break; }
  done
  [ -n "$opener" ] || return 0
  if [ "$opener" = "gio" ]; then
    ( gio open "$URL" >/dev/null 2>&1 & ) || true
  else
    ( "$opener" "$URL" >/dev/null 2>&1 & ) || true
  fi
}

banner() {
  local version
  version="$(node -p "require('./js/version.js').VERSION" 2>/dev/null || echo '?')"
  say ""
  say "  ${C_B}APEX JediSyslogger${C_0} ${C_DIM}v$version — SIEM log ingestion simulator${C_0}"
  say "  ${C_DIM}url ${C_0} $URL"
  say "  ${C_DIM}bind${C_0} $HOST:$PORT"
  say ""
}

# -------------------------------------------------------------- commands --

cmd_start() {
  local pid
  if pid="$(running_pid)"; then
    warn "JediSyslogger is already running (pid $pid) on $URL."
    say  "  ${C_DIM}./start.sh restart$PORT_HINT${C_0} to restart it, ${C_DIM}./start.sh stop$PORT_HINT${C_0} to stop it."
    open_browser
    exit 0
  fi

  if port_busy; then
    die "Port $PORT is already in use by something this script did not start. Pick another with --port 8100."
  fi

  if [ "$DAEMON" = "1" ]; then
    banner
    info "Starting in the background; logging to $LOGFILE"
    : > "$LOGFILE"
    nohup node server.js "${PASSTHROUGH[@]+"${PASSTHROUGH[@]}"}" >> "$LOGFILE" 2>&1 &
    echo $! > "$PIDFILE"
    if wait_until_up; then
      ok "Up on $URL (pid $(cat "$PIDFILE"))."
      say "  ${C_DIM}./start.sh logs -f$PORT_HINT${C_0} to follow the log, ${C_DIM}./start.sh stop$PORT_HINT${C_0} to stop."
      open_browser
    else
      warn "It did not come up. Last lines of $LOGFILE:"
      tail -n 25 "$LOGFILE" >&2 || true
      rm -f "$PIDFILE"
      exit 1
    fi
    exit 0
  fi

  banner
  if [ "$OPEN_BROWSER" = "1" ]; then
    # Open the browser once the server actually answers, in a subshell so the
    # server itself keeps the terminal.
    ( wait_until_up && open_browser ) >/dev/null 2>&1 &
  fi
  exec node server.js "${PASSTHROUGH[@]+"${PASSTHROUGH[@]}"}"
}

cmd_stop() {
  local pid
  if ! pid="$(running_pid)"; then
    warn "Not running (no live pid in $PIDFILE). Nothing else is touched."
    return 0
  fi
  info "Stopping JediSyslogger (pid $pid) …"
  kill "$pid" 2>/dev/null || true
  local i
  for ((i = 0; i < 40; i++)); do
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.25
  done
  if kill -0 "$pid" 2>/dev/null; then
    warn "It did not stop politely; sending SIGKILL."
    kill -9 "$pid" 2>/dev/null || true
    sleep 0.5
  fi
  rm -f "$PIDFILE"
  ok "Stopped."
}

cmd_status() {
  local pid
  if pid="$(running_pid)"; then
    if answering; then
      ok "Running (pid $pid) and answering on $URL."
      say "  ${C_DIM}version${C_0} $(node -p "require('./js/version.js').VERSION" 2>/dev/null || echo '?')"
      say "  ${C_DIM}log    ${C_0} $LOGFILE"
    else
      warn "Process $pid is alive but $URL is not answering yet."
    fi
  elif port_busy; then
    warn "Something is listening on $PORT, but it is not an instance this script started."
  else
    say "JediSyslogger is not running on $PORT."
  fi
}

cmd_logs() {
  [ -f "$LOGFILE" ] || die "No log at $LOGFILE yet. Start with './start.sh -d' to log to a file."
  if printf '%s\n' "${PASSTHROUGH[@]+"${PASSTHROUGH[@]}"}" | grep -qx -- "-f"; then
    tail -n 60 -f "$LOGFILE"
  else
    tail -n 60 "$LOGFILE"
  fi
}

case "$COMMAND" in
  start)   cmd_start ;;
  stop)    cmd_stop ;;
  restart) cmd_stop; DAEMON=1; cmd_start ;;
  status)  cmd_status ;;
  logs)    cmd_logs ;;
  # The desktop launcher picks its own loopback port and mints its own ticket;
  # it must not inherit PORT/JEDI_BIND from this script.
  desktop) unset PORT JEDI_BIND; exec node desktop.js "${PASSTHROUGH[@]+"${PASSTHROUGH[@]}"}" ;;
  cli)     exec ./bin/jedi "${PASSTHROUGH[@]+"${PASSTHROUGH[@]}"}" ;;
  *)       usage; exit 1 ;;
esac
