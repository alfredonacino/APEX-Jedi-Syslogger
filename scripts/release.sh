#!/usr/bin/env bash
# =============================================================================
# release.sh: build, sign and publish an APEX JediSyslogger release to the
# ARES Repository (app apex-jedisyslogger-portable). Unattended; no prompts.
#
#   scripts/release.sh [VERSION] [--stage] [--channel NAME] [--rollout PCT]
#                      [--notes TEXT | --notes-file FILE] [--skip-build]
#                      [--dry-run] [-h]
#
#   VERSION        must equal js/version.js (the source of truth). To release a
#                  new version, stamp it first: packaging/version.sh --set X.Y.Z
#   --stage        upload and attach the signed manifest, but do not publish
#   --channel      default: stable
#   --rollout PCT  offer it to ~PCT% of clients (default: the server's, 100)
#   --notes TEXT / --notes-file FILE   release notes, inside the signed manifest
#   --skip-build   use what is already in dist/ (sign.js still refuses
#                  artefacts older than the source)
#   --dry-run      build, then show what would be uploaded; contacts nothing
#
# The pipeline is the project's own: packaging/build.sh, then packaging/sign.js
# (signs with the manifest format and key that shipped builds verify), then
# packaging/publish.js (create, upload, attach, publish).
#
# Configuration, from ~/.config/ares-repository/apex-jedisyslogger-portable.env
# (variables already set in the environment win):
#   APEX_SERVER   default https://aresrepo.cybercontrol.tech
#   APEX_TOKEN    publishing token. Create it once with
#                 "/media/RAID1/CLAUDE_PROJECTS/ARES Repository/tools/issue-release-tokens.sh" apex-jedisyslogger-portable
#   Signing key, first found: APEX_SIGNING_KEY, APEX_SIGNING_KEY_FILE,
#   JEDI_PUBLISH_KEY, JEDI_PUBLISH_KEY_FILE, ~/.config/apex-jedisyslogger/publish.key
# =============================================================================
set -euo pipefail

SLUG=apex-jedisyslogger-portable
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CONF="${ARES_CONF_DIR:-$HOME/.config/ares-repository}/$SLUG.env"
ISSUE_TOOL="/media/RAID1/CLAUDE_PROJECTS/ARES Repository/tools/issue-release-tokens.sh"
DEFAULT_KEY_FILE="$HOME/.config/apex-jedisyslogger/publish.key"

usage() { sed -n '3,30p' "$0" | sed 's/^# \{0,1\}//'; }
die() { echo "release: $*" >&2; exit 1; }
say() { printf '  %s\n' "$*"; }

VERSION="" STAGE=0 CHANNEL=stable ROLLOUT="" NOTES="" HAVE_NOTES=0 SKIP_BUILD=0 DRY=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --stage) STAGE=1 ;;
    --channel) [[ $# -ge 2 ]] || die "--channel needs a name"; CHANNEL=$2; shift ;;
    --rollout) [[ $# -ge 2 ]] || die "--rollout needs a percentage"; ROLLOUT=$2; shift ;;
    --notes) [[ $# -ge 2 ]] || die "--notes needs text"; NOTES=$2; HAVE_NOTES=1; shift ;;
    --notes-file) [[ $# -ge 2 && -f "$2" ]] || die "--notes-file needs a readable file"
                  NOTES=$(<"$2"); HAVE_NOTES=1; shift ;;
    --skip-build) SKIP_BUILD=1 ;;
    --dry-run) DRY=1 ;;
    -*) die "unknown option $1 (see --help)" ;;
    *) [[ -z "$VERSION" ]] || die "only one VERSION, please"; VERSION=$1 ;;
  esac
  shift
done
[[ -z "$ROLLOUT" || "$ROLLOUT" =~ ^[0-9]+$ && $ROLLOUT -ge 1 && $ROLLOUT -le 100 ]] \
  || die "--rollout wants a whole number from 1 to 100"
[[ "$CHANNEL" =~ ^[A-Za-z0-9._-]+$ ]] || die "bad channel name: $CHANNEL"

cd "$ROOT"
command -v node >/dev/null || die "node is required"

# ---- configuration: the env file, without overriding what is already set ----
VARS=(APEX_SERVER APEX_APP APEX_TOKEN APEX_SIGNING_KEY APEX_SIGNING_KEY_FILE)
declare -A KEEP=()
for v in "${VARS[@]}"; do [[ -n "${!v:-}" ]] && KEEP[$v]=${!v}; done
if [[ -f "$CONF" ]]; then
  set -a; # shellcheck disable=SC1090
  source "$CONF"; set +a
fi
for v in "${!KEEP[@]}"; do export "$v=${KEEP[$v]}"; done
export APEX_SERVER="${APEX_SERVER:-https://aresrepo.cybercontrol.tech}"
[[ -z "${APEX_APP:-}" || "$APEX_APP" == "$SLUG" ]] || die "APEX_APP is '$APEX_APP' but this project is '$SLUG'"

if [[ -z "${APEX_TOKEN:-}" ]]; then
  msg="no APEX_TOKEN (looked in the environment and $CONF). Create one with:
         \"$ISSUE_TOOL\" $SLUG"
  if [[ $DRY -eq 1 ]]; then echo "release: warning: $msg" >&2; else die "$msg"; fi
fi

# ---- signing key: hand it to sign.js by name, never by value on argv --------
KEY_FROM=""
if [[ -n "${APEX_SIGNING_KEY:-}" ]]; then
  export JEDI_PUBLISH_KEY="$APEX_SIGNING_KEY"; KEY_FROM='$APEX_SIGNING_KEY'
elif [[ -n "${APEX_SIGNING_KEY_FILE:-}" ]]; then
  [[ -f "$APEX_SIGNING_KEY_FILE" ]] || die "APEX_SIGNING_KEY_FILE=$APEX_SIGNING_KEY_FILE does not exist"
  unset JEDI_PUBLISH_KEY; export JEDI_PUBLISH_KEY_FILE="$APEX_SIGNING_KEY_FILE"; KEY_FROM=$APEX_SIGNING_KEY_FILE
elif [[ -n "${JEDI_PUBLISH_KEY:-}" ]]; then
  KEY_FROM='$JEDI_PUBLISH_KEY'
elif [[ -n "${JEDI_PUBLISH_KEY_FILE:-}" && -f "$JEDI_PUBLISH_KEY_FILE" ]]; then
  KEY_FROM=$JEDI_PUBLISH_KEY_FILE
elif [[ -f "$DEFAULT_KEY_FILE" ]]; then
  KEY_FROM=$DEFAULT_KEY_FILE
fi
if [[ -z "$KEY_FROM" ]]; then
  msg="no signing key. Set APEX_SIGNING_KEY or APEX_SIGNING_KEY_FILE in $CONF,
         or put the key at $DEFAULT_KEY_FILE (chmod 600)"
  if [[ $DRY -eq 1 ]]; then echo "release: warning: $msg" >&2; else die "$msg"; fi
fi

# ---- version ----------------------------------------------------------------
SRC_VERSION=$(node -p "require('./js/version.js').VERSION")
if [[ -n "$VERSION" && "$VERSION" != "$SRC_VERSION" ]]; then
  die "asked for $VERSION but js/version.js says $SRC_VERSION.
         Stamp it first: packaging/version.sh --set $VERSION (and commit), then re-run."
fi
VERSION=$SRC_VERSION
./packaging/version.sh --check >/dev/null || die "the version files disagree (packaging/version.sh --check)"

echo
say "APEX JediSyslogger $VERSION -> $APEX_SERVER  app $SLUG  channel $CHANNEL$([[ $STAGE -eq 1 ]] && echo '  (stage only)')$([[ $DRY -eq 1 ]] && echo '  (DRY RUN)')"
echo

# ---- build ------------------------------------------------------------------
if [[ $SKIP_BUILD -eq 0 ]]; then
  targets=()
  if command -v ar >/dev/null; then targets+=(--deb); else say "note: no 'ar' (binutils) - skipping the .deb"; fi
  if command -v rpmbuild >/dev/null; then targets+=(--rpm); else say "note: no rpmbuild - skipping the .rpm"; fi
  if command -v makepkg >/dev/null; then targets+=(--arch); else say "note: no makepkg - skipping the Arch package"; fi
  ./packaging/build.sh "${targets[@]}"
else
  say "--skip-build: using dist/ as it is"
fi

# ---- sign (local) -----------------------------------------------------------
if [[ -z "$KEY_FROM" ]]; then
  # Dry run without a key: list what sign.js would pick up, unsigned.
  say "not signing (no key). Files sign.js would include:"
  find dist -maxdepth 1 -type f -name "*$VERSION*" ! -name SHA256SUMS ! -name '*.json' ! -name '*.sig' -printf '    %f\n' | sort
  echo; say "dry run: nothing was contacted"; exit 0
fi
sign_args=(--channel "$CHANNEL")
[[ $HAVE_NOTES -eq 1 ]] && sign_args+=(--notes "$NOTES")
node packaging/sign.js "${sign_args[@]}"

# Exactly one file per (platform, arch, format), or nothing goes out.
node -e '
  const m = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"));
  const seen = new Map();
  for (const a of m.artifacts) {
    const k = `${a.platform}/${a.arch}/${a.format}`;
    if (seen.has(k)) { console.error(`release: ${seen.get(k)} and ${a.filename} are both ${k}`); process.exit(1); }
    seen.set(k, a.filename);
  }' "dist/publish/$CHANNEL.json"

# ---- publish ----------------------------------------------------------------
pub_args=(--channel "$CHANNEL" --app "$SLUG")
[[ $STAGE -eq 1 ]] && pub_args+=(--stage)
[[ -n "$ROLLOUT" ]] && pub_args+=(--rollout "$ROLLOUT")
[[ $DRY -eq 1 ]] && pub_args+=(--dry-run)
node packaging/publish.js "${pub_args[@]}"
[[ $DRY -eq 1 ]] && say "dry run: nothing was contacted"
exit 0
