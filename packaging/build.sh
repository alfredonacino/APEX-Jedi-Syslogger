#!/usr/bin/env bash
# build.sh — produce the distributable artefacts.
#
#   ./packaging/build.sh              portable archives + the single-file build
#   ./packaging/build.sh --sea        also a standalone binary for THIS platform
#
# The portable archives need nothing but Node on the target and are what most
# people should use. The --sea build produces an executable with Node baked in
# for machines that have no Node at all; it is the one path here that reaches
# outside the project, because Node's own single-executable feature needs
# `postject` to inject the blob. It stays opt-in for that reason, and the
# application itself keeps zero runtime dependencies either way.
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT=$PWD
# A package that claims a different version from the app inside it is worse
# than no package, so this is a hard gate rather than a warning.
./packaging/version.sh --check
VERSION=$(node -p "require('./js/version.js').VERSION")
NAME=apex-jedisyslogger
STAGE="dist/$NAME-$VERSION"

say() { printf '  %s\n' "$*"; }

rm -rf "$STAGE"
mkdir -p "$STAGE" dist

# ---- 1. Portable archive -------------------------------------------------
# The whole application, minus per-install state and build output. It runs as
# the terminal app (bin/jedi) and, if you want the browser UI on that machine,
# as the web app too (node server.js) — one artefact, both faces.
say "staging $NAME-$VERSION"
for item in jedi-cli.js server.js auth.js forward.js ecosystem.config.js \
            index.html login.html account.html about.html \
            README.md DOCUMENTATION.md CONNECTORS.md LICENSE \
            js css bin samples types jsconfig.json; do
  [ -e "$item" ] && cp -R "$item" "$STAGE/" || true
done
# Never ship per-install state or private key material.
rm -f "$STAGE/auth.json"
rm -rf "$STAGE/certs" "$STAGE/.git" "$STAGE/.claude"

cat > "$STAGE/INSTALL.txt" <<TXT
APEX JediSyslogger $VERSION — portable build

Requires Node.js 18 or newer (https://nodejs.org). Nothing to compile, nothing
to install, no npm.

  macOS / Linux      ./bin/jedi              live terminal dashboard
                     ./bin/jedi --help       every command and flag
  Windows            bin\\jedi.cmd

Put it on PATH (optional):
  macOS / Linux      sudo ln -s "\$PWD/bin/jedi" /usr/local/bin/jedi
  Windows            add this folder's bin\\ to PATH

The browser dashboard is in the same directory if you want it:
  node server.js     then open the printed URL

Terminal and web app are the same engine and the same version ($VERSION), so a
scenario raises the same detection in both.
TXT

say "creating archives"
( cd dist && tar -czf "$NAME-$VERSION.tar.gz" "$NAME-$VERSION" )
if command -v zip >/dev/null 2>&1; then
  ( cd dist && zip -qr "$NAME-$VERSION.zip" "$NAME-$VERSION" )
else
  say "zip not installed — skipping the Windows-friendly archive"
fi

# ---- 2. Single-file build ------------------------------------------------
# One .js you can scp to a box and run. Same sources, folded together.
node packaging/bundle.js "dist/jedi-$VERSION.js"

# ---- 3. Standalone binary (optional) -------------------------------------
if [ "${1:-}" = "--sea" ]; then
  NODE_MAJOR=$(node -p "process.versions.node.split('.')[0]")
  if [ "$NODE_MAJOR" -lt 20 ]; then
    echo "  --sea needs Node 20 or newer (this is $(node -v))" >&2; exit 1
  fi
  case "$(uname -s)-$(uname -m)" in
    Darwin-arm64)  PLAT=macos-arm64 ;;
    Darwin-x86_64) PLAT=macos-x64 ;;
    Linux-x86_64)  PLAT=linux-x64 ;;
    Linux-aarch64) PLAT=linux-arm64 ;;
    *)             PLAT=$(uname -s | tr 'A-Z' 'a-z')-$(uname -m) ;;
  esac
  BIN="dist/jedi-$VERSION-$PLAT"

  say "building $PLAT binary"
  cp "dist/jedi-$VERSION.js" dist/jedi-sea-entry.js
  node --experimental-sea-config packaging/sea-config.json
  cp "$(command -v node)" "$BIN"

  # A signed binary must have its signature removed before the blob is injected
  # and a new one applied after, or macOS refuses to run it at all.
  [ "$(uname -s)" = "Darwin" ] && codesign --remove-signature "$BIN" || true

  if ! npx --yes postject "$BIN" NODE_SEA_BLOB dist/jedi-sea.blob \
        --sentinel-fuse NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2 \
        ${MACOS_SEGMENT:+--macho-segment-name "$MACOS_SEGMENT"} \
        $([ "$(uname -s)" = "Darwin" ] && echo "--macho-segment-name NODE_SEA") ; then
    echo "  postject failed or is unavailable — the portable archive above is unaffected" >&2
    exit 1
  fi
  [ "$(uname -s)" = "Darwin" ] && codesign --sign - "$BIN" || true
  chmod +x "$BIN"
  say "built $BIN ($(du -h "$BIN" | cut -f1))"
  say "cross-building is not possible here: each platform's binary must be"
  say "built on that platform (or in CI), because it embeds that platform's node"
  rm -f dist/jedi-sea-entry.js dist/jedi-sea.blob
fi

# ---- 4. Checksums --------------------------------------------------------
( cd dist && ls | grep -vE "^($NAME-$VERSION|SHA256SUMS)$" | while read -r f; do
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$f"; else shasum -a 256 "$f"; fi
  done > SHA256SUMS )

echo
say "version $VERSION — the same version the web app reports"
ls -lh dist | sed 's/^/  /'
