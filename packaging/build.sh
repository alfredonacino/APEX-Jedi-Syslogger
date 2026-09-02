#!/usr/bin/env bash
# build.sh — produce the distributable artefacts.
#
#   ./packaging/build.sh              portable archives + the single-file build
#   ./packaging/build.sh --deb        also a .deb for Debian/Ubuntu
#   ./packaging/build.sh --rpm        also an .rpm for RHEL/Rocky/Alma/Fedora
#   ./packaging/build.sh --arch       also a .pkg.tar.zst for Arch/CachyOS
#   ./packaging/build.sh --sea        also a standalone binary for THIS platform
#   ./packaging/build.sh --all        everything this host can build
#
# The RPM and Arch packages are produced by their own native tooling, because
# those toolchains do the right thing and a hand-rolled substitute would not.
# Both build from dist/src/, and both need that tooling present on this host:
# rpm-tools for rpmbuild, base-devel for makepkg.
#
# The portable archives need nothing but Node on the target and are what most
# people should use. The --sea build produces an executable with Node baked in
# for machines that have no Node at all; it is the one path here that reaches
# outside the project, because Node's own single-executable feature needs
# `postject` to inject the blob. It stays opt-in for that reason, and the
# application itself keeps zero runtime dependencies either way.
set -euo pipefail

cd "$(dirname "$0")/.."

# Targets are additive: `--deb --rpm --arch` builds three, `--all` builds every
# one this host can. Reading only $1 meant the second flag was silently ignored.
want() {
  for a in "$@"; do :; done
  for given in $BUILD_TARGETS; do
    [ "$given" = "--all" ] && return 0
    [ "$given" = "$1" ] && return 0
  done
  return 1
}
BUILD_TARGETS="${*:-}"
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
# Artefacts from earlier versions, so dist/ only ever holds one release. The
# signer refuses to mix versions anyway; this keeps it from having to.
find dist -maxdepth 1 \( -name 'apex-jedisyslogger*' -o -name 'jedi-*' -o -name 'SHA256SUMS' \) \
  ! -name "*$VERSION*" -exec rm -rf {} + 2>/dev/null || true
rm -rf dist/publish dist/deb dist/src dist/rpm dist/arch

# ---- 1. Portable archive -------------------------------------------------
# The whole application, minus per-install state and build output. It runs as
# the terminal app (bin/jedi) and, if you want the browser UI on that machine,
# as the web app too (node server.js) — one artefact, both faces.
say "staging $NAME-$VERSION"
# packaging/ ships too: the distro manifests build *from this tarball*, so the
# spec, the PKGBUILD and the systemd unit have to be inside it.
for item in jedi-cli.js desktop.js server.js auth.js forward.js updater.js ecosystem.config.js \
            index.html login.html account.html about.html \
            README.md DOCUMENTATION.md CONNECTORS.md LICENSE \
            js css bin samples types packaging jsconfig.json; do
  [ -e "$item" ] && cp -R "$item" "$STAGE/" || true
done
# Never ship per-install state or private key material.
rm -f "$STAGE/auth.json"
rm -rf "$STAGE/certs" "$STAGE/.git" "$STAGE/.claude"

cat > "$STAGE/INSTALL.txt" <<TXT
APEX JediSyslogger $VERSION — portable build

Requires Node.js 18 or newer (https://nodejs.org). Nothing to compile, nothing
to install, no npm.

DESKTOP APP — the normal way to run it

  macOS            open "APEX JediSyslogger.app"
                   (unsigned, so the first launch needs Control-click > Open,
                   or System Settings > Privacy & Security > Open Anyway)
  Linux            ./bin/jedi desktop
  Windows          powershell -ExecutionPolicy Bypass -File .\\packaging\\install.ps1
                   then launch it from the Start Menu

It opens in its own window. There is no URL to type and no sign-in: the backend
binds to 127.0.0.1 on a port it picks itself, and the window is handed a
one-shot ticket for the session. Closing the window stops everything.

The window is rendered by a Chromium-family browser already on the machine
(Chromium, Chrome, Brave or Edge), run in app mode — no address bar, no tabs.
Without one, it falls back to your default browser and says so.

TERMINAL BUILD — same engine, no window

  ./bin/jedi                 live dashboard in the terminal
  ./bin/jedi --help          every command and flag
  Windows: bin\\jedi.cmd

Put it on PATH (optional):
  macOS / Linux    sudo ln -s "\$PWD/bin/jedi" /usr/local/bin/jedi
  Windows          install.ps1 does this for you

SERVER MODE — for a machine other people reach

  node server.js             the web app on a real port, with sign-in

Desktop, terminal and web are one engine at one version ($VERSION): a scenario
raises the same detection in all three.
TXT

# The canonical source tarball lives under dist/src: rpmbuild and makepkg build
# from it, but it is not itself a distribution and must not be published — it
# would be a byte-identical duplicate of the Linux archive.
say "creating archives"
mkdir -p dist/src
( cd dist && tar -czf "src/$NAME-$VERSION.tar.gz" "$NAME-$VERSION" )

# Platform-named copies. The store matches clients on platform, and it does not
# treat "any" as a wildcard — a single archive tagged "any" is invisible to a
# client that says it is darwin/arm64. Same bytes, honest labels.
cp "dist/src/$NAME-$VERSION.tar.gz" "dist/$NAME-$VERSION-linux.tar.gz"

# macOS gets the same payload plus a real .app bundle, so it is launched from
# Finder or the Dock like any other application rather than from a shell.
./packaging/build-macapp.sh "$STAGE"
( cd dist && tar -czf "$NAME-$VERSION-macos.tar.gz" "$NAME-$VERSION" )
rm -rf "$STAGE/APEX JediSyslogger.app"
if command -v zip >/dev/null 2>&1; then
  ( cd dist && zip -qr "$NAME-$VERSION-windows.zip" "$NAME-$VERSION" )
else
  say "zip not installed — skipping the Windows archive"
fi

# ---- 2. Single-file build ------------------------------------------------
# One .js you can scp to a box and run. Same sources, folded together.
node packaging/bundle.js "dist/jedi-$VERSION.js"

# ---- 3. Native packages (optional) ---------------------------------------
if want --deb; then
  ./packaging/build-deb.sh
fi
if want --rpm; then
  ./packaging/build-rpm.sh || say "RPM build failed — the other artefacts are unaffected"
fi
if want --arch; then
  ./packaging/build-arch.sh || say "Arch/CachyOS build failed — the other artefacts are unaffected"
fi

# ---- 4. Standalone binary (optional) -------------------------------------
if want --sea; then
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

# ---- 5. Checksums --------------------------------------------------------
( cd dist && find . -maxdepth 1 -type f ! -name SHA256SUMS -printf '%P\n' | sort | while read -r f; do
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$f"; else shasum -a 256 "$f"; fi
  done > SHA256SUMS )

echo
say "version $VERSION — the same version the web app reports"
find dist -maxdepth 1 -type f -printf '  %-46f %s bytes\n' | sort
