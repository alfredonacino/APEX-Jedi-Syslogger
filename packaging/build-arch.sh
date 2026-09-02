#!/usr/bin/env bash
# build-arch.sh — a pacman package for Arch, CachyOS, Manjaro, EndeavourOS.
#
# One package serves all of them: they share pacman and this is arch=any, so
# there is nothing CachyOS-specific to do. Needs makepkg (base-devel), which
# means it must be built on an Arch-family host.
set -euo pipefail
cd "$(dirname "$0")/.."

command -v makepkg >/dev/null 2>&1 || { echo "build-arch: makepkg not found — build this on an Arch-family host" >&2; exit 1; }
[ "$(id -u)" -ne 0 ] || { echo "build-arch: makepkg refuses to run as root" >&2; exit 1; }
./packaging/version.sh --check
VERSION=$(node -p "require('./js/version.js').VERSION")
NAME=apex-jedisyslogger
SRC="dist/src/$NAME-$VERSION.tar.gz"
[ -f "$SRC" ] || { echo "build-arch: $SRC missing — run ./packaging/build.sh first" >&2; exit 1; }

WORK=$PWD/dist/arch
rm -rf "$WORK"; mkdir -p "$WORK"
cp packaging/PKGBUILD "$WORK/"
cp "$SRC" "$WORK/"

( cd "$WORK" && makepkg -f --nodeps --noconfirm >makepkg.log 2>&1 ) || {
  echo "build-arch: makepkg failed — last lines:" >&2; tail -20 "$WORK/makepkg.log" >&2; exit 1; }

BUILT=$(find "$WORK" -maxdepth 1 -name "*.pkg.tar.*" | head -1)
[ -n "$BUILT" ] || { echo "build-arch: makepkg produced no package" >&2; exit 1; }
cp "$BUILT" "dist/$(basename "$BUILT")"
echo "  built dist/$(basename "$BUILT") ($(du -h "$BUILT" | cut -f1))"
echo "  install with:  sudo pacman -U ./$(basename "$BUILT")"
