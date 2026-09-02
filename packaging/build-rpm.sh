#!/usr/bin/env bash
# build-rpm.sh — an .rpm for RHEL, Rocky, Alma, CentOS Stream and Fedora.
#
# Builds from dist/src/, into a private rpmbuild tree under dist/rpm so nothing
# is written to ~/rpmbuild. Needs rpm-tools (rpmbuild); it is not Red Hat that
# is required, only the tool — this is built on CachyOS.
set -euo pipefail
cd "$(dirname "$0")/.."

command -v rpmbuild >/dev/null 2>&1 || { echo "build-rpm: rpmbuild not found (install rpm-tools)" >&2; exit 1; }
./packaging/version.sh --check
VERSION=$(node -p "require('./js/version.js').VERSION")
NAME=apex-jedisyslogger
SRC="dist/src/$NAME-$VERSION.tar.gz"
[ -f "$SRC" ] || { echo "build-rpm: $SRC missing — run ./packaging/build.sh first" >&2; exit 1; }

TOP=$PWD/dist/rpm
rm -rf "$TOP"
mkdir -p "$TOP"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}
cp "$SRC" "$TOP/SOURCES/"
cp packaging/$NAME.spec "$TOP/SPECS/"

rpmbuild --define "_topdir $TOP" -bb "$TOP/SPECS/$NAME.spec" >"$TOP/build.log" 2>&1 || {
  echo "build-rpm: rpmbuild failed — last lines:" >&2; tail -20 "$TOP/build.log" >&2; exit 1; }

BUILT=$(find "$TOP/RPMS" -name "*.rpm" | head -1)
[ -n "$BUILT" ] || { echo "build-rpm: rpmbuild produced no package" >&2; exit 1; }
cp "$BUILT" "dist/$(basename "$BUILT")"
echo "  built dist/$(basename "$BUILT") ($(du -h "$BUILT" | cut -f1))"
echo "  install with:  sudo dnf install ./$(basename "$BUILT")"
