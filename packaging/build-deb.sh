#!/usr/bin/env bash
# build-deb.sh — a .deb for Debian, Ubuntu, Mint, Raspberry Pi OS.
#
#   ./packaging/build-deb.sh
#
# Deliberately does not need dpkg-dev. A .deb is an `ar` archive of three
# members in a fixed order — debian-binary, control.tar.gz, data.tar.gz — so
# `ar` and `tar` are enough, and the package can be built from a machine that
# is not Debian (this project is developed on Arch). dpkg-deb is used instead
# when it happens to be installed, because it also runs its own sanity checks.
set -euo pipefail
cd "$(dirname "$0")/.."

./packaging/version.sh --check
VERSION=$(node -p "require('./js/version.js').VERSION")
NAME=apex-jedisyslogger
ARCH=all                      # pure JavaScript: one package for every CPU
BUILD="dist/deb/$NAME-$VERSION"
OUT="dist/${NAME}_${VERSION}_${ARCH}.deb"

command -v ar >/dev/null 2>&1 || { echo "build-deb: 'ar' is required (binutils)" >&2; exit 1; }

rm -rf "$BUILD"
mkdir -p "$BUILD/DEBIAN" \
         "$BUILD/usr/share/$NAME" \
         "$BUILD/usr/bin" \
         "$BUILD/lib/systemd/system" \
         "$BUILD/usr/share/doc/$NAME"

# ---- payload -------------------------------------------------------------
for item in jedi-cli.js desktop.js forward.js updater.js server.js auth.js ecosystem.config.js \
            index.html login.html account.html about.html \
            js css bin samples types; do
  cp -R "$item" "$BUILD/usr/share/$NAME/"
done
rm -f "$BUILD/usr/share/$NAME/auth.json"
rm -rf "$BUILD/usr/share/$NAME/certs"

install -m0755 bin/jedi "$BUILD/usr/bin/jedi"

# Desktop integration: a menu entry and its icons, so this is an application in
# the launcher rather than a command you have to know about.
install -Dm0644 packaging/apex-jedisyslogger.desktop \
  "$BUILD/usr/share/applications/$NAME.desktop"
for s in 16 32 48 64 128 256 512; do
  install -Dm0644 "packaging/icons/$NAME-$s.png" \
    "$BUILD/usr/share/icons/hicolor/${s}x${s}/apps/$NAME.png"
done
install -m0644 packaging/apex-jedisyslogger.service "$BUILD/lib/systemd/system/$NAME.service"
for doc in README.md DOCUMENTATION.md CONNECTORS.md; do install -m0644 "$doc" "$BUILD/usr/share/doc/$NAME/"; done
gzip -9n -c > "$BUILD/usr/share/doc/$NAME/changelog.Debian.gz" <<CHANGELOG
$NAME ($VERSION-1) unstable; urgency=low

  * Release $VERSION. See /usr/share/doc/$NAME/README.md.

 -- Alfredo Nacino <alfredo@nacino.net>  $(date -R)
CHANGELOG

INSTALLED_KB=$(du -sk "$BUILD" | cut -f1)

cat > "$BUILD/DEBIAN/control" <<CONTROL
Package: $NAME
Version: $VERSION-1
Section: net
Priority: optional
Architecture: $ARCH
Depends: nodejs (>= 18)
Recommends: systemd
Installed-Size: $INSTALLED_KB
Maintainer: Alfredo Nacino <alfredo@nacino.net>
Homepage: https://github.com/alfredonacino/APEX-Jedi-Syslogger
Description: SIEM log-ingestion simulator with a terminal dashboard
 A synthetic log source and a miniature SIEM in one tool, for detection
 engineering practice. Generates RFC 3164/5424 syslog plus 42 appliance
 formats (Palo Alto, FortiGate, Cisco, Sysmon, CloudTrail, Microsoft 365,
 Entra ID, Defender for Endpoint and more), injects 72 MITRE ATT&CK-tagged
 attack scenarios, and runs a stateful detection-rule engine over the result.
 .
 Forwards live to a real collector over UDP, TCP or Splunk HEC. The terminal
 dashboard needs no browser; the same tree also serves an optional web UI.
 .
 All generated traffic is synthetic. Nothing is collected from the host.
CONTROL

# md5sums lets `debsums` verify an installed copy. Paths are relative to /.
( cd "$BUILD" && find usr lib -type f -print0 | sort -z | xargs -0 md5sum | sed 's| | |' > DEBIAN/md5sums )

# The service is not started on install: this generates network traffic, and a
# package must never begin doing that on its own.
cat > "$BUILD/DEBIAN/postinst" <<'POSTINST'
#!/bin/sh
set -e
if [ "$1" = "configure" ]; then
  if command -v systemctl >/dev/null 2>&1; then systemctl daemon-reload || true; fi
  # Menus and icon caches are indexed, not scanned.
  if command -v update-desktop-database >/dev/null 2>&1; then update-desktop-database -q /usr/share/applications || true; fi
  if command -v gtk-update-icon-cache >/dev/null 2>&1; then gtk-update-icon-cache -qtf /usr/share/icons/hicolor || true; fi
  echo "apex-jedisyslogger: launch 'APEX JediSyslogger' from your applications menu,"
  echo "  or run 'jedi desktop' for the window, 'jedi' for the terminal dashboard."
  echo "  The forwarding service is installed but NOT started: it generates synthetic"
  echo "  log traffic, so enable it deliberately after setting JEDI_TARGET:"
  echo "    sudo systemctl edit apex-jedisyslogger && sudo systemctl enable --now apex-jedisyslogger"
fi
exit 0
POSTINST
cat > "$BUILD/DEBIAN/prerm" <<'PRERM'
#!/bin/sh
set -e
if [ "$1" = "remove" ] && command -v systemctl >/dev/null 2>&1; then
  systemctl stop apex-jedisyslogger.service >/dev/null 2>&1 || true
  systemctl disable apex-jedisyslogger.service >/dev/null 2>&1 || true
fi
exit 0
PRERM
chmod 0755 "$BUILD/DEBIAN/postinst" "$BUILD/DEBIAN/prerm"

# ---- assemble ------------------------------------------------------------
if command -v dpkg-deb >/dev/null 2>&1; then
  dpkg-deb --root-owner-group --build "$BUILD" "$OUT" >/dev/null
else
  # Member order is part of the format, and `ar` must not add its symbol table.
  TMP=$(mktemp -d)
  printf '2.0\n' > "$TMP/debian-binary"
  tar -czf "$TMP/control.tar.gz" --owner=0 --group=0 --numeric-owner -C "$BUILD/DEBIAN" .
  tar -czf "$TMP/data.tar.gz"    --owner=0 --group=0 --numeric-owner -C "$BUILD" --exclude=./DEBIAN .
  rm -f "$OUT"
  ( cd "$TMP" && ar rcD "$OLDPWD/$OUT" debian-binary control.tar.gz data.tar.gz )
  rm -rf "$TMP"
fi

echo "  built $OUT ($(du -h "$OUT" | cut -f1))"
echo "  install with:  sudo apt install ./$(basename "$OUT")"
