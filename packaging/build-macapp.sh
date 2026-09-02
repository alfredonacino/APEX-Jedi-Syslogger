#!/usr/bin/env bash
# build-macapp.sh — assemble the macOS .app bundle.
#
#   ./packaging/build-macapp.sh <destination-dir>
#
# A .app is a directory with a fixed layout, so it can be assembled anywhere —
# this one is built on Linux. What cannot be done off a Mac is signing and
# notarising it, so the bundle is unsigned: Gatekeeper will ask the user to
# confirm the first launch. That is stated in INSTALL.txt rather than papered
# over.
set -euo pipefail
cd "$(dirname "$0")/.."

DEST=${1:?usage: build-macapp.sh <destination-dir>}
VERSION=$(node -p "require('./js/version.js').VERSION")
APP="$DEST/APEX JediSyslogger.app"

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp packaging/icons/apex-jedisyslogger.icns "$APP/Contents/Resources/"

cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key>              <string>APEX JediSyslogger</string>
  <key>CFBundleDisplayName</key>       <string>APEX JediSyslogger</string>
  <key>CFBundleIdentifier</key>        <string>tech.cybercontrol.apex.jedisyslogger</string>
  <key>CFBundleVersion</key>           <string>$VERSION</string>
  <key>CFBundleShortVersionString</key><string>$VERSION</string>
  <key>CFBundleExecutable</key>        <string>apex-jedisyslogger</string>
  <key>CFBundleIconFile</key>          <string>apex-jedisyslogger.icns</string>
  <key>CFBundlePackageType</key>       <string>APPL</string>
  <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
  <key>LSMinimumSystemVersion</key>    <string>11.0</string>
  <key>LSApplicationCategoryType</key> <string>public.app-category.developer-tools</string>
  <key>NSHighResolutionCapable</key>   <true/>
  <!-- Nothing here is a background agent: closing the window ends the process. -->
  <key>LSUIElement</key>               <false/>
</dict>
</plist>
PLIST

cat > "$APP/Contents/MacOS/apex-jedisyslogger" <<'LAUNCH'
#!/bin/sh
# Bundle launcher. The payload sits beside the .app inside the unpacked archive,
# so resolve up out of Contents/MacOS rather than assuming an install location.
set -e
here=$(cd -- "$(dirname -- "$0")" && pwd)
app_root=$(cd -- "$here/../../.." && pwd)

if [ ! -f "$app_root/desktop.js" ]; then
  osascript -e 'display alert "APEX JediSyslogger" message "The application files are missing. Keep the .app inside the folder it was unpacked in."' 2>/dev/null || true
  exit 1
fi

node=${JEDI_NODE:-node}
if ! command -v "$node" >/dev/null 2>&1; then
  # Homebrew installs land outside the GUI session's PATH; look before giving up.
  for candidate in /opt/homebrew/bin/node /usr/local/bin/node; do
    [ -x "$candidate" ] && node=$candidate && break
  done
fi
if ! command -v "$node" >/dev/null 2>&1 && [ ! -x "$node" ]; then
  osascript -e 'display alert "APEX JediSyslogger" message "Node.js 18 or newer is required.\n\nInstall it from nodejs.org or with: brew install node"' 2>/dev/null || true
  exit 1
fi

exec "$node" "$app_root/desktop.js"
LAUNCH
chmod +x "$APP/Contents/MacOS/apex-jedisyslogger"
echo "  built $(basename "$APP") ($(du -sh "$APP" | cut -f1))"
