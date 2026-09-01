#!/usr/bin/env bash
# version.sh — one version, everywhere.
#
#   packaging/version.sh              print the version
#   packaging/version.sh --check      verify every file agrees (exit 1 if not)
#   packaging/version.sh --set 1.1.0  stamp a new version into all of them
#
# js/version.js is the source of truth: the web dashboard, the terminal build
# and the server banner all read it at runtime. The packaging files cannot —
# a PKGBUILD is not JavaScript — so they carry a copy, and this script is what
# stops the copy from drifting. `build.sh` runs --check before it packages
# anything, so a mismatched version cannot be released.
set -euo pipefail
cd "$(dirname "$0")/.."

SRC=js/version.js
current() { node -p "require('./$SRC').VERSION"; }

# file:regex pairs — the regex must capture the version in group 1.
targets() {
  cat <<'T'
packaging/PKGBUILD|^pkgver=(.+)$
packaging/apex-jedisyslogger.spec|^Version:[[:space:]]+(.+)$
packaging/apex-jedisyslogger.rb|^  version "(.+)"$
T
}

case "${1:-}" in
  --set)
    NEW=${2:-}
    [[ $NEW =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "version.sh: --set wants X.Y.Z" >&2; exit 2; }
    OLD=$(current)
    TODAY=$(date +%Y-%m-%d)
    node -e "
      const fs=require('fs'); let s=fs.readFileSync('$SRC','utf8');
      s=s.replace(/VERSION: '[^']+'/, \"VERSION: '$NEW'\").replace(/RELEASED: '[^']+'/, \"RELEASED: '$TODAY'\");
      fs.writeFileSync('$SRC',s);"
    sed -i.bak -E "s/^pkgver=.*/pkgver=$NEW/" packaging/PKGBUILD
    sed -i.bak -E "s/^Version:([[:space:]]+).*/Version:\1$NEW/" packaging/apex-jedisyslogger.spec
    sed -i.bak -E "s/^  version \".*\"/  version \"$NEW\"/" packaging/apex-jedisyslogger.rb
    sed -i.bak -E "s|/v[0-9]+\.[0-9]+\.[0-9]+/apex-jedisyslogger-[0-9]+\.[0-9]+\.[0-9]+\.tar\.gz|/v$NEW/apex-jedisyslogger-$NEW.tar.gz|" packaging/apex-jedisyslogger.rb
    rm -f packaging/*.bak
    echo "$OLD → $NEW  (web app, terminal build and packages)"
    echo "next:  git commit -am \"Release v$NEW\" && git tag -a v$NEW -m \"v$NEW\" && git push --follow-tags"
    ;;
  --check|"")
    V=$(current)
    bad=0
    while IFS='|' read -r file re; do
      [ -f "$file" ] || continue
      found=$(grep -E "$re" "$file" | head -1 | sed -E "s/$re/\1/" | tr -d '"' | xargs)
      if [ "$found" != "$V" ]; then
        echo "version mismatch: $file says '$found', $SRC says '$V'" >&2
        bad=1
      fi
    done < <(targets)
    [ "${1:-}" = "--check" ] && { [ $bad -eq 0 ] && echo "version $V — web app, terminal build and packages agree"; exit $bad; }
    echo "$V"
    ;;
  *) echo "usage: version.sh [--check | --set X.Y.Z]" >&2; exit 2 ;;
esac
