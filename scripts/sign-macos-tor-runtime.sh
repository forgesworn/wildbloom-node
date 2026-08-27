#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <signing-identity-or-dash> <tor-runtime>" >&2
  exit 64
fi
if [ "$(uname -s)" != "Darwin" ]; then
  echo "macOS Tor runtime signing must run on macOS" >&2
  exit 65
fi

identity="$1"
runtime="$2"
tor="$runtime/tor/tor"
test -x "$tor"

sign() {
  if [ "$identity" = "-" ]; then
    codesign --force --sign - "$1"
  else
    codesign --force --options runtime --timestamp --sign "$identity" "$1"
  fi
  codesign --verify --strict --verbose=2 "$1"
}

while IFS= read -r candidate; do
  if file "$candidate" | grep -q 'Mach-O'; then
    sign "$candidate"
  fi
done < <(find "$runtime/tor" -maxdepth 1 -type f ! -name tor -print | sort)
sign "$tor"
"$tor" --version >/dev/null
