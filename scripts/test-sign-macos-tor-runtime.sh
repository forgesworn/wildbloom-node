#!/usr/bin/env bash
set -euo pipefail

# Exercise real Mach-O signing, including nested helper names with spaces.
# No Developer ID certificate or network access is needed for this regression.
test "$(uname -s)" = Darwin
script_dir="$(cd "$(dirname "$0")" && pwd)"
fixture="$(mktemp -d "${TMPDIR:-/tmp}/wildbloom-signing-test.XXXXXX")"
trap 'rm -rf -- "$fixture"' EXIT
mkdir -p "$fixture/tor/pluggable_transports"
printf '%s\n' 'int main(void) { return 0; }' > "$fixture/synthetic.c"
clang "$fixture/synthetic.c" -o "$fixture/tor/tor"
cp "$fixture/tor/tor" "$fixture/tor/pluggable_transports/synthetic helper"
printf '%s\n' 'synthetic non-executable resource' > "$fixture/tor/README.txt"
codesign --remove-signature "$fixture/tor/tor"
codesign --remove-signature "$fixture/tor/pluggable_transports/synthetic helper"
if codesign --verify "$fixture/tor/pluggable_transports/synthetic helper" 2>/dev/null; then
  echo 'fixture unexpectedly signed before the test' >&2
  exit 1
fi
bash "$script_dir/sign-macos-tor-runtime.sh" - "$fixture"
codesign --verify --strict "$fixture/tor/tor"
codesign --verify --strict "$fixture/tor/pluggable_transports/synthetic helper"
test "$(cat "$fixture/tor/README.txt")" = 'synthetic non-executable resource'
echo 'PASS: nested Mach-O transport helper signed; ordinary resource unchanged'
