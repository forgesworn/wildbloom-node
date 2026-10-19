#!/usr/bin/env bash
# Hosted macOS 15 runners lose many HTTP/3 (QUIC over UDP) requests to
# Apple's CloudKit ticket service: `stapler validate` and `stapler staple`
# then fail with exit 68 after about 7 seconds ("The network connection was
# lost"). The same lookups over TCP are reliable, and macOS 26 runners are
# unaffected. Refusing outbound UDP 443 to Apple's network (17.0.0.0/8) makes
# the system use TCP at once.
#
# For disposable CI runners only: this replaces the packet filter rules.
set -euo pipefail

if [ "${CI:-}" != "true" ]; then
  echo "refusing to change the packet filter outside CI" >&2
  exit 64
fi
if [ "$(uname -s)" != "Darwin" ]; then
  echo "only needed on macOS runners" >&2
  exit 65
fi

rule='block return out quick proto udp from any to 17.0.0.0/8 port 443'
if ! output=$(printf '%s\npass all\n' "$rule" | sudo pfctl -f - 2>&1); then
  echo "$output" >&2
  exit 1
fi
# Already enabled is fine; the checks below decide.
sudo pfctl -e >/dev/null 2>&1 || true
if ! sudo pfctl -s info 2>/dev/null | grep -q 'Status: Enabled'; then
  echo "the packet filter did not enable" >&2
  exit 1
fi
# Compare with the rule as pf itself prints it (it adds `inet`, `port =`).
expected=$(printf '%s\n' "$rule" | pfctl -nvf - 2>/dev/null | grep '^block')
if [ -z "$expected" ] || ! sudo pfctl -s rules 2>/dev/null | grep -qxF "$expected"; then
  echo "the UDP 443 rule is not loaded" >&2
  exit 1
fi
echo "Apple ticket lookups now use TCP"
