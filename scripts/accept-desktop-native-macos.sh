#!/usr/bin/env bash
set -euo pipefail
# Compatibility entry point; the shared runner supports all desktop platforms.
exec node "$(dirname "$0")/accept-desktop-native.mjs"
