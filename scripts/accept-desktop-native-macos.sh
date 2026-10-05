#!/usr/bin/env bash
set -euo pipefail

if [ "$(uname -s)" != Darwin ]; then
  echo "Native desktop lifecycle acceptance currently requires macOS." >&2
  exit 2
fi
cd "$(dirname "$0")/.."
host_target="$(rustc -vV | awk '/^host:/ { print $2 }')"
cargo build --locked -p wildbloomd --bin wildbloomd --example acceptance_signer
mkdir -p desktop/src-tauri/binaries
cp target/debug/wildbloomd "desktop/src-tauri/binaries/wildbloomd-$host_target"
cargo build --locked --manifest-path desktop/src-tauri/Cargo.toml --features native-acceptance
node desktop/tests/native-pools.mjs
