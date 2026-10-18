#!/usr/bin/env bash
set -euo pipefail

cargo audit --deny warnings

# These informational advisories are locked transitive dependencies of Tauri's
# current Linux WebKit/GTK shell and URL-pattern parser, and of the zbus 5
# D-Bus stack behind keyring and tauri-plugin-single-instance on Linux.  Keep the list exact so
# a new warning still fails CI.  See docs/DEPENDENCY-RISK.md.
desktop_ignores=(
  RUSTSEC-2024-0370
  RUSTSEC-2024-0411
  RUSTSEC-2024-0412
  RUSTSEC-2024-0413
  RUSTSEC-2024-0414
  RUSTSEC-2024-0415
  RUSTSEC-2024-0416
  RUSTSEC-2024-0417
  RUSTSEC-2024-0418
  RUSTSEC-2024-0419
  RUSTSEC-2024-0420
  RUSTSEC-2024-0429
  RUSTSEC-2025-0075
  RUSTSEC-2025-0080
  RUSTSEC-2025-0081
  RUSTSEC-2025-0098
  RUSTSEC-2025-0100
  RUSTSEC-2026-0370
  RUSTSEC-2026-0371
  RUSTSEC-2026-0372
)
audit_arguments=(--file desktop/src-tauri/Cargo.lock --deny unmaintained --deny unsound)
for advisory in "${desktop_ignores[@]}"; do
  audit_arguments+=(--ignore "$advisory")
done
cargo audit "${audit_arguments[@]}"

# Yanked crates cannot be ignored per advisory, so any yanked desktop
# dependency fails CI.  See docs/DEPENDENCY-RISK.md.
yanked="$(cargo audit "${audit_arguments[@]}" --json 2>/dev/null \
  | jq -r '[.warnings.yanked[]? | "\(.package.name) \(.package.version)"] | sort | join("\n")')"
if [[ -n "$yanked" ]]; then
  printf 'Unexpected yanked desktop dependencies:\n%s\n' "$yanked" >&2
  exit 1
fi
