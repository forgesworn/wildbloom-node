#!/usr/bin/env bash
set -euo pipefail

# webpki-roots 0.26.11 is a semver shim that re-exports webpki-roots 1.x, so
# it carries whichever 1.x is locked.  RUSTSEC-2026-0381 flags the shim by its
# version number.  Ignore that advisory only while every locked webpki-roots
# is the shim or a fixed 1.x.  See docs/DEPENDENCY-RISK.md.
check_webpki_roots() {
  local lock="$1" bad
  bad="$(awk '/^name = "webpki-roots"$/ { getline; gsub(/^version = "|"$/, ""); print }' "$lock" \
    | while read -r version; do
        case "$version" in
          (0.26.11) ;;
          (1.*) [[ "$(printf '%s\n1.0.10\n' "$version" | sort -V | head -n 1)" == 1.0.10 ]] || echo "$version" ;;
          (*) echo "$version" ;;
        esac
      done)"
  if [[ -n "$bad" ]]; then
    printf 'webpki-roots in %s is neither the 0.26.11 shim nor 1.0.10 or later:\n%s\n' "$lock" "$bad" >&2
    exit 1
  fi
}
check_webpki_roots Cargo.lock
check_webpki_roots desktop/src-tauri/Cargo.lock

cargo audit --deny warnings --ignore RUSTSEC-2026-0381

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
audit_arguments=(--file desktop/src-tauri/Cargo.lock --deny unmaintained --deny unsound --ignore RUSTSEC-2026-0381)
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
