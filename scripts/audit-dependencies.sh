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

# RUSTSEC-2026-0543 reports maintenance status, not a vulnerability. Keep the
# temporary exception confined to the reviewed toll-booth dependency. A new
# direct consumer, chrono version or toll-booth revision requires another review.
chrono_tree="$(cargo tree --locked --invert chrono --depth 1 --prefix none --format '{p}')"
expected_chrono=$'chrono v0.4.45\ntoll-booth v0.2.1 (https://github.com/forgesworn/toll-booth-rs?rev=acd8b1495b4033fcbf3156b9f32d70fcabec74fa#acd8b149)'
if [[ "$chrono_tree" != "$expected_chrono" ]]; then
  echo 'chrono maintenance exception no longer matches the reviewed dependency; see docs/DEPENDENCY-RISK.md' >&2
  exit 1
fi
cargo audit --deny warnings --ignore RUSTSEC-2026-0381 --ignore RUSTSEC-2026-0543

# Cargo locks serde_with's optional Chrono support even though Tauri does not
# enable it. Bound this maintenance exception to the exact locked consumer;
# do not extend it to an added user of Chrono.
python3 - <<'PY'
import tomllib
with open("desktop/src-tauri/Cargo.lock", "rb") as lock:
    packages = tomllib.load(lock)["package"]
chrono = [(p["name"], p["version"]) for p in packages if p["name"] == "chrono"]
users = [(p["name"], p["version"]) for p in packages
         if any(d.split()[0] == "chrono" for d in p.get("dependencies", []))]
if chrono != [("chrono", "0.4.45")] or users != [("serde_with", "3.22.0")]:
    raise SystemExit("desktop Chrono maintenance exception changed; see docs/DEPENDENCY-RISK.md")
PY

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
audit_arguments=(--file desktop/src-tauri/Cargo.lock --deny unmaintained --deny unsound --ignore RUSTSEC-2026-0381 --ignore RUSTSEC-2026-0543)
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
