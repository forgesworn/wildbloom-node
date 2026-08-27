#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <linux-x86_64|macos-aarch64|macos-x86_64|windows-x86_64> <destination>" >&2
  exit 64
fi

platform="$1"
destination="$2"
version="${TOR_EXPERT_BUNDLE_VERSION:-15.0.20}"
fingerprint="EF6E286DDA85EA2A4BA7DE684E2C6E8793298290"

case "$platform" in
  linux-x86_64|macos-aarch64|macos-x86_64|windows-x86_64) ;;
  *)
    echo "unsupported Tor Expert Bundle platform: $platform" >&2
    exit 64
    ;;
esac

if [ -e "$destination/tor" ] || [ -e "$destination/data" ]; then
  echo "destination already contains a Tor runtime: $destination" >&2
  exit 65
fi

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/wildbloom-tor.XXXXXX")"
trap 'rm -rf -- "$work_dir"' EXIT
archive="tor-expert-bundle-${platform}-${version}.tar.gz"
base_url="https://dist.torproject.org/torbrowser/${version}"

mkdir -p "$destination"
download() {
  curl --proto '=https' --tlsv1.2 --location --fail --silent --show-error \
    --retry 10 --retry-all-errors --retry-delay 2 "$1" --output "$2"
}

download "$base_url/$archive" "$work_dir/$archive"
download "$base_url/$archive.asc" "$work_dir/$archive.asc"
download "https://keys.openpgp.org/vks/v1/by-fingerprint/$fingerprint" \
  "$work_dir/tor-browser-developers.asc"

actual_fingerprint="$(
  gpg --batch --show-keys --with-colons "$work_dir/tor-browser-developers.asc" \
    | awk -F: '$1 == "fpr" { print $10; exit }'
)"
if [ "$actual_fingerprint" != "$fingerprint" ]; then
  echo "Tor signing key fingerprint did not match the pinned value" >&2
  exit 66
fi

# GnuPG 2.5 enables keyboxd by default and ignores --keyring during imports.
# gpgv accepts a dearmoured OpenPGP keyring directly, which also keeps this
# verification isolated from the runner's user keyring.
gpg --batch --yes --dearmor \
  --output "$work_dir/tor-browser-keyring.gpg" \
  "$work_dir/tor-browser-developers.asc"
gpgv --keyring "$work_dir/tor-browser-keyring.gpg" \
  "$work_dir/$archive.asc" "$work_dir/$archive"

tar -xzf "$work_dir/$archive" -C "$destination"
test -f "$destination/data/geoip"
test -f "$destination/data/geoip6"
if [ "$platform" = "windows-x86_64" ]; then
  test -f "$destination/tor/tor.exe"
else
  test -x "$destination/tor/tor"
fi

if command -v sha256sum >/dev/null 2>&1; then
  digest="$(sha256sum "$work_dir/$archive" | awk '{print $1}')"
else
  digest="$(shasum -a 256 "$work_dir/$archive" | awk '{print $1}')"
fi
printf 'Tor Expert Bundle %s\narchive=%s\nsha256=%s\nsigning-key=%s\n' \
  "$version" "$archive" "$digest" "$fingerprint" \
  > "$destination/WILDBLOOM-TOR-PROVENANCE.txt"
