# Wildbloom Node

Run your own Blossom storage at home without opening a router port.

Wildbloom Node is a small, cross-platform Blossom server.  It stores blobs on
your disk by SHA-256, accepts only tightly scoped Nostr authorisation, and makes
the server reachable through a persistent Tor v3 onion.  It does not use
WebRTC, STUN or TURN.

This is a production candidate, not a durability promise.  The headless node
targets macOS, Linux and Windows.  The native tray application bundles a
signature-verified Tor Expert Bundle, creates the onion service and starts the
node without asking the user to open a router port.  Unsigned preview installers
are built separately from production releases; we will not label them as trusted
downloads until the platform signing and clean-machine acceptance gates pass.

## Why this exists

Blossom gives Nostr applications a sensible content-addressed storage protocol,
but using somebody else's server is still using somebody else's disk.  They can
lose it, remove it or stop paying the bill.  Wildbloom Node makes a user's own
machine a standard Blossom server and lets another authorised node copy the
blob through BUD-04.

It is not a torrent client.  Every replica currently stores a complete blob and
serves it over ordinary Blossom HTTP.  Nostr can carry private storage offers
and replication intent; Tor carries the bytes.  A separate QUIC and opaque-relay
lane is a future spike, not part of the durability claim.  RelaySwarm's WebRTC
session remains for live browser media rather than storage.

## What works

- BUD-01 `GET` and `HEAD`, optional file extensions and single byte ranges.
- BUD-02 streaming `PUT /upload` with `Content-Length` and `X-SHA-256`.
- BUD-04 `PUT /mirror` from hash-addressed onion or public HTTPS origins through
  the node's private Tor SOCKS listener.
- BUD-06 authorised upload preflight with quota and per-blob checks.
- Strict BUD-11 kind `24242` signature, operation, hash, server and expiry
  checks.
- Authenticated, self-only BUD-12 listing with bounded cursor pagination, plus
  claim-aware deletion.  One signer cannot list or delete another signer's
  claims.
- Persistent SQLite metadata and a disk content-addressed store.
- Pre-stream global quota reservation, per-blob limits, deduplication and
  interrupted-upload cleanup.
- Deny-by-default writes, bounded concurrent streams, complete integrity scans
  and repair from previously verified mirror sources.
- Claim-aware owner, friend and guest retention over one deduplicated CAS.
  Friends have expiring per-key byte ceilings; signed guest mirrors use only
  spare capacity and are evicted first.
- Opaque attachment serving for friend-only and guest-only blobs, including
  `nosniff`; conflicting owner MIME claims also fail opaque.
- Crash reconciliation restores indexed tombstones and removes unindexed files
  left by interrupted file/database transactions.
- Loopback-only binding by default and a persistent Tor v3 onion identity.
- Native Rust and Tauri compile CI configured for macOS, Linux and Windows.
- A native Tauri tray shell with platform data directories, start-at-login,
  storage status and no private-key input.
- Installed `.deb` and NSIS preview acceptance on fresh hosted Linux and Windows
  runners, including Tor bootstrap, Blossom health, single-instance behaviour,
  child cleanup and uninstall.

There is no proof-of-storage protocol, paid quota or automatic discovery of
strangers willing to hold data.  Repair can restore a damaged local copy only
when the node already recorded a verified source which is still online.  Those
boundaries are documented in the [roadmap](docs/ROADMAP.md).

The [storage priority contract](docs/STORAGE-POLICY.md) defines the exact
admission and eviction promises.  The implementation and adversarial local
tests are present; cross-platform CI and the independent V4V recovery journey
remain release evidence rather than assumptions.

## Install and run

The desktop application is the intended consumer install.  Until signed
installers are published, build it only from a revision you have reviewed.

### Build the desktop preview from source

Install Rust 1.94.1, the platform's normal Tauri 2 build prerequisites, GnuPG
and the Tauri CLI.  Choose the matching target and Tor bundle name:

| System | Rust target | Tor bundle name |
| --- | --- | --- |
| Windows x64 | `x86_64-pc-windows-msvc` | `windows-x86_64` |
| Linux x64 | `x86_64-unknown-linux-gnu` | `linux-x86_64` |
| macOS Apple Silicon | `aarch64-apple-darwin` | `macos-aarch64` |
| macOS Intel | `x86_64-apple-darwin` | `macos-x86_64` |

From a fresh clone, replace the two values below with that row:

```sh
cargo install tauri-cli --version 2.11.4 --locked
scripts/prepare-tor-runtime.sh <tor-bundle-name> desktop/src-tauri/tor-runtime
cargo build --locked --release --target <rust-target> -p wildbloomd
cp target/<rust-target>/release/wildbloomd desktop/src-tauri/binaries/wildbloomd-<rust-target>
# On macOS only: scripts/sign-macos-tor-runtime.sh - desktop/src-tauri/tor-runtime
cd desktop/src-tauri
cargo tauri build --target <rust-target>
```

On Windows, both daemon paths end in `.exe`.  This produces an explicitly
unsigned preview.  The verified Tor runtime is bundled as a complete resource,
not fetched on first start.  Production signing and updater artefacts are made
only by the fail-closed release workflow described in [the release process](docs/RELEASE.md).
Linux desktop releases use native `.deb` and `.rpm` packages; the headless
daemon can be built as an ordinary binary on other Linux distributions.  Both
packages have detached release signatures; Linux updates are explicit package
installs rather than an AppImage replacement dressed up as an auto-update.

### Run the headless service

The headless path needs [Rust](https://www.rust-lang.org/tools/install) 1.94.1
or later and a current [Tor Expert Bundle](https://www.torproject.org/download/tor/),
with the `tor` executable on `PATH`.

```sh
git clone https://github.com/forgesworn/wildbloom-node.git
cd wildbloom-node
cargo build --release
./target/release/wildbloomd --allow-pubkey <64-lower-case-hex-public-key>
```

The first Tor bootstrap can take several minutes and has a fifteen-minute
allowance; later starts reuse its private directory cache.  Once ready, the log
prints the stable `.onion` Blossom URL.  Add that URL to a Blossom-capable client.  The
node stores data in the operating system's per-user application-data directory
unless `--data-dir` or `WILDBLOOM_DATA_DIR` says otherwise.  Without an owner,
friend grant or explicit open-shelter policy it remains read-only.

For local development without Tor, keep the same explicit owner authority:

```sh
cargo run -p wildbloomd -- --no-tor --allow-pubkey <64-lower-case-hex-public-key>
```

Useful controls:

```text
--quota-bytes <BYTES>          total stored blob quota, default 10 GiB
--max-blob-bytes <BYTES>       maximum single blob, default 1 GiB
--allow-pubkey <HEX>           owner public key, repeatable
--friend-grant <P:L:E>         friend pubkey, byte limit and Unix expiry
--open-shelter                 admit unknown signed mirrors as guest data
--max-concurrent-writes <N>    concurrent upload/mirror limit, default 4
--repair-interval <SECONDS>    integrity and repair interval, default 3600
--verify-storage               verify every stored byte and exit
--bind <IP:PORT>               local listener, default 127.0.0.1:3742
--tor-bin <PATH>               Tor executable, default tor
--no-tor                       local-only development mode
```

Do not put the local listener on the public internet merely because the flag
exists.  If a conventional HTTPS reverse proxy is genuinely required, read the
[threat model](docs/THREAT-MODEL.md) first.

## How applications use it

Applications use the onion URL exactly as they use another Blossom server:

1. Hash the exact bytes with SHA-256.
2. Sign a short-lived kind `24242` `upload` event for that hash and this node's
   onion hostname.
3. `PUT /upload` with the event in `Authorization: Nostr <base64url-event>`.
4. Keep the returned descriptor URL or publish it through the application's
   normal Nostr records.
5. To add another replica, sign for the destination node and call its
   `PUT /mirror` with the source descriptor URL.

An operator may add an invited key with
`--friend-grant <pubkey>:<byte-limit>:<expires-at>`.  `--open-shelter` is a
separate, explicit policy: unknown keys may submit signed BUD-04 mirrors when
the high free-space watermark remains intact, but they still cannot upload
directly and receive no retention promise.

Wildbloom's browser app keeps encryption client-side, so a node stores ciphertext
rather than plaintext.  See the exact [protocol and trust boundaries](docs/PROTOCOL.md)
and the [V4V dogfood path](docs/V4V-DOGFOOD.md).

## Development

```sh
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
scripts/audit-dependencies.sh
```

Security issues should follow [SECURITY.md](SECURITY.md).  Contributions are
welcome under the [MIT licence](LICENSE).  Desktop packages also retain the
exact upstream licences for their signature-verified Tor runtime; see
[third-party notices](THIRD_PARTY_NOTICES.md).

## Support ForgeSworn

If this is useful, sponsor [TheCryptoDonkey on GitHub](https://github.com/sponsors/TheCryptoDonkey),
[support BRAYs on Ko-fi](https://ko-fi.com/brays), or back
[ForgeSworn on Geyser](https://geyser.fund/project/forgesworn).
