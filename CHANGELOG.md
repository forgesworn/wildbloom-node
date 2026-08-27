# Changelog

## Unreleased

### Added

- Native Wildbloom Node tray application for Windows, Linux and macOS.
- Complete Tor Expert Bundle packaging with a pinned upstream signing key.
- Deny-by-default writer allowlists and bounded concurrent writes.
- BUD-06 upload preflight and owner-aware BUD-12 deletion.
- Full on-disk integrity verification and repair from verified mirror sources.
- Automated two-node Tor acceptance covering replication, deliberate loss,
  repair, source shutdown and onion-identity retention.
- A pinned signed-updater feed, explicit update UI and fail-closed draft release
  workflow for Developer ID, notarisation and Windows Authenticode builds.
- `AppState::with_fetcher` lets a shell supply an explicit transport adapter
  and refuses to combine one with a mirror proxy.
- Owner, friend and guest claims over one deduplicated CAS, with expiring friend
  ceilings, mirror-only open shelter, watermarks and oldest-guest-first eviction.
- Authenticated self-only BUD-12 listing with bounded SHA-256 cursor pagination.
- Opaque attachment responses for friend-only, guest-only and MIME-ambiguous
  blobs.
- Startup recovery for interrupted CAS/database moves and migration from the
  0.2 owner schema.

### Changed

- BUD-04 mirroring and integrity repair fetch through a transport-neutral
  `BlobFetcher` interface (`wildbloom_core::fetch`).  `TorHttpFetcher` over the
  loopback `socks5h` proxy is the only shipped adapter.  A node without one
  still refuses `/mirror` and leaves repair candidates unrepaired, exactly as
  before.  Successful mirrors and repairs log the path that carried the bytes.
- The two-node Tor acceptance test retries the mirror while a freshly
  published onion is still unreachable, and takes its Tor bootstrap budget
  from `WILDBLOOM_TEST_TOR_TIMEOUT` (default 300 seconds) for days when
  directory fetches stall.
- The unsafe public direct-write switch is replaced by explicit
  `--open-shelter`, which admits unknown signers only through BUD-04 mirroring.

- Platform-native per-user data directories replace the working directory as
  the headless daemon default.
- The Blossom protocol declaration now includes BUD-01, BUD-02, BUD-04,
  BUD-06, BUD-11 and BUD-12.

### Security

- A node with no configured writer public key is read-only.
- Tor is tied to its parent process and the desktop app uses a private explicit
  torrc, loopback listeners and a five-minute bootstrap deadline.
- macOS signs the Tor executable and its dynamic library as nested code after
  verifying the upstream archive signature.
- Dependency audit exceptions are exact and documented.  New RustSec warnings
  fail CI.
