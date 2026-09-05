# Changelog

## 0.2.1 - 2026-08-29

- Update the shared shelter-kit core to 0.1.2 so BUD-11 authorisation accepts
  standard base64, not only url-safe. A spec-compliant Blossom client now
  authenticates against the node.

## 0.2.2 - 2026-09-05

- Include Shelter Kit v0.4.1's serialised policy updates, preventing a
  concurrent friend-grant update from restoring a removed owner set.
- Use Shelter Kit v0.4.0, including shell tombstone and optional admission
  APIs. The Node keeps admission filtering disabled by default. Schema 5
  preserves existing data and verification evidence; do not downgrade a store
  to an older core that cannot enforce tombstone policy.
- Version both the daemon and desktop at 0.2.2 for the current installer set.

- Use Shelter Kit v0.3.0 for owner-scoped listing, current-grant friend lists
  and verification timestamps. Schema 4 preserves data and marks historical
  repair sources unverified until explicitly checked again. Deduplicated
  mirrors no longer certify unread remote bodies.
- Align the desktop version with the daemon at 0.2.1, and pin signed Tor Expert
  Bundle 15.0.21 from the official archive so later upstream releases do not
  invalidate the pinned download URL.

- Consume Shelter Kit v0.2.2, including URL-shaped BUD-11 server scopes,
  schema-v3 advisory claim classes, runtime policy APIs and lane-aware repair.
  Local CLI friend grants have no delegated issuer. The daemon test client and
  shared fetch adapters use the ring TLS provider without enabling a second
  provider through reqwest.

- Tor is now an explicit desktop transport choice rather than a runtime
  requirement.  A fresh install waits for the choice before starting either
  process.  Existing saved settings default to Tor for compatibility; direct
  mode starts only the loopback Blossom sidecar and supports an operator-owned
  HTTPS origin.

- Managed Tor uses full relay descriptors for its onion-only circuits.  This is
  a larger one-off directory download, but avoids a bootstrap dead-end observed
  when directory caches returned a consensus and zero microdescriptors.

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
- The router, content-addressed store and fetch boundary are published as the
  neutral MIT-licensed `shelter-kit` v0.1.0 crate.
- Direct public-HTTPS mirror and repair through `shelter-kit` v0.1.1, with
  redirects and ambient proxies disabled and non-public DNS answers refused.

### Changed

- BUD-04 mirroring and integrity repair fetch through a transport-neutral
  `BlobFetcher` interface (`wildbloom_core::fetch`).  `TorHttpFetcher` over the
  loopback `socks5h` proxy and `DirectHttpsFetcher` are shipped adapters.  A
  node without either still refuses `/mirror` and leaves repair candidates
  unrepaired.  Successful mirrors and repairs log the path that carried the
  bytes.
- The two-node Tor acceptance test retries the mirror while a freshly
  published onion is still unreachable, and takes its Tor bootstrap budget
  from `WILDBLOOM_TEST_TOR_TIMEOUT` (default 900 seconds) for days when
  directory fetches stall.
- The unsafe public direct-write switch is replaced by explicit
  `--open-shelter`, which admits unknown signers only through BUD-04 mirroring.
- `wildbloomd` now consumes the tagged `shelter-kit` crate and supplies its own
  validated `Wildbloom Node` BUD-01 product identity.

- Platform-native per-user data directories replace the working directory as
  the headless daemon default.
- The Blossom protocol declaration now includes BUD-01, BUD-02, BUD-04,
  BUD-06, BUD-11 and BUD-12.

### Security

- A node with no configured writer public key is read-only.
- Tor is tied to its parent process and the desktop app uses a private explicit
  torrc, loopback listeners and a fifteen-minute cold-bootstrap deadline.
- Direct mode retains the loopback-only default, refuses public plaintext HTTP
  origins and treats external HTTPS, DNS and firewall configuration as an
  explicit operator boundary.
- macOS signs the Tor executable and its dynamic library as nested code after
  verifying the upstream archive signature.
- Dependency audit exceptions are exact and documented.  New RustSec warnings
  fail CI.
