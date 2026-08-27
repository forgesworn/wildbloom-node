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

### Changed

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
