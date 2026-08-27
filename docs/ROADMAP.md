# Roadmap

## Production candidate, implemented

- persistent whole-blob CAS;
- strict BUD-01, BUD-02, BUD-04, BUD-06, BUD-11 and BUD-12 profile;
- stable managed Tor v3 endpoint;
- global and per-blob quotas;
- deny-by-default writer allowlist and bounded concurrent writes;
- full integrity scan and repair from a previously verified mirror source;
- native daemon source and build/test matrix for macOS, Linux and Windows;
- native Tauri tray shell with bundled, upstream-signature-verified Tor;
- unsigned `.deb` and NSIS previews installed, started through Tor, checked for
  single-instance and child cleanup, and uninstalled on fresh hosted runners;
- live onion reachability evidence from an independent Tor client;
- two independent macOS nodes mirroring through Tor and retaining the exact
  blob after the source node stops;
- automated loss, repair, source shutdown and onion-identity restart acceptance
  across two fresh Tor clients on macOS;
- a transport-neutral `BlobFetcher` interface for BUD-04 mirroring and repair,
  with Tor as the only shipped adapter and unchanged default behaviour when no
  adapter is configured;
- claim-aware owner, friend and guest retention with fixed watermarks,
  mirror-only open shelter, oldest-guest-first eviction, opaque serving,
  self-only BUD-12 listing and migration from the 0.2 owner schema.
- the unbound router, store and `BlobFetcher` interface are published as the
  neutral MIT-licensed `shelter-kit` v0.1.0 crate, while the daemon keeps the
  `Wildbloom Node` BUD-01 product identity.

## Next acceptance gates

- V4V uploads encrypted media to a Wildbloom Node and plays it from the remaining
  replica after another endpoint is unavailable;
- production installers are signed, notarised where required, installed and
  removed on clean retail Windows, Linux, Intel Mac and Apple Silicon systems;
- the tray shell survives reboot and retains the same onion identity on all
  three operating systems;
- signed pin manifests record desired replica count, independent observations
  find missing copies, and repair restores the count;
- retention, replica discovery, custody challenges and optional paid quota have
  explicit policy and tests;
- owner, friend and guest retention, migration and interrupted-transaction
  acceptance pass on the Windows, Linux and macOS CI matrix;
- a ForgeSworn-owned native lane (standard QUIC direct path plus an opaque
  WebSocket relay) is spiked on two desktops and a physical Android phone across
  home NAT, carrier NAT, VPN egress and UDP-blocking networks, with direct,
  relayed and failed outcomes recorded separately, before it becomes an
  optional `BlobFetcher` adapter.  RelaySwarm's WebRTC session is not the
  storage lane.

None of these should be described as shipped until its own test has run on the
named platform or independent nodes.
