# Changelog

## Unreleased

- Add `wildbloomd --group-mode`, a closed storage node for the devices of
  enrolled groups (phase S3 of `docs/GROUP-GRANTS.md`).  `--group-keeper
  <keeper>:<ceiling bytes>` enrols a room authority key; its kind `27541`
  grants arrive on `POST /groups/v1/events`.  Only granted keys may use the
  node, every read needs a BUD-11 `get` token and sees only what the signer's
  group holds, and group reads are never cacheable.  It refuses
  `--open-shelter`, `--service-profile` and `--checkout-profile`.

## 0.3.12 preview - 2026-10-24

- Direct send works without TURN.  Drop and the `/send` and `/get` pages now
  default to the public STUN server `stun:stun.cloudflare.com:3478`; no
  ForgeSworn-run STUN or TURN server is built in any more.  A node without a
  TURN issuer makes Drop fall back to that STUN server.
- Self-hosters can still hand out their own servers: `wildbloomd --turn-issuer`
  accepts STUN-only `--turn-url` lists (no secret), or TURN with a secret.
- "Hide my address" still needs a TURN server and now refuses clearly before a
  link is made when none is offered.  It is now off by default for installs
  that never set it; a setting you chose is kept.
- Clearer message when a direct connection cannot be made (mobile data or
  some work networks).

## 0.3.11 preview - 2026-10-20

- Update the TLS certificate checks in Drop and `wildbloomd`: `rustls-webpki`
  0.103.16 and `webpki-roots` and `webpki-root-certs` 1.0.10, which stop
  trusting distrusted emSign intermediates (RUSTSEC-2026-0381, -0382 and
  -0383).

## 0.3.10 preview - 2026-10-20

- Drop can receive a file straight from someone's phone. They open the
  owner's link, both sides check the same words, and once the owner accepts,
  the file streams over a direct connection into
  `~/Downloads/Wildbloom Received`, marked as downloaded. Nothing is stored on
  any server. Find it under **Add files… > Receive a file…**.
- TURN credentials from `POST /turn/v1/credentials` are now valid for 15
  minutes instead of an hour, and Debug output never shows a credential or
  username.

## 0.3.9 preview - 2026-10-20

- Hold back a mass removal from the Wildbloom folder until the owner chooses.
  When many files vanish from the folder at once (50 files, or 10 that are at
  least half of the folder, within 10 minutes), Wildbloom removes none of them
  anywhere: the other computers keep their copies and no encrypted copy is
  deleted. The status line says how many were deleted, and **Review…** lists a
  few of them with **Put them back** (written back from their encrypted copies),
  **Remove them everywhere** or **Decide later**. A moved or renamed folder is
  never held, a few deleted files still go through at once, and adds and edits
  keep working. The hold survives restarts. Only the computer where the files
  were deleted holds them; update every computer so each has the brake.
- The Drop index moves to schema 5, adding the held removals. 0.3.8 and earlier
  refuse a schema 5 index, so do not downgrade after upgrading.
- Add an opt-in TURN credential issuer (`--turn-issuer`, with `--device-grants`
  and one to four `--turn-url`s) for the planned direct send. A granted
  device's NIP-98 request to `POST /turn/v1/credentials` returns two TURN REST
  credentials valid for an hour, one for itself and one for the person at the
  other end, each with a fresh random username label. Each device may make 30
  requests an hour, counted apart from the pairing issuer's. The secret is the
  TURN server's `static-auth-secret`, read from a private file or
  `WILDBLOOM_TURN_SECRET`, and is never logged or returned. Nothing works until
  the TURN server also has the matching `static-auth-secret` line. The pairing
  issuer now shares its NIP-98 and device grant checks with this route; its
  behaviour is unchanged.

## 0.3.8 preview - 2026-10-19

- Learn when a shared file has been downloaded. The recipient's page confirms
  the download over the same encrypted connection (foregather-kit 0.5.0's
  optional transfer reply) while the link is open, within 10 minutes of making
  it. The share window and the file's row then show **Downloaded**, and by
  default the shared copy is deleted at once, so a share works once. Without a
  confirmation the copy is deleted when it expires or on Stop sharing, as before.
- Add Sharing settings: delete the shared copy after a confirmed download or
  keep it until it expires, and how long shared copies last (1 hour, 24 hours
  or 7 days). Changes apply to files shared afterwards.
- Make the Drop window calmer. Rows with both copies drop their "2 copies"
  label, Share appears on hover or keyboard focus (always on touch screens),
  the drop band goes once there are files, **Add files…** moves to the footer,
  and the share window keeps its heading and status in fixed places.
- The Drop index moves to schema 4, adding the download time to shares. 0.3.7
  and earlier refuse a schema 4 index, so do not downgrade after upgrading.

## 0.3.7 preview - 2026-10-19

- Check the key list for changes from the owner's other computers every 10
  seconds instead of every 2 minutes, so an add, edit or removal on one
  computer reaches the others in seconds rather than minutes. A check that
  finds nothing new is one signed listing request to the online node.

## 0.3.6 preview - 2026-10-18

- Add Wildbloom Drop to the desktop app. A dropped file is encrypted on this
  computer under its own key, kept on the local node and copied to the owner's
  online node, and shows **2 copies** once both are verified. First run approves
  the computer once through a NIP-46 signer with a device grant; one recovery
  key restores every file on another computer. Share sends a fresh encrypted
  copy through a Foregather live pairing (a link and four spoken words), which
  is deleted on Stop sharing or after 24 hours.
- Keep computers that share a recovery key in step. Each reads the key list
  from its nodes every 2 minutes and when its local node starts, takes in
  files added elsewhere and applies removals. A computer now deletes online
  copies only where it holds the claim, so removing a restored file no longer
  leaves a deletion the node refuses for ever.
- Add the Wildbloom folder, off until the owner turns it on. `~/Wildbloom`
  holds a readable copy of every kept file, in the same subfolders, on every
  computer where it is on. Adds, edits and deletions there reach the other
  computers. Replaced and removed files go to the Trash or Recycle Bin, never
  deleted outright, and concurrent changes keep both versions. Nothing changes
  while the folder is missing or a scan is incomplete. The folder holds
  plaintext, so full-disk encryption is recommended.
- Add opt-in owner-authorised device grants (`--device-grants`): an owner-signed
  kind 27540 event grants a device key and a recovery identity a per-key byte
  ceiling until an expiry, and a later event revokes it. Expiry and revocation
  stop new writes at once and move stored claims to the owner instead of
  demoting them. Grants persist in a private SQLite file beside the store.
- Add an opt-in pairing issuer (`--pairing-issuer`) that exchanges a granted
  device's NIP-98 request for a one-use Foregather live creation grant. The
  operator token stays on the node and is never logged or returned.
- Remove the updater's `zip` feature and clear new dependency audit findings.
- Drop on Windows and Linux is compiled and unit tested in CI but not yet
  exercised on devices. Native tray clicks, Dock drops on a bundled app and
  screen readers remain unverified.

## 0.3.4 preview - Unreleased

- Automate both Mac preview signatures and Apple notarisation from an exact,
  successful CI build using the owner's existing Keychain. Retain build,
  signature, checksum and native upgrade evidence without exporting credentials.
- Require a genuine upgrade from the signed 0.3.3 baseline for new Mac builds;
  reject reinstalls, downgrades and mismatched daemon/desktop versions.
- Allow hosted native Intel and Apple Silicon acceptance of checksum-pinned
  signed draft candidates. Automatic updater and physical reboot acceptance
  remain separate gates.

## 0.3.3 preview.2 (Mac signing) - 2026-10-06

- Sign the existing Apple Silicon and Intel 0.3.3 binaries with Developer ID,
  notarise both apps and DMGs, and staple and verify their tickets. Retain exact
  input/output checksums, Apple submission IDs and package verification evidence.
- Include nested Tor transport helpers in the runtime signing script and cover
  them with a real Mach-O regression in macOS CI. Add a repeatable local Keychain
  signing tool which refuses an input checksum mismatch before accessing credentials.
- These remain manual-install previews. Windows signing, automatic updates,
  clean-machine acceptance, physical multi-device recovery and independent
  security review remain open. Windows/Linux preview.1 downloads are unchanged.

## 0.3.3 preview - 2026-10-06

- Protect Windows owner receipts, coordinator state and repair work with private
  ACLs created before writing data. Refuse broad/null ACLs and reparse points;
  share the checks between the desktop and daemon.
- Exercise real second-account read/write denial on Windows, plus persisted
  native receipt, report and lock ACL checks. Existing overly broad state is
  refused rather than silently changing its permissions.
- Harden the future signed-release workflow with an all-platform credential
  preflight, byte-level updater signature verification, and Windows runtime,
  expected-signer and timestamp checks.
- This remains an unsigned/ad-hoc preview. Trusted signing, independent security
  review and physical multi-device acceptance remain separate release gates.

## 0.3.2 preview - 2026-10-06

- Review and explicitly clear interrupted owner repair files from the desktop.
  Cleanup holds the repair lock, rejects changed reviews and unexpected files,
  and preserves receipts, reports and remote parts. Repair remains stopped.
- Exercise the native desktop recovery lifecycle on Linux, macOS and Windows,
  including expired-authority refusal and interrupted-file cleanup.
- Preserve existing required CI check names while adding native acceptance.
  Preview signing and physical-device limitations remain unchanged.

## 0.3.1 preview - 2026-10-05

- Stop owner repair on local temporary-storage write failures instead of
  misreporting them as unavailable remote parts.
- Explain expired repair authority and CLI failures with actionable messages.
- Add automated corruption, threshold, rejected-upload, false-acknowledgement,
  storage-failure, hard-kill and in-flight expiry tests. Hard-crash leftovers
  still require operator review before restart; authority is never renewed
  implicitly.
- Include the native macOS desktop lifecycle acceptance suite in CI. Preview
  signing and physical-device limitations remain unchanged.

## Unreleased

- WILDBLOOM_SERVER_NAME accepts a comma-separated list, matching --allow-pubkey and --friend-grant.
- Add `wildbloomd replicas run --policy-dir --state-root`: one process
  maintains every `signed-<id>.json` in a directory, with per-policy state and
  locks, per-prefix intervals (`--interval-for`), stop-until-changed handling
  and per-policy failure backoff instead of exiting.
- Add `wildbloomd replicas enrol`: derive and sign `<prefix>-intake` and
  chunked `<prefix>-archive-<hex>` policies from an operator-supplied
  inventory, with an append-only ledger, trusted-state checks, a grace rule,
  loss reporting, expiry renewal and verification of every signed return.
- Document that coordinator repair cannot restore a node whose index still
  lists a blob whose file is gone, and the node-side remedies.

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
