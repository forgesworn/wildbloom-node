# Threat model

## Protected assets

- uploaded bytes and client-side ciphertext;
- the operator's disk and configured quota;
- the persistent Tor onion secret key when Tor is enabled;
- Nostr identities used by clients;
- availability and integrity of published blob URLs.

## Current protections

- The HTTP listener binds to loopback unless the operator uses an explicit
  public-bind override.
- The managed onion forwards only to that loopback listener when selected.
  Tor relay and exit operation are disabled.  Direct mode does not start Tor.
- The desktop starts Tor from the signature-verified bundled resource tree.  On
  Linux it replaces Tor's child-process `LD_LIBRARY_PATH` with that exact bundle
  directory, so the packaged `libevent` is found without inheriting an
  operator-supplied library search path.
- Linux gives the bundled daemon a kernel parent-death signal and checks the
  parent PID immediately after registering it.  A killed desktop must not leave
  a writable storage process running without its controlling UI.
- Uploads require a valid Nostr signature scoped to `upload`, the exact SHA-256,
  one accepted server name and an expiry no more than five minutes after event
  creation.
- Singleton operation and expiry tags cannot be duplicated.  Standard
  multi-server and multi-hash scopes are accepted only when every value is
  well-formed and the current server and blob are included.  A captured token
  can therefore only replay an idempotent upload within its signed scope before
  it expires.
- Quota is reserved before streaming.  Bodies are streamed to a private file,
  bounded by both the declared size and per-blob limit, then independently
  hashed.
- Mirror origins must be hash-addressed `.onion` or public HTTPS URLs.
  Redirects, URL credentials, queries, fragments, IP literals, single-label
  hosts and plaintext clearnet origins are rejected before the fetch.  Tor mode
  sends origin name resolution and transfer through a loopback-only `socks5h`
  listener.  Direct mode disables ambient proxies, filters every DNS answer to
  public address space and accepts only HTTPS; it cannot be used for onion
  sources.
- On Unix, node state, temporary files, database files and onion keys are mode
  `0700` or `0600`.  Windows uses the current user's application-data directory
  and its inherited ACL.  Clean-machine installer review remains a release gate.
- A default node accepts no writes.  Operators configure exact owner keys and
  may issue expiring per-key friend byte grants.  Open shelter is separate and
  accepts unknown keys only for signed BUD-04 mirrors above the high free-space
  watermark; unknown direct uploads remain denied.
- Owner and friend reservations may evict only best-effort guest blobs.  Guest
  requests cannot consume the protected reserve or evict a stronger claim.
- Friend-only and guest-only responses are opaque attachments with `nosniff`.
  A declared MIME type becomes inline only for an unambiguous active owner
  claim.
- Upload and mirror concurrency is bounded.  Complete integrity scans hash the
  bytes on disk, and repair accepts only the exact length and SHA-256 from a
  previously verified hash-addressed source.

## What this does not prove

- A node can delete or lose a blob after acknowledging it.  A signed response is
  not proof of future custody.
- Tor hides the home address from clients but does not make a powered-off home
  server available.
- Direct mode exposes the node and clients to normal DNS, TLS endpoint and IP
  metadata.  Wildbloom does not configure or audit the operator's reverse
  proxy, certificate, firewall or router.
- SHA-256 proves byte integrity, not ownership, legality or the truth of media.
- Blob size, timing, requester public key and onion endpoint remain metadata.
- Nostr relays used for discovery can censor, omit or split views.  Blob transfer
  and retrieval do not depend on a relay once endpoints are known.
- Server-side encryption is not supplied.  Applications such as Wildbloom must
  encrypt before upload when confidentiality matters.
- There is no automatic replica discovery, replica counting or remote custody
  challenge.  Local repair works only while a previously recorded source is
  reachable.  It cannot repair the last remaining copy after that source is
  gone.

## Operator responsibilities

Protect the data directory, back it up if the onion identity matters, keep the
selected transport and Wildbloom updated, choose a quota the disk can actually
sustain, and do not publish a non-loopback listener without an authenticated
HTTPS boundary.
