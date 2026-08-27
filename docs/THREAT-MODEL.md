# Threat model

## Protected assets

- uploaded bytes and client-side ciphertext;
- the operator's disk and configured quota;
- the persistent Tor onion secret key;
- Nostr identities used by clients;
- availability and integrity of published blob URLs.

## Current protections

- The HTTP listener binds to loopback unless the operator uses an explicit
  public-bind override.
- The managed onion forwards only to that loopback listener.  Tor relay and exit
  operation are disabled.
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
  hosts and plaintext clearnet origins are rejected before the fetch.  All
  origin name resolution and transfer happens through Tor via a loopback-only
  `socks5h` listener, keeping private-network names away from the host resolver.
- On Unix, node state, temporary files, database files and onion keys are mode
  `0700` or `0600`.  Windows relies on the user's directory ACL; installer ACL
  hardening remains work.

## What this does not prove

- A node can delete or lose a blob after acknowledging it.  A signed response is
  not proof of future custody.
- Tor hides the home address from clients but does not make a powered-off home
  server available.
- SHA-256 proves byte integrity, not ownership, legality or the truth of media.
- Blob size, timing, requester public key and onion endpoint remain metadata.
- Nostr relays used for discovery can censor, omit or split views.  Blob transfer
  and retrieval do not depend on a relay once endpoints are known.
- Server-side encryption is not supplied.  Applications such as Wildbloom must
  encrypt before upload when confidentiality matters.
- There is not yet automatic replica counting, challenge/audit or repair after
  a node disappears.

## Operator responsibilities

Protect the data directory, back it up if the onion identity matters, keep Tor
and Wildbloom updated, choose a quota the disk can actually sustain, and do not
publish a non-loopback listener without an authenticated HTTPS boundary.
