# Architecture

Wildbloom separates storage semantics from the shell that runs them.

```text
Wildbloom / V4V client
  |  signed BUD-11 request
  v
Tor v3 onion  ->  loopback-only wildbloomd
                         |
             +-----------+-----------+
             |                       |
        Blossom HTTP           BUD-04 fetcher
        BUD-01/02/11        (BlobFetcher: Tor today)
             |                       |
             +-----------+-----------+
                         |
               quota + SHA-256 gate
                         |
          SQLite metadata + disk CAS blobs
```

`wildbloom-core` owns Nostr verification, Blossom behaviour, quota reservation,
integrity checks, repair and persistent storage.  It fetches mirror and repair
bytes through a transport-neutral `BlobFetcher` interface; the only shipped
adapter is `TorHttpFetcher`, which speaks through the loopback SOCKS proxy the
shell supplies.  A fetcher carries bytes and reports which path carried them.
It never sees authorisation events, retention tiers or the owner's identity,
and the core still checks exact length and SHA-256 on everything it delivers.
`wildbloomd` owns process configuration, the local TCP listener, shutdown and
either a managed Tor process or an explicitly supplied loopback Tor SOCKS
proxy.

The Tauri tray application is a narrow process shell.  It starts the complete
signature-verified Tor Expert Bundle from its resources, preserves the onion
identity in the platform's per-user application-data directory, and launches
the exact `wildbloomd` sidecar on loopback.  Its UI receives status through
Tauri IPC.  It does not contain a second Blossom implementation and never asks
for a Nostr private key.  Linux Tor execution uses only the verified bundle's
private shared-library directory rather than the ambient library search path.
The Linux daemon also asks the kernel to deliver `SIGTERM` when its exact
desktop parent dies, then verifies that the parent survived the setup race.

## Why Rust

One native core gives us predictable streaming I/O, bounded memory use, SQLite,
strong types around trust boundaries and ordinary binaries for macOS, Linux and
Windows.  There is no browser-only networking primitive in the node, so WebRTC
and its STUN/TURN machinery are unnecessary.

## Storage model

Blobs live at `blobs/<first-two-hex>/<sha256>`.  The database records size, MIME
type, creation time and authorised owner relationships.  An upload reserves its
declared size in an immediate SQLite transaction before the body is streamed to
a private temporary file.  The actual digest and byte count are checked before
an atomic move into the CAS.

This is whole-blob replication today.  Chunk manifests, erasure coding and a
native node-to-node lane can be added above the CAS and behind the fetcher
boundary, but a standard Blossom URL must remain available for clients that
know nothing about those optimisations.  RelaySwarm's WebRTC session is browser
live-video distribution and is not the storage lane.

Each successful BUD-04 mirror records the exact verified source URL.  An
integrity scan streams every locally indexed blob through SHA-256.  A missing or
corrupt copy can be downloaded again from those recorded sources, but only if a
source is still reachable and returns the exact recorded length and hash.  This
is local repair, not replica discovery or proof that another operator retains a
copy.

## Next storage boundary

The next core revision gives the operator's files, invited friends and
best-effort guest mirrors distinct retention priorities without creating three
stores.  Tier belongs to each signed claim over a deduplicated blob; it is not a
single property of the blob and it is not the owner's desired replica count.
The complete target policy and its acceptance boundary are in
[`STORAGE-POLICY.md`](STORAGE-POLICY.md).

The Axum router is already exposed without binding a listener, and BUD-04
mirroring and repair already go through the transport-neutral `BlobFetcher`
interface with Tor as the only shipped adapter.  Loopback shells and any future
direct transport plug in as further adapters over one authenticated Blossom
router and one CAS rather than separate daemons or stores.

The candidate direct transport is a ForgeSworn-owned lane over standard QUIC
(Quinn with rustls) with an opaque WebSocket relay as the universal fallback.
It enters this repository only after a time-boxed spike on real home, carrier,
VPN and UDP-blocking networks passes, it is always optional, and it never
becomes a requirement for the default Tor node.  Its relay must not learn
authorisation events, retention tiers, blob plaintext or the owner's identity.
