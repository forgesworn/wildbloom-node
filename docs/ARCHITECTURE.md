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
        Blossom HTTP            mirror fetcher
        BUD-01/02/11          BUD-04 over Tor
             |                       |
             +-----------+-----------+
                         |
               quota + SHA-256 gate
                         |
          SQLite metadata + disk CAS blobs
```

`wildbloom-core` owns Nostr verification, Blossom behaviour, quota reservation,
integrity checks, repair and persistent storage.  `wildbloomd` owns process
configuration, the local TCP listener, shutdown and either a managed Tor process
or an explicitly supplied loopback Tor SOCKS proxy.

The Tauri tray application is a narrow process shell.  It starts the complete
signature-verified Tor Expert Bundle from its resources, preserves the onion
identity in the platform's per-user application-data directory, and launches
the exact `wildbloomd` sidecar on loopback.  Its UI receives status through
Tauri IPC.  It does not contain a second Blossom implementation and never asks
for a Nostr private key.

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

This is whole-blob replication today.  Chunk manifests, erasure coding and
RelaySwarm transport can be added above the CAS, but a standard Blossom URL must
remain available for clients that know nothing about those optimisations.

Each successful BUD-04 mirror records the exact verified source URL.  An
integrity scan streams every locally indexed blob through SHA-256.  A missing or
corrupt copy can be downloaded again from those recorded sources, but only if a
source is still reachable and returns the exact recorded length and hash.  This
is local repair, not replica discovery or proof that another operator retains a
copy.
