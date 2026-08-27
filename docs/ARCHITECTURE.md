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

`wildbloom-core` owns Nostr verification, Blossom behaviour, quota reservation
and persistent storage.  `wildbloomd` owns process configuration, the local TCP
listener, shutdown and the managed Tor process.  A later Tauri shell should call
the same core rather than reimplementing the server.

## Why Rust

One native core gives us predictable streaming I/O, bounded memory use, SQLite,
strong types around trust boundaries and ordinary binaries for macOS, Linux and
Windows.  It also leaves a clean path to a Tauri tray application.  There is no
browser-only networking primitive in the node, so WebRTC and its STUN/TURN
machinery are unnecessary.

## Storage model

Blobs live at `blobs/<first-two-hex>/<sha256>`.  The database records size, MIME
type, creation time and authorised owner relationships.  An upload reserves its
declared size in an immediate SQLite transaction before the body is streamed to
a private temporary file.  The actual digest and byte count are checked before
an atomic move into the CAS.

This is whole-blob replication today.  Chunk manifests, erasure coding and
RelaySwarm transport can be added above the CAS, but a standard Blossom URL must
remain available for clients that know nothing about those optimisations.

