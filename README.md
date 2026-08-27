# Wildbloom Node

Run your own Blossom storage at home without opening a router port.

Wildbloom Node is a small, cross-platform Blossom server.  It stores blobs on
your disk by SHA-256, accepts only tightly scoped Nostr authorisation, and makes
the server reachable through a persistent Tor v3 onion.  It does not use
WebRTC, STUN or TURN.

This is an alpha prototype.  The headless node targets macOS, Linux and Windows,
but installation is still from source and Tor must already be installed.  The
real Tor and two-node replication acceptance has run on macOS; Windows and Linux
runtime evidence is still open.  A friendly desktop installer and unattended
repair are next.

## Why this exists

Blossom gives Nostr applications a sensible content-addressed storage protocol,
but using somebody else's server is still using somebody else's disk.  They can
lose it, remove it or stop paying the bill.  Wildbloom Node makes a user's own
machine a standard Blossom server and lets another authorised node copy the
blob through BUD-04.

It is not a torrent client.  Every replica currently stores a complete blob and
serves it over ordinary Blossom HTTP.  Nostr can carry private storage offers
and replication intent; Tor carries the bytes.  RelaySwarm is a promising later
direct transport, but it is not yet part of the durability claim.

## What works

- BUD-01 `GET` and `HEAD`, optional file extensions and single byte ranges.
- BUD-02 streaming `PUT /upload` with `Content-Length` and `X-SHA-256`.
- BUD-04 `PUT /mirror` from hash-addressed onion or public HTTPS origins through
  the node's private Tor SOCKS listener.
- Strict BUD-11 kind `24242` signature, operation, hash, server and expiry
  checks.
- Persistent SQLite metadata and a disk content-addressed store.
- Pre-stream global quota reservation, per-blob limits, deduplication and
  interrupted-upload cleanup.
- Loopback-only binding by default and a persistent Tor v3 onion identity.
- Native Rust build/test CI configured for macOS, Linux and Windows.

There is no deletion API, paid quota, automatic replica repair or desktop GUI
yet.  Those omissions are deliberate and documented in the [roadmap](docs/ROADMAP.md).

## Install and run

You need [Rust](https://www.rust-lang.org/tools/install) 1.94.1 or later and a
current [Tor Expert Bundle](https://www.torproject.org/download/tor/), with the
`tor` executable on `PATH`.

```sh
git clone https://github.com/forgesworn/wildbloom-node.git
cd wildbloom-node
cargo build --release
./target/release/wildbloomd
```

The first Tor bootstrap can take a minute or two.  Once ready, the log prints
the stable `.onion` Blossom URL.  Add that URL to a Blossom-capable client.  The
node stores data under `./data` unless `--data-dir` or
`WILDBLOOM_DATA_DIR` says otherwise.

For local development without Tor:

```sh
cargo run -p wildbloomd -- --no-tor
```

Useful controls:

```text
--quota-bytes <BYTES>          total stored blob quota, default 10 GiB
--max-blob-bytes <BYTES>       maximum single blob, default 1 GiB
--bind <IP:PORT>               local listener, default 127.0.0.1:3742
--tor-bin <PATH>               Tor executable, default tor
--no-tor                      local-only development mode
```

Do not put the local listener on the public internet merely because the flag
exists.  If a conventional HTTPS reverse proxy is genuinely required, read the
[threat model](docs/THREAT-MODEL.md) first.

## How applications use it

Applications use the onion URL exactly as they use another Blossom server:

1. Hash the exact bytes with SHA-256.
2. Sign a short-lived kind `24242` `upload` event for that hash and this node's
   onion hostname.
3. `PUT /upload` with the event in `Authorization: Nostr <base64url-event>`.
4. Keep the returned descriptor URL or publish it through the application's
   normal Nostr records.
5. To add another replica, sign for the destination node and call its
   `PUT /mirror` with the source descriptor URL.

Wildbloom's browser app keeps encryption client-side, so a node stores ciphertext
rather than plaintext.  See the exact [protocol and trust boundaries](docs/PROTOCOL.md)
and the [V4V dogfood path](docs/V4V-DOGFOOD.md).

## Development

```sh
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo audit
```

Security issues should follow [SECURITY.md](SECURITY.md).  Contributions are
welcome under the [MIT licence](LICENSE).

## Support ForgeSworn

If this is useful, sponsor [TheCryptoDonkey on GitHub](https://github.com/sponsors/TheCryptoDonkey),
[support BRAYs on Ko-fi](https://ko-fi.com/brays), or back
[ForgeSworn on Geyser](https://geyser.fund/project/forgesworn).
