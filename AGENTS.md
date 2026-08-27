# Wildbloom Node contributor rules

Wildbloom Node is a cross-platform, self-hosted Blossom storage node.  Treat
storage, network exposure and Nostr authorisation as security boundaries.

## Non-negotiable boundaries

- Never log Nostr secret keys, bearer authorisation events or uploaded bytes.
- Never accept an upload without a valid, unexpired BUD-11 event scoped to the
  exact operation, SHA-256 hash and configured server identity.
- Bind to loopback unless the operator explicitly chooses another address.
- Enforce quota before reading an upload and enforce a per-blob size limit while
  streaming.  Do not buffer complete blobs in memory.
- Content-address blobs by the SHA-256 of the bytes actually received.  Never
  trust a filename, URL, MIME type or client-provided digest on its own.
- Temporary files, the SQLite database and Tor material are private operator
  state.  Use restrictive permissions where the platform supports them.
- Do not introduce WebRTC, STUN or TURN.  New transports sit behind an explicit
  adapter and must retain standard Blossom HTTP interoperability.
- Do not claim durable replication until independent nodes and repair after
  loss have been exercised by an automated acceptance test.
- Tests and documentation must use synthetic keys, hashes and domains only.

## Required checks

Run `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`
and `cargo test --workspace` before pushing.

