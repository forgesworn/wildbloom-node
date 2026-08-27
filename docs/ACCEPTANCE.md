# Acceptance evidence

## 2026-08-27 native macOS prototype

Environment: macOS, Rust 1.94.1 and Tor 0.4.9.5.

- All 18 Rust unit and HTTP integration tests passed, including adversarial
  BUD-11 scope/signature cases, quota reservation, deduplication, signed upload
  and byte-range retrieval.
- `cargo clippy --workspace --all-targets -- -D warnings` passed.
- RustSec audited all 262 locked dependencies with no vulnerability reported.
- Gitleaks found no secret in the pre-commit tree.
- A fresh managed Tor process produced a v3 onion.  A second independent Tor
  client fetched `/healthz` through it.  Restarting the node with the same data
  directory produced the same onion hostname.
- Two node processes used separate data directories and separate onion
  identities.  Node A accepted the then-current `README.md` as a signed BUD-02
  upload.  Node B fetched it from A's onion through BUD-04.  After A was stopped,
  B returned 4,523 bytes with SHA-256
  `8a1d541d2b864c1cc5b558056a261deb2e970350134d8ff1b93fd7576b79ce5c`.
  B reported one stored blob, 4,523 used bytes and zero reserved bytes.

The onion hostnames were disposable test identities and are intentionally not
published.  This run proves a real macOS Tor path and independent whole-blob
replication.  It does not prove Windows/Linux Tor runtime, automatic repair,
long-term custody or V4V production use.
