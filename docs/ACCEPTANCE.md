# Acceptance evidence

## 2026-08-27 native macOS prototype

Environment: macOS, Rust 1.94.1 and Tor 0.4.9.5.

- All 23 Rust unit and HTTP integration tests passed, including adversarial
  BUD-11 scope/signature cases, quota reservation, deduplication, signed upload
  and deletion, BUD-06 preflight, byte-range retrieval, integrity scanning and
  the deletion-versus-repair race.
- `cargo clippy --workspace --all-targets -- -D warnings` passed.
- RustSec audited all 271 locked daemon dependencies with no vulnerability or
  informational warning reported.  It audited all 541 desktop dependencies with
  no vulnerability reported and only the 17 exact transitive informational
  exceptions in [the dependency risk register](DEPENDENCY-RISK.md).
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
- The automated Tor acceptance then started two new nodes with fresh, separate
  Tor clients and onion identities.  Node A accepted a signed 37-byte BUD-02
  upload.  Node B copied it from A through BUD-04 and recorded the verified
  source.  The test removed B's local file directly.  B's next integrity pass
  detected the missing copy and restored SHA-256
  `05e867990b450d3fbc112e79fb679319ce19e81fa3d35dd44807d731a9ce6e72`
  from A through Tor.  After A stopped, B still served the exact 37 bytes.
  B then shut down cleanly, restarted with the same data directory and retained
  the same onion identity.
- Tor Expert Bundle 15.0.20 for Apple Silicon was downloaded from the Tor
  Project, its detached signature verified against pinned primary fingerprint
  `EF6E286DDA85EA2A4BA7DE684E2C6E8793298290`, and its complete executable,
  libraries and GeoIP data compiled into the local desktop resource path.
- The ad-hoc-signed Apple Silicon `.app` was rebuilt after signing Tor 0.4.9.11
  and its bundled `libevent` as nested code.  macOS accepted the complete app,
  Tor bootstrapped, the daemon returned HTTP 200 from `/healthz`, SQLite
  reported `ok`, a second launch retained exactly one app, Tor and daemon
  process, and quitting left no child process behind.  The onion key and SQLite
  database remained mode `0600`.  Ad-hoc signing is local execution evidence,
  not a notarised public release.
- An encrypted Tauri updater key was generated outside the repository with
  mode `0600`; its password is in the local macOS keychain and both private
  values are configured as GitHub Actions secrets.  Only its public
  verification key is pinned in the desktop configuration.
- V4V's real browser Blossom client produced a five-minute signed BUD-11 event,
  uploaded 42 synthetic bytes to a fresh loopback Wildbloom Node, fetched them
  again and matched SHA-256
  `7fd675c634c8eedfde15374f1e66e202f6ff4afdd624ae12560eef9cd16dfdbd`.
  That bounded dogfood result explicitly records `realTor: false`; it does not
  replace the independent Tor test above.

## 2026-08-27 installed desktop preview matrix

Commit `bfc8c06a23466c4819cf89795d0e64118b9e88a8` ran in
[desktop preview workflow 33070895932](https://github.com/forgesworn/wildbloom-node/actions/runs/33070895932).

- On a fresh GitHub-hosted Linux runner, the generated `.deb` installed through
  the operating-system package manager.  The installed Tor executable reported
  a valid version and `ldd` found no unresolved bundled library.  The desktop
  then created a valid v3 onion and SQLite store, started the packaged daemon,
  returned the default empty, read-only 10 GiB storage status from `/healthz`,
  and kept both the database and onion secret key at mode `0600`.
- A second Linux launch exited while the original remained alive.  The harness
  then sent `SIGKILL` to the desktop, bypassing its normal exit callback.  Tor
  and `wildbloomd` both stopped, proving the Linux parent-death handling, and
  the package uninstalled without leaving its executable on `PATH`.
- On a fresh GitHub-hosted Windows runner, the NSIS installer installed the app
  into an isolated directory.  The installed Tor executable reported a valid
  version; the desktop created a valid v3 onion and SQLite store; and the
  packaged daemon returned the same empty, read-only 10 GiB status.  A second
  launch exited, the installed process tree stopped, and the silent uninstaller
  removed the executable.
- The same exact-head workflow also built Apple Silicon and Intel macOS `.app`
  and `.dmg` previews after verifying and ad-hoc signing their bundled Tor code.
  Runtime behaviour for macOS remains evidenced by the native run above, not by
  those packaging jobs.

These are short-lived, explicitly unsigned preview artefacts on hosted virtual
machines.  They are not notarised or trusted public installers and do not prove
the updater, reboot/start-at-login behaviour, physical retail hardware or
long-term custody.

The onion hostnames were disposable test identities and are intentionally not
published.  These runs prove a real macOS Tor path, independent whole-blob
replication, repair after local loss and onion identity retention after a clean
restart, plus installed Linux and Windows preview startup on fresh hosted
runners.  They do not prove long-term custody, automatic replica discovery,
trusted signed installers or V4V production use.
