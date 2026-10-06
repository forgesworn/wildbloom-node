# Desktop owner pool management

Wildbloom Node 0.3.0 adds an owner-pool area alongside the storage-node settings.
It supervises the bundled daemon's existing signed-receipt repair service. This
computer may reconstruct ciphertext; use an owner-controlled machine separate
from nodes promised only one coded part. Encryption keys remain elsewhere.

## Set up a pool

1. Select **Create a pool or add replacement nodes in the browser**. This opens
   the fixed Wildbloom browser client only after your click. Choose replicated
   or split storage, enter nodes and independent failure groups, encrypt, sign,
   save the receipt and recovery key separately, then upload and verify.
2. In the desktop's **Storage pools** section, choose the saved JSON receipt and
   enter the expected author's public key from your signer. **Verify and save
   receipt locally** checks its signature, exact event ID, layout and transport
   using the bundled daemon. It contacts neither storage nodes nor a signer.
3. Select the receipt. Review its owner, layout, transport and destinations.
   **Check storage (read only)** reads complete parts and checks their hashes;
   it does not reconstruct, sign or upload. An unreachable or corrupt part is
   shown as unavailable, not assumed permanently lost. Spares may remain
   unchecked once the required copies are verified.
4. To repair, provide an absolute external signer executable and optional
   arguments (one literal argument per line; no shell expansion). The helper
   takes unsigned Nostr event JSON on stdin and returns the exact signed event
   on stdout. Never put signing secrets in arguments. Select the authority
   expiry, interval, transfer budget per pass and temporary disk budget, then
   explicitly approve reconstruction and signing and select **Start automatic
   repair**. The signer itself must allow unattended requests for unattended
   operation. No raw key is accepted by Wildbloom.
5. **Stop check or repair** closes the supervision pipe and waits for graceful
   cancellation. Closing the window leaves repair in the tray. Quitting,
   updating, restarting or losing the desktop process stops the owner process.
   Imported receipts survive restart; signing authority does not. Start again
   explicitly after reopening. Signing paths and arguments are not persisted.

The desktop manages up to 16 receipts with one active pool process at a time.
This bounds concurrent reconstruction and signer use. For multiple continuous
pool services or boot-time supervision use the documented CLI with a separate
work directory and bounded authority per service.

## Health and replacement

Health is a timestamped observation, not a custody guarantee. The UI distinguishes
unknown storage, full requested protection, recoverable but underprotected, and
below the recovery threshold. Counts refer to verified failure groups per part.
Node reachability can change after any completed check. The process status and
expiry are separate from the last observation; stopped repair never means
ongoing protection. Checks and repair reserve their transfer/disk budgets and
stop on invalid receipts, expired authority or exhausted limits.

For a permanently lost node, stop the old service, open the browser client,
load the existing signed receipt, enter explicit per-part replacements, then
sign and back up the new receipt. Import that new receipt in the desktop and
check it before starting repair. Existing destinations remain in signed history;
the desktop never edits an unsigned placement, redirects parts or deletes
remote copies. Remove an old local receipt only after confirming your backup.
Removing it preserves reports and work folders.

## Tor and private state

Direct receipts use public HTTPS and no proxy. Tor receipts require an explicit
`socks5h://127.0.0.1:PORT` belonging to a local Tor client; no DNS or direct
fallback is allowed. The desktop pool service does not inherit the storage
node's optional Tor process or silently start a transport. The browser client
requires its own appropriate Tor Browser setup for onion endpoints.

Receipts live under the application's local data directory in
`owner-pools/<receipt-id>/receipt.json`; each receipt has its own private `work`
directory. The UI shows the exact work path. Unix permissions are 0700 for
new directories and 0600 for receipt files. Windows relies on the user's private
application-data ACLs; clean-machine acceptance must verify those ACLs.

A graceful stop drops temporary ciphertext files. After an abrupt failure,
leftover `pool-pass-*` directories cause the daemon to refuse a new pass.
Open **Local receipt and work folder**, select **Review interrupted repair files**,
and inspect the folder names, file names and byte counts. Confirm the temporary
parts are disposable, then select **Clear reviewed repair files**. This uses the
same exclusive lock as the CLI owner service and refuses cleanup while that
service is active, if the reviewed files changed, or if folders contain links,
nested directories or unexpected files. A changed review requires fresh review
and confirmation. Cleanup preserves receipts, reports and remote data; it never
starts repair or restores signing consent. Unexpected files require manual review
in the displayed work folder. Do not remove receipt backups or unrelated data. Disk and
transfer limits default to 5 GiB and 8 GiB per pass respectively; the desktop
caps each at 32 GiB. No quota override is granted on remote nodes.

## Acceptance

- `cargo test --locked --workspace` includes actual daemon subprocess checks
  for local receipt inspection, healthy/degraded read-only observations with
  zero uploads, supervision-pipe cancellation, cleanup and lock reuse.
- `cargo test --locked --manifest-path desktop/src-tauri/Cargo.toml` validates
  authority/transport settings, command construction and private local state.
- `cd desktop && npm ci --ignore-scripts && npm test` exercises UI consent,
  actions, hostile text, mobile layout and accessibility with mocked IPC. Set
  `WILDBLOOM_BROWSER_EXECUTABLE` if Chromium is not installed by Playwright.
  Mocked IPC does not establish native webview or physical-node acceptance.
- Complete [PHYSICAL-POOL-ACCEPTANCE.md](PHYSICAL-POOL-ACCEPTANCE.md) on actual
  devices before claiming independent-site or clean-machine acceptance.

### Native desktop lifecycle acceptance

With Rust, Node 24 and the normal desktop build prerequisites installed, run
`npm run test:native --prefix desktop` on macOS, Windows or Linux. To save evidence
on Unix:

```sh
WILDBLOOM_NATIVE_EVIDENCE=/tmp/wildbloom-native-pools.json \
  npm run test:native --prefix desktop
```

This builds the actual Tauri desktop with an explicit `native-acceptance` debug
feature, stages the real daemon sidecar, and runs four disposable loopback nodes.
The driver operates the production DOM in the native WKWebView, WebKitGTK or WebView2. Import, check,
repair and Stop buttons invoke the production IPC handlers and subprocess
supervisor; IPC is not mocked. A separate example executable signs only with a
fixed synthetic test identity. The coding fixture has the expected envelope
header and deterministic opaque bytes; file encryption/decryption remains
covered by the browser pool acceptance suite.

The test verifies private receipt import, read-only health without signing or
uploads, degraded protection after two stores are lost, rejection of expired
authority without signing or starting a worker, real repair and Stop,
and another loss repaired while the window is hidden. The driver sends a real
window close request and uses the same `app.exit` path as tray Quit. It checks
that the child exits, reconstruction files are removed, the receipt survives
reopening, and signer settings/consent/repair authority do not. A fresh check
after reopening proves the work-directory lock was released. The cleanup journey
also stages synthetic interrupted-pass files, reviews them through real IPC,
requires confirmation, refuses a changed review, clears only the reviewed files,
and verifies that an explicit read-only check works afterwards. The expanded
thirteen-check journey passed locally on Apple Silicon macOS on 6 October 2026
in 30.7 seconds. The eleven-check hosted results below predate cleanup; consult
the release's retained CI evidence for its exact source and platform outcomes.

Every run uses a randomly named application identifier and fresh node stores;
it never overrides HOME or opens the normal application profile. Temporary
stores and that exact test profile are removed afterwards. Optional private JSON
evidence includes outcomes, source/build/harness hashes, OS and native webview
versions, and timing, but no receipts, endpoints, signer arguments or keys. A
nonzero command exit means failure, including failures before evidence exists.
Each desktop CI job runs this test and retains platform-labelled evidence. Linux
uses Xvfb and a session D-Bus; Windows uses CIM to identify daemon children
without confusing WebView2 subprocesses with repair workers. Receipt mode bits
are checked on Unix; Windows application-data ACL review remains a separate gate.

The driver is available only with the explicit Cargo feature, communicates over
the parent process's pipes rather than a network listener, and cannot compile
into a release build. That feature alone enables loopback receipt acceptance in
the desktop's daemon commands. Normal builds retain the production transport
rules and contain no driver. The test does not establish signed/notarised
installer acceptance, human keyboard/file-picker/menu accessibility, physical
multi-device independence, or Windows receipt ACL acceptance. Wiring a platform
into CI does not establish a passing run: consult its retained JSON evidence.

On 5 October 2026 the native journey passed repeatedly on the owner's Mac,
including all ten lifecycle checks in approximately 23 seconds after building.
The normal daemon and desktop Rust tests, Clippy and the existing browser-based
desktop UI/accessibility suite also passed. Hosted macOS results and retained
JSON evidence are recorded separately by the native lifecycle CI step.

The portable harness added later on 5 October passed all eleven checks locally
on Apple Silicon macOS, including expired-authority refusal. Windows, Linux
and hosted macOS also passed all eleven checks in [CI run 37285842022](https://github.com/forgesworn/wildbloom-node/actions/runs/37285842022)
on source `bf6b7c968620a723c0e8ecf7508141e42432d9f2`: Linux in 22.3 seconds,
macOS in 26.2 seconds and Windows in 31.4 seconds. All eight CI jobs passed;
the platform jobs retained JSON evidence artifacts. This is native debug-app
evidence, not trusted installer acceptance.
