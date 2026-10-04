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
Review them in the displayed work folder and remove only identified disposable
pass directories. Do not remove receipt backups or unrelated data. Disk and
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
