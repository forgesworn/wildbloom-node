# Private pool receipts and part maintenance

Wildbloom's browser supports complete encrypted replicas and Reed–Solomon
threshold parts. Nodes store these as ordinary hash-addressed Blossom blobs;
there is no new upload endpoint or weakening of authentication or quotas.
The owner client owns encoding, private recovery receipts and keys.
Reconstruction runs in the browser or the explicit owner repair process.
See the [versioned browser contract](../../wildbloom/docs/POOL-STORAGE.md)
in a sibling checkout, or
[the Wildbloom repository](https://github.com/forgesworn/wildbloom/blob/main/docs/POOL-STORAGE.md).

## Import without networking

```sh
umask 077
wildbloomd replicas pool-template \
  --receipt private-pool-receipt.json \
  --owner "$OWNER_PUBKEY" \
  --revision 1 \
  --expires-at "$EXPIRY_UNIX_SECONDS" > pool-maintenance-templates.json
```

`OWNER_PUBKEY` is a public key, never a secret key. The command verifies the
signature, author, format, encrypted payload, coding bounds, canonical
endpoints and separation between parts before producing anything. Expiry
must be in the future and no more than one year away. Repeated maintenance
policies use increasing revisions as described in [REPLICA-POLICY.md](REPLICA-POLICY.md).
Tor receipts produce `tor-only` policies. Direct receipts require public HTTPS;
`--permit-loopback-development` instead requires literal IPv4 loopback origins
for the entire receipt. It is not a production LAN profile.

The JSON output contains `unsigned_policies`: one ordinary version-1 replica
policy event per part. Each policy has only that part's exact hash, size and
approved destinations. Replicated mode requests two or three configured
failure groups. Erasure mode requests one configured group for each part.
Neither the receipt nor the templates claim current custody; output explicitly
sets `storage_verified` and `reconstructs_ciphertext` to false.

Take each exact unsigned event to the owner's external signer. Verify/sign
the intended policy, save the returned canonical signed event under
`signed-<policy-id>.json` in a private policy directory, then use the existing
`replicas run --policy-dir ... --state-root ... --owner ...` workflow. The
coordinator re-verifies the signed returns and every observed copy. Fresh
write authority is still required for each mirror; admission, retention and
quota remain destination decisions. The importer performs no signing,
network requests, state writes or deletions.

## Limits and repair

The existing coordinator can mirror a surviving copy of a part to an approved
spare destination. It cannot regenerate a part whose last copy is gone.
Use the owner service described below or the browser's **Verify and repair pool**
for that: it reconstructs the
ciphertext from any threshold of surviving parts in the owner's client,
regenerates the missing parts and uploads only the appropriate part to each
destination. It does not need the decryption key. Adding replacement nodes
requires a new owner-signed receipt and preserves all previous assignments.
Importing that new receipt generates new policy IDs; stop obsolete policies
with their usual signed stop revisions when replacing maintenance intent.

Do not run reconstruction inside a storage node and claim it never possessed
the complete ciphertext. Do not reassign a returning node or shared failure
group to another part of the same ciphertext. Signed failure-group declarations
are operator assertions, not independent evidence of physical separation.
Public Blossom retrieval and operator collusion remain possible; encryption
is the confidentiality boundary.

Capacity weights in the browser guide initial placement. They are not live
free-space measurements, reservations, automatic draining or cluster-wide
rebalancing. The importer performs no background reconstruction or distributed leader
election; the separate owner repair command below provides unattended repair. Existing whole-blob repair remains unchanged.

Unit tests cover isolated policy generation and malformed coding, shared
groups, owner, revision, expiry and transport refusal. The browser's
`acceptance:pool` additionally exercises the native importer against an actual
saved browser receipt and six real local nodes. Independent physical-node,
real-Tor pool and cross-platform runtime acceptance remain separate gates.

## Unattended owner-side repair

`pool-repair` is an explicit, separate CLI process. It is never started by a
storage node's normal server or its per-part mirror coordinator. Run it on an
owner-controlled machine permitted to reconstruct the complete ciphertext.
No decryption key is required or accepted. An external signer keeps signing
keys outside Wildbloom and receives only an exact short-lived upload request
for one assigned hash and destination at a time.

```sh
wildbloomd replicas pool-repair \
  --receipt /private/pool-receipt.json \
  --receipt-id "$RECEIPT_EVENT_ID" \
  --owner "$OWNER_PUBKEY" \
  --work-dir /private/wildbloom-owner-repair \
  --allow-reconstruction \
  --expires-at "$EXPIRY_UNIX_SECONDS" \
  --signer /absolute/path/to/external-signer \
  --interval 300
```

The signer contract is the same as replica maintenance: one unsigned canonical
Nostr event JSON on stdin, one signed event JSON on stdout, no shell. Static
arguments use repeatable `--signer-arg=VALUE`. Returned author, ID, tags, content,
signature and expiry must match the exact request. Signer timeout defaults to
30 seconds and is bounded to 1–60 seconds. No bearer events are persisted.

Use `--once` for one bounded pass; exit status is non-zero if requested
protection is not achieved. Without it, incomplete protection is reported and
retried after the interval (5 seconds to one day). Default: five minutes after
completion. Reports contain observations, not promises of future custody.
Monitor the private `pool-report.json` file for freshness and `protected` /
`recoverable`; operational failures terminate the process with a non-zero exit.
An operator's service manager may supervise this foreground command. It must
not substitute new receipt IDs or renew expiry without operator action.

The signed receipt's exact event ID is pinned at startup. Every network stage
and signature return rechecks the receipt file and expiry. Changes/removal stop
maintenance; replacement requires an explicit restart with the new signed
receipt ID. Expiry is mandatory, at most one year away, and also cancels an
in-progress pass. SIGINT/SIGTERM cancels the pass and drops temporary files.
Only one process may hold the private working directory's OS lock. Different
machines are not coordinated by that local lock; designate one owner service
per receipt. No remote deletion, reassignment or membership discovery occurs.

The process verifies complete surviving parts to private temporary files,
reconstructs in 64 KiB stripes and checks every regenerated part plus the full
ciphertext hash and FSWNENC2 header before asking for any upload signature.
Fewer than `k` surviving parts produces a degraded report and no upload. Every
restored copy requires a full verified GET. Nodes retain their quota, admission
and retention decisions; a refusal tries another signed same-part destination.
A fully healthy pass verifies existing copies without reconstruction or writes.

Transfers reserve each attempted read, write and read-back against
`--transfer-budget-bytes` (default 8 GiB per pass). Temporary space is bounded
conservatively by `(2n + 1) * part_size` before networking and by
`--max-work-bytes` (default 5 GiB). This is a configured bound, not a reservation
of filesystem free space. Disk errors stop the pass. No entire file is held in
RAM; HTTP and coding use bounded chunks. A hard kill or machine crash may leave
private `pool-pass-*` directories. Startup refuses those leftovers; review and
remove only the matching temporary directories before restarting. They contain
ciphertext/parts, never recovery keys. Successful passes and graceful shutdown
remove their temporary files; the observation report remains.

Tor receipts require `--proxy socks5h://127.0.0.1:PORT` and use the existing
fail-closed Tor transport without local onion DNS or clearnet fallback. Direct
receipts require public HTTPS with private/special address DNS filtering.
`--permit-loopback-development` permits only literal IPv4 loopback receipts and
cannot be combined with Tor or a proxy.

The browser's `acceptance:pool` runs the actual owner process after every
browser closes, repairs entirely missing data parts from parity, rejects a
changed signer return, restarts without uploads, exercises a second loss and
repair by the resident service, verifies exclusive locking and expiry refusal,
and decrypts native-repaired bytes in a fresh browser. Use `--maximum` for the
256 MiB source case. This proves browser/native version-1 coding compatibility
and local process recovery, not independent physical custody.

## Automated failure tests

Run `cargo test --workspace` for the quick failure suite alongside the existing
unit and process tests. The existing CI matrix runs it on Linux, macOS and
Windows; no external nodes, operator keys or disk-filling setup are required.

- Real HTTP responses with wrong hashes or lengths are rejected. A synthetic
  2-of-4 fixture restores both data parts from verified parity and compares
  every restored byte. Below threshold, no signature or upload is attempted.
- A target returning HTTP 507 and a target falsely acknowledging an upload
  remain degraded until a later pass verifies the restored bytes.
- An insufficient scratch budget refuses before network activity. An
  unavailable working path refuses without changing the file occupying it.
  Failed local download opens/writes stop repair with a local storage error,
  rather than reporting the remote node as unavailable. Unix tests interrupt
  access to the scratch file during a GET; Linux additionally exercises real
  ENOSPC using `/dev/full`. macOS and Windows do not simulate a full filesystem.
- A hard kill during a partial download releases the OS lock and preserves the
  incomplete private files. Restart refuses before network activity. The test
  then removes only its known disposable pass directory to model operator
  review and verifies a clean restart. Crash recovery does **not** silently
  delete leftover files or resume unattended.
- Expiry cancels a stalled network read and cleans temporary files. A signature
  returned after expiry cannot authorise an upload. Restart with expired
  authority gives an explicit expiry error; renewal remains an owner action.

The repair-pass tests use real HTTP and scratch files with a synthetic
in-process signer. Process tests launch the actual daemon and interrupt it
while bytes are partially downloaded. These complement the browser recovery
and native desktop suites; they do not replace independent physical-device,
installer or power-loss acceptance.

## Desktop controls in 0.3.0

The desktop can import and inspect signed receipts locally, check storage
without a signer, show per-part observations and supervise bounded owner repair.
See [DESKTOP-POOLS.md](DESKTOP-POOLS.md). `replicas pool-inspect` performs only
local validation. `replicas pool-repair --check-only` performs one read-only pass
without signing, reconstruction or uploads. `--stop-on-stdin` binds the lifetime
to a supervising pipe: a byte or EOF cancels the process gracefully. Normal CLI
services without that option keep their existing signal/expiry behaviour.
