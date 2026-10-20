# Wildbloom Drop: IPC contract (webview side)

This is what `drop.js`, `share.js` and the Drop section of `app.js` call and listen to.
The Rust side implements against it. `tests/drop-stub.js` is an executable copy of the
same contract: if the two disagree, fix whichever is wrong and keep them in step.

Conventions

- Commands are called with `window.__TAURI__.core.invoke(name, args)`. `args` is one
  object with camelCase keys (Tauri maps them to the snake_case Rust parameters).
  Commands with no arguments are called with none.
- All payload field names are camelCase (`#[serde(rename_all = "camelCase")]`).
- Times are Unix seconds. Sizes are bytes (the UI shows decimal kB, MB, GB).
- Ids (`id`) are opaque strings, stable for the life of a file row.
- A command rejects with either a string or an object `{ code, message?, host?, detail?, ownerNpub? }`.
  The UI reads `code` (lower snake case). A bare string that is a code is treated as one;
  any other string is shown as the message. Unknown codes fall back to a generic message.
  `keychain_unavailable` may be returned by any command and sends the UI to the keychain screen.
- No secrets cross this boundary except the recovery key, once, for display (`recovery_key_for_display`).
  The UI keeps it only in the DOM of the open step and clears it when the step ends.
- The CSP is unchanged (`connect-src ipc: http://ipc.localhost`). The webview makes no network request.

## Commands

### Platform and state

| Command | Args | Returns |
|---|---|---|
| `platform_info` | none | `{ os: "macos" \| "windows" \| "linux", desktop: string, computerName: string }`. `desktop` is `XDG_CURRENT_DESKTOP` on Linux (for example `ubuntu:GNOME`, `KDE`), else `""`. The UI sets `data-os` (`mac`, `windows`, `linux`), `data-desktop` (`gnome`, `kde`, `other`) and `data-button-order` on `<html>`. |
| `drop_status` | `{ recheck?: "keychain" \| "online" \| "keylist" }` | `DropStatus` plus `files: FileRow[]`. `recheck` asks Rust to probe again before answering ("Try again" and "Try now"; `keylist` reseals the key list). |

`DropStatus`

```
{
  firstRun: null | { step: "node" | "approve" | "recovery" | "keychain", nodeSettingsExist: boolean },
  node: "ok" | "stopped" | "error",
  keychain: "ok" | "unavailable",
  online: { configured: boolean, url: string, host: string, reachable: boolean,
            failedChecks: number, usedBytes: number, limitBytes: number, full: boolean },
  approval: { state: "none" | "active" | "expired", byNpub?: string, deviceNpub?: string,
              until?: number, limitBytes?: number },
  recovery: { keyList: "ok" | "failed", savedAt?: number, confirmed: boolean },
  watchFolder: { enabled: boolean, path: string,          // path is for display, for example "~/Wildbloom"
                 state: "off" | "on" | "unavailable" | "too_many" },   // Added.
  limits: { dropMaxBytes: number, shareMaxBytes: number },
  sharing: { afterDownload: "delete" | "keep",              // Added.
             expirySeconds: 3600 | 86400 | 604800 },
  receiving: { hideAddress: boolean,                        // Added. Receive a file
               folder: string,                              // the Received folder, for display
               maxBytes: number },                          // 250000000
  browserApproval: boolean                                  // true once the browser route exists; hides or shows its link
}
```

- `firstRun` non-null means first run is unfinished. Rust owns the step: the UI moves on by
  calling the command for the current step and then `drop_status` again. `"keychain"` means
  the keychain or Secret Service cannot be reached (also reported as `keychain: "unavailable"`).
- `online.failedChecks` counts consecutive failed reachability checks. The status line shows
  "Can't reach your online node" above 2.
- `approval.until - now < 30 days` while `active` shows the renewal line.
- `recovery.confirmed: false` is only expected after a restore that skipped saving.
- `recovery.keyList: "failed"` means the encrypted key list could not be opened or sealed
  (files are kept on this computer, but a restore would not see the newest ones until it
  is). **Added.** The status line shows, after "{n} files have only 1 copy": "Wildbloom
  couldn't update the list it needs to restore your files. Your files are safe on this
  computer." with "Try again" (`drop_status` with `recheck: "keylist"`).
- **Added.** `watchFolder.state` is `off` when the folder is off and `on` when it is working.
  `unavailable` means the folder (or its marker) can't be found; the status line shows, after
  the keychain line, "Your Wildbloom folder can't be found. Changes there are paused." with
  "Use folder again" (`set_watch_folder` with `enabled: true`). `too_many` means a scan hit the
  item limit; the line, straight after that one, is "Your Wildbloom folder has more than 20,000
  items. Changes there are paused." with no action. `enabled` stays true in both.
- **Added.** Rows in state `held` add, straight after the two folder lines and before "Approval
  for this computer has ended": "{n} files were deleted from your Wildbloom folder. They're kept
  until you choose." (1: "1 file was deleted from your Wildbloom folder. It's kept until you
  choose.") with "Review…", which opens the review dialog (see `held` below).
- **Added.** Rows in state `not_kept` add, after "{n} files have only 1 copy" and the key list
  line: "{n} files in your Wildbloom folder can't be kept." (1: "1 file in your Wildbloom folder
  can't be kept."). They are left out of the "All {n} files have 2 copies" count.
- **Added.** `sharing` is the node window's Sharing settings (`set_sharing`). `afterDownload`
  is what happens to a shared copy once its recipient confirms the download: `delete` (the
  default) deletes it at once, `keep` keeps it until its deletion time. `expirySeconds` is
  how long a sent copy stays otherwise: an hour, a day (the default) or a week. Both are read
  when a file is sent; a share already sent keeps what it was sent with. A changed setting
  is sent as `drop://status`.
- **Added.** `receiving` is "Receive a file". `hideAddress` (default true) is the node
  window's "Hide my address when receiving" setting (`set_receiving`): Drop then connects only
  through the relay, so the sender sees the relay's address, not this computer's. It is read
  when a receive starts. `folder` is where received files land, outside the Wildbloom folder
  (`~/Downloads/Wildbloom Received` by default; a full path on Windows). `maxBytes` is the
  largest file Drop accepts. A changed setting is sent as `drop://status`.
- The status line (spec 6.1) is resolved in `drop.js` from these fields and the rows, in the
  priority order of the spec. The tray tooltip and menu status item (Rust) must resolve the
  same order from the same data; the copy is in section 6.1 of the design spec.

`FileRow`

```
{ id: string, name: string, bytes: number, added: number,
  state: "encrypting" | "queued" | "copying" | "two_copies" | "no_online" | "waiting" | "failed"
       | "missing_online" | "online_full" | "missing_local" | "restoring" | "shared"
       | "stop_pending" | "sharing_ended" | "share_owner_only" | "unreadable"
       | "not_kept"                      // Added.
       | "held",                         // Added.
  progress: number | null,         // 0 to 100, for encrypting, copying, restoring
  sharedUntil?: number,            // state "shared"
  sharingEnded?: number,           // state "sharing_ended" (shown for 24 h)
  downloadedAt?: number,           // Added. When the recipient confirmed the download, on "shared" (the copy
                                   // is kept), "sharing_ended" (deleted) and "stop_pending" (being deleted)
  notKept?: "too_big" | "name" | "too_long" | "too_deep",   // Added. State "not_kept" only
  folder?: string,                 // Added. Parent path relative to the Wildbloom folder, shown muted under the name
  inWatchFolder?: boolean }        // Changed: the row is linked to a file in the Wildbloom folder
```

**Added.** `not_kept`: a file in the Wildbloom folder that Wildbloom does not keep. Copy "Not kept"
then `too_big` "over {limit}" (the limit is `limits.dropMaxBytes`), `name` "rename it to keep it",
`too_long` "its folder path is too long", `too_deep` "it's too many folders deep". Warning icon,
no Share, menu: "Show in Finder" only (`reveal_file`). `inWatchFolder` rows gain "Open"
(`open_file`) and "Show in Finder" (macOS), "Show in Explorer" (Windows) or "Show in Folder"
(Linux) at the top of their menu. The Remove confirmation, while `watchFolder.enabled`, reads
"{name} is removed from Wildbloom on all your computers. Copies in your Wildbloom folders go to
the Trash. Its encrypted copies and key are deleted, which can't be undone." ("Recycle Bin" on
Windows). With the folder off it keeps the earlier copy (plus the "It stays in your Wildbloom
folder" line for linked rows).

**Added.** `held`: a linked file that vanished from the Wildbloom folder as part of a mass
deletion, which the brake holds back until the owner chooses. Nothing about it has changed
anywhere else: no tombstone, its copies and key are kept, and the other computers keep their
copies. Rust holds deletions inferred by the folder pass (never window removals, other
computers' removals or replaced versions) when, within 10 minutes and counting files missing
that are still settling, they reach 50 files, or 10 files that are at least half of the files
in the folder. A deletion whose content is still in
the folder (a move or a rename) is never held or counted. While any row is held, every further
inferred deletion joins the hold. A held file that comes back (or a different file saved at its
place, which is an edit as ever) leaves the hold. Turning the folder off, or "Use folder again"
with a new marker, ends every hold with nothing removed. The hold survives restarts (Drop index
schema 5). Copy "Deleted from your folder · kept until you choose", spoken "Deleted from your
Wildbloom folder. Kept until you choose.", warning icon, no Share, `inWatchFolder` false. Menu:
"Put Back" ("Put back" off macOS), "Save a Copy…", "Remove…". Put Back sends
`resolve_held_removals` with that one id and `put_back`, then the notice "Putting {name} back in
your Wildbloom folder."

The review dialog (from "Review…") lists the held rows the UI has, sorted by folder then name:

- Heading "{n} files were deleted from your Wildbloom folder" (1: "1 file was deleted from your
  Wildbloom folder").
- "That's more than Wildbloom removes without asking. Your other computers and your online node
  still have them." (1: "… still have it.")
- Up to 5 names as `folder/name`, then "and {k} more." when there are more.
- "If you remove them everywhere, copies in your other Wildbloom folders go to the Trash. Their
  encrypted copies and keys are deleted, which can't be undone." ("Recycle Bin" on Windows; 1:
  "If you remove it everywhere, … Its encrypted copies and key are deleted, …")
- Buttons "Put them back" (primary, focused), "Remove them everywhere" and "Decide later"
  (also Escape, which sends nothing). 1: "Put it back", "Remove it everywhere". macOS and
  GNOME: Remove · Decide later · Put back; Windows and KDE: Put back · Remove · Decide later.
- The choice sends `resolve_held_removals` with the listed ids, then the notice "Putting {n}
  files back in your Wildbloom folder." or "Removed {n} files from Wildbloom." with Rust's count.
  A row held while the dialog was open is not in the ids and stays held.

States map one to one onto the rows table in section 6.2, plus `share_owner_only` (**added**):
the approval ended before the shared copy could be deleted, so the node moved it to its owner
and only the owner can remove it. Copy "2 copies · only your online node’s owner can remove
the shared copy now", warning icon, menu as "2 copies". Shown for a day. `name` is the display name
(never a path). Rust should send at most about four `drop://file` updates a second per row.

### Files

| Command | Args | Returns |
|---|---|---|
| `add_paths` | `{ paths: string[] }` | `AddResult`. Only paths from a native drop on the Drop window in the last minute are accepted (Rust records them from the window's drop event); any other path is refused as `unreadable`, so the page cannot name a file for Drop to read. |
| `pick_files` | none (Rust opens the native picker) | `AddResult` (empty lists if cancelled) |
| `open_file` | `{ id }` | nothing. **Added.** Opens the row's file in the Wildbloom folder with the system's default app. Rejects `{ code: "not_in_folder" }` when the row has no file there; the UI then shows "That file isn't in your Wildbloom folder." |
| `reveal_file` | `{ id }` | nothing. **Added.** Shows the row's file in Finder, Explorer or the file manager. Rejects `{ code: "not_in_folder" }` as `open_file` does. `not_kept` rows count as having a file in the folder. |
| `retry` | `{ id: string \| null }` | nothing. `null` means every failed row ("Retry all"). Also used for "Copy again". |
| `copy_back` | `{ id }` | nothing |
| `save_copy` | `{ id }` | `{ folder: string }` (display name of the folder, for "Saved {name} to {folder}."), or `null` if the owner cancelled. **Changed:** Rust always opens the native save dialog; the page never names a path. |
| `resolve_held_removals` | `{ ids: string[], choice: "remove" \| "put_back" }` | `{ count: number }`, the rows it acted on. **Added.** Only rows in `ids` that are still `held` are touched. `remove` removes each one whose file is still missing from the folder as a deletion there would have been (its encrypted copies and key are deleted and the other computers move their copies to the Trash); one that came back leaves the hold and stays, and one whose place can't be read stays held and is not counted. `put_back` ends each hold and the next folder pass writes the file back at its place from its encrypted copy (never over anything). Either way the brake's 10-minute count starts again. Rejects `{ code: "bad_choice" }` for any other `choice`, and `remove` rejects `{ code: "folder_unavailable", message }` while the folder can't be found, as `remove` does. Then `drop://file` per row and `drop://status`. |
| `remove` | `{ id }` | nothing. **Added:** while the folder is on, rejects `{ code: "folder_unavailable", message }` when the row has a file in a Wildbloom folder that can't be found (removing it then would bring the file back when the folder returns), and `{ code: "trash_failed", message }` when that file could not be moved to the Trash or Recycle Bin. Nothing is removed in either case; the UI shows `message`. |

`AddResult`

```
{ added: string[],
  refused: [{ name, reason: "folder" | "too_big" | "no_space" | "unreadable", limitBytes?: number }],
  duplicates: [{ name, id }] }     // id of the existing row, which flashes
```

### First run, approval, recovery, settings

| Command | Args | Returns |
|---|---|---|
| `check_online_node` | `{ url }` | `{ ok: true, host, usedBytes, limitBytes }`. Rejects `{ code, host }` with `no_answer`, `not_a_node`, `tls` or `offline`. The UI has already refused empty and non-https input. |
| `set_online_node` | `{ url: string \| null }` | nothing. `null` is "Set up later". On first run this also writes the direct, loopback-only node settings (design question Q10) and moves `firstRun.step` on (`approve` with a URL, `recovery` without). **Changed:** a different node (or `null`) first ends every live share: the shared copy is deleted on the old node, or the deletion is queued against it. The node window's confirmation says so when rows are `shared`: "You're sharing {n} files. Their shared copies on {host} are deleted now, so their links stop working." (1 file: "You're sharing 1 file. Its shared copy on {host} is deleted now, so its link stops working."). Copies of files on the old node are kept, and Remove later deletes them there too. |
| `approve_device` | `{ bunkerUrl: string \| null, browser?: boolean }` | nothing; starts the NIP-46 approval. Rejects `{ code: "bad_link" }` or `{ code: "offline" }`. `browser: true` with a null link is reserved for the browser route and is only sent when `browserApproval` is true. |
| `renew_approval` | same as `approve_device` | nothing. Same flow, for renewals and expired approvals. |
| `approval_status` | none | `ApprovalStatus` (below). The UI calls it when the approval step opens and then once a second while waiting. |
| `cancel_approval` | none | nothing. Also called when a sheet or step is dismissed while waiting. |
| `recovery_key_for_display` | none | `{ key: string }` (the `wbk1_` string, ungrouped). |
| `save_recovery_file` | none | `{ filename: string }`, or `null` if cancelled. **Changed:** Rust always opens the native save dialog. |
| `open_drop_flow` | `{ flow: "recovery" }` | nothing. **Added**, for the node window: shows the Drop window and sends it `drop://open-flow`, so the recovery key is only ever read by the Drop window. |
| `confirm_recovery_saved` | none | nothing. Marks the key as saved and ends first run (`firstRun` becomes null). |
| `restore` | `{ recoveryKey: string \| null, recoveryFile: string \| null, url: string \| null }` | `{ next: "approve" \| "done", host?: string }`. Exactly one of `recoveryKey` and `recoveryFile` is set. `recoveryFile` is a path from `dialog.open`; Rust reads it, and uses its online node address when `url` is null. Rejects `{ code, host }` with `bad_key`, `no_answer`, `not_a_node`, `tls`, `offline`. `approve` means the new computer must be approved next; the restore itself continues in Rust after approval. |
| `set_watch_folder` | `{ enabled: boolean }` | nothing. **Changed:** the UI asks "Keep a readable copy of every file in ~/Wildbloom?" (Turn on / Cancel) before sending `enabled: true` from the Drop window or node settings. It sends `enabled: true` without asking from "Use folder again" (the folder is already on). **Added:** "Use folder again" changes nothing when the folder and its marker are back; when the marker is still missing (or another folder's), Rust clears every link and writes a new marker, so files already there are linked again by content at their place and anything else is taken in as new. No deletion is ever inferred against a recreated folder. |
| `open_watch_folder` | none | nothing |
| `set_sharing` | `{ afterDownload: "delete" \| "keep", expirySeconds: 3600 \| 86400 \| 604800 }` | nothing. **Added**, node window only: the Sharing settings, then `drop://status` with the new `sharing`. Any other value (a different string, another number, a non-integer) rejects `{ code: "bad_setting" }` and nothing is stored. Applies to files sent afterwards. |

`ApprovalStatus`

```
{ state: "idle" | "waiting" | "approved" | "failed" | "restore_failed",
  code?: "timeout" | "declined" | "wrong_owner" | "refused" | "offline"     // when failed
       | "no_files" | "wrong_key",                                          // when restore_failed
  detail?: string,          // reason text for "refused"
  ownerNpub?: string,       // the key that signed, for "wrong_owner"
  byNpub?: string,          // the approving key, when approved
  deviceNpub: string,       // this computer's public key (npub, full length)
  limitBytes: number,       // the ceiling that will be granted
  until: number }           // when the approval will end
```

After a restore, if listing or decrypting fails once the computer is approved, Rust reports
`state: "restore_failed"` with `no_files` or `wrong_key`; the UI returns to the restore screen.

### Sharing

| Command | Args | Returns |
|---|---|---|
| `share_start` | `{ id }` | the first `ShareState`, then `share://state` events. Also used for "Try again". |
| `share_again` | `{ id }` | the first `ShareState`. A fresh offer, locator and words that reuse the existing shared copy if it still exists. Used for "Share again" on a shared row and for "Start again". |
| `share_verify` | `{ id, matches: boolean }` | optionally the next `ShareState` (`sending` or `mismatch`); otherwise the event follows. |
| `share_cancel` | `{ id }` | nothing. Means "the sheet closed": Rust ends the live session, and deletes the shared copy if nothing was sent. The UI does not call it after `sent`, `downloaded` or `too_big`, and treats it as best effort. **Changed:** after `sent` it would also stop listening for the download confirmation, so closing a sent sheet must not call it. |
| `stop_sharing` | `{ id }` | nothing. Deletes the shared copy (queued until online if needed; the row shows `stop_pending`). Also stops listening for a download confirmation. |

`ShareState` (command results and `share://state` payloads, with `id` added in events)

```
{ id: string,
  state: "preparing" | "ready" | "opened" | "check" | "sending" | "sent" | "expired"
       | "wrong_words" | "mismatch" | "left" | "relay_unreachable" | "node_unreachable"
       | "downloaded",                // Added.
  progress?: number,        // preparing, 0 to 100
  link?: string,            // ready, opened, check, and wrong_words with triesLeft > 0
  words?: string[4],        // same states as link
  checkWords?: string[3],   // check
  expiresAt?: number,       // ready, opened, check: when the 600 s window ends; the UI runs the countdown
  triesLeft?: number,       // wrong_words: above 0 keeps the sheet on the link and words
  deleteAt?: number,        // sent, and downloaded with copy "kept": when the shared copy will be deleted
  awaitingDownload?: boolean,         // Added. sent: true while a download confirmation can still arrive
  afterDownload?: "delete" | "keep",  // Added. sent: the policy this share was sent with
  downloadedAt?: number,              // Added. downloaded: when the recipient confirmed it
  copy?: "deleted" | "deleting" | "kept" }   // Added. downloaded: what happened to the shared copy
```

**Added.** Download confirmation. After the recipient's receipt Rust emits `sent` with
`awaitingDownload: true` and keeps listening, in the background whether or not the sheet is
open, until the live session's deadline (the same 600 s window as the link, counted from
when it was made). The recipient's page sends one confirmation on the same encrypted channel
once it has saved the file. Then:

- Rust records the time on the share and emits `downloaded` with `downloadedAt` and `copy`,
  plus `drop://file` for the row (with `downloadedAt`), even when no sheet is open.
- With `afterDownload: "delete"` the shared copy is deleted at once (`copy: "deleted"`, row
  `sharing_ended`), or queued when the online node can't be reached (`copy: "deleting"`, row
  `stop_pending` until it is deleted, then `sharing_ended`).
- With `"keep"` it stays until `deleteAt` (`copy: "kept"`, row `shared`).

When the window ends with no confirmation, or with anything that is not a valid one (the
relay can withhold a confirmation but cannot forge one), Rust emits `sent` again with
`awaitingDownload: false` and nothing else changes: the copy stays until `deleteAt` or Stop
sharing. A missing confirmation never means anything. A missing `awaitingDownload` means
false. The listening ends with Stop sharing, Remove, Share again, an online node change or
quitting the app; it does not survive a restart, and none of these emits a further state.
A sent share that is only listening does not count as an open share for the quit
confirmation.

The UI shows "too big" itself, without a command, when `bytes > limits.shareMaxBytes`.
A command that rejects with `{ code: "node_unreachable" }` shows that state; any other
rejection shows `relay_unreachable`.

### Receiving ("Receive a file")

**Added.** A person's phone or browser sends one file straight to this computer: Drop shows a
link and four words, both people compare three check words, and the file then travels over an
encrypted WebRTC data channel. Nothing about the file is stored on any server. The Drop window
shows the sheet; a hidden window (below) does the WebRTC. Rust owns the transfer, so hiding or
closing the Drop window never ends it, and the sheet can be reopened at any time:
`receive_state` and the events bring it back to where the transfer is. One receive runs at a
time.

| Command | Args | Returns |
|---|---|---|
| `receive_start` | none | the first `ReceiveState` (`preparing`), then `receive://state` events. Rejects `{ code: "busy" }` while a receive is running (until its final state) and `{ code: "node_unreachable" }` when there is no online node this computer is approved for. Also "Try again" and "Start again" after any final state. |
| `receive_state` | none | the current `ReceiveState`, or `{ state: "idle" }` when nothing has run since Drop started. Call it when the sheet opens or the window loads, then follow the events. |
| `receive_verify` | `{ matches: boolean }` | nothing. The owner's answer in `check`. The next state follows as an event. Ignored in any other state. |
| `receive_consent` | `{ accept: boolean }` | nothing. The owner's answer in `consent`. `false` ends in `declined` (no connection is made and nothing reaches a relay). Ignored in any other state. |
| `receive_cancel` | none | nothing. Ends the receive at any stage before `kept`: the other person is told and anything partly received is deleted. The sheet's Cancel and Stop buttons call it; closing or hiding the window does not. Best effort; harmless when nothing runs. A file already kept stays kept. |
| `receive_add_to_wildbloom` | `{ id }` (the `id` of a `kept` state) | `{ name: string, folder: string }`: the name the file took in the Wildbloom folder (a taken name gets " (2)", " (3)" … before the extension) and the folder for display ("~/Wildbloom"). The file is moved, so the folder mirror takes it in as the owner's own and it syncs like any other. Rejects `folder_off` (the Wildbloom folder is not turned on: offer to turn it on), `folder_unavailable` (it can't be found), `cannot_sync` (an empty file, or a name the folder ignores such as one ending in `.part`), `not_found` (the file is no longer where it was kept, or Drop has restarted since) or `move_failed`. |
| `receive_reveal` | `{ id }` | nothing. "Show in Finder" (macOS), "Show in Explorer" (Windows) or "Show in Folder" (Linux) for the kept file, wherever Add to Wildbloom moved it. Rejects `not_found` as above. |
| `set_receiving` | `{ hideAddress: boolean }` | nothing. **Node window only**, like `set_sharing`. Then `drop://status`. |

`ReceiveState` (command results and `receive://state` payloads)

```
{ state: "idle" | "preparing" | "waiting" | "opened" | "check" | "waiting_file" | "consent"
       | "connecting" | "receiving" | "verifying" | "kept" | "declined" | "cancelled" | "failed",
  link?: string,            // waiting, opened, check: the link to send
  words?: string[4],        // same states: the words to say another way
  expiresAt?: number,       // same states: when the 600 s window ends; the UI runs the countdown
  checkWords?: string[3],   // check
  name?: string,            // consent onwards: the file's name (kept: the name it was kept under)
  size?: number,            // consent onwards: the file's size in bytes
  type?: string,            // consent onwards: its media type
  hidden?: boolean,         // connecting, receiving: this computer's address is hidden behind the relay
  acknowledged?: number,    // receiving: envelope bytes on disk and acknowledged to the sender
  total?: number,           // receiving: the envelope's length (a little more than size)
  reconnecting?: boolean,   // connecting, receiving: the connection dropped and Drop is getting it back
  id?: string,              // kept: the handle for receive_add_to_wildbloom and receive_reveal
  path?: string,            // kept: where the file is, for display ("~/Downloads/Wildbloom Received/holiday.mp4")
  folder?: string,          // kept: the Received folder, for display
  canAdd?: boolean,         // kept: Add to Wildbloom can run now (the folder is on and found)
  by?: "you" | "them",      // cancelled
  reason?: string }         // failed, below
```

| State | Sheet (copy follows the design spec, section 8.3) |
|---|---|
| `idle` | Nothing running: "Receive a file" with a Start button. |
| `preparing` | Getting a link: a spinner. |
| `waiting` | "Send the link, say the words another way": `link` (Copy link), the four `words` (Copy words) and the countdown to `expiresAt`. Cancel. |
| `opened` | As `waiting`, plus "Someone opened your link". |
| `check` | "Do these 3 words match theirs?" with `checkWords`, Yes (`receive_verify` true) and No (false). |
| `waiting_file` | "Waiting for them to choose a file." Cancel. |
| `consent` | "They want to send you {name} ({size})." with Accept and Decline (`receive_consent`). `type` may pick an icon. Nothing has been sent yet. |
| `connecting` | "Connecting…", with `name`. `hidden` may add "Your address is hidden." `reconnecting` true: "Reconnecting…". Stop. |
| `receiving` | Progress `acknowledged / total` (never from anything else), with `name` and `size`. `reconnecting` true: "Reconnecting…" on the same bar. Stop. |
| `verifying` | "Checking the file…". Every byte has arrived; nothing can be opened yet. |
| `kept` | "Received {name}" with `path`, and "Add to Wildbloom" (shown when `canAdd`; otherwise say the Wildbloom folder is off) and "Show in Finder" (platform wording as `reveal_file`). The file is in `folder`, outside the Wildbloom folder, and is not synced until added. |
| `declined` | "You said no. Nothing was sent." |
| `cancelled` | `by: "you"`: "Stopped. Nothing was kept." `by: "them"`: "They closed the page. Nothing was kept." |
| `failed` | By `reason`, with "Start again". |

`reason` for `failed`:

| `reason` | Meaning |
|---|---|
| `node_unreachable` | The online node did not answer, or this computer is not approved there. |
| `no_turn` | The online node does not issue relay (TURN) credentials yet, so it cannot receive files directly. |
| `turn_refused`, `turn_limit` | The node refused relay credentials (`turn_limit`: too many tries this hour; try later). |
| `relay_unreachable` | The pairing relay failed. |
| `expired` | The 10-minute window ended before the file started to arrive. |
| `wrong_words` | Someone opened the link with the wrong words. The link can't be used again. |
| `mismatch` | The owner said the check words did not match. |
| `too_big` | Their file is larger than `receiving.maxBytes`. |
| `unsupported` | Their page can't use what this computer offered (for example its relay). |
| `protocol` | Something arrived that the protocol does not allow. |
| `peer_failed`, `peer_storage` | Their side failed. |
| `connect` | The two devices never connected. |
| `lost` | The connection was lost and could not be restored. |
| `verification` | The file did not check out (wrong size, damaged or not what they offered). Nothing was kept. |
| `storage` | There is no room on this computer. Nothing was kept. |
| `no_relay` | Hiding the address needs a relay and none was offered. |
| `webview` | The connection could not be set up in this app. |

An unknown `reason` falls back to a generic "Something went wrong. Nothing was kept."

## Hidden direct-send window

**Added.** For each transfer, after the owner accepts the file, Rust creates a never-shown
window, label `direct`, at `direct.html`, and destroys it when the transfer ends. It runs the
one `RTCPeerConnection` and the frame logic with the web project's TypeScript
(`src/direct/peer.ts`'s `DirectPeer` with its `buildRtcConfiguration`, and `transfer.ts`'s
`receiveEnvelope`), with a `DirectSink` that forwards to Rust. Its capability
(`capabilities/direct-window.json`) allows only listening for events and the four commands
below. The CSP is unchanged: WebKit's WebRTC needs no `connect-src` entry.

What it receives and never receives:

- It gets Drop's own TURN credential (`create.iceServers`) and the SDP. Nothing else: never the
  link, the words, the page's credential (that travels only inside the invitation) or the
  envelope key (Rust keeps it and verifies the file itself).
- It must not log a credential or an SDP, and keeps nothing in browser storage.

**Start-up.** Subscribe to `direct://peer` first, then call
`invoke("direct_peer_report", { report: { kind: "ready" } })`. Rust sends nothing before
`ready`, and gives up with `failed`/`webview` if it does not come within 20 seconds.

**Requests** arrive as the event `direct://peer`. Each has `transfer` (the transfer's `id`; send
it back in every report) and `seq` (send it back in the reply). One request is outstanding at a
time except `close`, which may come at any moment.

| `op` | Fields | What to do | Reply (`kind`) |
|---|---|---|---|
| `create` | `iceServers: [{ credential, urls, username }]`, `relayOnly: boolean`, `envelopeBytes: number`, `size: number` | `new DirectPeer({ iceServers, hide: relayOnly })`: one connection and the pre-negotiated data channel (`negotiated: true`, `id: 0`, label `wildbloom-direct/1`). Keep `envelopeBytes` and `size` for `receiveEnvelope`. Report every connection state change from now on (below). | `done`; `error` with `reason: "no-relay"` for `NoRelayError`, any other `reason` for anything else |
| `offer` | none | `peer.offer()`: the local description once gathering completes or three seconds after it starts. | `offer` with `sdp` |
| `answer` | `sdp` | `peer.applyAnswer(sdp)`, for the answer and for each restart answer. After the first, wait for the data channel: report `channel` when it opens and start `receiveEnvelope({ channel, envelopeBytes, plaintextBytes: size, sink })`. | `done` |
| `restart` | none | `peer.offer(true)`: an ICE restart offer on the same connection. The data channel carries on. | `offer` with `sdp` |
| `close` | `stop: 1 \| 2 \| 3 \| null` | If `receiveEnvelope` is still running and `stop` is set, send the STOP frame with that reason (1 when the owner cancelled, 2 for a failure Rust found, 3 when there was no room) and end it. Wait at most a second for the send buffer to drain, then close the connection. Rust destroys the window after the reply or after a second. | `done` |

**Reports** go through `invoke("direct_peer_report", { report })`, where `report` is one of:

```
{ kind: "ready" }
{ kind: "done", transfer, seq }
{ kind: "offer", transfer, seq, sdp }
{ kind: "error", transfer, seq, reason }                 // "no-relay" or a short code
{ kind: "state", transfer, state }                        // connectionState: "new" | "connecting" | "connected"
                                                          //   | "disconnected" | "failed" | "closed"
{ kind: "channel", transfer }                             // the data channel opened
{ kind: "ended", transfer, outcome }                      // receiveEnvelope settled: "kept", or the
                                                          //   TransferError kind: "cancelled" | "peer-cancelled"
                                                          //   | "peer-failed" | "peer-storage" | "protocol"
                                                          //   | "closed" | "verification" | "storage"
```

Report state changes as they happen, without judging them: Rust decides on restarts (at once
on `failed`, after 8 seconds of `disconnected`, at most five, only before the session
deadline) and gives up (90 seconds without a first connection, 45 seconds after `failed`
without recovering). A report for another transfer is ignored. The window does not run the
connection watchdog or restarts of its own.

**The sink.** `receiveEnvelope` calls the `DirectSink` in order, one step at a time:

- `write(bytes)`: `invoke("direct_sink_write", bytes, { headers: { "Wildbloom-Transfer":
  transfer, "Wildbloom-Offset": String(offset) } })`, with `bytes` the DATA frame's payload as
  a `Uint8Array` (sent as the raw request body) and `offset` the envelope bytes written before
  it (0 first). It resolves once the bytes are on disk; `receiveEnvelope` sends its ACK only
  then. Rust writes them to a private temp file in its own state folder, never under
  `~/Wildbloom`, and refuses a gap, an overlap or a byte past `envelopeBytes`.
- `end({ sha256, size })`: `invoke("direct_sink_end", { transfer, sha256, size })` with
  `sha256` as 64 lower-case hex characters. Rust checks, in order: exactly `envelopeBytes`
  arrived; the envelope opens with the key and every record authenticates, with the record
  count and padding matching its header; the metadata is the manifest exactly; the
  plaintext's size and SHA-256 are END's. It resolves once the file is kept in the Received
  folder: `receiveEnvelope` then sends KEPT.
- `abort()`: `invoke("direct_sink_abort", { transfer })`. Deletes what Rust holds. Safe to
  repeat.

Both `direct_sink_write` and `direct_sink_end` reject `{ code: "sink_failed" }` (throw an
`Error`, so `receiveEnvelope` sends STOP 2) or `{ code: "sink_storage" }` (throw
`SinkStorageError`, so it sends STOP 3). Either way Rust has already deleted the temp files.
Nothing is visible to the owner before KEPT.

## Events (Rust to webview)

| Event | Payload | Meaning |
|---|---|---|
| `drop://file` | `FileRow`, or `{ id, removed: true }` | Upsert or delete one row. |
| `drop://status` | `DropStatus` without `files` | Any change outside the rows. Merged into the UI's copy. The node window listens too. |
| `share://state` | `ShareState` with `id` | State of the open share. Ignored when no sheet is open for that `id`. |
| `receive://state` | `ReceiveState` | **Added.** The receive sheet's state, sent to the Drop window only (it carries the link and words). Sent whether or not the sheet is open. |
| `direct://peer` | a request (above) | **Added.** To the hidden `direct` window only. |
| `drop://notice` | `{ kind: "keeps_running" }` | **Added.** Shown as an inline notice, "Wildbloom keeps running. Open it again from your apps." Send it once, before hiding the window, when the window is closed on a desktop with no tray (GNOME without AppIndicator). |
| `drop://open-flow` | `{ flow: "recovery" }` | **Added.** Open the recovery key sheet ("Save recovery key again…", checkbox not required) in the Drop window. |
| `drop://drag-info` | `{ files: number, folders: number, tooBig: number }` | **Added.** The webview cannot inspect paths. When Rust receives the window's drag-enter (it carries paths) it classifies them and emits this so the overlay can say "Folders can't be added yet" or "Too big to add". `tooBig` counts files over `limits.dropMaxBytes`. Optional: without it the overlay just says "Drop to keep 2 copies". |

The UI also listens to Tauri's own `tauri://drag-enter`, `tauri://drag-leave` and
`tauri://drag-drop` (payload `{ paths }`) for the overlay and the drop itself.

## JavaScript APIs the UI uses (to wire in the capability files)

All through `withGlobalTauri` (already true). Each is optional in the sense that the UI
degrades quietly if it is missing, but the behaviours below need these permissions on the
`drop` window (and the two clipboard and dialog items on `main`).

| Global | Use | Capability |
|---|---|---|
| `__TAURI__.event.listen` | events above | `core:event:default` |
| `__TAURI__.menu.Menu`, `__TAURI__.dpi.LogicalPosition` | native row menu (`Menu.new`, `popup`), shown from the ⋯ button or right click | `core:menu:default` |
| `__TAURI__.dialog.open` | "Open recovery file" | `dialog:allow-open` (save dialogs are opened by Rust, so `dialog:allow-save` is not granted) |
| `__TAURI__.clipboardManager.writeText` | Copy link, Copy words, Copy key, Copy public key | `clipboard-manager:allow-write-text` |
| `__TAURI__.clipboardManager.readText` | **Added.** The Paste buttons (signer link, recovery key). Falls back to `navigator.clipboard.readText`, then to focusing the field so the user can press Cmd-V or Ctrl-V. | `clipboard-manager:allow-read-text` (not in the spec's list) |
| `__TAURI__.webviewWindow.WebviewWindow.getByLabel("main")` then `show()`, `setFocus()` | "Open node settings", "Settings", Cmd-, and Ctrl-, | `core:webview:allow-get-all-webviews`, `core:window:allow-show`, `core:window:allow-set-focus` (show and the webview listing are **added**). If Rust prefers, route this through a command and change `openNodeSettings` in `drop.js`. |

Keyboard: the UI handles Cmd/Ctrl-O (add files), Shift-Cmd/Ctrl-O (open the folder),
Shift-Cmd/Ctrl-S (share the focused row), Cmd/Ctrl-F (find) and Cmd/Ctrl-comma (node
settings), and blocks F5 and Cmd/Ctrl-R. Native menu accelerators that consume the same
keys are fine; a key the native menu takes never reaches the page, so nothing runs twice.

## Commands per window

Every app command is listed in the build's app manifest, so a window can call only what its
capability allows:

- **Drop window** (`capabilities/drop-window.json`): every Drop command above except
  `open_drop_flow`, `set_sharing` and `set_receiving`, and except the `direct_*` commands. No
  node settings, sharing or receiving settings, pool or updater commands. The `receive_*`
  commands also refuse `{ code: "wrong_window" }` from any other window.
- **Hidden direct-send window** (`capabilities/direct-window.json`, label `direct`): only
  `direct_peer_report`, `direct_sink_write`, `direct_sink_end` and `direct_sink_abort`, and
  listening for events (`core:event:allow-listen`, `allow-unlisten`). It cannot emit events.
  The four commands refuse `{ code: "wrong_window" }` from any other window.
- **Node window** (`capabilities/default.json`): its own node, pool and update commands, plus
  `platform_info`, `drop_status`, `check_online_node`, `set_online_node`, `approve_device`,
  `renew_approval`, `approval_status`, `cancel_approval`, `set_watch_folder`,
  `open_watch_folder`, `open_drop_flow`, `set_sharing` (**added**) and `set_receiving`
  (**added**). (`open_file` and `reveal_file` are Drop window only.) It cannot share, remove or save files, restore, or
  read or save the recovery key.

## Behaviour Rust can rely on

- On load the drop window calls `platform_info`, then `drop_status`, and subscribes to events
  before it renders, so nothing between the two is lost.
- The node window calls `drop_status` once on load (and after each of its own actions), and
  refreshes from `drop://status`. It never polls.
- First run is driven by `drop_status.firstRun.step`. The UI never skips ahead on its own,
  except that restore shows its own screen between `node` and `approve`.
- Dismissing a sheet or step while an approval is waiting calls `cancel_approval`.
- Closing the share sheet calls `share_cancel` (not after `sent` or `downloaded`).
- **Added.** The receive sheet calls `receive_state` when it opens and follows
  `receive://state`. Its Cancel and Stop buttons call `receive_cancel`; dismissing the sheet
  after a final state, or hiding the window, does not. Quitting while a receive runs asks
  "Quit and stop receiving?" ("The file they're sending won't arrive."), and Rust tells the
  other person before it exits.
