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
| `drop_status` | `{ recheck?: "keychain" \| "online" }` | `DropStatus` plus `files: FileRow[]`. `recheck` asks Rust to probe again before answering ("Try again" and "Try now"). |

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
  recovery: { savedAt?: number, confirmed: boolean },
  watchFolder: { enabled: boolean, path: string },       // path is for display, for example "~/Wildbloom"
  limits: { dropMaxBytes: number, shareMaxBytes: number },
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
- The status line (spec 6.1) is resolved in `drop.js` from these fields and the rows, in the
  priority order of the spec. The tray tooltip and menu status item (Rust) must resolve the
  same order from the same data; the copy is in section 6.1 of the design spec.

`FileRow`

```
{ id: string, name: string, bytes: number, added: number,
  state: "encrypting" | "queued" | "copying" | "two_copies" | "no_online" | "waiting" | "failed"
       | "missing_online" | "online_full" | "missing_local" | "restoring" | "shared"
       | "stop_pending" | "sharing_ended" | "unreadable",
  progress: number | null,         // 0 to 100, for encrypting, copying, restoring
  sharedUntil?: number,            // state "shared"
  sharingEnded?: number,           // state "sharing_ended" (shown for 24 h)
  inWatchFolder?: boolean }        // adds a line to the Remove confirmation
```

States map one to one onto the rows table in section 6.2. `name` is the display name
(never a path). Rust should send at most about four `drop://file` updates a second per row.

### Files

| Command | Args | Returns |
|---|---|---|
| `add_paths` | `{ paths: string[] }` | `AddResult` |
| `pick_files` | none (Rust opens the native picker) | `AddResult` (empty lists if cancelled) |
| `retry` | `{ id: string \| null }` | nothing. `null` means every failed row ("Retry all"). Also used for "Copy again". |
| `copy_back` | `{ id }` | nothing |
| `save_copy` | `{ id, path: string \| null }` | `{ folder: string }` (display name of the folder, for "Saved {name} to {folder}."). The UI passes the path from `dialog.save` when that plugin is available; `null` means Rust should open the native save dialog itself. |
| `remove` | `{ id }` | nothing |

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
| `set_online_node` | `{ url: string \| null }` | nothing. `null` is "Set up later". On first run this also writes the direct, loopback-only node settings (design question Q10) and moves `firstRun.step` on (`approve` with a URL, `recovery` without). |
| `approve_device` | `{ bunkerUrl: string \| null, browser?: boolean }` | nothing; starts the NIP-46 approval. Rejects `{ code: "bad_link" }` or `{ code: "offline" }`. `browser: true` with a null link is reserved for the browser route and is only sent when `browserApproval` is true. |
| `renew_approval` | same as `approve_device` | nothing. Same flow, for renewals and expired approvals. |
| `approval_status` | none | `ApprovalStatus` (below). The UI calls it when the approval step opens and then once a second while waiting. |
| `cancel_approval` | none | nothing. Also called when a sheet or step is dismissed while waiting. |
| `recovery_key_for_display` | none | `{ key: string }` (the `wbk1_` string, ungrouped). |
| `save_recovery_file` | `{ path: string \| null }` | `{ filename: string }`. `null` means Rust opens the native save dialog; the UI passes the chosen path when `dialog.save` exists. |
| `confirm_recovery_saved` | none | nothing. Marks the key as saved and ends first run (`firstRun` becomes null). |
| `restore` | `{ recoveryKey: string \| null, recoveryFile: string \| null, url: string \| null }` | `{ next: "approve" \| "done", host?: string }`. Exactly one of `recoveryKey` and `recoveryFile` is set. `recoveryFile` is a path from `dialog.open`; Rust reads it, and uses its online node address when `url` is null. Rejects `{ code, host }` with `bad_key`, `no_answer`, `not_a_node`, `tls`, `offline`. `approve` means the new computer must be approved next; the restore itself continues in Rust after approval. |
| `set_watch_folder` | `{ enabled: boolean }` | nothing |
| `open_watch_folder` | none | nothing |

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
| `share_cancel` | `{ id }` | nothing. Means "the sheet closed": Rust ends the live session, and deletes the shared copy if nothing was sent. The UI does not call it after `sent` or `too_big`, and treats it as best effort. |
| `stop_sharing` | `{ id }` | nothing. Deletes the shared copy (queued until online if needed; the row shows `stop_pending`). |

`ShareState` (command results and `share://state` payloads, with `id` added in events)

```
{ id: string,
  state: "preparing" | "ready" | "opened" | "check" | "sending" | "sent" | "expired"
       | "wrong_words" | "mismatch" | "left" | "relay_unreachable" | "node_unreachable",
  progress?: number,        // preparing, 0 to 100
  link?: string,            // ready, opened, check, and wrong_words with triesLeft > 0
  words?: string[4],        // same states as link
  checkWords?: string[3],   // check
  expiresAt?: number,       // ready, opened, check: when the 600 s window ends; the UI runs the countdown
  triesLeft?: number,       // wrong_words: above 0 keeps the sheet on the link and words
  deleteAt?: number }       // sent: when the shared copy will be deleted
```

The UI shows "too big" itself, without a command, when `bytes > limits.shareMaxBytes`.
A command that rejects with `{ code: "node_unreachable" }` shows that state; any other
rejection shows `relay_unreachable`.

## Events (Rust to webview)

| Event | Payload | Meaning |
|---|---|---|
| `drop://file` | `FileRow`, or `{ id, removed: true }` | Upsert or delete one row. |
| `drop://status` | `DropStatus` without `files` | Any change outside the rows. Merged into the UI's copy. The node window listens too. |
| `share://state` | `ShareState` with `id` | State of the open share. Ignored when no sheet is open for that `id`. |
| `drop://notice` | `{ kind: "keeps_running" }` | **Added.** Shown as an inline notice, "Wildbloom keeps running. Open it again from your apps." Send it once, before hiding the window, when the window is closed on a desktop with no tray (GNOME without AppIndicator). |
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
| `__TAURI__.dialog.save`, `.open` | recovery file, "Save a copy", "Open recovery file" | `dialog:allow-save`, `dialog:allow-open` |
| `__TAURI__.clipboardManager.writeText` | Copy link, Copy words, Copy key, Copy public key | `clipboard-manager:allow-write-text` |
| `__TAURI__.clipboardManager.readText` | **Added.** The Paste buttons (signer link, recovery key). Falls back to `navigator.clipboard.readText`, then to focusing the field so the user can press Cmd-V or Ctrl-V. | `clipboard-manager:allow-read-text` (not in the spec's list) |
| `__TAURI__.webviewWindow.WebviewWindow.getByLabel("main")` then `show()`, `setFocus()` | "Open node settings", "Settings", Cmd-, and Ctrl-, | `core:webview:allow-get-all-webviews`, `core:window:allow-show`, `core:window:allow-set-focus` (show and the webview listing are **added**). If Rust prefers, route this through a command and change `openNodeSettings` in `drop.js`. |

Keyboard: the UI handles Cmd/Ctrl-O (add files), Shift-Cmd/Ctrl-O (open the folder),
Shift-Cmd/Ctrl-S (share the focused row), Cmd/Ctrl-F (find) and Cmd/Ctrl-comma (node
settings), and blocks F5 and Cmd/Ctrl-R. Native menu accelerators that consume the same
keys are fine; a key the native menu takes never reaches the page, so nothing runs twice.

## Behaviour Rust can rely on

- On load the drop window calls `platform_info`, then `drop_status`, and subscribes to events
  before it renders, so nothing between the two is lost.
- The node window calls `drop_status` once on load (and after each of its own actions), and
  refreshes from `drop://status`. It never polls.
- First run is driven by `drop_status.firstRun.step`. The UI never skips ahead on its own,
  except that restore shows its own screen between `node` and `approve`.
- Dismissing a sheet or step while an approval is waiting calls `cancel_approval`.
- Closing the share sheet calls `share_cancel` (not after `sent`).
