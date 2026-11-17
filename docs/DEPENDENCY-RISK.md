# Dependency risk register

`scripts/audit-dependencies.sh` fails on every RustSec vulnerability and every
new informational warning in either lockfile.

## Chrono maintenance in the pinned dependencies

RUSTSEC-2026-0543, issued after the previous release, marks all Chrono versions
as unmaintained; it does not identify a vulnerability or offer a patched
version. The headless lock uses Chrono 0.4.45 solely through `toll-booth` 0.2.1
at `acd8b1495b4033fcbf3156b9f32d70fcabec74fa`. That dependency uses it for
timestamps, quota dates and expiry parsing. Replacing its public date/time
types is separate upstream work and must retain expiry/refusal behaviour.

The headless audit temporarily accepts only this maintenance advisory. It first
checks the exact version, direct dependency and pinned revision with `cargo tree`;
a changed consumer or source fails closed. Other Chrono advisories still fail.
Remove the exception when Toll Booth replaces Chrono.

The desktop lock also includes Chrono 0.4.45, through `serde_with` 3.22.0's
optional Chrono support. Tauri's current feature selection does not activate
that support (`cargo tree --target all --all-features --invert chrono` prints
no dependency). The desktop audit checks the exact locked version and sole
consumer before accepting this maintenance advisory. Remove it when
`serde_with` replaces Chrono. These exceptions accept a maintenance risk;
neither suppresses a Chrono vulnerability.

RUSTSEC-2026-0486 is fixed by locking Rustix 1.1.6 in both products. The older
0.38 line also present in the desktop is unaffected. No exception covers it.

The desktop also locks `quinn-udp` 0.5.16 for RUSTSEC-2026-0538 and moves the
yanked `nostr-connect` 0.45.2 to 0.45.3, retaining the same TLS features.

Besides Chrono, the desktop lock has 20 explicit informational exceptions. Ten mark
the GTK3 Rust bindings used by Tauri's Linux WebKit shell as unmaintained.  Five
mark the old `unic-*` crates behind Tauri's URL-pattern parser as unmaintained,
and one is the proc-macro helper used by the GTK bindings.  The remaining
advisory, `RUSTSEC-2024-0429`, concerns the `glib::VariantStrIter` iterator
implementation in that same Linux-only GTK chain.

The last three, `RUSTSEC-2026-0370`, `-0371` and `-0372`, mark `zvariant`,
`zbus_names` and `zvariant_derive` as unmaintained because they were folded
into `zbus` 6.  They come from `zbus` 5 behind `keyring`'s Linux
secret-service store and `tauri-plugin-single-instance`; they report no
vulnerability.  Remove them once both move to `zbus` 6.

These are not hidden behind a general warning exemption.  Every advisory ID is
listed in the audit script, so an added warning fails CI.  Wildbloom does not
directly use `glib::VariantStrIter`, but transitive reachability is not proof of
non-use.  The durable fix is an upstream Tauri/Wry Linux shell which no longer
depends on this GTK3 chain.  We should remove exceptions as soon as locked
upgrades permit it and re-evaluate the Linux desktop release if the unsoundness
becomes exploitable through ordinary WebView or tray behaviour.

## Updater archive support is off

`tauri-plugin-updater` is built with `default-features = false` and only
`rustls-tls`, which leaves out its `zip` feature and with it `zip` 4.x
(yanked, and vulnerable to RUSTSEC-2026-0367, -0368 and -0369 with no 4.x
fix).  That feature only unpacks Tauri v1-style update archives: `.zip` on
Windows and gzipped AppImages on Linux.  Release builds set
`createUpdaterArtifacts: true`, so Windows updates are the signed NSIS or MSI
installer itself, macOS updates are `.app.tar.gz` (unpacked by the plugin
without this feature), and Linux ships no updater artifacts.  Do not switch
to `v1Compatible` artifacts without turning the feature back on and
re-auditing `zip`.  The audit script now fails on any yanked crate.

## The webpki-roots 0.26 shim

`tokio-tungstenite` (in `wildbloomd`, and through `nostr-sdk` in the desktop)
still depends on `webpki-roots` 0.26.11.  That release is a semver shim: it
depends on `webpki-roots` 1 and re-exports it, so its root certificates are
whichever 1.x is locked.  RUSTSEC-2026-0381 (distrusted emSign intermediates)
is fixed in 1.0.10 but flags the shim by its version number.  The audit
script ignores that one advisory only after checking that every locked
`webpki-roots` in both lockfiles is the 0.26.11 shim or 1.0.10 or later, so a
locked 1.x older than the fix still fails CI.  Drop the ignore once neither
lockfile contains 0.26.11.
