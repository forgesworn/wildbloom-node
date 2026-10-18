# Dependency risk register

`scripts/audit-dependencies.sh` fails on every RustSec vulnerability and every
new informational warning in either lockfile.

The desktop lock currently has 20 explicit informational exceptions.  Ten mark
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
