# Dependency risk register

`scripts/audit-dependencies.sh` fails on every RustSec vulnerability and every
new informational warning in either lockfile.

The desktop lock currently has 17 explicit informational exceptions.  Ten mark
the GTK3 Rust bindings used by Tauri's Linux WebKit shell as unmaintained.  Five
mark the old `unic-*` crates behind Tauri's URL-pattern parser as unmaintained,
and one is the proc-macro helper used by the GTK bindings.  The remaining
advisory, `RUSTSEC-2024-0429`, concerns the `glib::VariantStrIter` iterator
implementation in that same Linux-only GTK chain.

These are not hidden behind a general warning exemption.  Every advisory ID is
listed in the audit script, so an added warning fails CI.  Wildbloom does not
directly use `glib::VariantStrIter`, but transitive reachability is not proof of
non-use.  The durable fix is an upstream Tauri/Wry Linux shell which no longer
depends on this GTK3 chain.  We should remove exceptions as soon as locked
upgrades permit it and re-evaluate the Linux desktop release if the unsoundness
becomes exploitable through ordinary WebView or tray behaviour.

## Yanked `zip` 4.6.1

The desktop lock also contains `zip` 4.6.1, pulled in by `tauri-plugin-updater`.
Every `zip` 4.x release has since been yanked, and every published updater,
including 2.14.0 and the 3.0 alphas, still requires `zip` ^4, so no locked
upgrade removes it.  There is no RustSec advisory against it.

Yanked crates cannot be ignored by advisory ID, so the audit script denies
unmaintained and unsound warnings as before and then compares the yanked list
with exactly `zip 4.6.1`.  Any other yanked crate, or a different `zip`
version, still fails CI.  Remove the exception once an updater release moves
off `zip` 4.
