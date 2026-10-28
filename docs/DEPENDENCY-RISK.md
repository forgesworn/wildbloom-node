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

## crypto-bigint 0.5 timing advisory

RUSTSEC-2026-0387 reports secret-dependent branches in several crypto-bigint
operations meant to be constant time; it is fixed in 0.7.6 and 0.5.x gets no
fix.  `wildbloomd` locks crypto-bigint 0.5.5 only through `wildbloom-checkout`
-> `lnurlcash-core` -> `k256` 0.13 (`elliptic-curve` 0.13).  `k256` does its
own field and scalar arithmetic; crypto-bigint sits underneath the
`elliptic-curve` scalar primitives and `Reduce<U256>`, which `lnurlcash-core`
uses when it reduces a Schnorr tweak.  Exploiting the leak needs fine-grained
timing of those operations on the node, so the audit script ignores this one
advisory for the root lockfile.  The desktop lockfile does not contain
crypto-bigint.  Drop the ignore once `lnurlcash-core` moves to `k256` 0.14,
which uses the fixed crypto-bigint line, and Wildbloom pins that revision.
