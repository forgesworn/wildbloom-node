# Release process

I don't want an installer with a green GitHub tick and no evidence that the
thing a user downloaded was actually signed.  Wildbloom keeps preview builds
and production releases separate for that reason.

## Unsigned preview

The `Desktop preview installers` workflow builds the locked source on Linux
x64, Windows x64, Intel macOS and Apple Silicon macOS.  It downloads the exact
pinned Tor Expert Bundle for each target, verifies the detached signature and
keeps the result as a short-lived workflow artefact.  It does not create a
GitHub release.  The artefact name says `unsigned-preview` because that is what
it is.  On fresh hosted Linux and Windows runners it also installs the generated
package, starts the installed app through Tor, checks the packaged Blossom
service and single-instance behaviour, stops the process tree and uninstalls.
On both hosted Mac architectures, the [installation harness](MACOS-INSTALL-ACCEPTANCE.md)
exercises fresh startup and direct mode with the candidate, then installs a
checksum-pinned signed baseline, starts Tor, replaces it with the new DMG,
verifies settings/onion identity retention and
removes the app. It distinguishes a same-version reinstall from a cross-version
replacement and retains sanitised evidence; reboot, interactive UI and automatic
update acceptance remain separate.

Linux releases are deliberately `.deb` and `.rpm` packages.  We don't publish
an AppImage: the current Tauri bundler path is not dependable enough on its
hosted Linux runner, and a nominally portable file which fails to start on
current distributions is worse than two honest native packages.  The headless
daemon remains an ordinary Linux binary for other package systems.

Use preview builds to find packaging and clean-machine faults. Marketing links
must label published previews accurately, including their missing trust gates;
never present them as trusted installers or advise bypassing OS trust checks.

A preview may have verified platform signatures without meeting the production
gate below. The [0.3.3 signed Mac preview](MACOS-SIGNING-2026-10-06.md) follows
this path: publish separately, retain exact input/output hashes and signing
evidence, label the remaining acceptance gaps, and keep automatic updates off.
Signing existing binaries does not change their source commit; the release tag
must identify the original build source, with signing-tool provenance recorded
separately. Never overwrite an earlier preview's installer bytes.

## Production credentials

A production release needs three different authorities:

- the Wildbloom updater private key, held as encrypted GitHub secrets, signs
  every updater artefact and both standalone Linux packages;
- a Developer ID Application certificate plus Apple notarisation credentials
  signs and notarises both macOS builds;
- a trusted Windows code-signing certificate signs the Windows executable and
  installers, with a timestamp from the certificate provider.

The updater key is ours to create.  Apple and Windows trust comes from their
certificate programmes.  An Apple Development or ad-hoc identity is useful for
testing and still isn't a public Developer ID release.  A self-signed Windows
certificate proves only that we can sign our own file.  It doesn't remove the
SmartScreen trust boundary.

Never commit a private key, certificate archive, password, app-specific Apple
password, Azure credential or onion-service key.  The public updater key and
certificate thumbprints are safe to commit.

The encrypted updater key is held outside the repository and the public half
is pinned in `desktop/src-tauri/tauri.conf.json`.  GitHub Actions needs these
repository secrets:

```text
TAURI_SIGNING_PRIVATE_KEY
TAURI_SIGNING_PRIVATE_KEY_PASSWORD
APPLE_CERTIFICATE
APPLE_CERTIFICATE_PASSWORD
APPLE_SIGNING_IDENTITY
APPLE_ID
APPLE_PASSWORD
APPLE_TEAM_ID
WINDOWS_CERTIFICATE
WINDOWS_CERTIFICATE_PASSWORD
WINDOWS_TIMESTAMP_URL
```

Run `node scripts/check-signing-readiness.mjs` to inspect configured secret names
without reading values. A configured name does not prove a credential is valid.
On 6 October 2026 only the updater secret names were configured. A later scan
of the user Keychain search list found a working local notarisation profile in
the login Keychain. Both Mac 0.3.3 candidates were then signed with Developer ID,
accepted by Apple and stapled. See [the exact candidate evidence](MACOS-SIGNING-2026-10-06.md).
Local signing authority does not establish hosted CI authority.

For Apple, use the existing Developer ID Application identity if authorised for
this product and configure the six Apple secrets above through the GitHub secret
UI or a private local file/stdin. Never paste private material into chat, command
arguments, PRs or logs. The certificate archive must include its private key;
notarisation uses an Apple app-specific password with the corresponding team.
Do not export every identity from a developer Keychain to obtain this one.

For Windows, first identify the trusted signing provider. The current workflow
supports a provider-authorised importable PFX plus an RFC 3161 timestamp URL.
Hardware-backed certificates or cloud signing need that provider's Tauri
`signCommand` integration; do not export hardware-protected keys or substitute
a self-signed certificate. A new trusted signature can still encounter
SmartScreen reputation warnings. See the official
[Tauri Windows signing guide](https://v2.tauri.app/distribute/sign/windows/) and
[macOS signing guide](https://v2.tauri.app/distribute/sign/macos/).

The signed release workflow refuses `workflow_dispatch` from any branch other
than `main`, refuses version drift and stops before building when a required
credential is absent. A preflight checks all platforms before any platform
creates a draft. Windows daemon/Tor executables are signed and checked before
bundling; installer checks require the configured signer and a timestamp.
`wildbloom-release-verify` streams each macOS/Windows updater artifact through
minisign verification against the public key pinned in source. Its tests reject
modified artifact bytes and a wrong key; signature-file existence is insufficient.  After the read-only credential preflight, platform build jobs receive only
their own Apple or Windows signing credentials.  It always creates a draft release.
Linux `.deb` and `.rpm` files get detached minisign signatures made with the
same separately held release key.  They are installed or replaced explicitly;
we do not advertise Tauri's AppImage-only Linux auto-update path.

## Release gate

Before a draft can become public:

1. `main` must be clean, aligned with its reviewed pull request and green on the
   daemon, desktop, audit and real-Tor gates.
2. The source version must match the intended tag and changelog.
3. Every platform build must use a signature-verified pinned Tor archive and
   the locked Rust dependencies.
4. macOS signatures, notarisation and stapling must verify.  Windows
   Authenticode status must be valid.  Updater signatures must verify on macOS
   and Windows; the detached signatures on both Linux packages must verify.
5. Install, first start, direct local mode, onion bootstrap, transport switching,
   write allowlist, restart, identity retention, update and uninstall must run
   on clean machines for every named target.  Direct mode must prove that no
   Tor child starts; Tor mode must retain its onion identity.
6. Release notes must say which operating systems and architectures were
   actually exercised.  CI compilation is not device evidence.
7. Only then should the draft release be published and the marketing download
   links changed to it.

Record the commit, workflow run, Tor archive version and digest, installer
hashes, signing identities, notarisation result and clean-machine observations.
If one of those is missing, the release isn't finished.
