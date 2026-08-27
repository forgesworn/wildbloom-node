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

Linux releases are deliberately `.deb` and `.rpm` packages.  We don't publish
an AppImage: the current Tauri bundler path is not dependable enough on its
hosted Linux runner, and a nominally portable file which fails to start on
current distributions is worse than two honest native packages.  The headless
daemon remains an ordinary Linux binary for other package systems.

Use preview builds to find packaging and clean-machine faults.  Don't link them
from the marketing site and don't ask users to click through operating-system
trust warnings.

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

The signed release workflow refuses `workflow_dispatch` from any branch other
than `main`, refuses version drift and stops before building when a required
credential is absent.  Apple secrets are exposed only to macOS jobs and Windows
certificate secrets only to Windows jobs.  It always creates a draft release.
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
5. Install, first start, onion bootstrap, write allowlist, restart, identity
   retention, update and uninstall must run on clean machines for every named
   target.
6. Release notes must say which operating systems and architectures were
   actually exercised.  CI compilation is not device evidence.
7. Only then should the draft release be published and the marketing download
   links changed to it.

Record the commit, workflow run, Tor archive version and digest, installer
hashes, signing identities, notarisation result and clean-machine observations.
If one of those is missing, the release isn't finished.
