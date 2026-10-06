# Mac installation and replacement acceptance

`Signed Mac installation acceptance` runs the published, checksum-pinned
`v0.3.3-preview.2` DMG on fresh Apple Silicon and Intel GitHub runners. It runs
on changes to its harness, after merge, and on manual dispatch. The preview and
signed release workflows also run this harness with their newly built DMG as
the replacement candidate and the published signed preview as the baseline.

The harness copies the real app from a read-only DMG into a disposable
`Applications` directory, executes its production binary and bundled services,
quits through the normal macOS application event, replaces the app, then removes
it. First-launch and direct-mode checks use the candidate. A second empty profile
lets the baseline create its own database and onion identity before replacement;
this avoids inadvertently checking a database downgrade. No acceptance feature
is compiled into the package and no signature is
modified. Signed inputs require Gatekeeper acceptance and stapled tickets;
preview candidates explicitly use `--candidate-adhoc`, which checks signatures
but does not claim Developer ID trust. The baseline always requires trust checks.

## Checks

- First launch waits for an explicit transport choice without starting children.
- With explicitly seeded synthetic settings, direct mode reaches loopback
  Blossom health, honours quota and writer configuration, and creates no Tor state.
- Tor mode runs the packaged runtime, bootstraps and reaches Blossom health.
- Settings, database and onion secret key have private file permissions.
- Normal application quit stops its observed child processes.
- Replacing the bundle and starting it again preserves settings and the onion
  public/secret keys and hostname; hashes are compared only in memory.
- Removing the app preserves the operator profile and its onion identity.

Evidence records both installer hashes, versions, host architecture, completed
checks and limits. If the versions match, it says **same-version reinstall**.
Different versions are labelled **cross-version replacement**. Neither result
proves the automatic updater works. Workflow artefacts contain sanitised JSON
only: no raw logs, onion addresses, onion key hashes or operator state.

## Run locally

Use Python 3.11 or newer in a disposable macOS account. The harness refuses any
existing Wildbloom profile or running installed Wildbloom app. It does not change
`HOME`, move existing profiles or change login-item settings. It creates a fresh
profile at the app's normal path, checks that app removal preserves it, then
removes only that test-created profile during cleanup. It launches a visible app
and makes real Tor connections after explicitly selecting Tor in test settings.

Reinstall the public signed preview:

```sh
python3 scripts/accept-desktop-macos-bundle.py --output /tmp/macos-install.json
```

Test a newly built preview against the signed baseline:

```sh
python3 scripts/accept-desktop-macos-bundle.py \
  --bundle desktop/src-tauri/target/aarch64-apple-darwin/release/bundle \
  --candidate-adhoc --output /tmp/macos-candidate.json
```

Omit `--candidate-adhoc` for a signed candidate. For another trusted baseline,
use `scripts/accept-desktop-macos.py --help` and provide both DMGs and their exact
SHA-256 digests, a new output path and `--allow-current-account` explicitly.
Never run two harness instances concurrently in the same account.

## Remaining physical and interactive gates

This is process/service acceptance of the installed release binary. It does
not inspect rendered UI or click settings controls. Settings are seeded while
the app is stopped; the separate native pool suite exercises desktop IPC/UI.
It does not reboot the machine, exercise start-at-login, test an automatic
update, prove an onion can be reached from another device, or establish
independent physical-device acceptance. Keep those release gates open.

## Recorded run

On 7 October 2026 the complete signed-preview reinstall passed on the existing
Apple Silicon development Mac, including real Tor bootstrap before and after
replacement. [Sanitised local evidence](evidence/macos-install-2026-10-07/local-arm64.json)
records the exact published DMG hash and scope. This is a fresh app profile on
an existing development machine, not a newly installed OS. The harness source
is versioned alongside this evidence; `harness_commit` is null for this local
pre-commit run. Hosted runs record their exact `GITHUB_SHA` separately.
