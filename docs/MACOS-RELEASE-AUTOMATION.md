# Automated Mac candidates and version upgrades

Mac preview signing can run on the owner's Mac independently of Windows signing.
GitHub builds the locked source on both native architectures; the local command
checks the exact successful workflow run and checkout before using the existing
Developer ID identity and notarisation Keychain profile. No credential export,
private key in GitHub, self-hosted runner or automatic publication is needed.

This follows Apple's [Developer ID notarisation flow](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution).
The [Tauri signing guide](https://v2.tauri.app/distribute/sign/macos/) describes
the separate hosted credential setup. Hosted Apple signing remains unconfigured
until those credentials are provisioned; this command automates local signing.

## Run

1. Commit matching daemon and desktop versions and lockfiles. Pass required CI.
2. Dispatch `desktop-preview.yml` at that branch and wait for the whole run to
   succeed. Retain its full source SHA and run ID. Previews remain ad-hoc inputs.
3. Use the clean checkout at that exact SHA and Python 3.11 or newer:

   ```sh
   python3 scripts/release-macos-preview.py \
     --run-id BUILD_RUN_ID --source-commit FULL_SOURCE_SHA \
     --identity 'Developer ID Application: YOUR NAME (TEAM)' \
     --team-id TEAM --profile EXISTING_NOTARY_PROFILE \
     --output /private/tmp/wildbloom-NEW-VERSION-signed \
     --allow-current-account
   ```

   An optional `--keychain` selects a non-default Keychain. Never put secrets
   into arguments. The command refuses an existing output directory. Its native
   installation harness refuses an existing Wildbloom profile or running app;
   use a disposable macOS account if you already run Wildbloom here.
4. The command downloads only the two named Mac build artifacts, signs every
   nested Mach-O, notarises/staples each app and DMG, verifies Gatekeeper and
   runs the native upgrade from checksum-pinned signed 0.3.3. It emits
   `macos-release-evidence.json`, `macos-install.json` and `SHA256SUMS`.
5. Create a draft preview whose tag targets the **binary source SHA**; attach
   both signed DMGs and the sanitised evidence/checksums. Do not attach temporary
   app profiles or logs. Do not replace published installer bytes.
6. Dispatch `macos-install.yml` with `release_tag`, `arm64_sha256` and
   `intel_sha256` copied from the verified output. Both native hosted runners
   receive checksum-verified artifacts from a separate draft-fetch job and
   exercise signed baseline-to-candidate upgrades. GitHub hides drafts from
   read-only tokens, so only the fetch-only Linux job has `contents: write`;
   it has no checkout and executes no candidate code. Mac runners keep
   read-only permissions, recheck the bytes and have no release token in the
   app's environment. Retain both reports and
   workflow/source references before publishing a preview.

The upgrade assertion compares numeric versions, checks the daemon version
matches its app bundle, and rejects same-version installs and downgrades.
Acceptance proves fresh startup, direct-mode isolation, real Tor startup,
settings/onion-key retention across replacement, normal child shutdown and
data retention on app removal. This is an explicit installed-app replacement;
it does not establish the Tauri automatic-update path or physical reboot/login
behaviour. The production all-platform signing gate is unchanged.

If Apple rejects a submission, inspect its retained log and ID. The command
stops without publication; existing output is never silently reused. The
underlying signing script retains completed and pending submission evidence.
