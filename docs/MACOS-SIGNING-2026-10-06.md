# Mac signing acceptance, 6 October 2026

Both Node 0.3.3 Mac preview binaries have local Developer ID signed and Apple
notarised candidates. The app and DMG submissions were accepted separately;
both tickets were stapled and validated. Gatekeeper accepted both final DMGs
and their contained apps on the existing Apple Silicon development Mac.

These are new package bytes for the existing 0.3.3 binaries. Distribute them as
the separate [signed Mac preview.2](https://github.com/forgesworn/wildbloom-node/releases/tag/v0.3.3-preview.2),
with their checksums and signing evidence. Keep the `v0.3.3-preview.1` assets
unchanged for provenance and Windows/Linux downloads. Neither Mac package has
an updater signature; this is a manual-install preview, not a stable release.

## Exact inputs and results

The inputs are the public DMGs built by installer workflow `37460450117` from
`39e46f4d5802d8660ce1617956cf5ae9b6200e11`. The merged main commit
`95185d73339a6ec372c1ad0cbac1b74e48743e32` has the same source tree. Signing and
stapling modify the package bytes; the output hashes below identify the candidates.

Identity: `Developer ID Application: Epona Solutions Ltd (2GLP954N6A)`.
Existing Keychain credentials were used without exporting private keys or
reading passwords into the process environment, chat or logs.

| Architecture | Candidate SHA-256 | Evidence |
| --- | --- | --- |
| Apple Silicon | `d03616835df7c5fce531c8429c40a57733562f948f4a472e6802ec713acf743d` | [Signing and package verification](evidence/macos-signing-2026-10-06/aarch64.json) |
| Intel | `255b02b6dbb3dee1560b12a4d1298ac91f3b967a08a2c41670ac720cf1231520` | [Signing and package verification](evidence/macos-signing-2026-10-06/x64.json) |

The records include original input hashes, all four Apple submission IDs,
submission hashes, signing script hash and final stapled artifact hashes.
Developer ID team, secure timestamp and hardened runtime were checked on all
six Mach-O files: desktop, daemon, Tor, libevent, lyrebird and conjure-client.
Final images were mounted read-only and checked independently after packaging.
The signed Apple Silicon daemon's version and pool commands, plus Tor and its
bundled dylib, executed successfully. The Intel architecture and signatures
were inspected; this is not native Intel execution evidence.

## Repeat with local Keychain authority

Use Python 3.11 or newer on macOS with Xcode command-line tools. Independently
verify the source release and its checksum before passing that checksum to
the script. The output directory must not exist. Profile and identity names
are identifiers, not passwords.

```sh
python3 scripts/notarize-macos-preview.py \
  --input /path/to/verified-preview.dmg \
  --sha256 VERIFIED_INPUT_SHA256 \
  --source-commit FULL_PREVIEW_BUILD_COMMIT \
  --identity 'Developer ID Application: YOUR ORGANISATION (TEAMID)' \
  --team-id TEAMID \
  --profile YOUR_EXISTING_NOTARY_PROFILE \
  --keychain /path/to/login.keychain-db \
  --output /path/to/new-candidate-directory
```

The script verifies the input checksum before accessing credentials or mounting,
copies the app off a read-only image, signs each Mach-O file explicitly, verifies
the expected team, notarises and staples the app, then builds, signs, notarises
and staples the DMG. It retains evidence and Apple logs. An Apple timeout is
not success: use the retained submission ID with `notarytool info` before
deciding whether to retry. Failed candidates remain local for diagnosis.

See Apple's [custom notarisation workflow](https://developer.apple.com/documentation/security/customizing-the-notarization-workflow)
for Keychain profile management and submission inspection.

The hosted Tor signing helper now traverses transport subdirectories. Its
regression test compiles synthetic Mach-O files, removes their signatures and
requires the helper to sign both the top-level runtime and a nested helper
whose filename contains a space. It passed locally and is wired into macOS CI;
the new CI step must pass before merging the signing changes. The local candidate script also
passed a corrupt-input refusal check without creating output or accessing a
notarisation profile.

## Remaining gates

- Configure hosted Apple signing authority separately. GitHub currently has
  updater secret names only; local Keychain success does not configure CI.
- Verify updater signatures before offering automatic updates.
- Complete clean-machine installation, GUI startup, reboot, upgrade, uninstall
  and onion identity retention on the advertised Mac architectures. Read-only
  package checks on this development Mac do not establish these results.
- Windows signing, independent security review and physical multi-device
  recovery acceptance remain separate release gates.

Keep production promotion subject to [the release gate](RELEASE.md#release-gate).
