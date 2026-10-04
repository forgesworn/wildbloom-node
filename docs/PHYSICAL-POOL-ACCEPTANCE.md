# Physical pool recovery acceptance

Prepared for the 0.3.0 desktop preview. **Not yet performed.** Only the owner's
Mac is currently available. Automated local-process and hosted-runner results
must be recorded separately; they cannot fill in this checklist.

## Equipment and boundaries

Use a disposable, non-sensitive source file and a designated test signing
identity. Do not put secret keys, recovery keys, receipt JSON, endpoint addresses
or private node state in public evidence. Record build hashes, public test
identity fingerprints, file lengths/hashes, OS versions and outcomes only.

Minimum setup: owner Mac plus separate storage machines or sites. For a 2-of-4
pool test use four independently managed storage destinations in four declared
failure groups. Distinct processes or DNS names on one machine are not physical
independence. Two nodes sharing power/network/storage belong to the same failure
group. Keep the owner repair machine separate from part holders.

Before starting, back up existing node databases/configuration and onion keys.
Use fresh test data directories and account quotas. Never delete arbitrary blobs
to simulate loss: identify the fixture's exact signed part hash first. Prefer
stopping a test node or disconnecting its test network. Retain an independent
source copy, the private receipt and a separately stored file recovery key.

## Record before testing

- [ ] Exact browser, daemon and desktop source commits and installer SHA-256.
- [ ] OS/browser versions; distinguish Safari from Playwright WebKit.
- [ ] Preview signing status, packaging source and test machine identity.
- [ ] Four failure groups and their actual independent power/network/storage.
- [ ] Fresh test signer access verified without importing keys into Wildbloom.
- [ ] Direct HTTPS or Tor-only profile chosen explicitly, with no mixed fallback.
- [ ] File size, source SHA-256 and layout recorded; secrets stored separately.

## Desktop and recovery journey

1. [ ] Install the preview on the owner Mac. Start with a fresh application
   profile through an operator-controlled test account; confirm no pool network
   traffic or signer prompts before explicit actions.
2. [ ] In the browser, upload a small encrypted 2-of-4 fixture. Save its signed
   receipt and separate recovery key. Verify all four parts after upload.
3. [ ] Import the receipt in the desktop. Wrong-owner and modified-receipt
   imports must fail without contacting any node or signer.
4. [ ] Perform a read-only check. Confirm four verified parts and no signing or
   upload requests. Record the observation timestamp.
5. [ ] Stop two designated storage nodes. Repeat the check. It must report
   recoverable but underprotected; never confuse cached health with a new pass.
6. [ ] In a fresh browser session, load the saved receipt and recover using the
   two surviving parts and separate key. Compare exact source bytes/hash.
   A wrong key must fail without exposing a decrypted download.
7. [ ] Restart the two missing nodes with their same test stores. Start owner
   repair with a short, explicit authority expiry and approved external signer.
   Close the desktop window: the tray service should keep checking. Quit the
   app: owner checks/signing/uploads must stop.
8. [ ] Reopen. The imported receipt remains, but automatic repair must remain
   stopped until newly approved. Confirm a fresh check before trusting health.
9. [ ] Test genuine part loss in an isolated test store: stop that test node,
   replace only its disposable test data directory, then restart at the same
   endpoint. Repair must restore the exact part and verify it by read-back.
10. [ ] Test replacement: stop a designated node permanently, add a new approved
    destination for that part in the browser and sign/save a new receipt. Import
    it, check, and repair. The old receipt must not silently adopt the new node.
11. [ ] Lose another part after repair. Repeat fresh-browser recovery and exact
    SHA-256 comparison, then repair again. Record the actual surviving sites.
12. [ ] Stop enough nodes to drop below the threshold. The UI must report this
    and repair must not invent bytes or upload a reconstructed file.
13. [ ] Let authority expire during checking/repair. No later signer invocation
    or upload may start. Explicit stop must also cancel a deliberately slow read.
14. [ ] Reboot and reopen the desktop. Confirm stored receipt integrity and
    stopped owner authority. Test update/quit/uninstall and child cleanup on
    each advertised OS. Uninstalling software is not consent to delete backups.

## Further device and operational rows

- [ ] Repeat the recovery journey on physical iPhone/Safari and Android with the
  intended external signer, including backgrounding, cancellation and restart.
- [ ] Repeat with the maximum supported source size only on a device that can
  safely accommodate it; record memory pressure and browser/OS termination.
- [ ] Exercise the intended Tor Browser security level, new identity and timeout
  UI using real onion destinations; record direct fallback refusal separately.
- [ ] Test VoiceOver/Safari, NVDA on Windows, keyboard-only use, 200%/400% zoom
  and operating-system contrast modes with a person who did not build the UI.
- [ ] Verify Windows application-data ACLs and Unix private receipt/work modes.
- [ ] Verify trusted signing/notarisation separately before promoting previews
  to a trusted release. A passed recovery test does not establish installer trust.

## Evidence record

For each row record: date, tester, exact build/installer hash, devices/sites,
scenario, expected result, observed result and pass/fail/blocked. Attach redacted
screenshots and hashes where useful. Record failures and repairs rather than
replacing them with a later successful run. Keep private receipts, keys, signer
commands and detailed endpoint inventories outside the public evidence record.
