# Security policy

Wildbloom Node is a production candidate and has not received an independent
security audit.  Do not expose valuable unencrypted material until you have
reviewed the current limitations.

Please report vulnerabilities through GitHub's private vulnerability reporting
for `forgesworn/wildbloom-node`.  If that is unavailable, contact the maintainer
privately rather than opening a public issue.  Include the affected revision,
platform, reproduction and likely impact.  We will acknowledge a useful report
as soon as practical and coordinate disclosure after a fix is available.

Never include real Nostr secret keys, Tor onion private keys, access tokens or
private blobs in a report.

Only the latest signed release and the latest `main` revision are supported.
Unsigned preview installers are test artefacts, not supported releases.
