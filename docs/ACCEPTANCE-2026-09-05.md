# Shared-core integration acceptance, 5 September 2026

The `chore/shared-core-upgrade` change consumes Shelter Kit v0.2.2 at
`4407ec3f0281edf527681deffd26384485dfea94`, replacing v0.1.2. The lockfile
uses one ring TLS provider; local CLI friend grants have no delegated issuer.

On macOS 14.6.1 (23G93), Rust 1.94.1:

- Formatting, workspace Clippy with warnings denied, six daemon tests and
  six desktop tests passed. Both dependency lockfiles passed the repository's
  audit policy.
- The real Tor acceptance passed in 331.36 seconds, using two fresh isolated
  node stores and `/opt/homebrew/bin/tor`. It verified replication, deliberate
  destination blob loss, exact-byte repair, source shutdown, and destination
  restart retaining its onion identity. Onion publication took several minutes;
  the bounded retry completed without restarting the test.

Reproduce the network acceptance with:

```sh
WILDBLOOM_TEST_TOR_BIN=/path/to/tor cargo test --locked \
  -p wildbloomd --test tor_replication -- --ignored
```

This is live Tor replication between isolated node processes on one Mac.
Trusted installer signatures, clean retail machines, independent physical-node
custody and the advertised platform installer matrix remain separate gates.
