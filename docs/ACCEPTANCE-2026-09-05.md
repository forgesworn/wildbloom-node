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

## Shelter Kit 0.3 and current bundled runtime

The follow-up consumes Shelter Kit v0.3.0 at
`7df4ed1304e9ca77c8f446b5417f8b214f414f70` and aligns the desktop and daemon at
0.2.1. The same live Tor replication, loss/repair and identity-restart journey
passed in 56.44 seconds using Tor Expert Bundle 15.0.21 on this Mac.

The bundle's detached signature was verified against the pinned Tor Browser
Developers key before extraction. The nested macOS executables then received
ad-hoc signatures using the existing preview script so they could run locally.
This verifies the signed upstream download and preview execution; it is not a
Developer ID signature or Apple notarisation of Wildbloom Node.

The acceptance harness now fails promptly if a node exits before readiness,
instead of waiting through the Tor bootstrap timeout. Its regression passes
without starting Tor. Six daemon tests, that harness regression, six desktop
tests, formatting, Clippy and both dependency audits pass locally.

## Shelter Kit 0.4 and Node 0.2.2

The next integration uses Shelter Kit v0.4.0 and schema 5. Admission remains
disabled unless a shell explicitly supplies a filter; the existing Node
configuration therefore keeps accepting the same content. Schema-5 stores
must not be downgraded to a core that predates tombstone enforcement.

On the same Mac and verified Tor Expert Bundle 15.0.21, two fresh node
processes passed replication, deliberate destination loss, exact repair,
source shutdown and onion-identity restart in 38.98 seconds. The six daemon
tests, readiness-exit regression and six desktop tests passed, as did
formatting and workspace Clippy with warnings denied. The earlier 0.2.1
installer matrix passed all four targets in run 33934251403; the 0.2.2
installers require a separate build of this source.
