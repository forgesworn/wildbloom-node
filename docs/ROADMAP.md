# Roadmap

## Alpha, implemented

- persistent whole-blob CAS;
- strict BUD-01, BUD-02, BUD-04 and BUD-11 profile;
- stable managed Tor v3 endpoint;
- global and per-blob quotas;
- native daemon source and build/test matrix for macOS, Linux and Windows;
- live onion reachability evidence from an independent Tor client;
- two independent macOS nodes mirroring through Tor and retaining the exact
  blob after the source node stops.

## Next acceptance gates

- V4V uploads encrypted media to a Wildbloom Node and plays it from the remaining
  replica after another endpoint is unavailable;
- a Tauri tray shell bundles a verified Tor binary, sets Windows ACLs, selects a
  sensible platform data directory and survives reboot on all three operating
  systems;
- signed pin manifests record desired replica count, independent observations
  find missing copies, and repair restores the count;
- deletion, retention, rate limiting and optional paid quota have explicit
  policy and tests;
- RelaySwarm direct transfer is measured against Tor on desktop and phone before
  it becomes an optional transport adapter.

None of these should be described as shipped until its own test has run on the
named platform or independent nodes.
