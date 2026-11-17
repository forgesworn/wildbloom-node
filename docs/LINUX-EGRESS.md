# Optional Linux outbound network guard

The mirror fetcher already rejects non-public direct destinations and redirects.
This additional nftables guard confines the headless daemon's outbound traffic,
including other HTTP clients, to public addresses and explicit local services.
It is opt-in: inspect the operator's actual dependencies before enabling it.

Use a dedicated, unprivileged service account. The guard matches its numeric
socket UID, so it also affects other processes running as that account. Do not
use it for a shared account, root, rootless Podman or a container without first
establishing the correct network boundary. It does not change other UIDs,
forwarded container traffic or other firewall tables. Existing host firewall
rules still apply; an exception here cannot override another firewall's deny.

Replies to incoming connections remain allowed, including reverse-proxy reads.
New outgoing connections to loopback, private, link-local, metadata, shared,
reserved and the host's own addresses are refused. IPv6 is limited to public
unicast, excluding documentation, Teredo and 6to4 ranges. Public outgoing
connections remain available for configured HTTPS mirror/repair, checkout and
discovery services. A proxy or allowed local service remains its own trust
boundary: the guard cannot inspect where that service subsequently connects.

## Configure and check

1. Inspect `systemctl show wildbloom-node -p User -p ExecStart`, `id -u` for that
   account, the effective configuration and `/etc/resolv.conf`. Do not print
   operator tokens, keys or bearer events. Identify actual outbound connections.
2. Copy `deploy/linux/egress.example.json` to a private operator path. Replace
   its example UID. Add only the exact local address/port each enabled service
   needs: pairing, a Tor SOCKS listener, payment backend or a private signer.
   Unused services need no exception. List the actual DNS resolver addresses;
   only TCP/UDP port 53 is permitted to those addresses. Do not allow a whole
   private subnet or all of loopback for convenience.
3. Render without applying anything:

   ```sh
   python3 scripts/render-egress-policy.py --config /private/egress.json > /private/egress.nft
   sudo nft --check --file /private/egress.nft
   ```

4. Run `sudo python3 scripts/test-egress-policy.py` on Linux. It uses disposable
   network namespaces and synthetic listeners: proves baseline reachability,
   blocks seven destinations, retains public IPv4/IPv6, local pairing and DNS,
   verifies responses to a private reverse proxy, leaves other UIDs unaffected
   and exercises an atomic reload. It removes its fixtures and namespaces.
   No test traffic leaves the disposable network.

## Apply and persist

Keep a private backup of any existing files. Set a short automatic rollback
before applying the rules remotely, then cancel it only after live verification.
For an initial installation, rollback deletes just the `wildbloom_egress` table;
for replacement, restore the saved rules instead. Never flush the host ruleset.

Install the reviewed rules at `/etc/wildbloom-node/egress.nft` (root-owned,
mode 0600), the supplied service in `/etc/systemd/system/`, and
`deploy/linux/egress-dependency.conf` at
`/etc/systemd/system/wildbloom-node.service.d/egress.conf`. Run:

```sh
sudo systemctl daemon-reload
sudo systemctl start wildbloom-egress.service
```

The running daemon need not restart. The dependency starts the guard before the
daemon after boot and fails startup if rule loading fails. Each nft batch
atomically replaces only our table. Use `systemctl reload wildbloom-egress` to
apply a reviewed update. Stopping the guard unit leaves rules installed; an
explicit rollback must remove or restore them. A full host firewall reset can
remove the table: reload the guard after such maintenance and verify its rules.

Verify health, existing-blob GET/HEAD/ranges and hashes, rejection of unauthorised
writes, pairing and DNS. Test a synthetic connection as the daemon UID against
an unapproved local port and confirm rejection. Payment and signer calls need
their existing synthetic acceptance checks; do not make a real payment just to
test this guard. Inspect `nft list table inet wildbloom_egress` for rule counters.

For first-install rollback, remove only the new dependency file, reload systemd,
stop the oneshot unit, then run `nft delete table inet wildbloom_egress`.
Retain private deployment evidence outside the served data directory.
