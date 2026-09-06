# Replica maintenance policy

Status: local implementation candidate. This is Wildbloom's local client
policy, not a Bothy pin contract or a change to the shared storage core.
Automated process acceptance is separate from physical, independent-operator,
cross-platform and release acceptance.

## Behaviour

An operator runs `wildbloomd replicas run` with an owner-signed policy and a
private state directory. The coordinator verifies complete returned bytes,
requests standard BUD-04 mirrors where a configured copy is missing, and
verifies the destination again after its acknowledgement. A successful PUT or
HEAD is never counted as a verified copy. The coordinator holds no Nostr
signing key and does not publish a policy, contact a discovery relay or choose
a default service.

The policy defines a desired number of configured failure groups. An owner
must explicitly declare which targets are owner-managed and which share a
failure group. Multiple origins in one group count once. Friend/guest targets
may be sources, but do not satisfy an owner-managed target. These declarations
are operator inputs: neither a signature nor an HTTP response proves physical
independence or future retention. Reports say `verified_configured_groups`,
with an observation time, not guaranteed durable copies.

## Signed local policy, version 1

The envelope is a canonical Nostr event of kind 30078, with exactly one `d`
tag `wildbloom.replica-policy.v1:<id>` and one `expiration` tag matching the
content's `expires_at`. Its author must match the public key supplied by the
operator. All seven signed-event fields, the event ID, signature, content
schema, bounds and transport profile are validated before network activity.

Content is JSON with `type: "wildbloom.replica-policy"`, `version: 1`, a local
`id`, positive monotonic `revision`, `expires_at`, `profile`, `desired_groups`,
`targets` and `blobs`. Each target has an `id`, canonical HTTP(S) `origin`,
`failure_group` and `retention` (`owner`, `friend` or `guest`). Each blob has
an exact lowercase `sha256` and positive `size`. Every target may supply a
source copy; only targets declared `owner` are repair destinations or count
towards the requested floor. There must be enough distinct configured owner
groups to meet the floor. No key, filename, original MIME type or arbitrary
download URL belongs in this policy.

The local app-data envelope follows [NIP-78](https://github.com/nostr-protocol/nips/blob/master/78.md).
This is not a general interchange kind, signed storage receipt or new Nostr
replication protocol. Other Blossom servers see only ordinary GET and
[BUD-04](https://github.com/hzrd149/blossom/blob/master/buds/04.md) requests.

Persist the highest accepted revision and event ID before any network action.
The same revision may be reopened only with the same event ID. An older or
conflicting revision is refused, including after restart. A changed policy
invalidates earlier pending authorisations and current observations. An absent,
invalid or expired policy stops further network work. A higher signed revision
with `desired_groups: 0` is an explicit stop policy; it never deletes replicas.

## Transport selection

- `direct-https`: public HTTPS origins only, without URL credentials, query,
  fragment or path. No onion origins, redirects, ambient proxy or private DNS
  results. The selected connection uses the vetted resolution.
- `tor-only`: checksum-valid v3 onion origins through an explicitly supplied
  loopback `socks5h` proxy. No clearnet origin or direct fallback.
- `loopback-development`: literal IPv4 loopback HTTP origins only. The operator
  must explicitly permit this development profile. It is not secure LAN
  transport and does not close the internet-disconnected physical LAN gate.

All blob URLs are constructed from a validated origin and the exact policy
hash. Requests and response bodies have deadlines and size limits. Complete
blob verification streams through a hasher; it does not allocate a blob-sized
buffer. The coordinator has bounded work per pass and retries at an explicit
interval. Unknown or stale responses never restore an old policy's consent.

The default pass budget is 8 GiB of verification reservations and four repair
attempts. Each attempted GET reserves the policy's complete blob size, including
failed requests. Each blob's full target scan plus all permitted repair
read-backs must fit the budget or the configuration is refused. A persisted
cursor rotates blobs and source/destination attempts to avoid repeatedly
spending the budget on the same failed pair. The maximum policy contains 128
blobs, 16 targets and 1 GiB per blob; one HTTP request has a 15-second connection
deadline and a ten-minute total deadline. Work is sequential and blob reads
stream through the hasher.

## Signing and authority

The signed policy is client intent, not server upload authority. Every mirror
still needs a fresh [BUD-11](https://github.com/hzrd149/blossom/blob/master/buds/11.md)
event of kind 24242, `t=upload`, scoped to the exact destination hostname and
blob hash, with a short expiry. Destination admission and quotas remain in
force. No expired bearer event is reused, and no copy is silently promoted
from a friend/guest holding into an owner-managed promise.

The unsigned request's content also binds the exact policy event ID and
configured destination origin. A return from another revision or another
origin sharing the same hostname cannot satisfy the local handoff, even in the
same second. The BUD-11 server scope itself remains the standard hostname
scope. The destination sees this policy-event identifier in its authorisation,
but never receives the local policy document.

The default signing path is a local file handoff: write the exact unsigned
event into the private state directory, report `awaiting_authorisation`, and
accept only the matching returned signed event. The coordinator does not
contact a signer in this mode. Expired or superseded requests must be signed
again. Pending files are managed state and are removed when consumed or
invalidated; no bearer event is kept in the observation log.

An optional local signer executable is separately configured by the operator
for unattended maintenance. Enabling it explicitly authorises invocation for
the selected policy's bounded repair operations. The executable receives one
unsigned event JSON on stdin and returns only its signed event on stdout.
There is no shell interpolation, key argument or network signer discovery.
Bound stdout, execution time and pending processes; discard stderr so helper
diagnostics cannot leak secrets into daemon logs. Verify signature, author,
exact unsigned fields and current policy before issuing the write.

An ordinary event signer may still require a human confirmation. The
coordinator must surface refusal/unavailability and remain below target rather
than generating or importing an identity key. This executable integration is
a local operator adapter, not a new network signer protocol or hardware proof.

## State and failure

Use a separate private state directory and an exclusive coordinator lock.
Never modify Shelter Kit's store schema. State writes are atomic and synced;
unknown/corrupt state is a refusal, not a reset of rollback protection. Bind
state to one owner and policy ID. Observations retain their timestamps across
restart, but every new maintenance pass re-verifies bytes before counting
them. Failed or budget-deferred checks do not inherit an earlier success.

Differentiate verified bytes, unavailable/invalid copies, acknowledgement
awaiting verification, awaiting authorisation, refused writes and deferred
work. Try a verified source from another configured origin and another
configured eligible destination when one is unavailable. A disappeared last
source is an honest unrecoverable deficit; a list of URLs cannot recreate it.
Do not delete surplus copies or alter another node's retention policy.

Revalidate policy identity, revision and expiry before every new signing or
network action. A change during a request invalidates its observation and
prevents subsequent actions. In-flight remote writes cannot be recalled; their
ordinary short-lived authorisation and exact hash scope still apply.

## Required acceptance

1. Signature, schema, replay/revision, expiry, target/group and transport
   failures produce no network or signer call. File/command signing accepts
   only an exact signed return, and refuses oversized, late or modified data.
2. A full scan validates length and hash; headers, descriptors, URLs and old
   observations cannot substitute for returned bytes. Wrong/truncated/long
   bodies and a false mirror acknowledgement do not raise the count.
3. Separate real nodes restore the target after a lost/corrupt copy, survive
   coordinator and node restarts, and recover from a remaining source after
   the original stops. An unreachable target/source produces a visible deficit
   or uses another explicitly configured eligible node.
4. Policy removal/change/expiry, signer refusal, quota failure, concurrent
   coordinators and interrupted state writes fail safely. No secrets, bearer
events or blob bytes appear in logs; work and memory remain bounded.
5. Independently installed physical nodes and independently operated services
   repeat the declared product journey with ForgeSworn endpoints blocked.
   Loopback processes and synthetic signers do not close this gate.

## Operator workflow

Create a private working directory and a policy-content JSON file. For example,
replace the following synthetic values with the exact hash and size of the
encrypted blob, a future expiry, and your independently configured servers:

```json
{
  "type": "wildbloom.replica-policy",
  "version": 1,
  "id": "my-encrypted-files",
  "revision": 1,
  "expires_at": 1800000000,
  "profile": "direct-https",
  "desired_groups": 2,
  "targets": [
    {"id": "home", "origin": "https://home.example/", "failure_group": "home", "retention": "owner"},
    {"id": "second-site", "origin": "https://second.example/", "failure_group": "second-site", "retention": "owner"}
  ],
  "blobs": [{"sha256": "abababababababababababababababababababababababababababababababab", "size": 1048576}]
}
```

The servers must already admit your public identity for uploads. At least one
configured target must hold the exact blob: the policy cannot create missing
bytes. `owner` and `failure_group` describe the operator's intended deployment;
the coordinator does not grant server-side ownership or storage rights.

```sh
umask 077
wildbloomd replicas template --content replica-policy.json --owner "$OWNER_PUBKEY" > unsigned-policy.json
```

Take that exact unsigned JSON to your external signer and save its returned
signed event as `signed-policy.json`. `OWNER_PUBKEY` is the signer's lowercase
hexadecimal public key. No private key is accepted by these commands.

```sh
wildbloomd replicas run --policy signed-policy.json --owner "$OWNER_PUBKEY" --state-dir replica-state --once
```

When the report lists pending event IDs, sign each required
`replica-state/pending/request-<event-id>.json` externally and place only the
returned signed event in `replica-state/pending/signed-<event-id>.json`. Run the
same command again within the request's 120-second expiry. Changed, late or
invalid returns cause `signer_unavailable`; no write follows them. State and
pending directories are created privately; an existing non-private directory
is refused on Unix.

Omit `--once` for maintenance. Completed passes normally wait 300 seconds;
`--interval` changes that interval. While authorisation is pending, the
coordinator checks local return-file presence once a second and wakes before
the normal interval when a return arrives or a request expires. This polling
does not contact any signer or service. A removed, invalid, expired or changed
policy encountered during a pass causes an error exit and clears pending work;
restart with the intended signed policy. A higher signed revision with a zero
floor stops without deleting remote bytes.

For explicitly authorised unattended signing, add
`--signer /absolute/path/to/local-signer` and optional repeatable
`--signer-arg` values. The helper has 30 seconds by default
(`--signer-timeout`, maximum 60), a 16 KiB stdout limit, and no shell wrapper.
It must return the exact signed event; it decides whether a human confirmation
or hardware action is still required. Never put a private key in arguments.

For Tor-only operation, use a `tor-only` policy containing checksum-valid v3
onion origins and explicitly supply `--proxy socks5h://127.0.0.1:9050` for the
operator's already running Tor listener. This command does not start Tor or
find a proxy. The direct profile refuses a proxy; the development profile
requires `--permit-loopback-development`. Standard Node mirror admission
continues to reject loopback source URLs, so the development client profile
does not bypass server SSRF protection.

`--verification-budget-bytes` and `--max-mirror-attempts` bound each pass; the
latter also bounds unsigned repair requests. Reports distinguish actual
`mirror_attempts` from `repair_attempts`, which include requests awaiting or
refused by a signer. `verification_bytes_reserved` is a conservative bound,
not measured wire traffic. A deferred blob reports no current verified groups.

Never delete the state directory to resolve an error: it contains rollback
protection. Treat changing that state or the expected public identity as an
explicit new trust decision. The lock is local advisory coordination; state on
an untrusted or non-locking network filesystem is outside this guarantee.

## Local evidence and limits

`cargo test --test replica_maintenance -- --nocapture` starts five real Node
stores and separate coordinator processes using synthetic identities and a
controlled loopback SOCKS fixture with explicitly mapped onion names. It
restores a two-group floor, stops the original, restarts a surviving source,
detects same-length corrupt bytes, refuses a full destination and recovers the
exact 1,048,607 bytes into a fresh replacement store. It never contacts Tor or
a public service. Unit tests cover signing, replay, policy races, locks, state
interruption, resource limits, response bodies, redirects and profile isolation.

An existing server may acknowledge a mirror while retaining a corrupt indexed
copy. The coordinator's read-back detects this and can use another eligible
target; it does not delete or rewrite that server's claims. Repairing that
server's local record remains its operator's task. If no verified source or
eligible writable destination remains, the report retains the deficit.

This coordinator is a headless operator feature. Desktop configuration, Bothy
pins, whole-vault integration, independent review, real Tor coordinator
acceptance, physical nodes and trusted release evidence remain open. The
existing ignored Tor replication test covers the older local Node repair
journey and does not substitute for these new coordinator gates.

Address filtering uses a conservative public subset of the IANA
[IPv4](https://www.iana.org/assignments/iana-ipv4-special-registry/) and
[IPv6](https://www.iana.org/assignments/iana-ipv6-special-registry/) special-purpose
registries. V3 onion validation follows the Tor
[address encoding specification](https://spec.torproject.org/rend-spec/encoding-onion-addresses.html).
