# Public storage service discovery

Public discovery is opt-in. Without `--service-profile /absolute/private/profile.json`
there is no `/services/v1` route, external signing or relay connection. Existing
private owner/friend nodes remain unpublished. A service profile requires open
shelter, an enabled checkout, or both. Sales still require their separate checkout
profile; enabling discovery never enables a payment rail or a new write permission.

The versioned `forgesworn-storage-service-v1` profile uses Nostr kind 31402.
Its contract and fixtures originate in
[402-announce](https://github.com/forgesworn/402-announce/pull/44), commit
`599b3e8e31d24319e9b3ec9a523408593fec2648`. This is a ForgeSworn extension,
not a claim of ratified NIP-402 interoperability. Generic 402 consumers need
explicit support for free shelter and the Wildbloom checkout flow.

## HTTP listing without relay publication

Create a private ordinary file (0600 on Unix). All paths passed to the daemon
must be absolute. Use a dedicated service public key, separate from owner,
friend, buyer and payment keys. The daemon refuses a configured owner/friend
key as the service identity. A signer is never given an owner key by the daemon.

This example is synthetic; replace the public key and origin with your own
explicit configuration. The initial implementation accepts exactly the one
origin used by the running daemon, including the trailing slash:

```json
{
  "service_pubkey": "1b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
  "identifier": "public-storage",
  "name": "Example public storage",
  "about": "Public storage provided by this operator.",
  "origins": ["https://storage.example/"],
  "browser_origins": ["https://app.example"],
  "withdrawn": false,
  "announcement": null
}
```

The origin must be public HTTPS or a checksum-valid v3 onion origin. Loopback,
private IPs, URL credentials, query strings and noncanonical origins are refused.
Host and forwarding headers never construct the listing. Browser access is
restricted to the explicitly listed HTTPS origins; the endpoint is public and
does not require storage authorisation. No credentials, paths, owner/friend
lists, physical usage, commitments, exact free bytes or customer records appear
in the response. Names and descriptions are intentionally public operator text.

For a direct free shelter, explicitly enable `--no-tor --open-shelter
--direct-https-mirrors` and the matching `--public-url`, as well as the service
profile. For managed Tor, use the onion address of the node and Tor-routed
mirrors. A profile cannot override the managed onion address. Open shelter
without an enabled mirror transport appears paused.

`GET /services/v1` returns the current service description, observed timestamp,
expiry, stable service key/listing identifier and the configured public origin.
It has `Cache-Control: no-store`, a four-worker bound and a global 120 requests
per minute admission limit. SQLite work runs outside the async executor.
`GET /checkout/v1/offers` retains its existing response and behavior.

Free shelter is BUD-04 mirroring under signed BUD-11 authorisation. Unknown direct
uploads remain refused. Guest copies are best effort and evictable, oldest first.
Paid terms and enabled rails come from the exact `Checkout` instance serving
quotes and payment routes. Prices are whole-package prices, not per-byte rates.
LNURLcash issuer details appear only when that receiving rail is actually enabled.
Payments go directly to the operator using `wildbloom-checkout-v1`; this is not
L402 middleware and no ForgeSworn custody or onward distribution is introduced.

## Availability and admission

The endpoint and publisher share one snapshot builder. Availability is coarse:

| Service | Accepting means |
| --- | --- |
| Paid offer | Its entire capacity fits the current quota minus committed usage, including sold capacity, live quote holds and in-flight writes. |
| Free mirror | Some new positive-sized guest mirror fits above Shelter Kit v0.5.0's guest high watermark. It does not promise that a maximum-size blob fits. |

Insufficient capacity appears full. A failed commitment read appears unknown.
A missing mirror transport appears paused. This is an observation of local
admission, not an uptime, backend-health or durable-retention proof. There is no
owner capacity reserve added by this change: snapshots follow the enforcement
in the currently pinned Shelter Kit. Discovery reserves nothing. Another buyer,
owner or write can consume capacity after an accepting snapshot; checkout still
atomically reserves before offering payment. Renewals may remain possible even
when capacity for a new customer is full.

Clients must explicitly select a service, fetch its current HTTP description,
bind service key + listing identifier + selected origin, review current terms,
and obtain a fresh quote with new payment consent. Signed relay metadata alone
does not establish who controls an HTTPS origin and must never trigger purchases.

## Opt-in Nostr publication

Replace `announcement: null` with an explicit publisher configuration:

```json
{
  "signer": "/opt/example/service-signer",
  "signer_args": [],
  "state_dir": "/var/lib/example-service-announcements",
  "transport": "direct",
  "relays": [
    {"url": "wss://relay.example/", "addresses": ["<approved-public-IP>:443"]}
  ],
  "heartbeat_seconds": 1800,
  "ttl_seconds": 7200
}
```

The address placeholder must be replaced with operator-approved public socket
addresses for that relay. Synthetic documentation addresses are refused. Direct
publication requires `--no-tor` and no mirror proxy; it connects only to the
explicit public pins, preserving TLS verification of the relay hostname. DNS
changes require an explicit pin refresh. No ambient proxy or redirect is used.

For Tor publication, use `"transport": "tor-only"`, relay destinations with
`"addresses": []`, and the node's managed Tor or explicitly supplied loopback
`socks5h` mirror proxy. WSS public relays and checksum-valid v3 onion WS/WSS
relays are supported. Domains are sent to the SOCKS proxy without local DNS;
a proxy refusal or failure never falls back to direct networking. Relay AUTH
and discovery of additional relays are intentionally unsupported.

The external signer reads one unsigned Nostr event as bounded JSON from stdin
and writes one signed event to stdout. Its executable path must be absolute.
No shell is used; stderr is discarded, output is bounded and a ten-second
deadline kills and reaps the child. Never put keys or credentials in arguments.
The daemon verifies the signature and the exact requested event ID before
publication. Signer rewrites, another author and expired responses are refused.
No service secret key is stored or generated by the daemon.

At most eight explicitly configured relays are contacted in parallel, with a
15-second deadline each, 64 KiB frame/message limits and a 32-message read bound.
Only NIP-01 `OK` with the exact event ID and boolean `true` counts as acceptance.
Logs report acknowledgement counts, never relay error bodies or signing material.
At least one acknowledgement is required; partial acknowledgement counts remain
visible to the operator. Acceptance is not proof that a relay will retain or serve
the announcement. No public relay is contacted by automated tests.

The publisher polls local coarse state once a minute, rate-limits changes and
failures to once per five minutes, and refreshes unchanged state every 30 minutes
by default. Default signed expiry is two hours. Heartbeats must be 5–60 minutes;
TTL must be 10 minutes–24 hours and at least twice the heartbeat. Timing can
reveal node activity even with coarse capacity and a dedicated key.

The private publisher state directory must be separate from the blob store. A
lifetime process lock prevents two publishers using it. The exact signed event
is durably persisted before relay I/O; restart must preserve this directory.
Signatures after restart must be strictly newer and restart does not bypass the
five-minute publication limit. A backwards clock refuses publication until it
catches up. Corrupt, rebound or insecure state fails closed.

On graceful shutdown, the daemon attempts a newer withdrawn announcement with
all services paused before stopping Tor. This attempt is bounded to 30 seconds.
An abrupt shutdown, failed signer or unreachable relay leaves signed expiry as
the fallback. `withdrawn: true` can also publish explicit withdrawal while the
node runs. Withdrawal changes discovery metadata only: existing paid allowances
and the configured write policy remain effective.

Consumers must select the latest valid event by author + `d` identifier before
filtering expiry, withdrawal or capacity, and retain signed replacement
watermarks. They must never resurrect an older accepting offer after seeing a
newer expired, withdrawn or full record. Expiration is client filtering, not
guaranteed relay deletion; a fresh client cannot detect events a relay omits.

## Validation and remaining acceptance

The vendored 19 signed cross-language fixtures include paid, free, combined,
onion, full, withdrawn and expired profiles plus 12 cryptographically valid
semantic rejection vectors. Tests verify exact terms, signature rewrites,
restart watermarks, admission boundaries, origin binding, explicit relay pins,
SOCKS domain routing, rejected/incorrect acknowledgements and oversized frames.

The two-daemon acceptance test uses separate stores and a controlled loopback
SOCKS fixture to discover a free shelter, refuse an unknown direct upload, mirror
exact opaque bytes, report full at the guest watermark and preserve it on restart.
It is not real Tor, independent hosting or browser encryption evidence. Existing
checkout tests separately cover quote/payment/activation and concurrent oversell.
Browser discovery and the shared 402 consumer integrations are separate changes.
Live relay retrieval, real Tor publication and real operator wallet/mint receipts
remain separate acceptance gates; this change enables no operator publication
or live sales automatically.
