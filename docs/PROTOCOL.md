# Wildbloom protocol profile

Wildbloom uses standard Blossom for bytes and Nostr for authority and private
coordination.  The standards remain the compatibility boundary; the coordination
messages below are an experimental profile, not a new NIP.

## Blossom endpoints

| Endpoint | Profile | Behaviour |
| --- | --- | --- |
| `GET /<sha256>[.<ext>]` | BUD-01 | Full blob or one RFC 7233-style byte range |
| `HEAD /<sha256>[.<ext>]` | BUD-01 | Same headers without a body |
| `PUT /upload` | BUD-02 + BUD-11 | Authorised streaming upload |
| `PUT /mirror` | BUD-04 + BUD-11 | Authorised copy over the selected transport |
| `HEAD /upload` | BUD-06 + BUD-11 | Authorised size, type and quota preflight |
| `GET /list/<pubkey>` | BUD-12 + BUD-11 | Authenticated, cursor-paginated list of only the signer's active claims |
| `DELETE /<sha256>` | BUD-12 + BUD-11 | Remove the signer's claim and, after the final active claim, the blob |
| `GET /healthz` | Wildbloom | Process and storage counters, no private data |

Authorisation is a signed kind `24242` event encoded as unpadded base64url JSON:

```text
Authorization: Nostr <event>
```

The node requires exactly one `t` and `expiration` tag, plus at least one
well-formed `x` and `server` tag whose set includes the current blob and node:

```json
["t", "upload"]
["x", "<lower-case SHA-256>"]
["server", "<exact node hostname>"]
["expiration", "<future unix timestamp>"]
```

The event signature and id must verify.  The event cannot be materially in the
future, and its creation-to-expiry lifetime cannot exceed five minutes.
Direct upload signers must be a configured owner or hold an unexpired friend
grant.  An operator may separately enable open shelter for unknown signed
BUD-04 mirrors; that never authorises direct unknown uploads.  A default
installation is read-only.

`PUT /upload` additionally requires `Content-Length` and `X-SHA-256`.  The
received length and independently calculated digest must match.  New blobs
return `201`; deduplicated blobs return `200`.

`HEAD /upload` uses `X-SHA-256`, `X-Content-Length` and `X-Content-Type` and
checks the same signature, maximum blob size and current quota before any body
is sent.  It does not reserve capacity.  A later upload can therefore still
lose a race for the remaining quota.

`PUT /mirror` takes `{"url":"http://<source>.onion/<sha256>.<ext>"}` or a
hash-addressed public HTTPS URL.  The destination authorisation can cover one
or more nodes but must include the destination server.  The source must return
`200` and an exact `Content-Length`; the destination still hashes every
received byte.  Tor mode resolves and fetches through its private SOCKS
listener.  Direct mode accepts only public HTTPS, disables redirects and
ambient proxies, and rejects DNS answers in non-public address space.

Owner and friend mirror requests receive their configured retention tier.
With open shelter enabled, any other valid signer receives a best-effort guest
claim only when the predicted free space remains at or above the high
watermark.  The request contains no tier field and cannot promote itself.

`GET /list/<pubkey>` requires a short-lived `list` event signed by the exact
path pubkey and scoped to this server.  Results are newest first, limited to
100, and use the previous page's SHA-256 as the cursor.  There is no public
inventory endpoint.

`DELETE /<sha256>` requires the `delete` operation in its BUD-11 event.  It
removes only the signing public key's claim.  The bytes disappear only when the
final active claim is removed.  This is a local deletion request,
not a promise that another replica or cache removed its copy.

Primary specifications:
[BUD-01](https://github.com/hzrd149/blossom/blob/master/buds/01.md),
[BUD-02](https://github.com/hzrd149/blossom/blob/master/buds/02.md),
[BUD-04](https://github.com/hzrd149/blossom/blob/master/buds/04.md),
[BUD-06](https://github.com/hzrd149/blossom/blob/master/buds/06.md),
[BUD-11](https://github.com/hzrd149/blossom/blob/master/buds/11.md), and
[BUD-12](https://github.com/hzrd149/blossom/blob/master/buds/12.md).

## Owner-authorised device grants

`wildbloomd --device-grants` lets a configured `--allow-pubkey` owner delegate
bounded, expiring write authority to a device key at runtime, without
restarting the node.  It is off by default and refuses to start without an
owner.  This is an experimental Wildbloom profile, not a NIP.

| Endpoint | Authority | Result |
| --- | --- | --- |
| `POST /grants/v1` | Body: one owner-signed kind `27540` `grant` event (JSON, at most 16 KiB) | `201` new or `200` replaced, with the grant status |
| `DELETE /grants/v1/<device>` | `Authorization: Nostr <base64 event>`: one owner-signed kind `27540` `revoke` event | `200` with the revoked status |
| `GET /grants/v1/<device>` | NIP-98 `GET` signed by that device, its recovery identity or an owner | `200` status; `state` is `active`, `expired`, `revoked` or `withdrawn` (issuer no longer an owner) |

Grant event:

```json
["t", "grant"]
["device", "<64 lower-case hex device public key>"]
["recovery", "<64 lower-case hex recovery identity public key>"]
["bytes", "<per-key byte ceiling, canonical decimal, at least 1>"]
["until", "<Unix time the grant ends>"]
["server", "<exact configured server name>"]
["expiration", "<NIP-40 Unix time this event stops being accepted>"]
```

Revoke event:

```json
["t", "revoke"]
["device", "<64 lower-case hex device public key, equal to the path>"]
["server", "<exact configured server name>"]
["expiration", "<NIP-40 Unix time this event stops being accepted>"]
```

Kind `27540` sits in the ephemeral range, so a relay that is handed one by
mistake does not store it.  It is not a registered NIP kind, and it stays
clear of Blossom's `24242`, NIP-46's `24133` and NIP-98's `27235`.  The
content is free text of at most 512 bytes (a signer can show it to the owner)
and is never interpreted.

Every listed tag must appear exactly once with exactly one value, and any other
tag refuses the event.  The signature and id must verify and the signer must be
a configured owner.  The `server` tag is compared exactly with the node's
configured server names.  The event is accepted only while `created_at` is at
most 30 seconds in the future, `expiration` is in the future, and `expiration`
is at most ten minutes after `created_at`.  `until` must be in the future and at
most two years away.  The device and recovery keys must differ, must not be an
owner or a `--friend-grant` key, and a key cannot be a device in one grant and
a recovery identity in another.  A recovery identity may be named by several
grants (one per computer) from the same owner.

Replay protection: every accepted grant or revoke event id is single use, and
each event for a device must have a strictly later `created_at` than the last
one accepted for that device.  A captured, never-submitted older grant
therefore cannot undo a later revocation.  Two events for one device in the
same second are therefore not both accepted: the second is refused with `409`,
and a client should wait a second and sign again.  A revocation for a device
that has no grant yet is accepted and recorded, so an older grant posted later
cannot land.  A new grant for a device replaces its previous one; that is how
renewal works.  The node's service announcement key, owners and
`--friend-grant` keys can never be delegated.

While a grant is active, the device and the recovery identity may upload,
mirror, preflight and delete as ordinary BUD-11 signers.  The byte ceiling
applies to each key separately, so one grant can hold at most twice `bytes`.
A recovery identity named by several active grants takes the largest of their
ceilings.  BUD-12 listing and deletion stay self-only.  A delegated write body
must keep arriving (at most 60 seconds between chunks) and finish within two
hours, or within `Content-Length / 16 KiB` seconds when that is longer.  A
delete by an active key of a blob whose claim was moved to the owner and not
yet handed back succeeds as if the key still held it.  Once a grant has ended, every request from its keys other than `GET`,
`OPTIONS` and non-preflight `HEAD` is refused with `403`.  What happens when the
grant ends (expiry, revocation or its owner leaving the owner set) is set out
in [STORAGE-POLICY.md](STORAGE-POLICY.md#owner-delegated-claims).

### Pairing creation-grant issuer

`--pairing-issuer --pairing-relay-url <foregather base>` (with
`--device-grants`) adds one route:

| Endpoint | Authority | Result |
| --- | --- | --- |
| `POST /pairing/v1/live-grants` | NIP-98 `POST`, empty body, signed by a device with an active grant | `201 {token,resource,expires,remaining,max_invitation_lifetime}` |

The node calls Foregather's `POST /v1/creation-grants` with exactly
`{"resource":"live","expires":<now+300>,"max_uses":1,"max_invitation_lifetime":600}`
and the operator token as `Authorization: Bearer`.  The token comes from
`--pairing-operator-token-file` (an absolute, mode `0600` file; recommended)
or the `WILDBLOOM_PAIRING_OPERATOR_TOKEN` environment variable, never a
command-line argument.  The variable is removed from the environment of the
Tor and signer child processes.  The token must be Foregather's canonical
32-byte unpadded base64url form.
It is never logged or returned.  The relay URL must be HTTPS, or plain HTTP to
loopback.  Redirects and ambient proxies are disabled.

The NIP-98 profile is the checkout one: exact `u` and `method`, a `payload`
tag for the empty body, at most 60 seconds old.  Each NIP-98 event id is single
use, the recovery identity and owners cannot request grants, and each device may
obtain at most 30 grants in any rolling hour.  The budget is checked before the
event id is spent, so a refused request spends neither.  The upstream reply is checked for a live,
one-use, 600-second grant before the token is passed on; the management `id` is
not returned.  Upstream failures are redacted to `502` or `503`.

## Experimental private storage offer

An operator may send the following JSON as the plaintext of a NIP-17 private
direct message.  NIP-17 supplies private delivery; the sender's Nostr signature
identifies who made the offer.

```json
{
  "type": "wildbloom.storage-offer",
  "version": 1,
  "node": "http://exampleexampleexampleexampleexampleexampleexampleexample.onion/",
  "buds": [1, 2, 4, 6, 11, 12],
  "availableBytes": 10737418240,
  "maxBlobBytes": 1073741824,
  "expires": 1787800000
}
```

Accepting an offer does not prove custody or reserve disk forever.  The client
still signs each exact upload or mirror request and verifies the returned blob
through an independent GET.  Offers should be sent through more than one Nostr
relay where availability matters.

A future ForgeSworn-owned QUIC lane with an opaque WebSocket relay may carry the
same blob stream behind `BlobFetcher`.  It must remain optional: Tor and direct
HTTPS Blossom are already interoperable choices, and no WebRTC/STUN/TURN layer
is required.
