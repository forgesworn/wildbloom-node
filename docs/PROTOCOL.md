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
must keep arriving: at most 60 seconds between chunks, and each chunk no later
than two hours plus one second per 16 KiB already received after the upload
began.  A body that averages at least 16 KiB/s after that grace never times
out.  A delete by an active key of a blob whose claim was moved to the owner
and not yet handed back succeeds as if the key still held it.  Once a grant has
ended, every request from its keys other than `GET`, `OPTIONS` and non-preflight `HEAD` is refused with `403`.  What happens when the
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

## File requests

Drop can ask a person for one file.  The person opens a link on their phone,
types four spoken words, and the page encrypts the file with a key Drop chose
and uploads it to the owner's online node under a short-lived request grant.
Drop then downloads it, adds it through its normal path and deletes the request
copy.  This is an experimental Wildbloom profile, not a NIP.  Shared test
vectors for everything below are in
[`vectors/wildbloom-request-v1.json`](../vectors/wildbloom-request-v1.json);
the Rust and TypeScript implementations must both pass them.

### Pairing

The Foregather live pairing Share uses: namespace `wildbloom.drop`, purpose
`request`, 4 words, one attempt, a session of at most 600 seconds, and the link
base `https://<web>/send`.  Drop is the inviter and the phone page the
recipient.  Drop asks the node for the request grant only after both sides
have confirmed the check words, so a failed pairing leaves no write authority.
It then sends the invitation below as the transfer-v1 invitation bytes.  The
session only carries the invitation and the optional reply; the upload can
happen after it ends, until the grant's `until`.

### Invitation `wildbloom-request/1`

Canonical JSON: these keys in this order, no whitespace, strings escaped as
`JSON.stringify` and `serde_json` escape them (so `/` is never escaped), and
unknown keys refused.  At most 16,364 bytes, the transfer-v1 invitation limit.

```text
{"v":"wildbloom-request/1","node":"https://<online node origin>/","signer":"<64 hex request secret key>",
 "key":"wbk1_…","size":<max envelope bytes>,"bytes":<max plaintext bytes>,"files":1,"until":<unix seconds>}
```

| Key | Rule |
| --- | --- |
| `v` | exactly `wildbloom-request/1` |
| `node` | the node's origin in WHATWG serialised form with a path of exactly `/`: no further path, query, fragment or userinfo, not an onion address.  HTTPS, or plain HTTP only to `localhost`, `127.0.0.1` or `[::1]`, as for Share.  The BUD-11 `server` tag is its host. |
| `signer` | 64 lower-case hex digits of a valid secp256k1 secret key (not zero, below the group order).  The page derives the request public key from it. |
| `key` | the file key, a `wbk1_` input key that decodes canonically to 32 bytes; the page encrypts with it instead of generating one |
| `size` | the largest envelope the page may upload: at least one envelope (65,608 bytes) and at most 270,532,608; equal to the grant's `bytes` |
| `bytes` | the largest plaintext: at least 1, below `size`, at most 250,000,000 |
| `files` | exactly `1` in this version |
| `until` | when the grant ends: in the future and at most 86,400 seconds away; equal to the grant's `until` |

All numbers are JSON integers within JavaScript's exact range.  The invitation
holds two secrets (`signer` and `key`): parsers zeroise them after use, never
log them and redact them from debug output.  A parser refuses anything else; the
vectors name the rule each refused case breaks (`length`, `shape`, `version`,
`node`, `signer`, `key`, `size`, `bytes`, `files`, `until` or `canonical`).

### Reply

While the session is still open, the page may send one reply inside
`foregather-transfer-reply/1` as it starts uploading:

```json
{"v":1,"event":"sending","sha256":"<64 lower-case hex envelope hash>","size":<envelope bytes>}
```

It is read strictly, as Share reads its downloaded reply: a JSON object with
exactly these four members (any order and JSON whitespace, no duplicates), `v`
the integer 1, `event` exactly `sending`, `size` an integer from 1 to
9,007,199,254,740,991.  Anything else is no reply.  The reply is early feedback only:
Drop finds the upload by listing the request key's claims, so a withheld or
refused reply changes nothing.

### Request grants

`wildbloomd --request-grants` (which requires `--device-grants`) adds two
routes.  It is off by default; without it both answer `404`.

| Endpoint | Authority | Result |
| --- | --- | --- |
| `POST /request/v1/upload-grants` | NIP-98 `POST` signed by a device with an active grant; body `{"pubkey":"<64 hex>","bytes":<n>,"until":<unix>}`, at most 1 KiB | `201 {"pubkey","bytes","until"}`, the accepted terms |
| `DELETE /request/v1/upload-grants/<pubkey>` | NIP-98 `DELETE` (empty body, no `payload` tag) signed by the device that made it | `200 {"pubkey","state":"ended"}` |

The NIP-98 profile is the pairing issuer's: exact `u` and `method`, a `payload`
tag over the `POST` body, at most 60 seconds old, and each event id single use
(the device grant replay table).  The body is one JSON object with exactly
those three members, in any order.  The node checks, in this order, and spends
the event id only once every check has passed:

1. the NIP-98 event (`401`), then that its signer is a device with an active
   grant (`403`).  Owners, recovery identities and request keys are never
   devices;
2. the body: `pubkey` is 64 lower-case hex digits naming a point on the curve,
   `bytes` is from 1 to 270,532,608, and `until` is in the future and at most
   86,400 seconds away (`400`);
3. `pubkey` was never seen before: not an owner, `--friend-grant`, service,
   device or recovery key, not the caller, not an earlier request key, and
   holding no claim and no paid allowance in the store (`409`);
4. the device has fewer than 3 open request grants and was issued fewer than
   10 in the last hour (`429`);
5. the device has room: its byte ceiling, less what it holds and has in
   flight, less the `bytes` of its open request grants, covers `bytes`, and
   the node's quota and per-blob limit would take a blob of `bytes` now
   (`409 no_room`).  This is a check, not a reservation.

Errors are JSON `{"error":"<code>"}` with `Cache-Control: no-store`.  Clients
match on the code:

| Status | `error` | Meaning |
| --- | --- | --- |
| `400` | `invalid_request` | a query, a duplicate `Authorization` header, or a body that is not exactly the object above |
| `400` | `invalid_pubkey` | `pubkey` is not 64 lower-case hex naming a point on the curve, or the `DELETE` path is not 64 lower-case hex |
| `400` | `invalid_bytes` | `bytes` is 0 or over 270,532,608 |
| `400` | `invalid_until` | `until` is not in the future or is more than 86,400 seconds away |
| `401` | `unauthorised` | the NIP-98 event is missing or fails the profile |
| `403` | `not_a_device` | the signer has no active device grant |
| `403` | `not_yours` | `DELETE` by a device that did not make the grant |
| `404` | `unknown_request` | `DELETE` of a key that was never issued |
| `409` | `key_in_use` | the key was seen before (step 3); a replayed issue lands here too |
| `409` | `no_room` | step 5 |
| `409` | `replayed` | the `DELETE` event id was already used |
| `413` | `body_too_large` | the body is over 1 KiB |
| `429` | `too_many_open` | the device already has 3 open request grants |
| `429` | `too_many_requests` | the device was issued 10 in the last hour |
| `503` | `unavailable` | grant state or the core is unavailable; sign again and retry |

While a request grant is active its key is a core friend grant with ceiling
`bytes` and the same far-future core expiry as delegated keys, so the ceiling
(`507` when exceeded), streaming limits and deduplication charging are
core-enforced.  The key may `PUT /upload`, preflight with `HEAD /upload`,
`DELETE /<sha256>` its own claims and read, including `GET /list/<itself>`,
with ordinary BUD-11 events.  Its write bodies keep the delegated pacing (60
seconds between chunks, then 16 KiB/s after a two-hour grace).  `PUT /mirror`
and any other write are refused with `403 {"error":"upload_only"}`.  The pairing
issuer and the device grant routes refuse it, as it is not a device.

A request grant ends at `until`, on `DELETE`, or when its device's grant ends.
From that moment the gate refuses the key's uploads, preflights and deletes
with `403 {"error":"request_ended"}`; reads still pass.  Every error also
carries its code in the `X-Reason` header, which is all a refused
`HEAD /upload` has, as a `HEAD` response has no body.  A revoked device's
request grants stay ended even if the same device is granted again.  The
maintenance sweep (shortly after a `DELETE` or revocation, at start-up and
every minute) then waits briefly for the key's in-flight writes, deletes every
claim the key holds except any under a paid allowance, and only then drops the
key from the core's trusted set.  The bytes go when no other claim holds them;
another key's claim on the same blob keeps it.  Nothing moves to the owner (see
[STORAGE-POLICY.md](STORAGE-POLICY.md#request-grants)).  `DELETE` answers the
same for a grant that has already ended, so it is safe to repeat with a fresh
event.  Issuing pushes the changed set into the core, which waits for
in-flight core writes, as a device grant does.

Records live in `request-grants.sqlite3`, a private `0600` SQLite file beside
the store, apart from device grants.  They are kept after a grant ends, so a
key is never granted twice.  As for device grants, recorded request grants are
honoured whenever that file exists, even if `--request-grants` is later turned
off: the gate and the end-of-grant deletion keep running, only the routes go.
Start-up refuses a recorded request key that is now configured as an owner,
`--friend-grant` or service key, or that is a device or recovery identity.

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
