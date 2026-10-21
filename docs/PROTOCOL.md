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

[GROUP-GRANTS.md](GROUP-GRANTS.md) drafts a related profile, not yet
implemented: keeper-signed kind `27541` grants that admit a KithMoot room's
devices to a node in a closed group mode with authenticated reads.

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

### TURN credential issuer

`--turn-issuer --turn-url <url>` (with `--device-grants`) adds one route for
[direct send](#direct-send-experimental):

| Endpoint | Authority | Result |
| --- | --- | --- |
| `POST /turn/v1/credentials` | NIP-98 `POST`, empty body, signed by a device with an active grant | `201 {expires,own,peer}` |

`--turn-url` is given 1 to 4 times, or comma-separated.  Each value is a
distinct `stun:`, `turn:` or `turns:` URL of at most 256 bytes of printable
ASCII without spaces, quotes or backslashes, and at least one is `turn:` or
`turns:`.  The URLs are checked at start-up; a node with a bad one does not
start.

The authority is the pairing issuer's, through the same code: the checkout
NIP-98 profile (exact `u` and `method`, a `payload` tag for the empty body, at
most 60 seconds old), a single-use event id, and a signer that is a device with
an active grant.  Owners and recovery identities are refused.  Each device may
make at most 30 requests in any rolling hour.  That budget is kept apart from
the pairing issuer's and is checked before the event id is spent, so a refused
request spends neither.  Refusals use the pairing issuer's status codes and
redacted bodies, among them `400` for a body or a query, `401` for a missing or
invalid NIP-98 event, `403` without an active device grant, `409` for a reused
event and `429` once the budget is spent.

The response carries `Cache-Control: no-store` and is exactly:

```json
{"expires":1800003600,"own":{"credential":"<28 characters>","urls":["turn:turn.example.net:3478?transport=udp"],"username":"1800003600:<22 characters>"},"peer":{"credential":"<28 characters>","urls":["turn:turn.example.net:3478?transport=udp"],"username":"1800003600:<22 characters>"}}
```

`own` is for the caller and `peer` for the verified person at the other end.
Each has exactly the members and limits of an [`ice`](#invitation-and-manifest)
entry, so Drop puts `peer` into `invite` unchanged.  `urls` are the configured
URLs in their configured order.  `expires` is the issue time plus 900
seconds: Drop asks just before it opens a session, which lasts at most 600
seconds, so every allocation and restart falls inside it.  Each credential is coturn's TURN REST form (`use-auth-secret` with
the default `:` separator):

- `username` is `<expires>:<label>`, where `label` is 16 fresh random bytes in
  unpadded base64url, minted by the node for that credential alone;
- `credential` is the standard padded base64 of HMAC-SHA1 keyed with the secret
  over the bytes of `username`.

The secret is the TURN server's `static-auth-secret` string.  It comes from
`--turn-secret-file` (an absolute, mode `0600` file; recommended) or the
`WILDBLOOM_TURN_SECRET` environment variable, exactly one of the two, never a
command-line argument.  The variable is removed from the environment of the
Tor and signer child processes.  The node removes exactly one trailing `\n` or
`\r\n`; what remains must be 32 to 256 bytes of printable ASCII (`!` to `~`)
other than `"`, `'` and `#`, which a configuration file or a shell could read
differently.  Anything else, such as a second trailing newline or a leading
space, stops the node from starting rather than being trimmed, so it never
signs with a different string from the one coturn reads.  The secret is never
logged or returned.

The TURN server learns each username: an expiry and a random label that
appears nowhere else.  It never learns a device key, a NIP-98 event, the relay
session or a direct send's `id`.  It still sees addresses, byte counts and
timing, as [What servers learn](#what-servers-learn) says.  The node learns
only that a granted device asked for credentials, and when.

coturn checks the expiry when an allocation is made.  In a local check with
coturn 4.17.2, a new allocation after `expires` was refused, while an
allocation made before it could still be refreshed after it.

Operator notes:

- The coturn in front of it needs this secret as an additional
  `static-auth-secret` line.  The line must be distinct from any other
  service's secret on that server, such as KithMoot's on
  `kithmoot.forgesworn.dev`, so it can be rotated or revoked alone.  A local
  check with coturn 4.17.2 accepted credentials made from either of two
  `static-auth-secret` lines and refused one made from neither.
- Nothing works until both are deployed: the node flags and the coturn line.
  Until then the node issues credentials that the TURN server refuses.
- To rotate, add the new line to coturn, restart the node with the new secret,
  and remove the old line 15 minutes later, once the last credential signed
  with it has expired.

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

## Direct send (experimental)

Profile `wildbloom-direct/1`.  Direct send moves one file between Drop and a
person's browser over a WebRTC data channel that is set up inside a
word-verified Foregather live channel.  It is specified here before it is
built.  Version 1 covers a page sending a file to Drop (`to-drop`).

The node takes no part in the transfer.  Its roles are the existing
[pairing creation-grant issuer](#pairing-creation-grant-issuer), which lets
Drop open the session, and the
[TURN credential issuer](#turn-credential-issuer), which mints the TURN
credentials.  `wildbloomd` runs no WebRTC, STUN or TURN code, and Blossom
storage and the transports above are unchanged.  Nothing about the file rests
on any server.

### Session

Drop always opens the session, as it does for Share.  It obtains a one-use live
grant from the issuer, allocates a Foregather live session with namespace
`wildbloom.drop` and purpose `send`, four words, one attempt and a lifetime of
at most 600 seconds, and shows the link and words.  The page checks namespace
and purpose against its own configuration, never against the link.  After the
PAKE both people compare three check words.  Only then do both ends switch the
confirmed channel to Foregather's `foregather-exchange/1` profile
(foregather-kit 0.6.0 or later); each exchange message carries one
`wildbloom-direct/1` message.  Drop is the inviter and always makes the WebRTC
offer.  `dir` in the invitation, not the pairing role, says which way the file
goes.

### Message encoding

Every message is one JSON object in UTF-8, at most 16,379 bytes, in strict
canonical form:

- no whitespace outside strings, members in ascending order of their ASCII
  names, no duplicate names, and exactly the members listed for its event;
- strings escape only `"`, `\` and U+0000 to U+001F, using `\b`, `\f`, `\n`,
  `\r` and `\t` where they exist and lower-case `\u00xx` otherwise; every other
  character, including `/` and non-ASCII, is literal, and lone surrogates are
  refused;
- numbers are integers from 0 to 2^53 - 1 in shortest decimal form, with no
  sign, fraction or exponent; booleans are `true` or `false`, and there is no
  `null`.

This is what `JSON.stringify` produces for an object built with its members in
that order, and what `serde_json` produces for a sorted map.  A reader parses
the message, checks it, serialises it again and compares the bytes; any
difference refuses it.  Every message has `"v":1` and an `event`.  A reader
that does not implement the version refuses it with `stop`, reason
`unsupported`.

### Messages

| From | Index | `event` | Other members |
| --- | --- | --- | --- |
| Drop | 0 | `invite` | `dir`, `hide`, `ice`, `id`, `max` |
| page | 0 | `manifest` | `name`, `size`, `type` |
| Drop | 1 | `accept` | `sdp`: Drop's offer |
| Drop | 1 | `decline` | none |
| page | 1 | `answer` | `key`, `sdp`: the page's answer |
| Drop | 2 to 6 | `restart` | `sdp`: an ICE restart offer |
| page | 2 to 6 | `restart-answer` | `sdp` |
| either | its next index | `stop` | `reason` |

The index is the sender's exchange message index.  The order is:

1. Drop sends `invite` as soon as both people confirm the check words.
2. The page reads and checks it, then sends `manifest` for the file the person
   chooses, or `stop`.
3. Drop shows the owner the name and size, then sends `accept` or `decline`.
   `decline` ends the direct send.  Before it asks, Drop checks that the
   volumes holding its temp folder and the Received folder each have twice
   the envelope length E free and 64 MiB more, since the envelope and the
   plaintext both pass through temp files.  If not, it sends `stop` with
   `failed` and tells the owner there is no room, without asking.
4. The page reads `accept` and sends `answer`.
5. Within the session deadline Drop may restart ICE at most five times.  It
   sends `restart` at index k + 1 only after reading the page's message at
   index k, and the page answers at the same index with `restart-answer`.
6. Either side may send `stop` in place of its next message (Drop's first
   message is always `invite`) and then sends nothing more; a side that reads
   `stop` ends too.  Each side sends at most eight messages, indexes 0 to 7.

An event at an index the table does not allow, from the wrong side, or a ninth
message is a protocol failure: the reader sends `stop` with reason `failed` if
it still can, and ends.  Once the data is flowing, a packet in the page's slot
that does not authenticate did not come from the page (the relay or someone at
it wrote it), so it cannot end the transfer: Drop stops reading the exchange,
makes no more restarts, and the transfer carries on.  Before then such a packet
ends the direct send as a protocol failure.  Neither side creates an
`RTCPeerConnection` before `accept`: Drop creates its connection after the
owner accepts, and the page on reading `accept`.  A declined or abandoned
session therefore exposes no address and allocates nothing on a TURN server.

### Invitation and manifest

| Member | Rule |
| --- | --- |
| `dir` | `"to-drop"`: the page sends the file to Drop.  `"from-drop"` is reserved for Drop sending to the page; its message order is not specified yet.  A page refuses a direction it does not implement with `unsupported`; the `send` page implements only `to-drop` |
| `hide` | `true` when Drop uses relay-only ICE and its address is hidden behind TURN.  It only tells the page what to say |
| `ice` | 1 to 4 servers, each exactly `{"credential","urls","username"}`.  `urls` holds 1 to 4 `stun:`, `turn:` or `turns:` URLs of at most 256 bytes; `username` and `credential` hold 1 to 256 bytes without control characters.  At least one URL is `turn:` or `turns:` |
| `id` | 16 random bytes in canonical unpadded base64url: the transfer's name in each app's own state.  It is never sent to a server, and is neither the relay locator nor a TURN username |
| `max` | The largest file, in bytes, Drop will accept: 1 to 250,000,000 in v1 |
| `name` | The FSWNENC2 metadata name: a fixed point of the shared name rule (`sanitise_name` in `crates/envelope`) with none of the disguising characters below |
| `size` | The file's exact size in bytes, 0 to `max` |
| `type` | The FSWNENC2 metadata media type: lower case, not empty (`application/octet-stream` when unknown), at most 255 UTF-16 units, no control characters |

A direct send's `name` must not hold a character that changes how a name is
drawn or that cannot be seen, which the shared name rule lets through: U+061C,
U+180E, U+200B to U+200F, U+202A to U+202E, U+2060 to U+2064, U+2066 to
U+2069, U+206A to U+206F, U+FEFF and U+E0000 to U+E007F.  These are the
bidirectional controls (so `invoice`, U+202E, `fdp.terminal` is drawn as
`invoicelanimret.pdf`), the zero-width and word-joining characters, the
deprecated formatting characters, the tag characters and the byte order mark.
A reader refuses such a manifest with `failed`, after the name-rule check and
before the media type; it never removes the characters itself.  The sending
page removes them from the chosen file's name before it builds the manifest, so
an honest file still sends under the plain name it is made of.  The rule
applies to direct send only; the shared name rule is unchanged.

The manifest is exactly the metadata the page will seal into the envelope, so
both sides know the envelope's length from it.  The page does not offer a file
larger than `max`, and Drop refuses one with `unsupported`.

`reason` in `stop` is `cancelled` (a person stopped or closed the page),
`unsupported` (this end cannot use what the other offered: version, direction,
ICE server or size) or `failed` (a protocol, connection or verification
failure).

### ICE servers and the TURN credential

Drop obtains two short-lived TURN REST credentials (coturn's `use-auth-secret`
form, each with its own random username label): one for itself and one for the
page.  The page's credential travels only inside `invite`, after the check
words, so only the verified peer receives it.  It never appears in the link, a
URL, the relay's public fields, a log or browser storage, and the page forgets
it when the direct send ends.  Drop obtains both from the node's
[TURN credential issuer](#turn-credential-issuer) before it opens the session,
so a node without the issuer fails before any link is shown, and puts `peer`
into `ice` unchanged.  An abandoned session's credentials lapse unused.

Each URL in `ice` must equal, byte for byte, an entry of the page's build-time
allowlist; otherwise the page refuses with `unsupported`.  A paired but hostile
inviter therefore cannot point the page at its own TURN server to learn an
address the page asked to hide.  The page builds its configuration only from
`ice` and adds no other server; Drop uses its own credential with the same
servers.

Each side decides for itself whether to hide its own address.  Hiding means
`iceTransportPolicy: "relay"` with STUN URLs removed: the other device then sees
only the TURN server's address, while the TURN server still sees the real one.
Drop hides by default; the page connects directly unless the person turns
hiding on.  Browsers already hide local addresses behind mDNS names, because
these pages never ask for camera or microphone access.

### Session descriptions

Descriptions are not trickled.  Each side sends `localDescription.sdp` once ICE
gathering completes, or three seconds after gathering starts, whichever comes
first.  A description is at most 8,000 bytes of printable ASCII with CRLF line
ends, so every message stays under 16,379 bytes.  The reader refuses one that
does not start with `v=0`, does not have exactly one media section
`m=application <port> UDP/DTLS/SCTP webrtc-datachannel`, or has no
`a=fingerprint:sha-256` line.  Offers and answers reach each side only through
the AEAD channel whose words the people compared, so the DTLS fingerprints and
ICE credentials are bound to the paired peer: neither the relay nor a STUN or
TURN server can substitute them.

### Data channel and frames

Each side has one `RTCPeerConnection` and one pre-negotiated data channel:
`negotiated: true`, `id: 0`, ordered and reliable (no `maxRetransmits` or
`maxPacketLifeTime`), label `wildbloom-direct/1`, binary messages only.  Any
other data channel, a media track or a text message ends the connection.

The file travels as one FSWNENC2 envelope in per-file mode, sealed with the
`key` from `answer` (fresh for every transfer) and the manifest as its
metadata.  Its length E follows from the manifest.  With M the byte length of
the metadata JSON `{"name":…,"size":…,"type":…}`, let P be FSWNENC2's padded
length of 4 + M + `size` bytes (at least 64 KiB, then the next power of two up
to 1 MiB, then whole MiB); then E = 56 + P + 16 × ⌈P / 1,048,576⌉.

Frames are binary and big-endian, and their first byte is their type:

| Type | Frame | Layout and length | From | Meaning |
| --- | --- | --- | --- | --- |
| `01` | DATA | `01 offset_u64 bytes`, 10 to 65,536 bytes | sender | envelope bytes starting at `offset` |
| `02` | ACK | `02 next_u64`, 9 bytes | receiver | the first `next` envelope bytes are on disk |
| `03` | END | `03 sha256_32 size_u64`, 41 bytes | sender | every byte is sent: the file's SHA-256 and size |
| `04` | KEPT | `04`, 1 byte | receiver | verified and kept |
| `05` | STOP | `05 reason_u8`, 2 bytes | either | ending: 1 cancelled, 2 failed, 3 storage |

In `to-drop` the page is the sender and Drop the receiver.  Any other type
(`06` is reserved for a later resume across connections), length or direction
is a failure: the reader sends STOP 2 and closes.

- DATA offsets are contiguous from 0 and the bytes total exactly E.  A gap, an
  overlap, a byte past E or DATA after END is a failure.
- The sender's frames are at most F = min(`sctp.maxMessageSize`, 65,536) bytes.
  If F is below 16,384 the sender stops with reason 2.
- The sender never has more than 8,388,608 envelope bytes in flight beyond the
  last ACK.  It pauses while `bufferedAmount` exceeds 1 MiB and resumes on
  `bufferedamountlow`, with the threshold at 256 KiB.  The receiver sends ACK at
  least every 1,048,576 bytes it writes and when it reaches E; `next` strictly
  increases and never exceeds the bytes received.  The sender shows progress
  from ACKs, never from bytes queued.
- When the selected candidate pair has a relay candidate at either end, the
  sender also paces DATA: on average at most 400,000 envelope bytes a second,
  with no burst above 65,536 bytes.  The sender reads the selected pair from
  `getStats()` once connected and again after each ICE restart, and does not
  pace a direct pair.  TURN servers enforce a per-allocation rate by dropping
  what exceeds it, and SCTP recovers from those drops so slowly that an unpaced
  send through a 1,000,000-byte-a-second limit averaged under 140,000 bytes a
  second at a 130 ms round trip, where one paced at 400,000 ran without stalls.
- After END the receiver checks, in order: exactly E bytes arrived; the envelope
  opens with `key`, every record authenticates, and the record count and
  padding bucket match the header; the metadata equals the manifest exactly;
  the plaintext's size and SHA-256 equal END.  Only then does it keep the file
  and send KEPT.  Any mismatch sends STOP 2 and deletes both the envelope and
  plaintext temp files.  Nothing can be saved before KEPT.
- The sender says the file arrived only after reading KEPT on this channel.
- After KEPT or STOP both sides close the connection, Drop deletes the relay
  session, and both close the exchange.  An unknown STOP reason reads as 2.

### Reconnection and the deadline

While the session is open, at most 600 seconds from issue, Drop answers an ICE
failure or a network change with `restart` on the same connection.  The DTLS
session, SCTP association and data channel carry on, and SCTP retransmits
whatever was outstanding, so no frame changes and the application resends
nothing.  Every envelope record is encrypted exactly once.  If the data channel
closes, the direct send has failed: v1 has no resume, and the people start again
with a new link.  The data channel may outlive the session, but once the
deadline passes no restart is possible and an ICE failure ends the direct send.
While connected, a page that sends no envelope byte for 90 seconds cannot hold
Drop: Drop ends the direct send as lost and sends STOP 2.  A reconnection is
timed by its own clocks instead.

### Limits

| Bound | v1 value |
| --- | --- |
| Exchange message | 16,379 bytes of canonical JSON |
| Messages per side | 8, indexes 0 to 7, within the exchange's 32 |
| ICE restarts | 5 |
| Session description | 8,000 bytes |
| ICE servers | 1 to 4, each with 1 to 4 URLs of at most 256 bytes |
| File | `max`, at most 250,000,000 bytes |
| Data frame | at most 65,536 bytes; F at least 16,384 |
| Unacknowledged envelope bytes | 8,388,608 |
| Relayed send rate | 400,000 envelope bytes a second, bursts of at most 65,536 |
| Session | at most 600 seconds; the data channel may outlive it |

### What servers learn

The pairing relay holds the hellos, proofs and a few KiB of encrypted exchange
messages until Drop deletes the session or it expires; logical expiry is not
erasure.  STUN and TURN servers see both addresses, byte counts and timing.  A
TURN server relays DTLS records that carry FSWNENC2 records, and stores nothing.
No server sees the words, the check words, the descriptions, or the file's
name, size, key or bytes, and TURN usernames share no identifier with the relay
session.  Without hiding, each side sees the other's public address.

### Vectors

`vectors/wildbloom-direct-v1.json` holds synthetic examples: valid messages
with their exact text and SHA-256, refused messages with the `stop` reason the
reader sends, valid and refused data-channel frames, and envelope lengths.  The
first envelope length matches the FSWNENC2 known-answer vector's 65,608 bytes.
Servers, credentials and keys in it are synthetic.  Both readers check every
vector: Drop's Rust tests read this file, and the web project's tests read a
byte-for-byte copy of it.
