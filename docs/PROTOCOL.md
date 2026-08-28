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
