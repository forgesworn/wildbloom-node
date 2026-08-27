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
| `PUT /mirror` | BUD-04 + BUD-11 | Authorised onion-to-onion copy |
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
["server", "<exact onion hostname>"]
["expiration", "<future unix timestamp>"]
```

The event signature and id must verify.  The event cannot be materially in the
future, and its creation-to-expiry lifetime cannot exceed five minutes.

`PUT /upload` additionally requires `Content-Length` and `X-SHA-256`.  The
received length and independently calculated digest must match.  New blobs
return `201`; deduplicated blobs return `200`.

`PUT /mirror` takes `{"url":"http://<source>.onion/<sha256>.<ext>"}` or a
hash-addressed public HTTPS URL.  The destination authorisation can cover one
or more nodes but must include the destination server.  The source must return
`200` and an exact `Content-Length`; the destination still hashes every
received byte.  Every fetch and DNS lookup goes through the node's managed Tor
process.

Primary specifications:
[BUD-01](https://github.com/hzrd149/blossom/blob/master/buds/01.md),
[BUD-02](https://github.com/hzrd149/blossom/blob/master/buds/02.md),
[BUD-04](https://github.com/hzrd149/blossom/blob/master/buds/04.md), and
[BUD-11](https://github.com/hzrd149/blossom/blob/master/buds/11.md).

## Experimental private storage offer

An operator may send the following JSON as the plaintext of a NIP-17 private
direct message.  NIP-17 supplies private delivery; the sender's Nostr signature
identifies who made the offer.

```json
{
  "type": "wildbloom.storage-offer",
  "version": 1,
  "node": "http://exampleexampleexampleexampleexampleexampleexampleexample.onion/",
  "buds": [1, 2, 4, 11],
  "availableBytes": 10737418240,
  "maxBlobBytes": 1073741824,
  "expires": 1787800000
}
```

Accepting an offer does not prove custody or reserve disk forever.  The client
still signs each exact upload or mirror request and verifies the returned blob
through an independent GET.  Offers should be sent through more than one Nostr
relay where availability matters.

RelaySwarm could later carry the same offer and blob stream directly using its
Noise-authenticated HyperDHT path.  It must remain an optional transport: Tor
and standard Blossom are the interoperable fallback, and no WebRTC/STUN/TURN
layer is required.
