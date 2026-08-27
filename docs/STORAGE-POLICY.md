# Storage priority policy

This document defines the next storage-policy boundary for Wildbloom Node.  It
is a target contract, not a claim about the current `0.2` implementation.  The
current node has one global quota, gives every allowed writer the same
retention and performs no automatic eviction.

The intended operator promise is simple:

1. keep the operator's files first;
2. keep invited friends' files within the limits the operator agreed;
3. use spare capacity for other signed, opaque blobs without promising to keep
   them.

## Retention tiers

The core uses neutral names.  Product shells may describe them differently,
but they must not change their meaning.

| Tier | Admission | Automatic eviction | Serving |
| --- | --- | --- | --- |
| `owner` | Exact operator-configured public keys | Never | A declared type may be served when trusted metadata is unambiguous |
| `friend` | An unexpired operator-issued grant with a per-key byte ceiling | Not until another exact copy has been independently verified and the policy permits the move | Opaque attachment |
| `guest` | Signed mirror request accepted by explicit open-shelter policy | First, at any time | Opaque attachment |

There is no anonymous tier.  A valid BUD-11 signature identifies a Nostr key;
it does not identify a legal person or prove that the signed bytes are lawful.

Tier is assigned by node policy after signature verification.  An uploader,
pin or mirror request cannot promote itself.  Disabling open shelter removes
new guest admission without changing the higher tiers.

## Tier and replica class are separate

Retention tier answers: "how strongly does this node prefer these bytes?"
Replica class answers: "how many independently verified copies does the owner
want?"

A medically important blob may be `guest` on a stranger's node, while a casual
photo is `owner` on its publisher's node.  The first is still evicted before
the second.  Replica targets therefore belong to signed claims, not to the CAS
blob row and not to the local retention-tier enum.

## Claims, not blob ownership

One SHA-256 identifies one physical blob, but several public keys may claim it.
The database must retain that many-to-one relationship:

```text
blobs(hash, size, created_at)
claims(hash, signer_pubkey, retention_tier, declared_type,
       grant_id, claim_expires_at, created_at)
repair_sources(hash, source_url, last_verified_at)
reservations(id, hash, size, retention_tier, signer_pubkey, created_at)
```

Names are illustrative until the migration is reviewed.  The invariants are
not:

- tier and declared type live on a signed claim, never as one mutable fact on
  a deduplicated blob;
- the effective local tier is the strongest active claim;
- physical quota counts the blob once;
- a friend's byte ceiling charges the full logical size of every active claim,
  even when another signer already caused the bytes to be stored;
- conflicting trusted type claims fall back to opaque serving;
- expired or revoked claims cannot leave bytes accidentally protected.

## Admission and reserve

The pool has validated low and high free-space watermarks.  The initial target
is ten and twenty per cent of configured capacity.  A deployment may tune them,
but `0 <= low < high < quota` must always hold.

- An `owner` reservation may evict `guest` blobs to make room.  It never evicts
  a `friend` or another `owner` claim automatically.
- A `friend` reservation must remain within that signer's active grant ceiling.
  It may evict `guest` blobs, but not another friend.
- A `guest` mirror is admitted only when the predicted free space after the
  reservation remains at or above the high watermark.  It never triggers
  eviction.
- If protected and promised bytes physically fill the pool, the node refuses
  the next upload honestly.  Priority cannot manufacture disk space.

Admission, eviction selection and reservation must occur under one immediate
database transaction.  A concurrent request must not spend bytes that another
request has already reserved.  Blob bodies are still streamed to private
temporary files, bounded by the declared length and per-blob limit, then
committed only after the actual SHA-256 and length match.

## Eviction

The first implementation evicts the oldest eligible guest blobs.  Public GETs
must not refresh eviction age, otherwise an uploader can keep its own guest
data by repeatedly downloading it.  A later scoring policy may use bounded,
authenticated or internally verified signals, but it must remain deterministic
and resistant to that trivial pinning attack.

Removing a guest copy is not data loss claimed by this node because no
retention promise was made.  It is still observable state and should produce a
bounded, non-secret eviction record containing the hash, size, tier, reason and
time.  It must not record client addresses, authorisation tokens or bytes.

Friend eviction remains disabled until the node can prove all of the following:

1. the grant permits it;
2. an exact alternate copy was retrieved or challenged recently enough;
3. removal will not put the signed replica target below its floor;
4. the friend receives advance notice through the selected coordination lane.

Until then a full node rejects new work rather than silently deleting a
friend's copy.

## Guest admission is mirror-only

The current `--allow-public-writes` switch is deliberately labelled unsafe on a
shared quota.  It must not become the guest-tier design.

Open shelter accepts guest bytes through BUD-04 mirroring after a valid signed
claim and local admission decision.  Direct uploads from unknown public keys
remain disabled.  A later paid or proof-of-work gate may bound open admission,
but payment does not promote a guest blob or turn best-effort storage into a
durability promise.

## Opaque serving

Files held only for friends or guests are returned as
`application/octet-stream` with `Content-Disposition: attachment` and
`X-Content-Type-Options: nosniff`.  They are not an inline public CDN on the
operator's hostname.

An envelope parser may reject malformed framing for non-owner claims.  It
cannot prove confidentiality, harmlessness or ownership: an adversary can wrap
arbitrary bytes in a valid envelope and publish the key elsewhere.  Entropy
tests and a lack of familiar file magic are not security evidence.  Hash-based
takedown and an explicit operator policy remain necessary.

## Listing and deletion

If the optional BUD-12 `GET /list/<pubkey>` endpoint is implemented, it must
require a short-lived BUD-11 `list` event whose signer matches the path and
whose `server` scope includes this node.  Responses are cursor-paginated and
contain only that signer's active claims.  The node never exposes a public
inventory of friends or guests.

BUD-12 deletion removes only the signer's claim.  The physical blob disappears
when no active claim remains, unless an operator tombstone requires immediate
removal and blocks re-admission.  Revoking a friend grant may demote its claims
to `guest`; it must not silently present demotion as deletion from every other
replica.

## Shared-core boundary

The reusable Rust core owns:

- BUD request parsing and Nostr authorisation;
- tier assignment, grants, claims, quota reservation and eviction;
- the streaming SHA-256 CAS and SQLite migrations;
- an unbound Axum router;
- integrity, listing, mirror and repair semantics;
- a transport-neutral fetch interface.

It does not own a TCP listener, Tor process, iroh endpoint, bridge, desktop
shell, Android service, relay selection or product branding.  Those are
adapters and shells around the same router and store.

The encrypted-envelope byte format and known-answer vectors should be a
product-neutral specification consumed by clients in any language.  The node
does not hold client encryption keys and must not grow a second encryption
scheme merely because two products use the same store.

## Acceptance before implementation is called shipped

- A validly signed guest cannot select `owner` or `friend`.
- A guest flood cannot consume the reserve or evict a higher tier.
- Friend ceilings hold across deduplication, concurrent reservations, expiry
  and restart.
- Adding and removing claims recomputes the effective tier without duplicating
  or prematurely deleting physical bytes.
- Crash recovery leaves neither spent reservations nor unindexed blob files.
- Owner admission evicts only eligible guest blobs and stops if that is not
  enough.
- Guest responses are always opaque attachments; ambiguous trusted metadata
  also fails opaque.
- BUD-12 listing is self-only, bounded and cursor-paginated.
- An eviction and subsequent exact re-mirror pass across two independent nodes.
- SQLite migration and the unchanged default owner-only configuration pass on
  Windows, Linux and macOS.

The present `0.2` node satisfies none of the tier or eviction claims above.
Keep this document in future tense until those gates pass.
