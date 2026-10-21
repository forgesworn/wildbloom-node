# Group grants

Status: draft profile `group-grants/1`, 21 October 2026.  Phase S3, the
`wildbloomd` group mode of section 12, is built; KithMoot and Bothy are not.
This is phase S2 of KithMoot's group-hosted design; S3 to S9 consume it.  It
is an experimental profile, not a NIP, and not legal advice.

The phases and decision this document refers to:

| Name | What it is |
|---|---|
| S2 | This contract |
| S3 | `wildbloomd` group mode: refuse guests and open shelter, authenticate reads, enforce grants and the group ceiling |
| S4 | The KithMoot keeper mints and revokes grants when it admits and removes devices, and delivers them in the room |
| S5 | A room carries its group storage nodes in its signed invitation; clients upload to a granted node and fetch with authentication |
| S7 | Group replica policy: copies on several members' nodes, and deletes that reach every copy |
| S8 | Group relay: a member-run NIP-42 relay that accepts only granted keys |
| S9 | Group TURN: a node's TURN issuer accepts group grants |
| D9 | A proposed closed "group box" profile for a Bothy box used as a group node (drop tier off, public fronts off), which needs the Bothy maintainers' agreement |

Vectors: [`vectors/group-grants-v1.json`](../vectors/group-grants-v1.json),
built and checked by [`scripts/group-grants/vectors.mjs`](../scripts/group-grants/vectors.mjs)
(see [Vectors](#16-vectors)).

## 1. Why

ForgeSworn is UK based and should not provide a public user-to-user service.
The provider of such a service is whoever controls who can use it, so the aim
is a closed one: a group's own servers (a member's always-on node, which may be
the owner's) accept only the devices of people admitted to that group's room,
and the one member who admits them, the keeper, decides who that is.

Today that cannot be built.  KithMoot signs uploads and relay events with a
per-device, per-room key that is registered nowhere, so a server cannot tell a
group's devices from anybody else's, and a store must take any key and serve
any hash.  A group grant registers those keys: the keeper signs one for each
admitted device, the node accepts requests only from keys it names, and reads
are authenticated so a hash is not a capability.

## 2. Summary of the choices

| Question | Choice | Section |
|---|---|---|
| Who signs | The keeper, with the room's authority key (KithMoot's inviter key, pinned in the link) | 3.4 |
| How a node knows which keeper it serves | The node owner enrols that key, with a group ceiling, on their own machine | 3.2 |
| Event | Kind `27541`, ephemeral range, empty content, strict tags | 4 |
| Room selector | The room id (`d`), already public on the room's rekeys | 4.3 |
| Node binding | One `server` per grant; a device holds one grant per node | 4.2 |
| Revocation | A replacement of the same grant id with `status` `revoked`, terminal for that id; `reset` ends every grant of a room at a node | 4.5 |
| Lifetime | `expiration` (NIP-40) is the end of the grant, at most 90 days after `created_at` | 4.4 |
| Delivery to devices | One control-channel op per grant event, inside the room's encryption | 7.1 |
| Delivery to nodes | Posted by the keeper, by the device itself, and by any member carrying a revocation | 7.2 |
| Reads | BUD-11 `t=get` with `x` and `server` required, from a key whose group holds the blob | 6.2 |
| Caching | `Cache-Control: private, no-store` and `Vary: Authorization` on every read | 6.6 |

## 3. Roles and keys

### 3.1 Roles

| Role | Key | What it does |
|---|---|---|
| Node owner | A configured owner key (`--allow-pubkey` in `wildbloomd`) | Runs the node.  Enrols keepers, sets each group's ceiling, can unenrol at any time and remove a group's files |
| Keeper | The room's authority key | The always-on member who admits devices.  Signs grants, revocations and resets.  Never a device in its own grants |
| Member device | KithMoot's per-device, per-room key | Signs Blossom tokens (BUD-11), NIP-98 requests and NIP-42 relay authentication.  Names nobody outside the room |
| Coordinator | A key of the keeper's replica coordinator | A device in the keeper's own grants, with `upload`, `get` and `purge`, used to copy, verify and delete across nodes |
| Group node | A node in group mode | Serves only granted keys.  May be the keeper's own machine or another member's |
| Group relay, group TURN | Their host names | Honour the same grants with their own scopes (S8, S9) |

The node owner and the keeper are often the same person.  When they are not,
the node owner has chosen to serve that keeper's room on their machine, and
the keeper decides which devices use it.  This contract does not settle who is
the provider in law; KithMoot's design records that reading and its marks.

### 3.2 Enrolment

A node accepts group events only from keeper keys its owner has enrolled.
Enrolment is a local act on the owner's machine (a command, a flag or the
desktop app's switch), never a network request in this profile.  An
enrolment records:

- the keeper key (64 lower-case hex);
- the group ceiling in bytes, chosen by the node owner;
- optionally the room ids the owner expects, so a keeper key cannot open a
  second group on that node without the owner's say.

A keeper key must not be a node owner, friend, device-grant, recovery or
service key, nor a device in any group at that node.  Unenrolling a keeper
ends every grant it signed at once.  The group's stored files stay until the
node owner removes them or the node's retention removes them (section 9).

In KithMoot the authority key is pinned in every member's link, so a member
who switches on "Keep this group's files on this computer" enrols the key
their own app already trusts.

### 3.3 The group

At a node, a **group** is one enrolled keeper key and one room id.  Every
device key belongs to at most one group at a node, and stays in it while the
node keeps a grant row or a claim for that key.  A blob is **held by a group**
while any key of that group holds a claim on it, including a key whose grant
has ended.

### 3.4 Why the authority key, and not the node owner's or a new key

KithMoot's design said the keeper's node owner key would sign.  That key is
its holder's authority over a whole node and their own files, so a keeper
process holding it online would hand a keeper compromise the owner's storage
as well, and every other member's node would have to trust a key that also
identifies the owner's own Wildbloom use.  The authority key is better:

- members already verify it for `relays`, `admins`, `channels` and `meeting`
  ops, so a grant needs no extra announcement;
- it moves with the room when a keeper changes machine ("Taking over a room
  that already exists" in KithMoot's deploy notes), so moving a keeper needs no
  action on any node;
- the node learns nothing new by seeing it, because it is already public on
  every rekey (kind 1462).

The cost is one enrolment per room on a node, since each KithMoot room has its
own authority key.  A dedicated per-room grant key would hide the link between
a node and the room's public rekeys from the node, at the price of an
announcement op and a key to back up.  The owner chose the authority key (O1).

## 4. The grant event

### 4.1 Kind 27541

Kind `27541` sits in the ephemeral range, so a relay handed one by mistake
does not store it.  Grants never travel bare on relays (section 7).

Checked before choosing it:

- wildbloom-node: `24242`, `27235` (NIP-98), `27540` (device grants), `30078`
  (replica policy), `31402` (service discovery).
- KithMoot `origin/main` d7571f6 (`src/kinds.ts`, the kind table in
  `docs/protocol.md`, `docs/protocol/kind-registration.json`): `1059`, `1063`,
  `1460` to `1464`, `20460` to `20472`, `21059`, `24242`, `30078`, `30460` to
  `30469`, `9734`, `9735`, and RelaySwarm's `24170` and `24171` noted there.
- Bothy (bothy-node `main` 0e71681, bothy `master` d387f55): `10640`, `24242`
  (`t=pin` and `t=event-grant`), `24640` to `24645`, `30640`, `30642`, `30643`.
- Published NIPs: `nostr-protocol/nips` master 0b5532c (20 October 2026) and
  `nostr-protocol/registry-of-kinds` 2ae5c82 (18 October 2026).  The
  registry's ephemeral-range entries are 20013, 20014, 21000 to 21003, 21059,
  22242, 23194 to 23197, 23311, 23313, 23333, 23903, 24133, 24242, 25050 to
  25055, 27235 and 28934 to 28936.  Nothing lies between 27236 and 28933.
- Every Git repository checked out beside this one, for the literal
  `27541`: the only matches were inside minified third-party bundles, none of
  them a kind.

Not checked: a live relay scan for kind 27541 events.  KithMoot's registration
notes treat that scan as a separate step before any registry submission (open
question O14).

Why not `27540` with a new verb: the signer authority differs (a keeper, not
a node owner), the lifetimes differ (section 4.7), and the existing parser
refuses unknown verbs, so reuse would mix two authorities in one kind for no
gain.  Why not `24242` with `t=group-grant`, as Bothy does for its event
grants: a 24242 event is what every Blossom server reads as a token, and a
long-lived keeper-signed one would rely on every server refusing an unknown
verb.  A separate kind cannot be read as a token at all (vector
`get-grant-event-as-token`).

### 4.2 Grant tags

`content` is empty.  Tags, each exactly one value, in this order when writing:

| Tag | Count | Value |
|---|---|---|
| `t` | 1 | `grant` |
| `grant` | 1 | Grant id: 32 lower-case hex (16 random bytes chosen by the keeper) |
| `d` | 1 | Room id: 64 lower-case hex (section 4.3) |
| `device` | 1 | The device key: 64 lower-case hex, not the signer |
| `server` | 1 | The node's host name, lower case, no scheme, port or path (`grove.example.net`, or an onion host name) |
| `scope` | 1 to 7 | One scope each, no repeats (section 4.6) |
| `bytes` | 1 if `upload` is a scope, else 0 | Per-device byte ceiling: canonical decimal, 1 to 2^63 - 1 |
| `status` | 1 | `active` or `revoked` |
| `expiration` | 1 | NIP-40: the Unix second the grant ends |

Any other tag, a repeated singleton, a tag with other than one value, an
upper-case key, a decimal with a leading zero, an event field outside NIP-01,
or non-empty content makes the event malformed.  A grant names no participant
(`p`) and no recovery identity: nothing of a removed member may outlive their
revocation, and the node must not learn who a device belongs to.

A grant names exactly one node.  A device holds one grant per node it may
use, so a node learns of no other node, revocation and expiry stay per node,
and a node added after a member was removed has never been given a grant for
that member.

A grant event is about 700 bytes of JSON (vector `good-grant`).

### 4.3 The room selector

`d` is the room id: in KithMoot, HKDF-SHA256 of the room secret with the info
`kithmoot/v1/room-id` (KithMoot `docs/protocol.md`, "Primitives and
encoding").  It is not the room secret, the room key, the link or its bearer,
and none of them can be derived from it.  It is stable across epochs, so a
group's files stay one group through rekeys.

It is not secret either: the room id and the authority key are on every
rekey.  A node therefore learns which public rekey traffic its group belongs
to.  It could already link a device key to the room's roster events, which
relays see, so the id adds little.  A derived selector is open question O2.

### 4.4 Acceptance rules

A node accepts a grant event only if, in this order (the first failure
decides the answer):

1. The body is at most 16 KiB and a strict NIP-01 event (exactly `id`,
   `pubkey`, `created_at`, `kind`, `tags`, `content`, `sig`).
2. Kind is 27541, content is empty, the tags follow 4.2 (or 4.5 for a reset),
   and `device` is not the signer.
3. `expiration` is after `created_at` and at most 90 days (7,776,000 seconds)
   after it.
4. The id and BIP-340 signature verify.
5. The signer is an enrolled keeper.
6. `server` equals one of the node's configured names.
7. `created_at` is at most 30 seconds ahead of the node clock and
   `expiration` is in the future.

Then against the node's state:

8. The device is not a node owner, friend, device-grant, recovery or service
   key, not an enrolled keeper, and not a key of another group at this node.
9. `created_at` is later than any reset floor for this keeper, room and node.
10. If the node already holds this grant id from this keeper: the same event
    is answered `200`; the room, device and node must not change; `created_at`
    must be strictly later; and a `revoked` id can never become `active`.
11. An `active` grant is refused while another active grant id names the same
    keeper, room, device and node.

A grant is **active** while its newest accepted event says `active`, its
`expiration` is in the future, it is newer than the floor, and its keeper is
still enrolled.  It **ends** at the first of: the `created_at` of its
revocation, the `created_at` of a reset that covers it, its `expiration`, or
the keeper's unenrolment.

### 4.5 Renewal, revocation, reset and re-admission

- **Renewal** re-signs the same grant id with a later `created_at` and a later
  `expiration`.  Scopes and `bytes` may change; room, device and node may not.
- **Revocation** re-signs the same grant id with `status` `revoked` and a
  later `created_at`.  It carries the same tags as the grant, including scopes.
  It is terminal: that id never becomes active again.  A revocation for an id
  the node has never seen is accepted and recorded, so the grant cannot land
  later.  The keeper sets a revocation's `expiration` to the latest
  `expiration` it signed for that id.
- **Re-admission** uses a new grant id.
- **Reset** ends every grant of one room at one node that is not newer than
  the reset.  Tags: `t` `reset`, `d`, `server`, `expiration`, and it passes
  rules 1 to 7 of 4.4.  A newer reset replaces the floor; an older one is
  stale.  Renewals and new grants signed after the reset land again.  The keeper uses it to close a room, after
  losing its record of grant ids, or when it cannot list every grant a node
  may hold.  A reset's `expiration` is `created_at` plus 90 days, so it can be
  carried late.
- Two different events for one grant id in the same second: the second is
  refused, and the keeper signs again a second later (vector `same-second`).
- Re-posting the current event for an id or the current reset is idempotent
  (`200`).  Re-posting an older one is `409` stale.

What a node keeps: each grant id until the latest `expiration` it has seen for
it, and each reset floor for 90 days after its `created_at`.  After that no
event the record could refuse can still be unexpired.

### 4.6 Scopes

| Scope | Lets the device | Served by |
|---|---|---|
| `upload` | `PUT /upload`, `HEAD /upload`, `PUT /mirror` into its group, within `bytes` | Node (S3) |
| `get` | `GET` and `HEAD`, including ranges, of blobs its group holds | Node (S3) |
| `delete` | `DELETE` of its own claims | Node (S3) |
| `purge` | `DELETE` of every claim its group holds on a blob | Node (S3, used in S7) |
| `turn` | `POST /turn/v1/credentials` | Node's TURN issuer (S9) |
| `relay-read` | Subscriptions on a NIP-42 authenticated connection | Group relay (S8) |
| `relay-write` | Publishing on a NIP-42 authenticated connection | Group relay (S8) |

A service accepts scopes it does not serve and ignores them, so one grant can
cover a host that runs a node, a relay and a TURN issuer.  A keeper grants
`purge` only to keys it controls (its coordinator).  Listing (BUD-12) stays
self-only and needs an active grant with `upload`.

### 4.7 How this differs from device grants (kind 27540)

| | Device grant, kind 27540 | Group grant, kind 27541 |
|---|---|---|
| Signer | A node owner | An enrolled keeper (the room's authority key) |
| Names | A device and a recovery identity | A device only |
| Room | None | `d`, the room id |
| Lifetime | Event accepted for 10 minutes; separate `until`, up to two years | `expiration` is the grant's end, up to 90 days |
| Why | Posted once by the owner's app, straight away | Carried through the room and posted later, by several parties |
| Replay | Single-use event ids, per-device ordering | Per grant id ordering, idempotent re-post, revoked is terminal, reset floor |
| Revocation | Separate `t=revoke` at `DELETE /grants/v1/<device>` | `status` `revoked` on the same id, or `reset` |
| Authority | Every write implied | Explicit scopes |
| Reads | Unauthenticated, as for every `wildbloomd` blob | Authenticated and confined to the group |
| When it ends | Claims move to the issuing owner | Claims stay with the group; reads by other members continue |
| Content | Free text up to 512 bytes | Empty |
| Ceiling | Per key | Per device, inside the node owner's group ceiling |

### 4.8 Membership and epochs

Grants are not bound to room epochs.  KithMoot's keepers may rekey weekly on
a schedule; binding grants to epochs would re-grant every device every week
for nothing, because storage access follows admission, while which old files
a member can open follows the file keys in messages and the room's history
window.

- **Removal.** When a host removes a participant, the keeper (S4), in this
  order: records the removal; signs `revoked` for every grant id it issued to
  every device of that participant, at every node; pushes them (7.2); then
  publishes the rekey (kind 1462) as today; then posts the revocations in the
  new epoch so the remaining members can carry them.
- **Scheduled rekey.** Grants are unchanged.
- **Joining.** A device gets grants when the keeper admits it.  A persistent
  group can admit a member while the keeper is offline; that device chats on
  the room's relays at once and gets grants when the keeper is next online.
- **Leaving with a node.** The member unenrols the keeper on their own node
  and may remove the group's files.  The keeper's coordinator stops counting
  that node's copies.
- **Close.** The keeper posts a `reset` for the room at every node, then
  purges (S7).
- **Keeper changes machine.** The authority key moves with the room, so
  nodes see no change.
- **Authority key replaced.** A keeper keeps its room's inviter key for good;
  a compromised authority means a new room.  A browser that rotates its link
  forgets its old inviter key, which is one more reason group storage needs a
  keeper.  If the key were replaced, each node owner re-enrols the new key,
  the group's claims stay under the same enrolment, and every grant of the
  old key ends.  A handover event signed by the old key is open
  question O10.

## 5. Submitting events to a node

`POST /groups/v1/events` takes one kind 27541 event as the JSON body (at most
16 KiB).  The signature is the authority, so the request needs no
`Authorization` and anyone may post: the keeper, the device named, or any
member carrying a revocation.

| Status | Reason | When |
|---|---|---|
| `201` | `accepted` | A new grant, renewal, revocation or reset was recorded.  Body `{"state":"active"}`, `"revoked"` or `"reset"` |
| `200` | `unchanged` | This exact event is already the current one |
| `400` | `malformed`, `lifetime` | Rules 1 to 3 |
| `401` | `signature` | Rule 4 |
| `403` | `keeper`, `server`, `future`, `expired` | Rules 5 to 7 |
| `409` | `key-conflict`, `floor`, `stale`, `scope-changed`, `revoked`, `scope-taken` | Rules 8 to 11 |
| `413` | `too-large` | Over 16 KiB |

Reasons are the names the vectors use; the wire carries the status and a
short `X-Reason` text.  Responses carry `Cache-Control: no-store`.  The node
verifies the signature before touching its database, and limits the rate of
this route as a whole, since every request over Tor arrives from loopback.
Only an event that parses, verifies and names an enrolled keeper spends that
keeper's budget, and only a grant that changes the node's state does; junk has
a budget of its own, and a revocation, a reset or a replay of an event the node
already holds is never refused for rate.

A device may ask about its own grant with `GET /groups/v1/self`, signed with
NIP-98 by that device, to show how much of its ceiling is used.  It is
optional in S3.

## 6. Authenticated use

### 6.1 Tokens

Every Blossom request to a group node carries exactly one
`Authorization: Nostr <base64 kind 24242 event>` header.  The node decodes
standard or URL-safe base64, padded or not, as `wildbloomd` already does.  On
top of BUD-11 and the existing `wildbloomd` rules (exactly one `t` and
`expiration`, non-empty content of at most 1,024 bytes):

- at least one `server` tag, and one of them names this node.  BUD-11 allows
  an unscoped token; group mode refuses it;
- for `get`, `upload` and `delete`, at least one `x` tag, every one 64
  lower-case hex, and one of them the request's hash.  BUD-11 makes `x`
  optional for `get`; group mode requires it.  A BUD-11 client can meet both;
- `created_at` at most 30 seconds ahead of the node clock;
- `expiration` in the future, and no more than this after `created_at`:

| Verb | Endpoints | Longest token | Reuse |
|---|---|---|---|
| `get` | `GET /<sha256>`, `HEAD /<sha256>` | 300 s | Reusable until it expires |
| `upload` | `PUT /upload`, `HEAD /upload`, `PUT /mirror` | 300 s | Reusable until it expires |
| `list` | `GET /list/<pubkey>` | 300 s | Reusable until it expires |
| `delete` | `DELETE /<sha256>` | 604,801 s | Single use |

Read tokens are reusable because a range read makes many requests and a home
node should not keep a row per read.  A captured read token lets its holder
read only the hashes it names, at the node it names, until it expires, and
capturing it means breaking the transport.  Upload tokens are reusable so a
BUD-06 preflight and its upload can share one, as today.  A delete token is
spent once: KithMoot keeps signed deletes for a week and a second to retry
them (`BLOB_DELETE_RETRY_SECONDS`), so its lifetime allows that, and spending
it stops a replay from deleting a blob uploaded again later.

A request never carries its grant.  The node finds the grant by the token's
signer: the one active grant at this node that names that key.  Tokens stay
ordinary BUD-11, so existing Blossom client code works with one header.  A
client that is refused `403` posts its grant (section 5) and retries once.

### 6.2 Reads

`GET` and `HEAD` of `/<sha256>[.<ext>]`, with or without `Range`, need a
`get` token from a key with an active `get` grant, and the blob held by that
key's group.  Otherwise:

- no token, or a bad one: `401`, whether or not the blob exists;
- a valid token from a key without an active `get` grant: `403`;
- a blob the signer's group does not hold, including one held only by another
  group or by the node owner: `404`, the same answer as for a blob nobody
  holds.

So a hash is not enough to read, and a member of one group cannot learn what
another group on the same node holds.  A key whose grant has ended reads
nothing.

### 6.3 Uploads

`PUT /upload`, `HEAD /upload` and `PUT /mirror` need an `upload` token from a
key with an active `upload` grant.  The bytes are checked as today.  The claim
is the signer's, in its group.  The answer is `201` when the group did not
hold the blob and `200` when it did, whatever any other group or the node
owner holds, so the status is not an existence oracle across groups.  Per-blob
limits, the device's `bytes` and the group ceiling apply (section 9).

### 6.4 Deletes and purge

`DELETE /<sha256>` needs a `delete` token and one of:

- an active `delete` grant: removes the signer's own claim;
- an active `purge` grant: removes every claim the signer's group holds on
  that blob;
- a grant that had `delete` and ended less than seven days ago: removes the
  signer's own claim, and nothing else (O4, decided: allowed for seven days).

A blob with no claim of the signer (or, for `purge`, of its group) answers
`404`.  A spent delete token answers `404` if there is nothing to delete and
`409` if the claim is back, and never deletes twice.  The bytes go only when
the last claim of any group or of the owner is gone, as today.  A delete
reaches one node; reaching every holder is S7.

### 6.5 Clock skew

Nodes allow 30 seconds ahead.  Clients set `created_at` one second in the
past, as KithMoot already does, and keep read tokens short.  A client whose
clock is far wrong is refused `future` or `expired`; it can compare its clock
with the node's `Date` header and say so (section 11).  A node with a wrong
clock refuses every device, and the keeper's coordinator is the first to see
it.

### 6.6 Caching and CORS

The core serves blobs with `Cache-Control: public, max-age=31536000,
immutable`.  In group mode every `GET` and `HEAD` answer carries
`Cache-Control: private, no-store` and `Vary: Authorization` instead, so a
reverse proxy in front of a direct-mode node never serves a blob to the next
person who asks.  A node never answers `304` to a request without a valid
token.  Clients keep their own copy of an envelope if they want one.  Tokens
never go in a URL.  `OPTIONS` stays unauthenticated, reveals nothing, and
allows the `Authorization`, `Range` and `X-SHA-256` request headers.

### 6.7 Refusals

| Status | Reason | Meaning |
|---|---|---|
| `400` | `bad-request` | The request itself cannot be read, such as an upload without `X-SHA-256` |
| `401` | `missing`, `encoding`, `event`, `signature`, `verb`, `server`, `hash`, `future`, `expired`, `lifetime` | The token itself is absent or wrong; the client can see why from its own token |
| `403` | `not-granted` | The token is valid but its signer has no active grant with that scope here.  One reason whatever the cause: unknown, revoked, expired or missing scope |
| `404` | `absent` | Not held by the signer's group (or, for a delete, not the signer's) |
| `409` | `spent` | A spent delete token whose claim is back |

Checks run in that order, and the signature is verified before any database
lookup, so an unknown key and a known one cost the same.  Only the holder of
a device key can make a valid token for it, so `403` tells nobody else
whether a key is granted.

### 6.8 Mirrors between group nodes

`PUT /mirror` makes the destination fetch the blob from a source URL.  Between
two group nodes that fetch is a read, and the source now refuses it without a
token.  Two ways out, for S7 to choose (open question O8): the coordinator
puts a `get` token for the source into the mirror body, which the destination
sends to the source and never stores; or the coordinator downloads and uploads
itself, at the cost of its own bandwidth.

### 6.9 TURN and relays

- **TURN (S9).** The node TURN issuer accepts its existing NIP-98 request from
  a key with an active `turn` grant, with the same per-device budget, and
  refuses ended keys.  Whether it returns a `peer` credential to a group key is
  S9's choice.
- **Relays (S8).** A group relay authenticates the connection with NIP-42 and
  checks that the authenticated key has `relay-read` or `relay-write` for that
  relay's host name.  It gates the connection, not each event's author:
  several room kinds are signed by throwaway or one-time keys (call bells
  1464, signal wraps 21059, quiet drops 1059, member epoch grants 20472).  A
  relay takes grant events as `EVENT` messages, keeps them in its authority
  store, answers `OK`, and never stores or fans them out.

## 7. Delivery

### 7.1 Keeper to device, inside the room

The room is end to end encrypted, and its control channel already carries
every structural op, believed only when signed by the authority.  A grant
event is already signed by the authority, so it rides as it is, one event per
op (an event is about 700 bytes; a control message is chat text of at most
2,000 characters):

```json
{"op":"storage-grant","event":{ "kind": 27541, "...": "..." }}
```

- The keeper sends one when it admits a device, when it renews (proposed:
  when a third of the grant's life is left), and when a device asks with
  `{"op":"storage-grant?"}`.  The asker is the message's credential-bound
  device, as for `hand`, so the request names nothing.
- A receiver keeps an event only if it verifies, is kind 27541, follows
  section 4, is signed by the authority pinned in its link, and names its
  room id.  It keeps a grant whose `device` is its own key, and every
  `revoked` grant and reset, to carry to nodes.
- Any member may repost a revocation or a reset: the signature, not the
  sender, is what counts, so the op has no `host`.
- Older clients ignore an op they do not know.

The control channel is kept on relays for the room's history window, so a
device that was offline still finds its grant.  A grant sealed to each device
(like kind 20469) would hide grants from other members, but needs a new kind,
and ephemeral events are not kept for an offline device (open question O12).

### 7.2 How a node obtains events

All three paths use `POST /groups/v1/events`:

1. **The keeper pushes** every grant, revocation and reset it signs to the node
   it names, over the transport it already uses for that node (Tor or HTTPS),
   and keeps a journal entry until that node answers `200`, `201` or `409`.
   `429` (`rate`) and `503` are retryable: the keeper keeps the entry and tries
   again later.  Any other answer (a node that no longer enrols the keeper,
   say) stops the retries for that node and is reported to the room's hosts.
2. **The device posts its own grant** on first contact with a node, after a
   renewal, and after any `403`.
3. **Every member device carries revocations and resets.**  Before its first
   request to a node in a session, a device posts each `revoked` grant and
   reset it holds for that node and has not yet seen acknowledged there.

No grant rides inside a Blossom request, and no node fetches grants from
anywhere.  A header carrying the grant on every request was considered and
rejected: it would make tokens non-standard, cost a second signature check per
request, and add nothing the post-and-retry does not.

### 7.3 Revocation reaching a node that was offline

A removed device cannot be relied on to deliver its own revocation.  It can
post its old active grant to a node that has not yet heard the revocation, and
that grant is honoured until one of these happens first:

- the keeper's journal reaches the node;
- any member device that read the revocation in the room contacts the node;
- the grant expires (at most 90 days; KithMoot's default is 30 days, renewed when 10 are left, O3).

Once the revocation lands, the older grant can never land again, at that node
or by replay.  A node that comes back online cannot know what it missed; the
contract bounds that window, it does not close it.

### 7.4 What a removed device can still do

It keeps every envelope it downloaded and every file key it received, and can
decrypt and share them.  It cannot fetch anything more from a node that knows
of its removal, upload, get TURN credentials or use a group relay.  For seven
days after its grant ended it may delete its own uploads (6.4).  This is
stated, not fixed: no storage contract can take back copies.

## 8. What each party learns

| Party | Learns | Never sent |
|---|---|---|
| A group node | The authority key and room id (already public on the room's rekeys); every granted device key with its scopes, ceiling and expiry; each blob's hash, size, upload time and uploader key; when each device reads which blob (so it holds fetch times, which retention from last fetch would use); IP addresses unless Tor is used.  By watching relays it can link device keys to the room's roster and rekey traffic | Room secret, room key, epoch keys, the link and its bearer, file keys, file names, types or contents, participant keys, display names, which person a device belongs to, and any other node |
| The keeper | What any member sees, plus every grant it signed and which participant each device belongs to | Nothing it does not already hold as a member |
| Other members | Every device's grants, so which devices may use which nodes, with scopes and ceilings | Nothing they did not already see as members |
| Relays | The keeper's `storage-grant` ops as ordinary encrypted chat events of a size and time | Grants, nodes, hashes, provided S5 stops the bare kind 1063 announcement for group uploads |
| Another node | Nothing from this contract | Grants for other nodes |
| ForgeSworn | Nothing | Anything about the group |

KithMoot today publishes a kind 1063 event bare on the room's relays for each
upload in an ordinary room, naming the URL and hash.  For a group node that
would publish the node's address and tie it to a device key.  S5 must not
publish it for group uploads, as quiet rooms already do not.

## 9. Quotas and retention

- **Per device.** `bytes` charges every claim the device holds, as a friend
  ceiling does today.  It stops counting when the grant ends.
- **Per group.** The node owner's group ceiling charges each blob the group
  holds once, including blobs held only by keys whose grants have ended.
- **Per blob.** The node's own per-blob limit.
- **Full node.** Refuses new uploads (`507`) rather than evicting group
  claims.  A group never evicts the owner's files or another group's.
- **Several devices.** Each device gets its own `bytes`.  A keeper caps grants
  per participant (O5, decided: up to five); a node cannot, since it never learns
  participants.
- **Requests.** The node sets per-key limits on request rate, concurrent
  streams and read bytes.  The figures are the node owner's (open question
  O13).
- **Retention.** Node-local in this profile: an enrolment setting.  KithMoot's
  design wants the group's expiry, by default 90 days from last fetch, carried
  in the grant; that and delete propagation belong to S7 (open question O7).

## 10. Threat review

| Threat | What the contract does | What it does not solve |
|---|---|---|
| Replayed tokens | `server` and `x` required; read and upload tokens live at most 300 s; delete tokens are single use | A captured read token works for its hashes until it expires, for whoever broke the transport |
| Replayed grant events | Per grant id ordering, revoked terminal, reset floors, records kept until every version has expired | Nothing more is needed while records are kept; a lost grant database forgets revocations (back it up with the store) |
| Revoked keys | Refused at once for every request except a seven-day delete of their own claims | A node that has not heard the revocation honours the grant until it does or the grant expires (7.3) |
| Wrong room | A grant names one room; reads see only the signer's group; a key is in one group per node | A node owner who enrols two keepers serves both; that is their choice |
| Wrong node | A grant names one node; tokens must name the node | Nothing |
| Expired grants | Checked on every request, not only at posting | Clock errors move the edge (6.5) |
| A stolen device key | Bound to its scopes and ceiling until the keeper revokes it; it cannot sign grants | The thief reads what the device could read and deletes that device's uploads until revocation lands.  It already holds the room key from the same device |
| A member exhausting quota | Per-device `bytes`, the group ceiling, per-key request limits | Several devices per participant multiply `bytes` unless the keeper caps them |
| A malicious node | Learns only what section 8 lists; cannot forge grants or tokens for other nodes; bytes are content-addressed and FSWNENC2 is authenticated | It can refuse, lose or delete, log everything it sees, and link device keys to relay traffic.  A member's machine is theirs |
| Keeper compromise | Blast radius is one room on the nodes that enrolled its key; unenrolment ends every grant at once; group ceilings bound disk | The attacker can grant itself every scope, read all the group's ciphertext, revoke members and purge every copy.  It also holds the room key, so the room itself is lost |
| Grant forwarded to a non-member | Useless without the device's secret key | A member who hands over their device key, or downloads and re-shares, cannot be stopped; removal is the remedy |
| Downgrade to an old open mode | Group mode refuses open shelter, guests and discovery at start; reads always need a token; clients never fall back to a public server and refuse a node that serves an unauthenticated read (S5) | A node owner can switch group mode off or publish what they hold (ciphertext).  The probe proves only what that node did at that moment.  Old clients that ignore the storage op upload to whatever server their person chose |
| Denial of service on a home machine | Bounded headers and bodies; tokens checked before any body is read; signature checked before any database or disk work; per-key limits; Tor's onion-service proof-of-work defence where available | Per-address limits are useless over Tor.  An attacker who knows the onion address can still make the node verify signatures and Tor do its work.  S5 keeps the address off relays |
| Existence oracle across groups | Reads answer `404` for blobs another group holds; uploads answer `201` unless the signer's own group held the blob | Timing of deduplicated writes, which nobody has measured |
| Shared caches | `private, no-store`, `Vary: Authorization`, no unauthenticated `304` | A proxy that ignores HTTP caching rules |
| Kind confusion | 27541 cannot be read as a token; tokens are 24242 only; device grants keep 27540 | Nothing |
| Probing for granted keys | One `403` reason for every cause; only a key's holder can sign for it | A granted member learns what any member already knows |

## 11. Failure behaviour

A client never falls back to a public server or an unauthenticated read.
When a group node will not do what it asks, it says so plainly:

| Situation | What the client does | What the person is told |
|---|---|---|
| No grant yet | Asks with `storage-grant?`; keeps files in the outbox | "Group files will be available once the keeper has let this device in." |
| No granted node answers an upload | Keeps the envelope and holds the message (KithMoot's outbox); retries; offers Cancel and sending straight to someone online | "Waiting for the group's storage." |
| No granted node answers a read | Tries every node the room names, then waits | "This file is on the group's computers, and none of them can be reached right now." |
| `403` after removal | Stops using the group's storage | "This device is no longer let in to the group's storage." |
| `future` or `expired` and the node's `Date` disagrees | Stops retrying | "This device's clock is wrong, so the group's storage refused it. Check the date and time." |
| A node serves an unauthenticated read | Stops using that node | "One of the group's computers is giving files to anyone who asks, so this app has stopped using it. Tell the person who runs it." |
| Grant near expiry with the keeper offline | Keeps working until it ends | "The group's keeper has not been online for a while. Group files stop working on <date> unless it comes back." |
| A delete reaches some nodes | Records the rest (S7) | "Deleted from N of M group computers." |

## 12. wildbloomd mapping (for S3)

Built in S3.  The names and shapes S3 settled are in the right-hand column.

| Element | In `wildbloomd` |
|---|---|
| Group mode | A start flag, `--group-mode` (`WILDBLOOM_GROUP_MODE`).  Refuses `--open-shelter`, the guest tier, service discovery (kind 31402, `--service-profile`) and paid profiles (`--checkout-profile`) at start-up, and needs at least one keeper.  Makes every read need a token; sets the cache headers in 6.6 |
| Enrolment | A repeatable `--group-keeper <hex>:<ceiling bytes>[:<room>+<room>]` (`WILDBLOOM_GROUP_KEEPERS`, comma-separated), checked at start like `--friend-grant`.  The keeper is 64 lower-case hex, the ceiling is bytes per group, and the optional rooms (64 lower-case hex, joined with `+`) limit which room ids that keeper may open here.  A keeper listed twice, or also an owner, friend, device-grant, recovery, service or group device key, stops the node starting.  There is no enrolment file in S3 |
| Event route | `POST /groups/v1/events`, beside `/grants/v1`.  At most 120 new or changed grants a minute from enrolled keepers and 600 refused posts a minute from anyone, across all callers; revocations, resets and replays are never counted.  A reason is the response's `X-Reason`.  `GET /groups/v1/self` is not built (optional in S3) |
| State | A private `0600` SQLite file `group-grants.sqlite3` beside the store, like `device-grants.sqlite3`: grant rows by keeper and grant id, reset floors, the key to group map, and the spent delete token ids (the `used_events` table and `consume_event` of the device grants, in this file).  Grant rows are kept until their latest expiration plus the seven-day delete grace, floors for 90 days, spent ids until the token expires; a key stays in its group for good.  Part of retention state: back it up with the store |
| Claims | Each group key that ever had an `upload` grant is a core friend grant with core grant id `wildbloom-group:<keeper>:<room>`, the far-future sentinel expiry device grants use, and the ceiling of its newest upload grant.  Its claims are ordinary friend claims in the store.  The real expiry and scopes are enforced by a gate in front of the core router |
| Reads | The gate's check for `GET` and `HEAD`, before the core serves the bytes.  A blob counts as held by a group while any key of the group claims it.  The gate keeps that view in memory and rebuilds it from the store's claims after a restart |
| Uploads, preflights, deletes | Completed by the gate through the store, not by the core router: the core checks a token against the machine clock and has no `get` verifier, so a group token (which the gate verifies on the node's clock) cannot go through it.  `PUT /mirror` is allowed by the gate and then made by the core.  A key whose group does not hold a blob gets a claim on it only once the whole body has been read and hashed; the core drops a mirror's fetched bytes when it already has the blob, so such a mirror is taken back and answers `409` `wrong-blob` |
| Ended keys | Stay in the core's friend set while they hold claims; the gate refuses them.  Their claims are not moved to an owner, unlike device grants |
| Spent ids | The device grants' `consume_event` table shape, keyed by token id until its expiry, in the group file |
| TURN | `device_auth` accepts a key with an active `turn` group grant (S9, not built) |
| Pairing issuer | Not open to group keys |
| Device grants | Keep working; a key cannot be in both.  A device grant refuses a group key, and a group grant refuses a device-grant key |

What S3 chose where the profile is silent or an open question applies (section 15):

- The owner's own keys, friends and device-grant keys need a token to read too
  (O11, the stated default), and a valid `get` token shows them only the blobs
  they hold themselves.  Their uploads, mirrors, deletes and lists reach the
  core as before.  An enrolled keeper is not a user and is refused `403`.
- A room the enrolment does not list is refused `403 keeper`.
- A length is judged as for a blob the node has never seen (the per-blob
  limit, the key's own ceiling, the group ceiling, the node quota) before any
  byte is read, whenever the key, or for a group key its group, does not hold
  the hash; only then are the bytes read and hashed.  A stored hash and an
  unknown one answer alike at every length, on `PUT` and `HEAD /upload`, for
  group keys and for owner, friend and device-grant keys.
- A mirror by an owner, friend or device-grant key for a blob it does not hold
  is not refused up front, because that would show whether the node contacts
  the source and so whether the blob exists.  The core makes the claim, the key
  cannot read the blob while the gate vouches for it, and the claim is taken
  back with the answer a wrong-bytes mirror of a new hash gets.
- A new upload key is pushed to the core while only the push lock is held, so
  a revocation or a reset never waits on a core write in flight.  A keeper's
  grant budget is its own.
- `/healthz` in group mode says `{"status":"ok"}` and nothing about storage.
  The desktop app reads storage figures from it, so it must not run its
  `wildbloomd` in group mode.
- `--storage-proofs` is refused with `--group-mode`: its proofs answer any key
  whether a blob is stored.  `/healthz` answers liveness only and `/` is
  never cached by a shared cache.
- Per-key request-rate and read-byte limits (O13) are not built; the only
  limits are the ceilings, the per-blob limit, and a cap on concurrent group
  upload streams (`--max-concurrent-writes`, counted apart from the core's).
- Retention from last fetch (O7) is not built: a group's files stay until a
  holder deletes them or the node owner removes them.
- A mirror's size is unknown until the core has fetched it, so the group
  ceiling is checked after it: a mirror that would pass the ceiling is taken
  back and answers `507`.
- A delete token is spent by any permitted attempt, including one that finds
  nothing to delete.

## 13. Bothy mapping (proposal; needs decented's agreement)

Bothy already has circle event grants: kind 24242 with `t=event-grant`,
`server` as the box's canonical `ws://<onion>/events` URL, `d` (64-hex room),
`p` (persona), `device`, `grant` (32 hex), `read` and `write` kind lists
(read 1460, 1462 and 20461; write 1460 and 20461), `expiration` up to 400
days, and `status` `active` or `revoked`, signed by a keeper key of the box's
active claim (bothy-node `crates/bothy-core/src/events/circle_grant.rs`).  Its
tag list is closed, so Bothy cannot honour a group grant as it stands.  The
revocation model above is borrowed from it on purpose.

| Group grant | Bothy circle grant | Gap |
|---|---|---|
| Kind 27541 | Kind 24242 `t=event-grant` | Bothy would accept 27541 too, or the keeper signs both |
| Signer: an enrolled room authority key | A keeper key of the box's claim (master, stash or persona) | Bothy enrols keepers by claim, not per room |
| `d` room id | `d` room | Same meaning |
| `device` | `device` | Same |
| No participant | `p` persona, required | Bothy would allow `p` absent, or equal to `device`, so the box does not learn the person |
| `server` host name | `server` canonical Link URL | Each side keeps its own form |
| `grant`, `status` | `grant`, `status` | Same rules: later `created_at`, scope fixed per id, revoked terminal |
| `relay-read`, `relay-write` | `read`, `write` kind lists | Bothy checks each event's author; KithMoot room kinds signed by throwaway keys need connection-level authority |
| `upload`, `get`, `delete`, `purge`, `bytes` | None in event grants; Bothy's storage promises are kind 30642 shelter grants, which name keepers, never boxes | A storage mapping is new work for both |
| `turn` | None | Not proposed |
| `reset` | None | Bothy would add it, or revoke each id |
| 90 days | 400 days | Agree one figure, or each keeps its own |

Box profile: KithMoot's design asks decented for a closed "group box" profile
(drop tier off, public `wss://` fronts off, Link only), its decision D9.

## 14. Acceptance checks

### S3: `wildbloomd` group mode

- Every vector in `vectors/group-grants-v1.json` passes: each `grantEvents`
  case on a fresh node, each `requests` case after `requestFixture`, each
  `sequences` case in order, with each case's own clock.
- Start-up in group mode refuses open shelter, the guest tier and discovery.
- Unauthenticated `GET`, `HEAD` and range reads answer `401` for stored and
  missing hashes alike; a reverse proxy test sees `private, no-store` and
  `Vary: Authorization`.
- A revoked, reset or expired key is refused on the next request, with no
  sweep delay.
- Grant rows, floors and spent ids survive a restart.
- The device and group ceilings are enforced; a full node refuses rather than
  evicts.
- After a member's grant ends, another member still reads what they uploaded.
- With group mode off, every existing test passes unchanged, and owner and
  device-grant flows are as before.

### S4: the keeper mints and revokes

- Grants are signed with the room's authority key; grant ids are 16 fresh
  random bytes; one grant per device per node; renewal reuses the id.
- Admission, removal and re-admission journeys against a local `wildbloomd`:
  the removed device's `GET` is refused, another member still reads its
  uploads, and the re-admitted device has a new grant id.
- Revocations are signed for every device of the removed participant at every
  node, pushed, journalled until acknowledged, and posted in the new epoch.
- A node offline at the removal refuses the device once the keeper's journal
  or another member reaches it, even if the device posts its old grant first.
- Close posts a reset at every node.  The journal survives a restart.
- No grant event is published bare on any relay; every `storage-grant` op
  fits one control message.

### S5: the room carries its nodes

- The authority signs the room's list of nodes, versioned like `relays`;
  older readers ignore it.
- Clients upload only to listed nodes where they hold a grant, hold files in
  the outbox when none answers, and never fall back to a public server.
- Reads sign `t=get` with `x` and `server`; a range read reuses one token
  within its life; delete confirmation uses an authenticated `HEAD`.
- No bare kind 1063 is published for a group upload.
- A client refuses a node that serves an unauthenticated read, and says so.
- End to end with two local nodes, one offline: the file is delivered once
  the second appears.

## 15. Open questions

For the owner:

Decided by the owner on 21 October 2026:

- **O1.** Sign with the room authority key, not a dedicated per-room grant
  key.
- **O3.** KithMoot's default grant lifetime is 30 days, renewed when 10 are
  left, under the 90-day cap.
- **O4.** A removed device may keep deleting its own uploads for seven days,
  so "Leave and tidy up" and KithMoot's retry journal keep working.
- **O5.** The keeper grants every admitted device automatically, up to five
  devices per participant.

Still open:

- **O2.** Use the room id as `d` (chosen), or a derived storage selector?  With
  the authority key as signer, a derived selector hides nothing.
- **O6.** Default per-device and group ceilings: no figure is assumed here.
- **O7.** Retention from last fetch: a tag in the grant, or one setting at
  enrolment?  Either way the node keeps fetch times.
- **O8.** Mirrors between group nodes: a source token in the mirror body, or
  the coordinator copies by itself?
- **O9.** Should enrolment ever be remote (an owner-signed event), or only local
  as here?
- **O10.** A handover event signed by an old authority key, so nodes follow a
  replaced key without their owners?  Not proposed: a stolen key could hand
  itself on.
- **O11.** In group mode, do owner and device-grant keys keep unauthenticated
  reads of their own files?  Proposed: no, every read needs a token.
- **O12.** Grants visible to all members on the control channel (chosen), or
  sealed to each device under a new kind?
- **O13.** Per-key rate and read limits for a home node.  S3 builds none.
  One consequence: the proofs of owner, friend and device-grant keys (reading
  an upload's bytes before a claim on a blob they do not hold) take the same
  write permits as group uploads, so one such key can hold every permit for
  as long as it trickles a body, and group uploads then answer `429`.  Group
  members can do the same.  The remedy is a separate permit pool for proofs,
  or per-key limits on concurrent streams and read bytes.
- **O14.** Register kind 27541 upstream after a relay scan, or keep it a
  project kind?

For decented, where Bothy is involved:

- **B1.** Would Bothy accept kind 27541 beside its 24242 event grants, or
  should a keeper sign both shapes?
- **B2.** Can `p` be absent or equal to `device`?
- **B3.** Can a box enrol a room authority key, rather than only its claim's
  keeper keys?
- **B4.** How should the storage scopes meet Bothy's shelter grants, which name
  keepers rather than boxes?
- **B5.** Can a sheltered relay gate writes by the authenticated connection, so
  call bells, signal wraps, quiet drops and member epoch grants can ride it?
- **B6.** One lifetime cap, or each its own?
- **B7.** A reset event for Bothy?
- **B8.** The closed group box profile (D9).

## 16. Vectors

`vectors/group-grants-v1.json`, profile `group-grants/1`.  Keys, hashes and
host names are synthetic.  The rooms are KithMoot's own vector rooms
(`roomDerivation`, `typical-secret-1` and `-2`), so a room id traces back to
that file.  Every case carries its own node clock `now`, and each negative
case breaks exactly one rule.

- `keys`, `rooms`, `node`, `blobs`: the fixture.  The node is
  `grove.example.net` with one owner and two enrolled keepers; another node is
  `heath.example.net`.  `blobs` gives each blob's bytes as UTF-8 text and
  their SHA-256; an upload step's `body` names one.
- `grantEvents`: one event posted to a fresh node, with the expected status,
  reason and state.
- `requestFixture`: four grants and three uploads, applied to a fresh node
  before every `requests` case.
- `requests`: one Blossom request after the fixture, with the expected status
  and reason.
- `sequences`: ordered steps (`post`, `request` or `check`) against one node.
  `check` asks whether a key has an active grant with a scope at that moment.

To regenerate or check, from `scripts/group-grants`:

```sh
npm ci
node vectors.mjs --check   # the committed file must match a fresh build byte for byte
node vectors.mjs --write   # rewrite it
```

The script signs with `@noble/curves` 2.0.1 (BIP-340 with 32 zero bytes of
auxiliary randomness, so output is deterministic), hashes with `node:crypto`,
and pins `nostr-tools` 2.25.2, the version in KithMoot's lockfile.  Each case
states its expected outcome by hand; a reference model of this document runs
over every case and must agree, and `nostr-tools`' `verifyEvent` re-checks
every id and signature independently, which must fail exactly for the
`signature` cases.  S3 adds Rust tests that read the same file.
