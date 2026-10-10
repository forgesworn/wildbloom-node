# Operator responsibilities

> **DRAFT, 10 October 2026.** Not legal advice, and it has not been
> reviewed by a lawyer. The capability facts below were drafted from the
> code on `main` (fa9ab72) and rechecked against `main` (4474ce1). For
> whoever runs a Wildbloom Node to read before doing so. Text in
> `[square brackets]` is a decision or fact each operator must fill in for
> their own instance.

## ForgeSworn publishes software; it does not run nodes

ForgeSworn publishes the Wildbloom Node software. It does not run or host
nodes, for itself or for anyone else, and it does not control your node.

Whoever runs a node, or offers one to other people, is responsible for
their own legal position in whatever jurisdiction applies, including how
they handle reports of illegal content. Take your own legal advice before
you open a node to other people. `[LEGAL REVIEW: each operator, for their
own jurisdiction.]`

[`legal/report-handling.md`](legal/report-handling.md) sets out a generic
way to handle reports, built on the facts below.

## What changes when you admit other people

An operator who only ever admits their own keys (`--allow-pubkey` with no
`--friend-grant` and no `--open-shelter`) is storing only their own content.
The moment you add a friend grant or open shelter, the node stores files
other people chose and can serve them to whoever asks for the right hash.
That is the point to take advice. `[DECISION: each operator should record,
for their own instance, which of these two situations they are in, and
review it again if they change their configuration.]`

This is so whatever transport you choose (loopback-only, a persistent Tor
v3 onion, or your own HTTPS reverse proxy).

## What the node holds and who can read it

- **Files.** You, and anyone with root on the host, can read what the node
  stores. Uploads sent with encryption turned off arrive and are kept as
  plaintext, with their filename and type; encrypted uploads are kept as
  the envelope the uploader sent.
- **Records about people.** Claim records hold each signer's public key.
  Reverse-proxy logs, if you keep them, hold IP addresses. Any notes you
  keep about who holds a friend grant are yours too.
- **Checkout, if you enable it.** Checkout routes are mounted only when you
  start the daemon with `--checkout-profile`. Its private state database
  holds orders bound to the buyer's public key, any Lightning refund address
  the buyer sent, and spendable LNURLcash notes in plaintext: keep it
  private, back it up securely and exclude it from diagnostics. Keep
  reverse-proxy body and query logging off, because LNURLcash query strings
  contain spendable assets. Give the Phoenixd adapter its limited-access
  password, not the spending password. See [`CHECKOUT.md`](CHECKOUT.md).
<!-- docs/CHECKOUT.md:3-7, 75-78, 109-111, 285-291; plaintext uploads:
wildbloom src/main.ts:531-533. -->

## What the software can and cannot do for you

This section is drawn directly from the current protocol
(`docs/PROTOCOL.md`) and CLI (`README.md`). Update it if the software's
capabilities change.

### Removing a blob by hash

**What exists today:** `DELETE /<sha256>` (BUD-12 + BUD-11) removes **the
signing key's own claim** on that hash. The bytes are only deleted once every
claim on that hash has been removed. This is a self-service removal for
whoever signed the claim, not an operator takedown tool.

**Gap:** there is no built-in way for the operator to force-remove someone
else's claim, or to force-delete a blob by hash regardless of who claims it,
through the node's own API or CLI. If you need to remove a specific blob that
you did not upload yourself, your options today are:

- stop the node, edit the SQLite metadata and CAS files on disk directly
  (unsupported, no tooling provided, at your own risk of corrupting the
  store), then restart; or
- rotate to a fresh data directory if the offending content cannot be
  isolated any other way (destroys everything else you hold too).

Neither is a real operational answer. `[GAP: a supported operator-forced
delete-by-hash command, independent of any signer's claim, does not exist in
this codebase as of fa9ab72. Track this as a feature request before treating
"remove a blob by hash" as an operational capability you can promise anyone,
including in response to a legal notice.]`

### Blocking an uploader

**What exists today:**

- `--allow-pubkey` is a startup allowlist of owner keys. There is no runtime
  "ban" command; changing who is an owner means changing the CLI flags (or
  the equivalent desktop-app setting) and restarting the node.
- `--friend-grant <pubkey>:<byte-limit>:<expiry>` gives a specific key a
  time-boxed, size-capped allowance. It naturally lapses at its `expiry`.
  There is no command to revoke a friend grant before its expiry without
  restarting with a changed configuration.
- `--open-shelter` is a single on/off switch for admitting unknown signed
  guest mirrors. There is no per-key denylist under open shelter: you cannot
  block one specific abusive key while leaving open shelter on for everyone
  else. Turning open shelter off blocks all unknown keys, including
  legitimate ones.

**Gap:** there is no runtime, per-key block or ban list, for any tier
(owner, friend or guest). `[GAP: as of fa9ab72, the only way to stop a
specific key is to restart the node with a changed configuration (removing an
`--allow-pubkey` or `--friend-grant` entry), or to turn off `--open-shelter`
entirely. Track a runtime revocation/denylist command as a feature request
before promising anyone a fast per-uploader block.]`

### What you can promise, honestly, today

- You can stop admitting a specific friend key by restarting with an updated
  `--friend-grant` list (or waiting for the grant to expire).
- You can stop admitting all unknown guest keys by restarting without
  `--open-shelter`.
- You can remove your own claim on a blob (and, if you were the only
  claimant, the bytes) with a signed `DELETE`.
- You cannot, today, instantly force-remove someone else's claim, or block
  one abusive key without a restart, or without also blocking every other
  key in the same tier. Say so plainly in your own reporting process rather
  than promising a capability the software does not have.
- The sure way to stop serving something is to stop the whole node: stop
  `wildbloomd`, or the container or host it runs in, and keep it stopped
  until the content is dealt with.

## A report contact

If your node accepts anything other than your own keys, publish a contact
address people can use to report illegal or abusive content, and check it.
`[INPUT: the operator's report contact.]`

## Retention

- **Blobs.** A blob you store stays on disk until every claim on it is
  removed (by the claiming key's own `DELETE`), or until you remove it
  yourself outside the application (see the gap above). There is no
  automatic time-based expiry of owner or friend claims; guest claims are the
  first evicted under storage pressure (`docs/STORAGE-POLICY.md`) but are not
  otherwise time-limited.
- **Metadata.** The SQLite database keeps claim records (signer public key,
  retention tier, declared type, grant expiry) for as long as the claim
  exists. `[DECISION: set and document your own retention period for
  anything you keep outside the application, such as reverse-proxy access
  logs or notes about who holds a friend grant.]`
- **Reports.** Decide and document how long you keep records of reports you
  receive and what you did about them, on your own legal advice.
  `[DECISION, per operator]`

## Open items

1. Each operator's own legal position, in their own jurisdiction, before
   opening a node to other people. `[LEGAL REVIEW, per operator]`
2. Each operator's retention periods for logs, notes and report records.
   `[DECISION, per operator]`
3. No supported way to force-delete a blob by hash independent of the
   claiming key's own signature. `[GAP]`
4. No supported runtime per-key block or ban list for any retention tier.
   `[GAP]`
5. Each operator must choose, publish and check their own report contact.
   `[INPUT, per operator]`
