# Operator responsibilities

> **DRAFT for legal review, 25 September 2026.** Not legal advice, and it has
> not been reviewed by a lawyer. Drafted from the code on `main` (fa9ab72)
> for whoever runs a Wildbloom Node to read before doing so. Text in
> `[square brackets]` is a decision or fact each operator must fill in for
> their own instance.

## You are the operator

Wildbloom Node is software. ForgeSworn publishes the code; it does not run,
own or control your node. If you start `wildbloomd`, whether headless or
through the desktop app, **you are the operator** of that instance under UK
law, in the same way you would be if you ran any other server that stores
files on your own disk and serves them to other people.

This is true whatever transport you choose (loopback-only, a persistent Tor
v3 onion, or your own HTTPS reverse proxy), and whatever retention tiers you
configure (owner-only, friends, or open shelter for guests). Running the
software is what makes you the operator, not any particular configuration
flag.

If ForgeSworn itself runs a public Wildbloom Node, that instance is
ForgeSworn's responsibility as operator, under the process in
[`docs/legal/report-handling.md`](legal/report-handling.md). As of this
document's date, nothing in this repository, or in the deployment
configuration for wildbloom.forgesworn.dev, stands up a public Wildbloom
Node: the hosted web app is static (see
[Wildbloom's online safety position](https://github.com/forgesworn/wildbloom/blob/main/docs/legal/online-safety-position-draft.md)),
and it runs no Blossom server. `[DECISION: if this changes, for example if
ForgeSworn stands up a public wildbloomd instance, update this paragraph and
treat that instance under the report-handling runbook.]`

## Why this matters under UK law

A Wildbloom Node that accepts uploads from anyone other than yourself (a
friend grant, or open shelter for guests) stores files chosen by other
people and can serve them to whoever asks for the right hash. That is the
shape of thing the Online Safety Act 2023 and UK GDPR regulate, and running
one brings duties that do not go away because the software is small,
self-hosted, or free.

**Online Safety Act 2023.** If your node accepts content from users other
than yourself, and that content can be encountered by other people (which is
the point of running a Blossom server), it can be a "user-to-user service" or
a "file-storage and file-sharing service" in Ofcom's risk-profile sense. That
brings duties to: assess the risk of illegal content, have a way for people
to report illegal content, act on reports, and keep records of what you did.
See Ofcom's guidance at
<https://www.ofcom.org.uk/online-safety/information-for-industry/guide-for-services/risk-assessments>.
`[LEGAL REVIEW: whether a small, non-commercial, self-hosted node with a
handful of friend grants meets the size and reach thresholds that trigger
these duties in practice; the duties apply in principle regardless of size,
but Ofcom's codes of practice scale by size and risk.]`

An operator who only ever admits their own keys (`--allow-pubkey` with no
`--friend-grant` and no `--open-shelter`) is storing only their own content.
That is much closer to a personal backup than a service to other users, and
the case for user-to-user duties is weaker. The moment you add a friend grant
or open shelter, you are storing content other people chose and can serve it
to third parties, and the analysis above applies. `[DECISION: each operator
should record, for their own instance, which of these two situations they
are in, and review it again if they change their configuration.]`

**UK GDPR.** If your node's logs, database or configuration hold anything
that identifies a real person, such as a Nostr public key tied to someone you
know, an IP address in a reverse-proxy log, or contact details for a friend
grant you noted down somewhere, you are a data controller for that
information and have UK GDPR obligations towards the people it concerns:
lawful basis, a way for them to ask what you hold, a way to correct or delete
it, and appropriate security. `[LEGAL REVIEW: whether a purely personal or
household activity exemption applies to a small self-hosted node run for
friends; this is fact-specific and the exemption is narrow.]`

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

## A report contact you must publish

If your node accepts anything other than your own keys, publish a contact
address people can use to report illegal or abusive content, and check it.
This is both good practice and, for content that may be illegal, part of what
the Online Safety Act expects of services that accept user content.

`[DECISION: each operator must choose and publish their own contact address.
For a ForgeSworn-run node, see
docs/legal/report-handling.md, which uses abuse@safety.forgesworn.dev.]`

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
  receive and what you did about them; the Online Safety Act's
  record-keeping expectations point towards keeping such records for a
  meaningful period (compare Ofcom's guidance for larger services, which
  suggests multi-year retention, though the exact expectation for a small
  self-hosted node is unsettled). `[LEGAL REVIEW]`

## Open items

1. Whether the Online Safety Act's user-to-user or file-storage duties
   formally apply to a small, non-commercial, friends-and-guests node, and
   at what point size or reach changes that answer. `[LEGAL REVIEW]`
2. Whether the household/personal-activity exemption from UK GDPR applies to
   a small self-hosted node. `[LEGAL REVIEW]`
3. No supported way to force-delete a blob by hash independent of the
   claiming key's own signature. `[GAP]`
4. No supported runtime per-key block or ban list for any retention tier.
   `[GAP]`
5. Each operator must choose, publish and check their own report contact.
   `[DECISION, per operator]`
