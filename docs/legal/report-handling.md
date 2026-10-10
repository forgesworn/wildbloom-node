# Report handling runbook: running a Wildbloom Node

> **DRAFT, 10 October 2026.** Not legal advice, and it has not been
> reviewed by a lawyer. Drafted from the code on `main` (4474ce1). It
> describes what the software can and cannot do, and a generic way to
> handle reports. It does not say what the law requires of you.

## ForgeSworn publishes software; it does not run nodes

ForgeSworn publishes the Wildbloom Node software. It does not run or host
nodes, for itself or for anyone else. Nothing found in this repository, in
the `wildbloom` repository's Cloudflare Pages deployment (which serves only
a static build), or in the `kithmoot` deployment configuration stands up a
public `wildbloomd` instance.

Anyone who runs a node, or offers one to other people, is responsible for
their own legal position in whatever jurisdiction applies, including how
they handle reports of illegal content. Take your own legal advice before
you open a node to other people.

## What the operator can see

The operator, and anyone with root on the host, can read what the node
stores. Uploads sent with encryption turned off arrive and are kept as
plaintext, with their filename and type; encrypted uploads are kept as the
envelope the uploader sent.
<!-- Store is SQLite plus content-addressed files on disk
(../OPERATOR-RESPONSIBILITIES.md, "Removing a blob by hash"); plaintext
upload option: wildbloom src/main.ts:531-533, index.html:352. -->

## What the software can and cannot do

Read [`../OPERATOR-RESPONSIBILITIES.md`](../OPERATOR-RESPONSIBILITIES.md)
("What the software can and cannot do for you") before promising a reporter
anything. In summary, as of `main` (4474ce1):

- You can stop admitting a specific friend key, but only by restarting the
  node with an updated `--friend-grant` list, or by waiting for the grant to
  expire.
- You can stop admitting all unknown guest keys, by restarting without
  `--open-shelter`. You cannot block one guest key without also blocking
  every other unknown key. There is no runtime per-key block list (`[GAP]`
  item 4 in `../OPERATOR-RESPONSIBILITIES.md`).
- You cannot force-remove a blob or a specific claim through the running
  application; only the claiming key can `DELETE` its own claim (`[GAP]`
  item 3). A force-removal today means stopping the node and editing the
  on-disk SQLite database and content-addressed store directly, which is
  unsupported, undocumented tooling and carries a real risk of corrupting
  the store.
- The sure way to stop serving something is to stop the whole node: stop
  `wildbloomd`, or the container or host it runs in, and keep it stopped
  until the content is dealt with.

Do not tell a reporter you can "remove a specific uploader's access
instantly" or "delete a file within minutes" until these gaps are closed.
Tell them honestly what you can do and on what timescale.

## Contact

Publish a contact address for reports about content on your node, and check
it. `[INPUT: the operator's report contact.]`

## A generic process

The specifics, including any mandatory reporting route, timescales and how
long records must be kept, are for your own legal advice.
`[LEGAL REVIEW: each operator, for their own jurisdiction.]`

### Receive

1. **Log every report** on receipt, whatever channel it arrives on: date and
   time received, the reporter's contact detail if given, what they
   reported, the hash or claim they identified, and the channel it arrived
   on.
2. **Acknowledge** the report. `[DECISION: target acknowledgement time.]`
3. **Triage severity.** Anything that may be child sexual abuse material is
   the most serious category; see below.

### Investigate

1. Identify the exact hash and, if named, the claiming key or keys the
   report concerns.
2. Check whether the hash is stored on your node (`GET /healthz` for
   process and storage counters; direct database inspection for claim
   detail, since there is no public inventory endpoint by design; see
   `docs/PROTOCOL.md`, "There is no public inventory endpoint").
3. Do not download or open the content to check it unless you are confident
   it is safe to view. For anything that could be child sexual abuse
   material, do not view it at all.
4. Record what you found: whether the hash exists on this node, which tier
   it is held under (owner, friend or guest), and whether any other claim on
   the same hash exists.

### Act

Given the gaps above, the available actions are, in order of preference:

1. **Ask the claiming key to remove it**, if you can identify and reach
   them, and the report does not need urgency that rules this out.
2. **Stop the node and manually remove the blob and its claim rows** from
   the SQLite database and CAS directory, then restart. Document exactly
   what was removed, when, and by whom, since this bypasses the
   application's own integrity guarantees.
3. **Restart with a changed configuration** to stop admitting the reported
   key going forward (drop a `--friend-grant` entry, or disable
   `--open-shelter` if the key came in as a guest).
4. **Take the node fully offline** if the report is severe enough that
   partial measures are not acceptable.

### Child sexual abuse material

Treat reports of child sexual abuse material as the most serious category
and pass them to the relevant authorities in your jurisdiction. Do not
view, copy or forward the material to check a report. Stopping the whole
node, if that is the only sure way to stop serving the hash, is preferable
to inspecting the content to be more surgical.

### Record

Keep a written log of every report and what was done, including reports
that led to no action and why. Keep nothing beyond what you decide, on
advice, to keep. The log should not itself contain the reported content.
`[DECISION: retention period for this log; see
../OPERATOR-RESPONSIBILITIES.md, "Retention".]`

## Review

Review this runbook whenever the software's removal or blocking
capabilities change (see the gaps tracked in
`../OPERATOR-RESPONSIBILITIES.md`).

## Open items

1. The manual database-edit removal path is unsupported and undocumented by
   the software itself; consider whether a supported operator-delete command
   should be built before this path is relied on in practice. `[GAP]`
2. No runtime per-key block list for any retention tier. `[GAP]`
3. Each operator sets their own report contact, timescales and record
   retention, on their own legal advice. `[INPUT, per operator]`
