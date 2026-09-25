# Report handling runbook: a ForgeSworn-run Wildbloom Node

> **DRAFT for legal review, 25 September 2026.** Not legal advice, and it has
> not been reviewed by a lawyer. This runbook applies only to a Wildbloom
> Node that ForgeSworn itself operates. As of this document's date,
> **ForgeSworn does not run a public Wildbloom Node.** Nothing found in this
> repository, in the `wildbloom` repository's Cloudflare Pages deployment
> (which serves only a static build), or in the `kithmoot` deployment
> configuration stands up a public `wildbloomd` instance; `kithmoot` runs a
> separate Blossom server (`blossom-server-ts`) for its own chat attachments,
> and exposes a loopback-and-Tor-only read front so that other people's
> `wildbloomd` replicas can fetch and verify blobs it already holds, which is
> not the same as ForgeSworn operating a `wildbloomd` node itself. This
> runbook exists so that, if and when ForgeSworn does run one, the process is
> ready rather than improvised. `[DECISION: keep this note accurate; update
> it the moment any ForgeSworn infrastructure runs wildbloomd publicly.]`

## Contact

**abuse@forgesworn.dev** is the published contact for reports about content
on a ForgeSworn-run Wildbloom Node. `[DECISION: confirm this address is set
up, monitored, and named wherever a ForgeSworn-run node's /healthz or
equivalent public information page is served, per the general operator
responsibilities in ../OPERATOR-RESPONSIBILITIES.md.]`

## What we can tell a reporter today

Read [`../OPERATOR-RESPONSIBILITIES.md`](../OPERATOR-RESPONSIBILITIES.md)
("What the software can and cannot do for you") before promising a reporter
anything. In summary, as of `main` (fa9ab72):

- We can stop admitting a specific friend key, but only by restarting the
  node with an updated `--friend-grant` list, or by waiting for the grant to
  expire.
- We can stop admitting all unknown guest keys, by restarting without
  `--open-shelter`. We cannot block one guest key without also blocking every
  other unknown key.
- We cannot force-remove a blob or a specific claim through the running
  application; only the claiming key can `DELETE` its own claim. A
  force-removal today means stopping the node and editing the on-disk SQLite
  database and content-addressed store directly, which is unsupported,
  undocumented tooling and carries a real risk of corrupting the store.

Do not tell a reporter we can "remove a specific uploader's access instantly"
or "delete a file within minutes" until the gaps above are closed. Tell them
honestly what we can do and on what timescale.

## Intake

1. **Log every report** on receipt, whatever channel it arrives on (email to
   abuse@forgesworn.dev, a GitHub security advisory, or any other route):
   date and time received, the reporter's contact detail if given, what they
   reported, the hash or claim they identified, and the channel it arrived
   on.
2. **Acknowledge** the report. `[DECISION: target acknowledgement time, e.g.
   within 2 working days.]`
3. **Triage severity.** Anything that may be child sexual abuse material gets
   immediate priority and must not be downloaded, opened, or forwarded by a
   ForgeSworn person for review; see "CSAM and similarly severe content"
   below.

## Investigation

1. Identify the exact hash and, if named, the claiming key(s) the report
   concerns.
2. Check whether the hash is currently stored on the ForgeSworn-run node
   (`GET /healthz` for process/storage counters; direct database inspection
   for claim detail, since there is no public inventory endpoint by design —
   see `docs/PROTOCOL.md`, "There is no public inventory endpoint").
3. Do not download or open the content to "verify" it yourself unless you
   are confident it is safe to view. For anything that could be CSAM, do not
   view it at all; see below.
4. Record what you found: whether the hash exists on this node, which tier
   it is held under (owner, friend or guest), and whether any other claim on
   the same hash exists.

## Action

Given the current gaps (see "What we can tell a reporter today"), the
available actions on a ForgeSworn-run node are, in order of preference:

1. **Ask the claiming key to remove it**, if we can identify and reach them,
   and the report does not require urgency that rules this out.
2. **Stop the node and manually remove the blob and its claim rows** from the
   SQLite database and CAS directory, then restart. Document exactly what was
   removed, when, and by whom, since this bypasses the application's own
   integrity guarantees and must be auditable after the fact.
3. **Restart with a changed configuration** to stop admitting the reported
   key going forward (drop a `--friend-grant` entry, or disable
   `--open-shelter` if the key came in as a guest and no other legitimate
   guest traffic depends on it staying on).
4. **Take the node fully offline** if the report is severe enough that
   partial measures are not acceptable while a proper fix is prepared.

Record which action was taken, when, and why.

## CSAM and similarly severe content

Do not view, download, forward or store suspected child sexual abuse
material yourself. In the UK, report it to the Internet Watch Foundation
(<https://report.iwf.org.uk/>) and, where required, to the National Crime
Agency, rather than attempting to verify or handle it directly. Take the
affected node or the specific blob offline by the least-exposure route
available (stopping the whole node, if that is the only sure way to stop
serving the hash, is preferable to inspecting the content to be more
surgical). Preserve the hash and any report metadata for law enforcement;
do not preserve the content itself beyond what the law requires.

## Recordkeeping

Keep a written log of every report and what was done, including reports that
led to no action and why. `[DECISION: retention period for this log; see
../OPERATOR-RESPONSIBILITIES.md, "Retention".]` This log is separate from,
and should not itself contain, the illegal content reported.

## Review

Review this runbook whenever the software's removal or blocking
capabilities change (see the gaps tracked in
`../OPERATOR-RESPONSIBILITIES.md`), and at least once a year while any
ForgeSworn-run node is live.

## Open items

1. Confirm abuse@forgesworn.dev is live and monitored before this runbook is
   relied on. `[DECISION]`
2. Target acknowledgement and resolution times. `[DECISION]`
3. This runbook currently applies to no live instance; update the header
   note the moment that changes. `[DECISION]`
4. The manual database-edit removal path is unsupported and undocumented by
   the software itself; consider whether a supported operator-delete command
   should be built before this path is relied on in practice. `[GAP]`
