# Operator checkout v1

The daemon mounts private checkout routes only when started with an explicit
`--checkout-profile` (and `--no-tor`). The browser has separate offer, quote,
payment, status and recovery actions. The desktop settings panel does not yet
configure this service. Both Lightning and exact-value LNURLcash pay the chosen
operator directly. No receiving credentials are bundled or enabled by default.

Controlled acceptance uses the real daemon and Chromium with synthetic receiving
services. It covers payment, restart recovery and encrypted paid uploads. This is
not live-wallet/mint acceptance or a production sales deployment.

The implementation reuses these pinned libraries:

- Shelter Kit `v0.5.0`: capacity holds and paid allowances.
- ForgeSworn `toll-booth-rs` at `acd8b1495b4033fcbf3156b9f32d70fcabec74fa`:
  the `LightningBackend` interface. Its generic monetary credits and L402
  middleware are not used. Its Rust Phoenixd module is currently a placeholder;
  this crate supplies a receive-only Phoenixd adapter implementing that interface.
  Live-wallet acceptance remains outstanding.
- `lnurlcash-core` at `adc9c475cf7a7cdd9ac09a059347d0aaae287995`: note parsing,
  authoritative information requests, rotation construction, replacement secret
  generation, mutation parsing and certificate verification. No HTTP client
  feature is enabled; the operator supplies I/O.
- `lightning-invoice` `0.34.1`: full BOLT-11 parsing/signature validation, exact
  amount, currency, payment hash and expiry checks.

No ForgeSworn service, pooled receiving account, customer balance, cross-operator
credit, payout, conversion or forwarding endpoint is introduced. The note
receiver holds the selling operator's received assets in private local state.
These are engineering boundaries, not a legal classification. The UK launch
review and operator obligations in Wildbloom's paid-storage plan remain open.

## Contract

Routes are mounted at the configured origin root. This is a Wildbloom checkout
extension, not BUD-07, a new Nostr event kind, or a standard LNURLcash HTTP payment
header. Existing Blossom routes retain their independent BUD-11 authorisation.

| Method and path | Effect |
| --- | --- |
| `GET /checkout/v1/offers` | Public seller, offers, configured issuers and available rails; no receiving I/O. |
| `POST /checkout/v1/orders` | Authenticate buyer, freeze terms and reserve capacity. |
| `GET /checkout/v1/orders/{id}` | Read that signer's private order; no receiving I/O. |
| `POST /checkout/v1/orders/{id}/lightning` | Create one operator invoice after quote consent. |
| `POST /checkout/v1/orders/{id}/lnurlcash` | Receive and rotate one exact-value note after quote consent. |
| `POST /checkout/v1/orders/{id}/check` | One explicit bounded settlement or recovery attempt. |

All order routes use the published [NIP-98 draft](https://github.com/nostr-protocol/nips/blob/master/98.md),
kind `27235`, in `Authorization: Nostr <standard-base64-event>`. This profile
requires empty content, exactly one two-element `u` and `method` tag, an exact
configured-origin URL match, and a valid event ID and signature. POST requires
one `payload` tag containing SHA-256 of the exact body bytes. GET has no body or
payload tag. Queries and duplicate authorisation headers are rejected. Freshness
is at most 60 seconds old or 30 seconds ahead. A valid event can be replayed
within that window; durable operation identity prevents a second charge or grant.
No server-side Nostr signing key is accepted or needed.

Request bodies are capped at 16 KiB. Unknown JSON fields are refused. Responses
carry `Cache-Control: no-store`. Proxy Host/Forwarded headers never determine the
signed URL. Reverse proxies must preserve the path and must not record request
bodies or authorisation headers.

Quote request example (synthetic offer):

```json
{"request_id":"buyer-generated-unique-id","offer_id":"small","rail":"lnurlcash","issuer_id":"issuer","renews":null,"refund_to":"buyer@example.com"}
```

`request_id` and offer IDs contain 1–128 ASCII letters, digits, `_` or `-`.
LNURLcash uses `"rail":"lnurlcash"` and a configured `issuer_id`. Each order fixes
one rail. The server derives its order ID from signer and request ID. Identical
retries return the stored quote, even after pricing changes; different terms
under the same request ID conflict. A new price requires a new request and consent.
`refund_to` is an optional Lightning Address sent only to the selected node. It
is bound into the immutable quote and enables the local operator refund command
for an LNURLcash payment that settles but cannot activate storage. Older clients
may omit it; those orders continue to require direct manual resolution.

The version-1 quote contains seller identity/name, exact node origin, buyer's
public key, network, rail, pinned issuer endpoint/callback/key, full offer,
creation time, expiry, optional renewal target and optional refund destination. The offer has a positive revision and fixes ciphertext
capacity, duration, grace, integer milli-satoshi price, delivery allowance and
explicit delivery, retention and refund policies. Prices must be whole sats for
this initial two-rail integration. Holds last 60 seconds to 24 hours. There is
one live sale per signer in Shelter; renewal preserves signer and capacity.

The server returns `quote_digest`, SHA-256 of its stored quote JSON bytes. It is
an opaque consent commitment, not an independently signed seller receipt. Do not
re-serialise the quote in another language to recompute it. All payment/check
POSTs echo `{"quote_digest":"..."}`. LNURLcash also includes `"note":"..."`;
that request contains money and must never reach analytics, logs or browser
persistence. The browser displays the seller and terms before payment authorisation.

Public order state includes the immutable quote, consent digest, state, optional
Lightning invoice and activated allowance receipt. Receipts include the stable
allowance ID, capacity and activation/write/retention deadlines. They prove local
activation, not independent replication, future custody or an independently
verifiable payment. A refund receipt exposes only pending/completed status,
amount, payment hash and completion time to the authenticated buyer. No input
note, replacement spend, refund invoice, mutation URL or Lightning preimage is
returned. Unknown orders and another signer's orders both return 404.

## Durable receiving and recovery

Use a dedicated operator-controlled state directory, separate from Shelter's
store. On Unix it is mode 0700; checkout files are mode 0600. SQLite uses WAL and
FULL synchronous commits, a versioned schema and an exclusive process lock.
The database contains spendable notes in plaintext: keep it private, back it up
securely, exclude it from diagnostics, and retain its WAL consistently. These
permissions are not encryption at rest or protection against the local owner.
Windows private ACLs are enforced through `wildbloom-private-state`. Existing broad permissions are refused.

The two databases deliberately form a recoverable sequence:

1. Persist `reserving` and exact terms, reserve the same sale in Shelter, then
   mark `quoted`. Retry the same request after an interrupted reservation.
2. Persist the receiving operation before external mutation. A payment is never
   offered for an unreserved order.
3. Verify receipt and persist `settled` with a unique settlement reference.
4. Activate the exact sale idempotently in Shelter, then save `active` and the
   receipt. An interruption after activation returns the original result on
   retry, including after later renewals or expiry.

Lightning creation first saves `invoice_pending`. Any error, timeout, invalid
invoice or process interruption remains pending: the current shared backend
interface has no idempotent issuance key. A trusted operator must find the
original invoice using its order-ID memo and call `recover_invoice`; there is
no public recovery/settlement assertion endpoint. Never simply issue another
invoice. A conforming backend must create an invoice expiring within the hold;
the shared interface does not accept a requested expiry. The Phoenixd adapter
  reads the matching durable order and requests an expiry 15 seconds before its
  deadline; the signed invoice is still validated before being returned.

Only the stored invoice hash is checked at the receiving backend. `paid=true`
without a 32-byte preimage hashing to that exact hash does not activate storage.
Invoice and settlement identities cannot be used for two orders. Checks do not
accept a customer's payment-success assertion.

LNURLcash accepts only an exact configured endpoint, callback and pinned mint
key. Unrecognised or duplicate note URL query parameters are refused before I/O.
The informational response supplies the authoritative amount; an encoded amount
is not trusted. Only the whole note of exactly the quote's value is accepted;
there is no split, change or overpayment credit. This integration enables notes
only with the Bitcoin mainnet configuration; the protocol does not itself attest
a chain network in the note. Issuer choice remains the operator's responsibility.

Before rotating, the ledger saves the exact mutation URL, generated replacement
secret, output identities, issuer/key and unique input note identity. An uncertain
response stays `lnurl_pending`, refusing an alternative note. Explicit recovery
first checks the saved replacement with the pinned issuer and verifies its
amount/certificate. Otherwise it replays the byte-identical original rotation.
A missing, spent or malformed response never erases the journal or authorises a
new payment. A valid replacement certificate is retained with settlement.

Each receiving call has a 15-second deadline; LNURLcash recovery can make two
calls. Construction and GET requests start no receiving I/O. There are no
background polls. The caller must request recovery; pending operations can stay
pending indefinitely if the issuer/backend cannot reconcile them. Even after
quote expiry, an explicit check may reconcile/replay the original uncertain
mutation. A late receipt that cannot activate its hold becomes `refund_required`,
with the asset retained for the seller's direct refund handling. For an
LNURLcash order with `refund_to`, the stopped-node operator tool resolves that
address, requests one exact-value invoice, journals the invoice and exact melt
before spending, and marks the order `refunded` only after matching settlement
evidence. A lost response resumes from the journal and never creates a second
invoice or changes the destination. This is an explicit operator action, not
background spending, a customer balance or a payout service. Lightning-rail
and address-free orders remain manual. Do not redeem pending notes out of band
before reconciliation.

A Lightning Address may delegate invoice creation to a different HTTPS origin.
The refund transport resolves, public-address filters and pins each origin
independently; ambient proxies and redirects stay disabled. Any receiver
verification URL must remain on the delegated callback origin, so the invoice
response cannot introduce a second cross-origin hop.

Restore checkout and Shelter state as a consistent pair. Never transplant an
order database to an unrelated store or reset pending state to retry payment.
Existing issuer configuration must remain available for pending-note recovery;
changing the issuer behind an existing ID cannot silently redirect the asset.

## Admission and remaining deployment gates

Checkout permits four concurrent requests, 120 requests/minute and one receiving
operation at a time. SQLite work is isolated in blocking workers; a disconnected
client does not release its slot while journalled receiving is still running.
Bodies have a 10-second deadline. The private ledger stops admitting new orders
at 10,000 records; existing orders remain recoverable. There is no automatic
record deletion: operators must plan retention/archival before this ceiling.
These are resource limits, not Sybil resistance or protection from availability
attacks against public endpoints.

Before accepting real payments, provision the operator's limited receiving
credentials, test the actual wallet/mint, paired backup/restore and direct refund
procedure, and complete the operator's terms and launch review. A paid allowance
proves activation in this node, not replication or future custody.

`delivery_bytes` is committed contract data, **not a metered download limit**.
The UI labels delivery operator-managed. Operators must be able to honour their
published delivery terms; do not advertise automated bandwidth enforcement.

Checkout refuses Tor-only mode and onion endpoints without a clearnet fallback.
This does not change Tor storage. Cashu, on-chain Bitcoin and Monero are outside
this initial two-rail implementation. Cross-platform and live-service acceptance
are separate from the local synthetic test.

## Daemon configuration

Build `cargo build --locked -p wildbloomd`. Use an absolute private JSON profile
and a separate private state directory. The profile and password must be regular
non-symlink files, at most 64 KiB, mode 0600 on Unix or private Windows ACLs.
`checkout.origin` must exactly equal `--public-url` with a trailing slash.
`browser_origins` lists exact origins without a trailing slash; CORS permits only
those origins. Keep the listener on loopback behind an operator-controlled TLS
proxy for remote browsers. No remote proxy credentials are inferred.

```sh
wildbloomd --no-tor --public-url https://storage.example/ \
  --checkout-profile /private/operator/checkout-profile.json --storage-proofs
```

Synthetic Lightning-only profile (replace origins, paths and policy terms):

```json
{
  "checkout": {
    "origin": "https://storage.example/",
    "seller_id": "my-node", "seller_name": "My storage node",
    "network": "bitcoin", "quote_seconds": 600,
    "allow_loopback_http": false, "tor_only": false,
    "offers": [{
      "id": "one-gib", "revision": 1, "capacity_bytes": 1073741824,
      "duration_seconds": 2592000, "grace_seconds": 604800,
      "price_msat": 1000000, "delivery_bytes": 10737418240,
      "delivery_policy": "Operator-managed delivery; no automatic meter",
      "retention_policy": "30 days of writes plus 7 days of recovery",
      "refund_policy": "Contact this operator for fulfilment or refund"
    }],
    "issuers": []
  },
  "state": "/private/operator/checkout",
  "browser_origins": ["https://wildbloom.forgesworn.dev"],
  "phoenixd": {
    "destination": {"origin": "http://127.0.0.1:9740/", "addresses": ["127.0.0.1:9740"], "allow_loopback_http": true},
    "password_file": "/private/operator/phoenixd-limited-password"
  },
  "notes": []
}
```

For LNURLcash add a configured issuer `{id,note_endpoint,callback,mint_pubkey}`
and pin **both** its note and callback endpoints in `notes`. No spend URL or
bearer note belongs in a config example, diagnostic log or public event.

## Repeatable controlled acceptance

```sh
cargo build --locked -p wildbloomd -p wildbloom-checkout --bin wildbloomd --example checkout_fixture
# In the matching Wildbloom browser checkout, after npm run build:
WILDBLOOM_NODE_BIN=/absolute/path/target/debug/wildbloomd \
WILDBLOOM_CHECKOUT_FIXTURE=/absolute/path/target/debug/examples/checkout_fixture \
  npm run acceptance:services
```

The fixture is a loopback-only developer example with public synthetic keys. It
is not a receiving wallet and is never included in the daemon. The acceptance
also verifies trusted discovery, fresh storage audits, corrupt-byte refusal,
no payment/proof publication, no browser persistence and accessible controls.

## Concrete receiving transports and local operator commands

`HttpNoteTransport` accepts an explicit list of issuer note **and callback**
endpoints. Configure both when their paths differ. Each entry pins an origin to
1–16 operator-approved socket addresses; ports must match the origin. Hostnames
are resolved only through these pins, with ordinary hostname verification for
TLS. Address refresh is an operator action. There is no ambient proxy, automatic
DNS discovery, redirect, referer, transport retry or Tor fallback. HTTP requires
an explicit loopback exception and all pins must be loopback. IP-literal URLs
must match their pins. An approved private address is an intentional operator
choice; this is not a public DNS resolver or arbitrary-URL fetch service.

Both adapters use a five-second connection timeout, twelve-second whole-request
timeout, 64 KiB streaming body cap, and refuse content-encoded responses. Error
messages exclude URLs, backend bodies and credentials. Deployments must also
keep dependency HTTP wire/debug tracing and reverse-proxy body/query logging
disabled: LNURLcash query strings contain spendable assets.

`Phoenixd` implements `toll_booth::backends::LightningBackend`; sending remains
unsupported. Supply the operator's **limited-access password**, not its spending
password (the adapter cannot distinguish the two). Invoice creation uses the
order ID as description and `externalId`, with a deadline derived from the
private ledger. Only `invoice_pending` orders with the exact price are accepted.
The checkout owns the one-attempt issuance rule. Original-invoice lookup asks
for all incoming invoices filtered by that external ID, capped at two results.
Zero, duplicate or mismatched results remain pending. An unpaid response never
exports its preimage to the checkout. Missing/malformed responses cannot activate
storage. This contract was checked against upstream Phoenixd source at
[`9df2610`](https://github.com/ACINQ/phoenixd/blob/9df2610be057de61ffea4de167610ce30a4818ac/src/commonMain/kotlin/fr/acinq/phoenixd/Api.kt)
and its [JSON models](https://github.com/ACINQ/phoenixd/blob/9df2610be057de61ffea4de167610ce30a4818ac/src/commonMain/kotlin/fr/acinq/phoenixd/json/JsonSerializers.kt).
It is not evidence of a tested deployed Phoenixd version.

Build the local tool with `cargo build -p wildbloom-checkout --bin checkout-operator`.
Stop the owning checkout/Node process first; both stores retain exclusive locks.
Use the existing checkout directory and its **matching** Shelter store. Never
point recovery at a different store or create a new store to bypass a lock.

```sh
checkout-operator --state /private/operator/checkout inspect --limit 50
checkout-operator --state /private/operator/checkout inspect --after ORDER_ID --limit 50
checkout-operator --state /private/operator/checkout recover-invoice ORDER_ID --profile /private/operator/recovery.json
checkout-operator --state /private/operator/checkout reconcile ORDER_ID --profile /private/operator/recovery.json
checkout-operator --state /private/operator/checkout refund ORDER_ID --profile /private/operator/recovery.json --confirm-destination
```

`inspect` performs no receiving I/O and outputs only order ID, state, rail and
expiry. It accepts 1–100 entries and a keyset cursor. `recover-invoice` attaches
one validated original invoice and does not check settlement. `reconcile` runs
one existing reconciliation operation, including replay of a previously
journalled LNURLcash mutation when necessary, and prints only the resulting
state. `refund` works only for `refund_required` LNURLcash orders with a bound
Lightning Address and a certified retained note. Review that private destination
before passing `--confirm-destination`. The command resolves and pins public DNS
for each HTTPS origin, rejects local and special-use addresses, follows no
redirects, journals before spending and safely resumes the same invoice. No
command starts a new purchase, resets pending state or exports bearer assets.

The recovery profile is strict JSON with these fields:

- `checkout`: all fields of `Config`, matching the existing seller, offers and
  issuer configuration (including old issuer keys needed by pending orders).
- `storage_root`, `quota_bytes`, `max_blob_bytes`: the existing Node store and
  its configured limits. An existing `wildbloom.sqlite3` is required.
- `phoenixd`: null, or `{ "destination": { "origin": "http://127.0.0.1:9740/",
  "addresses": ["127.0.0.1:9740"], "allow_loopback_http": true },
  "password_file": "/private/operator/phoenixd-limited-password" }`.
- `notes`: a list of `{ "endpoint": "https://issuer.example/note",
  "destination": { "origin": "https://issuer.example/",
  "addresses": ["192.0.2.1:443"], "allow_loopback_http": false } }`.
  Documentation addresses are synthetic; configure real operator-approved pins.

Use absolute paths. Profiles and password files must be regular, non-symlink
files of at most 64 KiB, mode 0600 on Unix (no group/other access); on Windows
supply private ACLs. Passwords are read from files, never command-line arguments.
The tool emits static errors and starts no HTTP listener. Profile opening may
run normal Shelter recovery/migration, so make a consistent offline backup of
both private directories before using a new binary. The version-1 checkout
schema migrates in place to version 2 by adding the private refund journal.
Automated paired backup and restore verification remain launch gates.

Adapter increment validation on 4 October 2026: 23 checkout tests and one operator
file-policy test passed, including real loopback HTTP invoice, note rotation,
lost-response lookup, redirect refusal and oversized chunked-body fixtures.
Workspace tests, workspace all-target lint, formatting and dependency audit
passed. No payment test used a live wallet or mint. The real-Tor workspace
test remains ignored.
