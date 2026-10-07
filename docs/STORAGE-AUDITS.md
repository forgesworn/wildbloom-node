# Private full-read storage audits

Enable `wildbloomd --storage-proofs` to expose `POST /storage/v1/proof`. The
endpoint is off by default, including for desktop-launched nodes. It works with
direct or managed-Tor storage; it does not require checkout or a server signing
key. The Wildbloom browser explicitly audits a resolved signed file or every
part/target in a private pool receipt without needing its decryption key.

## What to choose

| Approach | Benefit | Cost and limit |
| --- | --- | --- |
| Full-read audit (implemented) | Checks every stored byte against the owner's commitment; simple to inspect | Reads and downloads the full file/shard; a node can fetch it elsewhere on demand |
| Random Merkle-block challenges (future) | Much cheaper frequent checks | Probabilistic coverage; needs committed trees, client verification and careful sampling |
| Proof of replication/time (future) | Can address stronger dedicated-copy or time claims | Specialist constructions, preprocessing, additional state and independent cryptographic review |

For trusted pools, use the existing scheduled owner repair service to download,
hash-verify and repair targets, with these explicit nonce-bound audits when
fresh evidence is wanted. Existing scheduled repair already verifies all bytes;
this change does not introduce another background browser job or grant new repair
authority. Start with this design. Add Merkle sampling only if measured bandwidth
makes frequent complete scans impractical. None guarantees future availability.

The distinction between these proof families is described in the
[Filecoin proof-of-storage specifications](https://spec.filecoin.io/algorithms/pos/).
This endpoint does not claim compatibility with Filecoin or a succinct proof of
retrievability construction.

## Wire contract

This is a versioned Wildbloom extension, not a Blossom standard or Nostr event
kind. Requests use exact [NIP-98](https://github.com/nostr-protocol/nips/blob/master/98.md)
URL/method/body-hash authorisation as documented in [checkout](CHECKOUT.md).

```json
{"sha256":"<64 lowercase hex>","nonce":"<fresh random 32 bytes in lowercase hex>"}
```

The server scans the CAS file, requires its SHA-256 and length to match stored
metadata, and returns `{version:1,sha256,nonce,size,digest}`. The proof digest is:

```
SHA256(UTF8("wildbloom.storage-proof.v1\n") || raw_nonce_32 || uint64_BE(size) || stored_bytes)
```

The browser checks the exact fresh challenge and owner's signed size/hash,
downloads every byte independently, and recomputes the digest. It records its
own verification time, origin and result in an explicit private JSON download.
No audit record or payment detail is published to a relay. This response is not
an independently signed operator attestation: its value comes from the owner's
verification against their signed receipt. It cannot distinguish a local disk
read from fetching the bytes elsewhere.

## Resource and privacy boundary

- One in-flight audit and six authenticated challenges per minute per node.
- Request at most 1 KiB, body deadline 10 seconds, scan deadline 300 seconds.
- Streaming 64 KiB scan buffers; exact length and ordinary SHA-256 verified.
- Every response is `no-store`; request query strings are refused.
- Any authenticated signer knowing a public blob hash can request an audit.
  Authentication and rate limits are not Sybil resistance or ownership proof.
- CORS permits explicit browser POSTs; no cookies. Operators should keep proxy
  bodies/authorisation out of logs. Requester public key, hash, timing and size
  remain visible to the node. Encryption hides contents, not this metadata.
- A failed audit is not proof of deletion: overload, network failure and timeout
  also fail. Existing owner repair remains the place to restore redundancy.

Tests cover independent Rust/TypeScript digest vectors, fresh nonce binding,
invalid authentication/body/nonce, missing or corrupt data, admission limits,
private browser evidence and a real daemon full-read/corruption journey.
