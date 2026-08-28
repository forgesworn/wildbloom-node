# V4V dogfood path

V4V already uploads through a standard Blossom client and can list more than one
server.  Wildbloom Node deliberately keeps that boundary, so V4V should not gain
a private storage SDK.

The staged integration is:

1. Run a node and copy its selected onion or HTTPS URL from the ready log.
2. Add the URL as an additional Blossom server.  Onion URLs require a
   deliberately Tor-capable V4V path; public HTTPS uses ordinary networking.
3. Upload one encrypted test track to the existing server and the home node.
4. Read both descriptors back, compare SHA-256 and byte length, then play each
   copy independently.
5. Stop one server and prove the other descriptor still serves and decrypts.
6. Ask a second Wildbloom Node to BUD-04 mirror the first copy, then repeat the
   loss test.

V4V's storage signer should be configured as an `owner`.  An invited artist may
receive an expiring `friend` byte grant.  Unknown signed mirrors, if the
operator deliberately enables open shelter, remain evictable `guest` data and
must never be counted toward V4V's promised replica floor.  V4V retains the
encryption keys, catalogue, payment and replica-count truth; the node retains
bytes and local claim policy.

That is evidence of independent replicas.  Merely listing two server URLs, or
publishing a Nostr event which says they exist, is not.

V4V should keep encryption before Blossom upload and must not publish a private
onion, real host, test identity or endpoint into its public repository.  The
local acceptance fixture should receive those values from environment variables.

Normal browsers do not fetch an onion URL without Tor.  A Wildbloom Node behind
operator-managed HTTPS can instead be used for ordinary playback, with the
usual IP and infrastructure metadata exposure.  In either mode, use the
Wildbloom copy as an independent recovery replica and verify its exact
ciphertext hash before decryption.
