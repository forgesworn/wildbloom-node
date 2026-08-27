# V4V dogfood path

V4V already uploads through a standard Blossom client and can list more than one
server.  Wildbloom Node deliberately keeps that boundary, so V4V should not gain
a private storage SDK.

The staged integration is:

1. Run a node and copy its onion URL from the ready log.
2. Open V4V through Tor-capable browsing and add the onion as an additional
   Blossom server.
3. Upload one encrypted test track to the existing server and the home node.
4. Read both descriptors back, compare SHA-256 and byte length, then play each
   copy independently.
5. Stop one server and prove the other descriptor still serves and decrypts.
6. Ask a second Wildbloom Node to BUD-04 mirror the first copy, then repeat the
   loss test.

That is evidence of independent replicas.  Merely listing two server URLs, or
publishing a Nostr event which says they exist, is not.

V4V should keep encryption before Blossom upload and must not publish a private
onion, real host, test identity or endpoint into its public repository.  The
local acceptance fixture should receive those values from environment variables.

