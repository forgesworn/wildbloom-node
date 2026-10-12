These synthetic signed fixtures are vendored byte-for-byte from
forgesworn/402-announce commit 599b3e8e31d24319e9b3ec9a523408593fec2648
(fixtures/storage-v1). No real operators, relay announcements or payment assets.

The Rust contract test verifies all 19 signatures before checking semantic
acceptance/rejection and compares reconstructed content and tags against the
JavaScript contract. Keep updates explicit and tied to the shared contract.
