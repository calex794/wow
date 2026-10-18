# W3 crypto proof — provisional implementation

**Status:** experimental, unaudited, NOT production-ready. This branch is deliberately separate from Akula Sync Core and from the final CBOR AkulaNetEnvelopeV0 schema.

- Inner structure: COSE_Sign1 containing a payload signed by Ed25519. The signature binds the plaintext and the exact public wire header through COSE external AAD.
- Outer protection: HPKE RFC 9180 base mode, X25519-HKDF-SHA256, HKDF-SHA256, ChaCha20-Poly1305. The exact header is also HPKE AAD, with an independent information string for domain separation.
- Public wire header (temporary **binary** research layout, not final CBOR): version (1 byte), message ID (16 bytes), recipient ID (16 bytes), expiry (8-byte big-endian). Encapsulated X25519 key (32 bytes) and HPKE ciphertext follow.
- Sender trust: the recipient must already know the sender's verified Ed25519 key and bind it to an authorized device identity OUTSIDE this packet. A self-declared key is insufficient.
- Strict rejection: unknown suite, incorrect recipient, expired message, wrong sender, changed AAD, ciphertext corruption, and oversized messages.

**IMPORTANT GAPS:** not yet a COSE-HPKE unified envelope; no canonical CBOR outer schema, independent test vectors, key verification/distribution/rotation/revocation, durable replay protection, interop with Swift/Kotlin, fuzzing, audit, or real radio/internet transport. The signing key used in unit tests is deterministic **test material** and must never be used in the field. Signing identity and file access rights remain in future Akula trust/ACL.

References: https://www.rfc-editor.org/rfc/rfc9180.html ; https://www.rfc-editor.org/rfc/rfc9052.html ; https://app.notion.com/p/3fc32a84beec81a9b90be53f49971330 .
