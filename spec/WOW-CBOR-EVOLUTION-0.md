# WOW-CBOR-EVOLUTION-0: laboratory profile

Status: LAB ONLY; unsigned and unencrypted. Not the planned AkulaNetEnvelopeV0.

Source: https://app.notion.com/p/3fc32a84beec81a9b90be53f49971330
Background: LesHa canonical CBOR/COSE and schema evolution, UFMT negative tests.

Base map keys: 0=version (0), 1=message_id bstr16, 2=route_token bstr16, 3=expiry uint, 4=priority 0..2, 5=raw *plaintext test* payload.

Optional key 6: nonempty definite map of extension ID uint to opaque bstr. IDs sorted ascending, unique, minimum-length integer encoding. Positive even IDs are unknown ancillary fields preserved byte-for-byte. Odd IDs are critical and unsupported by this reader, hence fail closed. Provisional ID convention only; production register is not yet frozen. Up to 16 extension entries of 1024 bytes each; total message max 16 KiB.

The old decoder fails closed on key 6 instead of silently dropping an unknown extension. The new decoder can parse six- or seven-field canonical messages. Real relays must forward original authenticated bytes without re-encoding, after security and capability checks. The experimental decoder checks syntax only; it gives NO authenticity, secrecy, integrity, authorization, replay safety or durable delivery.

Tests cover fixed reviewed hex strings, unknown critical, ordering, duplicate IDs, nonminimal integers, empty map, wrong version, truncation, per-extension/global resource bounds.

CI runs cargo test and clippy. Independent second-language encoder, property testing and fuzzing still required. A mutating bit flip can remain valid syntax; it is intentionally not claimed to be detectable until cryptographic protection exists.
