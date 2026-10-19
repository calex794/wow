# W6 multi-writer identity registry / authority protocol v4

Status: stacked laboratory Draft PR on #40. Not production authority custody.

## Goal and acceptance contract

One remote authority must identify each writer by its own authenticated
QUIC/TLS EndpointId. No two independent hosts may depend on sharing the
same online reader private key. The initial lab registry supports a primary
writer and **four independently pinned optional additional writers**, i.e.
up to five physical devices (PC plus four Android devices eventually).
This upper bound is a deliberate laboratory bound, NOT a product-wide
unlimited peer registry.

## Threat model

A compromised TLS reader may request a write fence but cannot publish a
signed operator Allow/Revoke. The durable **single** remote `w6_writer_fence`
still serializes all five keys with each other and with signed policy CAS.
Only the exact authenticated writer and nonce holding the fence may FINISH.
A different authorized writer cannot hijack FINISH even if it knows the
same checkpoint or nonce. One malicious/hung writer can block everyone;
this remains an availability risk, not silently mitigated by TTL.

TLS EndpointIds are provisioned independently, in protected configuration.
QUIC peer-provided "I am writer B" strings, network addresses or recovered
policy SQLite must never add new readers. Key membership cannot be changed
by the online TLS administrator. Offline operator+isolation-witness-signed
orphan recovery may only replace the **exact reader slot** holding a
durable orphan fence after independent external isolation.

## Storage and compatibility

Protected `AnchorServicePolicy` now contains:

```text
reader: EndpointId
additional_readers: [Option<EndpointId>; 4]
administrator: EndpointId
operator: pinned OFFLINE VerifyingKey
recovery_witness: distinct pinned OFFLINE VerifyingKey
authority: nonzero pinned AuthorityDomainId
```

All provisioned keys must be pairwise distinct, including admin, both
offline roots, primary reader and four optional additional readers.
Empty slots are explicitly `None` and are not authorized.

The remote SQLite `w6_external_anchor` row stores a deterministic
**132-byte** comparison-only encoding for all four additional slots:
each slot is `present[1] || endpoint_id[32]` or exactly 33 zero bytes
for `None`. The row is never promoted to configuration authority.
On open, every read, begin, finish and signed CAS, the full persisted
registry must match independently provided protected config. Reordered,
removed or replaced readers fail closed. No silent add, table repair,
remote self-enrollment or rollback to pre-v4 state.

Existing v3 authority files lack the `additional_readers` column.
**Opening them as v4 must fail closed.** There is no automatic migration;
any replacement needs an independent offline-reviewed provisioning and
high-water mark reconciliation procedure. Atomic `create_new`
provisioning still refuses to mutate any existing authority file.

## Wire protocol

Anchor ALPN bumped to
`akula-wow/w6-external-anchor-lab/4`. The GET, signed CAS and
WRITE-BEGIN/WRITE-FINISH frame layouts and pinned authority echo remain
as in v3. The ALPN change prevents a new client silently negotiating with
the single-writer v3 service despite the new protected registry semantics.

BEGIN/FINISH for reader A cannot be substituted by reader B because the
remote authority uses the **TLS connection's authenticated EndpointId**,
never a client-claimed string. A stale local policy checkpoint remains
unusable after signed revocation no matter which authorized writer
attempts to commit.

## Orphan-specific semantics

The existing offline dual-signed order identifies previous_reader,
replacement_reader, authority domain, exact checkpoint, nonce and
monotonic recovery generation. Previously only the primary reader could
be replaced. v4 permits recovery for whichever authorized reader
**actually holds the fence**, and changes ONLY that pinned slot in one
SQLite IMMEDIATE/FULL transaction with the signed audit journal. The
four other reader keys remain valid; an old primary/additional reader,
duplicate writer credential, admin key or offline-root key cannot be
used as the replacement identity. A stale authority instance with an
old registry is denied on every read and CAS after the recovery.

**A signed isolation assertion is NOT proof the old writer has stopped.**
Production release of an orphan still requires separately verified
host isolation or a storage-level fencing mechanism. No timers or
automatic unlocks.

## Required test evidence

1. Five unique keys: all five can read; each can acquire the same
   single fence when free; other keys and signed CAS cannot act while
   one holds it. Only the exact holder may release.
2. Secondary writer held fence: dual-signed recovery rotates that
   **secondary only**. The other four remain authorized. Old key and
   older cached authority instances fail.
3. Wrong key, duplicate keys, role overlap, slot reordering, removal,
   corruption and old schema fail closed.
4. Real Roha/noq QUIC: independent TLS keys A/B/C share one writer
   gate; revoked checkpoints stop all writers.
5. Independent OS child authority + two different local SQLite policy
   files + real Mailbox durable SQLite COMMIT: host B uses a distinct
   QUIC TLS reader from host A; operator CAS cannot publish mid-write.
6. Exact-head push and PR CI: pinned Roha/noq forks, feature and
   default Rust tests, strict Clippy, W4/W5 genuine Linux ENOSPC.

## Unsolved gates

A single global exclusive writer fence intentionally limits throughput.
It is a narrow but conservative correctness mechanism. Lab same-host
OS children are not independent physical nodes. No production authority
anti-rollback, single-root compromise resilience, guaranteed host
isolation, physical multi-device E2E, mobile transport/background
scheduling, or pre-TLS accept resource limits are claimed.

Keep this PR Draft until CI and independent security review; do not merge
into `wow/main` based solely on loopback laboratory evidence.
