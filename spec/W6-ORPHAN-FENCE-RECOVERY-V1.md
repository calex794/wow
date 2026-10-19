# W6-P0: Operator-custodied orphan Mailbox writer recovery

**Status:** laboratory, stacked Draft over #39. Not a production isolation
attestation or an automated rollback/cleanup system.

## The impossibility boundary

After a QUIC timeout, SIGKILL, or an unknown SQLite Mailbox COMMIT, a
remote checkpoint service cannot distinguish a truly dead writer from a
*paused* writer that will resume and commit after the fence has been removed.
A timer, absence of heartbeats, TLS disconnect, a reader logout or an online
administrative command provides **no proof** the original writer is dead.

Therefore W6 must **NOT** support automatic fence expiry, administrative
`force_unlock()`, or one-signature remote unlock. A recovery is only safe
**conditional on externally trusted physical isolation of the old writer**
(or an independently enforced storage fencing mechanism). Ed25519 signatures
record attestations; the cryptography does not magically establish host
isolation.

## Privileged-only recovery protocol

All authority service processes, **including earlier protocol binaries
that do not enforce the new reader configuration checks**, are stopped
and prevented from reopening the SQLite database. The authority enters
an operator-controlled maintenance window. All old writer processes
are independently isolated as well. In the laboratory we can SIGKILL
the authority child; in production that alone does NOT kill every writer
on every other host. Network ACL removal is not sufficient if the writer
already holds a local SQLite transaction. A v3 binary still running with
cached old reader credentials would undermine the rotation even if the
new code rejects them; external process isolation is indispensable.

The authority's *local privileged* `inspect_orphan_fence()` returns the
canonical, durable pinned domain, authenticated old reader ID, checkpoint,
32-byte nonce and next recovery generation. The nonce must not be logged,
returned by an untrusted network RPC, or displayed in ordinary diagnostics.
It is already in the authority DB. The offline operator builds one
`OrphanFenceRecoveryOrder` containing:

```text
authority_id[32]
previous_reader_ed25519_endpoint_id[32]
replacement_reader_ed25519_endpoint_id[32]
expected_checkpoint[40] = revision_u64_be[8] || blake3_digest[32]
writer_fence_nonce[32]
recovery_generation_u64_be[8]
```

Two independently provisioned private keys sign the **same exact order**
with different domain separators:

- Operator: `Akula/WOW/W6/orphan-fence/rotate-operator/v1\0`
- Physical isolation witness:
  `Akula/WOW/W6/orphan-fence/physical-isolation-witness/v1\0`

The operator's public key and **distinct witness public key** are pinned
in *protected local authority configuration* and persisted as comparison
copies in the authority SQLite file. Their private keys must not be in the
authority service, TLS reader or online TLS admin. It is a *one-operator plus
one independent attestor* ceremony; each cryptographic role is mandatory.

There is **no QUIC API** for orphan release. The only mutation entrypoint
is a privileged local authority Rust method
`recover_orphan_after_external_isolation(...)`, to be invoked **only
after verified external fencing** and administrative authorisation.

## Atomic recover-or-hold conditions

Under one SQLite `BEGIN IMMEDIATE`, and `synchronous=FULL`:

1. Verify both signatures and domain-separated role bindings *before* any
   storage mutation. Same public key for both roots is refused at
   provisioning and reopen. Wrong role, nonce, reader, domain,
   generation, checkpoint or replacement reader fails closed.
2. Independently verify the pinned authority configuration and that the
   actual exclusive write fence is still held by the exact old reader,
   nonce and checkpoint.
3. Require next generation to be exactly one greater than the committed
   audit journal. Refuse replays, previously cleared fences and attempts
   to give the reader/admin identity back to the old writer.
4. Insert a persistent recovery journal row containing generation, domain,
   old/new reader, original checkpoint, **hash** of nonce, and both exact
   signed attestation proofs. Do not store raw nonce in the new audit row.
5. Atomically change the authorized reader TLS EndpointId, delete ONLY the
   exact held writer fence, and commit. In-memory policy changes only
   after COMMIT. No signed policy checkpoint is advanced by this step.
6. The external deployment configuration is independently updated to pin
   the new reader key before restarting the QUIC listener. Old protected
   config refuses to reopen the recovered authority DB. New code checks
   persisted reader identity on every read/write/CAS and fails stale
   authority processes closed.

Do not treat audit SQLite as a tamper-proof external witness or a
physically independent high-water mark. Rolling back the entire SQLite
store still defeats that assumption; independent custody remains P0.

## Evidence and failure tests

* Forged or same-role signatures, wrong domain, nonce, checkpoint,
  generation, duplicate order and forbidden replacement key do not clear
  the fence. An unsigned TLS administrator cannot unlock it.
* Two independent SQLite connections simulate a stale authority process.
  Once a separate maintenance instance changes the reader, the stale
  instance refuses GET, WRITE-BEGIN, WRITE-FINISH and signed CAS.
* After an independent OS child restart using *new* protected reader
  config, the old TLS reader key is rejected. The new reader can
  BEGIN/FINISH a fence; operator-signed CAS remains serialized.
* Recovery audit survives SQLite reopen. Old config is rejected. The
  previous W4/W5 real ENOSPC and W6 Roha/noq fork-pinned strict Clippy
  suites must pass on the final exact SHA for both push and PR.

## Migration and remaining gaps

Old v3 authority databases do **not** contain the pinned
`recovery_witness` column or `w6_writer_recovery` journal and must
fail closed; there is deliberately no implicit migration or new trust
root adoption. W6 QUIC ALPN remains /3 because this operation is local
only; the authority's persisted trust-root schema is a breaking change
requiring separately reviewed offline re-provisioning.

No production guarantee exists until an **independently trusted host
isolation or storage fencing service** can reliably attest that no
stale remote writer may still commit after the recovery. Merely signing
a claim of shutdown is insufficient. Also open: multiple independent
writer TLS identities, physical two-host tests, anti-rollback of the
remote authority database, unattended real-OS power-cut failure
injection, QUIC pre-handshake DoS admission and operational recovery UI.

If isolation evidence is unavailable or ambiguous: **DO NOT RECOVER.
Keep the durable fence and authority in HOLD.**
