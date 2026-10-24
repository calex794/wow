# W6 Authority Domain / Signed CAS v2 (laboratory profile)

Status: **Draft, NOT production**. Originally researched in stacked PR #38. Re-integrated on modern WOW main in PR #61; independent transport, operator signatures and crash recovery remain laboratory-only. Cross-host writer fence and trustworthy offline custody are separate acceptance gates.
The protocol deliberately refuses signatures from the earlier W6 v1 transition
profile; it does not silently negotiate to a weaker mode.

## Identity and trust boundaries

* **AuthorityDomainId** is a nonzero 32-byte operator-provisioned, high-entropy
  value for one logical remote authority/cluster. It must be generated using an
  OS CSPRNG and pinned in independently protected configuration of the
  **offline operator**, the **local W6 policy process**, the **remote authority**
  and the **QUIC client**. Never obtain it from an unverified packet or from
  the policy DB being protected. Do not reuse the same ID for two unrelated
  authorities, even if they share the same offline operator key.
* **TLS EndpointId** authenticates the QUIC server/peer. It is **not** the
  logical authority ID. This distinction allows server TLS key rotation and
  multiple replicas of a single logical authority without changing the
  operator's signed domain.
* **Operator VerifyingKey** is pinned independently of the remote database.
  Only the matching offline private key can sign the original allow/revoke
  command and the exact checkpoint transition. Both signatures use distinct
  domain strings. Two signatures from one operator are **not** a quorum.

## Cryptographic transition contract

The second Ed25519 signing input is exactly:

```text
"Akula/WOW/W6/operator-anchor-transition/authority-v2\0"
|| authority_domain_id[32]
|| expected_revision_u64_be[8] || expected_blake3_digest[32]
|| replacement_revision_u64_be[8] || replacement_blake3_digest[32]
|| original_operator_signed_change[194]
```

The 64-byte transition proof is verified against the **server's own pinned
authority ID**, never a value selected by the sender. The original 194-byte
operator change still has its separately verified domain-separated signature
and must match the replacement revision. TLS-admin-only CAS is denied.

The network protocol uses **ALPN `akula-wow/w6-external-anchor-lab/2`**.
GET and signed CAS requests retain their bounded fixed sizes; successful
GET/CAS replies are **73 bytes**:
`status[1] || authority_id[32] || checkpoint[40]`.
Clients compare the echoed authority ID with *locally pinned* configuration
before accepting any read or successful CAS. An authenticated but misrouted
QUIC connection cannot silently provide an unscoped checkpoint.

## Local and remote persistence

* The remote authority stores `authority` alongside pinned read/admin TLS
  EndpointIds, the pinned operator public key, and revision/digest. A
  different supplied authority on `open` is a configuration mismatch.
* Local `PeerEnrollmentDb::open_for_authority` accepts the authority from
  protected **external** config and stores a comparison copy in
  `w6_authority_binding`. A subsequent `open` without a domain, or with
  a different domain, fails closed. The legacy unbound `open` remains
  strictly a **lab bootstrap** mode; a bound DB refuses its unanchored
  authorize/write/mutation operations.
* Every signed pending transition journals `authority_id` alongside
  old/new checkpoints and both operator signatures before remote CAS.
  Recovery requires equality between the pinned local ID, the trusted
  client's ID, the journal ID, and the ID covered by the operator's proof.
  Failure retains the journal in HOLD; it never silently rebinds.
* A W6 v1 SQLite database may not have the v2 authority columns. There
  is **no automatic v1 to v2 migration** and no automatic new trust-root
  enrollment. Administrators must separately reconcile and re-provision
  according to an explicitly reviewed offline procedure. Schema errors
  fail closed.

## Required adversarial evidence

1. Same operator key, same TLS keys, same original checkpoint but
   **different authority IDs**: signature authorized for A cannot CAS B.
2. Correct TLS key but wrong client-pinned authority: even **GET** fails.
3. Restart with different authority configuration refuses the existing
   remote or local SQLite database.
4. Crash-gap recovery with wrong domain refuses before any policy mutation.
5. Existing signed CAS, QUIC process crash/restart, W4/W5 ENOSPC, and strict
   Clippy remain green on the exact head SHA.

## Explicitly not solved

Same physical disk/host rollback, copied authority configuration or accidental
reuse of an ID across clusters, compromised offline signer, independent
digest reconstruction from policy rows, cross-host revoke versus Mailbox COMMIT
fencing, pre-TLS QUIC resource exhaustion, hardware custody, and real Android
or independent-LAN acceptance. These remain separate P0 gates.

**Do not deploy a public authority listener based only on the lab's CI.**
