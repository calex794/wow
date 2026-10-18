//! W6 trusted operator-signed enrollment of iroh TLS EndpointIds into W3
//! DeviceIds and a SINGLE authorized relay route, durably in SQLite.
//!
//! These records are NOT submitted by an incoming QUIC peer. Only a trusted
//! control plane may apply changes, and every change needs a signature from
//! an OUT-OF-BAND pinned operator key. The SQLite copy of the operator key
//! detects configuration mismatches but is NEVER itself a trust anchor.
//!
//! Revocation is sticky for an EndpointId. Re-enrollment after compromise
//! must use a new iroh key/EndpointId and a newer operator revision. An active
//! device's W3 key epoch can rotate strictly upward on the same endpoint.
//! The global revision and tombstones survive ordinary process restarts.
//!
//! Bounds: 128 endpoint rows, including revoked tombstones. No automatic
//! deletion. An OPTIONAL external checkpoint gate rejects stale/tampered
//! policy DB snapshots and advances a separately trusted revision *before*
//! applying SQLite changes. The anchor MUST be monotonic/durable and hosted
//! outside the attacker's rollback domain; no real HSM/server is provided.
//! File/WAL quota, cross-host propagation, hardware key custody, and a safe
//! administrator-led recovery protocol are OUT OF SCOPE here.
//! This is a lab-only trust-policy component, not an HTTP/QUIC admin endpoint.
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use iroh::EndpointId;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use std::path::Path;

const DOMAIN: &[u8] = b"Akula/WOW/W6/endpoint-route-enrollment/lab-v1\0";
const VERSION: u8 = 1;
const BODY_BYTES: usize = 130;
pub const SIGNED_ENROLLMENT_BYTES: usize = BODY_BYTES + 64;
pub const MAX_ENROLLED_ENDPOINTS: i64 = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PolicyOperation { Allow = 1, Revoke = 2 }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EndpointRouteBinding {
    pub endpoint_id: EndpointId,
    pub w3_device_id: [u8; 16],
    pub w3_epoch: u64,
    pub relay_id: [u8; 16],
    pub namespace: [u8; 16],
    pub route_token: [u8; 16],
    pub issuer_id: [u8; 16],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OperatorChange {
    pub operation: PolicyOperation,
    /// Strictly increasing trusted control-plane serial, > 0 and <= i64::MAX.
    pub revision: u64,
    pub binding: EndpointRouteBinding,
}

#[derive(Debug)]
pub enum EnrollmentError {
    Db(rusqlite::Error),
    InvalidEncoding,
    UntrustedOperator,
    InvalidSignature,
    RevisionRollback,
    TooManyPeers,
    UnknownEndpoint,
    Revoked,
    WrongScope,
    EpochRollback,
    BindingConflict,
    CorruptStorage,
    Anchor(AnchorError),
    CheckpointMismatch,
    /// An offline-signed transition was staged but not yet reconciled.
    PendingRecovery,
}
impl From<rusqlite::Error> for EnrollmentError {
    fn from(value: rusqlite::Error) -> Self { Self::Db(value) }
}


const CHECKPOINT_DOMAIN: &[u8] = b"Akula/WOW/W6/policy-checkpoint/lab-v1\0";

/// Canonical, operator-root-bound digest over ALL 128-or-fewer persisted
/// endpoint records (including revoke tombstones) and the last revision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicyCheckpoint {
    pub revision: u64,
    pub digest: [u8; 32],
}

/// Only the exact signed pending transition may be reconciled after restart.
/// This is not a generic authorization to reset the external high-water mark.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignedRecoveryOutcome {
    NoPending,
    /// This process submitted the previously signed CAS during recovery.
    ForwardedPending,
    AppliedAfterCas,
    AlreadyApplied,
}

/// Errors from an EXTERNAL, non-rollbackable source. No untrusted local file
/// may masquerade as an authoritative anchor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnchorError {
    Unavailable,
    Conflict,
    InvalidAttestation,
}

/// Trust contract: current() must return a *fresh authenticated* checkpoint;
/// advance() must be atomic, durable, compare-and-swap and strictly
/// monotonic. The trusted anchor must live outside the SQLite snapshot
/// rollback/tamper domain. Implementing this over another writable file on
/// the same machine IS NOT SECURITY. An in-memory implementation is suitable
/// for regression tests ONLY and is lost after reboot.
pub trait TrustedPolicyAnchor: Send + Sync {
    fn current(&self) -> Result<PolicyCheckpoint, AnchorError>;
    fn advance(
        &self, expected: PolicyCheckpoint, replacement: PolicyCheckpoint,
    ) -> Result<(), AnchorError>;

    /// Offline-authorized remote CAS. The remote authority MUST require the
    /// signed operator change AND a distinct operator signature binding the
    /// old checkpoint and exact NEW digest. Backends that do not implement
    /// this fail closed. An admin TLS credential alone is not authorization.
    fn advance_signed(
        &self, _old: PolicyCheckpoint, _next: PolicyCheckpoint,
        _change: &[u8], _proof: &[u8],
    ) -> Result<(), AnchorError> {
        Err(AnchorError::InvalidAttestation)
    }
}

/// Scope from trusted W6 server config, NEVER network-provided fields.
#[derive(Clone, Copy)]
pub struct EnrollmentLookup<'a> {
    pub remote: &'a EndpointId,
    pub relay: &'a [u8;16],
    pub namespace: &'a [u8;16],
    pub token: &'a [u8;16],
    pub issuer: &'a [u8;16],
}

struct PendingSignedTransition {
    expected: PolicyCheckpoint,
    replacement: PolicyCheckpoint,
    change: Vec<u8>,
    proof: Vec<u8>,
}

fn ensure_no_pending(db: &Connection) -> Result<(), EnrollmentError> {
    let pending: i64 = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM w6_pending_transition)", [],
        |row| row.get(0),
    )?;
    if pending != 0 {
        return Err(EnrollmentError::PendingRecovery);
    }
    Ok(())
}

fn pending_signed_transition(
    db: &Connection,
) -> Result<Option<PendingSignedTransition>, EnrollmentError> {
    let found = db.query_row(
        "SELECT expected_revision, expected_digest,
                replacement_revision, replacement_digest, signed_change, signed_proof
         FROM w6_pending_transition WHERE singleton=1",
        [], |row| Ok((
            row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?,
            row.get::<_, i64>(2)?, row.get::<_, Vec<u8>>(3)?,
            row.get::<_, Vec<u8>>(4)?, row.get::<_, Vec<u8>>(5)?,
        )),
    ).optional()?;
    let Some((old_revision, old_digest, new_revision, new_digest, change, proof)) = found
    else {
        return Ok(None);
    };
    if old_revision < 0 || new_revision <= old_revision
        || change.len() != SIGNED_ENROLLMENT_BYTES
        || proof.len() != SIGNED_TRANSITION_PROOF_BYTES
    {
        return Err(EnrollmentError::CorruptStorage);
    }
    let old_digest: [u8; 32] = old_digest.try_into()
        .map_err(|_| EnrollmentError::CorruptStorage)?;
    let new_digest: [u8; 32] = new_digest.try_into()
        .map_err(|_| EnrollmentError::CorruptStorage)?;
    Ok(Some(PendingSignedTransition {
        expected: PolicyCheckpoint {
            revision: old_revision as u64, digest: old_digest,
        },
        replacement: PolicyCheckpoint {
            revision: new_revision as u64, digest: new_digest,
        },
        change, proof,
    }))
}

fn ensure_anchor(
    anchor: &dyn TrustedPolicyAnchor, local: PolicyCheckpoint,
) -> Result<(), EnrollmentError> {
    let remote = anchor.current().map_err(EnrollmentError::Anchor)?;
    if remote != local { return Err(EnrollmentError::CheckpointMismatch); }
    Ok(())
}

/// Reads a canonical SQLite snapshot. Never derive the trusted checkpoint
/// from this method alone; the external anchor must be provisioned by an
/// independent control plane, not initialized from possibly untrusted DB.
fn policy_checkpoint(
    db: &Connection, operator: &VerifyingKey,
) -> Result<PolicyCheckpoint, EnrollmentError> {
    let revision: i64 = db.query_row(
        "SELECT last_revision FROM w6_policy_state WHERE singleton=1",
        [], |row| row.get(0),
    )?;
    if revision < 0 { return Err(EnrollmentError::CorruptStorage); }

    let mut hasher = blake3::Hasher::new();
    hasher.update(CHECKPOINT_DOMAIN);
    hasher.update(operator.as_bytes());
    hasher.update(&(revision as u64).to_be_bytes());

    let mut stmt = db.prepare(
        "SELECT endpoint,device,epoch,relay,namespace,token,issuer,revoked
         FROM w6_peer_enrollments ORDER BY endpoint ASC"
    )?;
    let mut rows = stmt.query([])?;
    let mut count = 0u64;
    while let Some(row) = rows.next()? {
        count += 1;
        if count > MAX_ENROLLED_ENDPOINTS as u64 {
            return Err(EnrollmentError::CorruptStorage);
        }
        let endpoint: Vec<u8> = row.get(0)?;
        let stored = StoredBinding {
            device: row.get(1)?, epoch: row.get(2)?,
            relay: row.get(3)?, namespace: row.get(4)?,
            token: row.get(5)?, issuer: row.get(6)?,
            revoked: row.get(7)?,
        };
        if endpoint.len() != 32 || !stored.valid() {
            return Err(EnrollmentError::CorruptStorage);
        }
        hasher.update(&endpoint);
        hasher.update(&stored.device);
        hasher.update(&stored.epoch.to_be_bytes());
        hasher.update(&stored.relay);
        hasher.update(&stored.namespace);
        hasher.update(&stored.token);
        hasher.update(&stored.issuer);
        hasher.update(&stored.revoked.to_be_bytes());
    }
    hasher.update(&count.to_be_bytes());
    Ok(PolicyCheckpoint {
        revision: revision as u64,
        digest: *hasher.finalize().as_bytes(),
    })
}

fn bytes16(raw: &[u8], start: usize) -> [u8;16] {
    raw[start..start + 16].try_into().expect("fixed body length checked")
}
fn num64(raw: &[u8], start: usize) -> u64 {
    u64::from_be_bytes(
        raw[start..start + 8].try_into().expect("fixed body length checked")
    )
}
fn valid_numbers(action: &OperatorChange) -> bool {
    action.revision > 0
        && action.revision <= i64::MAX as u64
        && action.binding.w3_epoch <= i64::MAX as u64
}
fn encoded_body(action: &OperatorChange) -> Result<Vec<u8>, EnrollmentError> {
    if !valid_numbers(action) { return Err(EnrollmentError::InvalidEncoding); }
    let b = &action.binding;
    let mut result = Vec::with_capacity(BODY_BYTES);
    result.push(VERSION);
    result.push(action.operation as u8);
    result.extend_from_slice(&action.revision.to_be_bytes());
    result.extend_from_slice(b.endpoint_id.as_bytes());
    result.extend_from_slice(&b.w3_device_id);
    result.extend_from_slice(&b.w3_epoch.to_be_bytes());
    result.extend_from_slice(&b.relay_id);
    result.extend_from_slice(&b.namespace);
    result.extend_from_slice(&b.route_token);
    result.extend_from_slice(&b.issuer_id);
    debug_assert_eq!(result.len(), BODY_BYTES);
    Ok(result)
}
fn signing_input(body: &[u8]) -> Vec<u8> {
    let mut data = Vec::with_capacity(DOMAIN.len() + body.len());
    data.extend_from_slice(DOMAIN);
    data.extend_from_slice(body);
    data
}

/// Offline/control-plane helper. Holding a signing key is privileged; this
/// does not give an unauthenticated client a way to change the relay policy.
pub fn sign_operator_change(
    signer: &SigningKey, action: &OperatorChange,
) -> Result<Vec<u8>, EnrollmentError> {
    let mut data = encoded_body(action)?;
    let signature = signer.sign(&signing_input(&data));
    data.extend_from_slice(&signature.to_bytes());
    Ok(data)
}

fn decode(raw: &[u8]) -> Result<OperatorChange, EnrollmentError> {
    if raw.len() != SIGNED_ENROLLMENT_BYTES || raw[0] != VERSION {
        return Err(EnrollmentError::InvalidEncoding);
    }
    let operation = match raw[1] {
        1 => PolicyOperation::Allow,
        2 => PolicyOperation::Revoke,
        _ => return Err(EnrollmentError::InvalidEncoding),
    };
    let mut endpoint = [0u8;32];
    endpoint.copy_from_slice(&raw[10..42]);
    let endpoint_id = EndpointId::from_bytes(&endpoint)
        .map_err(|_| EnrollmentError::InvalidEncoding)?;
    let action = OperatorChange {
        operation,
        revision: num64(raw, 2),
        binding: EndpointRouteBinding {
            endpoint_id,
            w3_device_id: bytes16(raw, 42),
            w3_epoch: num64(raw, 58),
            relay_id: bytes16(raw, 66),
            namespace: bytes16(raw, 82),
            route_token: bytes16(raw, 98),
            issuer_id: bytes16(raw, 114),
        },
    };
    if !valid_numbers(&action) { return Err(EnrollmentError::InvalidEncoding); }
    Ok(action)
}


const TRANSITION_DOMAIN: &[u8] = b"Akula/WOW/W6/operator-anchor-transition/lab-v1\0";
pub const SIGNED_TRANSITION_PROOF_BYTES: usize = 64;

/// A remote transition requires two distinct offline signatures.
/// The first covers the original W6 operator change. The second binds the
/// exact old and new checkpoint digests to those same signed-change bytes.
/// TLS administrator possession alone cannot invent a new checkpoint.
fn transition_message(
    change: &[u8], expected: PolicyCheckpoint, replacement: PolicyCheckpoint,
) -> Vec<u8> {
    let mut bytes=Vec::with_capacity(
        TRANSITION_DOMAIN.len()+SIGNED_ENROLLMENT_BYTES+80,
    );
    bytes.extend_from_slice(TRANSITION_DOMAIN);
    bytes.extend_from_slice(&expected.revision.to_be_bytes());
    bytes.extend_from_slice(&expected.digest);
    bytes.extend_from_slice(&replacement.revision.to_be_bytes());
    bytes.extend_from_slice(&replacement.digest);
    bytes.extend_from_slice(change);
    bytes
}

pub fn verify_operator_change(
    bytes: &[u8], operator: &VerifyingKey,
) -> Result<OperatorChange, EnrollmentError> {
    let action=decode(bytes)?;
    let signature=Signature::from_slice(&bytes[BODY_BYTES..])
        .map_err(|_|EnrollmentError::InvalidSignature)?;
    operator.verify_strict(
        &signing_input(&bytes[..BODY_BYTES]), &signature,
    ).map_err(|_|EnrollmentError::InvalidSignature)?;
    Ok(action)
}

pub fn verify_signed_anchor_transition(
    operator: &VerifyingKey, change: &[u8],
    expected: PolicyCheckpoint, replacement: PolicyCheckpoint,
    proof: &[u8],
) -> Result<OperatorChange, EnrollmentError> {
    let action=verify_operator_change(change,operator)?;
    if replacement.revision!=action.revision
        || replacement.revision<=expected.revision
        || replacement.revision>i64::MAX as u64
    {
        return Err(EnrollmentError::InvalidEncoding);
    }
    if proof.len()!=SIGNED_TRANSITION_PROOF_BYTES {
        return Err(EnrollmentError::InvalidEncoding);
    }
    let signature=Signature::from_slice(proof)
        .map_err(|_|EnrollmentError::InvalidSignature)?;
    operator.verify_strict(
        &transition_message(change,expected,replacement),
        &signature,
    ).map_err(|_|EnrollmentError::InvalidSignature)?;
    Ok(action)
}

/// PRIVILEGED OFFLINE helper; never place this SigningKey in a W6 relay or
/// remote authority. A control plane must independently review the computed
/// replacement checkpoint before authorizing it.
pub fn sign_anchor_transition(
    signer: &SigningKey, change: &[u8],
    expected: PolicyCheckpoint, replacement: PolicyCheckpoint,
) -> Result<[u8;SIGNED_TRANSITION_PROOF_BYTES],EnrollmentError> {
    let action=verify_operator_change(change,&signer.verifying_key())?;
    if replacement.revision!=action.revision
        || replacement.revision<=expected.revision
        || replacement.revision>i64::MAX as u64
    {
        return Err(EnrollmentError::InvalidEncoding);
    }
    Ok(signer.sign(&transition_message(change,expected,replacement)).to_bytes())
}

struct StoredBinding {
    device: Vec<u8>,
    epoch: i64,
    relay: Vec<u8>,
    namespace: Vec<u8>,
    token: Vec<u8>,
    issuer: Vec<u8>,
    revoked: i64,
}
impl StoredBinding {
    fn read(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            device: row.get(0)?,
            epoch: row.get(1)?,
            relay: row.get(2)?,
            namespace: row.get(3)?,
            token: row.get(4)?,
            issuer: row.get(5)?,
            revoked: row.get(6)?,
        })
    }
    fn valid(&self) -> bool {
        self.device.len() == 16 && self.epoch >= 0
            && self.relay.len() == 16 && self.namespace.len() == 16
            && self.token.len() == 16 && self.issuer.len() == 16
            && (self.revoked == 0 || self.revoked == 1)
    }
    fn scope_matches(&self, b: &EndpointRouteBinding) -> bool {
        self.device.as_slice() == b.w3_device_id
            && self.relay.as_slice() == b.relay_id
            && self.namespace.as_slice() == b.namespace
            && self.token.as_slice() == b.route_token
            && self.issuer.as_slice() == b.issuer_id
    }
}

fn stored_at(
    db: &Connection, endpoint: &EndpointId,
) -> Result<Option<StoredBinding>, EnrollmentError> {
    Ok(db.query_row(
        "SELECT device,epoch,relay,namespace,token,issuer,revoked
         FROM w6_peer_enrollments WHERE endpoint = ?1",
        params![endpoint.as_bytes().as_slice()],
        StoredBinding::read,
    ).optional()?)
}

pub struct PeerEnrollmentDb {
    db: Connection,
    operator: VerifyingKey,
}
impl PeerEnrollmentDb {
    /// Root key is an independently pinned local parameter. Reopening a DB
    /// with a DIFFERENT root fails closed; DB content cannot choose the root.
    pub fn open(path: &Path, operator: VerifyingKey) -> Result<Self, EnrollmentError> {
        let db = Connection::open(path)?;
        db.busy_timeout(std::time::Duration::from_secs(2))?;
        db.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=FULL;
             CREATE TABLE IF NOT EXISTS w6_policy_state (
               singleton INTEGER PRIMARY KEY CHECK(singleton=1),
               operator_key BLOB NOT NULL CHECK(length(operator_key)=32),
               last_revision INTEGER NOT NULL CHECK(last_revision>=0)
             );
             CREATE TABLE IF NOT EXISTS w6_peer_enrollments (
               endpoint BLOB PRIMARY KEY NOT NULL CHECK(length(endpoint)=32),
               device BLOB NOT NULL CHECK(length(device)=16),
               epoch INTEGER NOT NULL CHECK(epoch>=0),
               relay BLOB NOT NULL CHECK(length(relay)=16),
               namespace BLOB NOT NULL CHECK(length(namespace)=16),
               token BLOB NOT NULL CHECK(length(token)=16),
               issuer BLOB NOT NULL CHECK(length(issuer)=16),
               revoked INTEGER NOT NULL CHECK(revoked IN (0,1))
             );
             CREATE TABLE IF NOT EXISTS w6_pending_transition (
               singleton INTEGER PRIMARY KEY CHECK(singleton=1),
               expected_revision INTEGER NOT NULL CHECK(expected_revision>=0),
               expected_digest BLOB NOT NULL CHECK(length(expected_digest)=32),
               replacement_revision INTEGER NOT NULL CHECK(replacement_revision>0),
               replacement_digest BLOB NOT NULL CHECK(length(replacement_digest)=32),
               signed_change BLOB NOT NULL CHECK(length(signed_change)=194),
               signed_proof BLOB NOT NULL CHECK(length(signed_proof)=64)
             );"
        )?;
        db.execute(
            "INSERT OR IGNORE INTO w6_policy_state
             (singleton,operator_key,last_revision) VALUES(1,?1,0)",
            params![operator.as_bytes().as_slice()],
        )?;
        let persisted: Vec<u8> = db.query_row(
            "SELECT operator_key FROM w6_policy_state WHERE singleton=1",
            [], |row|row.get(0),
        )?;
        if persisted.as_slice() != operator.as_bytes() {
            return Err(EnrollmentError::UntrustedOperator);
        }
        Ok(Self { db, operator })
    }

    /// Informational digest for external provisioning/test fixtures. It is
    /// NOT independently trustworthy until an external anchor has recorded
    /// it through a privileged bootstrap ceremony.
    pub fn checkpoint(&self) -> Result<PolicyCheckpoint, EnrollmentError> {
        policy_checkpoint(&self.db, &self.operator)
    }

    pub fn last_revision(&self) -> Result<u64, EnrollmentError> {
        let value: i64 = self.db.query_row(
            "SELECT last_revision FROM w6_policy_state WHERE singleton=1",
            [], |row|row.get(0),
        )?;
        if value < 0 { return Err(EnrollmentError::CorruptStorage); }
        Ok(value as u64)
    }

    /// Compute the complete candidate checkpoint inside an UNCOMMITTED
    /// SQLite IMMEDIATE transaction. The transaction is rolled back on drop.
    /// An OFFLINE operator must inspect/sign this (old,new) transition before
    /// the relay can publish the digest to the remote authority. This preview
    /// is NOT a durable or independent trust source by itself.
    pub fn preview_signed_update(
        &mut self, bytes: &[u8],
    ) -> Result<(PolicyCheckpoint,PolicyCheckpoint),EnrollmentError> {
        let action=verify_operator_change(bytes,&self.operator)?;
        let tx=self.db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        ensure_no_pending(&tx)?;
        let old=policy_checkpoint(&tx,&self.operator)?;
        apply_change_in_transaction(&tx,action)?;
        let next=policy_checkpoint(&tx,&self.operator)?;
        // tx is dropped here WITHOUT commit: PREVIEW ONLY.
        Ok((old,next))
    }

    /// Serialized, atomic signed update. No remote W6 handler can call this.
    /// Monotonic revision rejects stale/replayed changes across a restart.
    pub fn apply_signed(&mut self, bytes: &[u8]) -> Result<(), EnrollmentError> {
        self.apply_signed_internal(bytes, None, None)
    }

    /// Anchored operator update. Publishes the new canonical checkpoint
    /// BEFORE SQLite commit. A crash or failure between the two steps leaves
    /// an anchor ahead of the DB; subsequent reads fail closed rather than
    /// resurrecting an older authorization. Recovery requires a separately
    /// authenticated operator workflow, not automatic rollback of the anchor.
    pub fn apply_signed_anchored(
        &mut self, bytes: &[u8], anchor: &dyn TrustedPolicyAnchor,
    ) -> Result<(), EnrollmentError> {
        self.apply_signed_internal(bytes, Some(anchor), None)
    }

    /// REQUIRED for remote TLS-backed W6 authority: the offline signer has
    /// reviewed and signed the *entire* expected/replacement checkpoint as
    /// well as the original operator change. TLS-admin-only CAS is rejected.
    pub fn apply_signed_anchored_with_proof(
        &mut self, bytes: &[u8], proof: &[u8],
        anchor: &dyn TrustedPolicyAnchor,
    ) -> Result<(), EnrollmentError> {
        self.apply_signed_internal(bytes, Some(anchor), Some(proof))
    }

    /// Persist the fully verified, offline-signed transition BEFORE sending
    /// network CAS. The local policy remains unchanged until remote confirmation.
    /// Any ambiguous CAS error leaves the durable intent in place, and ALL
    /// authorization/write paths fail closed until explicit reconciliation.
    fn apply_signed_with_signed_journal(
        &mut self, bytes: &[u8], proof: &[u8],
        anchor: &dyn TrustedPolicyAnchor,
    ) -> Result<(), EnrollmentError> {
        let action = verify_operator_change(bytes, &self.operator)?;
        let tx = self.db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        ensure_no_pending(&tx)?;
        let expected = policy_checkpoint(&tx, &self.operator)?;
        ensure_anchor(anchor, expected)?;

        // The preview and the pending journal share one IMMEDIATE transaction.
        // The SAVEPOINT undoes only the policy mutation, not the staged intent.
        tx.execute_batch("SAVEPOINT w6_signed_candidate;")?;
        apply_change_in_transaction(&tx, action)?;
        let replacement = policy_checkpoint(&tx, &self.operator)?;
        verify_signed_anchor_transition(
            &self.operator, bytes, expected, replacement, proof,
        )?;
        tx.execute_batch(
            "ROLLBACK TO SAVEPOINT w6_signed_candidate;
             RELEASE SAVEPOINT w6_signed_candidate;",
        )?;
        tx.execute(
            "INSERT INTO w6_pending_transition
             (singleton,expected_revision,expected_digest,
              replacement_revision,replacement_digest,signed_change,signed_proof)
             VALUES(1,?1,?2,?3,?4,?5,?6)",
            params![
                expected.revision as i64, expected.digest.as_slice(),
                replacement.revision as i64, replacement.digest.as_slice(),
                bytes, proof,
            ],
        )?;
        tx.commit()?;

        // The journal is now durable. An unavailable/ambiguous response MUST
        // NOT erase it or retry with a newly computed digest.
        anchor.advance_signed(expected, replacement, bytes, proof)
            .map_err(EnrollmentError::Anchor)?;
        match self.recover_pending_signed_update(anchor)? {
            SignedRecoveryOutcome::AppliedAfterCas
            | SignedRecoveryOutcome::ForwardedPending
            | SignedRecoveryOutcome::AlreadyApplied => Ok(()),
            _ => Err(EnrollmentError::CheckpointMismatch),
        }
    }

    /// Explicit, fail-closed W6 recovery after process death or unknown CAS
    /// outcome. Never roll back the remote authority: either abort an intent
    /// not yet published, or reapply the exact offline-signed local mutation.
    /// The pending journal is deleted atomically with any local COMMIT.
    ///
    /// An observed old remote checkpoint is NOT proof that a previously
    /// submitted CAS cannot arrive later. Therefore we NEVER abandon a
    /// staged intent on GET(expected): retry the SAME preapproved signed CAS.
    /// A failed or ambiguous retry leaves the intent in HOLD until the
    /// independently trusted authority confirms the replacement checkpoint.
    ///
    /// The remote authority remains a separate trust and rollback domain;
    /// this does not solve cross-host fencing or a compromised offline signer.
    pub fn recover_pending_signed_update(
        &mut self, anchor: &dyn TrustedPolicyAnchor,
    ) -> Result<SignedRecoveryOutcome, EnrollmentError> {
        let tx = self.db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let Some(pending) = pending_signed_transition(&tx)? else {
            return Ok(SignedRecoveryOutcome::NoPending);
        };
        let action = verify_signed_anchor_transition(
            &self.operator, &pending.change, pending.expected,
            pending.replacement, &pending.proof,
        )?;
        let local = policy_checkpoint(&tx, &self.operator)?;
        let mut remote = anchor.current().map_err(EnrollmentError::Anchor)?;
        let mut forwarded = false;
        if local == pending.expected && remote == pending.expected {
            // A late CAS from the interrupted process can still arrive after
            // this read. Never clear the journal just because GET saw old.
            // Re-publish only the EXACT existing operator-signed transition.
            // Even when RPC reports Conflict/Unavailable, GET may reveal that
            // this or the original request already committed.
            let publish = anchor.advance_signed(
                pending.expected, pending.replacement,
                &pending.change, &pending.proof,
            );
            remote = anchor.current().map_err(EnrollmentError::Anchor)?;
            if remote == pending.expected {
                return match publish {
                    Err(error) => Err(EnrollmentError::Anchor(error)),
                    Ok(()) => Err(EnrollmentError::CheckpointMismatch),
                };
            }
            if remote == pending.replacement {
                forwarded = true;
            }
        }
        let outcome = if local == pending.expected && remote == pending.replacement {
            apply_change_in_transaction(&tx, action)?;
            if policy_checkpoint(&tx, &self.operator)? != pending.replacement {
                return Err(EnrollmentError::CheckpointMismatch);
            }
            if forwarded {
                SignedRecoveryOutcome::ForwardedPending
            } else {
                SignedRecoveryOutcome::AppliedAfterCas
            }
        } else if local == pending.replacement && remote == pending.replacement {
            SignedRecoveryOutcome::AlreadyApplied
        } else {
            // Unknown remote high-water or locally modified/rolled-back DB:
            // HOLD pending record; no policy write or compensating anchor CAS.
            return Err(EnrollmentError::CheckpointMismatch);
        };
        tx.execute("DELETE FROM w6_pending_transition WHERE singleton=1", [])?;
        tx.commit()?;
        Ok(outcome)
    }

    fn apply_signed_internal(
        &mut self, bytes: &[u8], anchor: Option<&dyn TrustedPolicyAnchor>,
        proof: Option<&[u8]>,
    ) -> Result<(), EnrollmentError> {
        if let (Some(anchor), Some(proof)) = (anchor, proof) {
            return self.apply_signed_with_signed_journal(bytes, proof, anchor);
        }
        let action = verify_operator_change(bytes,&self.operator)?;
        let tx = self.db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        ensure_no_pending(&tx)?;
        let prior = if let Some(anchor) = anchor {
            let local = policy_checkpoint(&tx, &self.operator)?;
            ensure_anchor(anchor, local)?;
            Some(local)
        } else {
            None
        };
        apply_change_in_transaction(&tx,action)?;
        if let (Some(anchor), Some(previous)) = (anchor, prior) {
            let next = policy_checkpoint(&tx, &self.operator)?;
            if next.revision <= previous.revision {
                return Err(EnrollmentError::RevisionRollback);
            }
            // Critical order: external durable anchor BEFORE local SQLite
            // commit. Failure of the anchor means no local policy mutation.
            // If SQLite subsequently fails, the anchor is ahead: fail closed.
            if let Some(proof)=proof {
                verify_signed_anchor_transition(
                    &self.operator,bytes,previous,next,proof,
                )?;
                anchor.advance_signed(previous,next,bytes,proof)
                    .map_err(EnrollmentError::Anchor)?;
            } else {
                anchor.advance(previous,next).map_err(EnrollmentError::Anchor)?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Snapshot check only, suitable for rejecting untrusted peers BEFORE
    /// reading any QUIC application stream. This method alone MUST NOT be
    /// used to authorize a later Mailbox write across process boundaries.
    pub fn authorize(
        &self, remote: &EndpointId, relay: &[u8;16],
        namespace: &[u8;16], token: &[u8;16], issuer: &[u8;16],
    ) -> Result<([u8;16],u64), EnrollmentError> {
        ensure_no_pending(&self.db)?;
        authorize_from(&self.db, remote, relay, namespace, token, issuer)
    }


    /// Provisional QUIC admission, using one real SQLite write transaction
    /// to read a canonical snapshot and verify the *external* anchor before
    /// the stream is read. No mailbox write is authorized by this alone.
    pub fn authorize_anchored(
        &mut self, anchor: &dyn TrustedPolicyAnchor, lookup: EnrollmentLookup<'_>,
    ) -> Result<([u8;16],u64), EnrollmentError> {
        let tx = self.db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        ensure_no_pending(&tx)?;
        ensure_anchor(anchor, policy_checkpoint(&tx, &self.operator)?)?;
        let identity = authorize_from(
            &tx, lookup.remote, lookup.relay, lookup.namespace,
            lookup.token, lookup.issuer,
        )?;
        tx.commit()?;
        Ok(identity)
    }

    /// The mandatory final authorization boundary for shared-SQLite writers.
    ///
    /// BEGIN IMMEDIATE obtains an actual SQLite RESERVED write lock on the
    /// operator policy database, not just an in-process Mutex. Every signed
    /// operator Allow/Revoke uses the SAME IMMEDIATE transaction in
    /// apply_signed(), so even an independent OS process cannot commit a
    /// policy change BETWEEN this check and the callback's durable Mailbox
    /// write. The callback must complete the Mailbox COMMIT before returning.
    /// An error rolls back this read-only policy transaction on drop.
    ///
    /// No network I/O/await under this lock. A busy/locked policy DB fails
    /// closed; lock starvation is an availability threat and not resolved here.
    /// This does NOT fix physical DB-snapshot rollback or replicate policies
    /// across *different* policy SQLite files/hosts.
    pub fn with_authorized_write<T, E, F>(
        &mut self, remote: &EndpointId, relay: &[u8;16],
        namespace: &[u8;16], token: &[u8;16], issuer: &[u8;16],
        commit_mailbox: F,
    ) -> Result<T, E>
    where
        E: From<EnrollmentError>,
        F: FnOnce(([u8;16], u64)) -> Result<T, E>,
    {
        self.with_write_internal(
            None, EnrollmentLookup { remote, relay, namespace, token, issuer },
            commit_mailbox,
        )
    }

    /// REQUIRED final grant for an anchored W6 network ingress: proof of
    /// current externally attested policy snapshot happens INSIDE the same
    /// SQLite IMMEDIATE transaction held across the Mailbox durable COMMIT.
    /// Do not substitute the legacy unanchored method in a network adapter.
    pub fn with_anchored_write<T, E, F>(
        &mut self, anchor: &dyn TrustedPolicyAnchor,
        lookup: EnrollmentLookup<'_>, commit_mailbox: F,
    ) -> Result<T, E>
    where
        E: From<EnrollmentError>,
        F: FnOnce(([u8;16],u64)) -> Result<T,E>,
    {
        self.with_write_internal(Some(anchor), lookup, commit_mailbox)
    }


    fn with_write_internal<T, E, F>(
        &mut self, anchor: Option<&dyn TrustedPolicyAnchor>,
        lookup: EnrollmentLookup<'_>, commit_mailbox: F,
    ) -> Result<T, E>
    where
        E: From<EnrollmentError>,
        F: FnOnce(([u8;16], u64)) -> Result<T, E>,
    {
        let tx = self.db.transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(EnrollmentError::from).map_err(E::from)?;
        ensure_no_pending(&tx).map_err(E::from)?;
        if let Some(anchor) = anchor {
            let snapshot=policy_checkpoint(&tx, &self.operator).map_err(E::from)?;
            ensure_anchor(anchor, snapshot).map_err(E::from)?;
        }
        let identity = authorize_from(
            &tx, lookup.remote, lookup.relay, lookup.namespace,
            lookup.token, lookup.issuer,
        ).map_err(E::from)?;
        let result = commit_mailbox(identity)?;
        tx.commit().map_err(EnrollmentError::from).map_err(E::from)?;
        Ok(result)
    }
}


/// Exact W6 signed change semantics reused for preview and COMMIT. A single
/// implementation prevents any mismatch between what offline operator signed
/// and what the relay actually commits.
fn apply_change_in_transaction(
    tx: &rusqlite::Transaction<'_>, action: OperatorChange,
) -> Result<(),EnrollmentError> {
        let last: i64 = tx.query_row(
            "SELECT last_revision FROM w6_policy_state WHERE singleton=1",
            [], |row|row.get(0),
        )?;
        if last < 0 { return Err(EnrollmentError::CorruptStorage); }
        if action.revision <= last as u64 {
            return Err(EnrollmentError::RevisionRollback);
        }
        let existing = stored_at(tx, &action.binding.endpoint_id)?;
        match action.operation {
            PolicyOperation::Allow => {
                if let Some(old) = existing {
                    if !old.valid() { return Err(EnrollmentError::CorruptStorage); }
                    if old.revoked == 1 { return Err(EnrollmentError::Revoked); }
                    if !old.scope_matches(&action.binding) {
                        return Err(EnrollmentError::BindingConflict);
                    }
                    if action.binding.w3_epoch <= old.epoch as u64 {
                        return Err(EnrollmentError::EpochRollback);
                    }
                    tx.execute(
                        "UPDATE w6_peer_enrollments SET epoch=?2 WHERE endpoint=?1",
                        params![
                            action.binding.endpoint_id.as_bytes().as_slice(),
                            action.binding.w3_epoch as i64,
                        ],
                    )?;
                } else {
                    let count: i64 = tx.query_row(
                        "SELECT COUNT(*) FROM w6_peer_enrollments",
                        [], |row|row.get(0),
                    )?;
                    if count >= MAX_ENROLLED_ENDPOINTS {
                        return Err(EnrollmentError::TooManyPeers);
                    }
                    let b = action.binding;
                    tx.execute(
                        "INSERT INTO w6_peer_enrollments
                         (endpoint,device,epoch,relay,namespace,token,issuer,revoked)
                         VALUES(?1,?2,?3,?4,?5,?6,?7,0)",
                        params![
                            b.endpoint_id.as_bytes().as_slice(),
                            b.w3_device_id.as_slice(),
                            b.w3_epoch as i64,
                            b.relay_id.as_slice(),
                            b.namespace.as_slice(),
                            b.route_token.as_slice(),
                            b.issuer_id.as_slice(),
                        ],
                    )?;
                }
            }
            PolicyOperation::Revoke => {
                let old = existing.ok_or(EnrollmentError::UnknownEndpoint)?;
                if !old.valid() { return Err(EnrollmentError::CorruptStorage); }
                if old.revoked == 1 { return Err(EnrollmentError::Revoked); }
                if !old.scope_matches(&action.binding)
                    || old.epoch as u64 != action.binding.w3_epoch
                {
                    return Err(EnrollmentError::BindingConflict);
                }
                tx.execute(
                    "UPDATE w6_peer_enrollments SET revoked=1 WHERE endpoint=?1",
                    params![action.binding.endpoint_id.as_bytes().as_slice()],
                )?;
            }
        }
        tx.execute(
            "UPDATE w6_policy_state SET last_revision=?1 WHERE singleton=1",
            params![action.revision as i64],
        )?;
    Ok(())
}

/// Internal shared verifier: the caller chooses either a snapshot Connection
/// or an exclusive-writer SQLite Transaction. Never infer identity from peer
/// message bytes, even if its transport-level TLS signature is genuine.
fn authorize_from(
    db: &Connection, remote: &EndpointId, relay: &[u8;16],
    namespace: &[u8;16], token: &[u8;16], issuer: &[u8;16],
) -> Result<([u8;16],u64), EnrollmentError> {
    let old = stored_at(db, remote)?.ok_or(EnrollmentError::UnknownEndpoint)?;
    if !old.valid() { return Err(EnrollmentError::CorruptStorage); }
    if old.revoked == 1 { return Err(EnrollmentError::Revoked); }
    if old.relay.as_slice() != relay
        || old.namespace.as_slice() != namespace
        || old.token.as_slice() != token
        || old.issuer.as_slice() != issuer
    {
        return Err(EnrollmentError::WrongScope);
    }
    let device: [u8;16] = old.device.try_into()
        .map_err(|_| EnrollmentError::CorruptStorage)?;
    Ok((device,old.epoch as u64))
}
