//! W11: a separately administered checkpoint anchor for W9/W10.
//!
//! The anchor verifies the witness's signed checkpoint and commits a second,
//! independently signed statement *after* it has durably stored that exact
//! checkpoint in its own SQLite (WAL + FULL). Clients provision BOTH signing
//! keys out of band. They compare this independently acquired attestation
//! to their W10 pinned checkpoint before claiming that a history is current.
//!
//! A remote anchor's genuine signature never proves the remote host ran this
//! code, its disk is physically independent, or its checkpoint is fresh.
//! An operator who controls both files/signer keys can roll back or fork both.
//! Privacy: even digest/sequence commitments are linkable; do not globally
//! publish receipts or signed raw offers.
use crate::custody_witness_w9::{self, ChainRelation, WitnessError, CHECKPOINT_LEN};
use crate::trust_w3::TrustRegistry;
use crate::witness_pin_w10::{PinError, WitnessPinStore};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use std::path::Path;

const DOMAIN: &[u8] = b"Akula/WOW/W11/independent-checkpoint-anchor/Ed25519-v1\0";
const VERSION: u8 = 1;
const BODY_LEN: usize = 121;
pub const ANCHOR_RECEIPT_LEN: usize = BODY_LEN + 64;
const MAX_SEQUENCE: u64 = 1024;

#[derive(Debug)]
pub enum AnchorError {
    Db(rusqlite::Error),
    Witness(WitnessError),
    Pin(PinError),
    WrongScope,
    UntrustedAnchor,
    InvalidReceipt,
    InvalidSignature,
    MissingHistory,
    Stale,
    Equivocation,
    Frozen,
    NotPinned,
    NotMatched,
}
impl From<rusqlite::Error> for AnchorError {
    fn from(e: rusqlite::Error) -> Self { Self::Db(e) }
}
impl From<WitnessError> for AnchorError {
    fn from(e: WitnessError) -> Self { Self::Witness(e) }
}
impl From<PinError> for AnchorError {
    fn from(e: PinError) -> Self { Self::Pin(e) }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct AnchorIdentity {
    pub anchor_id: [u8; 16],
    pub anchor_epoch: u64,
    pub witness_id: [u8; 16],
    pub witness_epoch: u64,
}
impl AnchorIdentity {
    fn valid(self) -> bool {
        self.anchor_id != [0; 16] && self.witness_id != [0; 16]
            && self.anchor_id != self.witness_id
            && self.anchor_epoch > 0 && self.witness_epoch > 0
            && self.anchor_epoch <= i64::MAX as u64
            && self.witness_epoch <= i64::MAX as u64
    }
}
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct VerifiedAnchor {
    pub scope: AnchorIdentity,
    pub sequence: u64,
    pub witness_head: [u8; 32],
    pub checkpoint_digest: [u8; 32],
}
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum AnchorObservation { First, Unchanged, Advanced }
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum AnchorComparison {
    Matched,
    LocalBehind,
    AnchorBehind,
    UnprovenGap,
    Equivocation,
    NoLocalPin,
}
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum AnchorGossip {
    Same,
    SameHeightEquivocation,
    Older,
    Newer,
}
/// Private evidence includes both signed W9 statements and can link slots.
pub type WitnessForkPair = (Vec<u8>, Vec<u8>);
type StoredForkPair = (Option<Vec<u8>>, Option<Vec<u8>>);
type SavedState = (Option<Vec<u8>>, Option<Vec<u8>>, i64);

fn a16(src: &[u8]) -> [u8; 16] { src.try_into().expect("checked receipt length") }
fn a32(src: &[u8]) -> [u8; 32] { src.try_into().expect("checked receipt length") }
fn a64(src: &[u8]) -> u64 {
    u64::from_be_bytes(src.try_into().expect("checked receipt length"))
}

fn ensure_anchor_signer(
    scope: AnchorIdentity, signer: &SigningKey, trust: &TrustRegistry,
) -> Result<(), AnchorError> {
    if !scope.valid() { return Err(AnchorError::WrongScope); }
    let enrolled = trust.key_for(scope.anchor_id, scope.anchor_epoch)
        .map_err(|_| AnchorError::UntrustedAnchor)?;
    if enrolled != &signer.verifying_key() {
        return Err(AnchorError::UntrustedAnchor);
    }
    Ok(())
}

/// Fixed-size, domain-separated signature binding one EXACT signed W9 head
/// to a separate anchor identity and epoch. Does not reveal W8 offer bytes.
fn sign_anchor(
    scope: AnchorIdentity, checkpoint: &[u8], sequence: u64,
    witness_head: [u8; 32], signer: &SigningKey,
) -> Vec<u8> {
    let mut body = Vec::with_capacity(ANCHOR_RECEIPT_LEN);
    body.push(VERSION);
    body.extend_from_slice(&scope.anchor_id);
    body.extend_from_slice(&scope.anchor_epoch.to_be_bytes());
    body.extend_from_slice(&scope.witness_id);
    body.extend_from_slice(&scope.witness_epoch.to_be_bytes());
    body.extend_from_slice(&sequence.to_be_bytes());
    body.extend_from_slice(&witness_head);
    body.extend_from_slice(blake3::hash(checkpoint).as_bytes());
    debug_assert_eq!(body.len(), BODY_LEN);
    let mut signed = Vec::with_capacity(DOMAIN.len() + body.len());
    signed.extend_from_slice(DOMAIN);
    signed.extend_from_slice(&body);
    body.extend_from_slice(&signer.sign(&signed).to_bytes());
    body
}

/// Checks BOTH the witness's original Ed25519 signature and the independent
/// anchor signature, with pinned source identities from local policy.
pub fn verify_anchor(
    receipt: &[u8], exact_checkpoint: &[u8], expected: AnchorIdentity,
    trust: &TrustRegistry,
) -> Result<VerifiedAnchor, AnchorError> {
    if !expected.valid() { return Err(AnchorError::WrongScope); }
    if receipt.len() != ANCHOR_RECEIPT_LEN || receipt[0] != VERSION {
        return Err(AnchorError::InvalidReceipt);
    }
    let parsed = AnchorIdentity {
        anchor_id: a16(&receipt[1..17]),
        anchor_epoch: a64(&receipt[17..25]),
        witness_id: a16(&receipt[25..41]),
        witness_epoch: a64(&receipt[41..49]),
    };
    if parsed != expected { return Err(AnchorError::WrongScope); }
    let checkpoint = custody_witness_w9::verify_checkpoint(
        exact_checkpoint, expected.witness_id, trust,
    )?;
    if checkpoint.witness_epoch != expected.witness_epoch {
        return Err(AnchorError::WrongScope);
    }
    let sequence = a64(&receipt[49..57]);
    let head = a32(&receipt[57..89]);
    let digest = a32(&receipt[89..121]);
    if sequence != checkpoint.sequence || head != checkpoint.head
        || digest != *blake3::hash(exact_checkpoint).as_bytes()
    {
        return Err(AnchorError::InvalidReceipt);
    }
    let key = trust.key_for(expected.anchor_id, expected.anchor_epoch)
        .map_err(|_| AnchorError::UntrustedAnchor)?;
    let signature = Signature::from_slice(&receipt[BODY_LEN..])
        .map_err(|_| AnchorError::InvalidSignature)?;
    let mut signed = Vec::with_capacity(DOMAIN.len() + BODY_LEN);
    signed.extend_from_slice(DOMAIN);
    signed.extend_from_slice(&receipt[..BODY_LEN]);
    key.verify(&signed, &signature).map_err(|_| AnchorError::InvalidSignature)?;
    Ok(VerifiedAnchor {
        scope: expected,
        sequence,
        witness_head: head,
        checkpoint_digest: digest,
    })
}

/// A signed independently stored head and a local W10 pin are BOTH required.
/// Do not translate an out-of-date or missing peer anchor into "all clear".
/// Reconciliation never automatically reduces/replaces local W10 checkpoint.
pub fn compare_with_pin(
    receipt: &[u8], checkpoint: &[u8], expected: AnchorIdentity,
    pin: &WitnessPinStore, trust: &TrustRegistry,
) -> Result<AnchorComparison, AnchorError> {
    let _ = verify_anchor(receipt, checkpoint, expected, trust)?;
    if pin.frozen()? { return Err(AnchorError::Frozen); }
    let Some(local) = pin.current()? else {
        return Ok(AnchorComparison::NoLocalPin);
    };
    let local_verified = custody_witness_w9::verify_checkpoint(
        &local, expected.witness_id, trust,
    )?;
    if local_verified.witness_epoch != expected.witness_epoch {
        return Err(AnchorError::WrongScope);
    }
    Ok(match custody_witness_w9::compare_checkpoints(
        &local, checkpoint, expected.witness_id, trust,
    )? {
        ChainRelation::Same => AnchorComparison::Matched,
        ChainRelation::Adjacent => AnchorComparison::LocalBehind,
        ChainRelation::RollbackSuspected => AnchorComparison::AnchorBehind,
        ChainRelation::MissingHistory => AnchorComparison::UnprovenGap,
        ChainRelation::Equivocation => AnchorComparison::Equivocation,
    })
}

/// An explicit *fail-closed* gate. Caller must fetch a sufficiently fresh
/// independently authenticated peer anchor and cannot treat timeout as pass.
pub fn require_matched(
    receipt: &[u8], checkpoint: &[u8], expected: AnchorIdentity,
    pin: &WitnessPinStore, trust: &TrustRegistry,
) -> Result<(), AnchorError> {
    if compare_with_pin(receipt, checkpoint, expected, pin, trust)?
        == AnchorComparison::Matched
    {
        Ok(())
    } else {
        Err(AnchorError::NotMatched)
    }
}

/// Signed conflicting statements from the SAME anchor key at one sequence
/// prove an anchor split view IF BOTH statements and their corresponding
/// signed witness checkpoints are available to independent clients.
pub fn compare_anchor_receipts(
    a: (&[u8], &[u8]), b: (&[u8], &[u8]), scope: AnchorIdentity,
    trust: &TrustRegistry,
) -> Result<AnchorGossip, AnchorError> {
    let av = verify_anchor(a.0, a.1, scope, trust)?;
    let bv = verify_anchor(b.0, b.1, scope, trust)?;
    if av.sequence == bv.sequence {
        return Ok(if av.witness_head == bv.witness_head
            && av.checkpoint_digest == bv.checkpoint_digest
        { AnchorGossip::Same } else { AnchorGossip::SameHeightEquivocation });
    }
    Ok(if av.sequence < bv.sequence {
        AnchorGossip::Newer
    } else {
        AnchorGossip::Older
    })
}

pub struct AnchorStore {
    db: Connection,
    scope: AnchorIdentity,
}
impl AnchorStore {
    /// This database MUST live outside the witness's SQLite. For actual
    /// anti-rollback against host compromise it MUST be independently
    /// administered and queried with a pinned transport/key.
    pub fn open(path: &Path, scope: AnchorIdentity) -> Result<Self, AnchorError> {
        if !scope.valid() { return Err(AnchorError::WrongScope); }
        let db = Connection::open(path)?;
        db.busy_timeout(std::time::Duration::from_secs(5))?;
        db.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
             CREATE TABLE IF NOT EXISTS anchor_state(
                 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                 anchor_id BLOB NOT NULL CHECK(length(anchor_id)=16),
                 anchor_epoch INTEGER NOT NULL CHECK(anchor_epoch>0),
                 witness_id BLOB NOT NULL CHECK(length(witness_id)=16),
                 witness_epoch INTEGER NOT NULL CHECK(witness_epoch>0),
                 checkpoint BLOB CHECK(checkpoint IS NULL OR length(checkpoint)=226),
                 receipt BLOB CHECK(receipt IS NULL OR length(receipt)=185),
                 frozen INTEGER NOT NULL CHECK(frozen IN (0,1)),
                 fork_a BLOB CHECK(fork_a IS NULL OR length(fork_a)=226),
                 fork_b BLOB CHECK(fork_b IS NULL OR length(fork_b)=226)
             );"
        )?;
        db.execute(
            "INSERT OR IGNORE INTO anchor_state(singleton,anchor_id,anchor_epoch,
                 witness_id,witness_epoch,checkpoint,receipt,frozen,fork_a,fork_b)
             VALUES(1,?1,?2,?3,?4,NULL,NULL,0,NULL,NULL)",
            params![
                scope.anchor_id.as_slice(), scope.anchor_epoch as i64,
                scope.witness_id.as_slice(), scope.witness_epoch as i64,
            ],
        )?;
        type Row = (Vec<u8>, i64, Vec<u8>, i64);
        let stored: Row = db.query_row(
            "SELECT anchor_id,anchor_epoch,witness_id,witness_epoch
             FROM anchor_state WHERE singleton=1", [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )?;
        if stored.0.as_slice() != scope.anchor_id
            || stored.1 != scope.anchor_epoch as i64
            || stored.2.as_slice() != scope.witness_id
            || stored.3 != scope.witness_epoch as i64
        {
            return Err(AnchorError::WrongScope);
        }
        Ok(Self { db, scope })
    }

    /// One immediate SQLite transaction: receipt is created from the witness
    /// checkpoint but is not RETURNED until checkpoint+receipt commit.
    pub fn observe(
        &mut self, checkpoint: &[u8], signer: &SigningKey, trust: &TrustRegistry,
    ) -> Result<(AnchorObservation, Vec<u8>), AnchorError> {
        ensure_anchor_signer(self.scope, signer, trust)?;
        if checkpoint.len() != CHECKPOINT_LEN {
            return Err(AnchorError::InvalidReceipt);
        }
        let observed = custody_witness_w9::verify_checkpoint(
            checkpoint, self.scope.witness_id, trust,
        )?;
        if observed.witness_epoch != self.scope.witness_epoch {
            return Err(AnchorError::WrongScope);
        }
        if observed.sequence > MAX_SEQUENCE {
            return Err(AnchorError::MissingHistory);
        }
        let tx = self.db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let state: SavedState = tx.query_row(
            "SELECT checkpoint,receipt,frozen FROM anchor_state WHERE singleton=1",
            [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        if state.2 != 0 { return Err(AnchorError::Frozen); }
        let status = if let Some(prior) = state.0 {
            match custody_witness_w9::compare_checkpoints(
                &prior, checkpoint, self.scope.witness_id, trust,
            )? {
                ChainRelation::Same => {
                    return Ok((AnchorObservation::Unchanged,
                        state.1.ok_or(AnchorError::InvalidReceipt)?));
                }
                ChainRelation::Adjacent => AnchorObservation::Advanced,
                ChainRelation::MissingHistory => return Err(AnchorError::MissingHistory),
                ChainRelation::RollbackSuspected => return Err(AnchorError::Stale),
                ChainRelation::Equivocation => {
                    tx.execute(
                        "UPDATE anchor_state
                         SET frozen=1,fork_a=?1,fork_b=?2 WHERE singleton=1",
                        params![prior.as_slice(),checkpoint],
                    )?;
                    tx.commit()?;
                    return Err(AnchorError::Equivocation);
                }
            }
        } else {
            if observed.sequence != 1 || observed.previous_head != [0; 32] {
                return Err(AnchorError::MissingHistory);
            }
            AnchorObservation::First
        };
        let signed = sign_anchor(
            self.scope, checkpoint, observed.sequence, observed.head, signer,
        );
        tx.execute(
            "UPDATE anchor_state SET checkpoint=?1,receipt=?2 WHERE singleton=1",
            params![checkpoint, &signed],
        )?;
        tx.commit()?;
        Ok((status, signed))
    }

    pub fn frozen(&self) -> Result<bool, AnchorError> {
        let frozen: i64 = self.db.query_row(
            "SELECT frozen FROM anchor_state WHERE singleton=1",
            [], |r| r.get(0),
        )?;
        Ok(frozen != 0)
    }
    /// Current independently anchored tuple. Frozen anchor is unusable.
    pub fn latest(&self) -> Result<Option<(Vec<u8>, Vec<u8>)>, AnchorError> {
        if self.frozen()? { return Err(AnchorError::Frozen); }
        let saved: SavedState = self.db.query_row(
            "SELECT checkpoint,receipt,frozen FROM anchor_state WHERE singleton=1",
            [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        match (saved.0, saved.1) {
            (Some(cp), Some(receipt)) => Ok(Some((cp, receipt))),
            (None, None) => Ok(None),
            _ => Err(AnchorError::InvalidReceipt),
        }
    }
    /// Returns signed conflicting W9 statements for private, authorized audit.
    pub fn fork(&self) -> Result<Option<WitnessForkPair>, AnchorError> {
        let pair: StoredForkPair = self.db.query_row(
            "SELECT fork_a,fork_b FROM anchor_state WHERE singleton=1",
            [], |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        Ok(match pair {
            (Some(a), Some(b)) => Some((a, b)),
            _ => None,
        })
    }
}
