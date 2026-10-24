//! WOW-CUSTODIAN-05 P0: private, LOCAL-ONLY observations of mail custodians.
//!
//! This is a bounded experiment, NOT a public reputation system, safety gate,
//! proof verifier or authority to revoke storage rights. No observation grants
//! STORE/FETCH/HANDOFF access, issues W4, moves a K3 slot, or removes old mail.
//! Event evidence must be verified by an already authorized caller; declaring
//! E2/E3 here does NOT authenticate a peer or prove physical independence.
//! The caller supplies an honest local time bound; uncertain time must not be
//! passed off as a trusted UTC measurement. Use a separate private database,
//! never a user's Vault or a public MapShard.
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use std::path::Path;
use std::time::Duration;

const MAX_EVENTS: i64 = 16_384;
const DAY_MS: u64 = 86_400_000;
const WEEK_MS: u64 = 7 * DAY_MS;
const MONTH_MS: u64 = 30 * DAY_MS;
const DOMAIN: &[u8] = b"Akula/WOW/LocalCustodianServiceEvent/v0\0";

#[derive(Debug)]
pub enum ObservationError {
    Database(rusqlite::Error),
    Invalid,
    UnverifiedClaim,
    Conflict,
    Exhausted,
    ClockUncertain,
    Corrupt,
}
impl From<rusqlite::Error> for ObservationError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Database(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i64)]
pub enum ServiceRole {
    Personal = 1,
    Community = 2,
    Public = 3,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServiceScope {
    pub service_key: [u8; 32],
    pub epoch: u64,
    pub role: ServiceRole,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(i64)]
pub enum EvidenceLevel {
    Claimed = 0,
    LocalObservation = 1,
    SignedExchange = 2,
    IndependentAudit = 3,
    RepeatedIndependentAudit = 4,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i64)]
pub enum EventKind {
    StoreClaimed = 1,
    AuditExactW3 = 2,
    AuditBadBytes = 3,
    AuditUnreachable = 4,
    FetchExactW3 = 5,
    FetchBadBytes = 6,
    FetchRefusedValid = 7,
    FetchDeniedCorrectly = 8,
    FetchTimeout = 9,
    HandoffAccepted = 10,
    HandoffAmbiguous = 11,
    RecipientW4Observed = 12,
    CheckpointConflict = 13,
    UnattributedFailure = 14,
    ServiceReached = 15,
    ServiceMissedInPromisedWindow = 16,
    HandoffRefusedValid = 17,
}
impl EventKind {
    fn from_db(value: i64) -> Result<Self, ObservationError> {
        use EventKind::*;
        match value {
            1 => Ok(StoreClaimed),
            2 => Ok(AuditExactW3),
            3 => Ok(AuditBadBytes),
            4 => Ok(AuditUnreachable),
            5 => Ok(FetchExactW3),
            6 => Ok(FetchBadBytes),
            7 => Ok(FetchRefusedValid),
            8 => Ok(FetchDeniedCorrectly),
            9 => Ok(FetchTimeout),
            10 => Ok(HandoffAccepted),
            11 => Ok(HandoffAmbiguous),
            12 => Ok(RecipientW4Observed),
            13 => Ok(CheckpointConflict),
            14 => Ok(UnattributedFailure),
            15 => Ok(ServiceReached),
            16 => Ok(ServiceMissedInPromisedWindow),
            17 => Ok(HandoffRefusedValid),
            _ => Err(ObservationError::Corrupt),
        }
    }
    fn minimum_evidence(self) -> EvidenceLevel {
        use EventKind::*;
        match self {
            StoreClaimed | FetchTimeout | FetchDeniedCorrectly |
            HandoffAmbiguous | UnattributedFailure | AuditUnreachable => EvidenceLevel::Claimed,
            AuditBadBytes | FetchBadBytes | FetchRefusedValid |
            HandoffRefusedValid | CheckpointConflict | RecipientW4Observed |
            ServiceMissedInPromisedWindow => EvidenceLevel::SignedExchange,
            _ => EvidenceLevel::LocalObservation,
        }
    }
}

/// Aliases are private, per-operation pseudonyms, NOT W3 message IDs, global
/// mailbox tags, or ciphertext digests. No raw peer grant or W3 is recorded.
/// evidence_digest is a digest of a separately checked, scoped proof, never
/// the bare W3 digest. This type does not validate the proof's signature.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServiceEvent {
    pub scope: ServiceScope,
    pub observer_key: [u8; 32],
    pub event_seq: u64,
    pub operation_alias: [u8; 16],
    pub lease_alias: [u8; 16],
    pub session_nonce: [u8; 16],
    pub observed_at_ms: u64,
    pub kind: EventKind,
    pub evidence_level: EvidenceLevel,
    pub evidence_digest: Option<[u8; 32]>,
}
impl ServiceEvent {
    fn validate(&self) -> Result<(), ObservationError> {
        if self.scope.service_key == [0; 32] || self.observer_key == [0; 32]
            || self.operation_alias == [0; 16]
            || self.scope.epoch == 0 || self.scope.epoch > i64::MAX as u64
            || self.event_seq == 0 || self.event_seq > i64::MAX as u64
            || self.observed_at_ms == 0 || self.observed_at_ms > i64::MAX as u64
            || self.evidence_digest == Some([0; 32])
        {
            return Err(ObservationError::Invalid);
        }
        if self.evidence_level < self.kind.minimum_evidence()
            || (self.evidence_level >= EvidenceLevel::SignedExchange
                && self.evidence_digest.is_none())
        {
            return Err(ObservationError::UnverifiedClaim);
        }
        Ok(())
    }
    fn commitment(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(DOMAIN);
        h.update(&self.scope.service_key);
        h.update(&self.scope.epoch.to_be_bytes());
        h.update(&(self.scope.role as i64).to_be_bytes());
        h.update(&self.observer_key);
        h.update(&self.event_seq.to_be_bytes());
        h.update(&self.operation_alias);
        h.update(&self.lease_alias);
        h.update(&self.session_nonce);
        h.update(&self.observed_at_ms.to_be_bytes());
        h.update(&(self.kind as i64).to_be_bytes());
        h.update(&(self.evidence_level as i64).to_be_bytes());
        h.update(&[u8::from(self.evidence_digest.is_some())]);
        if let Some(e) = self.evidence_digest {
            h.update(&e);
        }
        *h.finalize().as_bytes()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AppendResult { Stored, ExactReplay }

/// Counts for eligible observations only; unknown results are never failures.
/// Wilson lower bound is advisory and does not determine safety decisions.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Counters {
    pub successes: u64,
    pub eligible: u64,
    pub failures: u64,
    pub unknown: u64,
}
impl Counters {
    pub fn wilson_lower_bound(&self) -> Option<f64> {
        if self.eligible == 0 { return None; }
        let n = self.eligible as f64;
        let p = self.successes as f64 / n;
        let z = 1.96_f64;
        let z2 = z * z;
        Some(((p + z2 / (2.0 * n)
            - z * (p * (1.0 - p) / n + z2 / (4.0 * n * n)).sqrt())
            / (1.0 + z2 / n)).clamp(0.0, 1.0))
    }
    fn success(&mut self) { self.successes += 1; self.eligible += 1; }
    fn failure(&mut self) { self.failures += 1; self.eligible += 1; }
    fn unknown(&mut self) { self.unknown += 1; }
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WindowCounters {
    pub availability: Counters,
    pub storage: Counters,
    pub authorized_fetch: Counters,
    pub handoff: Counters,
    pub store_claims: u64,
    pub correctly_denied: u64,
    pub recipient_w4_observations: u64,
    pub checkpoint_conflicts: u64,
    pub unattributed_failures: u64,
}
impl WindowCounters {
    fn add(&mut self, kind: EventKind) {
        use EventKind::*;
        match kind {
            StoreClaimed => self.store_claims += 1,
            AuditExactW3 => self.storage.success(),
            AuditBadBytes => self.storage.failure(),
            AuditUnreachable => self.storage.unknown(),
            FetchExactW3 => self.authorized_fetch.success(),
            FetchBadBytes | FetchRefusedValid => self.authorized_fetch.failure(),
            FetchDeniedCorrectly => self.correctly_denied += 1,
            FetchTimeout => self.authorized_fetch.unknown(),
            HandoffAccepted => self.handoff.success(),
            HandoffRefusedValid => self.handoff.failure(),
            HandoffAmbiguous => self.handoff.unknown(),
            RecipientW4Observed => self.recipient_w4_observations += 1,
            CheckpointConflict => self.checkpoint_conflicts += 1,
            UnattributedFailure => self.unattributed_failures += 1,
            ServiceReached => self.availability.success(),
            ServiceMissedInPromisedWindow => self.availability.failure(),
        }
    }
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ServiceReport {
    pub last_24h: WindowCounters,
    pub days_2_to_7: WindowCounters,
    pub days_8_to_30: WindowCounters,
}

pub struct LocalObservationStore { db: Connection }
impl LocalObservationStore {
    pub fn open(path: &Path) -> Result<Self, ObservationError> {
        let db = Connection::open(path)?;
        db.busy_timeout(Duration::from_secs(5))?;
        db.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
             CREATE TABLE IF NOT EXISTS custodian_service_event_v0(
                service_key BLOB NOT NULL CHECK(length(service_key)=32),
                service_epoch INTEGER NOT NULL CHECK(service_epoch>0),
                role INTEGER NOT NULL CHECK(role BETWEEN 1 AND 3),
                observer_key BLOB NOT NULL CHECK(length(observer_key)=32),
                event_seq INTEGER NOT NULL CHECK(event_seq>0),
                operation_alias BLOB NOT NULL CHECK(length(operation_alias)=16),
                lease_alias BLOB NOT NULL CHECK(length(lease_alias)=16),
                session_nonce BLOB NOT NULL CHECK(length(session_nonce)=16),
                observed_at_ms INTEGER NOT NULL CHECK(observed_at_ms>0),
                kind INTEGER NOT NULL CHECK(kind BETWEEN 1 AND 17),
                evidence_level INTEGER NOT NULL CHECK(evidence_level BETWEEN 0 AND 4),
                evidence_digest BLOB CHECK(evidence_digest IS NULL OR length(evidence_digest)=32),
                event_hash BLOB NOT NULL CHECK(length(event_hash)=32),
                PRIMARY KEY(service_key,service_epoch,role,observer_key,event_seq),
                UNIQUE(service_key,service_epoch,role,observer_key,operation_alias,kind)
             );
             CREATE INDEX IF NOT EXISTS custodian_service_event_v0_window
             ON custodian_service_event_v0(service_key,service_epoch,role,observed_at_ms);
             -- Only verified bridge events enter the trusted metrics. Proofs
             -- and operations are deduplicated across all observer aliases.
             CREATE TABLE IF NOT EXISTS custodian_verified_event_v0(
                service_key BLOB NOT NULL CHECK(length(service_key)=32),
                service_epoch INTEGER NOT NULL CHECK(service_epoch>0),
                role INTEGER NOT NULL CHECK(role BETWEEN 1 AND 3),
                kind INTEGER NOT NULL CHECK(kind BETWEEN 1 AND 17),
                proof_key BLOB NOT NULL CHECK(length(proof_key)=32),
                operation_alias BLOB NOT NULL CHECK(length(operation_alias)=16),
                observed_at_ms INTEGER NOT NULL CHECK(observed_at_ms>0),
                PRIMARY KEY(service_key,service_epoch,role,kind,proof_key),
                UNIQUE(service_key,service_epoch,role,kind,operation_alias)
             );
             CREATE INDEX IF NOT EXISTS custodian_verified_event_v0_window
             ON custodian_verified_event_v0(service_key,service_epoch,role,observed_at_ms);
             -- W10 is a separately verified chain anchor, never a metric of
             -- custodian storage, fetch success, or recipient W4 delivery.
             CREATE TABLE IF NOT EXISTS custodian_w10_anchor_v0(
                service_key BLOB NOT NULL CHECK(length(service_key)=32),
                service_epoch INTEGER NOT NULL CHECK(service_epoch>0),
                role INTEGER NOT NULL CHECK(role BETWEEN 1 AND 3),
                witness_id BLOB NOT NULL CHECK(length(witness_id)=16),
                witness_epoch INTEGER NOT NULL CHECK(witness_epoch>0),
                sequence INTEGER NOT NULL CHECK(sequence>0),
                checkpoint_digest BLOB NOT NULL CHECK(length(checkpoint_digest)=32),
                PRIMARY KEY(service_key,service_epoch,role,witness_id,witness_epoch)
             );"
        )?;
        Ok(Self { db })
    }

    /// Durable and idempotent local append. The journal never silently deletes
    /// incident evidence. This is not a public remotely writable API.
    pub fn record(&mut self, event: ServiceEvent) -> Result<AppendResult, ObservationError> {
        self.record_inner(event, None)
    }

    /// Privileged local ingestion from the cryptographic W7/W8/W9 bridge.
    /// A public raw record() can NEVER retroactively become a verified event.
    pub(crate) fn record_verified(
        &mut self, event: ServiceEvent, proof_key: [u8; 32],
    ) -> Result<AppendResult, ObservationError> {
        if proof_key == [0; 32] { return Err(ObservationError::Invalid); }
        self.record_inner(event, Some(proof_key))
    }

    fn record_inner(
        &mut self, event: ServiceEvent, proof_key: Option<[u8; 32]>,
    ) -> Result<AppendResult, ObservationError> {
        event.validate()?;
        let hash = event.commitment();
        let role = event.scope.role as i64;
        let epoch = event.scope.epoch as i64;
        let seq = event.event_seq as i64;
        let tx = self.db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(proof) = proof_key {
            // The exact signed proof or W7 daily-bucket commitment may be
            // presented by 100 different claimed observers; count it once.
            let exists: Option<i64> = tx.query_row(
                "SELECT 1 FROM custodian_verified_event_v0
                 WHERE service_key=?1 AND service_epoch=?2 AND role=?3
                   AND kind=?4 AND proof_key=?5",
                params![event.scope.service_key.as_slice(), epoch, role,
                        event.kind as i64, proof.as_slice()],
                |row| row.get(0),
            ).optional()?;
            if exists.is_some() { return Ok(AppendResult::ExactReplay); }
            let same_operation: Option<i64> = tx.query_row(
                "SELECT 1 FROM custodian_verified_event_v0
                 WHERE service_key=?1 AND service_epoch=?2 AND role=?3
                   AND kind=?4 AND operation_alias=?5",
                params![event.scope.service_key.as_slice(), epoch, role,
                        event.kind as i64, event.operation_alias.as_slice()],
                |row| row.get(0),
            ).optional()?;
            if same_operation.is_some() { return Err(ObservationError::Conflict); }
        }
        let prior: Option<Vec<u8>> = tx.query_row(
            "SELECT event_hash FROM custodian_service_event_v0
             WHERE service_key=?1 AND service_epoch=?2 AND role=?3
               AND observer_key=?4 AND event_seq=?5",
            params![event.scope.service_key.as_slice(), epoch, role,
                    event.observer_key.as_slice(), seq],
            |row| row.get(0),
        ).optional()?;
        if let Some(existing) = prior {
            // A raw claim must never be upgraded to verified retrospectively.
            return if proof_key.is_none() && existing.as_slice() == hash.as_slice() {
                Ok(AppendResult::ExactReplay)
            } else {
                Err(ObservationError::Conflict)
            };
        }
        let duplicate_operation: Option<i64> = tx.query_row(
            "SELECT event_seq FROM custodian_service_event_v0
             WHERE service_key=?1 AND service_epoch=?2 AND role=?3
               AND observer_key=?4 AND operation_alias=?5 AND kind=?6",
            params![event.scope.service_key.as_slice(), epoch, role,
                    event.observer_key.as_slice(), event.operation_alias.as_slice(),
                    event.kind as i64],
            |row| row.get(0),
        ).optional()?;
        if duplicate_operation.is_some() { return Err(ObservationError::Conflict); }
        let count: i64 = tx.query_row(
            "SELECT COUNT(*) FROM custodian_service_event_v0", [], |row| row.get(0)
        )?;
        if count >= MAX_EVENTS { return Err(ObservationError::Exhausted); }
        tx.execute(
            "INSERT INTO custodian_service_event_v0
             (service_key,service_epoch,role,observer_key,event_seq,operation_alias,
              lease_alias,session_nonce,observed_at_ms,kind,evidence_level,
              evidence_digest,event_hash)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
            params![event.scope.service_key.as_slice(), epoch, role,
                    event.observer_key.as_slice(), seq,
                    event.operation_alias.as_slice(), event.lease_alias.as_slice(),
                    event.session_nonce.as_slice(), event.observed_at_ms as i64,
                    event.kind as i64, event.evidence_level as i64,
                    event.evidence_digest.as_ref().map(|d| d.as_slice()),
                    hash.as_slice()],
        )?;
        if let Some(proof) = proof_key {
            tx.execute(
                "INSERT INTO custodian_verified_event_v0
                 (service_key,service_epoch,role,kind,proof_key,
                  operation_alias,observed_at_ms)
                 VALUES(?1,?2,?3,?4,?5,?6,?7)",
                params![event.scope.service_key.as_slice(), epoch, role,
                        event.kind as i64, proof.as_slice(),
                        event.operation_alias.as_slice(), event.observed_at_ms as i64],
            )?;
        }
        tx.commit()?;
        Ok(AppendResult::Stored)
    }

    /// Local observation windows, not globally agreed UTC or uptime.
    /// Fail closed if the caller's clock appears to have moved backward.
    /// The legacy/raw lab tally, including caller-claimed evidence. Never use
    /// this report alone to rank untrusted custodians or issue rights.
    pub fn report(&self, scope: ServiceScope, now_ms: u64)
        -> Result<ServiceReport, ObservationError>
    {
        self.aggregate(scope, now_ms, false)
    }

    /// Only events accepted by the verifying W7/W8/W9 bridge are counted.
    /// These are still local observations/claims, NOT a global reputation or
    /// proof of independent fault domains, uptime, or future W3 retention.
    pub fn verified_report(&self, scope: ServiceScope, now_ms: u64)
        -> Result<ServiceReport, ObservationError>
    {
        self.aggregate(scope, now_ms, true)
    }

    fn aggregate(&self, scope: ServiceScope, now_ms: u64, verified: bool)
        -> Result<ServiceReport, ObservationError>
    {
        if scope.service_key == [0; 32] || scope.epoch == 0
            || scope.epoch > i64::MAX as u64 || now_ms == 0
            || now_ms > i64::MAX as u64
        { return Err(ObservationError::Invalid); }
        let sql = if verified {
            "SELECT kind,observed_at_ms FROM custodian_verified_event_v0
             WHERE service_key=?1 AND service_epoch=?2 AND role=?3
             ORDER BY observed_at_ms"
        } else {
            "SELECT kind,observed_at_ms FROM custodian_service_event_v0
             WHERE service_key=?1 AND service_epoch=?2 AND role=?3
             ORDER BY observed_at_ms"
        };
        let mut stmt = self.db.prepare(sql)?;
        let mut rows = stmt.query(params![
            scope.service_key.as_slice(), scope.epoch as i64, scope.role as i64
        ])?;
        let mut report = ServiceReport::default();
        while let Some(row) = rows.next()? {
            let kind = EventKind::from_db(row.get(0)?)?;
            let observed: i64 = row.get(1)?;
            if observed <= 0 { return Err(ObservationError::Corrupt); }
            let observed = observed as u64;
            if observed > now_ms { return Err(ObservationError::ClockUncertain); }
            let age = now_ms - observed;
            if age < DAY_MS {
                report.last_24h.add(kind);
            } else if age < WEEK_MS {
                report.days_2_to_7.add(kind);
            } else if age < MONTH_MS {
                report.days_8_to_30.add(kind);
            }
        }
        Ok(report)
    }

    /// Remember a W10-verified private pin, without converting a witness
    /// checkpoint into evidence of custodian availability/delivery.
    pub(crate) fn store_witness_anchor(
        &mut self, scope: ServiceScope, witness_id: [u8; 16],
        witness_epoch: u64, sequence: u64, checkpoint_digest: [u8; 32],
    ) -> Result<AppendResult, ObservationError> {
        if scope.service_key == [0; 32] || scope.epoch == 0
            || scope.epoch > i64::MAX as u64 || witness_id == [0; 16]
            || witness_epoch == 0 || witness_epoch > i64::MAX as u64
            || sequence == 0 || sequence > i64::MAX as u64
            || checkpoint_digest == [0; 32]
        { return Err(ObservationError::Invalid); }
        let tx = self.db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let previous: Option<(i64, Vec<u8>)> = tx.query_row(
            "SELECT sequence,checkpoint_digest FROM custodian_w10_anchor_v0
             WHERE service_key=?1 AND service_epoch=?2 AND role=?3
               AND witness_id=?4 AND witness_epoch=?5",
            params![scope.service_key.as_slice(), scope.epoch as i64, scope.role as i64,
                    witness_id.as_slice(), witness_epoch as i64],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).optional()?;
        if let Some((old_seq, old_digest)) = previous {
            if sequence < old_seq as u64 { return Err(ObservationError::Conflict); }
            if sequence == old_seq as u64 {
                return if old_digest.as_slice() == checkpoint_digest.as_slice() {
                    Ok(AppendResult::ExactReplay)
                } else {
                    Err(ObservationError::Conflict)
                };
            }
            tx.execute(
                "UPDATE custodian_w10_anchor_v0 SET sequence=?6,checkpoint_digest=?7
                 WHERE service_key=?1 AND service_epoch=?2 AND role=?3
                   AND witness_id=?4 AND witness_epoch=?5",
                params![scope.service_key.as_slice(), scope.epoch as i64, scope.role as i64,
                        witness_id.as_slice(), witness_epoch as i64,
                        sequence as i64, checkpoint_digest.as_slice()],
            )?;
        } else {
            tx.execute(
                "INSERT INTO custodian_w10_anchor_v0
                 (service_key,service_epoch,role,witness_id,witness_epoch,sequence,checkpoint_digest)
                 VALUES(?1,?2,?3,?4,?5,?6,?7)",
                params![scope.service_key.as_slice(), scope.epoch as i64, scope.role as i64,
                        witness_id.as_slice(), witness_epoch as i64,
                        sequence as i64, checkpoint_digest.as_slice()],
            )?;
        }
        tx.commit()?;
        Ok(AppendResult::Stored)
    }
}
