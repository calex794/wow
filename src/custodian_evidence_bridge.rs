//! WOW-CUSTODIAN-05 P0-2: explicit adapters to already verified W7/W8/W9/W10.
//!
//! The local observer has to establish transport identity/authorization before
//! using any adapter. In particular W7 verifies returned *bytes*, not who sent
//! them. No adapter verifies a physical operator, unbiased sampling, or actual
//! long-term retention. W8 signed PeerAccepted is a claim, never recipient W4.
//! Witness facts are private, not public sanctions or votes.
use crate::custodian_observation::{
    AppendResult, EvidenceLevel, EventKind, LocalObservationStore,
    ObservationError, ServiceEvent, ServiceRole, ServiceScope,
};
use crate::custody_audit_w7::AvailabilityObservation;
use crate::custody_transfer_w8::{self, TransferError};
use crate::custody_witness_w9::{self, ForkEvidence, WitnessError};
use crate::trust_w3::TrustRegistry;
use crate::witness_pin_w10::{PinError, WitnessPinStore};
use ed25519_dalek::SigningKey;

const W7_DOMAIN: &[u8] = b"WOW/Custodian/P02/W7/scoped-day-bucket/v0\0";
const W8_DOMAIN: &[u8] = b"WOW/Custodian/P02/W8/signed-ack/v0\0";
const W8_SLOT_DOMAIN: &[u8] = b"WOW/Custodian/P02/W8/issuer-slot/v0\0";
const W9_DOMAIN: &[u8] = b"WOW/Custodian/P02/W9/issuer-slot-fork/v0\0";
const W10_DOMAIN: &[u8] = b"WOW/Custodian/P02/W10/pinned-checkpoint/v0\0";
const DAY_MS: u64 = 86_400_000;

#[derive(Debug)]
pub enum BridgeError {
    Invalid,
    ScopeMismatch,
    Observation(ObservationError),
    Transfer(TransferError),
    Witness(WitnessError),
    Pin(PinError),
}
impl From<ObservationError> for BridgeError {
    fn from(value: ObservationError) -> Self { Self::Observation(value) }
}
impl From<TransferError> for BridgeError {
    fn from(value: TransferError) -> Self { Self::Transfer(value) }
}
impl From<WitnessError> for BridgeError {
    fn from(value: WitnessError) -> Self { Self::Witness(value) }
}
impl From<PinError> for BridgeError {
    fn from(value: PinError) -> Self { Self::Pin(value) }
}

/// Local binding of a service's pinned Ed25519 identity and role.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServiceIdentity {
    pub id: [u8; 16],
    pub epoch: u64,
    pub role: ServiceRole,
}

/// This context is created by the *local* authorized observer, never from
/// untrusted packet metadata. A pinned key in TrustRegistry identifies a
/// service; it does not by itself prove a current authenticated QUIC session.
/// The caller MUST verify that session separately for W7 observations.
pub struct LocalEvidenceContext<'a> {
    scope: ServiceScope,
    service_id: [u8; 16],
    observer: &'a SigningKey,
    seq: u64,
    session_nonce: [u8; 16],
    observed_at_ms: u64,
}
impl<'a> LocalEvidenceContext<'a> {
    pub fn bind(
        service: ServiceIdentity, observer: &'a SigningKey,
        event_seq: u64, session_nonce: [u8; 16],
        observed_at_ms: u64, trust: &TrustRegistry,
    ) -> Result<Self, BridgeError> {
        let ServiceIdentity { id: service_id, epoch, role } = service;
        if service_id == [0; 16] || epoch == 0 || epoch > i64::MAX as u64
            || event_seq == 0 || event_seq > i64::MAX as u64
            || session_nonce == [0; 16] || observed_at_ms == 0
            || observed_at_ms > i64::MAX as u64
        { return Err(BridgeError::Invalid); }
        let enrolled = trust.key_for(service_id, epoch)
            .map_err(|_| BridgeError::ScopeMismatch)?;
        Ok(Self {
            scope: ServiceScope { service_key: enrolled.to_bytes(), epoch, role },
            service_id, observer, seq: event_seq, session_nonce, observed_at_ms,
        })
    }

    pub fn scope(&self) -> ServiceScope { self.scope }

    pub(crate) fn observed_at_ms(&self) -> u64 { self.observed_at_ms }

    fn event(
        &self, kind: EventKind, level: EvidenceLevel,
        operation_alias: [u8; 16], lease_alias: [u8; 16],
        evidence: [u8; 32],
    ) -> ServiceEvent {
        ServiceEvent {
            scope: self.scope,
            observer_key: self.observer.verifying_key().to_bytes(),
            event_seq: self.seq,
            operation_alias,
            lease_alias,
            session_nonce: self.session_nonce,
            observed_at_ms: self.observed_at_ms,
            kind,
            evidence_level: level,
            evidence_digest: Some(evidence),
        }
    }
}

/// Each domain is bound to the service's actual pinned signing key and epoch.
/// Digests are kept in local SQLite only; never publish them in MapShard.
fn scoped_hash(domain: &[u8], scope: ServiceScope, content: &[u8]) -> [u8; 32] {
    let mut hash = blake3::Hasher::new();
    hash.update(domain);
    hash.update(&scope.service_key);
    hash.update(&scope.epoch.to_be_bytes());
    hash.update(&(scope.role as i64).to_be_bytes());
    hash.update(content);
    *hash.finalize().as_bytes()
}
fn alias(digest: [u8; 32]) -> [u8; 16] {
    let mut out = [0; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

impl LocalObservationStore {
    /// W7: count one exact-byte observation per ciphertext AND local day,
    /// regardless of how many claimed observers/identities replay it.
    ///
    /// The caller already obtained the W7 AvailabilityObservation by checking
    /// a trusted W3 reference against bytes returned by an authenticated C.
    /// This is local E1, *not* signed proof of disk retention or independence.
    pub fn record_w7_exact(
        &mut self, ctx: &LocalEvidenceContext<'_>,
        observed: &AvailabilityObservation,
    ) -> Result<AppendResult, BridgeError> {
        if observed.observed_at_ms() != ctx.observed_at_ms {
            return Err(BridgeError::Invalid);
        }
        let mut payload = Vec::with_capacity(40);
        payload.extend_from_slice(&observed.ciphertext_digest());
        payload.extend_from_slice(&(observed.observed_at_ms() / DAY_MS).to_be_bytes());
        let proof = scoped_hash(W7_DOMAIN, ctx.scope, &payload);
        let event = ctx.event(
            EventKind::AuditExactW3, EvidenceLevel::LocalObservation,
            alias(proof), [0; 16], proof,
        );
        Ok(self.record_verified(event, proof)?)
    }

    /// W8: require *both* independently verified Ed25519 signatures, exact
    /// offer_digest, target/epoch, slot, offer id and ciphertext digest.
    /// A signed acceptance establishes only that target claimed to accept.
    pub fn record_w8_acceptance(
        &mut self, ctx: &LocalEvidenceContext<'_>,
        offer: &[u8], acceptance: &[u8], trust: &TrustRegistry,
    ) -> Result<AppendResult, BridgeError> {
        let issued = custody_transfer_w8::verify_offer(offer, trust)?;
        let accepted = custody_transfer_w8::verify_acceptance(acceptance, trust)?;
        if accepted.target_id != ctx.service_id
            || accepted.target_epoch != ctx.scope.epoch
            || issued.target_id != accepted.target_id
            || issued.target_epoch != accepted.target_epoch
            || issued.source_id != accepted.source_id
            || issued.slot_alias != accepted.slot_alias
            || issued.offer_id != accepted.offer_id
            || issued.ciphertext_digest != accepted.ciphertext_digest
            || issued.expires_at_ms != accepted.expires_at_ms
            || accepted.offer_digest != *blake3::hash(offer).as_bytes()
        { return Err(BridgeError::ScopeMismatch); }
        let proof = scoped_hash(W8_DOMAIN, ctx.scope, acceptance);
        // One source-issued C-slot is one logical custody operation even if
        // a malicious issuer signs another offer_id for the same slot.
        let mut slot_binding = [0; 32];
        slot_binding[..16].copy_from_slice(&accepted.source_id);
        slot_binding[16..].copy_from_slice(&accepted.slot_alias);
        let slot_key = scoped_hash(W8_SLOT_DOMAIN, ctx.scope, &slot_binding);
        let event = ctx.event(
            EventKind::HandoffAccepted, EvidenceLevel::SignedExchange,
            alias(slot_key), accepted.slot_alias, proof,
        );
        Ok(self.record_verified(event, proof)?)
    }

    /// W9: independently verify both issuer offers and witness-signed
    /// checkpoints before recording an *incident against that exact issuer*.
    /// If the source is not the scoped service, do NOT penalize a target C.
    /// Incidents never enter storage/fetch success ratios or trigger sanctions.
    pub fn record_w9_issuer_fork(
        &mut self, ctx: &LocalEvidenceContext<'_>,
        evidence: &ForkEvidence, witness_id: [u8; 16],
        trust: &TrustRegistry,
    ) -> Result<AppendResult, BridgeError> {
        custody_witness_w9::verify_fork(evidence, witness_id, trust)?;
        let first = custody_transfer_w8::verify_offer(&evidence.first_offer, trust)?;
        let other = custody_transfer_w8::verify_offer(&evidence.conflicting_offer, trust)?;
        if first.source_id != ctx.service_id
            || first.source_epoch != ctx.scope.epoch
            || other.source_id != first.source_id
            || other.source_epoch != first.source_epoch
            || other.slot_alias != first.slot_alias
        { return Err(BridgeError::ScopeMismatch); }
        // A single issuer-slot conflict counts once even if many witnesses
        // replay evidence or the issuer signs a thousand conflicting offers.
        let proof = scoped_hash(W9_DOMAIN, ctx.scope, &first.slot_alias);
        let event = ctx.event(
            EventKind::CheckpointConflict, EvidenceLevel::SignedExchange,
            alias(proof), first.slot_alias, proof,
        );
        Ok(self.record_verified(event, proof)?)
    }

    /// W10: persist a locally pinned, authenticated witness head as an
    /// auxiliary monotonic diagnostic record. It is NEVER a quality success
    /// and cannot be converted to recipient W4 or proof of W3 storage.
    /// A frozen, missing or invalid pin fails closed without writing.
    pub fn record_w10_anchor(
        &mut self, ctx: &LocalEvidenceContext<'_>,
        pin: &WitnessPinStore, witness_id: [u8; 16],
        witness_epoch: u64, trust: &TrustRegistry,
    ) -> Result<AppendResult, BridgeError> {
        let seq = pin.inspect(trust)?.ok_or(BridgeError::Invalid)?;
        let bytes = pin.current()?.ok_or(BridgeError::Invalid)?;
        let verified = custody_witness_w9::verify_checkpoint(
            &bytes, witness_id, trust,
        )?;
        if verified.sequence != seq || verified.witness_epoch != witness_epoch {
            return Err(BridgeError::ScopeMismatch);
        }
        let digest = scoped_hash(W10_DOMAIN, ctx.scope, &bytes);
        Ok(self.store_witness_anchor(
            ctx.scope, witness_id, witness_epoch, seq, digest,
        )?)
    }
}
