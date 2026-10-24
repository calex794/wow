//! WOW-CUSTODIAN-05 P0-3: local, read-only recommendation laboratory.
//!
//! Never issues a STORE/FETCH grant, chooses/consumes a K3 slot, updates a
//! multipath plan, creates a W4 receipt, suspends a service, or deletes mail.
//! Claims about invitation/consent, operating capacity, availability, current
//! authenticated transport and failure domains MUST be checked by the caller.
//! This module checks the pinned Ed25519 service identity in TrustRegistry
//! and reads only the P0-2 verified_event index; raw reported E4 is ignored.
//!
//! W7 records are local exact-byte E1 observations, *not* proof of custodial
//! independence or continuous disk storage. W8 PeerAccepted is a signed CLAIM,
//! not proof of storage nor of final recipient delivery. Numerical thresholds
//! below are laboratory policy knobs, NOT approved product thresholds.
use crate::custodian_observation::{
    Counters, LocalObservationStore, ObservationError, ServiceRole, ServiceScope,
};
use crate::trust_w3::TrustRegistry;
use std::cmp::Ordering;

const MIN_REPEATED_SAMPLES: u64 = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PermissionAssertion {
    /// Caller already checked the exact scoped rights and requested operation.
    /// This flag is NOT an alternative to cryptographic authorization.
    CallerVerified,
    Unchecked,
    Denied,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DomainHint {
    Unknown,
    /// Operator-supplied label; never evidence of independent operators.
    Claimed([u8; 16]),
    /// Caller has independently checked the *failure domain* out of band.
    /// Still not a Byzantine guarantee and not a K3 allocation proof.
    IndependentlyChecked([u8; 16]),
}
#[derive(Clone, Copy, Debug)]
pub struct Candidate {
    pub service_id: [u8; 16],
    pub service_epoch: u64,
    pub role: ServiceRole,
    pub permission: PermissionAssertion,
    pub recipient_has_private_route: bool,
    pub advertisement_expires_at_ms: u64,
    pub reachable_now: bool,
    pub available_bytes: u64,
    pub pending_new_stores: u32,
    pub max_new_stores: u32,
    pub failure_domain: DomainHint,
}
#[derive(Clone, Copy, Debug)]
pub struct StoreIntent {
    pub now_ms: u64,
    pub packet_bytes: usize,
    pub role: ServiceRole,
    pub max_suggestions: usize,
    pub critical: bool,
    /// READ-ONLY status from the independent, persistent K3 ledger.
    /// No timeout or reputation result may free an occupied slot.
    pub k3_issued_slots: u8,
    pub k3_slot_limit: u8,
    pub unresolved_handoff: bool,
    /// Explicit consent for a limited, NONSENSITIVE new-store probe. A
    /// probation recommendation is never permission to transmit data.
    pub allow_probation: bool,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GateReason {
    UntrustedOrRevokedKey,
    WrongRole,
    PermissionNotVerified,
    NoRecipientRoute,
    ExpiredAdvertisement,
    TemporarilyUnreachable,
    InsufficientCapacity,
    NewStoreQuotaExhausted,
    IncidentNeedsIndependentReview,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceClass {
    NoEvidence,
    LimitedLocalObservation,
    RepeatedLocalObservation,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdvisoryTier {
    /// No observation or insufficient independent history. Does not imply bad.
    Probation,
    /// Repeat observed across separate time windows. Still only W7 E1.
    LocallyObserved,
}
#[derive(Clone, Copy, Debug)]
pub struct Quality {
    pub evidence: EvidenceClass,
    pub recent_storage: Counters,
    pub older_storage: Counters,
    /// One-sided 95% Wilson bound on the *last seven days* of exact-byte W7
    /// checks. It cannot prove future retention, independent processes or W4.
    pub storage_wilson_last_7d: Option<f64>,
    pub signed_handoff_claims_last_7d: u64,
    pub verified_fetch_observations_last_7d: u64,
    pub issuer_slot_conflicts_last_30d: u64,
}
#[derive(Clone, Copy, Debug)]
pub struct Assessment {
    pub service_id: [u8; 16],
    pub service_epoch: u64,
    pub gate: Result<(), GateReason>,
    pub tier: AdvisoryTier,
    pub quality: Option<Quality>,
    pub failure_domain: DomainHint,
    /// The laboratory ceiling for NEW proposals only, never a STORE grant.
    /// Not a globally enforced quota: the actual scheduler must revalidate.
    pub suggested_new_store_ceiling: u32,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdvisoryLimit {
    None,
    InsufficientIndependentFailureDomains,
    AllK3SlotsAlreadyIssued,
    AmbiguousExistingHandoff,
}
#[derive(Debug)]
pub struct AdvisoryReport {
    /// Every candidate remains visible with an explanation; nothing is banned.
    pub assessments: Vec<Assessment>,
    /// Positions in assessments, highest preference first. NOT assignments.
    pub suggestion_indices: Vec<usize>,
    pub limit: AdvisoryLimit,
}
#[derive(Debug)]
pub enum AdvisoryError {
    InvalidIntent,
    Observation(ObservationError),
}
impl From<ObservationError> for AdvisoryError {
    fn from(value: ObservationError) -> Self { Self::Observation(value) }
}

fn eligibility(c: &Candidate, intent: &StoreIntent, trust: &TrustRegistry)
    -> Result<ServiceScope, GateReason>
{
    if c.service_id == [0; 16] || c.service_epoch == 0
        || trust.key_for(c.service_id, c.service_epoch).is_err()
    { return Err(GateReason::UntrustedOrRevokedKey); }
    if c.role != intent.role { return Err(GateReason::WrongRole); }
    if c.permission != PermissionAssertion::CallerVerified {
        return Err(GateReason::PermissionNotVerified);
    }
    if !c.recipient_has_private_route { return Err(GateReason::NoRecipientRoute); }
    if c.advertisement_expires_at_ms <= intent.now_ms {
        return Err(GateReason::ExpiredAdvertisement);
    }
    if !c.reachable_now { return Err(GateReason::TemporarilyUnreachable); }
    if c.available_bytes < intent.packet_bytes as u64 {
        return Err(GateReason::InsufficientCapacity);
    }
    if c.max_new_stores == 0 || c.pending_new_stores >= c.max_new_stores {
        return Err(GateReason::NewStoreQuotaExhausted);
    }
    let key = trust.key_for(c.service_id, c.service_epoch)
        .map_err(|_| GateReason::UntrustedOrRevokedKey)?;
    Ok(ServiceScope {
        service_key: key.to_bytes(),
        epoch: c.service_epoch,
        role: c.role,
    })
}
fn quality(recent: Counters, older: Counters, claims: u64, fetch: u64, incidents: u64)
    -> Quality
{
    let last_week = Counters {
        successes: recent.successes.saturating_add(older.successes),
        eligible: recent.eligible.saturating_add(older.eligible),
        failures: recent.failures.saturating_add(older.failures),
        unknown: recent.unknown.saturating_add(older.unknown),
    };
    let evidence = if last_week.eligible == 0 {
        EvidenceClass::NoEvidence
    } else if recent.eligible > 0 && older.eligible > 0
        && last_week.eligible >= MIN_REPEATED_SAMPLES
    {
        EvidenceClass::RepeatedLocalObservation
    } else {
        EvidenceClass::LimitedLocalObservation
    };
    Quality {
        evidence, recent_storage: recent, older_storage: older,
        storage_wilson_last_7d: last_week.wilson_lower_bound(),
        signed_handoff_claims_last_7d: claims,
        verified_fetch_observations_last_7d: fetch,
        issuer_slot_conflicts_last_30d: incidents,
    }
}
fn prefer(a: &Assessment, b: &Assessment) -> Ordering {
    // Never consider W8 signature volume to be proof of physical retention;
    // never turn "NoEvidence" into a zero trust/safety score.
    let pa = u8::from(a.tier == AdvisoryTier::LocallyObserved);
    let pb = u8::from(b.tier == AdvisoryTier::LocallyObserved);
    pb.cmp(&pa)
        .then_with(|| {
            let score_a = a.quality.and_then(|q| q.storage_wilson_last_7d);
            let score_b = b.quality.and_then(|q| q.storage_wilson_last_7d);
            match (score_a, score_b) {
                (Some(a), Some(b)) => b.total_cmp(&a),
                // Missing evidence remains probation, not zero quality.
                _ => Ordering::Equal,
            }
        })
        .then_with(|| a.service_id.cmp(&b.service_id))
}

/// Build *suggestions* only, not actual placement. Every candidate's privacy-
/// protected report is fetched by this method from the verified SQLite index,
/// not from arbitrary caller-provided score/counter values.
pub fn recommend(
    store: &LocalObservationStore, trust: &TrustRegistry,
    intent: StoreIntent, candidates: &[Candidate],
) -> Result<AdvisoryReport, AdvisoryError> {
    if intent.now_ms == 0 || intent.now_ms > i64::MAX as u64
        || intent.packet_bytes == 0 || intent.packet_bytes > crate::MAX_MESSAGE_BYTES
        || intent.max_suggestions == 0 || intent.max_suggestions > 4
        || intent.k3_slot_limit == 0 || intent.k3_slot_limit > 4
        || intent.k3_issued_slots > intent.k3_slot_limit
    { return Err(AdvisoryError::InvalidIntent); }
    let mut assessments = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        let (gate, quality) = match eligibility(candidate, &intent, trust) {
            Err(reason) => (Err(reason), None),
            Ok(scope) => {
                let report = store.verified_report(scope, intent.now_ms)?;
                let recent = report.last_24h;
                let older = report.days_2_to_7;
                let incidents = recent.checkpoint_conflicts
                    .saturating_add(older.checkpoint_conflicts)
                    .saturating_add(report.days_8_to_30.checkpoint_conflicts);
                let q = quality(
                    recent.storage, older.storage,
                    recent.handoff.successes.saturating_add(older.handoff.successes),
                    recent.authorized_fetch.eligible
                        .saturating_add(older.authorized_fetch.eligible),
                    incidents,
                );
                // Cryptographically conflicting issuer offers require manual
                // review of NEW assignments only, never deletion of W3 or
                // revocation of valid prior FETCH/HANDOFF rights.
                let gate = if incidents > 0 {
                    Err(GateReason::IncidentNeedsIndependentReview)
                } else {
                    Ok(())
                };
                (gate, Some(q))
            }
        };
        let tier = if matches!(quality, Some(Quality {
            evidence: EvidenceClass::RepeatedLocalObservation, ..
        })) {
            AdvisoryTier::LocallyObserved
        } else {
            AdvisoryTier::Probation
        };
        let ceiling = match tier {
            AdvisoryTier::Probation => 1,
            AdvisoryTier::LocallyObserved => 8,
        };
        assessments.push(Assessment {
            service_id: candidate.service_id,
            service_epoch: candidate.service_epoch,
            gate, tier, quality, failure_domain: candidate.failure_domain,
            suggested_new_store_ceiling: ceiling.min(candidate.max_new_stores),
        });
    }

    // Existing K3 allocations/ambiguous transfers are immutable here. Even
    // all-failed custodians cannot free one slot or make a second copy.
    let limit = if intent.unresolved_handoff {
        AdvisoryLimit::AmbiguousExistingHandoff
    } else if intent.k3_issued_slots >= intent.k3_slot_limit {
        AdvisoryLimit::AllK3SlotsAlreadyIssued
    } else {
        AdvisoryLimit::None
    };
    let mut indices: Vec<usize> = (0..assessments.len())
        .filter(|&i| assessments[i].gate.is_ok()
            && (intent.allow_probation
                || assessments[i].tier == AdvisoryTier::LocallyObserved))
        .collect();
    indices.sort_by(|&a, &b| prefer(&assessments[a], &assessments[b]));
    let slots = (intent.k3_slot_limit - intent.k3_issued_slots) as usize;
    let cap = slots.min(intent.max_suggestions);
    let mut suggestions = Vec::with_capacity(cap);
    let mut checked_domains = Vec::new();
    if limit == AdvisoryLimit::None {
        for i in indices {
            if suggestions.len() == cap { break; }
            if intent.critical {
                let DomainHint::IndependentlyChecked(domain) =
                    assessments[i].failure_domain else {
                    continue;
                };
                if domain == [0; 16] || checked_domains.contains(&domain) {
                    continue;
                }
                checked_domains.push(domain);
            }
            suggestions.push(i);
        }
    }
    let limit = if limit == AdvisoryLimit::None && intent.critical
        && suggestions.len() < 2
    {
        // Fewer than two independently checked domains does not establish a
        // resilient critical path. Return no suggested assignments at all.
        suggestions.clear();
        AdvisoryLimit::InsufficientIndependentFailureDomains
    } else {
        limit
    };
    Ok(AdvisoryReport {
        assessments, suggestion_indices: suggestions, limit,
    })
}
