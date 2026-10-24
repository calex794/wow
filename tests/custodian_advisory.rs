//! WOW-CUSTODIAN-05 P0-3: proposals never allocate K3, block old custody,
//! or infer independent operators from a label or a signed PeerAccepted.
use akula_wire_lab::custodian_advisory::{
    recommend, AdvisoryLimit, AdvisoryTier, Candidate, DomainHint,
    EvidenceClass, GateReason, PermissionAssertion, StoreIntent,
};
use akula_wire_lab::custodian_evidence_bridge::{
    LocalEvidenceContext, ServiceIdentity,
};
use akula_wire_lab::custodian_observation::{
    LocalObservationStore, ServiceRole,
};
use akula_wire_lab::custody_audit_w7::AuditReference;
use akula_wire_lab::custody_transfer_w8::{
    self, OfferClaims, PeerConsent, PeerCustodyStore,
};
use akula_wire_lab::custody_witness_w9::{WitnessObservation, WitnessStore};
use akula_wire_lab::crypto_identity_w3::SignedHeader;
use akula_wire_lab::crypto_w3::new_recipient;
use akula_wire_lab::private_route_w3;
use akula_wire_lab::trust_w3::TrustRegistry;
use ed25519_dalek::SigningKey;
use tempfile::tempdir;

const DAY: u64 = 86_400_000;
const NOW: u64 = 50 * DAY;
fn id(b: u8) -> [u8; 16] { [b; 16] }
fn key(b: u8) -> SigningKey { SigningKey::from_bytes(&[b; 32]) }
fn trust() -> TrustRegistry {
    let mut r = TrustRegistry::new();
    for (id, epoch) in [(11, 1), (12, 2), (13, 3), (14, 4), (17, 9)] {
        r.enroll(self::id(id), epoch, key(id).verifying_key()).unwrap();
    }
    r
}
fn candidate(id: u8, epoch: u64) -> Candidate {
    Candidate {
        service_id: self::id(id),
        service_epoch: epoch,
        role: ServiceRole::Public,
        permission: PermissionAssertion::CallerVerified,
        recipient_has_private_route: true,
        advertisement_expires_at_ms: NOW + 2 * DAY,
        reachable_now: true,
        available_bytes: 65_536,
        pending_new_stores: 0,
        max_new_stores: 8,
        failure_domain: DomainHint::Unknown,
    }
}
fn intent() -> StoreIntent {
    StoreIntent {
        now_ms: NOW, packet_bytes: 1024,
        role: ServiceRole::Public,
        max_suggestions: 3,
        critical: false,
        k3_issued_slots: 0, k3_slot_limit: 3,
        unresolved_handoff: false,
        allow_probation: true,
    }
}
fn store() -> (tempfile::TempDir, LocalObservationStore) {
    let dir = tempdir().unwrap();
    let opened = LocalObservationStore::open(&dir.path().join("evidence.sqlite")).unwrap();
    (dir, opened)
}
fn w7(store: &mut LocalObservationStore, t: &TrustRegistry, service: u8, epoch: u64,
    seq: u64, time: u64)
{
    let observed_packet = format!("opaque-known-message-{service}-{seq}");
    let audit = AuditReference::from_trusted_ciphertext(observed_packet.as_bytes()).unwrap();
    let checked = audit.observe(Some(observed_packet.as_bytes()), time).unwrap();
    let observer = key(30);
    let context = LocalEvidenceContext::bind(
        ServiceIdentity { id: id(service), epoch, role: ServiceRole::Public },
        &observer, seq, id(77), time, t,
    ).unwrap();
    store.record_w7_exact(&context, &checked).unwrap();
}
fn w8_pair(t: &TrustRegistry, dir: &std::path::Path) -> (Vec<u8>, Vec<u8>) {
    let (_, public) = new_recipient();
    let w3 = private_route_w3::seal_private(
        &key(11), &public, id(4),
        SignedHeader {
            message_id: id(5), recipient_id: id(8), sender_id: id(11),
            expiry: NOW + 5 * DAY, epoch: 1,
        },
        b"legitimate signed claim but no recipient W4",
    ).unwrap();
    let offer = custody_transfer_w8::sign_offer(
        OfferClaims {
            source_id: id(11), source_epoch: 1,
            target_id: id(12), target_epoch: 2,
            slot_alias: id(44), offer_id: id(55),
            ciphertext_digest: *blake3::hash(&w3).as_bytes(),
            expires_at_ms: NOW + 5 * DAY,
        },
        &key(11),
    ).unwrap();
    let own = key(12);
    let mut receiver = PeerCustodyStore::open(&dir.join("peer.sqlite")).unwrap();
    let accepted = receiver.accept(
        &offer, &w3, PeerConsent {
            expected_source: id(11), target_id: id(12), target_epoch: 2,
            signer: &own, trust: t, now_ms: NOW as i64,
        },
    ).unwrap();
    (offer, accepted)
}
fn fork(t: &TrustRegistry, dir: &std::path::Path) -> akula_wire_lab::custody_witness_w9::ForkEvidence {
    let issuer = key(11);
    let make_offer = |target: u8, epoch: u64, offer_id: u8| {
        custody_transfer_w8::sign_offer(
            OfferClaims {
                source_id: id(11), source_epoch: 1,
                target_id: id(target), target_epoch: epoch,
                slot_alias: id(44), offer_id: id(offer_id),
                ciphertext_digest: [8; 32],
                expires_at_ms: NOW + DAY,
            },
            &issuer,
        ).unwrap()
    };
    let a = make_offer(12, 2, 55);
    let b = make_offer(13, 3, 56);
    let witness_key = key(17);
    let mut w = WitnessStore::open(&dir.join("w.sqlite"), id(17), 9).unwrap();
    assert!(matches!(w.observe(&a, &witness_key, t).unwrap(), WitnessObservation::FirstSeen(_)));
    match w.observe(&b, &witness_key, t).unwrap() {
        WitnessObservation::Conflict(e) => e,
        WitnessObservation::FirstSeen(_) => panic!("conflicting signed slot was missed"),
    }
}
#[test]
fn no_evidence_is_probation_not_zero_reliability_or_fraud() {
    let (_dir, evidence) = store();
    let r = recommend(&evidence, &trust(), intent(), &[candidate(12, 2)]).unwrap();
    assert_eq!(r.assessments[0].tier, AdvisoryTier::Probation);
    assert_eq!(r.assessments[0].quality.unwrap().evidence, EvidenceClass::NoEvidence);
    assert!(r.assessments[0].quality.unwrap().storage_wilson_last_7d.is_none());
    assert_eq!(r.assessments[0].gate, Ok(()));
    assert_eq!(r.suggestion_indices, vec![0]);
    assert_eq!(r.assessments[0].suggested_new_store_ceiling, 1);
    let mut strict = intent();
    strict.allow_probation = false;
    assert!(recommend(&evidence, &trust(), strict, &[candidate(12, 2)])
        .unwrap().suggestion_indices.is_empty());
}
#[test]
fn repeated_exact_byte_checks_across_windows_outrank_one_day_spam() {
    let (_dir, mut store) = store();
    let t = trust();
    for seq in 1..=4 {
        w7(&mut store, &t, 12, 2, seq, NOW - 1_000);
    }
    for seq in 1..=2 {
        w7(&mut store, &t, 13, 3, seq, NOW - 1_000);
    }
    for seq in 3..=4 {
        w7(&mut store, &t, 13, 3, seq, NOW - 2 * DAY);
    }
    let r = recommend(&store, &t, intent(), &[candidate(12, 2), candidate(13, 3)]).unwrap();
    assert_eq!(r.assessments[0].tier, AdvisoryTier::Probation);
    assert_eq!(r.assessments[0].quality.unwrap().evidence, EvidenceClass::LimitedLocalObservation);
    assert_eq!(r.assessments[1].tier, AdvisoryTier::LocallyObserved);
    assert_eq!(r.assessments[1].quality.unwrap().evidence, EvidenceClass::RepeatedLocalObservation);
    assert_eq!(r.suggestion_indices[0], 1);
    assert_eq!(r.assessments[1].suggested_new_store_ceiling, 8);
    // This is an ordering suggestion only. None of these four observations
    // is evidence of a physical second failure domain or W4 receipt.
}
#[test]
fn signed_peer_acceptance_is_not_storage_reliability_or_recipient_delivery() {
    let (dir, mut store) = store();
    let t = trust();
    let (offer, signed) = w8_pair(&t, dir.path());
    let observer = key(30);
    let ctx = LocalEvidenceContext::bind(
        ServiceIdentity { id: id(12), epoch: 2, role: ServiceRole::Public },
        &observer, 1, id(77), NOW, &t,
    ).unwrap();
    store.record_w8_acceptance(&ctx, &offer, &signed, &t).unwrap();
    let report = recommend(&store, &t, intent(), &[candidate(12, 2)]).unwrap();
    let q = report.assessments[0].quality.unwrap();
    assert_eq!(q.signed_handoff_claims_last_7d, 1);
    assert_eq!(q.recent_storage.eligible, 0);
    assert_eq!(q.evidence, EvidenceClass::NoEvidence);
    assert!(q.storage_wilson_last_7d.is_none());
    assert_eq!(report.assessments[0].tier, AdvisoryTier::Probation);
}
#[test]
fn cryptographic_double_offer_requires_local_review_of_issuer_only() {
    let (dir, mut store) = store();
    let t = trust();
    let e = fork(&t, dir.path());
    let observer = key(30);
    let ctx = LocalEvidenceContext::bind(
        ServiceIdentity { id: id(11), epoch: 1, role: ServiceRole::Public },
        &observer, 1, id(77), NOW, &t,
    ).unwrap();
    store.record_w9_issuer_fork(&ctx, &e, id(17), &t).unwrap();
    let r = recommend(&store, &t, intent(), &[candidate(11, 1), candidate(12, 2)]).unwrap();
    assert_eq!(r.assessments[0].gate, Err(GateReason::IncidentNeedsIndependentReview));
    assert_eq!(r.assessments[0].quality.unwrap().issuer_slot_conflicts_last_30d, 1);
    assert_eq!(r.assessments[1].gate, Ok(()));
    assert_eq!(r.suggestion_indices, vec![1]);
    // The signed conflict does NOT revoke issuer's old W3, FETCH, or W8.
}
#[test]
fn hard_safety_checks_are_separate_from_all_quality_scores() {
    let (_dir, evidence) = store();
    let t = trust();
    let ok = candidate(12, 2);
    let mut variants = Vec::new();
    let mut c = ok;
    c.permission = PermissionAssertion::Unchecked;
    variants.push((c, GateReason::PermissionNotVerified));
    let mut c = ok;
    c.permission = PermissionAssertion::Denied;
    variants.push((c, GateReason::PermissionNotVerified));
    let mut c = ok;
    c.recipient_has_private_route = false;
    variants.push((c, GateReason::NoRecipientRoute));
    let mut c = ok;
    c.advertisement_expires_at_ms = NOW;
    variants.push((c, GateReason::ExpiredAdvertisement));
    let mut c = ok;
    c.reachable_now = false;
    variants.push((c, GateReason::TemporarilyUnreachable));
    let mut c = ok;
    c.available_bytes = 5;
    variants.push((c, GateReason::InsufficientCapacity));
    let mut c = ok;
    c.max_new_stores = 1;
    c.pending_new_stores = 1;
    variants.push((c, GateReason::NewStoreQuotaExhausted));
    let mut c = ok;
    c.role = ServiceRole::Personal;
    variants.push((c, GateReason::WrongRole));
    let mut c = ok;
    c.service_id = id(44);
    variants.push((c, GateReason::UntrustedOrRevokedKey));
    let mut c = ok;
    c.service_epoch = i64::MAX as u64 + 1;
    variants.push((c, GateReason::UntrustedOrRevokedKey));

    for (candidate, expected) in variants {
        let r = recommend(&evidence, &t, intent(), &[candidate]).unwrap();
        assert_eq!(r.assessments[0].gate, Err(expected));
        assert!(r.suggestion_indices.is_empty());
    }
    // Going offline is NOT fraud: a recent verified audit survives.
    let mut c = ok;
    c.reachable_now = false;
    assert_eq!(recommend(&evidence, &t, intent(), &[c]).unwrap().assessments[0].gate,
        Err(GateReason::TemporarilyUnreachable));
}
#[test]
fn ambiguous_w8_or_exhausted_k3_never_creates_an_extra_copy() {
    let (_dir, evidence) = store();
    let t = trust();
    let mut request = intent();
    request.unresolved_handoff = true;
    assert_eq!(recommend(&evidence, &t, request, &[candidate(12, 2)]).unwrap().limit,
        AdvisoryLimit::AmbiguousExistingHandoff);
    assert!(recommend(&evidence, &t, request, &[candidate(12, 2)])
        .unwrap().suggestion_indices.is_empty());
    request.unresolved_handoff = false;
    request.k3_issued_slots = 3;
    let r = recommend(&evidence, &t, request, &[candidate(12, 2)]).unwrap();
    assert_eq!(r.limit, AdvisoryLimit::AllK3SlotsAlreadyIssued);
    assert!(r.suggestion_indices.is_empty());
    request.k3_issued_slots = 2;
    let r = recommend(&evidence, &t, request, &[candidate(12, 2),candidate(13, 3)]).unwrap();
    assert_eq!(r.suggestion_indices.len(), 1);
}
#[test]
fn a_claimed_asn_or_same_operator_is_not_independent_for_critical_mail() {
    let (_dir, evidence) = store();
    let t = trust();
    let mut request = intent();
    request.critical = true;
    let mut candidates = [candidate(12, 2),candidate(13, 3),candidate(14, 4)];
    candidates[0].failure_domain = DomainHint::Claimed(id(1));
    candidates[1].failure_domain = DomainHint::IndependentlyChecked(id(7));
    candidates[2].failure_domain = DomainHint::IndependentlyChecked(id(7));
    let r = recommend(&evidence, &t, request, &candidates).unwrap();
    assert_eq!(r.limit, AdvisoryLimit::InsufficientIndependentFailureDomains);
    assert!(r.suggestion_indices.is_empty());
    candidates[2].failure_domain = DomainHint::IndependentlyChecked(id(8));
    let r = recommend(&evidence, &t, request, &candidates).unwrap();
    assert_eq!(r.limit, AdvisoryLimit::None);
    assert_eq!(r.suggestion_indices, vec![1, 2]);
    assert_eq!(r.assessments[0].gate, Ok(()));
}
#[test]
fn advisory_is_deterministic_read_only_and_restart_safe() {
    let (dir, evidence) = store();
    let path = dir.path().join("evidence.sqlite");
    let t = trust();
    let before = evidence.verified_report(
        akula_wire_lab::custodian_observation::ServiceScope {
            service_key: key(12).verifying_key().to_bytes(),
            epoch: 2, role: ServiceRole::Public,
        },
        NOW,
    ).unwrap();
    let inputs = [candidate(13, 3), candidate(12, 2)];
    let a = recommend(&evidence, &t, intent(), &inputs).unwrap();
    let b = recommend(&evidence, &t, intent(), &inputs).unwrap();
    assert_eq!(a.suggestion_indices, b.suggestion_indices);
    assert_eq!(a.suggestion_indices, vec![1, 0]);
    let after = evidence.verified_report(
        akula_wire_lab::custodian_observation::ServiceScope {
            service_key: key(12).verifying_key().to_bytes(),
            epoch: 2, role: ServiceRole::Public,
        },
        NOW,
    ).unwrap();
    assert_eq!(before.last_24h.storage, after.last_24h.storage);
    drop(evidence);
    let reopened = LocalObservationStore::open(&path).unwrap();
    assert_eq!(recommend(&reopened, &t, intent(), &inputs).unwrap()
        .suggestion_indices, vec![1, 0]);
}
