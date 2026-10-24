//! P0-2 adversarial matrix: raw claims must not become verified statistics.
//! All remote W8/W9 signatures and W10 pins are checked before any local
//! observation; W7 is an exact-byte local E1 check only.
use akula_wire_lab::crypto_identity_w3::SignedHeader;
use akula_wire_lab::crypto_w3::new_recipient;
use akula_wire_lab::custodian_evidence_bridge::{
    BridgeError, LocalEvidenceContext,
};
use akula_wire_lab::custodian_observation::{
    AppendResult, EvidenceLevel, EventKind, LocalObservationStore,
    ObservationError, ServiceEvent, ServiceRole,
};
use akula_wire_lab::custody_audit_w7::{AuditError, AuditReference};
use akula_wire_lab::custody_transfer_w8::{
    self, OfferClaims, PeerConsent, PeerCustodyStore,
};
use akula_wire_lab::custody_witness_w9::{
    WitnessObservation, WitnessStore,
};
use akula_wire_lab::private_route_w3;
use akula_wire_lab::trust_w3::TrustRegistry;
use akula_wire_lab::witness_pin_w10::{
    PinOutcome, WitnessPinStore,
};
use ed25519_dalek::SigningKey;
use tempfile::tempdir;

const NOW: u64 = 100_000;
const EXPIRY: u64 = 500_000;
const DAY: u64 = 86_400_000;

fn id(b: u8) -> [u8; 16] { [b; 16] }
fn signer(b: u8) -> SigningKey { SigningKey::from_bytes(&[b; 32]) }
fn registry() -> TrustRegistry {
    let mut t = TrustRegistry::new();
    t.enroll(id(11), 1, signer(11).verifying_key()).unwrap();
    t.enroll(id(12), 2, signer(12).verifying_key()).unwrap();
    t.enroll(id(13), 3, signer(13).verifying_key()).unwrap();
    t.enroll(id(17), 9, signer(17).verifying_key()).unwrap();
    t
}
fn ctx<'a>(
    node: u8, epoch: u64, owner: &'a SigningKey,
    seq: u64, observed_at: u64, trust: &TrustRegistry,
) -> LocalEvidenceContext<'a> {
    LocalEvidenceContext::bind(
        id(node), epoch, ServiceRole::Public, owner, seq,
        id(90), observed_at, trust,
    ).unwrap()
}
fn packet() -> Vec<u8> {
    let (_, public) = new_recipient();
    private_route_w3::seal_private(
        &signer(11), &public, id(4),
        SignedHeader {
            message_id: id(5), recipient_id: id(8),
            expiry: EXPIRY, sender_id: id(11), epoch: 1,
        },
        b"private test packet with signed header",
    ).unwrap()
}
fn signed_offer(packet: &[u8], target: u8, slot: u8, offer: u8) -> Vec<u8> {
    custody_transfer_w8::sign_offer(
        OfferClaims {
            source_id: id(11), source_epoch: 1,
            target_id: id(target),
            target_epoch: if target == 12 { 2 } else { 3 },
            slot_alias: id(slot), offer_id: id(offer),
            ciphertext_digest: *blake3::hash(packet).as_bytes(),
            expires_at_ms: EXPIRY,
        },
        &signer(11),
    ).unwrap()
}
fn first(o: WitnessObservation) -> Vec<u8> {
    match o {
        WitnessObservation::FirstSeen(checkpoint) => checkpoint,
        WitnessObservation::Conflict(_) => panic!("expected first checkpoint"),
    }
}
fn conflict(o: WitnessObservation) -> akula_wire_lab::custody_witness_w9::ForkEvidence {
    match o {
        WitnessObservation::Conflict(e) => e,
        WitnessObservation::FirstSeen(_) => panic!("expected a signed conflict"),
    }
}

#[test]
fn w7_exact_bytes_are_e1_and_repeat_spam_is_one_daily_observation() {
    let folder = tempdir().unwrap();
    let mut store = LocalObservationStore::open(&folder.path().join("events.db")).unwrap();
    let trusted = registry();
    let w3 = packet();
    let reference = AuditReference::from_trusted_ciphertext(&w3).unwrap();
    let observation = reference.observe(Some(&w3), NOW).unwrap();
    let owner = signer(30);
    let context = ctx(12, 2, &owner, 1, NOW, &trusted);
    assert_eq!(
        store.record_w7_exact(&context, &observation).unwrap(),
        AppendResult::Stored
    );
    // One service + one ciphertext + one local day; 100 claimed observers
    // cannot turn this one byte check into 100 independent audits.
    for i in 31..=100 {
        let other = signer(i);
        let next = ctx(12, 2, &other, 1, NOW, &trusted);
        assert_eq!(
            store.record_w7_exact(&next, &observation).unwrap(),
            AppendResult::ExactReplay
        );
    }
    let report = store.verified_report(context.scope(), NOW).unwrap();
    assert_eq!(report.last_24h.storage.successes, 1);
    assert_eq!(report.last_24h.storage.eligible, 1);
    assert_eq!(report.last_24h.authorized_fetch.eligible, 0);
    assert_eq!(report.last_24h.recipient_w4_observations, 0);
    let mut bad = w3.clone();
    let midpoint = bad.len() / 2;
    bad[midpoint] ^= 1;
    assert_eq!(
        reference.observe(Some(&bad), NOW).unwrap_err(),
        AuditError::WrongCiphertext
    );
    assert_eq!(
        store.verified_report(context.scope(), NOW).unwrap()
            .last_24h.storage.successes,
        1
    );
    // A new day may supply a NEW observation; the same day cannot.
    let later = reference.observe(Some(&w3), NOW + DAY).unwrap();
    let second = ctx(12, 2, &owner, 2, NOW + DAY, &trusted);
    assert_eq!(
        store.record_w7_exact(&second, &later).unwrap(),
        AppendResult::Stored
    );
    assert_eq!(
        store.verified_report(context.scope(), NOW + DAY).unwrap()
            .last_24h.storage.successes,
        1
    );
}

#[test]
fn signed_w8_acceptance_is_bound_to_exact_offer_scope_and_single_slot() {
    let folder = tempdir().unwrap();
    let trusted = registry();
    let w3 = packet();
    let offer = signed_offer(&w3, 12, 55, 66);
    let custodian_key = signer(12);
    let mut peer = PeerCustodyStore::open(&folder.path().join("custodian.db")).unwrap();
    let ack = peer.accept(
        &offer, &w3, PeerConsent {
            expected_source: id(11), target_id: id(12), target_epoch: 2,
            signer: &custodian_key, trust: &trusted, now_ms: NOW as i64,
        },
    ).unwrap();
    let mut store = LocalObservationStore::open(&folder.path().join("events.db")).unwrap();
    let owner = signer(30);
    let context = ctx(12, 2, &owner, 1, NOW, &trusted);
    assert_eq!(
        store.record_w8_acceptance(&context, &offer, &ack, &trusted).unwrap(),
        AppendResult::Stored
    );
    let other_owner = signer(31);
    let retry = ctx(12, 2, &other_owner, 2, NOW, &trusted);
    assert_eq!(
        store.record_w8_acceptance(&retry, &offer, &ack, &trusted).unwrap(),
        AppendResult::ExactReplay
    );
    let report = store.verified_report(context.scope(), NOW).unwrap();
    assert_eq!(report.last_24h.handoff.successes, 1);
    assert_eq!(report.last_24h.storage.eligible, 0);
    assert_eq!(report.last_24h.recipient_w4_observations, 0);
    let wrong_service = ctx(13, 3, &owner, 3, NOW, &trusted);
    assert!(matches!(
        store.record_w8_acceptance(&wrong_service, &offer, &ack, &trusted),
        Err(BridgeError::ScopeMismatch)
    ));
    let mut forged = ack.clone();
    forged[80] ^= 1;
    assert!(matches!(
        store.record_w8_acceptance(&retry, &offer, &forged, &trusted),
        Err(BridgeError::Transfer(_))
    ));
    assert_eq!(
        store.verified_report(context.scope(), NOW).unwrap()
            .last_24h.handoff.eligible,
        1
    );
}

#[test]
fn malicious_double_offer_is_an_issuer_incident_not_target_custodian_fraud() {
    let folder = tempdir().unwrap();
    let trusted = registry();
    let w3 = packet();
    let offer_a = signed_offer(&w3, 12, 55, 66);
    let offer_b = signed_offer(&w3, 13, 55, 67);
    let witness_key = signer(17);
    let mut witness = WitnessStore::open(
        &folder.path().join("witness.db"), id(17), 9,
    ).unwrap();
    first(witness.observe(&offer_a, &witness_key, &trusted).unwrap());
    let evidence = conflict(witness.observe(
        &offer_b, &witness_key, &trusted,
    ).unwrap());
    let mut store = LocalObservationStore::open(&folder.path().join("events.db")).unwrap();
    let owner = signer(30);
    let source = ctx(11, 1, &owner, 1, NOW, &trusted);
    let target = ctx(12, 2, &owner, 2, NOW, &trusted);
    assert!(matches!(
        store.record_w9_issuer_fork(&target, &evidence, id(17), &trusted),
        Err(BridgeError::ScopeMismatch)
    ));
    assert_eq!(
        store.record_w9_issuer_fork(&source, &evidence, id(17), &trusted).unwrap(),
        AppendResult::Stored
    );
    let another = signer(31);
    let replay = ctx(11, 1, &another, 3, NOW, &trusted);
    assert_eq!(
        store.record_w9_issuer_fork(&replay, &evidence, id(17), &trusted).unwrap(),
        AppendResult::ExactReplay
    );
    let report = store.verified_report(source.scope(), NOW).unwrap();
    assert_eq!(report.last_24h.checkpoint_conflicts, 1);
    assert_eq!(report.last_24h.storage.eligible, 0);
    assert_eq!(report.last_24h.authorized_fetch.eligible, 0);
    assert_eq!(store.verified_report(target.scope(), NOW).unwrap()
        .last_24h.checkpoint_conflicts, 0);
    let mut tampered = evidence.clone();
    tampered.conflicting_offer[90] ^= 1;
    assert!(matches!(
        store.record_w9_issuer_fork(&source, &tampered, id(17), &trusted),
        Err(BridgeError::Witness(_))
    ));
}

#[test]
fn w10_durable_anchor_is_monotonic_and_never_counts_as_a_w4_or_audit() {
    let folder = tempdir().unwrap();
    let trust = registry();
    let w3 = packet();
    let witness_key = signer(17);
    let mut witness = WitnessStore::open(
        &folder.path().join("w.sqlite"), id(17), 9,
    ).unwrap();
    let first_cp = first(witness.observe(
        &signed_offer(&w3, 12, 55, 66), &witness_key, &trust,
    ).unwrap());
    let pin_path = folder.path().join("pin.sqlite");
    let mut pin = WitnessPinStore::open(&pin_path, id(17), 9).unwrap();
    assert_eq!(pin.pin(&first_cp, &trust).unwrap(), PinOutcome::First);
    let old_path = folder.path().join("oldpin.sqlite");
    let mut older_pin = WitnessPinStore::open(&old_path, id(17), 9).unwrap();
    older_pin.pin(&first_cp, &trust).unwrap();

    let owner = signer(30);
    let context = ctx(11, 1, &owner, 1, NOW, &trust);
    let path = folder.path().join("observations.db");
    {
        let mut store = LocalObservationStore::open(&path).unwrap();
        assert_eq!(
            store.record_w10_anchor(&context, &pin, id(17), 9, &trust).unwrap(),
            AppendResult::Stored
        );
        assert_eq!(
            store.record_w10_anchor(&context, &pin, id(17), 9, &trust).unwrap(),
            AppendResult::ExactReplay
        );
    }
    let second_cp = first(witness.observe(
        &signed_offer(&w3, 12, 56, 68), &witness_key, &trust,
    ).unwrap());
    assert_eq!(pin.pin(&second_cp, &trust).unwrap(), PinOutcome::Advanced);
    let mut store = LocalObservationStore::open(&path).unwrap();
    assert_eq!(
        store.record_w10_anchor(&context, &pin, id(17), 9, &trust).unwrap(),
        AppendResult::Stored
    );
    assert!(matches!(
        store.record_w10_anchor(&context, &older_pin, id(17), 9, &trust),
        Err(BridgeError::Observation(ObservationError::Conflict))
    ));
    assert!(matches!(
        store.record_w10_anchor(&context, &pin, id(17), 10, &trust),
        Err(BridgeError::ScopeMismatch)
    ));
    let report = store.verified_report(context.scope(), NOW).unwrap();
    assert_eq!(report.last_24h.storage.eligible, 0);
    assert_eq!(report.last_24h.handoff.eligible, 0);
    assert_eq!(report.last_24h.recipient_w4_observations, 0);
    assert_eq!(report.last_24h.checkpoint_conflicts, 0);
}

#[test]
fn one_hundred_fake_e4_reporters_cannot_inflate_the_verified_report() {
    let folder = tempdir().unwrap();
    let trusted = registry();
    let owner = signer(30);
    let bound = ctx(12, 2, &owner, 1, NOW, &trusted);
    let mut store = LocalObservationStore::open(&folder.path().join("obs.db")).unwrap();
    for i in 1..=100_u8 {
        let raw = ServiceEvent {
            scope: bound.scope(),
            observer_key: [i; 32],
            event_seq: 1,
            operation_alias: [i; 16],
            lease_alias: [2; 16],
            session_nonce: [4; 16],
            observed_at_ms: NOW,
            kind: EventKind::AuditExactW3,
            evidence_level: EvidenceLevel::RepeatedIndependentAudit,
            evidence_digest: Some([i; 32]),
        };
        assert_eq!(store.record(raw).unwrap(), AppendResult::Stored);
    }
    let raw = store.report(bound.scope(), NOW).unwrap();
    assert_eq!(raw.last_24h.storage.successes, 100);
    let verified = store.verified_report(bound.scope(), NOW).unwrap();
    assert_eq!(verified.last_24h.storage.successes, 0);
    assert!(verified.last_24h.storage.wilson_lower_bound().is_none());
    // Authenticated local W7 check is the only route to this tally.
    let w3 = packet();
    let reference = AuditReference::from_trusted_ciphertext(&w3).unwrap();
    let verified_byte_check = reference.observe(Some(&w3), NOW).unwrap();
    // This is a *different* observer identity and operation, not a raw
    // unverified event being upgraded in-place.
    let genuine = ctx(12, 2, &owner, 2, NOW, &trusted);
    assert_eq!(
        store.record_w7_exact(&genuine, &verified_byte_check).unwrap(),
        AppendResult::Stored
    );
    assert_eq!(
        store.verified_report(bound.scope(), NOW).unwrap()
            .last_24h.storage.successes,
        1
    );
}

#[test]
fn adversarial_child() {
    let Some(root) = std::env::var_os("WOW_CUSTODIAN_P02_ATTACK_DIR") else {
        return;
    };
    let folder = std::path::PathBuf::from(root);
    // Deliberately altered bytes from an isolated OS process. The child
    // cannot create a verified local event or forge the target signature.
    let mut packet = std::fs::read(folder.join("w3.bin")).unwrap();
    packet[0] ^= 1;
    std::fs::write(folder.join("forged_w3.bin"), packet).unwrap();
    let mut ack = std::fs::read(folder.join("signed_ack.bin")).unwrap();
    let last = ack.len() - 1;
    ack[last] ^= 1;
    std::fs::write(folder.join("forged_ack.bin"), ack).unwrap();
}

#[test]
fn independent_attacker_process_cannot_turn_corruption_into_a_verified_event() {
    let folder = tempdir().unwrap();
    let trusted = registry();
    let w3 = packet();
    let offer = signed_offer(&w3, 12, 55, 66);
    let custodian_key = signer(12);
    let mut receiver = PeerCustodyStore::open(&folder.path().join("peer.db")).unwrap();
    let valid_ack = receiver.accept(
        &offer, &w3, PeerConsent {
            expected_source: id(11), target_id: id(12), target_epoch: 2,
            signer: &custodian_key, trust: &trusted, now_ms: NOW as i64,
        },
    ).unwrap();
    std::fs::write(folder.path().join("w3.bin"), &w3).unwrap();
    std::fs::write(folder.path().join("signed_ack.bin"), &valid_ack).unwrap();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("adversarial_child")
        .env("WOW_CUSTODIAN_P02_ATTACK_DIR", folder.path())
        .status()
        .unwrap();
    assert!(status.success(), "the independent attacker process must complete");
    let corrupted_w3 = std::fs::read(folder.path().join("forged_w3.bin")).unwrap();
    let corrupted_ack = std::fs::read(folder.path().join("forged_ack.bin")).unwrap();

    let reference = AuditReference::from_trusted_ciphertext(&w3).unwrap();
    assert!(matches!(
        reference.observe(Some(&corrupted_w3), NOW),
        Err(AuditError::WrongCiphertext)
    ));
    let owner = signer(30);
    let bound = ctx(12, 2, &owner, 1, NOW, &trusted);
    let mut store = LocalObservationStore::open(
        &folder.path().join("observer.db"),
    ).unwrap();
    assert!(matches!(
        store.record_w8_acceptance(&bound, &offer, &corrupted_ack, &trusted),
        Err(BridgeError::Transfer(_))
    ));
    let untouched = store.verified_report(bound.scope(), NOW).unwrap();
    assert_eq!(untouched.last_24h.storage.eligible, 0);
    assert_eq!(untouched.last_24h.handoff.eligible, 0);
    assert_eq!(untouched.last_24h.checkpoint_conflicts, 0);
    // An attacker cannot poison the local journal so that the same legitimate
    // signed acceptance later fails.
    assert_eq!(
        store.record_w8_acceptance(&bound, &offer, &valid_ack, &trusted).unwrap(),
        AppendResult::Stored
    );
    assert_eq!(
        store.verified_report(bound.scope(), NOW).unwrap()
            .last_24h.handoff.successes,
        1
    );
}
