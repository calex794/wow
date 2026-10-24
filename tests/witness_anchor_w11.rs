//! W11 durable independent witness-head anchor. Signed snapshots can expose
//! an altered/rolled-back local pin but not a rollback of *all* controlled
//! copies, a lying remote operator, or missing/unobserved witness checkpoints.
use akula_wire_lab::custody_transfer_w8::{self, OfferClaims};
use akula_wire_lab::custody_witness_w9::{WitnessObservation, WitnessStore};
use akula_wire_lab::trust_w3::TrustRegistry;
use akula_wire_lab::witness_anchor_w11::{
    self, AnchorComparison, AnchorError, AnchorGossip, AnchorIdentity,
    AnchorObservation, AnchorStore,
};
use akula_wire_lab::witness_pin_w10::{PinError, PinOutcome, WitnessPinStore};
use ed25519_dalek::SigningKey;
use rusqlite::{params, Connection};
use std::path::Path;
use tempfile::tempdir;

fn id(v: u8) -> [u8; 16] { [v; 16] }
fn key(v: u8) -> SigningKey { SigningKey::from_bytes(&[v; 32]) }
fn scope() -> AnchorIdentity {
    AnchorIdentity {
        anchor_id: id(19), anchor_epoch: 11,
        witness_id: id(17), witness_epoch: 9,
    }
}
fn trust() -> TrustRegistry {
    let mut t = TrustRegistry::new();
    t.enroll(id(21), 3, key(21).verifying_key()).unwrap();
    t.enroll(id(17), 9, key(17).verifying_key()).unwrap();
    t.enroll(id(18), 10, key(18).verifying_key()).unwrap();
    t.enroll(id(19), 11, key(19).verifying_key()).unwrap();
    t
}
fn offer(slot: u8, target: u8) -> Vec<u8> {
    custody_transfer_w8::sign_offer(
        OfferClaims {
            source_id: id(21), source_epoch: 3,
            target_id: id(target),
            target_epoch: if target == 13 { 7 } else { 8 },
            slot_alias: id(slot), offer_id: id(slot + 50),
            ciphertext_digest: [6; 32], expires_at_ms: 500_000,
        }, &key(21),
    ).unwrap()
}
fn first(observation: WitnessObservation) -> Vec<u8> {
    match observation {
        WitnessObservation::FirstSeen(c) => c,
        WitnessObservation::Conflict(_) => panic!("expected first-seen checkpoint"),
    }
}
fn checkpoints(path: &Path, n: u8) -> Vec<Vec<u8>> {
    let mut witness = WitnessStore::open(path, id(17), 9).unwrap();
    (0..n).map(|i| {
        let signed = offer(41 + i, 13);
        first(witness.observe(&signed, &key(17), &trust()).unwrap())
    }).collect()
}
fn observe(store: &mut AnchorStore, checkpoint: &[u8]) -> Vec<u8> {
    store.observe(checkpoint, &key(19), &trust()).unwrap().1
}

#[test]
fn independently_signed_receipt_replays_exactly_after_anchor_restart() {
    let dir = tempdir().unwrap();
    let cps = checkpoints(&dir.path().join("witness.sqlite"), 1);
    let path = dir.path().join("independent-anchor.sqlite");
    let trusted = trust();
    let receipt = {
        let mut anchor = AnchorStore::open(&path, scope()).unwrap();
        let (status, receipt) = anchor.observe(&cps[0], &key(19), &trusted).unwrap();
        assert_eq!(status, AnchorObservation::First);
        let checked = witness_anchor_w11::verify_anchor(
            &receipt, &cps[0], scope(), &trusted,
        ).unwrap();
        assert_eq!(checked.sequence, 1);
        assert_eq!(checked.scope, scope());
        assert_eq!(anchor.latest().unwrap(), Some((cps[0].clone(), receipt.clone())));
        receipt
    };
    let mut restarted = AnchorStore::open(&path, scope()).unwrap();
    assert_eq!(restarted.observe(&cps[0], &key(19), &trusted).unwrap().0,
               AnchorObservation::Unchanged);
    assert_eq!(observe(&mut restarted, &cps[0]), receipt);
    assert_eq!(restarted.latest().unwrap(), Some((cps[0].clone(), receipt.clone())));
    let mut pin = WitnessPinStore::open(
        &dir.path().join("client-pin.sqlite"), id(17), 9,
    ).unwrap();
    assert_eq!(pin.pin(&cps[0], &trusted).unwrap(), PinOutcome::First);
    assert_eq!(witness_anchor_w11::compare_with_pin(
        &receipt, &cps[0], scope(), &pin, &trusted,
    ).unwrap(), AnchorComparison::Matched);
    witness_anchor_w11::require_matched(
        &receipt, &cps[0], scope(), &pin, &trusted,
    ).unwrap();
}

#[test]
fn independent_anchor_detects_local_sqlite_checkpoint_rollback_until_reconciled() {
    let dir = tempdir().unwrap();
    let trusted = trust();
    let cps = checkpoints(&dir.path().join("witness.sqlite"), 3);
    let mut external = AnchorStore::open(
        &dir.path().join("external.sqlite"), scope(),
    ).unwrap();
    let pin_path = dir.path().join("client.sqlite");
    let mut pin = WitnessPinStore::open(&pin_path, id(17), 9).unwrap();
    for cp in &cps {
        observe(&mut external, cp);
        pin.pin(cp, &trusted).unwrap();
    }
    let receipt = external.latest().unwrap().unwrap().1;
    witness_anchor_w11::require_matched(
        &receipt, &cps[2], scope(), &pin, &trusted,
    ).unwrap();

    // Attacker restores ONLY client SQLite to a valid previously signed
    // checkpoint, bypassing W10 API. External independent anchor is intact.
    drop(pin);
    let attacked = Connection::open(&pin_path).unwrap();
    attacked.execute(
        "UPDATE pinned_witness SET checkpoint=?1 WHERE singleton=1",
        params![cps[0].as_slice()],
    ).unwrap();
    drop(attacked);
    let mut pin = WitnessPinStore::open(&pin_path, id(17), 9).unwrap();
    assert_eq!(pin.inspect(&trusted).unwrap(), Some(1));
    assert_eq!(witness_anchor_w11::compare_with_pin(
        &receipt, &cps[2], scope(), &pin, &trusted,
    ).unwrap(), AnchorComparison::UnprovenGap);
    assert!(matches!(witness_anchor_w11::require_matched(
        &receipt, &cps[2], scope(), &pin, &trusted,
    ), Err(AnchorError::NotMatched)));
    // Controlled resynchronization replays verified intermediate signed
    // checkpoints, NOT blind adoption of seq=3 from an untrusted peer.
    assert_eq!(pin.pin(&cps[1], &trusted).unwrap(), PinOutcome::Advanced);
    assert_eq!(pin.pin(&cps[2], &trusted).unwrap(), PinOutcome::Advanced);
    witness_anchor_w11::require_matched(
        &receipt, &cps[2], scope(), &pin, &trusted,
    ).unwrap();
}

#[test]
fn lagging_anchor_and_missing_local_anchor_are_never_silent_success() {
    let dir = tempdir().unwrap(); let trusted = trust();
    let cps = checkpoints(&dir.path().join("w.sqlite"), 3);
    let mut anchor = AnchorStore::open(&dir.path().join("ext.sqlite"), scope()).unwrap();
    let mut pin = WitnessPinStore::open(&dir.path().join("p.sqlite"), id(17), 9).unwrap();
    assert_eq!(witness_anchor_w11::compare_with_pin(
        &observe(&mut anchor, &cps[0]), &cps[0], scope(), &pin, &trusted,
    ).unwrap(), AnchorComparison::NoLocalPin);
    pin.pin(&cps[0], &trusted).unwrap();
    let receipt2 = observe(&mut anchor, &cps[1]);
    pin.pin(&cps[1], &trusted).unwrap();
    pin.pin(&cps[2], &trusted).unwrap();
    assert_eq!(witness_anchor_w11::compare_with_pin(
        &receipt2, &cps[1], scope(), &pin, &trusted,
    ).unwrap(), AnchorComparison::AnchorBehind);
    assert!(matches!(witness_anchor_w11::require_matched(
        &receipt2, &cps[1], scope(), &pin, &trusted,
    ), Err(AnchorError::NotMatched)));
    assert_eq!(witness_anchor_w11::compare_with_pin(
        &observe(&mut anchor, &cps[2]), &cps[2], scope(), &pin, &trusted,
    ).unwrap(), AnchorComparison::Matched);
}

#[test]
fn anchor_fork_freezes_even_when_both_witness_signatures_are_valid() {
    let dir = tempdir().unwrap(); let trusted = trust();
    let mut honest = WitnessStore::open(&dir.path().join("wA.sqlite"), id(17), 9).unwrap();
    let mut rogue = WitnessStore::open(&dir.path().join("wB.sqlite"), id(17), 9).unwrap();
    let first_a = first(honest.observe(&offer(41, 13), &key(17), &trusted).unwrap());
    let first_b = first(rogue.observe(&offer(42, 13), &key(17), &trusted).unwrap());
    let anchor_path = dir.path().join("anchor.sqlite");
    let receipt;
    {
        let mut anchor = AnchorStore::open(&anchor_path, scope()).unwrap();
        receipt = observe(&mut anchor, &first_a);
        assert!(matches!(anchor.observe(&first_b, &key(19), &trusted),
            Err(AnchorError::Equivocation)));
        assert!(anchor.frozen().unwrap());
        assert_eq!(anchor.fork().unwrap(), Some((first_a.clone(), first_b.clone())));
        assert!(matches!(anchor.latest(), Err(AnchorError::Frozen)));
    }
    let mut restarted = AnchorStore::open(&anchor_path, scope()).unwrap();
    assert!(restarted.frozen().unwrap());
    assert!(matches!(restarted.observe(&first_a, &key(19), &trusted),
        Err(AnchorError::Frozen)));
    // Old receipt signature remains valid even after witness split: proof
    // of past observation is not a freshness/availability guarantee.
    witness_anchor_w11::verify_anchor(&receipt, &first_a, scope(), &trusted).unwrap();
}

#[test]
fn two_anchor_databases_with_same_real_signer_key_can_themselves_fork() {
    let dir = tempdir().unwrap(); let trusted = trust();
    let mut witness_a = WitnessStore::open(&dir.path().join("wa.sqlite"), id(17), 9).unwrap();
    let mut witness_b = WitnessStore::open(&dir.path().join("wb.sqlite"), id(17), 9).unwrap();
    let cpa = first(witness_a.observe(&offer(41, 13), &key(17), &trusted).unwrap());
    let cpb = first(witness_b.observe(&offer(42, 13), &key(17), &trusted).unwrap());
    let mut anchor_a = AnchorStore::open(&dir.path().join("anchorA.sqlite"), scope()).unwrap();
    let mut anchor_b = AnchorStore::open(&dir.path().join("anchorB.sqlite"), scope()).unwrap();
    let ra = observe(&mut anchor_a, &cpa);
    let rb = observe(&mut anchor_b, &cpb);
    assert_eq!(witness_anchor_w11::compare_anchor_receipts(
        (&ra, &cpa), (&rb, &cpb), scope(), &trusted,
    ).unwrap(), AnchorGossip::SameHeightEquivocation);
    // Possession of a valid Ed25519 key does not enforce one DB or one
    // executable version. Peer gossip must compare signed claims.
}

#[test]
fn forged_or_mismatched_anchor_receipts_cannot_clear_local_pin() {
    let dir = tempdir().unwrap(); let trusted = trust();
    let cps = checkpoints(&dir.path().join("w.sqlite"), 2);
    let mut anchor = AnchorStore::open(&dir.path().join("anchor.sqlite"), scope()).unwrap();
    let receipt = observe(&mut anchor, &cps[0]);
    let mut altered = receipt.clone();
    *altered.last_mut().unwrap() ^= 1;
    assert!(matches!(witness_anchor_w11::verify_anchor(
        &altered, &cps[0], scope(), &trusted,
    ), Err(AnchorError::InvalidSignature)));
    assert!(witness_anchor_w11::verify_anchor(
        &receipt, &cps[1], scope(), &trusted,
    ).is_err());
    let mut wrong_scope = scope();
    wrong_scope.anchor_id = id(18);
    assert!(matches!(witness_anchor_w11::verify_anchor(
        &receipt, &cps[0], wrong_scope, &trusted,
    ), Err(AnchorError::WrongScope)));
    assert!(matches!(anchor.observe(&cps[0], &key(18), &trusted),
        Err(AnchorError::UntrustedAnchor)));
    let mut revoked = trust();
    revoked.revoke(id(19)).unwrap();
    assert!(matches!(witness_anchor_w11::verify_anchor(
        &receipt, &cps[0], scope(), &revoked,
    ), Err(AnchorError::UntrustedAnchor)));
}

#[test]
fn anchor_rejects_missing_intermediates_and_stale_witness_checkpoint() {
    let dir = tempdir().unwrap(); let trusted = trust();
    let cps = checkpoints(&dir.path().join("w.sqlite"), 3);
    let mut external = AnchorStore::open(&dir.path().join("anchor.sqlite"), scope()).unwrap();
    assert!(matches!(external.observe(&cps[2], &key(19), &trusted),
        Err(AnchorError::MissingHistory)));
    observe(&mut external, &cps[0]);
    assert!(matches!(external.observe(&cps[2], &key(19), &trusted),
        Err(AnchorError::MissingHistory)));
    observe(&mut external, &cps[1]);
    observe(&mut external, &cps[2]);
    assert!(matches!(external.observe(&cps[0], &key(19), &trusted),
        Err(AnchorError::Stale)));
}

#[test]
fn frozen_client_pin_blocks_anchor_agreement_even_for_genuine_receipt() {
    let dir = tempdir().unwrap(); let trusted = trust();
    let mut witness_a = WitnessStore::open(&dir.path().join("wa.sqlite"), id(17), 9).unwrap();
    let mut witness_b = WitnessStore::open(&dir.path().join("wb.sqlite"), id(17), 9).unwrap();
    let cp_a = first(witness_a.observe(&offer(41, 13), &key(17), &trusted).unwrap());
    let cp_b = first(witness_b.observe(&offer(42, 13), &key(17), &trusted).unwrap());
    let mut external = AnchorStore::open(&dir.path().join("anchor.sqlite"), scope()).unwrap();
    let receipt = observe(&mut external, &cp_a);
    let mut pin = WitnessPinStore::open(&dir.path().join("client.sqlite"), id(17), 9).unwrap();
    pin.pin(&cp_a, &trusted).unwrap();
    assert!(matches!(pin.pin(&cp_b, &trusted), Err(PinError::Equivocation)));
    assert!(matches!(witness_anchor_w11::compare_with_pin(
        &receipt, &cp_a, scope(), &pin, &trusted,
    ), Err(AnchorError::Frozen)));
}
