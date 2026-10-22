//! W9 private witness laboratory: attacker can issue conflicting *valid*
//! W8 custody offers. The witness detects seen conflicts and gives portable,
//! signed evidence without pretending to prevent hidden global forks.
use akula_wire_lab::crypto_identity_w3::SignedHeader;
use akula_wire_lab::crypto_w3::new_recipient;
use akula_wire_lab::custody_transfer_w8::{
    self, OfferClaims, PeerConsent, PeerCustodyStore, TransferError,
};
use akula_wire_lab::custody_witness_w9::{
    self, ChainRelation, Verdict, WitnessError, WitnessObservation, WitnessStore,
};
use akula_wire_lab::private_route_w3;
use akula_wire_lab::receipt_w4;
use akula_wire_lab::trust_w3::TrustRegistry;
use ed25519_dalek::SigningKey;
use tempfile::tempdir;

fn id(n:u8)->[u8;16]{[n;16]}
fn key(n:u8)->SigningKey{SigningKey::from_bytes(&[n;32])}
fn registry()->TrustRegistry{
    let mut r=TrustRegistry::new();
    r.enroll(id(21),3,key(21).verifying_key()).unwrap(); // source
    r.enroll(id(13),7,key(13).verifying_key()).unwrap(); // custodian X
    r.enroll(id(14),8,key(14).verifying_key()).unwrap(); // custodian Y
    r.enroll(id(17),9,key(17).verifying_key()).unwrap(); // witness
    r.enroll(id(18),10,key(18).verifying_key()).unwrap(); // different witness
    r.enroll(id(8),6,key(8).verifying_key()).unwrap(); // true recipient
    r
}
fn packet()->Vec<u8>{
    let (_,public)=new_recipient();
    private_route_w3::seal_private(
        &key(9),&public,id(4),
        SignedHeader{
            message_id:id(5),recipient_id:id(8),expiry:500_000,
            sender_id:id(9),epoch:4,
        },
        b"witness examines OFFERS not encrypted message body",
    ).unwrap()
}
fn offer(packet:&[u8],target:u8,slot:u8,offer_id:u8)->Vec<u8>{
    custody_transfer_w8::sign_offer(
        OfferClaims {
            source_id:id(21),source_epoch:3,
            target_id:id(target),target_epoch:if target==13{7}else{8},
            slot_alias:id(slot),offer_id:id(offer_id),
            ciphertext_digest:*blake3::hash(packet).as_bytes(),
            expires_at_ms:500_000,
        },&key(21),
    ).unwrap()
}
fn first(observation:WitnessObservation)->Vec<u8>{
    match observation {
        WitnessObservation::FirstSeen(checkpoint)=>checkpoint,
        WitnessObservation::Conflict(_)=>panic!("expected first-seen receipt"),
    }
}
fn conflict(observation:WitnessObservation)->custody_witness_w9::ForkEvidence{
    match observation {
        WitnessObservation::Conflict(evidence)=>evidence,
        WitnessObservation::FirstSeen(_)=>panic!("expected detected fork"),
    }
}
fn consent<'a>(target:u8,trust:&'a TrustRegistry,signer:&'a SigningKey)->PeerConsent<'a>{
    PeerConsent {
        expected_source:id(21),
        target_id:id(target),target_epoch:if target==13{7}else{8},
        signer,trust,now_ms:101,
    }
}

#[test]
fn first_offer_is_signed_and_idempotent_across_restart() {
    let dir=tempdir().unwrap();
    let path=dir.path().join("witness.sqlite");
    let trusted=registry();
    let w3=packet();
    let signed=offer(&w3,13,42,31);
    let snapshot;
    {
        let mut witness=WitnessStore::open(&path,id(17),9).unwrap();
        snapshot=first(witness.observe(&signed,&key(17),&trusted).unwrap());
        let again=first(witness.observe(&signed,&key(17),&trusted).unwrap());
        assert_eq!(again,snapshot);
        assert_eq!(witness.checkpoint().unwrap(),Some(snapshot.clone()));
        let result=custody_witness_w9::verify_first_seen(
            &signed,&snapshot,id(17),&trusted,
        ).unwrap();
        assert_eq!(result.sequence,1);
        assert_eq!(result.verdict,Verdict::FirstSeen);
    }
    let mut reopened=WitnessStore::open(&path,id(17),9).unwrap();
    assert_eq!(first(reopened.observe(&signed,&key(17),&trusted).unwrap()),snapshot);
    assert!(matches!(WitnessStore::open(&path,id(18),10),
        Err(WitnessError::WrongWitness)));
}

#[test]
fn malicious_issuer_double_signs_same_slot_and_independent_witness_catches_fork() {
    let dir=tempdir().unwrap();
    let trusted=registry();
    let w3=packet();
    let x=offer(&w3,13,42,31);
    let y=offer(&w3,14,42,32);
    let mut custodian_x=PeerCustodyStore::open(&dir.path().join("x.sqlite")).unwrap();
    let mut custodian_y=PeerCustodyStore::open(&dir.path().join("y.sqlite")).unwrap();
    let ack_x=custodian_x.accept(&x,&w3,consent(13,&trusted,&key(13))).unwrap();
    let ack_y=custodian_y.accept(&y,&w3,consent(14,&trusted,&key(14))).unwrap();
    assert_ne!(ack_x,ack_y);
    // The illegal double signing was POSSIBLE. X/Y accepted without querying
    // any witness. It is not proof of any Byzantine global K enforcement.
    let mut witness=WitnessStore::open(&dir.path().join("w.sqlite"),id(17),9).unwrap();
    let receipt=first(witness.observe(&x,&key(17),&trusted).unwrap());
    let proof=conflict(witness.observe(&y,&key(17),&trusted).unwrap());
    custody_witness_w9::verify_fork(&proof,id(17),&trusted).unwrap();
    assert_eq!(proof.first_offer,x);
    assert_eq!(proof.conflicting_offer,y);
    assert_eq!(proof.first_checkpoint,receipt);
    let c=custody_witness_w9::verify_checkpoint(&proof.conflict_checkpoint,id(17),&trusted).unwrap();
    assert_eq!(c.verdict,Verdict::ConflictObserved);
    assert_eq!(c.sequence,2);
    assert_eq!(custody_witness_w9::compare_checkpoints(
        &proof.first_checkpoint,&proof.conflict_checkpoint,id(17),&trusted,
    ).unwrap(),ChainRelation::Adjacent);
    drop(witness);
    let mut witness=WitnessStore::open(&dir.path().join("w.sqlite"),id(17),9).unwrap();
    let old=witness.conflicting_evidence(id(21),id(42)).unwrap().unwrap();
    custody_witness_w9::verify_fork(&old,id(17),&trusted).unwrap();
    // After conflict, retrying EITHER offer must not return a first-seen OK.
    let observed=conflict(witness.observe(&x,&key(17),&trusted).unwrap());
    assert_eq!(observed.conflict_checkpoint,proof.conflict_checkpoint);
    let observed=conflict(witness.observe(&y,&key(17),&trusted).unwrap());
    assert_eq!(observed.conflict_checkpoint,proof.conflict_checkpoint);
    let third=offer(&w3,14,42,33);
    let observed=conflict(witness.observe(&third,&key(17),&trusted).unwrap());
    assert_eq!(observed.conflicting_offer,y);
    assert_eq!(witness.checkpoint().unwrap(),Some(proof.conflict_checkpoint));
}

#[test]
fn unauthorized_and_tampered_issuer_offers_cannot_poison_witness() {
    let dir=tempdir().unwrap();
    let trusted=registry();
    let w3=packet();
    let signed=offer(&w3,13,42,31);
    let mut witness=WitnessStore::open(&dir.path().join("w.sqlite"),id(17),9).unwrap();
    // Wrong witness signer: an arbitrary observer cannot fabricate attestation.
    assert!(matches!(witness.observe(&signed,&key(18),&trusted),
        Err(WitnessError::UntrustedWitness)));
    let mut forged=signed.clone();
    forged[90]^=1;
    assert!(matches!(witness.observe(&forged,&key(17),&trusted),
        Err(WitnessError::Transfer(TransferError::BadSignature))));
    assert!(witness.checkpoint().unwrap().is_none());
    let receipt=first(witness.observe(&signed,&key(17),&trusted).unwrap());
    let mut altered=receipt;
    altered[95]^=1;
    assert!(matches!(custody_witness_w9::verify_checkpoint(
        &altered,id(17),&trusted,
    ),Err(WitnessError::InvalidHead)));
}

#[test]
fn receiver_witness_gate_rejects_wrong_witness_offer_or_signature() {
    let dir=tempdir().unwrap();
    let trusted=registry();
    let w3=packet();
    let x=offer(&w3,13,42,31);
    let y=offer(&w3,14,42,32);
    let mut witness=WitnessStore::open(&dir.path().join("w.sqlite"),id(17),9).unwrap();
    let first_x=first(witness.observe(&x,&key(17),&trusted).unwrap());
    let mut store=PeerCustodyStore::open(&dir.path().join("x.sqlite")).unwrap();
    let signer=key(13);
    assert!(matches!(custody_witness_w9::accept_witnessed(
        &mut store,&x,&w3,consent(13,&trusted,&signer),&first_x,id(18),
    ),Err(WitnessError::WrongWitness)));
    assert!(matches!(custody_witness_w9::accept_witnessed(
        &mut store,&y,&w3,consent(13,&trusted,&signer),&first_x,id(17),
    ),Err(WitnessError::WrongOffer)));
    let mut corrupted=first_x.clone();
    *corrupted.last_mut().unwrap()^=1;
    assert!(matches!(custody_witness_w9::accept_witnessed(
        &mut store,&x,&w3,consent(13,&trusted,&signer),&corrupted,id(17),
    ),Err(WitnessError::InvalidSignature)));
    let signed_acceptance=custody_witness_w9::accept_witnessed(
        &mut store,&x,&w3,consent(13,&trusted,&signer),&first_x,id(17),
    ).unwrap();
    assert_eq!(signed_acceptance,
        store.accept(&x,&w3,consent(13,&trusted,&signer)).unwrap());
    let accepted=custody_transfer_w8::verify_acceptance(&signed_acceptance,&trusted).unwrap();
    assert_eq!(accepted.offer_id,id(31));
    // Not recipient W4: the peer claim still cannot end sender delivery.
    assert!(receipt_w4::verify(&signed_acceptance,&trusted).is_err());
}

#[test]
fn independent_witness_snapshots_can_equivocate_only_detectable_after_gossip() {
    let dir=tempdir().unwrap();
    let trusted=registry();
    let w3=packet();
    let x=offer(&w3,13,42,31);
    let y=offer(&w3,14,42,32);
    // The same compromised witness key is used with independent histories.
    let mut a=WitnessStore::open(&dir.path().join("a.sqlite"),id(17),9).unwrap();
    let mut b=WitnessStore::open(&dir.path().join("b.sqlite"),id(17),9).unwrap();
    let ax=first(a.observe(&x,&key(17),&trusted).unwrap());
    let by=first(b.observe(&y,&key(17),&trusted).unwrap());
    assert_eq!(custody_witness_w9::compare_checkpoints(
        &ax,&by,id(17),&trusted,
    ).unwrap(),ChainRelation::Equivocation);
    // A public 'healthy official version' banner would not prevent that.
    assert_eq!(custody_witness_w9::compare_checkpoints(
        &ax,&ax,id(17),&trusted,
    ).unwrap(),ChainRelation::Same);
}

#[test]
fn adjacent_chain_is_valid_but_older_or_unproven_gap_must_fail_closed() {
    let dir=tempdir().unwrap();
    let trusted=registry();
    let w3=packet();
    let mut witness=WitnessStore::open(&dir.path().join("w.sqlite"),id(17),9).unwrap();
    let a=first(witness.observe(&offer(&w3,13,42,31),&key(17),&trusted).unwrap());
    let b=first(witness.observe(&offer(&w3,13,43,32),&key(17),&trusted).unwrap());
    let c=first(witness.observe(&offer(&w3,13,44,33),&key(17),&trusted).unwrap());
    assert_eq!(custody_witness_w9::compare_checkpoints(
        &a,&b,id(17),&trusted,
    ).unwrap(),ChainRelation::Adjacent);
    assert_eq!(custody_witness_w9::compare_checkpoints(
        &b,&c,id(17),&trusted,
    ).unwrap(),ChainRelation::Adjacent);
    assert_eq!(custody_witness_w9::compare_checkpoints(
        &a,&c,id(17),&trusted,
    ).unwrap(),ChainRelation::MissingHistory);
    assert_eq!(custody_witness_w9::compare_checkpoints(
        &c,&a,id(17),&trusted,
    ).unwrap(),ChainRelation::RollbackSuspected);
    assert_eq!(witness.checkpoint().unwrap(),Some(c));
}

#[test]
fn fork_evidence_must_contain_two_valid_source_signatures_and_matching_receipts() {
    let dir=tempdir().unwrap();
    let trusted=registry();
    let w3=packet();
    let mut witness=WitnessStore::open(&dir.path().join("w.sqlite"),id(17),9).unwrap();
    let x=offer(&w3,13,42,31);
    let y=offer(&w3,14,42,32);
    witness.observe(&x,&key(17),&trusted).unwrap();
    let proof=conflict(witness.observe(&y,&key(17),&trusted).unwrap());
    custody_witness_w9::verify_fork(&proof,id(17),&trusted).unwrap();
    let mut tampered=proof.clone();
    tampered.conflicting_offer[80]^=1;
    assert!(custody_witness_w9::verify_fork(
        &tampered,id(17),&trusted,
    ).is_err());
    let mut altered_checkpoint=proof.clone();
    *altered_checkpoint.conflict_checkpoint.last_mut().unwrap()^=1;
    assert!(matches!(custody_witness_w9::verify_fork(
        &altered_checkpoint,id(17),&trusted,
    ),Err(WitnessError::InvalidSignature)));
    // Even a perfect proof of conflict DOES NOT prove two physical disks
    // or permit the witness to issue a fake final recipient W4.
    assert!(receipt_w4::verify(&proof.conflict_checkpoint,&trusted).is_err());
}

#[test]
fn revoked_witness_and_pseudonym_scoping_limit_witness_authority() {
    let dir=tempdir().unwrap();
    let mut trusted=registry();
    let w3=packet();
    let x=offer(&w3,13,42,31);
    let mut witness=WitnessStore::open(&dir.path().join("w.sqlite"),id(17),9).unwrap();
    let proof=first(witness.observe(&x,&key(17),&trusted).unwrap());
    trusted.revoke(id(17)).unwrap();
    assert!(matches!(custody_witness_w9::verify_first_seen(
        &x,&proof,id(17),&trusted,
    ),Err(WitnessError::UntrustedWitness)));
    // Old checkpoints remain physical bytes, but current trust refuses them.
    assert!(matches!(witness.observe(&x,&key(17),&trusted),
        Err(WitnessError::UntrustedWitness)));
}

#[test]
fn historical_first_seen_does_not_prove_future_absence_of_forks() {
    let dir=tempdir().unwrap();
    let trusted=registry();
    let w3=packet();
    let x=offer(&w3,13,42,31);
    let y=offer(&w3,14,42,32);
    let mut witness=WitnessStore::open(&dir.path().join("w.sqlite"),id(17),9).unwrap();
    let historical=first(witness.observe(&x,&key(17),&trusted).unwrap());
    let proof=conflict(witness.observe(&y,&key(17),&trusted).unwrap());
    // Signature of FIRST SEEN continues to verify even AFTER fork detection:
    // a peer must query fresh state/gossip for stronger no-fork expectations.
    assert!(custody_witness_w9::verify_first_seen(
        &x,&historical,id(17),&trusted,
    ).is_ok());
    custody_witness_w9::verify_fork(&proof,id(17),&trusted).unwrap();
    assert_eq!(witness.checkpoint().unwrap(),
        Some(proof.conflict_checkpoint));
}
