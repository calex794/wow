//! W8 signed escrow transfer across two independent SQLite files.
//! No shared transaction, physical remote host or global Byzantine quota.
use akula_wire_lab::crypto_identity_w3::SignedHeader;
use akula_wire_lab::crypto_w3::new_recipient;
use akula_wire_lab::custody_transfer_w8::{
    self, OfferClaims, OfferIssue, PeerConsent, PeerCustodyStore, TransferError, TransferPhase,
    OFFER_LEN, ACCEPT_LEN,
};
use akula_wire_lab::journal_w4::{Delivery, Journal};
use akula_wire_lab::multipath_w5::Lane;
use akula_wire_lab::private_route_w3;
use akula_wire_lab::receipt_w4;
use akula_wire_lab::trust_w3::TrustRegistry;
use ed25519_dalek::SigningKey;
use std::thread;
use tempfile::tempdir;

fn id(n:u8)->[u8;16]{[n;16]}
fn key(n:u8)->SigningKey {SigningKey::from_bytes(&[n;32])}
fn trust()->TrustRegistry {
    let mut t=TrustRegistry::new();
    t.enroll(id(21),3,key(21).verifying_key()).unwrap(); // source pseudonym
    t.enroll(id(13),7,key(13).verifying_key()).unwrap(); // custodian X
    t.enroll(id(14),8,key(14).verifying_key()).unwrap(); // custodian Y
    t.enroll(id(8),6,key(8).verifying_key()).unwrap(); // final Bob
    t
}
fn packet()->Vec<u8> {
    let (_,public)=new_recipient();
    private_route_w3::seal_private(
        &key(9),&public,id(4),
        SignedHeader {
            message_id:id(5),recipient_id:id(8),sender_id:id(9),
            expiry:500_000,epoch:4,
        }, b"one encrypted W3 with K=3 honest source ledger",
    ).unwrap()
}
fn initial(journal:&mut Journal,wire:&[u8]) {
    journal.enqueue(id(8),id(5),500_000,wire).unwrap();
    journal.begin_multipath(id(8),id(5),wire,500_000,3,100).unwrap();
    journal.reserve_multipath(
        (id(8),id(5)),wire,id(44),id(13),Lane::Gateway,101,
    ).unwrap();
}
fn issue(journal:&mut Journal,offer_id:[u8;16],target:[u8;16],
         source_trust:&TrustRegistry)->Result<Vec<u8>,TransferError>{
    journal.issue_custody_offer(OfferIssue {
        recipient:id(8),message:id(5),attempt_id:id(44),
        offer_id,source_id:id(21),source_epoch:3,
        target_id:target,target_epoch:if target==id(13){7}else{8},
        now_ms:102,
    },&key(21),source_trust)
}

#[test]
fn accepted_in_independent_sqlite_after_source_offline_ack_lost_replay_then_confirm() {
    let dir=tempdir().unwrap();
    let source_path=dir.path().join("source.sqlite");
    let receiver_path=dir.path().join("x.sqlite");
    let wire=packet();
    let trusted=trust();
    let mut source=Journal::open(&source_path).unwrap();
    initial(&mut source,&wire);
    let raw=issue(&mut source,id(31),id(13),&trusted).unwrap();
    assert_eq!(raw.len(),OFFER_LEN);
    let claims=custody_transfer_w8::verify_offer(&raw,&trusted).unwrap();
    assert_eq!(claims.source_id,id(21));
    assert_eq!(claims.target_id,id(13));
    assert_eq!(claims.ciphertext_digest,*blake3::hash(&wire).as_bytes());
    let mut receiver=PeerCustodyStore::open(&receiver_path).unwrap();
    let acceptance=receiver.accept(&raw,&wire,PeerConsent {
        expected_source:id(21),target_id:id(13),target_epoch:7,
        signer:&key(13),trust:&trusted,now_ms:105,
    }).unwrap();
    assert_eq!(acceptance.len(),ACCEPT_LEN);
    let verified=custody_transfer_w8::verify_acceptance(&acceptance,&trusted).unwrap();
    assert_eq!(verified.offer_id,id(31));
    // Receiver COMMITTED while source never got ACK.
    drop(receiver);
    drop(source);
    let mut source=Journal::open(&source_path).unwrap();
    let mut receiver=PeerCustodyStore::open(&receiver_path).unwrap();
    assert_eq!(source.mark_custody_ambiguous(id(31)).unwrap(),
               TransferPhase::Ambiguous);
    assert!(matches!(issue(&mut source,id(32),id(14),&trusted),
        Err(TransferError::Conflict)));
    assert_eq!(issue(&mut source,id(31),id(13),&trusted).unwrap(),raw);
    let recovered=receiver.accept(&raw,&wire,PeerConsent {
        expected_source:id(21),target_id:id(13),target_epoch:7,
        signer:&key(13),trust:&trusted,now_ms:107,
    }).unwrap();
    assert_eq!(recovered,acceptance);
    assert_eq!(source.accept_peer_custody_claim(&recovered,&trusted).unwrap(),
               TransferPhase::PeerClaimed);
    assert_eq!(source.accept_peer_custody_claim(&recovered,&trusted).unwrap(),
               TransferPhase::PeerClaimed);
    assert_eq!(source.state(id(8),id(5)).unwrap(),Delivery::Queued);
    assert_eq!(source.multipath_snapshot(id(8),id(5)).unwrap().allocated,2);
    assert_eq!(source.custody_transfer_snapshot(id(31)).unwrap().phase,
               TransferPhase::PeerClaimed);
    // No ACK ever releases route capacity to a different peer.
    assert!(matches!(issue(&mut source,id(33),id(14),&trusted),
        Err(TransferError::Conflict)));
}

#[test]
fn signed_offer_is_exactly_bound_to_target_slot_and_ciphertext() {
    let dir=tempdir().unwrap();
    let trusted=trust();
    let wire=packet();
    let mut source=Journal::open(&dir.path().join("source.sqlite")).unwrap();
    initial(&mut source,&wire);
    let raw=issue(&mut source,id(31),id(13),&trusted).unwrap();
    let mut x=PeerCustodyStore::open(&dir.path().join("x.sqlite")).unwrap();
    assert!(matches!(x.accept(&raw,&wire,PeerConsent {
        expected_source:id(21),target_id:id(14),target_epoch:8,
        signer:&key(14),trust:&trusted,now_ms:105,
    }),Err(TransferError::Unauthorized)));
    let mut altered=wire.clone();
    *altered.last_mut().unwrap()^=1;
    assert!(matches!(x.accept(&raw,&altered,PeerConsent {
        expected_source:id(21),target_id:id(13),target_epoch:7,
        signer:&key(13),trust:&trusted,now_ms:105,
    }),Err(TransferError::Conflict)));
    let mut forged=raw.clone();forged[100]^=1;
    assert!(matches!(x.accept(&forged,&wire,PeerConsent {
        expected_source:id(21),target_id:id(13),target_epoch:7,
        signer:&key(13),trust:&trusted,now_ms:105,
    }),Err(TransferError::BadSignature)));
    let forged_ack=x.accept(&raw,&wire,PeerConsent {
        expected_source:id(21),target_id:id(13),target_epoch:7,
        signer:&key(13),trust:&trusted,now_ms:105,
    }).unwrap();
    let mut modified=forged_ack.clone();*modified.last_mut().unwrap()^=1;
    assert!(matches!(source.accept_peer_custody_claim(&modified,&trusted),
        Err(TransferError::BadSignature)));
    assert_eq!(source.custody_transfer_snapshot(id(31)).unwrap().phase,
               TransferPhase::Pending);
}

#[test]
fn forged_peer_acceptance_by_other_key_does_not_release_credit() {
    let dir=tempdir().unwrap();
    let trusted=trust();
    let wire=packet();
    let mut source=Journal::open(&dir.path().join("source.sqlite")).unwrap();
    initial(&mut source,&wire);
    let raw=issue(&mut source,id(31),id(13),&trusted).unwrap();
    let mut x=PeerCustodyStore::open(&dir.path().join("x.sqlite")).unwrap();
    let mut ack=x.accept(&raw,&wire,PeerConsent {
        expected_source:id(21),target_id:id(13),target_epoch:7,
        signer:&key(13),trust:&trusted,now_ms:103,
    }).unwrap();
    *ack.last_mut().unwrap()^=1;
    assert!(matches!(source.accept_peer_custody_claim(&ack,&trusted),
        Err(TransferError::BadSignature)));
    assert_eq!(source.state(id(8),id(5)).unwrap(),Delivery::Queued);
    assert_eq!(source.custody_transfer_snapshot(id(31)).unwrap().phase,
               TransferPhase::Pending);
}

#[test]
fn revocation_expired_offer_and_clock_rollback_fail_closed() {
    let dir=tempdir().unwrap();let trusted=trust();let wire=packet();
    let mut source=Journal::open(&dir.path().join("source.sqlite")).unwrap();
    initial(&mut source,&wire);
    let raw=issue(&mut source,id(31),id(13),&trusted).unwrap();
    let mut receiver=PeerCustodyStore::open(&dir.path().join("x.sqlite")).unwrap();
    assert!(matches!(receiver.accept(&raw,&wire,PeerConsent {
        expected_source:id(21),target_id:id(13),target_epoch:7,
        signer:&key(13),trust:&trusted,now_ms:500_000,
    }),Err(TransferError::Expired)));
    let mut revoked=trust();
    revoked.revoke(id(21)).unwrap();
    assert!(matches!(receiver.accept(&raw,&wire,PeerConsent {
        expected_source:id(21),target_id:id(13),target_epoch:7,
        signer:&key(13),trust:&revoked,now_ms:101,
    }),Err(TransferError::Unauthorized)));
    receiver.accept(&raw,&wire,PeerConsent {
        expected_source:id(21),target_id:id(13),target_epoch:7,
        signer:&key(13),trust:&trusted,now_ms:300,
    }).unwrap();
    assert!(matches!(receiver.accept(&raw,&wire,PeerConsent {
        expected_source:id(21),target_id:id(13),target_epoch:7,
        signer:&key(13),trust:&trusted,now_ms:299,
    }),Err(TransferError::ClockRollback)));
    assert!(issue(&mut source,id(31),id(13),&trusted).is_ok());
}

#[test]
fn terminal_recipient_w4_fences_late_custody_offer_and_marks_source_recipient() {
    let dir=tempdir().unwrap();let trusted=trust();let wire=packet();
    let mut source=Journal::open(&dir.path().join("source.sqlite")).unwrap();
    initial(&mut source,&wire);
    let raw=issue(&mut source,id(31),id(13),&trusted).unwrap();
    let mut receiver=PeerCustodyStore::open(&dir.path().join("x.sqlite")).unwrap();
    let peer_ack=receiver.accept(&raw,&wire,PeerConsent {
        expected_source:id(21),target_id:id(13),target_epoch:7,
        signer:&key(13),trust:&trusted,now_ms:104,
    }).unwrap();
    let signed=receipt_w4::sign(&key(8),id(8),id(5),
        *blake3::hash(&wire).as_bytes(),6);
    let final_ack=receipt_w4::verify(&signed,&trusted).unwrap();
    assert_eq!(source.apply_recipient_receipt(&final_ack).unwrap(),
               Delivery::Recipient);
    assert_eq!(source.custody_transfer_snapshot(id(31)).unwrap().phase,
               TransferPhase::RecipientConfirmed);
    assert!(source.multipath_snapshot(id(8),id(5)).unwrap().stopped);
    assert!(matches!(issue(&mut source,id(31),id(13),&trusted),
        Err(TransferError::RecipientConfirmed)));
    assert_eq!(source.accept_peer_custody_claim(&peer_ack,&trusted).unwrap(),
               TransferPhase::RecipientConfirmed);
    assert_eq!(source.retry_bytes(id(8),id(5),105).unwrap(),None);
}

#[test]
fn competing_process_connections_to_one_sender_sqlite_can_issue_only_once() {
    let dir=tempdir().unwrap();let path=dir.path().join("source.sqlite");let wire=packet();
    let mut initial_owner=Journal::open(&path).unwrap();
    initial(&mut initial_owner,&wire);
    drop(initial_owner);
    let mut tasks=Vec::new();
    for offer_id in [id(31),id(32)] {
        let path=path.clone();
        tasks.push(thread::spawn(move || {
            let mut writer=Journal::open(&path).unwrap();
            issue(&mut writer,offer_id,id(13),&trust())
        }));
    }
    let results:Vec<_>=tasks.into_iter().map(|h|h.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|x|x.is_ok()).count(),1);
    assert_eq!(results.iter().filter(|x|matches!(x,Err(TransferError::Conflict))).count(),1);
    let source=Journal::open(&path).unwrap();
    let accepted_offer=custody_transfer_w8::verify_offer(
        results.iter().find_map(|r|r.as_ref().ok()).unwrap(),&trust(),
    ).unwrap();
    assert_eq!(source.custody_transfer_snapshot(accepted_offer.offer_id).unwrap().phase,
               TransferPhase::Pending);
    assert_eq!(source.multipath_snapshot(id(8),id(5)).unwrap().allocated,2);
}

#[test]
fn malicious_issuer_can_sign_two_forks_accepted_by_distinct_sqlite_devices() {
    let dir=tempdir().unwrap();let packet=packet();let trusted=trust();
    // A malicious operator bypasses the issuer ledger and signs both offers
    // for ONE slot. This is expected to be possible, NOT a passing guarantee
    // of global Byzantine K3. A/B independently trust this issuer.
    let same_slot=id(42);let digest=*blake3::hash(&packet).as_bytes();
    let x=OfferClaims {
        source_id:id(21),source_epoch:3,target_id:id(13),target_epoch:7,
        slot_alias:same_slot,offer_id:id(31),
        ciphertext_digest:digest,expires_at_ms:500_000,
    };
    let y=OfferClaims {target_id:id(14),target_epoch:8,offer_id:id(32),..x};
    let offer_x=custody_transfer_w8::sign_offer(x,&key(21)).unwrap();
    let offer_y=custody_transfer_w8::sign_offer(y,&key(21)).unwrap();
    let mut store_x=PeerCustodyStore::open(&dir.path().join("x.sqlite")).unwrap();
    let mut store_y=PeerCustodyStore::open(&dir.path().join("y.sqlite")).unwrap();
    let ack_x=store_x.accept(&offer_x,&packet,PeerConsent {
        expected_source:id(21),target_id:id(13),target_epoch:7,
        signer:&key(13),trust:&trusted,now_ms:105,
    }).unwrap();
    let ack_y=store_y.accept(&offer_y,&packet,PeerConsent {
        expected_source:id(21),target_id:id(14),target_epoch:8,
        signer:&key(14),trust:&trusted,now_ms:105,
    }).unwrap();
    let verified_x=custody_transfer_w8::verify_acceptance(&ack_x,&trusted).unwrap();
    let verified_y=custody_transfer_w8::verify_acceptance(&ack_y,&trusted).unwrap();
    assert_eq!(verified_x.slot_alias,verified_y.slot_alias);
    assert_ne!(verified_x.target_id,verified_y.target_id);
    // Witness/auditor comparison or trusted issuer checkpoint is required
    // to detect and prevent the cheating issuer's conflicting forks.
}
