//! Blue/WOW private W3 v3 and real Ed25519 receipts, without a network.
//! W4 is NOT encrypted on its return path in this lab test.
use akula_wire_lab::crypto_identity_w3::{SignedHeader,TrustedRecipient};
use akula_wire_lab::crypto_w3::{new_recipient,CryptoError};
use akula_wire_lab::private_route_w3::{seal_private,open_authenticated,inspect_route,PUBLIC_HEADER_BYTES};
use akula_wire_lab::custody_receipt_w6::{self,ExpectedCustody,CustodyProofError};
use akula_wire_lab::journal_w4::{Delivery,Insert,Journal,JournalError};
use akula_wire_lab::mailbox_w5::{Mailbox,MailboxLimits,PutStatus};
use akula_wire_lab::receipt_w4;
use akula_wire_lab::trust_w3::TrustRegistry;
use ed25519_dalek::SigningKey;
use tempfile::tempdir;

fn id(v:u8)->[u8;16]{[v;16]}
fn sk(v:u8)->SigningKey { SigningKey::from_bytes(&[v;32]) }
fn header()->SignedHeader {
    SignedHeader {message_id:id(5),recipient_id:id(8),expiry:500_000,
        sender_id:id(9),epoch:4}
}
fn trust(sender:&SigningKey,recipient:&SigningKey,custodian:&SigningKey)->TrustRegistry {
    let mut t=TrustRegistry::new();
    t.enroll(id(9),4,sender.verifying_key()).unwrap();
    t.enroll(id(8),6,recipient.verifying_key()).unwrap();
    t.enroll(id(13),7,custodian.verifying_key()).unwrap();
    t
}

#[test]
fn private_w3_real_ed25519_hpke_custodians_hold_exact_bytes() {
    let dir=tempdir().unwrap();
    let sender=sk(9);
    let bob=sk(8);
    let node=sk(13);
    let trust=trust(&sender,&bob,&node);
    let (secret,public)=new_recipient();
    let packet=seal_private(&sender,&public,id(4),header(),b"hello sealed WOW").unwrap();
    assert_eq!(packet[0],3);
    assert_eq!(inspect_route(&packet).unwrap().token,id(4));
    assert!(!packet[..PUBLIC_HEADER_BYTES].windows(16).any(
        |v| v==id(8).as_slice() || v==id(9).as_slice()));

    // Two genuinely separate SQLite files holding the SAME exact W3 bytes.
    let p=dir.path().join("personal.sqlite");
    let y=dir.path().join("public.sqlite");
    for path in [&p,&y] {
        let mut store=Mailbox::open(path,MailboxLimits::default()).unwrap();
        assert_eq!(store.put(id(4),id(5),100,200,&packet).unwrap(),PutStatus::Stored);
        assert_eq!(store.put(id(4),id(5),100,200,&packet).unwrap(),PutStatus::Duplicate);
        drop(store);
        let reopened=Mailbox::open(path,MailboxLimits::default()).unwrap();
        let got=reopened.get_page(id(4),101,None,1).unwrap();
        assert_eq!(got.len(),1);
        assert_eq!(got[0].bytes,packet);
    }

    // Custodian signs ONLY its storage statement; not the recipient W4.
    let proof=custody_receipt_w6::sign_after_store(
        &node,id(13),id(41),id(5),&packet,7,300_000).unwrap();
    let checked=custody_receipt_w6::verify(&proof,ExpectedCustody {
        custodian_id:id(13),slot_id:id(41),message_id:id(5),
        ciphertext:&packet,now_ms:100_000,
    },&trust).unwrap();
    assert_eq!(checked.ciphertext_digest(),*blake3::hash(&packet).as_bytes());

    // Bob alone opens authenticated W3, then commits a REAL Ed25519 W4.
    let opened=open_authenticated(&packet,TrustedRecipient {
        secret:&secret,recipient_id:id(8),now:100_000,registry:&trust,
    },id(4)).unwrap();
    assert_eq!(opened.header().sender_id,id(9));
    assert_eq!(opened.payload(),b"hello sealed WOW");
    let inbox=dir.path().join("bob.sqlite");
    let receipt;
    {
        let mut journal=Journal::open(&inbox).unwrap();
        let (insert,r)=journal.accept_private_authenticated_and_queue_receipt(
            &packet,TrustedRecipient{
                secret:&secret,recipient_id:id(8),now:100_000,registry:&trust,
            },id(4),&bob,6).unwrap();
        assert_eq!(insert,Insert::New);
        receipt=r;
    }
    {
        let mut journal=Journal::open(&inbox).unwrap();
        let (insert,replayed)=journal.accept_private_authenticated_and_queue_receipt(
            &packet,TrustedRecipient{
                secret:&secret,recipient_id:id(8),now:100_000,registry:&trust,
            },id(4),&bob,6).unwrap();
        assert_eq!(insert,Insert::Duplicate);
        assert_eq!(receipt,replayed);
        assert_eq!(journal.queued_recipient_receipt(id(9),id(5)).unwrap(),Some(receipt.clone()));
    }
    let verified=receipt_w4::verify(&receipt,&trust).unwrap();
    assert_eq!(verified.packet_digest(),*blake3::hash(&packet).as_bytes());
    let mut alice=Journal::open(&dir.path().join("alice.sqlite")).unwrap();
    alice.enqueue(id(8),id(5),500_000,&packet).unwrap();
    assert_eq!(alice.apply_recipient_receipt(&verified).unwrap(),Delivery::Recipient);
    assert_eq!(alice.retry_bytes(id(8),id(5),101).unwrap(),None);
}

#[test]
fn private_w3_wrong_invitation_revoked_sender_and_legacy_v2_fail_closed() {
    let sender=sk(9);let bob=sk(8);let node=sk(13);
    let (secret,public)=new_recipient();
    let mut registry=trust(&sender,&bob,&node);
    let wire=seal_private(&sender,&public,id(4),header(),b"private").unwrap();
    let open=|trust:&TrustRegistry,token|open_authenticated(
        &wire,TrustedRecipient {secret:&secret,recipient_id:id(8),
            now:100,registry:trust},token).err();
    assert_eq!(open(&registry,id(77)),Some(CryptoError::InvalidRecipient));
    registry.revoke(id(9)).unwrap();
    assert_eq!(open(&registry,id(4)),Some(CryptoError::UnauthorizedSender));
    registry.enroll(id(9),5,sender.verifying_key()).unwrap();
    assert_eq!(open(&registry,id(4)),Some(CryptoError::UnauthorizedSender));
    let dir=tempdir().unwrap();
    let mut journal=Journal::open(&dir.path().join("recipient.sqlite")).unwrap();
    assert!(matches!(journal.accept_private_authenticated_and_queue_receipt(
        &wire,TrustedRecipient {secret:&secret,recipient_id:id(8),
            now:100,registry:&registry},id(4),&bob,6
    ),Err(JournalError::Unauthorized)));
    assert!(journal.queued_recipient_receipt(id(9),id(5)).unwrap().is_none());

    let mut changed=wire;
    changed[17]^=1;
    assert!(open_authenticated(&changed,TrustedRecipient {secret:&secret,
        recipient_id:id(8),now:100,registry:&registry},id(4)).is_err());
}

#[test]
fn custodian_proof_rejects_changed_bytes_revocation_forgery_and_old_epoch() {
    let sender=sk(9);let bob=sk(8);let node=sk(13);
    let mut registry=trust(&sender,&bob,&node);
    let packet=b"opaque signed-and-encrypted-test-placeholder";
    let proof=custody_receipt_w6::sign_after_store(
        &node,id(13),id(41),id(5),packet,7,400).unwrap();
    let expected=||ExpectedCustody{
        custodian_id:id(13),slot_id:id(41),message_id:id(5),
        ciphertext:packet,now_ms:100,
    };
    assert!(custody_receipt_w6::verify(&proof,expected(),&registry).is_ok());
    assert!(matches!(custody_receipt_w6::verify(&proof,ExpectedCustody{
        slot_id:id(42),..expected()},&registry),Err(CustodyProofError::WrongScope)));
    assert!(matches!(custody_receipt_w6::verify(&proof,ExpectedCustody{
        ciphertext:b"changed",..expected()},&registry),Err(CustodyProofError::WrongCiphertext)));
    let mut forged=proof.clone();*forged.last_mut().unwrap()^=1;
    assert!(matches!(custody_receipt_w6::verify(&forged,expected(),&registry),
        Err(CustodyProofError::InvalidSignature)));
    assert!(matches!(custody_receipt_w6::verify(&proof,ExpectedCustody{
        now_ms:400,..expected()},&registry),Err(CustodyProofError::Expired)));
    registry.revoke(id(13)).unwrap();
    assert!(matches!(custody_receipt_w6::verify(&proof,expected(),&registry),
        Err(CustodyProofError::UntrustedCustodian)));
    // The storage statement has no conversion into W4.
    assert_eq!(receipt_w4::verify(&proof,&registry).err(),
        Some(receipt_w4::ReceiptError::InvalidLength));
}
