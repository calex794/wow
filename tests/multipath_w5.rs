//! In-process cryptographic W3/W4 and SQLite multipath regression.
use akula_wire_lab::crypto_identity_w3::{seal,SignedHeader,TrustedRecipient};
use akula_wire_lab::crypto_w3::new_recipient;
use akula_wire_lab::journal_w4::{Delivery,Insert,Journal,JournalError};
use akula_wire_lab::multipath_w5::{Lane,RouteError};
use akula_wire_lab::receipt_w4::{sign,verify,ReceiptError};
use akula_wire_lab::trust_w3::TrustRegistry;
use ed25519_dalek::SigningKey;
use rusqlite::Connection;
use std::sync::{Arc,Barrier};
use std::thread;
use tempfile::tempdir;

fn id(n:u8)->[u8;16]{[n;16]}
const CIPHERTEXT:&[u8]=b"exact opaque ciphertext bytes";

#[test]
fn original_plus_three_lanes_never_exceeds_four_after_restarts_or_lost_acks(){
    let d=tempdir().unwrap();let p=d.path().join("credits.sqlite");
    let forecast;
    {
        let mut j=Journal::open(&p).unwrap();
        assert_eq!(j.enqueue(id(2),id(7),9000,CIPHERTEXT).unwrap(),Insert::New);
        let hint=j.begin_multipath(id(2),id(7),CIPHERTEXT,9000,4,100).unwrap();
        assert_eq!(j.begin_multipath(id(2),id(7),CIPHERTEXT,9000,4,101).unwrap(),hint);
        forecast=j.reserve_multipath(id(2),id(7),CIPHERTEXT,
            id(11),id(21),Lane::Forecast,102).unwrap();
        assert_eq!(forecast.slot,1);
        assert_eq!(j.multipath_snapshot(id(2),id(7)).unwrap().allocated,2);
    }
    {
        let mut j=Journal::open(&p).unwrap();
        // A previously sent attempt was ACK-lost. Reissuing its request ID
        // returns its exact same local record, not another copy credit.
        assert_eq!(j.reserve_multipath(id(2),id(7),CIPHERTEXT,
            id(11),id(21),Lane::Forecast,104).unwrap(),forecast);
        assert!(matches!(j.reserve_multipath(id(2),id(7),CIPHERTEXT,
            id(11),id(99),Lane::Forecast,105),Err(RouteError::Conflict)));
        assert!(matches!(j.reserve_multipath(id(2),id(7),CIPHERTEXT,
            id(15),id(25),Lane::Forecast,103),Err(RouteError::ClockRollback)));
        let explore=j.reserve_multipath(id(2),id(7),CIPHERTEXT,
            id(12),id(22),Lane::Explore,106).unwrap();
        let gateway=j.reserve_multipath(id(2),id(7),CIPHERTEXT,
            id(13),id(23),Lane::Gateway,107).unwrap();
        assert_ne!(forecast.alias,explore.alias);
        assert_ne!(explore.alias,gateway.alias);
        assert_eq!(j.multipath_snapshot(id(2),id(7)).unwrap().allocated,4);
        assert!(matches!(j.reserve_multipath(id(2),id(7),CIPHERTEXT,
            id(14),id(24),Lane::Gateway,108),Err(RouteError::Exhausted)));
        assert!(matches!(j.begin_multipath(id(2),id(7),b"other",9000,4,109),
            Err(RouteError::Conflict)));
        // Gateway and mailbox statuses cannot impersonate recipient W4.
        assert_eq!(j.record_verified_receipt(id(2),id(7),Delivery::Mailbox).unwrap(),
            Delivery::Mailbox);
        assert!(!j.multipath_snapshot(id(2),id(7)).unwrap().stopped);
        assert!(matches!(j.record_verified_receipt(id(2),id(7),Delivery::Recipient),
            Err(JournalError::InvalidState)));
    }
}

#[test]
fn concurrent_connections_cannot_overissue_one_sqlite_quota(){
    let d=tempdir().unwrap();let p=d.path().join("shared.sqlite");
    let mut owner=Journal::open(&p).unwrap();
    owner.enqueue(id(2),id(7),9000,CIPHERTEXT).unwrap();
    owner.begin_multipath(id(2),id(7),CIPHERTEXT,9000,4,100).unwrap();
    drop(owner);
    let shared=Arc::new(p);let gate=Arc::new(Barrier::new(8));
    let mut threads=Vec::new();
    for n in 0..8u8 {
        let path=shared.clone();let gate=gate.clone();
        threads.push(thread::spawn(move||{
            let mut j=Journal::open(path.as_ref()).unwrap();
            gate.wait();
            j.reserve_multipath(id(2),id(7),CIPHERTEXT,
                id(10+n),id(30+n),Lane::Explore,101)
        }));
    }
    let mut accepted=0;let mut exhausted=0;
    for worker in threads{
        match worker.join().unwrap(){
            Ok(_)=>accepted+=1,
            Err(RouteError::Exhausted)=>exhausted+=1,
            Err(e)=>panic!("unexpected concurrency error: {e:?}"),
        }
    }
    assert_eq!((accepted,exhausted),(3,5));
    assert_eq!(Journal::open(shared.as_ref()).unwrap()
        .multipath_snapshot(id(2),id(7)).unwrap().allocated,4);
}

#[test]
fn verified_recipient_w4_fences_all_local_routes_across_restart(){
    let d=tempdir().unwrap();let p=d.path().join("signed.sqlite");
    let signer=SigningKey::from_bytes(&[4;32]);
    let mut trust=TrustRegistry::new();
    trust.enroll(id(2),8,signer.verifying_key()).unwrap();
    let digest=*blake3::hash(CIPHERTEXT).as_bytes();
    {
        let mut j=Journal::open(&p).unwrap();
        j.enqueue(id(2),id(7),9000,CIPHERTEXT).unwrap();
        j.begin_multipath(id(2),id(7),CIPHERTEXT,9000,4,100).unwrap();
        j.reserve_multipath(id(2),id(7),CIPHERTEXT,
            id(11),id(21),Lane::Forecast,101).unwrap();
        let fake=sign(&SigningKey::from_bytes(&[8;32]),id(2),id(7),digest,8);
        assert!(matches!(verify(&fake,&trust),Err(ReceiptError::InvalidSignature)));
        let signed_but_wrong_digest=sign(&signer,id(2),id(7),[9;32],8);
        let wrong=verify(&signed_but_wrong_digest,&trust).unwrap();
        assert!(matches!(j.apply_recipient_receipt(&wrong),Err(JournalError::Conflict)));
        assert_eq!(j.state(id(2),id(7)).unwrap(),Delivery::Queued);
        assert!(!j.multipath_snapshot(id(2),id(7)).unwrap().stopped);
    }
    {
        let mut j=Journal::open(&p).unwrap();
        let raw=sign(&signer,id(2),id(7),digest,8);
        assert_eq!(j.apply_recipient_receipt(&verify(&raw,&trust).unwrap()).unwrap(),
            Delivery::Recipient);
        assert!(j.multipath_snapshot(id(2),id(7)).unwrap().stopped);
        assert!(matches!(j.reserve_multipath(id(2),id(7),CIPHERTEXT,
            id(12),id(22),Lane::Explore,104),Err(RouteError::RecipientConfirmed)));
    }
    assert!(matches!(Journal::open(&p).unwrap()
        .begin_multipath(id(2),id(7),CIPHERTEXT,9000,4,110),
        Err(RouteError::RecipientConfirmed)));
}

#[test]
fn failing_sql_update_rolls_back_recipient_status_and_copy_fence_together(){
    let d=tempdir().unwrap();let p=d.path().join("fault.sqlite");
    let signer=SigningKey::from_bytes(&[4;32]);let mut trust=TrustRegistry::new();
    trust.enroll(id(2),8,signer.verifying_key()).unwrap();
    let raw=sign(&signer,id(2),id(7),*blake3::hash(CIPHERTEXT).as_bytes(),8);
    let verified=verify(&raw,&trust).unwrap();
    {
        let mut j=Journal::open(&p).unwrap();
        j.enqueue(id(2),id(7),9000,CIPHERTEXT).unwrap();
        j.begin_multipath(id(2),id(7),CIPHERTEXT,9000,4,100).unwrap();
    }
    Connection::open(&p).unwrap().execute_batch(
        "CREATE TRIGGER fail_stop BEFORE UPDATE ON multipath_plan
         WHEN NEW.stopped=1 BEGIN SELECT RAISE(ABORT,'injected failure'); END;",
    ).unwrap();
    {
        let mut j=Journal::open(&p).unwrap();
        assert!(matches!(j.apply_recipient_receipt(&verified),Err(JournalError::Db(_))));
        assert_eq!(j.state(id(2),id(7)).unwrap(),Delivery::Queued);
        assert!(!j.multipath_snapshot(id(2),id(7)).unwrap().stopped);
    }
    Connection::open(&p).unwrap().execute_batch("DROP TRIGGER fail_stop;").unwrap();
    let mut j=Journal::open(&p).unwrap();
    assert_eq!(j.apply_recipient_receipt(&verified).unwrap(),Delivery::Recipient);
    assert!(j.multipath_snapshot(id(2),id(7)).unwrap().stopped);
}

#[test]
fn real_w3_packet_three_paths_one_recipient_inbox_and_exact_durable_w4(){
    let d=tempdir().unwrap();
    let origin=d.path().join("origin.sqlite");
    let inbox=d.path().join("inbox.sqlite");
    let alice=SigningKey::from_bytes(&[3;32]);
    let bob=SigningKey::from_bytes(&[4;32]);
    let (secret,public)=new_recipient();
    let mut trust=TrustRegistry::new();
    trust.enroll(id(1),3,alice.verifying_key()).unwrap();
    trust.enroll(id(2),4,bob.verifying_key()).unwrap();
    let packet=seal(&alice,&public,SignedHeader{
        message_id:id(7),recipient_id:id(2),expiry:9000,sender_id:id(1),epoch:3,
    },b"one signed private message").unwrap();
    {
        let mut sender=Journal::open(&origin).unwrap();
        sender.enqueue(id(2),id(7),9000,&packet).unwrap();
        sender.begin_multipath(id(2),id(7),&packet,9000,4,100).unwrap();
        for (nonce,peer,lane) in [
            (11u8,21u8,Lane::Forecast),
            (12u8,22u8,Lane::Explore),
            (13u8,23u8,Lane::Gateway)
        ]{
            sender.reserve_multipath(id(2),id(7),&packet,
                id(nonce),id(peer),lane,101).unwrap();
        }
    }
    let receipt;
    {
        let mut recipient=Journal::open(&inbox).unwrap();
        let (first,signed)=recipient.accept_authenticated_and_queue_receipt(
            &packet,TrustedRecipient{
                secret:&secret,recipient_id:id(2),now:100,registry:&trust
            },&bob,4).unwrap();
        assert_eq!(first,Insert::New);
        receipt=signed;
    }
    // Two delayed copies + a dropped first W4 receipt. Recipient deduplicates
    // the same logical message and retries the EXACT saved W4 signature.
    {
        let mut recipient=Journal::open(&inbox).unwrap();
        for _ in 0..2{
            let (status,again)=recipient.accept_authenticated_and_queue_receipt(
                &packet,TrustedRecipient{
                    secret:&secret,recipient_id:id(2),now:101,registry:&trust
                },&bob,4).unwrap();
            assert_eq!(status,Insert::Duplicate);
            assert_eq!(again,receipt);
        }
        assert_eq!(recipient.queued_recipient_receipt(id(1),id(7)).unwrap(),
            Some(receipt.clone()));
    }
    let verified=verify(&receipt,&trust).unwrap();
    {
        let mut sender=Journal::open(&origin).unwrap();
        sender.apply_recipient_receipt(&verified).unwrap();
        assert!(sender.multipath_snapshot(id(2),id(7)).unwrap().stopped);
    }
    assert!(matches!(Journal::open(&origin).unwrap()
        .reserve_multipath(id(2),id(7),&packet,id(14),id(24),Lane::Explore,200),
        Err(RouteError::RecipientConfirmed)));
}
