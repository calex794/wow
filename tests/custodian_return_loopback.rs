//! Lab A -> C -> B -> C -> A: private W3 -> durable recipient W4 ->
//! opaque HPKE return -> sender-verified exact W4. All TCP is 127.0.0.1;
//! three SQLite files/keys are independent; no physical VPS or public QUIC.
use akula_wire_lab::{
    crypto_identity_w3::{SignedHeader, TrustedRecipient},
    crypto_w3,
    custodian_invitation::{sign_invitation_for_lab, MailboxInvitation},
    custodian_discovery::{sign_list_for_lab, ListClaims},
    custodian_mailbox::{sign_store_for_lab, MailboxPolicy, StoreClaims},
    custodian_return::{
        sign_return_deposit_for_lab, sign_return_read_for_lab,
        sign_return_route_for_lab, ReturnDeposit, ReturnRead, ReturnRoute,
    },
    custodian_wire::{
        bind_test_loopback, client_deposit_return, client_fetch_return,
        client_register_return, client_store_delegated, client_list,
        client_fetch_listed, serve_one_loopback, WireError,
    },
    journal_w4::{Delivery, Insert, Journal},
    private_return_w4::{self, ReturnInvitation},
    private_route_w3,
    trust_w3::TrustRegistry,
};
use ed25519_dalek::SigningKey;
use hpke::{Deserializable, Serializable};
use rusqlite::Connection;
use std::{net::TcpStream, path::{Path,PathBuf}, thread};

const OWNER:[u8;16]=[1;16];
const SENDER:[u8;16]=[7;16];
const CUSTODIAN:[u8;16]=[8;16];
const RECIPIENT:[u8;16]=[3;16];
const MAILBOX:[u8;16]=[11;16];
const SCOPE:[u8;16]=[5;16];
const MESSAGE:[u8;16]=[16;16];
const OFFER:[u8;16]=[12;16];
const SLOT:[u8;16]=[13;16];
const TOKEN:[u8;16]=[9;16];
const RETURN_TAG:[u8;16]=[61;16];
const EXPIRY:i64=10_000_000;

struct Context {
    owner:SigningKey,
    alice:SigningKey,
    bob:SigningKey,
    custodian:SigningKey,
    trust:TrustRegistry,
    bob_hpke_secret:crypto_w3::RecipientSecret,
    alice_hpke_secret:crypto_w3::RecipientSecret,
    alice_hpke_public:crypto_w3::RecipientPublic,
    invite:Vec<u8>,
    signed_store:Vec<u8>,
    w3:Vec<u8>,
    digest:[u8;32],
}
impl Context {
    fn new()->Self{
        let owner=SigningKey::from_bytes(&[1;32]);
        let alice=SigningKey::from_bytes(&[7;32]);
        let bob=SigningKey::from_bytes(&[3;32]);
        let custodian=SigningKey::from_bytes(&[8;32]);
        let mut trust=TrustRegistry::new();
        for (id,key) in [(OWNER,&owner),(SENDER,&alice),(RECIPIENT,&bob),(CUSTODIAN,&custodian)] {
            trust.enroll(id,1,key.verifying_key()).unwrap();
        }
        let (bob_hpke_secret,bob_hpke_public)=crypto_w3::new_recipient();
        let (alice_hpke_secret,alice_hpke_public)=crypto_w3::new_recipient();
        let mut bob_pub=[0u8;32];
        bob_pub.copy_from_slice(&bob_hpke_public.to_bytes());
        let invite=sign_invitation_for_lab(&owner,MailboxInvitation {
            issuer:OWNER,issuer_epoch:1,custodian:CUSTODIAN,mailbox:MAILBOX,
            scope:SCOPE,recipient:RECIPIENT,sender:SENDER,sender_epoch:1,
            offer:OFFER,slot:SLOT,max_packet_bytes:1024,valid_until_ms:EXPIRY,
            recipient_hpke_public:bob_pub,route_token:TOKEN,
        });
        // Sender inserts its secret return route + HPKE public key into
        // the authenticated, encrypted W3 payload addressed only to Bob.
        let mut payload=Vec::new();
        payload.extend_from_slice(&RETURN_TAG);
        payload.extend_from_slice(&alice_hpke_public.to_bytes());
        payload.extend_from_slice(b"private 3-party custodian receipt");
        let w3=private_route_w3::seal_private(
            &alice,&bob_hpke_public,TOKEN,
            SignedHeader {
                sender_id:SENDER,recipient_id:RECIPIENT,
                message_id:MESSAGE,expiry:EXPIRY as u64,epoch:1,
            },&payload,
        ).unwrap();
        let digest=*blake3::hash(&w3).as_bytes();
        let signed_store=sign_store_for_lab(&alice,StoreClaims {
            issuer:OWNER,issuer_epoch:1,custodian:CUSTODIAN,mailbox:MAILBOX,
            scope:SCOPE,recipient:RECIPIENT,message:MESSAGE,
            offer:OFFER,slot:SLOT,expires_at:EXPIRY,grant_until:EXPIRY-1,
            packet_len:w3.len() as u32,digest,
        });
        Self {owner,alice,bob,custodian,trust,bob_hpke_secret,
              alice_hpke_secret,alice_hpke_public,invite,signed_store,w3,digest}
    }
    fn provision(&self,path:&Path){
        let mut j=Journal::open(path).unwrap();
        j.operator_provision_mailbox(MailboxPolicy {
            mailbox:MAILBOX,issuer:OWNER,issuer_epoch:1,custodian:CUSTODIAN,
            scope:SCOPE,recipient:RECIPIENT,max_message_bytes:1024,max_offers:2,
        },&self.trust).unwrap();
    }
    fn route(&self)->ReturnRoute{
        ReturnRoute{sender:SENDER,sender_epoch:1,custodian:CUSTODIAN,
            mailbox:MAILBOX,recipient:RECIPIENT,message:MESSAGE,digest:self.digest,
            expires_at_ms:EXPIRY,tag:RETURN_TAG,grant_until_ms:EXPIRY-1}
    }
    fn deposit(&self,envelope:&[u8])->ReturnDeposit{
        ReturnDeposit{recipient:RECIPIENT,recipient_epoch:1,custodian:CUSTODIAN,
            mailbox:MAILBOX,message:MESSAGE,digest:self.digest,tag:RETURN_TAG,
            envelope_digest:*blake3::hash(envelope).as_bytes(),grant_until_ms:EXPIRY-1}
    }
    fn read(&self)->ReturnRead{
        ReturnRead{sender:SENDER,sender_epoch:1,custodian:CUSTODIAN,
            mailbox:MAILBOX,tag:RETURN_TAG,nonce:[88;16],grant_until_ms:100_000}
    }
}

fn serve(c:&Context,path:&Path, now:i64)
    ->(std::net::SocketAddr,thread::JoinHandle<Result<(),WireError>>){
    let listener=bind_test_loopback().unwrap();
    let addr=listener.local_addr().unwrap();
    let path:PathBuf=path.to_path_buf();
    let signer=c.custodian.clone();
    // Independent trust enrollment snapshot inside the C process.
    let mut trust=TrustRegistry::new();
    for (id,key) in [(OWNER,&c.owner),(SENDER,&c.alice),
                     (RECIPIENT,&c.bob),(CUSTODIAN,&c.custodian)] {
        trust.enroll(id,1,key.verifying_key()).unwrap();
    }
    let job=thread::spawn(move||{
        let mut journal=Journal::open(&path).unwrap();
        serve_one_loopback(&listener,&mut journal,&signer,1,&trust,now)
    });
    (addr,job)
}

fn on_socket<T>(
    c:&Context, db:&Path,now:i64,
    f:impl FnOnce(&mut TcpStream)->Result<T,WireError>,
)->Result<T,WireError>{
    let (addr,job)=serve(c,db,now);
    let mut socket=TcpStream::connect(addr).unwrap();
    let result=f(&mut socket);
    assert!(job.join().unwrap().is_ok());
    result
}
fn count(db:&Path,table:&str)->i64{
    let db=Connection::open(db).unwrap();
    db.query_row(&format!("SELECT COUNT(*) FROM {table}"),[],|r|r.get(0)).unwrap()
}

#[test]
fn encrypted_recipient_w4_survives_custodian_restart_and_updates_sender_only_after_verify(){
    let tmp=tempfile::tempdir().unwrap();
    let server=tmp.path().join("C.sqlite");
    let sender=tmp.path().join("A.sqlite");
    let recipient=tmp.path().join("B.sqlite");
    let c=Context::new();
    c.provision(&server);
    let mut alice_journal=Journal::open(&sender).unwrap();
    alice_journal.enqueue(RECIPIENT,MESSAGE,EXPIRY,&c.w3).unwrap();
    assert_eq!(alice_journal.state(RECIPIENT,MESSAGE).unwrap(),Delivery::Queued);

    // Alice sends exact signed W3 to C under Bob's earlier invitation.
    let claim=on_socket(&c,&server,2,|s|client_store_delegated(
        s,&c.invite,&c.signed_store,&c.w3,&c.trust,
    )).unwrap();
    assert_eq!(claim.store.message,MESSAGE);
    assert_eq!(alice_journal.state(RECIPIENT,MESSAGE).unwrap(),Delivery::Queued);

    // Alice pre-registers one opaque return slot, then disconnects.
    let signed_route=sign_return_route_for_lab(&c.alice,c.route());
    on_socket(&c,&server,3,|s|client_register_return(s,&signed_route)).unwrap();
    // Replaying the exact registration across a new connection does not
    // allocate a second row or authorize a different message.
    on_socket(&c,&server,3,|s|client_register_return(s,&signed_route)).unwrap();
    assert_eq!(count(&server,"custodian_private_w4_return"),1);
    let signed_read=sign_return_read_for_lab(&c.alice,c.read());
    assert!(on_socket(&c,&server,3,|s|
        client_fetch_return(s,&signed_read,RETURN_TAG)).unwrap().is_none());
    assert_eq!(alice_journal.state(RECIPIENT,MESSAGE).unwrap(),Delivery::Queued);

    // Bob was offline while Alice sent. Bob discovers the letter through
    // recipient-signed LIST and downloads exactly those bytes via network.
    let signed_list=sign_list_for_lab(&c.bob,ListClaims {
        issuer:OWNER,issuer_epoch:1,custodian:CUSTODIAN,mailbox:MAILBOX,
        scope:SCOPE,recipient:RECIPIENT,recipient_epoch:1,
        since_seq:0,grant_until_ms:100_000,nonce:[99;16],max_items:2,
    });
    let entries=on_socket(&c,&server,4,|s|client_list(s,&signed_list)).unwrap();
    assert_eq!(entries.len(),1);
    assert_eq!(entries[0].message,MESSAGE);
    assert_eq!(entries[0].digest,c.digest);
    let bob_packet=on_socket(&c,&server,4,|s|
        client_fetch_listed(s,&signed_list,entries[0])).unwrap()
        .expect("encrypted W3 must be retrievable after Alice disconnects");
    assert_eq!(bob_packet,c.w3);

    let mut bob_journal=Journal::open(&recipient).unwrap();
    let verified=private_route_w3::open_authenticated(
        &bob_packet,TrustedRecipient {
            secret:&c.bob_hpke_secret,recipient_id:RECIPIENT,now:4,
            registry:&c.trust,
        },TOKEN,
    ).unwrap();
    let payload=verified.payload();
    assert_eq!(&payload[..16],&RETURN_TAG);
    let reply_pub=crypto_w3::RecipientPublic::from_bytes(&payload[16..48]).unwrap();
    assert_eq!(&payload[48..],b"private 3-party custodian receipt");
    let (insert,w4)=bob_journal.accept_private_authenticated_and_queue_receipt(
        &bob_packet,TrustedRecipient {
            secret:&c.bob_hpke_secret,recipient_id:RECIPIENT,now:4,
            registry:&c.trust,
        },TOKEN,&c.bob,1,
    ).unwrap();
    assert_eq!(insert,Insert::New);
    assert_eq!(bob_journal.queued_recipient_receipt(SENDER,MESSAGE).unwrap(),Some(w4.clone()));

    let opaque=private_return_w4::seal_signed_receipt(&w4,&reply_pub,RETURN_TAG).unwrap();
    let signed_deposit=sign_return_deposit_for_lab(&c.bob,c.deposit(&opaque));
    on_socket(&c,&server,5,|s|client_deposit_return(s,&signed_deposit,&opaque)).unwrap();
    assert_eq!(alice_journal.state(RECIPIENT,MESSAGE).unwrap(),Delivery::Queued);
    // Lost first reply is simulated by an exact idempotent network resend
    // after a separate process reopens C's SQLite.
    on_socket(&c,&server,5,|s|client_deposit_return(s,&signed_deposit,&opaque)).unwrap();
    assert_eq!(count(&server,"custodian_private_w4_return"),1);
    assert_eq!(count(&server,"receipt_outbox"),0,
        "C must never persist Bob's clear W4 in its own inbox");

    // Alice restarts later and retrieves ONLY the opaque envelope.
    drop(alice_journal);
    let fetched=on_socket(&c,&server,6,|s|
        client_fetch_return(s,&signed_read,RETURN_TAG)).unwrap().unwrap();
    assert_eq!(fetched,opaque);
    assert_ne!(fetched,w4);
    let mut alice_journal=Journal::open(&sender).unwrap();
    assert_eq!(alice_journal.state(RECIPIENT,MESSAGE).unwrap(),Delivery::Queued);
    let confirmed=private_return_w4::open_verify_and_apply(
        &fetched,ReturnInvitation{
            expected_tag:RETURN_TAG,sender_secret:&c.alice_hpke_secret,
            expires_at_ms:EXPIRY as u64,now_ms:6,recipient_trust:&c.trust,
        },&mut alice_journal,
    ).unwrap();
    assert_eq!(confirmed,Delivery::Recipient);
    assert_eq!(alice_journal.state(RECIPIENT,MESSAGE).unwrap(),Delivery::Recipient);
    // Repeated reads/receipts are idempotent and do not re-open routes.
    let repeated=on_socket(&c,&server,6,|s|
        client_fetch_return(s,&signed_read,RETURN_TAG)).unwrap().unwrap();
    assert_eq!(repeated,fetched);
    assert_eq!(private_return_w4::open_verify_and_apply(
        &repeated,ReturnInvitation{
            expected_tag:RETURN_TAG,sender_secret:&c.alice_hpke_secret,
            expires_at_ms:EXPIRY as u64,now_ms:6,recipient_trust:&c.trust,
        },&mut alice_journal,
    ).unwrap(),Delivery::Recipient);
    assert_eq!(count(&recipient,"inbox"),1);
    assert_eq!(count(&recipient,"receipt_outbox"),1);
}

#[test]
fn return_slot_requires_sender_identity_exact_w3_and_existing_committed_store(){
    let tmp=tempfile::tempdir().unwrap();
    let path=tmp.path().join("C.sqlite");
    let c=Context::new();
    c.provision(&path);
    let signed_route=sign_return_route_for_lab(&c.alice,c.route());
    assert!(matches!(on_socket(&c,&path,2,|s|
        client_register_return(s,&signed_route)),Err(WireError::Denied)));
    let mut tampered_route=c.route();
    tampered_route.digest[0]^=1;
    let wrong=sign_return_route_for_lab(&c.alice,tampered_route);
    on_socket(&c,&path,2,|s|client_store_delegated(
        s,&c.invite,&c.signed_store,&c.w3,&c.trust)).unwrap();
    assert!(matches!(on_socket(&c,&path,3,|s|
        client_register_return(s,&wrong)),Err(WireError::Denied)));
    let stranger=SigningKey::from_bytes(&[99;32]);
    let forged=sign_return_route_for_lab(&stranger,c.route());
    assert!(matches!(on_socket(&c,&path,3,|s|
        client_register_return(s,&forged)),Err(WireError::Denied)));
    let registered=on_socket(&c,&path,3,|s|
        client_register_return(s,&signed_route));
    assert!(registered.is_ok());
    let mut second=c.route();
    second.tag=[77;16];
    let second_signed=sign_return_route_for_lab(&c.alice,second);
    assert!(matches!(on_socket(&c,&path,3,|s|
        client_register_return(s,&second_signed)),Err(WireError::Denied)));
    assert_eq!(count(&path,"custodian_private_w4_return"),1);
}

#[test]
fn return_deposit_rejects_wrong_signer_modified_envelope_and_alternate_ack(){
    let tmp=tempfile::tempdir().unwrap();
    let path=tmp.path().join("C.sqlite");
    let c=Context::new();
    c.provision(&path);
    on_socket(&c,&path,2,|s|client_store_delegated(
        s,&c.invite,&c.signed_store,&c.w3,&c.trust)).unwrap();
    on_socket(&c,&path,3,|s|client_register_return(
        s,&sign_return_route_for_lab(&c.alice,c.route()))).unwrap();
    let bogus_recipient_w4=akula_wire_lab::receipt_w4::sign(
        &c.bob,RECIPIENT,MESSAGE,c.digest,1,
    );
    let sealed=private_return_w4::seal_signed_receipt(
        &bogus_recipient_w4,&c.alice_hpke_public,RETURN_TAG,
    ).unwrap();
    let authentic=sign_return_deposit_for_lab(&c.bob,c.deposit(&sealed));
    let stranger=SigningKey::from_bytes(&[99;32]);
    let forged=sign_return_deposit_for_lab(&stranger,c.deposit(&sealed));
    assert!(matches!(on_socket(&c,&path,4,|s|
        client_deposit_return(s,&forged,&sealed)),Err(WireError::Denied)));
    let mut altered=sealed.clone();
    *altered.last_mut().unwrap()^=1;
    assert!(matches!(on_socket(&c,&path,4,|s|
        client_deposit_return(s,&authentic,&altered)),Err(WireError::Denied)));
    assert_eq!(count(&path,"receipt_outbox"),0);

    on_socket(&c,&path,4,|s|client_deposit_return(s,&authentic,&sealed)).unwrap();
    // Re-encryption changes bytes even though W4 is logically the same.
    // An ambiguous ACK cannot silently overwrite the original envelope.
    let changed=private_return_w4::seal_signed_receipt(
        &bogus_recipient_w4,&c.alice_hpke_public,RETURN_TAG,
    ).unwrap();
    let changed_proof=sign_return_deposit_for_lab(&c.bob,c.deposit(&changed));
    assert!(matches!(on_socket(&c,&path,4,|s|
        client_deposit_return(s,&changed_proof,&changed)),Err(WireError::Denied)));
}

#[test]
fn read_return_is_sender_only_and_revocation_fences_future_reads(){
    let tmp=tempfile::tempdir().unwrap();
    let path=tmp.path().join("C.sqlite");
    let c=Context::new();
    c.provision(&path);
    on_socket(&c,&path,2,|s|client_store_delegated(
        s,&c.invite,&c.signed_store,&c.w3,&c.trust)).unwrap();
    on_socket(&c,&path,3,|s|client_register_return(
        s,&sign_return_route_for_lab(&c.alice,c.route()))).unwrap();
    let read=sign_return_read_for_lab(&c.alice,c.read());
    let forged=sign_return_read_for_lab(&c.bob,c.read());
    assert!(matches!(on_socket(&c,&path,4,|s|
        client_fetch_return(s,&forged,RETURN_TAG)),Err(WireError::Denied)));
    assert!(on_socket(&c,&path,4,|s|
        client_fetch_return(s,&read,RETURN_TAG)).unwrap().is_none());
    let mut journal=Journal::open(&path).unwrap();
    journal.operator_revoke_fetch(MAILBOX).unwrap();
    drop(journal);
    assert!(matches!(on_socket(&c,&path,4,|s|
        client_fetch_return(s,&read,RETURN_TAG)),Err(WireError::Denied)));
}

#[test]
fn forged_w4_envelope_cannot_mark_sender_recipient_delivered(){
    let tmp=tempfile::tempdir().unwrap();
    let path=tmp.path().join("A.sqlite");
    let c=Context::new();
    let mut sender=Journal::open(&path).unwrap();
    sender.enqueue(RECIPIENT,MESSAGE,EXPIRY,&c.w3).unwrap();
    let forged=akula_wire_lab::receipt_w4::sign(
        &c.custodian,RECIPIENT,MESSAGE,c.digest,1,
    );
    let opaque=private_return_w4::seal_signed_receipt(
        &forged,&c.alice_hpke_public,RETURN_TAG,
    ).unwrap();
    assert!(private_return_w4::open_verify_and_apply(
        &opaque,ReturnInvitation {
            expected_tag:RETURN_TAG,sender_secret:&c.alice_hpke_secret,
            expires_at_ms:EXPIRY as u64,now_ms:5,recipient_trust:&c.trust,
        },&mut sender,
    ).is_err());
    assert_eq!(sender.state(RECIPIENT,MESSAGE).unwrap(),Delivery::Queued);
    // Wrong tag: even a genuine Bob W4 cannot bypass sender's pinned route.
    let valid=akula_wire_lab::receipt_w4::sign(&c.bob,RECIPIENT,MESSAGE,c.digest,1);
    let foreign=private_return_w4::seal_signed_receipt(
        &valid,&c.alice_hpke_public,[45;16],
    ).unwrap();
    assert!(private_return_w4::open_verify_and_apply(
        &foreign,ReturnInvitation {
            expected_tag:RETURN_TAG,sender_secret:&c.alice_hpke_secret,
            expires_at_ms:EXPIRY as u64,now_ms:5,recipient_trust:&c.trust,
        },&mut sender,
    ).is_err());
    assert_eq!(sender.state(RECIPIENT,MESSAGE).unwrap(),Delivery::Queued);
}
