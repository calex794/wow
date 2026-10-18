use akula_wire_lab::crypto_identity_w3::{seal,SignedHeader,TrustedRecipient};
use akula_wire_lab::crypto_w3::new_recipient;
use akula_wire_lab::journal_w4::{Insert,Journal,JournalError};
use akula_wire_lab::receipt_w4::{verify,ReceiptError};
use akula_wire_lab::trust_w3::TrustRegistry;
use ed25519_dalek::SigningKey;
use rusqlite::Connection;
use tempfile::tempdir;
fn id(v:u8)->[u8;16]{[v;16]}
#[test] fn atomically_store_authenticated_message_and_recover_exact_ack() {
 let dir=tempdir().unwrap();let db=dir.path().join("inbox.db");
 let sender=SigningKey::from_bytes(&[1;32]);let recipient=SigningKey::from_bytes(&[2;32]);
 let (secret,public)=new_recipient();let mut trust=TrustRegistry::new();
 trust.enroll(id(1),3,sender.verifying_key()).unwrap();
 trust.enroll(id(2),4,recipient.verifying_key()).unwrap();
 let wire=seal(&sender,&public,SignedHeader{message_id:id(7),recipient_id:id(2),
 expiry:9000,sender_id:id(1),epoch:3},b"test notice").unwrap();
 let signed;
 {let mut journal=Journal::open(&db).unwrap();
  let (status,receipt)=journal.accept_authenticated_and_queue_receipt(&wire,
   TrustedRecipient{secret:&secret,recipient_id:id(2),now:100,registry:&trust},&recipient,4).unwrap();
  assert_eq!(status,Insert::New);
  assert_eq!(verify(&receipt,&trust).unwrap().packet_digest(),*blake3::hash(&wire).as_bytes());
  signed=receipt;
 }
 {let mut journal=Journal::open(&db).unwrap();
  assert_eq!(journal.queued_recipient_receipt(id(1),id(7)).unwrap(),Some(signed.clone()));
  let (status,again)=journal.accept_authenticated_and_queue_receipt(&wire,
   TrustedRecipient{secret:&secret,recipient_id:id(2),now:100,registry:&trust},&recipient,4).unwrap();
  assert_eq!(status,Insert::Duplicate);assert_eq!(again,signed);
 }
}
#[test] fn failure_during_receipt_insert_rolls_back_inbox() {
 let dir=tempdir().unwrap();let db=dir.path().join("fault.db");
 let sender=SigningKey::from_bytes(&[1;32]);let recipient=SigningKey::from_bytes(&[2;32]);
 let (secret,public)=new_recipient();let mut trust=TrustRegistry::new();
 trust.enroll(id(1),3,sender.verifying_key()).unwrap();
 trust.enroll(id(2),4,recipient.verifying_key()).unwrap();
 let wire=seal(&sender,&public,SignedHeader{message_id:id(7),recipient_id:id(2),
 expiry:9000,sender_id:id(1),epoch:3},b"notice").unwrap();
 Journal::open(&db).unwrap();
 {let conn=Connection::open(&db).unwrap();conn.execute_batch("CREATE TRIGGER fail_receipt
  BEFORE INSERT ON receipt_outbox BEGIN SELECT RAISE(ABORT,'simulated failure'); END;").unwrap();}
 {let mut journal=Journal::open(&db).unwrap();
  assert!(matches!(journal.accept_authenticated_and_queue_receipt(&wire,
   TrustedRecipient{secret:&secret,recipient_id:id(2),now:100,registry:&trust},&recipient,4),
   Err(JournalError::Db(_))));
  assert!(journal.queued_recipient_receipt(id(1),id(7)).unwrap().is_none());
 }
 {let conn=Connection::open(&db).unwrap();
  let count:i64=conn.query_row("SELECT COUNT(*) FROM inbox",[],|r|r.get(0)).unwrap();
  assert_eq!(count,0);
  conn.execute_batch("DROP TRIGGER fail_receipt;").unwrap();}
 {let mut journal=Journal::open(&db).unwrap();
  assert_eq!(journal.accept_authenticated_and_queue_receipt(&wire,
   TrustedRecipient{secret:&secret,recipient_id:id(2),now:100,registry:&trust},&recipient,4).unwrap().0,
   Insert::New);
 }
}
#[test] fn untrusted_or_revoked_recipient_never_generates_ack(){
 let dir=tempdir().unwrap();let db=dir.path().join("bad.db");
 let sender=SigningKey::from_bytes(&[1;32]);let recipient=SigningKey::from_bytes(&[2;32]);
 let (secret,public)=new_recipient();let mut trust=TrustRegistry::new();
 trust.enroll(id(1),3,sender.verifying_key()).unwrap();
 let wire=seal(&sender,&public,SignedHeader{message_id:id(7),recipient_id:id(2),
 expiry:9000,sender_id:id(1),epoch:3},b"hello").unwrap();
 let mut journal=Journal::open(&db).unwrap();
 assert!(matches!(journal.accept_authenticated_and_queue_receipt(&wire,
  TrustedRecipient{secret:&secret,recipient_id:id(2),now:100,registry:&trust},&recipient,4),
  Err(JournalError::Unauthorized)));
 trust.enroll(id(2),4,recipient.verifying_key()).unwrap();
 trust.revoke(id(2)).unwrap();
 assert!(matches!(journal.accept_authenticated_and_queue_receipt(&wire,
  TrustedRecipient{secret:&secret,recipient_id:id(2),now:100,registry:&trust},&recipient,4),
  Err(JournalError::Unauthorized)));
 assert_eq!(journal.queued_recipient_receipt(id(1),id(7)).unwrap(),None);
 assert_eq!(verify(&[0u8;137],&trust),Err(ReceiptError::UnsupportedVersion));
}
