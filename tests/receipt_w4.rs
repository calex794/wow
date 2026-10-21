use akula_wire_lab::journal_w4::{Delivery,Journal,JournalError};
use akula_wire_lab::receipt_w4::{sign,verify,ReceiptError};
use akula_wire_lab::trust_w3::TrustRegistry;
use ed25519_dalek::SigningKey;
use tempfile::tempdir;
fn id(n:u8)->[u8;16]{[n;16]}
#[test] fn signed_recipient_receipt_is_durable_and_idempotent(){
 let d=tempdir().unwrap();let db=d.path().join("r.sqlite");
 let recipient=id(1);let message=id(2);let bytes=b"ciphertext";
 let signer=SigningKey::from_bytes(&[3;32]);
 let mut trust=TrustRegistry::new();trust.enroll(recipient,7,signer.verifying_key()).unwrap();
 let raw=sign(&signer,recipient,message,*blake3::hash(bytes).as_bytes(),7);
 let receipt=verify(&raw,&trust).unwrap();
 {let mut journal=Journal::open(&db).unwrap();
  journal.enqueue(recipient,message,9999,bytes).unwrap();
  assert_eq!(journal.apply_recipient_receipt(&receipt).unwrap(),Delivery::Recipient);
 }
 {let mut journal=Journal::open(&db).unwrap();
  assert_eq!(journal.state(recipient,message).unwrap(),Delivery::Recipient);
  assert_eq!(journal.apply_recipient_receipt(&receipt).unwrap(),Delivery::Recipient);
  assert_eq!(journal.retry_bytes(recipient,message,1).unwrap(),None);
 }
}
#[test] fn forged_wrong_epoch_revoked_and_wrong_digest_do_not_advance(){
 let d=tempdir().unwrap();let db=d.path().join("s.sqlite");
 let recipient=id(1);let message=id(2);let bytes=b"ciphertext";
 let signer=SigningKey::from_bytes(&[3;32]);let bad=SigningKey::from_bytes(&[4;32]);
 let mut trust=TrustRegistry::new();trust.enroll(recipient,7,signer.verifying_key()).unwrap();
 let digest=*blake3::hash(bytes).as_bytes();
 let mut journal=Journal::open(&db).unwrap();journal.enqueue(recipient,message,9999,bytes).unwrap();
 let wrong=sign(&bad,recipient,message,digest,7);
 assert_eq!(verify(&wrong,&trust),Err(ReceiptError::InvalidSignature));
 let wrong_epoch=sign(&signer,recipient,message,digest,8);
 assert_eq!(verify(&wrong_epoch,&trust),Err(ReceiptError::UntrustedRecipient));
 let mut modified=sign(&signer,recipient,message,digest,7);modified[20]^=1;
 assert_eq!(verify(&modified,&trust),Err(ReceiptError::InvalidSignature));
 let other_digest=sign(&signer,recipient,message,[77;32],7);
 let verified=verify(&other_digest,&trust).unwrap();
 assert!(matches!(journal.apply_recipient_receipt(&verified),Err(JournalError::Conflict)));
 assert_eq!(journal.state(recipient,message).unwrap(),Delivery::Queued);
 trust.revoke(recipient).unwrap();
 assert_eq!(verify(&sign(&signer,recipient,message,digest,7),&trust),Err(ReceiptError::UntrustedRecipient));
 assert_eq!(journal.state(recipient,message).unwrap(),Delivery::Queued);
}
