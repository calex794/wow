use akula_wire_lab::journal_w4::{Delivery,Insert,Journal,JournalError};
use tempfile::tempdir;
fn a(n:u8)->[u8;16]{[n;16]}
#[test] fn restart_exact_ciphertext_and_receipt_levels(){
 let d=tempdir().unwrap();let p=d.path().join("journal.sqlite");
 let ciphertext=vec![0,1,2,254,255];
 {let mut j=Journal::open(&p).unwrap();
  assert_eq!(j.enqueue(a(1),a(2),900,&ciphertext).unwrap(),Insert::New);
  assert_eq!(j.record_verified_receipt(a(1),a(2),Delivery::Gateway).unwrap(),Delivery::Gateway);
 }
 {let mut j=Journal::open(&p).unwrap();
  assert_eq!(j.retry_bytes(a(1),a(2),100).unwrap(),Some(ciphertext.clone()));
  assert_eq!(j.enqueue(a(1),a(2),900,&ciphertext).unwrap(),Insert::Duplicate);
  assert!(matches!(j.enqueue(a(1),a(2),900,b"conflict"),Err(JournalError::Conflict)));
  assert_eq!(j.record_verified_receipt(a(1),a(2),Delivery::Neighbor).unwrap(),Delivery::Gateway);
  assert_eq!(j.state(a(1),a(2)).unwrap(),Delivery::Gateway);
  assert!(matches!(j.record_verified_receipt(a(1),a(2),Delivery::Recipient),Err(JournalError::InvalidState)));
  assert_eq!(j.retry_bytes(a(1),a(2),100).unwrap(),Some(ciphertext.clone()));
 }
}
#[test] fn inbox_idempotent_across_restart_and_scoped_to_sender(){
 let d=tempdir().unwrap();let p=d.path().join("inbox.sqlite");
 {let mut j=Journal::open(&p).unwrap();
  assert_eq!(j.accept_verified(a(3),a(8),b"packet").unwrap(),Insert::New);
 }
 {let mut j=Journal::open(&p).unwrap();
  assert_eq!(j.accept_verified(a(3),a(8),b"packet").unwrap(),Insert::Duplicate);
  assert!(matches!(j.accept_verified(a(3),a(8),b"changed"),Err(JournalError::Conflict)));
  assert_eq!(j.accept_verified(a(4),a(8),b"changed").unwrap(),Insert::New);
 }
}
#[test] fn ttl_and_input_limits(){
 let d=tempdir().unwrap();let p=d.path().join("expiry.sqlite");
 let mut j=Journal::open(&p).unwrap();
 assert_eq!(j.enqueue(a(1),a(2),200,b"msg").unwrap(),Insert::New);
 assert_eq!(j.retry_bytes(a(1),a(2),200).unwrap(),None);
 assert!(matches!(j.enqueue(a(1),a(3),300,&vec![0;16385]),Err(JournalError::TooLarge)));
 assert_eq!(j.retry_bytes(a(1),a(2),100).unwrap(),Some(b"msg".to_vec()));
}
#[test] fn missing_message_cannot_be_marked_as_delivered(){
 let d=tempdir().unwrap();let p=d.path().join("missing.sqlite");
 let mut j=Journal::open(&p).unwrap();
 assert!(matches!(j.record_verified_receipt(a(1),a(2),Delivery::Recipient),Err(JournalError::InvalidState)));
 assert!(matches!(j.retry_bytes(a(1),a(2),1),Err(JournalError::NotFound)));
}
