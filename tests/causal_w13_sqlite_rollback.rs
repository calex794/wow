use akula_wire_lab::{
 causal_w12::{CausalRequest,CausalCommitment},
 causal_pin_w13::{ExternalCausalPin,Check},
 crypto_w3,crypto_identity_w3::SignedHeader,private_route_w3,
 journal_w4::Journal,trust_w3::TrustRegistry
};
use ed25519_dalek::SigningKey;
use std::fs;
fn packet(sender:&SigningKey,pk:&crypto_w3::RecipientPublicKey,message:[u8;16])->Vec<u8>{
 private_route_w3::seal_private(sender,pk,[9;16],SignedHeader{
  sender_id:[7;16],recipient_id:[3;16],message_id:message,expiry:10_000_000,epoch:1
 },b"sealed snapshot test").unwrap()
}
#[test]
fn real_sqlite_custodian_snapshot_rollback_detected_by_separate_observer(){
 let root=tempfile::tempdir().unwrap();
 let db=root.path().join("custodian.sqlite");
 let snapshot=root.path().join("old.sqlite");
 let observer=root.path().join("observer.sqlite");
 let sender=SigningKey::from_bytes(&[7;32]);
 let keeper=SigningKey::from_bytes(&[8;32]);
 let mut trust=TrustRegistry::new();
 trust.enroll([8;16],1,keeper.verifying_key()).unwrap();
 let (_,pk)=crypto_w3::new_recipient();
 let mut witness=ExternalCausalPin::open(&observer).unwrap();
 let save=|j:&mut Journal,message:[u8;16],p:Vec<u8>|->CausalCommitment{
  j.enqueue_w3_with_causal(CausalRequest{
   private_scope:[5;16],custodian_id:[8;16],custodian_epoch:1,
   recipient:[3;16],message,expiry_ms:10_000_000
  },&p,&keeper,&trust).unwrap()
 };
 let first={
  let mut j=Journal::open(&db).unwrap();
  let h=save(&mut j,[4;16],packet(&sender,&pk,[4;16]));
  assert_eq!(h.seq,1);
  h
 };
 fs::copy(&db,&snapshot).unwrap();
 let second={
  let mut j=Journal::open(&db).unwrap();
  let h=save(&mut j,[5;16],packet(&sender,&pk,[5;16]));
  assert_eq!(h.seq,2);
  let signed=j.export_w12_signed_head([5;16],[8;16],&trust).unwrap().unwrap();
  witness.pin_signed_claim(&signed,[5;16],[8;16],&trust).unwrap();
  h
 };
 assert_eq!(witness.compare([5;16],[8;16],Some(second)).unwrap(),Check::Match);
 // Deliberate restore of the *custodian's* earlier complete database.
 // Observer remains intact in independent SQLite file.
 fs::copy(&snapshot,&db).unwrap();
 let restored=Journal::open(&db).unwrap();
 let older=restored.audit_w12([5;16],[8;16],&trust).unwrap().unwrap();
 assert_eq!(older,first);
 assert_eq!(witness.compare([5;16],[8;16],Some(older)).unwrap(),Check::Rollback);
 assert_eq!(witness.compare([5;16],[8;16],None).unwrap(),Check::Rollback);
}
