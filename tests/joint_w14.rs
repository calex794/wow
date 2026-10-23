use akula_wire_lab::{
 causal_w12::{CausalRequest,verify_w12_signed_claim},
 custody_transfer_w8::{self,OfferClaims},
 custody_witness_w9::{WitnessStore,WitnessObservation},
 journal_w4::Journal,private_route_w3,crypto_identity_w3::SignedHeader,crypto_w3,
 joint_w14::{sign_joint_against_w10,verify_joint_against_w10},witness_pin_w10::WitnessPinStore,trust_w3::TrustRegistry
};
use ed25519_dalek::SigningKey;
fn id(n:u8)->[u8;16]{[n;16]}
#[test]
fn private_joint_w8_w9_w12_rejects_cross_message_replay_and_mutation(){
 let dir=tempfile::tempdir().unwrap();
 let sender=SigningKey::from_bytes(&[7;32]);
 let keeper=SigningKey::from_bytes(&[8;32]);
 let witness=SigningKey::from_bytes(&[17;32]);
 let mut trust=TrustRegistry::new();
 trust.enroll(id(8),1,keeper.verifying_key()).unwrap();
 trust.enroll(id(17),9,witness.verifying_key()).unwrap();
 let (_,pk)=crypto_w3::new_recipient();
 let packet=private_route_w3::seal_private(&sender,&pk,id(9),SignedHeader{
   sender_id:id(7),recipient_id:id(3),message_id:id(4),expiry:10_000_000,epoch:1,
 },b"joint W14 private evidence").unwrap();
 let mut j=Journal::open(&dir.path().join("keeper.sqlite")).unwrap();
 j.enqueue_w3_with_causal(CausalRequest{
   private_scope:id(5),custodian_id:id(8),custodian_epoch:1,
   recipient:id(3),message:id(4),expiry_ms:10_000_000,
 },&packet,&keeper,&trust).unwrap();
 let proof=j.export_w12_signed_head(id(5),id(8),&trust).unwrap().unwrap();
 let verified=verify_w12_signed_claim(&proof,&trust).unwrap();
 let offer=custody_transfer_w8::sign_offer(OfferClaims{
   source_id:id(8),source_epoch:1,target_id:id(13),target_epoch:7,
   slot_alias:id(21),offer_id:id(31),
   ciphertext_digest:verified.packet_digest,expires_at_ms:500_000,
 },&keeper).unwrap();
 let mut w=WitnessStore::open(&dir.path().join("w9.sqlite"),id(17),9).unwrap();
 let cp=match w.observe(&offer,&witness,&trust).unwrap(){
    WitnessObservation::FirstSeen(x)=>x,_=>panic!("fork")
 };
 let mut pin=WitnessPinStore::open(&dir.path().join("w10.sqlite"),id(17),9).unwrap();
 pin.pin(&cp,&trust).unwrap();
 let receipt=sign_joint_against_w10(&offer,&cp,&proof,id(5),id(17),9,&witness,&trust,&pin).unwrap();
 assert!(verify_joint_against_w10(&receipt,&offer,&cp,&proof,id(5),id(17),&trust,&pin).is_ok());
 let mut wrong=receipt.clone();
 *wrong.last_mut().unwrap()^=1;
 assert!(verify_joint_against_w10(&wrong,&offer,&cp,&proof,id(5),id(17),&trust,&pin).is_err());
 assert!(verify_joint_against_w10(&receipt,&offer,&cp,&proof,id(6),id(17),&trust,&pin).is_err());
 let mut bad_offer=offer.clone();
 *bad_offer.last_mut().unwrap()^=1;
 assert!(verify_joint_against_w10(&receipt,&bad_offer,&cp,&proof,id(5),id(17),&trust,&pin).is_err());
 // Even a newly signed offer for the same message cannot be substituted.
 let alternate=custody_transfer_w8::sign_offer(OfferClaims{
   source_id:id(8),source_epoch:1,target_id:id(14),target_epoch:7,
   slot_alias:id(22),offer_id:id(32),
   ciphertext_digest:verified.packet_digest,expires_at_ms:500_000,
 },&keeper).unwrap();
 assert!(verify_joint_against_w10(&receipt,&alternate,&cp,&proof,id(5),id(17),&trust,&pin).is_err());
}
