use akula_wire_lab::{causal_w12::CausalCommitment,causal_pin_w13::{ExternalCausalPin,Check,PinError}};
fn c(n:u64, b:u8)->CausalCommitment{CausalCommitment{seq:n,digest:[b;32]}}
#[test]
fn independent_pin_survives_simulated_source_rollback(){
 let temp=tempfile::tempdir().unwrap();
 let path=temp.path().join("observer.sqlite");
 let scope=[7;16];let node=[8;16];
 let mut pin=ExternalCausalPin::open(&path).unwrap();
 assert_eq!(pin.compare(scope,node,None).unwrap(),Check::NoPin);
 assert!(matches!(pin.pin_observed(scope,node,c(2,12)),Err(PinError::Missing)),
         "a missing genesis must not accept a later unverified head");
 pin.pin_observed(scope,node,c(1,11)).unwrap();
 assert!(matches!(pin.pin_observed(scope,node,c(2,12)),Err(PinError::Missing)),
         "unsigned raw observations must not bypass signed continuation");
 drop(pin);
 let mut pin=ExternalCausalPin::open(&path).unwrap();
 assert_eq!(pin.compare(scope,node,Some(c(1,11))).unwrap(),Check::Match);
 assert_eq!(pin.compare(scope,node,None).unwrap(),Check::Rollback);
 assert!(matches!(pin.compare(scope,node,Some(c(2,12))),Err(PinError::Missing)));
 assert!(matches!(pin.pin_observed(scope,node,c(2,12)),Err(PinError::Missing)));
}
#[test]
fn same_sequence_evidence_forks_freeze(){
 let temp=tempfile::tempdir().unwrap();
 let mut pin=ExternalCausalPin::open(&temp.path().join("observer.sqlite")).unwrap();
 let scope=[7;16];let node=[8;16];
 pin.pin_observed(scope,node,c(1,11)).unwrap();
 assert!(matches!(pin.pin_observed(scope,node,c(1,99)),Err(PinError::Conflict)));
 assert_eq!(pin.compare(scope,node,Some(c(1,11))).unwrap(),Check::Conflict);
 assert!(matches!(pin.pin_observed(scope,node,c(2,12)),Err(PinError::Frozen)));
}
#[test]
fn jumping_head_not_assumed_consistent(){
 let temp=tempfile::tempdir().unwrap();
 let mut pin=ExternalCausalPin::open(&temp.path().join("observer.sqlite")).unwrap();
 let scope=[7;16];let node=[8;16];
 pin.pin_observed(scope,node,c(1,11)).unwrap();
 assert!(matches!(pin.compare(scope,node,Some(c(10,10))),Err(PinError::Missing)));
}


#[test]
fn forged_and_cross_scope_signed_w12_claims_fail_closed() {
 use akula_wire_lab::causal_w12::verify_w12_signed_claim;
 use akula_wire_lab::trust_w3::TrustRegistry;
 use ed25519_dalek::SigningKey;
 let mut trust=TrustRegistry::new();
 let real=SigningKey::from_bytes(&[8;32]);
 trust.enroll([8;16],1,real.verifying_key()).unwrap();
 // Neither an arbitrary head hash nor a malformed short signed envelope
 // may gain a verified W12 identity.
 assert!(verify_w12_signed_claim(&[9;32],&trust).is_err());
 let dir=tempfile::tempdir().unwrap();
 let mut pin=ExternalCausalPin::open(&dir.path().join("p.sqlite")).unwrap();
 assert!(matches!(
     pin.pin_signed_claim(&[9;32],[5;16],[8;16],&trust),
     Err(PinError::Invalid)
 ));
 assert_eq!(pin.compare([5;16],[8;16],None).unwrap(),Check::NoPin);
}


#[test]
fn real_w3_w12_signed_head_is_verified_and_pinned(){
 use akula_wire_lab::{journal_w4::Journal,causal_w12::{CausalRequest,verify_w12_signed_claim},
 private_route_w3,crypto_identity_w3::SignedHeader,crypto_w3,trust_w3::TrustRegistry};
 use ed25519_dalek::SigningKey;
 let t=tempfile::tempdir().unwrap();
 let sender=SigningKey::from_bytes(&[7;32]);
 let custodian=SigningKey::from_bytes(&[8;32]);
 let mut trust=TrustRegistry::new();
 trust.enroll([8;16],1,custodian.verifying_key()).unwrap();
 let (_,pk)=crypto_w3::new_recipient();
 let mut j=Journal::open(&t.path().join("custodian.sqlite")).unwrap();
 let mut append=|id:u8| {
    let packet=private_route_w3::seal_private(&sender,&pk,[9;16],SignedHeader{
       sender_id:[7;16],recipient_id:[3;16],message_id:[id;16],
       expiry:10_000_000,epoch:1
    },b"actual opaque W3 and attested causal head").unwrap();
    let req=CausalRequest{private_scope:[5;16],custodian_id:[8;16],custodian_epoch:1,
        recipient:[3;16],message:[id;16],expiry_ms:10_000_000};
    let head=j.enqueue_w3_with_causal(req,&packet,&custodian,&trust).unwrap();
    let signed=j.export_w12_signed_head([5;16],[8;16],&trust).unwrap().unwrap();
    assert_eq!(verify_w12_signed_claim(&signed,&trust).unwrap().commitment,head);
    (head,signed)
 };
 let (head1,proof1)=append(4);
 let (head2,proof2)=append(5);
 let (head3,proof3)=append(6);
 assert_eq!((head1.seq,head2.seq,head3.seq),(1,2,3));

 let mut no_genesis=ExternalCausalPin::open(&t.path().join("no-genesis.sqlite")).unwrap();
 assert!(matches!(
    no_genesis.pin_signed_claim(&proof2,[5;16],[8;16],&trust),
    Err(PinError::Missing)
 ),"even a valid seq=2 signature cannot bootstrap a missing genesis");

 let mut witness=ExternalCausalPin::open(&t.path().join("witness.sqlite")).unwrap();
 assert_eq!(witness.pin_signed_claim(&proof1,[5;16],[8;16],&trust).unwrap(),head1);
 assert!(matches!(
    witness.pin_signed_claim(&proof3,[5;16],[8;16],&trust),
    Err(PinError::Missing)
 ),"an authenticated seq=3 cannot skip missing seq=2");
 assert_eq!(witness.compare([5;16],[8;16],Some(head1)).unwrap(),Check::Match);

 let mut wrong=ExternalCausalPin::open(&t.path().join("wrong-parent.sqlite")).unwrap();
 wrong.pin_observed([5;16],[8;16],c(1,99)).unwrap();
 assert!(matches!(
    wrong.pin_signed_claim(&proof2,[5;16],[8;16],&trust),
    Err(PinError::Missing)
 ),"the signed seq=2 predecessor must match the independent pin");

 assert_eq!(witness.pin_signed_claim(&proof2,[5;16],[8;16],&trust).unwrap(),head2);
 assert_eq!(witness.pin_signed_claim(&proof3,[5;16],[8;16],&trust).unwrap(),head3);
 assert_eq!(witness.pin_signed_claim(&proof3,[5;16],[8;16],&trust).unwrap(),head3);
 assert!(matches!(
    witness.pin_signed_claim(&proof1,[5;16],[8;16],&trust),
    Err(PinError::Rollback)
 ));
 let mut corrupt=proof3.clone(); *corrupt.last_mut().unwrap()^=1;
 assert!(matches!(witness.pin_signed_claim(&corrupt,[5;16],[8;16],&trust),Err(PinError::Invalid)));
 assert!(matches!(witness.pin_signed_claim(&proof3,[6;16],[8;16],&trust),Err(PinError::Invalid)));
 let mut revoked=trust;revoked.revoke([8;16]).unwrap();
 assert!(witness.pin_signed_claim(&proof3,[5;16],[8;16],&revoked).is_err());
 drop(witness);
 let witness=ExternalCausalPin::open(&t.path().join("witness.sqlite")).unwrap();
 assert_eq!(witness.compare([5;16],[8;16],Some(head3)).unwrap(),Check::Match);
 assert_eq!(witness.compare([5;16],[8;16],Some(head1)).unwrap(),Check::Rollback);
}
