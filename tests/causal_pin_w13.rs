use akula_wire_lab::{causal_w12::CausalCommitment,causal_pin_w13::{ExternalCausalPin,Check,PinError}};
fn c(n:u64, b:u8)->CausalCommitment{CausalCommitment{seq:n,digest:[b;32]}}
#[test]
fn independent_pin_survives_simulated_source_rollback(){
 let temp=tempfile::tempdir().unwrap();
 let path=temp.path().join("observer.sqlite");
 let scope=[7;16];let node=[8;16];
 let mut pin=ExternalCausalPin::open(&path).unwrap();
 assert_eq!(pin.compare(scope,node,None).unwrap(),Check::NoPin);
 pin.pin_observed(scope,node,c(1,11)).unwrap();
 pin.pin_observed(scope,node,c(2,12)).unwrap();
 drop(pin);
 let mut pin=ExternalCausalPin::open(&path).unwrap();
 assert_eq!(pin.compare(scope,node,Some(c(1,11))).unwrap(),Check::Rollback);
 assert_eq!(pin.compare(scope,node,None).unwrap(),Check::Rollback);
 assert_eq!(pin.compare(scope,node,Some(c(2,12))).unwrap(),Check::Match);
 assert!(matches!(pin.pin_observed(scope,node,c(1,11)),Err(PinError::Rollback)));
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
