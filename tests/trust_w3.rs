use akula_wire_lab::trust_w3::{TrustRegistry,TrustError};
use akula_wire_lab::crypto_w3::{new_recipient,seal,open,RecipientContext};
use ed25519_dalek::SigningKey;
fn key(n:u8)->SigningKey{SigningKey::from_bytes(&[n;32])}
#[test] fn explicit_enrollment_rotation_revocation() {
 let old=key(3);let next=key(4);let id=[7;16];
 let mut registry=TrustRegistry::new();
 assert_eq!(registry.verify(id,1,&old.verifying_key()),Err(TrustError::Untrusted));
 registry.enroll(id,1,old.verifying_key()).unwrap();
 assert_eq!(registry.verify(id,1,&old.verifying_key()),Ok(()));
 assert_eq!(registry.verify(id,1,&next.verifying_key()),Err(TrustError::WrongKey));
 assert_eq!(registry.enroll(id,1,next.verifying_key()),Err(TrustError::EpochConflict));
 registry.enroll(id,2,next.verifying_key()).unwrap();
 assert_eq!(registry.verify(id,1,&old.verifying_key()),Err(TrustError::WrongEpoch));
 assert_eq!(registry.enroll(id,1,old.verifying_key()),Err(TrustError::EpochRollback));
 registry.revoke(id).unwrap();
 assert_eq!(registry.verify(id,2,&next.verifying_key()),Err(TrustError::Revoked));
 assert_eq!(registry.enroll(id,2,next.verifying_key()),Err(TrustError::Revoked));
 registry.enroll(id,3,old.verifying_key()).unwrap(); // only via privileged re-enrollment
 assert_eq!(registry.verify(id,3,&old.verifying_key()),Ok(()));
}
#[test] fn verifying_key_is_not_file_permission() {
 let alice=key(3);let mallory=key(5);let mut registry=TrustRegistry::new();
 let id=[7;16];let target=[9;16];
 let (secret,public)=new_recipient();
 let packet=seal(&alice,&public,[1;16],target,1000,b"notice").unwrap();
 assert_eq!(registry.verify(id,1,&alice.verifying_key()),Err(TrustError::Untrusted));
 registry.enroll(id,1,alice.verifying_key()).unwrap();
 assert_eq!(registry.verify(id,1,&mallory.verifying_key()),Err(TrustError::WrongKey));
 registry.verify(id,1,&alice.verifying_key()).unwrap();
 assert_eq!(open(&packet,RecipientContext{secret:&secret,
  expected_sender:&alice.verifying_key(),expected_recipient:target,now:100}).unwrap().1,b"notice");
 registry.revoke(id).unwrap();
 assert_eq!(registry.verify(id,1,&alice.verifying_key()),Err(TrustError::Revoked));
 // Application must gate open()/dispatch on the result above. No Sync Core bridge yet.
}
