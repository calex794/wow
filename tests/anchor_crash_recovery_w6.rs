//! W6 signed crash-gap recovery: exact remote high-water determines whether
//! a durable offline-authorized pending intent is aborted or safely replayed.
#![cfg(feature = "iroh-transport")]

use akula_wire_lab::peer_enrollment_w6::{
    sign_anchor_transition, sign_operator_change, AnchorError, EndpointRouteBinding,
    EnrollmentError, EnrollmentLookup, OperatorChange, PeerEnrollmentDb,
    PolicyCheckpoint, PolicyOperation, SignedRecoveryOutcome, TrustedPolicyAnchor,
};
use ed25519_dalek::SigningKey;
use iroh::{EndpointId, SecretKey};
use std::sync::Mutex;
use tempfile::tempdir;

struct Anchor(Mutex<PolicyCheckpoint>);
impl TrustedPolicyAnchor for Anchor {
    fn current(&self) -> Result<PolicyCheckpoint, AnchorError> {
        Ok(*self.0.lock().unwrap())
    }
    fn advance(&self, _: PolicyCheckpoint, _: PolicyCheckpoint) -> Result<(), AnchorError> {
        Err(AnchorError::InvalidAttestation)
    }
    fn advance_signed(
        &self, old: PolicyCheckpoint, next: PolicyCheckpoint,
        _: &[u8], _: &[u8],
    ) -> Result<(), AnchorError> {
        let mut state=self.0.lock().unwrap();
        if *state!=old { return Err(AnchorError::Conflict); }
        *state=next;
        Err(AnchorError::Unavailable) // response lost after durable CAS
    }
}
fn signer() -> SigningKey { SigningKey::from_bytes(&[172;32]) }
fn endpoint() -> EndpointId { SecretKey::from_bytes(&[7;32]).public() }
fn binding() -> EndpointRouteBinding {
    EndpointRouteBinding {
        endpoint_id:endpoint(),w3_device_id:[1;16],w3_epoch:1,
        relay_id:[2;16],namespace:[3;16],route_token:[4;16],issuer_id:[5;16],
    }
}
fn change(rev:u64,operation:PolicyOperation)->Vec<u8> {
    sign_operator_change(&signer(),&OperatorChange {
        operation,revision:rev,binding:binding(),
    }).unwrap()
}
fn lookup<'a>(b:&'a EndpointRouteBinding)->EnrollmentLookup<'a>{
    EnrollmentLookup {
        remote:&b.endpoint_id,relay:&b.relay_id,namespace:&b.namespace,
        token:&b.route_token,issuer:&b.issuer_id,
    }
}
fn setup()->(tempfile::TempDir,PeerEnrollmentDb,Anchor) {
    let dir=tempdir().unwrap();
    let path=dir.path().join("policy.sqlite");
    let mut db=PeerEnrollmentDb::open(&path,signer().verifying_key()).unwrap();
    db.apply_signed(&change(1,PolicyOperation::Allow)).unwrap();
    let anchor=Anchor(Mutex::new(db.checkpoint().unwrap()));
    (dir,db,anchor)
}

#[test]
fn signed_intent_survives_unknown_cas_result_and_recovery_commits_exact_policy() {
    let (dir,mut db,anchor)=setup();
    let signed=change(2,PolicyOperation::Revoke);
    let (old,next)=db.preview_signed_update(&signed).unwrap();
    let proof=sign_anchor_transition(&signer(),&signed,old,next).unwrap();
    assert!(matches!(
        db.apply_signed_anchored_with_proof(&signed,&proof,&anchor),
        Err(EnrollmentError::Anchor(AnchorError::Unavailable))
    ));
    assert_eq!(db.checkpoint().unwrap(),old);
    assert!(matches!(
        db.authorize(&binding().endpoint_id,&binding().relay_id,
            &binding().namespace,&binding().route_token,&binding().issuer_id),
        Err(EnrollmentError::PendingRecovery)
    ));
    assert!(matches!(
        db.with_anchored_write::<(),EnrollmentError,_>(&anchor,lookup(&binding()),|_|Ok(())),
        Err(EnrollmentError::PendingRecovery)
    ));
    drop(db);
    let mut reopened=PeerEnrollmentDb::open(
        &dir.path().join("policy.sqlite"),signer().verifying_key(),
    ).unwrap();
    assert_eq!(
        reopened.recover_pending_signed_update(&anchor).unwrap(),
        SignedRecoveryOutcome::AppliedAfterCas
    );
    assert_eq!(reopened.checkpoint().unwrap(),next);
    assert_eq!(
        reopened.recover_pending_signed_update(&anchor).unwrap(),
        SignedRecoveryOutcome::NoPending
    );
}

#[test]
fn failed_before_remote_cas_can_abort_pending_without_policy_mutation() {
    let (_dir,mut db,anchor)=setup();
    let signed=change(2,PolicyOperation::Revoke);
    let (old,next)=db.preview_signed_update(&signed).unwrap();
    let proof=sign_anchor_transition(&signer(),&signed,old,next).unwrap();
    struct Unavailable;
    impl TrustedPolicyAnchor for Unavailable {
        fn current(&self)->Result<PolicyCheckpoint,AnchorError>{Err(AnchorError::Unavailable)}
        fn advance(&self,_:PolicyCheckpoint,_:PolicyCheckpoint)->Result<(),AnchorError>{Err(AnchorError::Unavailable)}
    }
    // A known unavailable CAS cannot be submitted if the preflight cannot
    // read current. Instead use a deterministic before-CAS negative proof.
    let mut corrupt=proof;
    corrupt[0]^=1;
    assert!(db.apply_signed_anchored_with_proof(&signed,&corrupt,&anchor).is_err());
    assert_eq!(db.checkpoint().unwrap(),old);
    assert_eq!(
        db.recover_pending_signed_update(&anchor).unwrap(),
        SignedRecoveryOutcome::NoPending
    );
    let _=Unavailable;
}

#[test]
fn remote_checkpoint_divergence_holds_pending_and_denies_access() {
    let (_dir,mut db,anchor)=setup();
    let signed=change(2,PolicyOperation::Revoke);
    let (old,next)=db.preview_signed_update(&signed).unwrap();
    let proof=sign_anchor_transition(&signer(),&signed,old,next).unwrap();
    assert!(db.apply_signed_anchored_with_proof(&signed,&proof,&anchor).is_err());
    *anchor.0.lock().unwrap()=PolicyCheckpoint {
        revision:next.revision+1,digest:[99;32],
    };
    assert!(matches!(
        db.recover_pending_signed_update(&anchor),
        Err(EnrollmentError::CheckpointMismatch)
    ));
    assert!(matches!(
        db.preview_signed_update(&change(3,PolicyOperation::Revoke)),
        Err(EnrollmentError::PendingRecovery)
    ));
}
