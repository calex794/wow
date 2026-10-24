//! W6 signed crash-gap recovery: exact remote high-water determines whether
//! a durable offline-authorized pending intent is aborted or safely replayed.
#![cfg(feature = "iroh-transport")]

use akula_wire_lab::peer_enrollment_w6::{
    sign_anchor_transition, sign_operator_change, AnchorError, AuthorityDomainId, EndpointRouteBinding,
    EnrollmentError, EnrollmentLookup, OperatorChange, PeerEnrollmentDb,
    PolicyCheckpoint, PolicyOperation, SignedRecoveryOutcome, TrustedPolicyAnchor,
};
use ed25519_dalek::SigningKey;
use iroh::{EndpointId, SecretKey};
use std::sync::Mutex;
use tempfile::tempdir;
use rusqlite::{params, Connection};

#[derive(Clone, Copy)]
enum CasBehavior { CommitThenLoseReply, FailBeforeCas, CommitAndAck, LateConflict }

struct Anchor {
    checkpoint: Mutex<PolicyCheckpoint>,
    behavior: Mutex<CasBehavior>,
}


impl TrustedPolicyAnchor for Anchor {
    fn authority_domain(&self)->Option<AuthorityDomainId>{Some(authority())}
    fn current(&self) -> Result<PolicyCheckpoint, AnchorError> {
        Ok(*self.checkpoint.lock().unwrap())
    }
    fn advance(&self, _: PolicyCheckpoint, _: PolicyCheckpoint) -> Result<(), AnchorError> {
        Err(AnchorError::InvalidAttestation)
    }
    fn advance_signed(
        &self, old: PolicyCheckpoint, next: PolicyCheckpoint,
        _: &[u8], _: &[u8],
    ) -> Result<(), AnchorError> {
        let mut state=self.checkpoint.lock().unwrap();
        if *state!=old { return Err(AnchorError::Conflict); }
        match *self.behavior.lock().unwrap() {
            CasBehavior::FailBeforeCas => Err(AnchorError::Unavailable),
            CasBehavior::CommitThenLoseReply => {
                *state=next;
                Err(AnchorError::Unavailable) // CAS committed; response lost
            },
            CasBehavior::CommitAndAck => {
                *state=next;
                Ok(())
            },
            CasBehavior::LateConflict => {
                // The in-flight original CAS commits just before recovery's
                // reissued CAS, causing Conflict rather than new success.
                *state=next;
                Err(AnchorError::Conflict)
            },
        }
    }
}
fn signer() -> SigningKey { SigningKey::from_bytes(&[172;32]) }
fn authority()->AuthorityDomainId {AuthorityDomainId::new([90;32]).unwrap()}
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
fn setup(behavior:CasBehavior)->(tempfile::TempDir,PeerEnrollmentDb,Anchor) {
    let dir=tempdir().unwrap();
    let path=dir.path().join("policy.sqlite");
    let mut db=PeerEnrollmentDb::open(&path,signer().verifying_key()).unwrap();
    db.apply_signed(&change(1,PolicyOperation::Allow)).unwrap();
    let cp=db.checkpoint().unwrap();
    drop(db);
    let db=PeerEnrollmentDb::open_for_authority(
        &path,signer().verifying_key(),authority(),
    ).unwrap();
    let anchor=Anchor {
        checkpoint:Mutex::new(cp),
        behavior: Mutex::new(behavior),
    };
    (dir,db,anchor)
}

#[test]
fn signed_intent_survives_unknown_cas_result_and_recovery_commits_exact_policy() {
    let (dir,mut db,anchor)=setup(CasBehavior::CommitThenLoseReply);
    let signed=change(2,PolicyOperation::Revoke);
    let (old,next)=db.preview_signed_update(&signed).unwrap();
    let proof=sign_anchor_transition(&signer(),authority(),&signed,old,next).unwrap();
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
    let mut reopened=PeerEnrollmentDb::open_for_authority(
        &dir.path().join("policy.sqlite"),signer().verifying_key(),authority(),
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
fn failed_before_remote_cas_remains_pending_until_exact_signed_forward_recovery() {
    let (dir,mut db,anchor)=setup(CasBehavior::FailBeforeCas);
    let signed=change(2,PolicyOperation::Revoke);
    let (old,next)=db.preview_signed_update(&signed).unwrap();
    let proof=sign_anchor_transition(&signer(),authority(),&signed,old,next).unwrap();
    // Unlike an invalid signature, the valid intent MUST be durably staged
    // before the test authority refuses the outbound CAS.
    assert!(matches!(
        db.apply_signed_anchored_with_proof(&signed,&proof,&anchor),
        Err(EnrollmentError::Anchor(AnchorError::Unavailable))
    ));
    assert_eq!(db.checkpoint().unwrap(),old);
    assert!(matches!(
        db.authorize_anchored(&anchor,lookup(&binding())),
        Err(EnrollmentError::PendingRecovery)
    ));
    drop(db);
    let mut reopened=PeerEnrollmentDb::open_for_authority(
        &dir.path().join("policy.sqlite"),signer().verifying_key(),authority(),
    ).unwrap();
    assert!(matches!(
        reopened.recover_pending_signed_update(&anchor),
        Err(EnrollmentError::Anchor(AnchorError::Unavailable))
    ));
    assert_eq!(*anchor.checkpoint.lock().unwrap(),old);
    assert_eq!(reopened.checkpoint().unwrap(),old);
    assert!(matches!(
        reopened.authorize_anchored(&anchor,lookup(&binding())),
        Err(EnrollmentError::PendingRecovery)
    ));
    // Connectivity returns. The pending preauthorized signature can be
    // forwarded without re-signing or permitting a new digest.
    *anchor.behavior.lock().unwrap()=CasBehavior::CommitAndAck;
    assert_eq!(
        reopened.recover_pending_signed_update(&anchor).unwrap(),
        SignedRecoveryOutcome::ForwardedPending
    );
    assert_eq!(*anchor.checkpoint.lock().unwrap(),next);
    assert_eq!(reopened.checkpoint().unwrap(),next);
    assert!(matches!(
        reopened.authorize_anchored(&anchor,lookup(&binding())),
        Err(EnrollmentError::Revoked)
    ));
    assert_eq!(
        reopened.recover_pending_signed_update(&anchor).unwrap(),
        SignedRecoveryOutcome::NoPending
    );
}

#[test]
fn remote_checkpoint_divergence_holds_pending_and_denies_access() {
    let (dir,mut db,anchor)=setup(CasBehavior::CommitThenLoseReply);
    let signed=change(2,PolicyOperation::Revoke);
    let (old,next)=db.preview_signed_update(&signed).unwrap();
    let proof=sign_anchor_transition(&signer(),authority(),&signed,old,next).unwrap();
    assert!(db.apply_signed_anchored_with_proof(&signed,&proof,&anchor).is_err());
    *anchor.checkpoint.lock().unwrap()=PolicyCheckpoint {
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
    drop(db);
    let mut reopened=PeerEnrollmentDb::open_for_authority(
        &dir.path().join("policy.sqlite"),signer().verifying_key(),authority(),
    ).unwrap();
    assert!(matches!(
        reopened.recover_pending_signed_update(&anchor),
        Err(EnrollmentError::CheckpointMismatch)
    ));
    assert_eq!(reopened.checkpoint().unwrap(),old);
    assert!(matches!(
        reopened.with_anchored_write::<(),EnrollmentError,_>(
            &anchor,lookup(&binding()),|_|Ok(())),
        Err(EnrollmentError::PendingRecovery)
    ));
}

#[test]
fn successful_signed_cas_commits_local_policy_and_removes_pending() {
    let (_dir,mut db,anchor)=setup(CasBehavior::CommitAndAck);
    let signed=change(2,PolicyOperation::Revoke);
    let (old,next)=db.preview_signed_update(&signed).unwrap();
    let proof=sign_anchor_transition(&signer(),authority(),&signed,old,next).unwrap();
    db.apply_signed_anchored_with_proof(&signed,&proof,&anchor).unwrap();
    assert_eq!(db.checkpoint().unwrap(),next);
    assert_eq!(
        db.recover_pending_signed_update(&anchor).unwrap(),
        SignedRecoveryOutcome::NoPending
    );
    assert!(matches!(
        db.authorize_anchored(&anchor,lookup(&binding())),
        Err(EnrollmentError::Revoked)
    ));
}

#[test]
fn journal_signature_tampering_does_not_enable_recovery_or_access() {
    let (dir,mut db,anchor)=setup(CasBehavior::CommitThenLoseReply);
    let signed=change(2,PolicyOperation::Revoke);
    let (old,next)=db.preview_signed_update(&signed).unwrap();
    let proof=sign_anchor_transition(&signer(),authority(),&signed,old,next).unwrap();
    assert!(db.apply_signed_anchored_with_proof(&signed,&proof,&anchor).is_err());
    drop(db);
    let path=dir.path().join("policy.sqlite");
    let sql=Connection::open(&path).unwrap();
    let mut bad=proof;
    bad[0]^=1;
    sql.execute(
        "UPDATE w6_pending_transition SET signed_proof=?1 WHERE singleton=1",
        params![bad.as_slice()],
    ).unwrap();
    drop(sql);
    let mut reopened=PeerEnrollmentDb::open_for_authority(&path,signer().verifying_key(),authority()).unwrap();
    assert!(matches!(
        reopened.recover_pending_signed_update(&anchor),
        Err(EnrollmentError::InvalidSignature)
    ));
    assert_eq!(reopened.checkpoint().unwrap(),old);
    assert!(matches!(
        reopened.authorize_anchored(&anchor,lookup(&binding())),
        Err(EnrollmentError::PendingRecovery)
    ));
}


#[test]
fn delayed_original_cas_racing_retry_recovers_without_losing_intent() {
    let (dir,mut db,anchor)=setup(CasBehavior::FailBeforeCas);
    let signed=change(2,PolicyOperation::Revoke);
    let (old,next)=db.preview_signed_update(&signed).unwrap();
    let proof=sign_anchor_transition(&signer(),authority(),&signed,old,next).unwrap();
    assert!(matches!(
        db.apply_signed_anchored_with_proof(&signed,&proof,&anchor),
        Err(EnrollmentError::Anchor(AnchorError::Unavailable))
    ));
    assert_eq!(db.checkpoint().unwrap(),old);
    drop(db);
    *anchor.behavior.lock().unwrap()=CasBehavior::LateConflict;
    let mut reopened=PeerEnrollmentDb::open_for_authority(
        &dir.path().join("policy.sqlite"),signer().verifying_key(),authority(),
    ).unwrap();
    assert_eq!(
        reopened.recover_pending_signed_update(&anchor).unwrap(),
        SignedRecoveryOutcome::ForwardedPending
    );
    assert_eq!(reopened.checkpoint().unwrap(),next);
    assert_eq!(
        reopened.recover_pending_signed_update(&anchor).unwrap(),
        SignedRecoveryOutcome::NoPending
    );
}

#[test]
fn mismatched_authority_scope_blocks_read_write_and_signed_recovery() {
    let (dir,mut db,anchor)=setup(CasBehavior::CommitThenLoseReply);
    assert!(matches!(
        PeerEnrollmentDb::open(
            &dir.path().join("policy.sqlite"),signer().verifying_key(),
        ),
        Err(EnrollmentError::AuthorityMismatch)
    ));
    assert!(matches!(
        PeerEnrollmentDb::open_for_authority(
            &dir.path().join("policy.sqlite"),signer().verifying_key(),
            AuthorityDomainId::new([91;32]).unwrap(),
        ),
        Err(EnrollmentError::AuthorityMismatch)
    ));

    struct WrongScope<'a>(&'a Anchor);
    impl TrustedPolicyAnchor for WrongScope<'_> {
        fn authority_domain(&self)->Option<AuthorityDomainId>{
            Some(AuthorityDomainId::new([91;32]).unwrap())
        }
        fn current(&self)->Result<PolicyCheckpoint,AnchorError>{self.0.current()}
        fn advance(
            &self,old:PolicyCheckpoint,new:PolicyCheckpoint,
        )->Result<(),AnchorError>{self.0.advance(old,new)}
    }
    let wrong=WrongScope(&anchor);
    assert!(matches!(
        db.authorize_anchored(&wrong,lookup(&binding())),
        Err(EnrollmentError::AuthorityMismatch)
    ));
    let mut callback=false;
    let res:Result<(),EnrollmentError>=db.with_anchored_write(
        &wrong,lookup(&binding()),|_|{callback=true;Ok(())}
    );
    assert!(matches!(res,Err(EnrollmentError::AuthorityMismatch)));
    assert!(!callback);
    assert!(matches!(
        db.apply_signed(&change(2,PolicyOperation::Revoke)),
        Err(EnrollmentError::AuthorityMismatch)
    ));
    let change=change(2,PolicyOperation::Revoke);
    let (old,next)=db.preview_signed_update(&change).unwrap();
    let proof=sign_anchor_transition(&signer(),authority(),&change,old,next).unwrap();
    assert!(matches!(
        db.apply_signed_anchored_with_proof(&change,&proof,&wrong),
        Err(EnrollmentError::AuthorityMismatch)
    ));
    assert!(matches!(
        db.apply_signed_anchored_with_proof(&change,&proof,&anchor),
        Err(EnrollmentError::Anchor(AnchorError::Unavailable))
    ));
    assert!(matches!(
        db.recover_pending_signed_update(&wrong),
        Err(EnrollmentError::AuthorityMismatch)
    ));
}
