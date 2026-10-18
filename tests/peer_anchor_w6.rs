//! W6 rollback tests: an operator-authenticated, independently retained
//! checkpoint must survive when the LOCAL SQLite policy DB is replaced with
//! an older snapshot. The test anchor is in-memory only and is explicitly NOT
//! an HSM or a deployable cross-reboot anti-rollback mechanism.
#![cfg(feature="iroh-transport")]
#[path="support/w6_memory_anchor.rs"]
mod w6_memory_anchor;

use akula_wire_lab::peer_enrollment_w6::{
    AnchorError, EnrollmentError, EndpointRouteBinding, OperatorChange,
    PeerEnrollmentDb, PolicyOperation, TrustedPolicyAnchor, sign_operator_change,
};
use ed25519_dalek::SigningKey;
use iroh::EndpointId;
use rusqlite::Connection;
use std::fs;
use std::path::Path;
use tempfile::tempdir;
use w6_memory_anchor::MemoryAnchor;

fn id(n:u8)->[u8;16]{[n;16]}
fn root()->SigningKey{SigningKey::from_bytes(&[220;32])}
fn binding()->EndpointRouteBinding{
    let signer=SigningKey::from_bytes(&[9;32]);
    EndpointRouteBinding{
        endpoint_id:EndpointId::from_bytes(&signer.verifying_key().to_bytes()).unwrap(),
        w3_device_id:id(9),w3_epoch:3,
        relay_id:id(10),namespace:id(11),route_token:id(12),issuer_id:id(13),
    }
}
fn signed(revision:u64,operation:PolicyOperation)->Vec<u8>{
    sign_operator_change(&root(),&OperatorChange{
        operation,revision,binding:binding(),
    }).unwrap()
}
fn allowed(policy:&mut PeerEnrollmentDb, anchor:&MemoryAnchor)->Result<([u8;16],u64),EnrollmentError>{
    let b=binding();
    policy.authorize_anchored(
        anchor,&b.endpoint_id,&b.relay_id,&b.namespace,&b.route_token,&b.issuer_id
    )
}
fn try_store(policy:&mut PeerEnrollmentDb,anchor:&MemoryAnchor,called:&mut bool)
    ->Result<(),EnrollmentError>
{
    let b=binding();
    policy.with_anchored_write(
        anchor,&b.endpoint_id,&b.relay_id,&b.namespace,
        &b.route_token,&b.issuer_id,
        |_| {*called=true; Ok(())}
    )
}
fn seeded_policy(path:&Path)->(PeerEnrollmentDb,MemoryAnchor){
    let mut policy=PeerEnrollmentDb::open(path,root().verifying_key()).unwrap();
    policy.apply_signed(&signed(1,PolicyOperation::Allow)).unwrap();
    // Laboratory fixture only; production bootstrap MUST use a separate
    // trusted ceremony to provision a durable, nonrollbackable anchor.
    let anchor=MemoryAnchor::new(policy.checkpoint().unwrap());
    (policy,anchor)
}
fn checkpoint_flush(path:&Path) {
    let conn=Connection::open(path).unwrap();
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);").unwrap();
}

#[test]
fn old_sqlite_snapshot_after_revocation_cannot_resurrect_tls_route() {
    let tmp=tempdir().unwrap();
    let path=tmp.path().join("policy.sqlite");
    let saved=tmp.path().join("policy-old.sqlite");
    let (policy,anchor)=seeded_policy(&path);
    let initial=policy.checkpoint().unwrap();
    drop(policy);
    checkpoint_flush(&path);
    fs::copy(&path,&saved).unwrap();

    let mut current=PeerEnrollmentDb::open(&path,root().verifying_key()).unwrap();
    current.apply_signed_anchored(
        &signed(2,PolicyOperation::Revoke),&anchor
    ).unwrap();
    assert_ne!(initial,anchor.observed());
    assert_eq!(anchor.observed().revision,2);
    assert!(matches!(allowed(&mut current,&anchor),Err(EnrollmentError::Revoked)));
    drop(current);
    checkpoint_flush(&path);

    // Attacker restores an actual *full old SQLite database file*, while
    // the independently trusted anchor retains revision 2 and its digest.
    fs::copy(&saved,&path).unwrap();
    let mut restored=PeerEnrollmentDb::open(&path,root().verifying_key()).unwrap();
    assert_eq!(restored.last_revision().unwrap(),1);
    // Without an external anchor, this old snapshot would authorize the key:
    let b=binding();
    assert_eq!(
        restored.authorize(
            &b.endpoint_id,&b.relay_id,&b.namespace,&b.route_token,&b.issuer_id
        ).unwrap(),(id(9),3)
    );
    // In W6 network ingress both early and FINAL commit gates fail closed.
    assert!(matches!(
        allowed(&mut restored,&anchor),
        Err(EnrollmentError::CheckpointMismatch)
    ));
    let mut callback_called=false;
    assert!(matches!(
        try_store(&mut restored,&anchor,&mut callback_called),
        Err(EnrollmentError::CheckpointMismatch)
    ));
    assert!(!callback_called);
    assert!(matches!(
        restored.apply_signed_anchored(&signed(2,PolicyOperation::Revoke),&anchor),
        Err(EnrollmentError::CheckpointMismatch)
    ));
}

#[test]
fn mutation_at_same_revision_is_detected_by_canonical_full_state_digest() {
    let tmp=tempdir().unwrap();let path=tmp.path().join("policy.sqlite");
    let (policy,anchor)=seeded_policy(&path);
    drop(policy);
    let sql=Connection::open(&path).unwrap();
    sql.execute(
        "UPDATE w6_peer_enrollments SET revoked=1 WHERE endpoint=?1",
        rusqlite::params![binding().endpoint_id.as_bytes().as_slice()],
    ).unwrap();
    drop(sql);
    let mut restored=PeerEnrollmentDb::open(&path,root().verifying_key()).unwrap();
    assert_eq!(restored.last_revision().unwrap(),1);
    assert_eq!(anchor.observed().revision,1);
    assert!(matches!(
        allowed(&mut restored,&anchor),Err(EnrollmentError::CheckpointMismatch)
    ));
    let mut called=false;
    assert!(matches!(
        try_store(&mut restored,&anchor,&mut called),
        Err(EnrollmentError::CheckpointMismatch)
    ));
    assert!(!called);
}

#[test]
fn unreachable_external_anchor_fails_closed_for_read_and_write_and_revoke() {
    let tmp=tempdir().unwrap();let path=tmp.path().join("policy.sqlite");
    let (mut policy,anchor)=seeded_policy(&path);
    anchor.set_unavailable(true);
    assert!(matches!(
        allowed(&mut policy,&anchor),
        Err(EnrollmentError::Anchor(AnchorError::Unavailable))
    ));
    let mut called=false;
    assert!(matches!(
        try_store(&mut policy,&anchor,&mut called),
        Err(EnrollmentError::Anchor(AnchorError::Unavailable))
    ));
    assert!(!called);
    assert!(matches!(
        policy.apply_signed_anchored(&signed(2,PolicyOperation::Revoke),&anchor),
        Err(EnrollmentError::Anchor(AnchorError::Unavailable))
    ));
    assert_eq!(policy.last_revision().unwrap(),1);
    anchor.set_unavailable(false);
    assert_eq!(allowed(&mut policy,&anchor).unwrap(),(id(9),3));
}

#[test]
fn anchor_cas_failure_rolls_back_uncommitted_local_revocation() {
    let tmp=tempdir().unwrap();let path=tmp.path().join("policy.sqlite");
    let (mut policy,anchor)=seeded_policy(&path);
    struct RejectAdvance<'a>(&'a MemoryAnchor);
    impl TrustedPolicyAnchor for RejectAdvance<'_> {
        fn current(&self)->Result<akula_wire_lab::peer_enrollment_w6::PolicyCheckpoint,AnchorError>{
            self.0.current()
        }
        fn advance(
            &self,_old:akula_wire_lab::peer_enrollment_w6::PolicyCheckpoint,
            _new:akula_wire_lab::peer_enrollment_w6::PolicyCheckpoint,
        )->Result<(),AnchorError>{Err(AnchorError::Conflict)}
    }
    assert!(matches!(
        policy.apply_signed_anchored(
            &signed(2,PolicyOperation::Revoke),&RejectAdvance(&anchor)
        ),
        Err(EnrollmentError::Anchor(AnchorError::Conflict))
    ));
    assert_eq!(policy.last_revision().unwrap(),1);
    assert_eq!(allowed(&mut policy,&anchor).unwrap(),(id(9),3));
    // A later successful anchored mutation advances the trusted high-water
    // mark BEFORE the SQLite commit and locks the revoked route.
    policy.apply_signed_anchored(
        &signed(2,PolicyOperation::Revoke),&anchor
    ).unwrap();
    assert_eq!(anchor.observed().revision,2);
    assert!(matches!(allowed(&mut policy,&anchor),Err(EnrollmentError::Revoked)));
}

#[test]
fn externally_advanced_checkpoint_without_local_commit_blocks_all_intake() {
    let tmp=tempdir().unwrap();let path=tmp.path().join("policy.sqlite");
    let (mut policy,anchor)=seeded_policy(&path);
    let before=anchor.observed();
    // Simulate crash between external advance and SQLite COMMIT by deriving
    // a valid later digest from a separate copy, then advancing the trusted
    // anchor while the original local policy still has revision 1.
    let shadow=tmp.path().join("shadow.sqlite");
    let (mut alternate,_shadow_anchor)=seeded_policy(&shadow);
    alternate.apply_signed(&signed(2,PolicyOperation::Revoke)).unwrap();
    let next=alternate.checkpoint().unwrap();
    assert_eq!(next.revision,2);
    anchor.advance(before,next).unwrap();
    assert_eq!(policy.last_revision().unwrap(),1);
    assert!(matches!(
        allowed(&mut policy,&anchor),Err(EnrollmentError::CheckpointMismatch)
    ));
    let mut called=false;
    assert!(matches!(
        try_store(&mut policy,&anchor,&mut called),
        Err(EnrollmentError::CheckpointMismatch)
    ));
    assert!(!called);
    // No silent fallback to stale local rev=1 is permitted.
}

#[test]
fn signed_forward_rotation_updates_checkpoint_and_remains_usable() {
    let tmp=tempdir().unwrap();let path=tmp.path().join("policy.sqlite");
    let (mut policy,anchor)=seeded_policy(&path);
    let old=anchor.observed();
    let mut rotated=binding();
    rotated.w3_epoch=4;
    let signed_rotate=sign_operator_change(&root(),&OperatorChange{
        operation:PolicyOperation::Allow,revision:2,binding:rotated,
    }).unwrap();
    policy.apply_signed_anchored(&signed_rotate,&anchor).unwrap();
    assert_ne!(old,anchor.observed());
    assert_eq!(anchor.observed(),policy.checkpoint().unwrap());
    assert_eq!(allowed(&mut policy,&anchor).unwrap(),(id(9),4));
    drop(policy);
    let mut restarted=PeerEnrollmentDb::open(&path,root().verifying_key()).unwrap();
    assert_eq!(allowed(&mut restarted,&anchor).unwrap(),(id(9),4));
}
