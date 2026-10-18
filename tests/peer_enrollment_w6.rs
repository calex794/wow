//! W6 operator-signed, durable mapping tests. Does NOT accept any network
//! field as an authority and does not open an administrative QUIC endpoint.
#![cfg(feature="iroh-transport")]

use akula_wire_lab::peer_enrollment_w6::{
    sign_operator_change, EndpointRouteBinding, EnrollmentError,
    OperatorChange, PeerEnrollmentDb, PolicyOperation, MAX_ENROLLED_ENDPOINTS,
};
use ed25519_dalek::SigningKey;
use iroh::EndpointId;
use tempfile::tempdir;

fn id(n:u8) -> [u8;16] { [n;16] }
fn endpoint(n:u8) -> EndpointId {
    let signer=SigningKey::from_bytes(&[n;32]);
    EndpointId::from_bytes(&signer.verifying_key().to_bytes()).unwrap()
}
fn root() -> SigningKey { SigningKey::from_bytes(&[220;32]) }
fn binding(n:u8) -> EndpointRouteBinding {
    EndpointRouteBinding {
        endpoint_id:endpoint(n),
        w3_device_id:id(n),
        w3_epoch:3,
        relay_id:id(201),
        namespace:id(202),
        route_token:id(203),
        issuer_id:id(204),
    }
}
fn action(operation:PolicyOperation,revision:u64,binding:EndpointRouteBinding)
    -> OperatorChange
{
    OperatorChange {operation,revision,binding}
}
fn apply(
    store:&mut PeerEnrollmentDb,signer:&SigningKey,op:PolicyOperation,
    rev:u64,b:EndpointRouteBinding,
) -> Result<(),EnrollmentError> {
    let bytes=sign_operator_change(signer,&action(op,rev,b)).unwrap();
    store.apply_signed(&bytes)
}
fn authorize(
    store:&PeerEnrollmentDb,b:EndpointRouteBinding,
) -> Result<([u8;16],u64),EnrollmentError> {
    store.authorize(
        &b.endpoint_id,&b.relay_id,&b.namespace,&b.route_token,&b.issuer_id,
    )
}

#[test]
fn operator_signature_is_required_and_rollbacks_fail_across_restart() {
    let dir=tempdir().unwrap();
    let path=dir.path().join("policy.sqlite");
    let owner=root();
    let attacker=SigningKey::from_bytes(&[221;32]);
    let b=binding(1);
    let mut store=PeerEnrollmentDb::open(&path,owner.verifying_key()).unwrap();

    assert!(matches!(authorize(&store,b),Err(EnrollmentError::UnknownEndpoint)));
    let forged=sign_operator_change(&attacker,&action(PolicyOperation::Allow,1,b)).unwrap();
    assert!(matches!(store.apply_signed(&forged),Err(EnrollmentError::InvalidSignature)));
    let mut altered=sign_operator_change(&owner,&action(PolicyOperation::Allow,1,b)).unwrap();
    altered[113]^=1; // route/issuer claim with an invalidated signature
    assert!(matches!(store.apply_signed(&altered),Err(EnrollmentError::InvalidSignature)));
    assert_eq!(store.last_revision().unwrap(),0);

    apply(&mut store,&owner,PolicyOperation::Allow,1,b).unwrap();
    assert_eq!(authorize(&store,b).unwrap(),(id(1),3));
    assert_eq!(store.last_revision().unwrap(),1);
    drop(store);

    // Reopening with another operator key must NOT silently trust the DB's
    // stored key or allow a new authority to replace a previous root.
    assert!(matches!(
        PeerEnrollmentDb::open(&path,attacker.verifying_key()),
        Err(EnrollmentError::UntrustedOperator)
    ));
    let mut reopened=PeerEnrollmentDb::open(&path,owner.verifying_key()).unwrap();
    assert_eq!(authorize(&reopened,b).unwrap(),(id(1),3));
    assert!(matches!(
        apply(&mut reopened,&owner,PolicyOperation::Allow,1,b),
        Err(EnrollmentError::RevisionRollback)
    ));
    assert_eq!(reopened.last_revision().unwrap(),1);
}

#[test]
fn signed_scope_and_device_identity_are_immutable_except_forward_epoch() {
    let dir=tempdir().unwrap();
    let owner=root();let b=binding(2);
    let mut store=PeerEnrollmentDb::open(
        &dir.path().join("policy.sqlite"),owner.verifying_key()
    ).unwrap();
    apply(&mut store,&owner,PolicyOperation::Allow,1,b).unwrap();

    for changed in [
        EndpointRouteBinding {relay_id:id(88),..b},
        EndpointRouteBinding {namespace:id(88),..b},
        EndpointRouteBinding {route_token:id(88),..b},
        EndpointRouteBinding {issuer_id:id(88),..b},
    ] {
        assert!(matches!(authorize(&store,changed),Err(EnrollmentError::WrongScope)));
        assert!(matches!(
            apply(&mut store,&owner,PolicyOperation::Allow,2,changed),
            Err(EnrollmentError::BindingConflict)
        ));
    }
    let another_device=EndpointRouteBinding {w3_device_id:id(77),w3_epoch:4,..b};
    assert!(matches!(
        apply(&mut store,&owner,PolicyOperation::Allow,2,another_device),
        Err(EnrollmentError::BindingConflict)
    ));
    let old_epoch=EndpointRouteBinding {w3_epoch:3,..b};
    assert!(matches!(
        apply(&mut store,&owner,PolicyOperation::Allow,2,old_epoch),
        Err(EnrollmentError::EpochRollback)
    ));
    assert_eq!(store.last_revision().unwrap(),1);

    let rotated=EndpointRouteBinding {w3_epoch:4,..b};
    apply(&mut store,&owner,PolicyOperation::Allow,2,rotated).unwrap();
    assert_eq!(authorize(&store,rotated).unwrap(),(id(2),4));
    assert_eq!(store.last_revision().unwrap(),2);
}

#[test]
fn signed_revocation_survives_restart_and_cannot_be_undone_for_same_tls_key() {
    let dir=tempdir().unwrap();let path=dir.path().join("policy.sqlite");
    let owner=root();let b=binding(3);
    let mut store=PeerEnrollmentDb::open(&path,owner.verifying_key()).unwrap();
    apply(&mut store,&owner,PolicyOperation::Allow,1,b).unwrap();
    apply(&mut store,&owner,PolicyOperation::Revoke,2,b).unwrap();
    assert!(matches!(authorize(&store,b),Err(EnrollmentError::Revoked)));
    drop(store);

    let mut reopened=PeerEnrollmentDb::open(&path,owner.verifying_key()).unwrap();
    assert!(matches!(authorize(&reopened,b),Err(EnrollmentError::Revoked)));
    let rotated=EndpointRouteBinding {w3_epoch:4,..b};
    assert!(matches!(
        apply(&mut reopened,&owner,PolicyOperation::Allow,3,rotated),
        Err(EnrollmentError::Revoked)
    ));
    assert_eq!(reopened.last_revision().unwrap(),2);
    let newly_keyed=EndpointRouteBinding{endpoint_id:endpoint(4),w3_epoch:4,..b};
    apply(&mut reopened,&owner,PolicyOperation::Allow,3,newly_keyed).unwrap();
    assert_eq!(authorize(&reopened,newly_keyed).unwrap(),(id(3),4));
    assert!(matches!(authorize(&reopened,b),Err(EnrollmentError::Revoked)));
}

#[test]
fn unauthorised_revocation_cannot_mutate_db_or_advance_revision() {
    let dir=tempdir().unwrap();let owner=root();
    let mut store=PeerEnrollmentDb::open(
        &dir.path().join("policy.sqlite"),owner.verifying_key()
    ).unwrap();
    let b=binding(5);
    assert!(matches!(
        apply(&mut store,&owner,PolicyOperation::Revoke,1,b),
        Err(EnrollmentError::UnknownEndpoint)
    ));
    assert_eq!(store.last_revision().unwrap(),0);
    apply(&mut store,&owner,PolicyOperation::Allow,1,b).unwrap();
    let fake=EndpointRouteBinding {route_token:id(77),..b};
    assert!(matches!(
        apply(&mut store,&owner,PolicyOperation::Revoke,2,fake),
        Err(EnrollmentError::BindingConflict)
    ));
    assert_eq!(authorize(&store,b).unwrap(),(id(5),3));
    assert_eq!(store.last_revision().unwrap(),1);
}

#[test]
fn finite_quota_includes_revoked_tombstones_and_cannot_be_bypassed() {
    let dir=tempdir().unwrap();let owner=root();
    let mut store=PeerEnrollmentDb::open(
        &dir.path().join("policy.sqlite"),owner.verifying_key()
    ).unwrap();
    for n in 0..MAX_ENROLLED_ENDPOINTS {
        let b=binding(n as u8);
        apply(&mut store,&owner,PolicyOperation::Allow,(n+1) as u64,b).unwrap();
    }
    let spare=binding(200);
    assert!(matches!(
        apply(&mut store,&owner,PolicyOperation::Allow,
              MAX_ENROLLED_ENDPOINTS as u64+1,spare),
        Err(EnrollmentError::TooManyPeers)
    ));
    assert_eq!(store.last_revision().unwrap(),MAX_ENROLLED_ENDPOINTS as u64);
    // Revoking does not reduce footprint: tombstone prevents resurrecting
    // a captured key after cleanup or process restart.
    apply(&mut store,&owner,PolicyOperation::Revoke,
          MAX_ENROLLED_ENDPOINTS as u64+1,binding(1)).unwrap();
    assert!(matches!(
        apply(&mut store,&owner,PolicyOperation::Allow,
              MAX_ENROLLED_ENDPOINTS as u64+2,spare),
        Err(EnrollmentError::TooManyPeers)
    ));
}

#[test]
fn sqlite_failure_rolls_back_policy_revision_and_record_together() {
    let dir=tempdir().unwrap();let path=dir.path().join("policy.sqlite");
    let owner=root();let b=binding(6);
    let mut store=PeerEnrollmentDb::open(&path,owner.verifying_key()).unwrap();
    // Intentional local injected DB write error on the monotonic watermark.
    let conn=rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch(
        "CREATE TRIGGER break_w6_revision BEFORE UPDATE ON w6_policy_state
         BEGIN SELECT RAISE(ABORT, 'injected W6 fs failure'); END;"
    ).unwrap();
    assert!(matches!(
        apply(&mut store,&owner,PolicyOperation::Allow,1,b),
        Err(EnrollmentError::Db(_))
    ));
    assert_eq!(store.last_revision().unwrap(),0);
    assert!(matches!(authorize(&store,b),Err(EnrollmentError::UnknownEndpoint)));
    conn.execute_batch("DROP TRIGGER break_w6_revision;").unwrap();
    apply(&mut store,&owner,PolicyOperation::Allow,1,b).unwrap();
    assert_eq!(store.last_revision().unwrap(),1);
    assert_eq!(authorize(&store,b).unwrap(),(id(6),3));
}
