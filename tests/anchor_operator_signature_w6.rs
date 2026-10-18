//! Direct verifier regression independent of Roha network framing.
//! Offline signer is TEST-ONLY and is never passed to the remote ledger.
#![cfg(feature="iroh-transport")]

use akula_wire_lab::peer_enrollment_w6::{
    sign_anchor_transition, sign_operator_change, verify_operator_change,
    verify_signed_anchor_transition, EndpointRouteBinding, OperatorChange,
    PolicyCheckpoint, PolicyOperation, SIGNED_ENROLLMENT_BYTES,
};
use akula_wire_lab::remote_anchor_w6::{
    AnchorServicePolicy, RemoteAnchorError, RemoteAnchorLedger,
};
use ed25519_dalek::SigningKey;
use iroh::SecretKey;
use tempfile::tempdir;

fn root() -> SigningKey { SigningKey::from_bytes(&[220;32]) }
fn endpoint(n:u8)->iroh::EndpointId{SecretKey::from_bytes(&[n;32]).public()}
fn bind() -> EndpointRouteBinding {
    EndpointRouteBinding {
        endpoint_id:endpoint(5),w3_device_id:[5;16],w3_epoch:3,
        relay_id:[7;16],namespace:[8;16],route_token:[9;16],issuer_id:[10;16],
    }
}
fn cp(n:u64,v:u8)->PolicyCheckpoint{PolicyCheckpoint{revision:n,digest:[v;32]}}
fn policy()->AnchorServicePolicy{
    AnchorServicePolicy {
        reader:endpoint(41),administrator:endpoint(42),
        operator:root().verifying_key(),
    }
}
fn sign(rev:u64)->Vec<u8>{
    sign_operator_change(&root(),&OperatorChange{
        operation:PolicyOperation::Revoke,revision:rev,binding:bind(),
    }).unwrap()
}

#[test]
fn legitimate_offline_dual_signature_is_valid_and_cas_is_monotonic() {
    let dir=tempdir().unwrap();
    let initial=cp(1,1);let next=cp(2,2);
    let mut store=RemoteAnchorLedger::provision(
        &dir.path().join("anchor.sqlite"),policy(),initial,
    ).unwrap();
    let change=sign(2);
    assert_eq!(change.len(),SIGNED_ENROLLMENT_BYTES);
    let action=verify_operator_change(&change,&root().verifying_key()).unwrap();
    assert_eq!(action.revision,2);
    let proof=sign_anchor_transition(&root(),&change,initial,next).unwrap();
    assert_eq!(proof.len(),64);
    verify_signed_anchor_transition(
        &root().verifying_key(),&change,initial,next,&proof,
    ).unwrap();
    assert_eq!(
        store.advance_for(endpoint(42),initial,next,&change,&proof).unwrap(),
        next
    );
    assert_eq!(store.current_for(endpoint(41)).unwrap(),next);
    assert!(matches!(
        store.advance_for(endpoint(42),initial,next,&change,&proof),
        Err(RemoteAnchorError::Conflict)
    ));
}

#[test]
fn direct_anchor_rejects_valid_tls_admin_with_wrong_offline_signature() {
    let dir=tempdir().unwrap();
    let initial=cp(5,5);let next=cp(6,6);
    let mut store=RemoteAnchorLedger::provision(
        &dir.path().join("anchor.sqlite"),policy(),initial,
    ).unwrap();
    let other=SigningKey::from_bytes(&[221;32]);
    let changed=sign_operator_change(&other,&OperatorChange{
        operation:PolicyOperation::Revoke,revision:6,binding:bind(),
    }).unwrap();
    let signature=sign_anchor_transition(&other,&changed,initial,next).unwrap();
    assert!(matches!(
        store.advance_for(endpoint(42),initial,next,&changed,&signature),
        Err(RemoteAnchorError::UntrustedOperatorTransition)
    ));
    assert_eq!(store.current_for(endpoint(41)).unwrap(),initial);
}
