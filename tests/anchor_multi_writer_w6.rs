//! W6 policy authority with five independently pinned QUIC writer keys.
//! Tests exercise identity-specific fences, replay, and exact-slot recovery.
#![cfg(feature="iroh-transport")]

use akula_wire_lab::peer_enrollment_w6::{
    AuthorityDomainId, EndpointRouteBinding, OperatorChange, PolicyCheckpoint,
    PolicyOperation, sign_anchor_transition, sign_operator_change,
};
use akula_wire_lab::remote_anchor_w6::{
    AnchorServicePolicy, OrphanFenceRecoveryOrder, RemoteAnchorError,
    RemoteAnchorLedger, sign_orphan_recovery_operator,
    sign_orphan_recovery_witness,
};
use ed25519_dalek::SigningKey;
use iroh::{EndpointId, SecretKey};
use tempfile::tempdir;

fn key(n:u8)->EndpointId { SecretKey::from_bytes(&[n;32]).public() }
fn operator()->SigningKey { SigningKey::from_bytes(&[220;32]) }
fn witness()->SigningKey { SigningKey::from_bytes(&[234;32]) }
fn domain()->AuthorityDomainId { AuthorityDomainId::new([90;32]).unwrap() }
fn cp(revision:u64,value:u8)->PolicyCheckpoint {
    PolicyCheckpoint {revision,digest:[value;32]}
}
fn policy()->AnchorServicePolicy {
    AnchorServicePolicy {
        reader:key(41),
        additional_readers:[Some(key(49)),Some(key(50)),Some(key(51)),Some(key(52))],
        administrator:key(42),authority:domain(),
        operator:operator().verifying_key(),
        recovery_witness:witness().verifying_key(),
    }
}
fn signed_revoke(old:PolicyCheckpoint,next:PolicyCheckpoint)->(Vec<u8>,[u8;64]) {
    let binding=EndpointRouteBinding {
        endpoint_id:key(7),w3_device_id:[1;16],w3_epoch:1,
        relay_id:[2;16],namespace:[3;16],route_token:[4;16],issuer_id:[5;16],
    };
    let change=sign_operator_change(&operator(),&OperatorChange {
        operation:PolicyOperation::Revoke,revision:next.revision,binding,
    }).unwrap();
    let proof=sign_anchor_transition(&operator(),domain(),&change,old,next).unwrap();
    (change,proof)
}
fn recovery_order(
    ledger:&RemoteAnchorLedger,new_reader:EndpointId,
)->(OrphanFenceRecoveryOrder,[u8;64],[u8;64]){
    let observed=ledger.inspect_orphan_fence().unwrap().unwrap();
    let order=OrphanFenceRecoveryOrder {
        authority:observed.authority,previous_reader:observed.reader,
        replacement_reader:new_reader,checkpoint:observed.checkpoint,
        nonce:observed.nonce,generation:observed.next_generation,
    };
    (order,sign_orphan_recovery_operator(&operator(),&order),
     sign_orphan_recovery_witness(&witness(),&order))
}

#[test]
fn five_unique_reader_tls_keys_share_one_exclusive_signed_cas_gate() {
    let dir=tempdir().unwrap();
    let old=cp(1,7);
    let next=cp(2,8);
    let mut ledger=RemoteAnchorLedger::provision(
        &dir.path().join("authority.sqlite"),policy(),old,
    ).unwrap();
    for id in [41,49,50,51,52] {
        assert_eq!(ledger.current_for(key(id)).unwrap(),old);
    }
    for denied in [42,44,220,234] {
        assert!(ledger.begin_write_for(key(denied),old,[3;32]).is_err());
    }
    assert!(matches!(
        ledger.current_for(key(44)),Err(RemoteAnchorError::UntrustedPeer)
    ));
    ledger.begin_write_for(key(49),old,[71;32]).unwrap();
    ledger.begin_write_for(key(49),old,[71;32]).unwrap(); // exact idempotent retry
    for id in [41,50,51,52] {
        assert!(matches!(
            ledger.begin_write_for(key(id),old,[72;32]),
            Err(RemoteAnchorError::Conflict)
        ));
        assert!(matches!(
            ledger.finish_write_for(key(id),old,[71;32]),
            Err(RemoteAnchorError::Conflict)
        ));
    }
    let (change,proof)=signed_revoke(old,next);
    assert!(matches!(
        ledger.advance_for(key(42),old,next,&change,&proof),
        Err(RemoteAnchorError::Conflict)
    ));
    ledger.finish_write_for(key(49),old,[71;32]).unwrap();
    ledger.begin_write_for(key(41),old,[73;32]).unwrap();
    ledger.finish_write_for(key(41),old,[73;32]).unwrap();
    ledger.advance_for(key(42),old,next,&change,&proof).unwrap();
    for id in [41,49,50,51,52] {
        assert!(matches!(
            ledger.begin_write_for(key(id),old,[74;32]),
            Err(RemoteAnchorError::Conflict)
        ));
    }
}

#[test]
fn exact_secondary_reader_orphan_rotation_preserves_other_four_writers() {
    let dir=tempdir().unwrap();
    let path=dir.path().join("authority.sqlite");
    let old=cp(1,8);
    let mut first=RemoteAnchorLedger::provision(&path,policy(),old).unwrap();
    first.begin_write_for(key(50),old,[91;32]).unwrap();
    let mut maintenance=RemoteAnchorLedger::open(&path,policy()).unwrap();
    let (order,op,witness)=recovery_order(&maintenance,key(60));
    assert_eq!(order.previous_reader,key(50));
    // A valid pair of signatures cannot rotate to another already
    // authorized writer: that would conflate physical failure domains.
    for forbidden in [41,49,51,52,42,220,234] {
        let mut bad=order;
        bad.replacement_reader=key(forbidden);
        let signed_op=sign_orphan_recovery_operator(&operator(),&bad);
        let signed_witness=sign_orphan_recovery_witness(&self::witness(),&bad);
        assert!(matches!(
            maintenance.recover_orphan_after_external_isolation(
                &bad,&signed_op,&signed_witness,
            ),
            Err(RemoteAnchorError::UntrustedRecovery)
        ));
    }
    maintenance.recover_orphan_after_external_isolation(
        &order,&op,&witness
    ).unwrap();
    assert!(maintenance.inspect_orphan_fence().unwrap().is_none());
    assert!(matches!(
        first.begin_write_for(key(50),old,[92;32]),
        Err(RemoteAnchorError::ConfigurationMismatch)
    ));
    for id in [41,49,51,52,60] {
        assert_eq!(maintenance.current_for(key(id)).unwrap(),old);
    }
    assert!(matches!(
        maintenance.current_for(key(50)),
        Err(RemoteAnchorError::UntrustedPeer)
    ));
    assert!(RemoteAnchorLedger::open(&path,policy()).is_err());
    let mut new_policy=policy();
    new_policy.additional_readers[1]=Some(key(60));
    let mut reopened=RemoteAnchorLedger::open(&path,new_policy).unwrap();
    reopened.begin_write_for(key(60),old,[93;32]).unwrap();
    reopened.finish_write_for(key(60),old,[93;32]).unwrap();
    let (change,proof)=signed_revoke(old,cp(2,9));
    reopened.advance_for(key(42),old,cp(2,9),&change,&proof).unwrap();
    assert!(reopened.recover_orphan_after_external_isolation(
        &order,&op,&witness
    ).is_err());
}

#[test]
fn pinned_reader_registry_requires_exact_match_and_unique_roles() {
    let dir=tempdir().unwrap();
    let path=dir.path().join("bad.sqlite");
    for duplicate in [41,42,49,220,234] {
        let mut bad=policy();
        bad.additional_readers[3]=Some(key(duplicate));
        assert!(matches!(
            RemoteAnchorLedger::provision(&path,bad,cp(1,1)),
            Err(RemoteAnchorError::ConfigurationMismatch)
        ));
        assert!(!path.exists());
    }
    let valid=dir.path().join("valid.sqlite");
    drop(RemoteAnchorLedger::provision(&valid,policy(),cp(1,1)).unwrap());
    let mut missing=policy();
    missing.additional_readers[1]=None;
    assert!(matches!(
        RemoteAnchorLedger::open(&valid,missing),
        Err(RemoteAnchorError::ConfigurationMismatch)
    ));
    let mut reordered=policy();
    reordered.additional_readers.swap(0,1);
    assert!(matches!(
        RemoteAnchorLedger::open(&valid,reordered),
        Err(RemoteAnchorError::ConfigurationMismatch)
    ));
    assert_eq!(
        RemoteAnchorLedger::open(&valid,policy()).unwrap()
            .current_for(key(52)).unwrap(),cp(1,1)
    );
}
