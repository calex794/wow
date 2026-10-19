//! Cross-host durable Mailbox writer fence; no QUIC shortcuts or time leases.
//! Direct authority SQLite tests use independently pinned keys and domains.
#![cfg(feature = "iroh-transport")]

use akula_wire_lab::peer_enrollment_w6::{
    sign_anchor_transition, sign_operator_change, AuthorityDomainId,
    EndpointRouteBinding, OperatorChange, PolicyCheckpoint, PolicyOperation,
};
use akula_wire_lab::remote_anchor_w6::{
    AnchorServicePolicy, RemoteAnchorError, RemoteAnchorLedger,
};
use ed25519_dalek::SigningKey;
use iroh::{EndpointId, SecretKey};
use rusqlite::Connection;
use tempfile::tempdir;

fn root()->SigningKey { SigningKey::from_bytes(&[220;32]) }
fn key(n:u8)->EndpointId { SecretKey::from_bytes(&[n;32]).public() }
fn domain()->AuthorityDomainId { AuthorityDomainId::new([90;32]).unwrap() }
fn config()->AnchorServicePolicy {
    AnchorServicePolicy {
        reader:key(41),administrator:key(42),
        operator:root().verifying_key(),authority:domain(),
        recovery_witness:SigningKey::from_bytes(&[234;32]).verifying_key(),
    }
}
fn cp(revision:u64,value:u8)->PolicyCheckpoint {
    PolicyCheckpoint{revision,digest:[value;32]}
}
fn signed_revoke(
    old:PolicyCheckpoint,next:PolicyCheckpoint,
)->(Vec<u8>,[u8;64]) {
    let binding=EndpointRouteBinding {
        endpoint_id:key(7),w3_device_id:[1;16],w3_epoch:1,
        relay_id:[2;16],namespace:[3;16],
        route_token:[4;16],issuer_id:[5;16],
    };
    let command=sign_operator_change(
        &root(),&OperatorChange {
            operation:PolicyOperation::Revoke,revision:next.revision,binding,
        },
    ).unwrap();
    let proof=sign_anchor_transition(
        &root(),domain(),&command,old,next,
    ).unwrap();
    (command,proof)
}

#[test]
fn permit_is_atomic_against_signed_revoke_and_is_nonce_writer_scoped() {
    let dir=tempdir().unwrap();
    let old=cp(1,9);
    let next=cp(2,10);
    let (change,proof)=signed_revoke(old,next);
    let mut db=RemoteAnchorLedger::provision(
        &dir.path().join("anchor.sqlite"),config(),old,
    ).unwrap();
    let nonce=[19;32];
    assert!(matches!(
        db.begin_write_for(key(42),old,nonce),
        Err(RemoteAnchorError::UntrustedPeer)
    ));
    assert!(matches!(
        db.begin_write_for(key(41),old,[0;32]),
        Err(RemoteAnchorError::Protocol)
    ));
    assert_eq!(db.begin_write_for(key(41),old,nonce).unwrap(),old);
    // An ambiguous first response may cause exact-token retransmission.
    assert_eq!(db.begin_write_for(key(41),old,nonce).unwrap(),old);
    assert!(matches!(
        db.begin_write_for(key(41),old,[21;32]),
        Err(RemoteAnchorError::Conflict)
    ));
    assert!(matches!(
        db.advance_for(key(42),old,next,&change,&proof),
        Err(RemoteAnchorError::Conflict)
    ));
    assert_eq!(db.current_for(key(41)).unwrap(),old);
    assert!(matches!(
        db.finish_write_for(key(41),old,[21;32]),
        Err(RemoteAnchorError::Conflict)
    ));
    assert!(matches!(
        db.finish_write_for(key(42),old,nonce),
        Err(RemoteAnchorError::UntrustedPeer)
    ));
    assert_eq!(db.finish_write_for(key(41),old,nonce).unwrap(),old);
    assert!(matches!(
        db.finish_write_for(key(41),old,nonce),
        Err(RemoteAnchorError::Conflict)
    ));
    assert_eq!(
        db.advance_for(key(42),old,next,&change,&proof).unwrap(),next
    );
    // A host still holding its OLD policy cannot start a new commit.
    assert!(matches!(
        db.begin_write_for(key(41),old,[22;32]),
        Err(RemoteAnchorError::Conflict)
    ));
}

#[test]
fn unfinished_writer_survives_authority_sqlite_reopen_and_blocks_cas() {
    let dir=tempdir().unwrap();
    let path=dir.path().join("anchor.sqlite");
    let old=cp(1,6);
    let next=cp(2,7);
    let (change,proof)=signed_revoke(old,next);
    let nonce=[45;32];
    let mut db=RemoteAnchorLedger::provision(&path,config(),old).unwrap();
    db.begin_write_for(key(41),old,nonce).unwrap();
    drop(db);
    let mut reopened=RemoteAnchorLedger::open(&path,config()).unwrap();
    assert!(matches!(
        reopened.advance_for(key(42),old,next,&change,&proof),
        Err(RemoteAnchorError::Conflict)
    ));
    assert!(matches!(
        reopened.finish_write_for(key(41),cp(99,99),nonce),
        Err(RemoteAnchorError::Conflict)
    ));
    reopened.finish_write_for(key(41),old,nonce).unwrap();
    reopened.advance_for(key(42),old,next,&change,&proof).unwrap();
}

#[test]
fn old_authority_missing_durable_writer_table_fails_closed() {
    let dir=tempdir().unwrap();
    let path=dir.path().join("anchor.sqlite");
    drop(RemoteAnchorLedger::provision(&path,config(),cp(1,1)).unwrap());
    let sql=Connection::open(&path).unwrap();
    sql.execute_batch("DROP TABLE w6_writer_fence").unwrap();
    drop(sql);
    assert!(RemoteAnchorLedger::open(&path,config()).is_err());
}

#[test]
fn duplicate_provision_never_changes_existing_legacy_authority_file() {
    let dir=tempdir().unwrap();
    let path=dir.path().join("legacy.sqlite");
    // Simulates an existing v2 authority with NO writer-fence table.
    let sql=Connection::open(&path).unwrap();
    sql.execute_batch(
        "CREATE TABLE w6_external_anchor(id INTEGER PRIMARY KEY);
         INSERT INTO w6_external_anchor(id) VALUES(1);"
    ).unwrap();
    drop(sql);
    assert!(matches!(
        RemoteAnchorLedger::provision(&path,config(),cp(1,1)),
        Err(RemoteAnchorError::AlreadyProvisioned)
    ));
    // Provision failed with ZERO schema changes, not a silent v2 -> v3
    // mutation that could have re-enabled writes without migration review.
    let sql=Connection::open(&path).unwrap();
    let old_rows:i64=sql.query_row(
        "SELECT COUNT(*) FROM w6_external_anchor",[],|r|r.get(0)
    ).unwrap();
    let unexpected_table:i64=sql.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table'
         AND name='w6_writer_fence'",[],|r|r.get(0)
    ).unwrap();
    assert_eq!(old_rows,1);
    assert_eq!(unexpected_table,0);
}
