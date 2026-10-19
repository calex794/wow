//! Cross-host durable Mailbox writer fence; no QUIC shortcuts or time leases.
//! Direct authority SQLite tests use independently pinned keys and domains.
#![cfg(feature = "iroh-transport")]

use akula_wire_lab::peer_enrollment_w6::{
    sign_anchor_transition, sign_operator_change, AuthorityDomainId,
    EndpointRouteBinding, OperatorChange, PolicyCheckpoint, PolicyOperation,
};
use akula_wire_lab::remote_anchor_w6::{
    AnchorServicePolicy, OrphanFenceRecoveryOrder, RemoteAnchorError, RemoteAnchorLedger,
    sign_orphan_recovery_operator, sign_orphan_recovery_witness,
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
        reader:key(41),additional_readers:[None;4],administrator:key(42),
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

fn recovery_witness()->SigningKey{SigningKey::from_bytes(&[234;32])}
fn signed_recovery(
    snapshot:akula_wire_lab::remote_anchor_w6::OrphanFenceInspection,
    new_reader:EndpointId,
)->(OrphanFenceRecoveryOrder,[u8;64],[u8;64]){
    let order=OrphanFenceRecoveryOrder{
        authority:snapshot.authority,
        previous_reader:snapshot.reader,
        replacement_reader:new_reader,
        checkpoint:snapshot.checkpoint,
        nonce:snapshot.nonce,
        generation:snapshot.next_generation,
    };
    let op=sign_orphan_recovery_operator(&root(),&order);
    let witness=sign_orphan_recovery_witness(&recovery_witness(),&order);
    (order,op,witness)
}

#[test]
fn orphan_release_requires_two_distinct_roles_and_rotates_writer_atomically() {
    let dir=tempdir().unwrap();
    let path=dir.path().join("anchor.sqlite");
    let baseline=cp(8,9);
    let mut anchor=RemoteAnchorLedger::provision(&path,config(),baseline).unwrap();
    anchor.begin_write_for(key(41),baseline,[72;32]).unwrap();
    let evidence=anchor.inspect_orphan_fence().unwrap().unwrap();
    assert_eq!(evidence.nonce,[72;32]);
    assert_eq!(evidence.reader,key(41));
    assert_eq!(evidence.next_generation,1);
    let (order,operator,witness)=signed_recovery(evidence,key(49));
    let wrong=sign_orphan_recovery_witness(&root(),&order);
    assert!(matches!(
        anchor.recover_orphan_after_external_isolation(&order,&operator,&wrong),
        Err(RemoteAnchorError::UntrustedRecovery)
    ));
    assert!(matches!(
        anchor.recover_orphan_after_external_isolation(&order,&operator,&operator),
        Err(RemoteAnchorError::UntrustedRecovery)
    ));
    let forged=sign_orphan_recovery_operator(&recovery_witness(),&order);
    assert!(matches!(
        anchor.recover_orphan_after_external_isolation(&order,&forged,&witness),
        Err(RemoteAnchorError::UntrustedRecovery)
    ));
    let altered=OrphanFenceRecoveryOrder {
        nonce:[73;32], ..order
    };
    assert!(matches!(
        anchor.recover_orphan_after_external_isolation(&altered,&operator,&witness),
        Err(RemoteAnchorError::UntrustedRecovery)
    ));
    let foreign=OrphanFenceRecoveryOrder {
        authority:AuthorityDomainId::new([91;32]).unwrap(),..order
    };
    assert!(matches!(
        anchor.recover_orphan_after_external_isolation(&foreign,&operator,&witness),
        Err(RemoteAnchorError::UntrustedRecovery)
    ));
    let stale=OrphanFenceRecoveryOrder{generation:order.generation+1,..order};
    assert!(matches!(
        anchor.recover_orphan_after_external_isolation(&stale,&operator,&witness),
        Err(RemoteAnchorError::UntrustedRecovery)
    ));
    for forbidden_reader in [key(42),key(234),key(220)] {
        let dangerous=OrphanFenceRecoveryOrder {
            replacement_reader:forbidden_reader,..order
        };
        let dangerous_op=sign_orphan_recovery_operator(&root(),&dangerous);
        let dangerous_witness=sign_orphan_recovery_witness(
            &recovery_witness(),&dangerous
        );
        assert!(matches!(
            anchor.recover_orphan_after_external_isolation(
                &dangerous,&dangerous_op,&dangerous_witness,
            ),
            Err(RemoteAnchorError::UntrustedRecovery)
        ));
    }
    // Without both exact valid roles the fence remains, and CAS still fails.
    assert!(anchor.inspect_orphan_fence().unwrap().is_some());
    let (command,proof)=signed_revoke(baseline,cp(9,10));
    assert!(matches!(
        anchor.advance_for(key(42),baseline,cp(9,10),&command,&proof),
        Err(RemoteAnchorError::Conflict)
    ));

    anchor.recover_orphan_after_external_isolation(
        &order,&operator,&witness,
    ).unwrap();
    assert!(anchor.inspect_orphan_fence().unwrap().is_none());
    assert!(matches!(
        anchor.begin_write_for(key(41),baseline,[74;32]),
        Err(RemoteAnchorError::UntrustedPeer)
    ));
    assert!(matches!(
        anchor.current_for(key(41)),
        Err(RemoteAnchorError::UntrustedPeer)
    ));
    assert_eq!(anchor.current_for(key(49)).unwrap(),baseline);
    anchor.begin_write_for(key(49),baseline,[75;32]).unwrap();
    anchor.finish_write_for(key(49),baseline,[75;32]).unwrap();
    anchor.advance_for(key(42),baseline,cp(9,10),&command,&proof).unwrap();
    assert!(anchor.recover_orphan_after_external_isolation(
        &order,&operator,&witness,
    ).is_err());

    // Same transaction stores a NONCE HASH, never the raw WRITE-FINISH
    // capability. Losing just the process after commit is recoverable by
    // opening with a newly provisioned reader identity.
    drop(anchor);
    let mut replacement=config();
    replacement.reader=key(49);
    assert!(matches!(
        RemoteAnchorLedger::open(&path,config()),
        Err(RemoteAnchorError::ConfigurationMismatch)
    ));
    let reopened=RemoteAnchorLedger::open(&path,replacement).unwrap();
    assert_eq!(reopened.current_for(key(49)).unwrap(),cp(9,10));
    let db=Connection::open(&path).unwrap();
    let (generation,nonce_hash):(i64,Vec<u8>)=db.query_row(
        "SELECT generation,nonce_hash FROM w6_writer_recovery",
        [],|r|Ok((r.get(0)?,r.get(1)?)),
    ).unwrap();
    assert_eq!(generation,1);
    assert_eq!(nonce_hash,blake3::hash(&[72;32]).as_bytes());
    assert_ne!(nonce_hash.as_slice(),&[72;32]);
}

#[test]
fn stale_authority_process_cannot_serve_or_clear_old_fence_after_rotation() {
    let dir=tempdir().unwrap();
    let path=dir.path().join("anchor.sqlite");
    let baseline=cp(1,1);
    let mut old_process=RemoteAnchorLedger::provision(&path,config(),baseline).unwrap();
    old_process.begin_write_for(key(41),baseline,[121;32]).unwrap();
    let mut maintenance=RemoteAnchorLedger::open(&path,config()).unwrap();
    let observation=maintenance.inspect_orphan_fence().unwrap().unwrap();
    let (order,operator,witness)=signed_recovery(observation,key(49));
    maintenance.recover_orphan_after_external_isolation(
        &order,&operator,&witness,
    ).unwrap();
    // Even if an old authority service missed its configuration update,
    // revalidating durable reader identity makes every old process fail
    // closed on GET/BEGIN/FINISH and signed CAS.
    assert!(matches!(
        old_process.current_for(key(41)),
        Err(RemoteAnchorError::ConfigurationMismatch)
    ));
    assert!(matches!(
        old_process.begin_write_for(key(41),baseline,[123;32]),
        Err(RemoteAnchorError::ConfigurationMismatch)
    ));
    assert!(matches!(
        old_process.finish_write_for(key(41),baseline,[121;32]),
        Err(RemoteAnchorError::ConfigurationMismatch)
    ));
    let (change,proof)=signed_revoke(baseline,cp(2,2));
    assert!(matches!(
        old_process.advance_for(key(42),baseline,cp(2,2),&change,&proof),
        Err(RemoteAnchorError::ConfigurationMismatch)
    ));
    maintenance.begin_write_for(key(49),baseline,[124;32]).unwrap();
    maintenance.finish_write_for(key(49),baseline,[124;32]).unwrap();
}

#[test]
fn same_operator_and_witness_root_must_fail_at_provisioning() {
    let dir=tempdir().unwrap();
    let mut wrong=config();
    wrong.recovery_witness=wrong.operator;
    assert!(matches!(
        RemoteAnchorLedger::provision(&dir.path().join("authority.sqlite"),wrong,cp(1,1)),
        Err(RemoteAnchorError::ConfigurationMismatch)
    ));
    for duplicate in [key(234),key(220)] {
        let mut bad=config();
        bad.reader=duplicate;
        assert!(matches!(
            RemoteAnchorLedger::provision(
                &dir.path().join("reader-overlap.sqlite"),bad,cp(1,1)
            ),
            Err(RemoteAnchorError::ConfigurationMismatch)
        ));
    }
    let mut bad=config();
    bad.administrator=key(234);
    assert!(matches!(
        RemoteAnchorLedger::provision(
            &dir.path().join("admin-overlap.sqlite"),bad,cp(1,1)
        ),
        Err(RemoteAnchorError::ConfigurationMismatch)
    ));
}
