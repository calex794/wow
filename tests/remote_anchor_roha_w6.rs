//! W6 external anchor service lab: actual pinned Roha/noq QUIC/TLS,
//! dedicated server SQLite store, distinct reader/admin TLS identities.
//! Loopback and same test runner are NOT rollback-isolated hardware/hosts.
#![cfg(feature="iroh-transport")]

use akula_wire_lab::peer_enrollment_w6::{
    AnchorError, EnrollmentError, EndpointRouteBinding, EnrollmentLookup,
    OperatorChange, PeerEnrollmentDb, PolicyCheckpoint, PolicyOperation,
    TrustedPolicyAnchor, sign_operator_change,
};
use akula_wire_lab::remote_anchor_w6::{
    ANCHOR_ALPN, AnchorServicePolicy, RemoteAnchorClient, RemoteAnchorError,
    RemoteAnchorLedger, serve_one_anchor_connection,
};
use ed25519_dalek::SigningKey;
use iroh::{Endpoint, EndpointAddr, SecretKey, endpoint::presets};
use rusqlite::Connection;
use std::{
    path::Path,
    sync::{Arc,Mutex},
};
use tempfile::tempdir;

fn sec(n:u8)->SecretKey{SecretKey::from_bytes(&[n;32])}
fn id(n:u8)->[u8;16]{[n;16]}
fn root()->SigningKey{SigningKey::from_bytes(&[220;32])}
fn binding()->EndpointRouteBinding{
    let client=SigningKey::from_bytes(&[5;32]);
    EndpointRouteBinding{
        endpoint_id:iroh::EndpointId::from_bytes(
            &client.verifying_key().to_bytes()
        ).unwrap(),
        w3_device_id:id(7),w3_epoch:3,
        relay_id:id(8),namespace:id(9),route_token:id(10),issuer_id:id(11),
    }
}
fn signed(revision:u64,operation:PolicyOperation)->Vec<u8>{
    sign_operator_change(&root(),&OperatorChange{
        operation,revision,binding:binding(),
    }).unwrap()
}
fn lookup<'a>(b:&'a EndpointRouteBinding)->EnrollmentLookup<'a>{
    EnrollmentLookup{
        remote:&b.endpoint_id,relay:&b.relay_id,
        namespace:&b.namespace,token:&b.route_token,issuer:&b.issuer_id,
    }
}
fn policy_config()->AnchorServicePolicy{
    AnchorServicePolicy{reader:sec(41).public(),administrator:sec(42).public()}
}
fn checkpoint_flush(path:&Path){
    let db=Connection::open(path).unwrap();
    db.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);").unwrap();
}

struct Server {
    endpoint:Endpoint,
    task:tokio::task::JoinHandle<()>,
}
impl Server {
    async fn start(path:&Path)->Self{
        let ledger=RemoteAnchorLedger::open(path,policy_config()).unwrap();
        let ledger=Arc::new(Mutex::new(ledger));
        let endpoint=Endpoint::builder(presets::Minimal)
            .clear_ip_transports().bind_addr("127.0.0.1:0").unwrap()
            .secret_key(sec(43))
            .alpns(vec![ANCHOR_ALPN.to_vec()])
            .bind().await.unwrap();
        let ep=endpoint.clone();
        let slots=Arc::new(tokio::sync::Semaphore::new(4));
        let task=tokio::spawn(async move {
            loop {
                let Some(incoming)=ep.accept().await else {return};
                // Bounded worker admission, never serially wait for one
                // client's RPC reply acknowledgement before accepting the
                // next independently authenticated TLS identity.
                let Ok(slot)=Arc::clone(&slots).try_acquire_owned() else {
                    drop(incoming); // fail closed under overload
                    continue;
                };
                let ledger=Arc::clone(&ledger);
                tokio::spawn(async move {
                    let _slot=slot;
                    if let Ok(conn)=incoming.await {
                        if let Err(error)=serve_one_anchor_connection(&conn,&ledger).await {
                            eprintln!("W6 LAB anchor responder failure: {error:?}");
                        }
                    }
                });
            }
        });
        Self{endpoint,task}
    }
    fn addr(&self)->EndpointAddr{self.endpoint.addr()}
    async fn stop(self){
        self.endpoint.close().await;
        self.task.abort();
        let _=self.task.await;
    }
}
fn client(key:u8,addr:EndpointAddr)->RemoteAnchorClient{
    RemoteAnchorClient::start(sec(key),addr).unwrap()
}
fn cp(revision:u64,value:u8)->PolicyCheckpoint{
    PolicyCheckpoint {revision,digest:[value;32]}
}
fn provision(path:&Path,initial:PolicyCheckpoint){
    let store=RemoteAnchorLedger::provision(
        path,policy_config(),initial
    ).unwrap();
    drop(store);
}
fn assert_anchor_error<T>(result:Result<T,AnchorError>,expected:AnchorError){
    let Some(actual)=result.err() else {panic!("unauthorized request succeeded")};
    assert_eq!(actual,expected);
}

#[tokio::test(flavor="multi_thread",worker_threads=4)]
async fn real_roha_quic_read_only_and_admin_cas_are_tls_identity_separated(){
    let dir=tempdir().unwrap();
    let path=dir.path().join("remote-anchor.sqlite");
    let first=cp(1,1);
    let second=cp(2,2);
    provision(&path,first);
    let server=Server::start(&path).await;
    let reader=client(41,server.addr());
    let admin=client(42,server.addr());
    let rogue=client(44,server.addr());
    assert_eq!(reader.current().unwrap(),first);
    assert_eq!(admin.current().unwrap(),first);
    assert_anchor_error(rogue.current(),AnchorError::InvalidAttestation);
    assert_anchor_error(
        reader.advance(first,second),AnchorError::InvalidAttestation
    );
    // TLS-authorized operator CAS advances, ordinary peer observes state.
    admin.advance(first,second).unwrap();
    assert_eq!(reader.current().unwrap(),second);
    // Replaying an earlier valid write or forging a stale expected revision
    // cannot overwrite the durable checkpoint.
    assert_anchor_error(admin.advance(first,second),AnchorError::Conflict);
    assert_anchor_error(admin.advance(second,first),AnchorError::Conflict);
    assert_eq!(reader.current().unwrap(),second);
    server.stop().await;
}

#[tokio::test(flavor="multi_thread",worker_threads=4)]
async fn separately_persisted_remote_state_survives_service_restart_and_stale_clients_fail(){
    let dir=tempdir().unwrap();let path=dir.path().join("remote-anchor.sqlite");
    provision(&path,cp(0,9));
    let server=Server::start(&path).await;
    let old_addr=server.addr();
    let admin=client(42,old_addr.clone());
    admin.advance(cp(0,9),cp(3,3)).unwrap();
    assert_eq!(client(41,old_addr.clone()).current().unwrap(),cp(3,3));
    server.stop().await;
    // The old client has only an outdated loopback address, and TLS does
    // not fall back to an unauthenticated endpoint or local cached state.
    assert_anchor_error(client(41,old_addr).current(),AnchorError::Unavailable);
    let reopened=Server::start(&path).await;
    assert_eq!(client(41,reopened.addr()).current().unwrap(),cp(3,3));
    let new_admin=client(42,reopened.addr());
    new_admin.advance(cp(3,3),cp(4,4)).unwrap();
    assert_eq!(client(41,reopened.addr()).current().unwrap(),cp(4,4));
    reopened.stop().await;
}

#[tokio::test(flavor="multi_thread",worker_threads=4)]
async fn old_local_sqlite_snapshot_denied_by_durable_remote_quic_anchor(){
    let dir=tempdir().unwrap();
    let local_path=dir.path().join("policy.sqlite");
    let saved=dir.path().join("policy-old.sqlite");
    let remote_path=dir.path().join("remote.sqlite");
    let mut policy=PeerEnrollmentDb::open(&local_path,root().verifying_key()).unwrap();
    policy.apply_signed(&signed(1,PolicyOperation::Allow)).unwrap();
    let initial=policy.checkpoint().unwrap();
    drop(policy);
    checkpoint_flush(&local_path);
    std::fs::copy(&local_path,&saved).unwrap();

    // Privileged OFFLINE provisioning on the remote authority is explicit,
    // no network caller can reinitialize its root on an empty DB.
    provision(&remote_path,initial);
    let server=Server::start(&remote_path).await;
    let reader=client(41,server.addr());
    let admin=client(42,server.addr());
    let mut local=PeerEnrollmentDb::open(&local_path,root().verifying_key()).unwrap();
    let b=binding();
    assert_eq!(local.authorize_anchored(&reader,lookup(&b)).unwrap(),(id(7),3));

    // Authenticated administrator publishes the remote watermark BEFORE
    // the independent local SQLite commit, per W6's fail-closed contract.
    local.apply_signed_anchored(
        &signed(2,PolicyOperation::Revoke),&admin
    ).unwrap();
    assert_eq!(reader.current().unwrap(),local.checkpoint().unwrap());
    drop(local);
    checkpoint_flush(&local_path);
    server.stop().await;

    // Attacker replaces ONLY the local policy database snapshot. Remote
    // authority holds revision 2 in its independent SQLite file.
    std::fs::copy(&saved,&local_path).unwrap();
    let mut rolled_back=PeerEnrollmentDb::open(
        &local_path,root().verifying_key()
    ).unwrap();
    assert_eq!(rolled_back.last_revision().unwrap(),1);

    // Restart remote authority, verifying actual SQLite persistency, and
    // reauthenticate our read-only endpoint before checking local intake.
    let restarted=Server::start(&remote_path).await;
    let new_reader=client(41,restarted.addr());
    assert_eq!(new_reader.current().unwrap().revision,2);
    assert!(matches!(
        rolled_back.authorize_anchored(&new_reader,lookup(&b)),
        Err(EnrollmentError::CheckpointMismatch)
    ));
    let mut called=false;
    let out:Result<(),EnrollmentError>=rolled_back.with_anchored_write(
        &new_reader,lookup(&b),|_|{called=true;Ok(())}
    );
    assert!(matches!(out,Err(EnrollmentError::CheckpointMismatch)));
    assert!(!called);
    restarted.stop().await;
}

#[tokio::test(flavor="multi_thread",worker_threads=4)]
async fn provisioning_is_explicit_and_endpoint_keys_cannot_be_replaced_by_db(){
    let dir=tempdir().unwrap();let path=dir.path().join("remote.sqlite");
    assert!(RemoteAnchorLedger::open(&path,policy_config()).is_err(),
        "missing store must NOT silently bootstrap");
    provision(&path,cp(0,7));
    assert!(matches!(
        RemoteAnchorLedger::provision(&path,policy_config(),cp(0,9)),
        Err(RemoteAnchorError::AlreadyProvisioned)
    ));
    let wrong=AnchorServicePolicy{
        reader:sec(45).public(),administrator:sec(46).public(),
    };
    assert!(matches!(
        RemoteAnchorLedger::open(&path,wrong),
        Err(RemoteAnchorError::ConfigurationMismatch)
    ));
    let server=Server::start(&path).await;
    assert_eq!(client(41,server.addr()).current().unwrap(),cp(0,7));
    server.stop().await;
}

#[tokio::test(flavor="multi_thread",worker_threads=4)]
async fn pinned_server_tls_key_prevents_writing_to_an_impostor_address(){
    let dir=tempdir().unwrap();let path=dir.path().join("remote.sqlite");
    provision(&path,cp(0,7));
    let genuine=Server::start(&path).await;
    let mut impostor_address=genuine.addr();
    impostor_address.id=sec(99).public(); // wrong trust root, same genuine IP
    let admin=client(42,impostor_address);
    assert_anchor_error(admin.current(),AnchorError::Unavailable);
    assert_eq!(client(41,genuine.addr()).current().unwrap(),cp(0,7));
    genuine.stop().await;
}
