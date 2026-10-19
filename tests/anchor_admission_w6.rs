//! One actual Roha/noq QUIC socket tests the *application* pre-TLS gate.
//! This is not a kernel/UDP parser DoS test or independent host validation.
#![cfg(feature="iroh-transport")]

use akula_wire_lab::anchor_admission_w6::{
    AnchorAdmission, AnchorAdmissionPolicy, anchor_incoming_limits,anchor_transport_config,
};
use akula_wire_lab::peer_enrollment_w6::{
    AuthorityDomainId, PolicyCheckpoint, AnchorError,
    TrustedPolicyAnchor,
};
use akula_wire_lab::remote_anchor_w6::{
    ANCHOR_ALPN, AnchorServicePolicy, RemoteAnchorClient, RemoteAnchorLedger,
};
use ed25519_dalek::SigningKey;
use iroh::{Endpoint, SecretKey, endpoint::presets};
use std::{sync::{Arc,Mutex},time::Duration};
use tempfile::tempdir;

fn key(n:u8)->SecretKey {SecretKey::from_bytes(&[n;32])}
fn domain()->AuthorityDomainId {AuthorityDomainId::new([90;32]).unwrap()}
fn cp()->PolicyCheckpoint {PolicyCheckpoint {revision:1,digest:[12;32]}}
fn policy()->AnchorServicePolicy {
    AnchorServicePolicy {
        reader:key(41).public(),
        additional_readers:[Some(key(49).public()),None,None,None],
        administrator:key(42).public(),
        operator:SigningKey::from_bytes(&[220;32]).verifying_key(),
        recovery_witness:SigningKey::from_bytes(&[234;32]).verifying_key(),
        authority:domain(),
    }
}

#[tokio::test(flavor="multi_thread",worker_threads=4)]
async fn prehandshake_capacity_denies_real_quic_without_reserving_more_workers(){
    let dir=tempdir().unwrap();
    let ledger=RemoteAnchorLedger::provision(
        &dir.path().join("authority.sqlite"),policy(),cp(),
    ).unwrap();
    let ledger=Arc::new(Mutex::new(ledger));
    let server=Endpoint::builder(presets::Minimal)
        .clear_ip_transports()
        .bind_addr("127.0.0.1:0").unwrap()
        .transport_config(anchor_transport_config())
            .server_incoming_limits(anchor_incoming_limits())
        .secret_key(key(43))
        .alpns(vec![ANCHOR_ALPN.to_vec()])
        .bind().await.unwrap();
    let address=server.addr();
    let limiter=Arc::new(AnchorAdmission::new(AnchorAdmissionPolicy {
        max_in_flight:1,rate_per_second:32,max_burst:32,
        handshake_budget:Duration::from_secs(2),
        connection_budget:Duration::from_secs(8),
    }).unwrap());
    // Occupy the entire pre-handshake budget WITHOUT creating an Incoming.
    // When a real TLS INITIAL arrives the server must refuse to poll it.
    let held=limiter.try_admit().unwrap();
    assert_eq!(limiter.available_slots(),0);
    let ep=server.clone();
    let storage=Arc::clone(&ledger);
    let guard=Arc::clone(&limiter);
    let runner=tokio::spawn(async move {
        loop {
            let Some(incoming)=ep.accept().await else {return};
            let _accepted=guard.dispatch(incoming,Arc::clone(&storage));
        }
    });
    let reader=RemoteAnchorClient::start(key(41),address.clone(),domain()).unwrap();
    assert_eq!(reader.current().unwrap_err(),AnchorError::Unavailable);
    assert_eq!(limiter.available_slots(),0);
    // The refusal did NOT corrupt or advance the independent authority DB.
    assert_eq!(ledger.lock().unwrap().current_for(key(42).public()).unwrap(),cp());
    drop(held);
    assert_eq!(limiter.available_slots(),1);
    assert_eq!(reader.current().unwrap(),cp());
    // The slot spans the receipt ACK and connection teardown, not only
    // the GET response bytes. Wait for verified RAII release before testing
    // a second independent TLS key with max_in_flight=1.
    tokio::time::timeout(Duration::from_secs(4),async {
        while limiter.available_slots()==0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.unwrap();
    // A distinct pinned writer also succeeds after capacity returns.
    let second=RemoteAnchorClient::start(key(49),address,domain()).unwrap();
    assert_eq!(second.current().unwrap(),cp());
    drop(second);
    drop(reader);
    server.close().await;
    runner.abort();
    let _=runner.await;
}
