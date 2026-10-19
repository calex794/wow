//! W6 external anchor service lab: actual pinned Roha/noq QUIC/TLS,
//! dedicated server SQLite store, distinct reader/admin TLS identities.
//! Loopback and same test runner are NOT rollback-isolated hardware/hosts.
#![cfg(feature="iroh-transport")]

use akula_wire_lab::peer_enrollment_w6::{
    AnchorError, AuthorityDomainId, EnrollmentError, EndpointRouteBinding, EnrollmentLookup,
    OperatorChange, PeerEnrollmentDb, PolicyCheckpoint, PolicyOperation,
    TrustedPolicyAnchor, sign_operator_change, sign_anchor_transition,
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
fn authority(n:u8)->AuthorityDomainId{AuthorityDomainId::new([n;32]).unwrap()}
fn current_domain()->AuthorityDomainId{authority(90)}
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
    AnchorServicePolicy{
        reader:sec(41).public(),
        additional_readers:[None;4],
        administrator:sec(42).public(),
        operator:root().verifying_key(),
        recovery_witness:SigningKey::from_bytes(&[234;32]).verifying_key(),
        authority:current_domain(),
    }
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
        Self::start_with_policy(path,policy_config()).await
    }
    async fn start_with_policy(path:&Path,policy:AnchorServicePolicy)->Self{
        let ledger=RemoteAnchorLedger::open(path,policy).unwrap();
        let ledger=Arc::new(Mutex::new(ledger));
        let endpoint=Endpoint::builder(presets::Minimal)
            .clear_ip_transports().bind_addr("127.0.0.1:0").unwrap()
            .secret_key(sec(43))
            .alpns(vec![ANCHOR_ALPN.to_vec()])
            .bind().await.unwrap();
        let ep=endpoint.clone();
        // Three independent TLS writer clients plus admin, repeated
        // short-lived RPC connections and cleanup overlap. Keep admission
        // BOUNDED but do not conflate honest burst saturation with an
        // authorization failure. Production pre-TLS quotas are separate P0.
        let slots=Arc::new(tokio::sync::Semaphore::new(16));
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
    client_with_domain(key,addr,current_domain())
}
fn client_with_domain(
    key:u8,addr:EndpointAddr,domain:AuthorityDomainId,
)->RemoteAnchorClient{
    RemoteAnchorClient::start(sec(key),addr,domain).unwrap()
}
fn cp(revision:u64,value:u8)->PolicyCheckpoint{
    PolicyCheckpoint {revision,digest:[value;32]}
}
/// Test fixture only: OFFLINE root signs exact old/new digest transition.
fn authorized_cas(
    admin:&RemoteAnchorClient,old:PolicyCheckpoint,new:PolicyCheckpoint,
)->Result<(),AnchorError>{
    let change=signed(new.revision,PolicyOperation::Revoke);
    let proof=sign_anchor_transition(&root(),current_domain(),&change,old,new).unwrap();
    admin.advance_signed(old,new,&change,&proof)
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
    assert_anchor_error(admin.advance(first,second),AnchorError::InvalidAttestation);
    authorized_cas(&admin,first,second).unwrap();
    assert_eq!(reader.current().unwrap(),second);
    // Replaying an earlier valid write or forging a stale expected revision
    // cannot overwrite the durable checkpoint.
    assert_anchor_error(authorized_cas(&admin,first,second),AnchorError::Conflict);
    assert_anchor_error(admin.advance(second,first),AnchorError::InvalidAttestation);
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
    authorized_cas(&admin,cp(0,9),cp(3,3)).unwrap();
    assert_eq!(client(41,old_addr.clone()).current().unwrap(),cp(3,3));
    server.stop().await;
    // The old client has only an outdated loopback address, and TLS does
    // not fall back to an unauthenticated endpoint or local cached state.
    assert_anchor_error(client(41,old_addr).current(),AnchorError::Unavailable);
    let reopened=Server::start(&path).await;
    assert_eq!(client(41,reopened.addr()).current().unwrap(),cp(3,3));
    let new_admin=client(42,reopened.addr());
    authorized_cas(&new_admin,cp(3,3),cp(4,4)).unwrap();
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
    let mut local=PeerEnrollmentDb::open_for_authority(
        &local_path,root().verifying_key(),current_domain(),
    ).unwrap();
    let b=binding();
    assert_eq!(local.authorize_anchored(&reader,lookup(&b)).unwrap(),(id(7),3));

    // Authenticated administrator publishes the remote watermark BEFORE
    // the independent local SQLite commit, per W6's fail-closed contract.
    let change=signed(2,PolicyOperation::Revoke);
    let (old,next)=local.preview_signed_update(&change).unwrap();
    let proof=sign_anchor_transition(&root(),current_domain(),&change,old,next).unwrap();
    local.apply_signed_anchored_with_proof(&change,&proof,&admin).unwrap();
    assert_eq!(reader.current().unwrap(),local.checkpoint().unwrap());
    drop(local);
    checkpoint_flush(&local_path);
    server.stop().await;

    // Attacker replaces ONLY the local policy database snapshot. Remote
    // authority holds revision 2 in its independent SQLite file.
    std::fs::copy(&saved,&local_path).unwrap();
    let mut rolled_back=PeerEnrollmentDb::open_for_authority(
        &local_path,root().verifying_key(),current_domain()
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
        reader:sec(45).public(),additional_readers:[None;4],administrator:sec(46).public(),
        operator:root().verifying_key(),
        recovery_witness:SigningKey::from_bytes(&[234;32]).verifying_key(),
        authority:current_domain(),
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


#[tokio::test(flavor="multi_thread",worker_threads=4)]
async fn stolen_administrator_tls_key_cannot_forge_operator_signed_transition() {
    let dir=tempdir().unwrap();
    let path=dir.path().join("remote.sqlite");
    let old=cp(7,11);
    let new=cp(8,12);
    provision(&path,old);
    let server=Server::start(&path).await;
    let admin=client(42,server.addr());
    let reader=client(41,server.addr());
    let valid_change=signed(8,PolicyOperation::Revoke);
    let valid_proof=sign_anchor_transition(&root(),current_domain(),&valid_change,old,new).unwrap();

    // Compromised TLS-admin credential alone is now insufficient.
    assert_anchor_error(admin.advance(old,new),AnchorError::InvalidAttestation);

    let forged_signer=SigningKey::from_bytes(&[222;32]);
    let forged_change=sign_operator_change(&forged_signer,&OperatorChange {
        operation:PolicyOperation::Revoke,revision:8,binding:binding(),
    }).unwrap();
    let forged_proof=sign_anchor_transition(
        &forged_signer,current_domain(),&forged_change,old,new,
    ).unwrap();
    assert_anchor_error(
        admin.advance_signed(old,new,&forged_change,&forged_proof),
        AnchorError::InvalidAttestation,
    );

    // Even a VALID offline operator change cannot authorize a different
    // digest without a separate signature binding that exact digest.
    assert_anchor_error(
        admin.advance_signed(old,cp(8,99),&valid_change,&valid_proof),
        AnchorError::InvalidAttestation,
    );
    let mut corrupt=valid_proof;
    corrupt[0]^=0x80;
    assert_anchor_error(
        admin.advance_signed(old,new,&valid_change,&corrupt),
        AnchorError::InvalidAttestation,
    );
    let other_valid_change=signed(8,PolicyOperation::Allow);
    assert_anchor_error(
        admin.advance_signed(old,new,&other_valid_change,&valid_proof),
        AnchorError::InvalidAttestation,
    );

    // Two correct offline signatures still do not allow a relay reader to
    // act as the privileged admin TLS identity.
    assert_anchor_error(
        reader.advance_signed(old,new,&valid_change,&valid_proof),
        AnchorError::InvalidAttestation,
    );
    assert_eq!(reader.current().unwrap(),old);

    // One EXACT signed intent may commit only once; replay is CAS conflict.
    admin.advance_signed(old,new,&valid_change,&valid_proof).unwrap();
    assert_eq!(reader.current().unwrap(),new);
    assert_anchor_error(
        admin.advance_signed(old,new,&valid_change,&valid_proof),
        AnchorError::Conflict,
    );
    server.stop().await;
}

#[tokio::test(flavor="multi_thread",worker_threads=4)]
async fn pinned_offline_operator_key_cannot_be_replaced_at_anchor_reopen() {
    let dir=tempdir().unwrap();
    let db=dir.path().join("remote.sqlite");
    provision(&db,cp(1,2));
    let wrong=AnchorServicePolicy {
        reader:sec(41).public(),additional_readers:[None;4],administrator:sec(42).public(),
        operator:SigningKey::from_bytes(&[221;32]).verifying_key(),
        recovery_witness:SigningKey::from_bytes(&[234;32]).verifying_key(),
        authority:current_domain(),
    };
    assert!(matches!(
        RemoteAnchorLedger::open(&db,wrong),
        Err(RemoteAnchorError::ConfigurationMismatch)
    ));
    assert_eq!(
        RemoteAnchorLedger::open(&db,policy_config()).unwrap()
            .current_for(sec(41).public()).unwrap(),
        cp(1,2)
    );
}

#[test]
fn offline_preview_signature_binds_real_w6_policy_mutation_before_publication() {
    let dir=tempdir().unwrap();
    let path=dir.path().join("policy.sqlite");
    let mut policy=PeerEnrollmentDb::open(&path,root().verifying_key()).unwrap();
    policy.apply_signed(&signed(1,PolicyOperation::Allow)).unwrap();
    let change=signed(2,PolicyOperation::Revoke);
    let prior=policy.checkpoint().unwrap();
    let (old,new)=policy.preview_signed_update(&change).unwrap();
    assert_eq!(old,prior);
    assert_eq!(old.revision,1);
    assert_eq!(new.revision,2);
    assert_ne!(old.digest,new.digest);
    assert_eq!(policy.last_revision().unwrap(),1);
    assert_eq!(policy.checkpoint().unwrap(),prior);
    let proof=sign_anchor_transition(&root(),current_domain(),&change,old,new).unwrap();
    let verified=akula_wire_lab::peer_enrollment_w6::verify_signed_anchor_transition(
        &root().verifying_key(),current_domain(),&change,old,new,&proof,
    ).unwrap();
    assert_eq!(verified.operation,PolicyOperation::Revoke);
    assert_eq!(verified.binding,binding());
    assert!(akula_wire_lab::peer_enrollment_w6::verify_signed_anchor_transition(
        &root().verifying_key(),current_domain(),&change,old,cp(2,200),&proof,
    ).is_err());
}

#[tokio::test(flavor="multi_thread",worker_threads=4)]
async fn cross_authority_replay_rejected_over_real_quic_even_with_same_tls_key() {
    let dir=tempdir().unwrap();
    let first=dir.path().join("first.sqlite");
    let second=dir.path().join("second.sqlite");
    let old=cp(1,15);
    let new=cp(2,16);
    let other=authority(91);
    provision(&first,old);
    drop(RemoteAnchorLedger::provision(
        &second,
        AnchorServicePolicy {authority:other,..policy_config()},
        old,
    ).unwrap());
    let change=signed(2,PolicyOperation::Revoke);
    let proof_a=sign_anchor_transition(
        &root(),current_domain(),&change,old,new,
    ).unwrap();
    let first_service=Server::start(&first).await;
    let second_service=Server::start_with_policy(
        &second,AnchorServicePolicy {authority:other,..policy_config()}
    ).await;
    // Both servers intentionally use the same TLS server key to prove that
    // pinned TLS EndpointId alone cannot disambiguate logical authorities.
    assert_eq!(first_service.addr().id,second_service.addr().id);
    let admin_b=client_with_domain(42,second_service.addr(),other);
    assert_eq!(admin_b.current().unwrap(),old);
    assert_anchor_error(
        admin_b.advance_signed(old,new,&change,&proof_a),
        AnchorError::InvalidAttestation,
    );
    assert_eq!(admin_b.current().unwrap(),old);
    // A misconfigured reader with the CORRECT server TLS key but the wrong
    // independently pinned domain MUST refuse even an innocent GET.
    let wrong_scope=client_with_domain(41,second_service.addr(),current_domain());
    assert_anchor_error(wrong_scope.current(),AnchorError::InvalidAttestation);
    // A response-only domain check would be TOO LATE for mutating
    // BEGIN/FINISH RPCs. Verify wrong-domain requests cause no side effects
    // at authority B even though both servers share one TLS EndpointId.
    assert_anchor_error(
        wrong_scope.begin_write_fence(old,[77;32]),
        AnchorError::InvalidAttestation,
    );
    let correct_b=client_with_domain(41,second_service.addr(),other);
    correct_b.begin_write_fence(old,[78;32]).unwrap();
    assert_anchor_error(
        wrong_scope.finish_write_fence(old,[78;32]),
        AnchorError::InvalidAttestation,
    );
    let proof_b=sign_anchor_transition(&root(),other,&change,old,new).unwrap();
    assert_anchor_error(
        admin_b.advance_signed(old,new,&change,&proof_b),
        AnchorError::Conflict,
    );
    correct_b.finish_write_fence(old,[78;32]).unwrap();
    let admin_a=client(42,first_service.addr());
    admin_a.advance_signed(old,new,&change,&proof_a).unwrap();
    assert_eq!(admin_a.current().unwrap(),new);
    assert_eq!(admin_b.current().unwrap(),old);
    admin_b.advance_signed(old,new,&change,&proof_b).unwrap();
    assert_eq!(admin_b.current().unwrap(),new);
    first_service.stop().await;
    second_service.stop().await;
}

#[tokio::test(flavor="multi_thread",worker_threads=4)]
async fn real_quic_independent_writer_keys_share_global_fence_and_revoke() {
    let dir=tempdir().unwrap();
    let db=dir.path().join("multi-reader.sqlite");
    let old=cp(1,33);
    let next=cp(2,34);
    let mut pinned=policy_config();
    pinned.additional_readers[0]=Some(sec(49).public());
    pinned.additional_readers[1]=Some(sec(50).public());
    drop(RemoteAnchorLedger::provision(&db,pinned,old).unwrap());
    let service=Server::start_with_policy(&db,pinned).await;
    let a=client(41,service.addr());
    let b=client(49,service.addr());
    let c=client(50,service.addr());
    let admin=client(42,service.addr());
    let stranger=client(51,service.addr());
    assert_eq!(a.current().unwrap(),old);
    assert_eq!(b.current().unwrap(),old);
    assert_eq!(c.current().unwrap(),old);
    assert_anchor_error(stranger.current(),AnchorError::InvalidAttestation);
    // Real, separate TLS/EndpointId keys for A, B and C. A's fence
    // prevents B/C from entering even when they know the same checkpoint.
    a.begin_write_fence(old,[201;32]).unwrap();
    assert_anchor_error(
        b.begin_write_fence(old,[202;32]),AnchorError::Conflict
    );
    assert_anchor_error(
        c.finish_write_fence(old,[201;32]),AnchorError::Conflict
    );
    assert_anchor_error(
        authorized_cas(&admin,old,next),AnchorError::Conflict
    );
    a.finish_write_fence(old,[201;32]).unwrap();
    b.begin_write_fence(old,[203;32]).unwrap();
    assert_anchor_error(
        a.begin_write_fence(old,[204;32]),AnchorError::Conflict
    );
    b.finish_write_fence(old,[203;32]).unwrap();
    c.begin_write_fence(old,[205;32]).unwrap();
    c.finish_write_fence(old,[205;32]).unwrap();
    authorized_cas(&admin,old,next).unwrap();
    for reader in [&a,&b,&c] {
        assert_anchor_error(
            reader.begin_write_fence(old,[206;32]),AnchorError::Conflict
        );
        assert_eq!(reader.current().unwrap(),next);
    }
    service.stop().await;
}
