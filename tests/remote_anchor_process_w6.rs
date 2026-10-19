//! W6 P0: ACTUAL independent operating-system child process hosts the
//! pinned Roha/noq QUIC anchor authority. The parent is the separate W6
//! policy client; all trusted CAS calls cross a real kernel UDP loopback
//! socket, and no Arc/Mutex is shared across the process boundary.
//!
//! These are same-host laboratory tests with fixed TEST keys and one
//! physical storage failure domain. This does NOT prove resistance to
//! rolling back the remote authority's own disk or to host compromise.
#![cfg(feature="iroh-transport")]

use akula_wire_lab::peer_enrollment_w6::{
    sign_operator_change, AnchorError, AuthorityDomainId, EnrollmentError, EnrollmentLookup,
    EndpointRouteBinding, OperatorChange, PeerEnrollmentDb, PolicyCheckpoint,
    PolicyOperation, TrustedPolicyAnchor, sign_anchor_transition,
};
use akula_wire_lab::remote_anchor_w6::{
    serve_one_anchor_connection, AnchorServicePolicy, RemoteAnchorClient,
    RemoteAnchorLedger, ANCHOR_ALPN,
};
use ed25519_dalek::SigningKey;
use iroh::{Endpoint, EndpointAddr, SecretKey, endpoint::presets};
use rusqlite::Connection;
use std::{
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};
use tempfile::tempdir;

const CHILD_ROOT: &str = "STAYA_W6_REMOTE_ANCHOR_CHILD_ROOT";
const READY_FILE: &str = "anchor-ready.addr";
const STOP_FILE: &str = "anchor-stop";

fn key(v:u8)->SecretKey {SecretKey::from_bytes(&[v;32])}
fn id(v:u8)->[u8;16] {[v;16]}
fn authority()->AuthorityDomainId {AuthorityDomainId::new([90;32]).unwrap()}
fn policy()->AnchorServicePolicy {
    AnchorServicePolicy {
        reader:key(41).public(),
        administrator:key(42).public(),
        operator:root().verifying_key(),
        authority:authority(),
    }
}
fn cp(revision:u64,byte:u8)->PolicyCheckpoint {
    PolicyCheckpoint {revision,digest:[byte;32]}
}
fn root()->SigningKey {SigningKey::from_bytes(&[220;32])}
fn binding()->EndpointRouteBinding {
    let signer=SigningKey::from_bytes(&[5;32]);
    EndpointRouteBinding {
        endpoint_id:iroh::EndpointId::from_bytes(
            &signer.verifying_key().to_bytes()
        ).unwrap(),
        w3_device_id:id(7),w3_epoch:3,
        relay_id:id(8),namespace:id(9),route_token:id(10),issuer_id:id(11),
    }
}
fn signed(rev:u64,operation:PolicyOperation)->Vec<u8> {
    sign_operator_change(&root(),&OperatorChange{
        operation,revision:rev,binding:binding(),
    }).unwrap()
}
fn lookup<'a>(b:&'a EndpointRouteBinding)->EnrollmentLookup<'a> {
    EnrollmentLookup {
        remote:&b.endpoint_id,relay:&b.relay_id,
        namespace:&b.namespace,token:&b.route_token,issuer:&b.issuer_id,
    }
}
fn provision(db:&Path,checkpoint:PolicyCheckpoint) {
    RemoteAnchorLedger::provision(db,policy(),checkpoint).unwrap();
}
fn flush(path:&Path) {
    Connection::open(path).unwrap()
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);").unwrap();
}

/// Child entrypoint. It is a *real new OS process* only when the parent sets
/// CHILD_ROOT; for an ordinary cargo test run it is an inert fixture test.
/// Its QUIC listen socket is restricted to 127.0.0.1 in this laboratory.
#[tokio::test(flavor="multi_thread",worker_threads=4)]
async fn child_remote_anchor_service_process() {
    let Some(root)=std::env::var_os(CHILD_ROOT) else {return};
    let root=PathBuf::from(root);
    let ledger=RemoteAnchorLedger::open(&root.join("anchor.sqlite"),policy()).unwrap();
    let ledger=Arc::new(Mutex::new(ledger));
    let endpoint=Endpoint::builder(presets::Minimal)
        .clear_ip_transports()
        .bind_addr("127.0.0.1:0").unwrap()
        .secret_key(key(43))
        .alpns(vec![ANCHOR_ALPN.to_vec()])
        .bind().await.unwrap();
    let ip=endpoint.addr().ip_addrs().copied()
        .find(SocketAddr::is_ipv4).expect("child must have IPv4 loopback");
    // Atomic rename ensures parent never parses a half-written IP address.
    fs::write(root.join("anchor-ready.tmp"),ip.to_string()).unwrap();
    fs::rename(root.join("anchor-ready.tmp"),root.join(READY_FILE)).unwrap();

    let permits=Arc::new(tokio::sync::Semaphore::new(4));
    let deadline=Instant::now()+Duration::from_secs(20);
    while Instant::now()<deadline && !root.join(STOP_FILE).exists() {
        let incoming=tokio::time::timeout(
            Duration::from_millis(30),endpoint.accept(),
        ).await;
        let Ok(Some(incoming))=incoming else {continue};
        let Ok(ticket)=Arc::clone(&permits).try_acquire_owned() else {
            drop(incoming);
            continue;
        };
        let ledger=Arc::clone(&ledger);
        tokio::spawn(async move {
            let _ticket=ticket;
            if let Ok(Ok(conn))=tokio::time::timeout(
                Duration::from_secs(3),incoming,
            ).await {
                let _=serve_one_anchor_connection(&conn,&ledger).await;
            }
        });
    }
    endpoint.close().await;
}

struct ChildAuthority {
    root:PathBuf,
    child:Option<Child>,
    addr:EndpointAddr,
}
impl ChildAuthority {
    fn start(root:&Path)->Self {
        // Reopening after SIGKILL must read the SAME independent anchor DB,
        // but cannot accidentally reuse an old child's readiness marker.
        let _=fs::remove_file(root.join(READY_FILE));
        let _=fs::remove_file(root.join(STOP_FILE));
        let child=Command::new(std::env::current_exe().unwrap())
            .args(["--exact","child_remote_anchor_service_process","--nocapture"])
            .env(CHILD_ROOT,root)
            .stdout(Stdio::piped())
            // Error diagnostics from the separate OS process stay visible
            // when the parent test itself fails before reaping the child.
            .stderr(Stdio::inherit())
            .spawn().unwrap();
        let mut instance=Self {
            root:root.to_owned(), child:Some(child),
            addr:EndpointAddr::new(key(43).public()),
        };
        let deadline=Instant::now()+Duration::from_secs(7);
        while !root.join(READY_FILE).exists() {
            if Instant::now()>=deadline {
                panic!("separate authority child did not publish QUIC address");
            }
            if instance.child.as_mut().unwrap().try_wait().unwrap().is_some() {
                let output=instance.child.take().unwrap().wait_with_output().unwrap();
                panic!(
                    "authority child exited: stdout={} stderr={}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            thread::sleep(Duration::from_millis(8));
        }
        let address:SocketAddr=fs::read_to_string(root.join(READY_FILE))
            .unwrap().parse().unwrap();
        assert!(address.ip().is_loopback(),"lab authority must bind only loopback");
        instance.addr=EndpointAddr::new(key(43).public()).with_ip_addr(address);
        instance
    }
    fn address(&self)->EndpointAddr {self.addr.clone()}
    fn finish(mut self,crash:bool) {
        if crash {
            // Deliberately simulate abrupt loss of the AUTHORITY process,
            // without killing the separate W6 parent policy client.
            self.child.as_mut().unwrap().kill().unwrap();
            let _=self.child.take().unwrap().wait();
        } else {
            fs::write(self.root.join(STOP_FILE),b"stop").unwrap();
            let deadline=Instant::now()+Duration::from_secs(4);
            loop {
                if self.child.as_mut().unwrap().try_wait().unwrap().is_some() {
                    let output=self.child.take().unwrap().wait_with_output().unwrap();
                    assert!(
                        output.status.success(),
                        "authority child failed: stdout={} stderr={}",
                        String::from_utf8_lossy(&output.stdout),
                        String::from_utf8_lossy(&output.stderr)
                    );
                    break;
                }
                assert!(Instant::now()<deadline,"authority did not stop");
                thread::sleep(Duration::from_millis(15));
            }
        }
    }
}
impl Drop for ChildAuthority {
    fn drop(&mut self) {
        if let Some(mut child)=self.child.take() {
            let _=child.kill();
            let _=child.wait();
        }
    }
}
fn client(v:u8,addr:EndpointAddr)->RemoteAnchorClient {
    RemoteAnchorClient::start(key(v),addr,authority()).unwrap()
}
fn authorized_cas(
    client:&RemoteAnchorClient,old:PolicyCheckpoint,next:PolicyCheckpoint,
)->Result<(),AnchorError> {
    let command=signed(next.revision,PolicyOperation::Revoke);
    let proof=sign_anchor_transition(&root(),authority(),&command,old,next).unwrap();
    client.advance_signed(old,next,&command,&proof)
}

#[test]
fn separate_os_process_crash_restart_retains_cas_and_rejects_unauthorized_quic_keys() {
    let dir=tempdir().unwrap();
    let remote=dir.path().join("anchor.sqlite");
    let initial=cp(1,1);
    let advanced=cp(2,2);
    provision(&remote,initial);
    let service=ChildAuthority::start(dir.path());
    let reader=client(41,service.address());
    let administrator=client(42,service.address());
    let stranger=client(44,service.address());
    assert_eq!(reader.current().unwrap(),initial);
    assert_eq!(stranger.current().unwrap_err(),AnchorError::InvalidAttestation);
    assert_eq!(
        reader.advance(initial,advanced).unwrap_err(),
        AnchorError::InvalidAttestation
    );
    assert_eq!(
        administrator.advance(initial,advanced).unwrap_err(),
        AnchorError::InvalidAttestation
    );
    authorized_cas(&administrator,initial,advanced).unwrap();
    assert_eq!(reader.current().unwrap(),advanced);
    assert_eq!(
        authorized_cas(&administrator,initial,advanced).unwrap_err(),
        AnchorError::Conflict
    );
    // A sudden OS PROCESS KILL must NOT roll back the already committed
    // SQLite WAL + synchronous=FULL checkpoint on the authority side.
    service.finish(true);
    let service=ChildAuthority::start(dir.path());
    assert_eq!(client(41,service.address()).current().unwrap(),advanced);
    authorized_cas(&client(42,service.address()),advanced,cp(3,3)).unwrap();
    assert_eq!(client(41,service.address()).current().unwrap(),cp(3,3));
    service.finish(false);
}

#[test]
fn separate_os_process_rejects_restored_local_policy_after_signed_revoke() {
    let dir=tempdir().unwrap();
    let local_path=dir.path().join("policy.sqlite");
    let copy=dir.path().join("policy-before-revoke.sqlite");
    let remote_path=dir.path().join("anchor.sqlite");
    let mut initial=PeerEnrollmentDb::open(&local_path,root().verifying_key()).unwrap();
    initial.apply_signed(&signed(1,PolicyOperation::Allow)).unwrap();
    let initial_checkpoint=initial.checkpoint().unwrap();
    drop(initial);
    flush(&local_path);
    fs::copy(&local_path,&copy).unwrap();
    provision(&remote_path,initial_checkpoint);

    let server=ChildAuthority::start(dir.path());
    let reader=client(41,server.address());
    let admin=client(42,server.address());
    let binding=binding();
    let mut active=PeerEnrollmentDb::open_for_authority(
        &local_path,root().verifying_key(),authority(),
    ).unwrap();
    assert_eq!(active.authorize_anchored(&reader,lookup(&binding)).unwrap(),(id(7),3));
    let change=signed(2,PolicyOperation::Revoke);
    let (old,next)=active.preview_signed_update(&change).unwrap();
    let proof=sign_anchor_transition(&root(),authority(),&change,old,next).unwrap();
    active.apply_signed_anchored_with_proof(&change,&proof,&admin).unwrap();
    assert_eq!(reader.current().unwrap(),active.checkpoint().unwrap());
    drop(active);
    flush(&local_path);
    server.finish(true);

    // Roll back ONLY local enrollment; independent child OS process ledger
    // retains revoke checkpoint, even across the child process SIGKILL.
    fs::copy(&copy,&local_path).unwrap();
    let mut restored=PeerEnrollmentDb::open_for_authority(
        &local_path,root().verifying_key(),authority(),
    ).unwrap();
    assert_eq!(restored.last_revision().unwrap(),1);
    let server=ChildAuthority::start(dir.path());
    let fresh_reader=client(41,server.address());
    assert_eq!(fresh_reader.current().unwrap().revision,2);
    assert!(matches!(
        restored.authorize_anchored(&fresh_reader,lookup(&binding)),
        Err(EnrollmentError::CheckpointMismatch)
    ));
    let mut callback_executed=false;
    let result:Result<(),EnrollmentError>=restored.with_anchored_write(
        &fresh_reader,lookup(&binding),|_|{callback_executed=true;Ok(())}
    );
    assert!(matches!(result,Err(EnrollmentError::CheckpointMismatch)));
    assert!(!callback_executed,"rolled-back policy must never invoke Mailbox commit");
    server.finish(false);
}

#[test]
fn separate_os_process_unavailable_anchor_fails_closed_without_cached_trust() {
    let dir=tempdir().unwrap();
    let remote=dir.path().join("anchor.sqlite");
    let local=dir.path().join("policy.sqlite");
    let mut enrollment=PeerEnrollmentDb::open(&local,root().verifying_key()).unwrap();
    enrollment.apply_signed(&signed(1,PolicyOperation::Allow)).unwrap();
    let initial=enrollment.checkpoint().unwrap();
    drop(enrollment);
    let mut enrollment=PeerEnrollmentDb::open_for_authority(
        &local,root().verifying_key(),authority(),
    ).unwrap();
    provision(&remote,initial);
    let server=ChildAuthority::start(dir.path());
    let reader=client(41,server.address());
    let trusted_binding=binding();
    assert_eq!(
        enrollment.authorize_anchored(&reader,lookup(&trusted_binding)).unwrap(),
        (id(7),3)
    );
    server.finish(true);
    // With a terminated external process, the signed local allow and
    // cached TLS EndpointId are NOT sufficient for admission or storage.
    assert!(matches!(
        enrollment.authorize_anchored(&reader,lookup(&trusted_binding)),
        Err(EnrollmentError::Anchor(AnchorError::Unavailable))
    ));
    let mut called=false;
    let res:Result<(),EnrollmentError>=enrollment.with_anchored_write(
        &reader,lookup(&trusted_binding),|_|{called=true;Ok(())}
    );
    assert!(matches!(res,Err(EnrollmentError::Anchor(AnchorError::Unavailable))));
    assert!(!called);
}


/// Simulate a dropped QUIC response AFTER the real remote authority committed
/// the signed CAS. The fake part is only the lost reply; the CAS itself crosses
/// a real Roha/noq connection into an independent OS child and SQLite WAL.
struct LostCasReply<'a>(&'a RemoteAnchorClient);
impl TrustedPolicyAnchor for LostCasReply<'_> {
    fn authority_domain(&self)->Option<AuthorityDomainId> {
        self.0.authority_domain()
    }
    fn current(&self) -> Result<PolicyCheckpoint,AnchorError> {
        self.0.current()
    }
    fn advance(
        &self,_:PolicyCheckpoint,_:PolicyCheckpoint,
    ) -> Result<(),AnchorError> {
        Err(AnchorError::InvalidAttestation)
    }
    fn advance_signed(
        &self,old:PolicyCheckpoint,next:PolicyCheckpoint,
        change:&[u8],proof:&[u8],
    ) -> Result<(),AnchorError> {
        self.0.advance_signed(old,next,change,proof)?;
        Err(AnchorError::Unavailable)
    }
}

#[test]
fn real_quic_signed_cas_lost_reply_recovers_after_authority_restart_and_policy_reopen() {
    let dir=tempdir().unwrap();
    let local_path=dir.path().join("policy.sqlite");
    let remote_path=dir.path().join("anchor.sqlite");
    let mut local=PeerEnrollmentDb::open(&local_path,root().verifying_key()).unwrap();
    local.apply_signed(&signed(1,PolicyOperation::Allow)).unwrap();
    let expected=local.checkpoint().unwrap();
    drop(local);
    let mut local=PeerEnrollmentDb::open_for_authority(
        &local_path,root().verifying_key(),authority(),
    ).unwrap();
    provision(&remote_path,expected);
    let server=ChildAuthority::start(dir.path());
    let admin=client(42,server.address());
    let reader=client(41,server.address());
    let change=signed(2,PolicyOperation::Revoke);
    let (old,next)=local.preview_signed_update(&change).unwrap();
    assert_eq!(old,expected);
    let proof=sign_anchor_transition(&root(),authority(),&change,old,next).unwrap();
    let lost=LostCasReply(&admin);
    assert!(matches!(
        local.apply_signed_anchored_with_proof(&change,&proof,&lost),
        Err(EnrollmentError::Anchor(AnchorError::Unavailable))
    ));
    // Remote CAS succeeded on the wire, local policy is unchanged and HELD.
    assert_eq!(reader.current().unwrap(),next);
    assert_eq!(local.checkpoint().unwrap(),old);
    let trusted_binding=binding();
    let mut invoked=false;
    let blocked:Result<(),EnrollmentError>=local.with_anchored_write(
        &reader,lookup(&trusted_binding),|_| {invoked=true;Ok(())}
    );
    assert!(matches!(blocked,Err(EnrollmentError::PendingRecovery)));
    assert!(!invoked);
    drop(admin);
    drop(reader);
    drop(local);
    server.finish(true);

    // A new local DB connection and a killed/restarted remote process must
    // recover using ONLY the read-only, pinned authority identity. No second
    // signing ceremony, blind retry, or rewrite of the remote CAS is needed.
    let restarted=ChildAuthority::start(dir.path());
    let fresh_reader=client(41,restarted.address());
    assert_eq!(fresh_reader.current().unwrap(),next);
    let mut local=PeerEnrollmentDb::open_for_authority(
        &local_path,root().verifying_key(),authority(),
    ).unwrap();
    assert_eq!(
        local.recover_pending_signed_update(&fresh_reader).unwrap(),
        akula_wire_lab::peer_enrollment_w6::SignedRecoveryOutcome::AppliedAfterCas
    );
    assert_eq!(local.checkpoint().unwrap(),next);
    assert!(matches!(
        local.authorize_anchored(&fresh_reader,lookup(&trusted_binding)),
        Err(EnrollmentError::Revoked)
    ));
    assert_eq!(
        local.recover_pending_signed_update(&fresh_reader).unwrap(),
        akula_wire_lab::peer_enrollment_w6::SignedRecoveryOutcome::NoPending
    );
    restarted.finish(false);
}

#[test]
fn separate_local_hosts_do_not_commit_after_cross_host_revoke() {
    use std::sync::mpsc;

    let dir=tempdir().unwrap();
    let a_path=dir.path().join("a-policy.sqlite");
    let b_path=dir.path().join("b-policy.sqlite");
    let mailbox_path=dir.path().join("b-mailbox.sqlite");
    let anchor_path=dir.path().join("anchor.sqlite");
    // Two physically separate SQLite files model two independent hosts.
    // Both are first bootstrapped with the SAME operator-approved state.
    let mut bootstrap=PeerEnrollmentDb::open(&a_path,root().verifying_key()).unwrap();
    bootstrap.apply_signed(&signed(1,PolicyOperation::Allow)).unwrap();
    let initial=bootstrap.checkpoint().unwrap();
    drop(bootstrap);
    flush(&a_path);
    fs::copy(&a_path,&b_path).unwrap();
    provision(&anchor_path,initial);
    let server=ChildAuthority::start(dir.path());
    let admin=client(42,server.address());
    let mut host_a=PeerEnrollmentDb::open_for_authority(
        &a_path,root().verifying_key(),authority(),
    ).unwrap();

    let (entered_tx,entered_rx)=mpsc::sync_channel::<()>(1);
    let (finish_tx,finish_rx)=mpsc::sync_channel::<()>(1);
    let writer_addr=server.address();
    let writer_mailbox_path=mailbox_path.clone();
    let writer=thread::spawn(move || -> Result<(),EnrollmentError> {
        let mut host_b=PeerEnrollmentDb::open_for_authority(
            &b_path,root().verifying_key(),authority(),
        )?;
        let reader=client(41,writer_addr);
        let local_binding=binding();
        host_b.with_anchored_write(
            &reader,lookup(&local_binding),|_|{
                // The remote fence was granted BEFORE callback entry.
                entered_tx.send(()).unwrap();
                finish_rx.recv_timeout(Duration::from_secs(7)).unwrap();
                // Actual independently durable Mailbox SQLite COMMIT on
                // host B, NOT merely an in-memory callback flag.
                let mut mailbox=Connection::open(&writer_mailbox_path)?;
                mailbox.execute_batch(
                    "PRAGMA journal_mode=WAL;
                     PRAGMA synchronous=FULL;
                     CREATE TABLE IF NOT EXISTS received (
                       id INTEGER PRIMARY KEY, body BLOB NOT NULL
                     );"
                )?;
                let tx=mailbox.transaction_with_behavior(
                    rusqlite::TransactionBehavior::Immediate
                )?;
                tx.execute(
                    "INSERT INTO received(id,body) VALUES(1,?1)",
                    rusqlite::params![b"durable mailbox commit".as_slice()],
                )?;
                tx.commit()?;
                Ok(())
            },
        )
    });

    entered_rx.recv_timeout(Duration::from_secs(7)).unwrap();
    let change=signed(2,PolicyOperation::Revoke);
    let (old,next)=host_a.preview_signed_update(&change).unwrap();
    let proof=sign_anchor_transition(&root(),authority(),&change,old,next).unwrap();
    assert_eq!(old,initial);
    assert!(matches!(
        host_a.apply_signed_anchored_with_proof(&change,&proof,&admin),
        Err(EnrollmentError::Anchor(AnchorError::Conflict))
    ));
    // The submitted revoke is durably HELD locally at host A. Authority
    // cannot claim the revocation is committed while host B is still writing.
    assert_eq!(admin.current().unwrap(),old);
    let mut invoked=false;
    let held:Result<(),EnrollmentError>=host_a.with_anchored_write(
        &admin,lookup(&binding()),|_|{invoked=true;Ok(())}
    );
    assert!(matches!(held,Err(EnrollmentError::PendingRecovery)));
    assert!(!invoked);

    finish_tx.send(()).unwrap();
    writer.join().unwrap().unwrap(); // writer's durable callback completed
    // Independent process/file reader verifies persisted Mailbox content.
    let persisted:i64=Connection::open(&mailbox_path).unwrap().query_row(
        "SELECT COUNT(*) FROM received WHERE id=1",[],|r|r.get(0)
    ).unwrap();
    assert_eq!(persisted,1);
    assert_eq!(
        host_a.recover_pending_signed_update(&admin).unwrap(),
        akula_wire_lab::peer_enrollment_w6::SignedRecoveryOutcome::ForwardedPending
    );
    assert_eq!(admin.current().unwrap(),next);

    // Host B's independent policy file STILL says "Allow", but can no
    // longer obtain a write permit from the external authority at rev=1.
    let mut host_b=PeerEnrollmentDb::open_for_authority(
        &dir.path().join("b-policy.sqlite"),root().verifying_key(),authority(),
    ).unwrap();
    let reader=client(41,server.address());
    let mut wrongly_committed=false;
    let stale:Result<(),EnrollmentError>=host_b.with_anchored_write(
        &reader,lookup(&binding()),|_|{wrongly_committed=true;Ok(())}
    );
    assert!(matches!(stale,Err(EnrollmentError::CheckpointMismatch)));
    assert!(!wrongly_committed);
    server.finish(false);
}

#[test]
fn real_quic_writer_fence_survives_authority_sigkill_until_explicit_finish() {
    let dir=tempdir().unwrap();
    let remote=dir.path().join("anchor.sqlite");
    let old=cp(1,1);
    let next=cp(2,2);
    provision(&remote,old);
    let server=ChildAuthority::start(dir.path());
    let reader=client(41,server.address());
    let nonce=[179;32];
    reader.begin_write_fence(old,nonce).unwrap();
    assert_eq!(reader.current().unwrap(),old);
    server.finish(true); // independent authority OS process SIGKILL

    let restarted=ChildAuthority::start(dir.path());
    let admin=client(42,restarted.address());
    let reader=client(41,restarted.address());
    assert!(matches!(
        authorized_cas(&admin,old,next),
        Err(AnchorError::Conflict)
    ));
    assert_eq!(reader.current().unwrap(),old);
    // No implicit timeouts or cleanup on child startup.
    assert!(matches!(
        reader.finish_write_fence(old,[180;32]),
        Err(AnchorError::Conflict)
    ));
    // Simulates explicit settlement only AFTER the writer has been stopped
    // or has positively completed its durable write.
    reader.finish_write_fence(old,nonce).unwrap();
    authorized_cas(&admin,old,next).unwrap();
    assert_eq!(reader.current().unwrap(),next);
    restarted.finish(false);
}
