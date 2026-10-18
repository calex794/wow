//! Actual two-OS-process SQLite policy lock test for W6 Mailbox writes.
//! Uses a separate Rust test executable process and one SQLite policy file,
//! not threads sharing a Mutex. Roha/noq QUIC identity is tested separately.
#![cfg(feature = "iroh-transport")]

use akula_wire_lab::mailbox_w5::{Mailbox, MailboxLimits, PutStatus};
use akula_wire_lab::peer_enrollment_w6::{
    sign_operator_change, EndpointRouteBinding, EnrollmentError, OperatorChange,
    PeerEnrollmentDb, PolicyOperation,
};
use ed25519_dalek::SigningKey;
use iroh::EndpointId;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::tempdir;

fn id(v: u8) -> [u8;16] { [v;16] }
fn owner() -> SigningKey { SigningKey::from_bytes(&[220;32]) }
fn binding() -> EndpointRouteBinding {
    let endpoint_signer = SigningKey::from_bytes(&[1;32]);
    EndpointRouteBinding {
        endpoint_id:EndpointId::from_bytes(
            &endpoint_signer.verifying_key().to_bytes(),
        ).unwrap(),
        w3_device_id:id(7),w3_epoch:3,
        relay_id:id(8),namespace:id(9),route_token:id(10),
        issuer_id:id(11),
    }
}
fn change(rev:u64,operation:PolicyOperation) -> Vec<u8> {
    sign_operator_change(&owner(),&OperatorChange {
        operation,revision:rev,binding:binding(),
    }).unwrap()
}
fn enroll(path:&Path) -> PeerEnrollmentDb {
    let mut policy=PeerEnrollmentDb::open(path,owner().verifying_key()).unwrap();
    policy.apply_signed(&change(1,PolicyOperation::Allow)).unwrap();
    policy
}
fn await_file(path:&Path) {
    let deadline=Instant::now()+Duration::from_secs(5);
    while Instant::now()<deadline {
        if path.exists() {return;}
        thread::sleep(Duration::from_millis(5));
    }
    panic!("child process did not create {}",path.display());
}
fn authorize(policy:&PeerEnrollmentDb) -> Result<([u8;16],u64),EnrollmentError> {
    let b=binding();
    policy.authorize(
        &b.endpoint_id,&b.relay_id,&b.namespace,&b.route_token,&b.issuer_id
    )
}

/// This test function is also a small process entrypoint, invoked with
/// --exact by the parent regression. During ordinary cargo test it does
/// nothing. Child uses an INDEPENDENT SQLite connection.
#[test]
fn child_process_applies_signed_revocation() {
    let Some(path)=std::env::var_os("STAYA_W6_POLICY_CHILD_DIR") else {return;};
    let root=PathBuf::from(path);
    let db=root.join("policy.sqlite");
    let signed=fs::read(root.join("signed-revoke.bin")).unwrap();
    let mut separate=PeerEnrollmentDb::open(&db,owner().verifying_key()).unwrap();
    fs::write(root.join("child-ready"),b"ready").unwrap();
    await_file(&root.join("go"));
    fs::write(root.join("child-started"),b"started").unwrap();
    separate.apply_signed(&signed).unwrap();
    fs::write(root.join("child-revoked"),b"revoked").unwrap();
}

#[test]
fn real_child_revocation_cannot_overtake_inflight_mailbox_commit() {
    let dir=tempdir().unwrap();
    let path=dir.path().join("policy.sqlite");
    let mut policy=enroll(&path);
    fs::write(dir.path().join("signed-revoke.bin"),
              change(2,PolicyOperation::Revoke)).unwrap();
    let mut mail=Mailbox::open_recovery_gated(
        &dir.path().join("mail.sqlite"),MailboxLimits::default(),
    ).unwrap();
    mail.try_resume_after_maintenance().unwrap();

    let mut child=Command::new(std::env::current_exe().unwrap())
        .args(["--exact","child_process_applies_signed_revocation","--nocapture"])
        .env("STAYA_W6_POLICY_CHILD_DIR",dir.path())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn().unwrap();
    // Confirm the separate OS process opened its *own* SQLite connection.
    await_file(&dir.path().join("child-ready"));
    let b=binding();
    let written=policy.with_authorized_write(
        &b.endpoint_id,&b.relay_id,&b.namespace,&b.route_token,&b.issuer_id,
        |(device,epoch)| {
            assert_eq!((device,epoch),(id(7),3));
            // Child is now allowed to attempt a competing SQLite IMMEDIATE
            // policy transaction, while this one holds its WRITE lock.
            fs::write(dir.path().join("go"),b"go").unwrap();
            await_file(&dir.path().join("child-started"));
            thread::sleep(Duration::from_millis(160));
            assert!(child.try_wait().unwrap().is_none(),
                "revocation must NOT complete before Mailbox commit");
            assert!(!dir.path().join("child-revoked").exists());
            let out=mail.put(id(10),id(55),100,200,b"durable opaque bytes")
                .unwrap();
            assert_eq!(out,PutStatus::Stored);
            Ok::<_,EnrollmentError>(out)
        }
    ).unwrap();
    assert_eq!(written,PutStatus::Stored);

    // The policy SQLite lock is now released; revocation is free to commit.
    let output=child.wait_with_output().unwrap();
    assert!(output.status.success(),"child failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(dir.path().join("child-revoked").exists());
    let persisted=PeerEnrollmentDb::open(&path,owner().verifying_key()).unwrap();
    assert!(matches!(authorize(&persisted),Err(EnrollmentError::Revoked)));
    assert_eq!(persisted.last_revision().unwrap(),2);
    assert_eq!(mail.stats().unwrap().messages,1);
    assert_eq!(
        mail.get_page(id(10),101,None,1).unwrap()[0].bytes,
        b"durable opaque bytes"
    );

    // Once the revoke has committed, new Mailbox commits are refused,
    // even if the network TLS and old signed grant remain valid.
    let mut after=PeerEnrollmentDb::open(&path,owner().verifying_key()).unwrap();
    let mut called=false;
    let blocked:Result<(),EnrollmentError>=after.with_authorized_write(
        &b.endpoint_id,&b.relay_id,&b.namespace,&b.route_token,&b.issuer_id,
        |_| {called=true;Ok(())}
    );
    assert!(matches!(blocked,Err(EnrollmentError::Revoked)));
    assert!(!called,"storage callback must not run after revoked policy");
    assert_eq!(mail.stats().unwrap().messages,1);
}

#[test]
fn policy_gate_rolls_back_on_failed_mailbox_callback_and_unblocks_revoker() {
    let dir=tempdir().unwrap();
    let path=dir.path().join("policy.sqlite");
    let mut first=enroll(&path);
    let mut second=PeerEnrollmentDb::open(&path,owner().verifying_key()).unwrap();
    let b=binding();
    let callback:Result<(),EnrollmentError>=first.with_authorized_write(
        &b.endpoint_id,&b.relay_id,&b.namespace,&b.route_token,&b.issuer_id,
        |_| Err(EnrollmentError::CorruptStorage),
    );
    assert!(matches!(callback,Err(EnrollmentError::CorruptStorage)));
    // Its dropped transaction released the cross-process writer lock, and
    // no policy revision was modified by the failed storage callback.
    assert_eq!(first.last_revision().unwrap(),1);
    second.apply_signed(&change(2,PolicyOperation::Revoke)).unwrap();
    assert!(matches!(authorize(&first),Err(EnrollmentError::Revoked)));
}
