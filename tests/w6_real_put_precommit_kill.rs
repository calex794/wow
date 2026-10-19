//! Opt-in, debug-only SIGKILL inside the actual Mailbox::put_inner.
//! The fault marker is emitted after INSERT but before tx.commit().
#![cfg(all(target_os = "linux", feature = "mailbox-put-fault-test", debug_assertions))]
use akula_wire_lab::mailbox_w5::{Mailbox, MailboxAdmission, MailboxLimits, MailError, PutStatus};
use std::{fs,process::{Command,Child,Stdio},path::Path,time::{Duration,Instant},thread};
use tempfile::tempdir;
const ENV:&str="STAYA_MAILBOX_PRECOMMIT_CHILD";
fn id(x:u8)->[u8;16]{[x;16]}
#[test]
fn child_actual_mailbox_put_stops_inside_transaction() {
    let Some(root)=std::env::var_os(ENV) else{return};
    let path=Path::new(&root).join("mail.sqlite");
    let mut db=Mailbox::open(&path,MailboxLimits::default()).unwrap();
    // No recovery grant is needed because this is a deliberately unguarded
    // diagnostic child only. The parent uses the protected baseline.
    // The parent protects admission via recovery gate, so resume explicitly.
    db.try_resume_after_maintenance().unwrap();
    let _ = db.put(id(4),id(6),101,200,b"interrupted-actual-put");
    panic!("precommit hook was bypassed");
}
struct ChildGuard(Option<Child>);
impl Drop for ChildGuard{fn drop(&mut self){if let Some(mut c)=self.0.take(){let _=c.kill();let _=c.wait();}}}
#[test]
fn sigkill_inside_actual_mailbox_put_rolls_back_and_restarts_paused(){
    let root=tempdir().unwrap();
    let path=root.path().join("mail.sqlite");
    let mut base=Mailbox::open_recovery_gated(&path,MailboxLimits::default()).unwrap();
    base.try_resume_after_maintenance().unwrap();
    assert_eq!(base.put(id(4),id(5),100,200,b"prior-committed").unwrap(),PutStatus::Stored);
    drop(base);
    let marker=path.with_extension("before-commit-marker");
    let child=Command::new(std::env::current_exe().unwrap())
        .args(["--exact","child_actual_mailbox_put_stops_inside_transaction","--nocapture"])
        .env(ENV,root.path()).stdout(Stdio::null()).stderr(Stdio::inherit()).spawn().unwrap();
    let mut child=ChildGuard(Some(child));
    let deadline=Instant::now()+Duration::from_secs(10);
    while !marker.exists(){
        assert!(child.0.as_mut().unwrap().try_wait().unwrap().is_none(),"child exited before INSERT");
        assert!(Instant::now()<deadline,"actual put never reached precommit fault hook");
        thread::sleep(Duration::from_millis(10));
    }
    let proc=child.0.as_mut().unwrap();
    assert!(proc.try_wait().unwrap().is_none());
    proc.kill().unwrap();
    assert!(!proc.wait().unwrap().success());
    child.0.take();
    let mut reopened=Mailbox::open(&path,MailboxLimits::default()).unwrap();
    assert_eq!(reopened.admission(),MailboxAdmission::PausedStorageFault);
    assert_eq!(reopened.stats().unwrap().messages,1);
    let entries=reopened.get_page(id(4),101,None,3).unwrap();
    assert_eq!(entries[0].id,id(5));
    assert_eq!(entries[0].bytes,b"prior-committed");
    assert!(matches!(reopened.put(id(4),id(6),101,200,b"interrupted-actual-put"),Err(MailError::AdmissionPaused)));
    reopened.try_resume_after_maintenance().unwrap();
    assert_eq!(reopened.put(id(4),id(6),101,200,b"interrupted-actual-put").unwrap(),PutStatus::Stored);
    assert_eq!(reopened.put(id(4),id(6),102,200,b"interrupted-actual-put").unwrap(),PutStatus::Duplicate);
    assert_eq!(reopened.stats().unwrap().messages,2);
}
