//! W6 storage-only crash boundary: SIGKILL an independent OS process while
//! the real Mailbox SQLite schema contains an UNCOMMITTED inserted packet.
//!
//! The writer starts BEGIN IMMEDIATE, INSERTs into mailbox_entries and waits
//! WITHOUT committing. The parent kills the child, opens the protected
//! Mailbox, and verifies that prior ciphertext remains byte-exact while the
//! uncommitted row is absent. The restart gate must stay CLOSED until explicit
//! maintenance; then a normal Mailbox::put may commit that same message.
//!
//! This is a deterministic SQLite/WAL crash-boundary test, NOT an injected
//! failpoint inside Mailbox::put_inner or an actual power-cut / fsync test.
//! The test uses synthetic bytes, no WAN traffic and a temporary directory.
#![cfg(target_os = "linux")]

use akula_wire_lab::mailbox_w5::{
    Mailbox, MailboxAdmission, MailboxLimits, MailError, PutStatus,
};
use rusqlite::{params, Connection, TransactionBehavior};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use tempfile::tempdir;

const ROOT_ENV: &str = "STAYA_W6_UNCOMMITTED_SQLITE_CHILD_ROOT";
const MARKER: &str = "uncommitted-insert-visible-to-child";
const MAX_WAIT: Duration = Duration::from_secs(10);
const ROUTE: [u8; 16] = [4; 16];
const BASELINE_ID: [u8; 16] = [5; 16];
const INTERRUPTED_ID: [u8; 16] = [6; 16];
const BASELINE_BYTES: &[u8] = b"synthetic-opaque-already-committed";
const INTERRUPTED_BYTES: &[u8] = b"synthetic-opaque-interrupted-insert";

struct KillOnDrop(Option<Child>);
impl Drop for KillOnDrop {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
impl KillOnDrop {
    fn terminate_and_reap(&mut self) {
        let child = self.0.as_mut().expect("child still exists");
        assert!(
            child.try_wait().unwrap().is_none(),
            "child exited before an OS SIGKILL; no crash was simulated"
        );
        child.kill().expect("send SIGKILL to independent SQLite writer");
        let status = child.wait().expect("reap killed SQLite writer");
        assert!(!status.success(), "SIGKILL unexpectedly exited successfully");
        self.0.take();
    }
}

fn db_path(root: &Path) -> PathBuf {
    root.join("mail.sqlite")
}

#[test]
fn child_holds_an_uncommitted_insert_in_real_mailbox_sqlite_schema() {
    let Some(root) = std::env::var_os(ROOT_ENV) else {
        return;
    };
    let root = PathBuf::from(root);
    let mut db = Connection::open(db_path(&root)).expect("open prepared mailbox DB");
    db.busy_timeout(Duration::from_secs(3)).unwrap();
    db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;")
        .unwrap();

    // Equivalent SQLite transaction class and insertion schema to the
    // Mailbox::put_inner storage boundary, without bypassing production
    // Mailbox::put or adding a network-controlled failpoint.
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)
        .expect("begin the uncommitted WAL transaction");
    let digest = blake3::hash(INTERRUPTED_BYTES);
    tx.execute(
        "INSERT INTO mailbox_entries
           (route_token, message_id, digest, sealed, expires_at, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            ROUTE.as_slice(), INTERRUPTED_ID.as_slice(),
            digest.as_bytes().as_slice(), INTERRUPTED_BYTES, 200i64, 100i64,
        ],
    )
    .expect("insert uncommitted synthetic opaque message");
    let internal_count: i64 = tx.query_row(
        "SELECT COUNT(*) FROM mailbox_entries WHERE route_token=?1",
        params![ROUTE.as_slice()],
        |row| row.get(0),
    ).unwrap();
    assert_eq!(internal_count, 2, "child did not reach the INSERT boundary");

    // Publish the marker ONLY while tx is alive, after INSERT but BEFORE
    // COMMIT. A rename prevents the parent observing a half-written marker.
    fs::write(root.join("txn-marker.tmp"), b"INSERTED_NOT_COMMITTED").unwrap();
    fs::rename(root.join("txn-marker.tmp"), root.join(MARKER)).unwrap();

    // The parent SIGKILLs this process. If the process is not killed,
    // failing is preferable to a false proof of mid-transaction crash.
    thread::sleep(Duration::from_secs(30));
    panic!("child unexpectedly survived the SIGKILL crash gate");
}

fn await_child_insert(root: &Path, child: &mut Child) {
    let deadline = Instant::now() + MAX_WAIT;
    while !root.join(MARKER).exists() {
        assert!(
            child.try_wait().unwrap().is_none(),
            "writer exited before reaching the uncommitted INSERT"
        );
        assert!(
            Instant::now() < deadline,
            "writer never reached the uncommitted SQLite INSERT"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn independent_sigkill_before_commit_rolls_back_only_the_new_message() {
    let root = tempdir().unwrap();
    let path = db_path(root.path());

    // Establish a confirmed committed baseline in the actual library API,
    // with the durable fail-closed restart admission policy enabled.
    let mut original = Mailbox::open_recovery_gated(
        &path, MailboxLimits::default(),
    ).unwrap();
    assert_eq!(original.admission(), MailboxAdmission::PausedStorageFault);
    original.try_resume_after_maintenance().unwrap();
    assert_eq!(
        original.put(ROUTE, BASELINE_ID, 100, 200, BASELINE_BYTES).unwrap(),
        PutStatus::Stored
    );
    drop(original);

    // Real child OS process, same on-disk schema, separate SQLite Connection.
    let child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "child_holds_an_uncommitted_insert_in_real_mailbox_sqlite_schema",
            "--nocapture",
        ])
        .env(ROOT_ENV, root.path())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn independent SQLite writer");
    let mut child = KillOnDrop(Some(child));
    await_child_insert(root.path(), child.0.as_mut().unwrap());
    child.terminate_and_reap();

    // A crash BEFORE COMMIT must preserve prior durable ciphertext while
    // rolling back the uncommitted row, even after opening from scratch.
    let mut reopened = Mailbox::open(&path, MailboxLimits::default()).unwrap();
    assert_eq!(reopened.admission(), MailboxAdmission::PausedStorageFault);
    assert_eq!(reopened.stats().unwrap().messages, 1);
    let rows = reopened.get_page(ROUTE, 101, None, 3).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].id, BASELINE_ID);
    assert_eq!(rows[0].bytes, BASELINE_BYTES);
    assert!(matches!(
        reopened.put(ROUTE, INTERRUPTED_ID, 101, 200, INTERRUPTED_BYTES),
        Err(MailError::AdmissionPaused)
    ));
    assert_eq!(reopened.stats().unwrap().messages, 1);

    // Only an explicit trusted maintenance action lifts the persisted
    // restart guard. The regular Mailbox code then stores the rejected ID
    // exactly once; an exact retry is Duplicate, not another insertion.
    reopened.try_resume_after_maintenance().unwrap();
    assert_eq!(reopened.admission(), MailboxAdmission::Open);
    assert_eq!(
        reopened.put(ROUTE, INTERRUPTED_ID, 101, 200, INTERRUPTED_BYTES).unwrap(),
        PutStatus::Stored
    );
    assert_eq!(
        reopened.put(ROUTE, INTERRUPTED_ID, 102, 200, INTERRUPTED_BYTES).unwrap(),
        PutStatus::Duplicate
    );
    drop(reopened);

    let last = Mailbox::open(&path, MailboxLimits::default()).unwrap();
    assert_eq!(last.admission(), MailboxAdmission::PausedStorageFault);
    assert_eq!(last.stats().unwrap().messages, 2);
    let rows = last.get_page(ROUTE, 103, None, 3).unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].id, BASELINE_ID);
    assert_eq!(rows[0].bytes, BASELINE_BYTES);
    assert_eq!(rows[1].id, INTERRUPTED_ID);
    assert_eq!(rows[1].bytes, INTERRUPTED_BYTES);

    eprintln!(
        "W6_SQLITE_SIGKILL_BOUNDARY preexisting=1 rollback_uncommitted=1 \
         restart_paused=1 explicit_recovery=1 final_records=2 \
         semantics=sqlite_wal_not_mailbox_put_inner"
    );
}
