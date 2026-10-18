//! W5 SQLite physical-storage observation and fail-closed main-page capacity.
//! This is NOT a hard total-filesystem limit: WAL/SHM are independent files.
use akula_wire_lab::mailbox_w5::{
    Mailbox, MailboxLimits, MailError, PutStatus,
};
use tempfile::tempdir;

fn id(n: u8) -> [u8; 16] { [n; 16] }

#[test]
fn main_database_page_cap_fails_closed_and_keeps_committed_rows() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("mail.sqlite");

    // Commit one previously accepted message before applying a tighter cap.
    let mut original = Mailbox::open(&path, MailboxLimits::default()).unwrap();
    assert_eq!(
        original.put(id(1), id(1), 0, 500, b"previously durable").unwrap(),
        PutStatus::Stored
    );
    drop(original);

    let conn = rusqlite::Connection::open(&path).unwrap();
    let used: i64 = conn.query_row("PRAGMA page_count", [], |r| r.get(0)).unwrap();
    drop(conn);
    let cap = u32::try_from(used + 1).unwrap();
    let mut mail = Mailbox::open_with_main_page_limit(
        &path, MailboxLimits::default(), cap,
    ).unwrap();
    assert_eq!(mail.main_page_limit().unwrap(), u64::from(cap));

    let mut successful = 0usize;
    let mut saw_sqlite_full = false;
    for next in 2u8..40 {
        let bytes = vec![next; 8192];
        match mail.put(id(next), id(1), 0, 500, &bytes) {
            Ok(PutStatus::Stored) => successful += 1,
            Err(MailError::Db(rusqlite::Error::SqliteFailure(inner, _)))
                if inner.code == rusqlite::ErrorCode::DiskFull =>
            {
                saw_sqlite_full = true;
                break;
            }
            Err(other) => panic!("unexpected insert outcome: {other:?}"),
            Ok(other) => panic!("unexpected insert status: {other:?}"),
        }
    }
    assert!(saw_sqlite_full, "page-cap test must reach SQLITE_FULL");
    assert_eq!(mail.stats().unwrap().messages, successful + 1);
    assert_eq!(
        mail.get_page(id(1), 1, None, 1).unwrap()[0].bytes,
        b"previously durable"
    );
    drop(mail);

    // SQLite's max_page_count is connection-scoped and MUST be reapplied.
    let reopened = Mailbox::open_with_main_page_limit(
        &path, MailboxLimits::default(), cap,
    ).unwrap();
    assert_eq!(reopened.main_page_limit().unwrap(), u64::from(cap));
    assert_eq!(reopened.stats().unwrap().messages, successful + 1);
    assert_eq!(
        reopened.get_page(id(1), 2, None, 1).unwrap()[0].bytes,
        b"previously durable"
    );
}

#[test]
fn disk_usage_and_idle_wal_checkpoint_preserve_mailbox_state() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("mail.sqlite");
    let mut mail = Mailbox::open(&path, MailboxLimits::default()).unwrap();
    mail.put(id(1), id(3), 0, 100, b"opaque-1").unwrap();
    mail.put(id(1), id(4), 0, 100, b"opaque-2").unwrap();

    let before = mail.disk_usage().unwrap();
    assert!(before.database_bytes > 0);
    assert!(before.total_bytes >= before.database_bytes);
    assert_eq!(
        before.total_bytes,
        before.database_bytes + before.wal_bytes + before.shm_bytes
    );

    let checkpoint = mail.checkpoint_wal_truncate().unwrap();
    assert!(checkpoint.log_frames >= 0);
    assert!(checkpoint.checkpointed_frames >= 0);
    let after = mail.disk_usage().unwrap();
    assert_eq!(after.wal_bytes, 0, "idle checkpoint should truncate WAL");
    assert!(after.database_bytes > 0);
    assert_eq!(mail.stats().unwrap().messages, 2);

    drop(mail);
    let reopened = Mailbox::open(&path, MailboxLimits::default()).unwrap();
    assert_eq!(reopened.stats().unwrap().messages, 2);
    let page = reopened.get_page(id(1), 1, None, 2).unwrap();
    assert_eq!(page[0].bytes, b"opaque-1");
    assert_eq!(page[1].bytes, b"opaque-2");
}

#[test]
fn invalid_page_cap_cannot_silently_become_an_unbounded_guard() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("mail.sqlite");
    assert!(matches!(
        Mailbox::open_with_main_page_limit(&path, MailboxLimits::default(), 0),
        Err(MailError::InvalidDiskLimit)
    ));
    assert!(matches!(
        Mailbox::open_with_main_page_limit(&path, MailboxLimits::default(), 1),
        Err(MailError::InvalidDiskLimit)
    ));
}
