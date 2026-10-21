//! W5: fail-closed intake, bounded storage, long-lived WAL readers.
use akula_wire_lab::mailbox_w5::{
    Mailbox, MailboxAdmission, MailboxLimits, MailError, PutStatus,
};
use tempfile::tempdir;

fn id(n: u8) -> [u8; 16] { [n; 16] }

#[test]
fn sqlite_page_full_pauses_intake_but_preserves_committed_data() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("pressure.sqlite");
    let mut original = Mailbox::open(&path, MailboxLimits::default()).unwrap();
    original.put(id(1), id(1), 0, 100, b"durable-before-pressure").unwrap();
    original.checkpoint_wal_truncate().unwrap();
    drop(original);
    let connection = rusqlite::Connection::open(&path).unwrap();
    let pages: i64 = connection.query_row("PRAGMA page_count", [], |r| r.get(0)).unwrap();
    drop(connection);

    let cap = u32::try_from(pages + 1).unwrap();
    let mut mail = Mailbox::open_with_main_page_limit(
        &path, MailboxLimits::default(), cap,
    ).unwrap();
    assert_eq!(mail.admission(), MailboxAdmission::Open);
    let mut seen_full = false;
    for n in 2u8..40 {
        match mail.put(id(n), id(n), 0, 100, &vec![n; 8192]) {
            Ok(PutStatus::Stored) => (),
            Err(MailError::Db(rusqlite::Error::SqliteFailure(ref error, _)))
                if error.code == rusqlite::ErrorCode::DiskFull =>
            {
                seen_full = true;
                break;
            }
            other => panic!("unexpected page-cap response: {other:?}"),
        }
    }
    assert!(seen_full);
    assert_eq!(mail.admission(), MailboxAdmission::PausedStorageFault);
    assert!(matches!(
        mail.put(id(99), id(99), 0, 100, b"must-pause"),
        Err(MailError::AdmissionPaused)
    ));
    assert_eq!(
        mail.get_page(id(1), 1, None, 1).unwrap()[0].bytes,
        b"durable-before-pressure"
    );
    drop(mail);

    // Restart is not proof of repaired media, but the existing page quota is
    // connection-scoped; with an explicit operator-chosen configuration
    // the previously committed bytes still pass their digest check.
    let restarted = Mailbox::open(&path, MailboxLimits::default()).unwrap();
    assert_eq!(
        restarted.get_page(id(1), 1, None, 1).unwrap()[0].bytes,
        b"durable-before-pressure"
    );
}

#[test]
fn long_lived_wal_reader_blocks_reclaim_during_many_successful_writes() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("pressure.sqlite");
    let mut mail = Mailbox::open(&path, MailboxLimits::default()).unwrap();
    mail.put(id(1), id(1), 0, 100, b"before").unwrap();
    mail.checkpoint_wal_truncate().unwrap();

    let reader = rusqlite::Connection::open(&path).unwrap();
    reader.execute_batch("BEGIN;").unwrap();
    let initial: i64 = reader.query_row(
        "SELECT COUNT(*) FROM mailbox_entries", [], |r| r.get(0),
    ).unwrap();
    assert_eq!(initial, 1);

    for n in 2u8..50 {
        mail.put(id(n), id(1), 0, 100, &vec![n; 2048]).unwrap();
    }
    assert_eq!(mail.stats().unwrap().messages, 49);
    let pending = mail.disk_usage().unwrap();
    assert!(pending.wal_bytes > 4096, "WAL should be pinned by reader");
    assert!(matches!(
        mail.checkpoint_wal_truncate(),
        Err(MailError::WalCheckpointBusy)
    ));
    assert_eq!(mail.admission(), MailboxAdmission::Open);
    assert_eq!(mail.stats().unwrap().messages, 49);

    reader.execute_batch("ROLLBACK;").unwrap();
    mail.checkpoint_wal_truncate().unwrap();
    assert_eq!(mail.disk_usage().unwrap().wal_bytes, 0);
    drop(mail);

    let opened = Mailbox::open(&path, MailboxLimits::default()).unwrap();
    assert_eq!(opened.stats().unwrap().messages, 49);
    assert_eq!(opened.get_page(id(1), 1, None, 1).unwrap()[0].bytes, b"before");
}
