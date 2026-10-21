//! W5: enqueue is not a destructive cleanup authority. Only explicit
//! maintenance can expire mailbox records using caller-provided time.
use akula_wire_lab::mailbox_w5::{
    Mailbox, MailboxLimits, MailError, PutStatus,
};
use tempfile::tempdir;

fn id(value: u8) -> [u8; 16] { [value; 16] }

#[test]
fn enqueue_with_future_time_cannot_delete_other_tokens() {
    let tmp = tempdir().unwrap();
    let path = tmp.path().join("mail.sqlite");
    let limits = MailboxLimits {
        total_records: 1,
        per_token_records: 1,
        total_payload_bytes: 128,
        per_token_payload_bytes: 128,
        max_ttl_seconds: 200,
    };
    let mut mail = Mailbox::open(&path, limits).unwrap();
    assert!(matches!(
        mail.put(id(1), id(1), 0, 50, b"keep me"),
        Ok(PutStatus::Stored)
    ));
    // The old code would silently DELETE the first recipient's entry when
    // the second request carried an attacker-controlled future clock.
    assert!(matches!(
        mail.put(id(2), id(2), 10000, 10100, b"new"),
        Err(MailError::QuotaExceeded)
    ));
    assert_eq!(mail.stats().unwrap().messages, 1);
    assert_eq!(
        mail.get_page(id(1), 1, None, 1).unwrap()[0].bytes,
        b"keep me"
    );

    // Retention cleanup is a separate, privileged operation. Its caller
    // must provide independently trusted time; it is not a network request.
    assert_eq!(mail.purge_expired(50).unwrap(), 1);
    assert!(matches!(
        mail.put(id(2), id(2), 50, 100, b"new"),
        Ok(PutStatus::Stored)
    ));
}

#[test]
fn purge_watermark_survives_restart_and_rejects_rollback() {
    let tmp = tempdir().unwrap();
    let path = tmp.path().join("mail.sqlite");
    {
        let mut mail = Mailbox::open(&path, MailboxLimits::default()).unwrap();
        mail.put(id(1), id(1), 1, 10, b"old").unwrap();
        assert_eq!(mail.purge_expired(12).unwrap(), 1);
        assert!(matches!(
            mail.put(id(2), id(2), 11, 20, b"backdated"),
            Err(MailError::ClockRollback)
        ));
    }
    {
        let mut mail = Mailbox::open(&path, MailboxLimits::default()).unwrap();
        assert!(matches!(
            mail.get_page(id(1), 11, None, 1),
            Err(MailError::ClockRollback)
        ));
        assert!(matches!(
            mail.purge_expired(11),
            Err(MailError::ClockRollback)
        ));
        assert!(matches!(
            mail.put(id(2), id(2), 12, 20, b"fresh"),
            Ok(PutStatus::Stored)
        ));
        assert_eq!(mail.stats().unwrap().messages, 1);
    }
}

#[test]
fn failed_purge_rolls_back_deletion_and_clock_watermark() {
    let tmp = tempdir().unwrap();
    let path = tmp.path().join("mail.sqlite");
    let mut mail = Mailbox::open(&path, MailboxLimits::default()).unwrap();
    mail.put(id(1), id(1), 0, 10, b"keep").unwrap();
    let guard = rusqlite::Connection::open(&path).unwrap();
    guard.execute_batch(
        "CREATE TRIGGER abort_mail_gc BEFORE DELETE ON mailbox_entries          BEGIN SELECT RAISE(ABORT, 'injected maintenance failure'); END;"
    ).unwrap();

    assert!(matches!(mail.purge_expired(11), Err(MailError::Db(_))));
    assert_eq!(mail.stats().unwrap().messages, 1);
    // A failed purge did not durably advance the watermark.
    assert_eq!(mail.get_page(id(1), 0, None, 1).unwrap()[0].bytes, b"keep");
    guard.execute_batch("DROP TRIGGER abort_mail_gc;").unwrap();
    assert_eq!(mail.purge_expired(11).unwrap(), 1);
    assert!(matches!(
        mail.get_page(id(1), 10, None, 1),
        Err(MailError::ClockRollback)
    ));
}
