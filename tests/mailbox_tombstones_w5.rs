//! W5: bounded post-expiry MessageId reservations.
//! These are local anti-replay markers, not end-recipient acknowledgments.
use akula_wire_lab::mailbox_w5::{
    Mailbox, MailboxLimits, MailError, PutStatus,
};
use tempfile::tempdir;

fn id(n: u8) -> [u8; 16] { [n; 16] }

fn limits(total: usize, per_token: usize) -> MailboxLimits {
    MailboxLimits {
        total_records: total,
        per_token_records: per_token,
        total_payload_bytes: 1024,
        per_token_payload_bytes: 512,
        max_ttl_seconds: 100,
    }
}

#[test]
fn deleted_id_is_reserved_after_restart_without_leaking_across_tokens() {
    let tmp = tempdir().unwrap();
    let path = tmp.path().join("mail.sqlite");
    {
        let mut mail = Mailbox::open(&path, limits(4, 2)).unwrap();
        assert_eq!(
            mail.put(id(1), id(7), 0, 20, b"original").unwrap(),
            PutStatus::Stored
        );
        assert_eq!(mail.purge_expired(20).unwrap(), 1);
        assert_eq!(mail.stats().unwrap().messages, 0);
        assert_eq!(mail.stats().unwrap().tombstones, 1);
    }
    {
        let mut mail = Mailbox::open(&path, limits(4, 2)).unwrap();
        for payload in [&b"original"[..], &b"changed"[..]] {
            assert!(matches!(
                mail.put(id(1), id(7), 21, 50, payload),
                Err(MailError::ReusedMessageId)
            ));
        }
        // MessageId is reserved per routing token, not across recipients.
        assert_eq!(
            mail.put(id(2), id(7), 21, 50, b"independent").unwrap(),
            PutStatus::Stored
        );
        assert_eq!(mail.stats().unwrap().tombstones, 1);
    }
}

#[test]
fn tombstone_quota_fail_closed_without_losing_expired_ciphertext() {
    let tmp = tempdir().unwrap();
    let path = tmp.path().join("mail.sqlite");
    let mut mail = Mailbox::open(&path, limits(3, 1)).unwrap();
    mail.put(id(1), id(1), 0, 10, b"first").unwrap();
    assert_eq!(mail.purge_expired(10).unwrap(), 1);
    mail.put(id(1), id(2), 10, 20, b"second").unwrap();

    // The first tombstone occupies the one-record per-token budget.
    assert!(matches!(
        mail.purge_expired(20),
        Err(MailError::TombstoneQuotaExceeded)
    ));
    let stats = mail.stats().unwrap();
    assert_eq!((stats.messages, stats.tombstones), (1, 1));
    assert_eq!(
        mail.get_page(id(1), 11, None, 1).unwrap()[0].bytes,
        b"second"
    );

    // Once the first reservation ages out, a later GC can proceed.
    assert_eq!(mail.purge_expired(110).unwrap(), 1);
    let stats = mail.stats().unwrap();
    assert_eq!((stats.messages, stats.tombstones), (0, 1));
    assert_eq!(
        mail.put(id(1), id(1), 110, 120, b"after-window").unwrap(),
        PutStatus::Stored
    );
}

#[test]
fn total_tombstone_budget_is_distinct_from_live_message_quota() {
    let tmp = tempdir().unwrap();
    let path = tmp.path().join("mail.sqlite");
    let mut mail = Mailbox::open(&path, limits(1, 1)).unwrap();
    mail.put(id(1), id(1), 0, 10, b"first").unwrap();
    assert_eq!(mail.purge_expired(10).unwrap(), 1);
    // A live record may be stored while one unrelated tombstone exists.
    assert_eq!(
        mail.put(id(2), id(2), 10, 20, b"other").unwrap(),
        PutStatus::Stored
    );
    assert!(matches!(
        mail.purge_expired(20),
        Err(MailError::TombstoneQuotaExceeded)
    ));
    let stats = mail.stats().unwrap();
    assert_eq!((stats.messages, stats.tombstones), (1, 1));
}

#[test]
fn tombstone_insert_failure_rolls_back_deletion_and_gc_high_watermark() {
    let tmp = tempdir().unwrap();
    let path = tmp.path().join("mail.sqlite");
    let mut mail = Mailbox::open(&path, limits(2, 2)).unwrap();
    mail.put(id(1), id(1), 0, 10, b"original").unwrap();
    let guard = rusqlite::Connection::open(&path).unwrap();
    guard.execute_batch(
        "CREATE TRIGGER abort_tombstone BEFORE INSERT ON mailbox_tombstones
         BEGIN SELECT RAISE(ABORT, 'injected failure'); END;"
    ).unwrap();

    assert!(matches!(mail.purge_expired(10), Err(MailError::Db(_))));
    let stats = mail.stats().unwrap();
    assert_eq!((stats.messages, stats.tombstones), (1, 0));
    assert_eq!(
        mail.get_page(id(1), 0, None, 1).unwrap()[0].bytes,
        b"original"
    );
    guard.execute_batch("DROP TRIGGER abort_tombstone;").unwrap();
    assert_eq!(mail.purge_expired(10).unwrap(), 1);
    assert!(matches!(
        mail.put(id(1), id(1), 11, 20, b"original"),
        Err(MailError::ReusedMessageId)
    ));
}

#[test]
fn tombstone_reclamation_requires_explicit_trusted_maintenance() {
    let tmp = tempdir().unwrap();
    let path = tmp.path().join("mail.sqlite");
    let mut mail = Mailbox::open(&path, limits(2, 2)).unwrap();
    mail.put(id(1), id(9), 0, 10, b"old").unwrap();
    assert_eq!(mail.purge_expired(10).unwrap(), 1);
    assert_eq!(mail.purge_expired(109).unwrap(), 0);
    assert!(matches!(
        mail.put(id(1), id(9), 109, 150, b"reuse"),
        Err(MailError::ReusedMessageId)
    ));
    assert_eq!(mail.purge_expired(110).unwrap(), 0);
    assert_eq!(mail.stats().unwrap().tombstones, 0);
    // Reservations are deliberately finite: this is not lifetime uniqueness.
    assert_eq!(
        mail.put(id(1), id(9), 110, 150, b"reuse").unwrap(),
        PutStatus::Stored
    );
}
