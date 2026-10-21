//! W5: fail-closed guarded admission is checked after restart, including
//! calls from the older Mailbox::open constructor.
use akula_wire_lab::mailbox_w5::{
    Mailbox, MailboxAdmission, MailboxLimits, MailError, PutStatus,
};
use tempfile::tempdir;

fn id(n: u8) -> [u8; 16] { [n; 16] }

#[test]
fn protected_mailbox_reopens_paused_even_via_legacy_constructor() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("mail.sqlite");

    // An already-open legacy connection must NOT bypass enabling the policy.
    let mut old_connection = Mailbox::open(&path, MailboxLimits::default()).unwrap();
    old_connection.put(id(1), id(1), 0, 100, b"already-committed").unwrap();

    let mut guarded = Mailbox::open_recovery_gated(
        &path, MailboxLimits::default(),
    ).unwrap();
    assert_eq!(guarded.admission(), MailboxAdmission::PausedStorageFault);
    assert!(matches!(
        guarded.put(id(1), id(2), 0, 100, b"not-yet-authorized"),
        Err(MailError::AdmissionPaused)
    ));
    assert!(matches!(
        old_connection.put(id(1), id(3), 0, 100, b"stale-handle"),
        Err(MailError::AdmissionPaused)
    ));
    assert_eq!(
        old_connection.admission(), MailboxAdmission::PausedStorageFault
    );

    guarded.try_resume_after_maintenance().unwrap();
    assert_eq!(guarded.admission(), MailboxAdmission::Open);
    assert_eq!(
        guarded.put(id(1), id(2), 0, 100, b"after-authorization").unwrap(),
        PutStatus::Stored
    );
    drop(guarded);
    drop(old_connection);

    // Simulate restarting the process. The stored policy is sufficient to
    // reject new puts; no best-effort write of "faulted" is required at ENOSPC.
    let mut rebooted = Mailbox::open(&path, MailboxLimits::default()).unwrap();
    assert_eq!(rebooted.admission(), MailboxAdmission::PausedStorageFault);
    assert!(matches!(
        rebooted.put(id(1), id(4), 0, 100, b"restart-denied"),
        Err(MailError::AdmissionPaused)
    ));
    assert_eq!(rebooted.stats().unwrap().messages, 2);
    let entries = rebooted.get_page(id(1), 1, None, 3).unwrap();
    assert_eq!(entries[0].bytes, b"already-committed");
    assert_eq!(entries[1].bytes, b"after-authorization");

    rebooted.try_resume_after_maintenance().unwrap();
    assert_eq!(rebooted.admission(), MailboxAdmission::Open);
    assert_eq!(
        rebooted.put(id(1), id(4), 1, 100, b"after-restart-recovery").unwrap(),
        PutStatus::Stored
    );
}

#[test]
fn reactivating_guard_revokes_previous_process_grant() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("mail.sqlite");
    let mut a = Mailbox::open_recovery_gated(
        &path, MailboxLimits::default(),
    ).unwrap();
    a.try_resume_after_maintenance().unwrap();
    a.put(id(1), id(1), 0, 100, b"written-by-a").unwrap();

    let mut b = Mailbox::open_recovery_gated(
        &path, MailboxLimits::default(),
    ).unwrap();
    // The durable recovery epoch changed: old process-local token is stale.
    assert!(matches!(
        a.put(id(1), id(2), 0, 100, b"stale-epoch"),
        Err(MailError::AdmissionPaused)
    ));
    assert_eq!(a.admission(), MailboxAdmission::PausedStorageFault);
    assert!(matches!(
        b.put(id(1), id(3), 0, 100, b"not-yet-recovered"),
        Err(MailError::AdmissionPaused)
    ));
    b.try_resume_after_maintenance().unwrap();
    b.put(id(1), id(4), 0, 100, b"committed-by-b").unwrap();
    assert_eq!(b.stats().unwrap().messages, 2);
}

#[test]
fn failed_recovery_transaction_cannot_unlock_guard_after_restart() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("mail.sqlite");
    let mut guarded = Mailbox::open_recovery_gated(
        &path, MailboxLimits::default(),
    ).unwrap();

    let injector = rusqlite::Connection::open(&path).unwrap();
    injector.execute_batch(
        "CREATE TRIGGER fail_recovery BEFORE UPDATE ON mailbox_admission_policy
         BEGIN SELECT RAISE(ABORT, 'simulated recovery failure'); END;"
    ).unwrap();
    assert!(matches!(
        guarded.try_resume_after_maintenance(),
        Err(MailError::Db(_))
    ));
    assert_eq!(guarded.admission(), MailboxAdmission::PausedStorageFault);
    drop(guarded);

    let mut reopened = Mailbox::open(&path, MailboxLimits::default()).unwrap();
    assert_eq!(reopened.admission(), MailboxAdmission::PausedStorageFault);
    assert!(matches!(
        reopened.put(id(1), id(1), 0, 100, b"must-not-commit"),
        Err(MailError::AdmissionPaused)
    ));
    injector.execute_batch("DROP TRIGGER fail_recovery;").unwrap();
    reopened.try_resume_after_maintenance().unwrap();
    reopened.put(id(1), id(1), 0, 100, b"committed-after-recovery").unwrap();
    assert_eq!(reopened.stats().unwrap().messages, 1);
}

#[test]
fn unguarded_legacy_experiments_remain_unchanged_until_explicit_opt_in() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("lab.sqlite");
    let mut mail = Mailbox::open(&path, MailboxLimits::default()).unwrap();
    assert_eq!(mail.admission(), MailboxAdmission::Open);
    assert_eq!(
        mail.put(id(1), id(1), 0, 100, b"legacy-lab").unwrap(),
        PutStatus::Stored
    );
    drop(mail);
    let mut reopened = Mailbox::open(&path, MailboxLimits::default()).unwrap();
    assert_eq!(reopened.admission(), MailboxAdmission::Open);
    reopened.put(id(1), id(2), 0, 100, b"legacy-restart").unwrap();
    assert_eq!(reopened.stats().unwrap().messages, 2);
}
