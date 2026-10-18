//! OS-level disk exhaustion test. Run ONLY on a separately mounted, tiny
//! Linux filesystem; the ordinary cargo test suite leaves this test ignored.
//! Its output is not a production durability or hardware power-loss proof.
#![cfg(target_os = "linux")]

use akula_wire_lab::mailbox_w5::{
    Mailbox, MailboxAdmission, MailboxLimits, MailError, PutStatus,
};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;

fn id(n: u8) -> [u8; 16] { [n; 16] }

#[test]
#[ignore = "requires STAYA_ENOSPC_MOUNT on isolated size-limited Linux tmpfs"]
fn actual_os_enospc_never_returns_stored_or_loses_prior_ciphertext() {
    let root = PathBuf::from(std::env::var_os("STAYA_ENOSPC_MOUNT")
        .expect("dedicated STAYA_ENOSPC_MOUNT must be configured"));
    let root = root.canonicalize().unwrap();
    let parent = root.parent().expect("mountpoint must have parent");
    assert_ne!(
        fs::metadata(&root).unwrap().dev(),
        fs::metadata(parent).unwrap().dev(),
        "refusing to exhaust a directory on the runner's main filesystem"
    );

    let db = root.join("mailbox.sqlite");
    let filler_path = root.join("space-filler.bin");
    assert!(!db.exists());
    assert!(!filler_path.exists());

    // Activation is persisted BEFORE any successful data acceptance.
    let mut mail = Mailbox::open_recovery_gated(&db, MailboxLimits::default()).unwrap();
    assert_eq!(mail.admission(), MailboxAdmission::PausedStorageFault);
    mail.try_resume_after_maintenance().unwrap();
    let first = b"durable-before-real-enospc";
    assert_eq!(
        mail.put(id(1), id(1), 0, 100, first).unwrap(),
        PutStatus::Stored
    );
    mail.checkpoint_wal_truncate().unwrap();

    // Fill only the dedicated tmpfs. No host filesystem, root volume, or
    // process-wide ulimit is modified. Explicitly observe Linux ENOSPC (28).
    let mut filler = OpenOptions::new().write(true).create_new(true)
        .open(&filler_path).unwrap();
    let block = [0x5au8; 4096];
    let mut filled = 0usize;
    loop {
        match filler.write(&block) {
            Ok(0) => panic!("filler write made no progress"),
            Ok(n) => filled += n,
            Err(err) if err.raw_os_error() == Some(28) => break,
            Err(err) => panic!("unexpected filesystem write error: {err}"),
        }
    }
    assert!(filled > 0);
    eprintln!("observed OS ENOSPC after {filled} bytes of filler");
    let second = mail.put(id(2), id(2), 0, 100, &vec![0x3b; 8192]);
    match &second {
        Err(MailError::Db(rusqlite::Error::SqliteFailure(code, _))) => {
            assert!(
                matches!(code.code, rusqlite::ErrorCode::DiskFull |
                    rusqlite::ErrorCode::SystemIoFailure),
                "expected SQLite FULL/IOERR under OS ENOSPC, got {code:?}"
            );
        }
        other => panic!("message was unexpectedly accepted on full filesystem: {other:?}"),
    }
    assert_eq!(mail.admission(), MailboxAdmission::PausedStorageFault);
    assert!(matches!(
        mail.put(id(3), id(3), 0, 100, b"blocked while paused"),
        Err(MailError::AdmissionPaused)
    ));
    // This mailbox neither signs recipient receipts nor applies Sync Core.
    // Failure cannot become a successful mailbox store result.
    assert_eq!(
        mail.get_page(id(1), 1, None, 1).unwrap()[0].bytes,
        first
    );

    // Reboot after the OS volume is repaired. A failed write cannot persist
    // a fault flag under ENOSPC, so protected databases ALWAYS restart paused.
    drop(mail);
    drop(filler);
    fs::remove_file(&filler_path).unwrap();

    let mut rebooted = Mailbox::open(&db, MailboxLimits::default()).unwrap();
    assert_eq!(rebooted.admission(), MailboxAdmission::PausedStorageFault);
    assert!(matches!(
        rebooted.put(id(2), id(2), 2, 100, b"not-yet-recovered"),
        Err(MailError::AdmissionPaused)
    ));
    assert_eq!(
        rebooted.get_page(id(1), 2, None, 1).unwrap()[0].bytes, first
    );
    rebooted.try_resume_after_maintenance().unwrap();
    assert_eq!(rebooted.admission(), MailboxAdmission::Open);
    assert_eq!(
        rebooted.put(id(2), id(2), 2, 100, b"after-storage-repair").unwrap(),
        PutStatus::Stored
    );
    drop(rebooted);

    let opened = Mailbox::open(&db, MailboxLimits::default()).unwrap();
    assert_eq!(opened.admission(), MailboxAdmission::PausedStorageFault);
    assert_eq!(opened.stats().unwrap().messages, 2);
    assert_eq!(opened.get_page(id(1), 3, None, 1).unwrap()[0].bytes, first);
    assert_eq!(
        opened.get_page(id(2), 3, None, 1).unwrap()[0].bytes,
        b"after-storage-repair"
    );
}
