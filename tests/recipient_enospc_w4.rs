//! W4: a real OS ENOSPC during authenticated recipient acceptance
//! must NEVER return or persist a recipient acknowledgment for the
//! uncommitted message. Uses only a separately mounted Linux tmpfs.
#![cfg(target_os = "linux")]

use akula_wire_lab::crypto_identity_w3::{seal, SignedHeader, TrustedRecipient};
use akula_wire_lab::crypto_w3::new_recipient;
use akula_wire_lab::journal_w4::{Insert, Journal, JournalError};
use akula_wire_lab::receipt_w4::verify;
use akula_wire_lab::trust_w3::TrustRegistry;
use ed25519_dalek::SigningKey;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;

fn id(n: u8) -> [u8; 16] { [n; 16] }

#[test]
#[ignore = "requires isolated Linux STAYA_W4_ENOSPC_MOUNT"]
fn os_enospc_cannot_return_or_persist_recipient_ack() {
    let mount = PathBuf::from(std::env::var_os("STAYA_W4_ENOSPC_MOUNT")
        .expect("isolated tmpfs mount required")).canonicalize().unwrap();
    assert_ne!(
        fs::metadata(&mount).unwrap().dev(),
        fs::metadata(mount.parent().unwrap()).unwrap().dev(),
        "refusing to fill the runner's main filesystem"
    );

    let db = mount.join("w4-inbox.sqlite");
    let filler_path = mount.join("w4-filler.bin");
    assert!(!db.exists());
    assert!(!filler_path.exists());

    let sender = SigningKey::from_bytes(&[1;32]);
    let recipient = SigningKey::from_bytes(&[2;32]);
    let (secret, public) = new_recipient();
    let mut trust = TrustRegistry::new();
    trust.enroll(id(1), 3, sender.verifying_key()).unwrap();
    trust.enroll(id(2), 4, recipient.verifying_key()).unwrap();
    let old_packet = seal(&sender, &public, SignedHeader {
        message_id: id(7), recipient_id: id(2), expiry: 9000,
        sender_id: id(1), epoch: 3,
    }, b"durable before storage exhaustion").unwrap();
    let new_packet = seal(&sender, &public, SignedHeader {
        message_id: id(8), recipient_id: id(2), expiry: 9000,
        sender_id: id(1), epoch: 3,
    }, b"not yet durably accepted").unwrap();

    let mut journal = Journal::open(&db).unwrap();
    let (insert, durable_receipt) = journal.accept_authenticated_and_queue_receipt(
        &old_packet,
        TrustedRecipient { secret: &secret, recipient_id: id(2), now: 100, registry: &trust },
        &recipient, 4,
    ).unwrap();
    assert_eq!(insert, Insert::New);
    assert_eq!(verify(&durable_receipt, &trust).unwrap().packet_digest(),
               *blake3::hash(&old_packet).as_bytes());

    // Fill this one dedicated test filesystem to a REAL Linux ENOSPC.
    let mut filler = OpenOptions::new().write(true).create_new(true)
        .open(&filler_path).unwrap();
    let block = [0x55u8; 4096];
    let mut filled = 0usize;
    loop {
        match filler.write(&block) {
            Ok(0) => panic!("filler stopped without ENOSPC"),
            Ok(n) => filled += n,
            Err(err) if err.raw_os_error() == Some(28) => break,
            Err(err) => panic!("unexpected filesystem write error: {err}"),
        }
    }
    assert!(filled > 0);
    eprintln!("W4 observed real Linux ENOSPC after {filled} filler bytes");

    let attempted = journal.accept_authenticated_and_queue_receipt(
        &new_packet,
        TrustedRecipient { secret: &secret, recipient_id: id(2), now: 100, registry: &trust },
        &recipient, 4,
    );
    match attempted {
        Err(JournalError::Db(rusqlite::Error::SqliteFailure(code, _))) => {
            assert!(
                matches!(code.code, rusqlite::ErrorCode::DiskFull |
                    rusqlite::ErrorCode::SystemIoFailure),
                "expected FULL/IOERR under ENOSPC, got {code:?}"
            );
        }
        other => panic!("failed durable accept must never return a signed ACK: {other:?}"),
    }
    assert!(
        journal.queued_recipient_receipt(id(1),id(8)).unwrap().is_none(),
        "uncommitted ciphertext has no queued signed receipt"
    );

    drop(filler);
    fs::remove_file(&filler_path).unwrap();
    drop(journal);

    // Reopen verifies the entire atomic unit, not just the API's returned error.
    let mut reopened = Journal::open(&db).unwrap();
    assert_eq!(
        reopened.queued_recipient_receipt(id(1),id(7)).unwrap(),
        Some(durable_receipt)
    );
    assert!(reopened.queued_recipient_receipt(id(1),id(8)).unwrap().is_none());
    let inspector = rusqlite::Connection::open(&db).unwrap();
    let uncommitted_rows: i64 = inspector.query_row(
        "SELECT COUNT(*) FROM inbox WHERE sender=?1 AND message=?2",
        rusqlite::params![id(1).as_slice(),id(8).as_slice()], |r| r.get(0),
    ).unwrap();
    assert_eq!(uncommitted_rows, 0, "failed transaction must roll back inbox");
    drop(inspector);

    // Retrying after the operator frees space is a new successful accept.
    // Only THAT successful COMMIT may release a signed recipient receipt.
    let (result, receipt) = reopened.accept_authenticated_and_queue_receipt(
        &new_packet,
        TrustedRecipient { secret: &secret, recipient_id: id(2), now: 100, registry: &trust },
        &recipient, 4,
    ).unwrap();
    assert_eq!(result, Insert::New);
    assert_eq!(
        verify(&receipt, &trust).unwrap().packet_digest(),
        *blake3::hash(&new_packet).as_bytes()
    );
}
