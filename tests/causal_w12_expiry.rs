//! W12/v0 signs exact W3 bytes, not an independent retention lease.
//! Prove that SQLite's effective retry expiry stays tied to the W3 header.
use akula_wire_lab::{
    causal_w12::{CausalError, CausalRequest},
    crypto_identity_w3::SignedHeader,
    crypto_w3, journal_w4::Journal, private_route_w3, trust_w3::TrustRegistry,
};
use ed25519_dalek::SigningKey;
use rusqlite::{params, Connection};
use std::path::Path;

const W3_EXPIRY: i64 = 10_000_000;
const SCOPE: [u8; 16] = [5; 16];
const CUSTODIAN: [u8; 16] = [8; 16];
const RECIPIENT: [u8; 16] = [3; 16];
const MESSAGE: [u8; 16] = [4; 16];

fn fixture() -> (SigningKey, TrustRegistry, Vec<u8>, CausalRequest) {
    let sender = SigningKey::from_bytes(&[7; 32]);
    let custodian = SigningKey::from_bytes(&[8; 32]);
    let mut trust = TrustRegistry::new();
    trust.enroll(CUSTODIAN, 1, custodian.verifying_key()).unwrap();
    let (_, public) = crypto_w3::new_recipient();
    let packet = private_route_w3::seal_private(
        &sender,
        &public,
        [9; 16],
        SignedHeader {
            sender_id: [7; 16],
            recipient_id: RECIPIENT,
            message_id: MESSAGE,
            expiry: W3_EXPIRY as u64,
            epoch: 1,
        },
        b"opaque W3 expiry is not a second mailbox lease",
    )
    .unwrap();
    let req = CausalRequest {
        private_scope: SCOPE,
        custodian_id: CUSTODIAN,
        custodian_epoch: 1,
        recipient: RECIPIENT,
        message: MESSAGE,
        expiry_ms: W3_EXPIRY,
    };
    (custodian, trust, packet, req)
}

fn table_count(path: &Path, table: &str) -> i64 {
    let db = Connection::open(path).unwrap();
    db.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| row.get(0))
        .unwrap()
}

#[test]
fn different_w3_and_local_deadlines_fail_before_any_w12_write() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("w12.sqlite");
    let (custodian, trust, packet, request) = fixture();
    let mut journal = Journal::open(&path).unwrap();

    for bad in [W3_EXPIRY - 1, W3_EXPIRY + 1] {
        let mut req = request;
        req.expiry_ms = bad;
        assert!(matches!(
            journal.enqueue_w3_with_causal(req, &packet, &custodian, &trust),
            Err(CausalError::Invalid)
        ));
    }
    assert_eq!(table_count(&path, "outbox"), 0);
    assert_eq!(table_count(&path, "receipt_outbox"), 0);
    let db = Connection::open(&path).unwrap();
    let new_tables: i64 = db.query_row(
        "SELECT count(*) FROM sqlite_master WHERE name IN ('causal_w12_event','causal_w12_head')",
        [],
        |row| row.get(0),
    ).unwrap();
    assert_eq!(new_tables, 0, "reject before creating W12 state");
}

#[test]
fn valid_v0_claim_and_idempotent_duplicate_survive_cold_reopen() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("w12.sqlite");
    let (custodian, trust, packet, req) = fixture();
    let first = {
        let mut journal = Journal::open(&path).unwrap();
        let first = journal.enqueue_w3_with_causal(req, &packet, &custodian, &trust).unwrap();
        assert_eq!(first.seq, 1);
        assert_eq!(
            journal.enqueue_w3_with_causal(req, &packet, &custodian, &trust).unwrap(),
            first
        );
        first
    };
    let mut journal = Journal::open(&path).unwrap();
    assert_eq!(journal.audit_w12(SCOPE, CUSTODIAN, &trust).unwrap(), Some(first));
    assert_eq!(
        journal.enqueue_w3_with_causal(req, &packet, &custodian, &trust).unwrap(),
        first
    );
    assert_eq!(table_count(&path, "causal_w12_event"), 1);
    assert_eq!(table_count(&path, "receipt_outbox"), 0);
}

#[test]
fn audit_detects_tampered_shorter_or_longer_retry_expiry() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("w12.sqlite");
    let (custodian, trust, packet, req) = fixture();
    {
        let mut journal = Journal::open(&path).unwrap();
        journal.enqueue_w3_with_causal(req, &packet, &custodian, &trust).unwrap();
    }
    for bad in [1i64, W3_EXPIRY + 1] {
        let db = Connection::open(&path).unwrap();
        assert_eq!(
            db.execute(
                "UPDATE outbox SET expiry=?1 WHERE recipient=?2 AND message=?3",
                params![bad, RECIPIENT.as_slice(), MESSAGE.as_slice()],
            ).unwrap(),
            1
        );
        drop(db);
        let journal = Journal::open(&path).unwrap();
        assert!(matches!(
            journal.audit_w12(SCOPE, CUSTODIAN, &trust),
            Err(CausalError::Corrupt)
        ));
        drop(journal);
    }
    let db = Connection::open(&path).unwrap();
    db.execute(
        "UPDATE outbox SET expiry=?1 WHERE recipient=?2 AND message=?3",
        params![W3_EXPIRY, RECIPIENT.as_slice(), MESSAGE.as_slice()],
    ).unwrap();
    drop(db);
    let journal = Journal::open(&path).unwrap();
    assert!(journal.audit_w12(SCOPE, CUSTODIAN, &trust).unwrap().is_some());
}
