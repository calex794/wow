//! Real loopback TCP socket coverage for the lab-only authenticated
//! custodian STORE/FETCH adapter. This is not a physical VPS or public QUIC E2E.
use akula_wire_lab::{
    crypto_identity_w3::SignedHeader,
    crypto_w3,
    custodian_mailbox::{
        sign_fetch_for_lab, sign_store_for_lab, CustodianStoredClaim, FetchClaims, MailboxPolicy,
        StoreClaims,
    },
    custodian_wire::{bind_test_loopback, client_fetch, client_store, serve_one_loopback, WireError},
    journal_w4::Journal,
    private_route_w3,
    trust_w3::TrustRegistry,
    MAX_MESSAGE_BYTES,
};
use ed25519_dalek::SigningKey;
use rusqlite::Connection;
use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::thread;

const ISSUER: [u8; 16] = [1; 16];
const CUSTODIAN: [u8; 16] = [8; 16];
const SCOPE: [u8; 16] = [5; 16];
const RECIPIENT: [u8; 16] = [3; 16];
const MAILBOX: [u8; 16] = [11; 16];
const MESSAGE: [u8; 16] = [4; 16];
const EXPIRY: i64 = 10_000_000;

struct Fixture {
    owner: SigningKey,
    custodian: SigningKey,
    trust: TrustRegistry,
    packet: Vec<u8>,
    policy: MailboxPolicy,
    claims: StoreClaims,
}
impl Fixture {
    fn new() -> Self {
        let owner = SigningKey::from_bytes(&[1; 32]);
        let custodian = SigningKey::from_bytes(&[8; 32]);
        let sender = SigningKey::from_bytes(&[7; 32]);
        let mut trust = TrustRegistry::new();
        trust.enroll(ISSUER, 1, owner.verifying_key()).unwrap();
        trust.enroll(CUSTODIAN, 1, custodian.verifying_key()).unwrap();
        let (_, recipient_public) = crypto_w3::new_recipient();
        let packet = private_route_w3::seal_private(
            &sender,
            &recipient_public,
            [9; 16],
            SignedHeader {
                sender_id: [7; 16],
                recipient_id: RECIPIENT,
                message_id: MESSAGE,
                expiry: EXPIRY as u64,
                epoch: 1,
            },
            b"loopback tcp signed store and independent fetch",
        )
        .unwrap();
        let policy = MailboxPolicy {
            mailbox: MAILBOX,
            issuer: ISSUER,
            issuer_epoch: 1,
            custodian: CUSTODIAN,
            scope: SCOPE,
            recipient: RECIPIENT,
            max_message_bytes: 1024,
            max_offers: 2,
        };
        let claims = StoreClaims {
            issuer: ISSUER,
            issuer_epoch: 1,
            custodian: CUSTODIAN,
            mailbox: MAILBOX,
            scope: SCOPE,
            recipient: RECIPIENT,
            message: MESSAGE,
            offer: [12; 16],
            slot: [13; 16],
            expires_at: EXPIRY,
            grant_until: EXPIRY - 1,
            packet_len: packet.len() as u32,
            digest: *blake3::hash(&packet).as_bytes(),
        };
        Self { owner, custodian, trust, packet, policy, claims }
    }

    fn provision(&self, path: &Path) {
        let mut journal = Journal::open(path).unwrap();
        journal.operator_provision_mailbox(self.policy, &self.trust).unwrap();
    }

    fn store(&self) -> Vec<u8> {
        sign_store_for_lab(&self.owner, self.claims)
    }

    fn fetch(&self) -> Vec<u8> {
        sign_fetch_for_lab(
            &self.owner,
            FetchClaims {
                issuer: ISSUER,
                issuer_epoch: 1,
                custodian: CUSTODIAN,
                mailbox: MAILBOX,
                scope: SCOPE,
                recipient: RECIPIENT,
                message: MESSAGE,
                grant_until: EXPIRY - 1,
                digest: self.claims.digest,
            },
        )
    }
}

fn count(path: &Path, table: &str) -> i64 {
    let db = Connection::open(path).unwrap();
    db.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| row.get(0))
        .unwrap()
}

fn serve(f: &Fixture, path: &Path) -> (std::net::SocketAddr, thread::JoinHandle<Result<(), WireError>>) {
    let listener = bind_test_loopback().unwrap();
    let addr = listener.local_addr().unwrap();
    let path: PathBuf = path.to_path_buf();
    let signer = f.custodian.clone();
    let trust = f.trust.clone();
    let handle = thread::spawn(move || {
        let mut journal = Journal::open(&path).unwrap();
        serve_one_loopback(&listener, &mut journal, &signer, 1, &trust, 2)
    });
    (addr, handle)
}

fn store_exchange(
    f: &Fixture,
    path: &Path,
    grant: &[u8],
    packet: &[u8],
) -> Result<CustodianStoredClaim, WireError> {
    let (addr, worker) = serve(f, path);
    let mut client = TcpStream::connect(addr).unwrap();
    let response = client_store(&mut client, grant, packet, &f.trust);
    assert!(worker.join().unwrap().is_ok());
    response
}

fn fetch_exchange(
    f: &Fixture,
    path: &Path,
    grant: &[u8],
) -> Result<Option<Vec<u8>>, WireError> {
    let (addr, worker) = serve(f, path);
    let mut client = TcpStream::connect(addr).unwrap();
    let response = client_fetch(&mut client, grant, f.claims.digest);
    assert!(worker.join().unwrap().is_ok());
    response
}

#[test]
fn loopback_store_claim_fetch_replay_and_cold_reopen() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("network.sqlite");
    let f = Fixture::new();
    f.provision(&path);
    let grant = f.store();

    let stored = store_exchange(&f, &path, &grant, &f.packet).unwrap();
    let same = store_exchange(&f, &path, &grant, &f.packet).unwrap();
    assert_eq!(stored, same, "lost network response must not create a second W12");
    assert_eq!(count(&path, "custodian_mailbox_offer"), 1);
    assert_eq!(count(&path, "outbox"), 1);
    assert_eq!(count(&path, "causal_w12_event"), 1);
    assert_eq!(count(&path, "receipt_outbox"), 0, "custodian must not emit recipient W4");

    let retrieved = fetch_exchange(&f, &path, &f.fetch()).unwrap();
    assert_eq!(retrieved, Some(f.packet.clone()));
    let reopened = Journal::open(&path).unwrap();
    assert_eq!(
        reopened.audit_w12(SCOPE, CUSTODIAN, &f.trust).unwrap(),
        Some(stored.causal)
    );
}

#[test]
fn unauthenticated_or_tampered_requests_never_reserve_or_read() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("denied.sqlite");
    let f = Fixture::new();
    f.provision(&path);

    let mut changed = f.packet.clone();
    *changed.last_mut().unwrap() ^= 1;
    assert!(matches!(
        store_exchange(&f, &path, &f.store(), &changed),
        Err(WireError::Denied)
    ));
    assert_eq!(count(&path, "custodian_mailbox_offer"), 0);
    assert_eq!(count(&path, "outbox"), 0);

    let mut wrong_grant = f.store();
    *wrong_grant.last_mut().unwrap() ^= 1;
    assert!(matches!(
        store_exchange(&f, &path, &wrong_grant, &f.packet),
        Err(WireError::Denied)
    ));
    assert_eq!(count(&path, "custodian_mailbox_offer"), 0);

    // STORE and FETCH do not share a signing domain or a wire command.
    assert!(matches!(
        fetch_exchange(&f, &path, &f.store()),
        Err(WireError::Invalid)
    ));
    assert!(matches!(
        fetch_exchange(&f, &path, &f.fetch()),
        Ok(None)
    ));
}

#[test]
fn revocation_blocks_existing_valid_fetch_and_store_capabilities() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("revoked.sqlite");
    let f = Fixture::new();
    f.provision(&path);
    store_exchange(&f, &path, &f.store(), &f.packet).unwrap();

    let mut journal = Journal::open(&path).unwrap();
    journal.operator_revoke_fetch(MAILBOX).unwrap();
    drop(journal);
    assert!(matches!(
        fetch_exchange(&f, &path, &f.fetch()),
        Err(WireError::Denied)
    ));

    let mut journal = Journal::open(&path).unwrap();
    journal.operator_revoke_store(MAILBOX).unwrap();
    drop(journal);
    assert!(matches!(
        store_exchange(&f, &path, &f.store(), &f.packet),
        Err(WireError::Denied)
    ));
    assert_eq!(count(&path, "outbox"), 1);
    assert_eq!(count(&path, "receipt_outbox"), 0);
}

#[test]
fn oversized_frames_are_rejected_before_read_allocation_or_storage() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("oversized.sqlite");
    let f = Fixture::new();
    f.provision(&path);
    let (addr, worker) = serve(&f, &path);
    let mut client = TcpStream::connect(addr).unwrap();
    client.write_all(&((MAX_MESSAGE_BYTES + 513) as u32).to_be_bytes()).unwrap();
    drop(client);
    assert!(matches!(worker.join().unwrap(), Err(WireError::Invalid)));
    assert_eq!(count(&path, "custodian_mailbox_offer"), 0);
}

#[test]
fn public_listener_is_rejected_before_accepting_a_connection() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("public.sqlite");
    let f = Fixture::new();
    f.provision(&path);
    let listener = TcpListener::bind("0.0.0.0:0").unwrap();
    let mut journal = Journal::open(&path).unwrap();
    assert!(matches!(
        serve_one_loopback(&listener, &mut journal, &f.custodian, 1, &f.trust, 2),
        Err(WireError::Denied)
    ));
    assert_eq!(count(&path, "custodian_mailbox_offer"), 0);
}
