//! Real loopback TCP socket coverage for the lab-only authenticated
//! custodian STORE/FETCH adapter. This is not a physical VPS or public QUIC E2E.
use akula_wire_lab::{
    crypto_identity_w3::SignedHeader,
    crypto_w3,
    custodian_discovery::{sign_list_for_lab, ListClaims, ListedEntry},
    custodian_invitation::{sign_invitation_for_lab, verify_invitation_for_sender, MailboxInvitation},
    custodian_mailbox::{
        sign_fetch_for_lab, sign_store_for_lab, CustodianStoredClaim, FetchClaims, MailboxPolicy,
        StoreClaims,
    },
    custodian_wire::{bind_test_loopback, client_fetch, client_fetch_listed,
        client_list, client_store, client_store_delegated, serve_one_loopback, WireError},
    journal_w4::Journal,
    private_route_w3,
    trust_w3::TrustRegistry,
    MAX_MESSAGE_BYTES,
};
use ed25519_dalek::SigningKey;
use hpke::Serializable;
use rusqlite::Connection;
use std::io::{Read, Write};
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
    sender_signer: SigningKey,
    recipient_signer: SigningKey,
    recipient_secret: crypto_w3::RecipientSecret,
    recipient_public: crypto_w3::RecipientPublic,
    trust: TrustRegistry,
    packet: Vec<u8>,
    policy: MailboxPolicy,
    claims: StoreClaims,
}
impl Fixture {
    fn new() -> Self {
        let owner = SigningKey::from_bytes(&[1; 32]);
        let custodian = SigningKey::from_bytes(&[8; 32]);
        let recipient_signer = SigningKey::from_bytes(&[3; 32]);
        let sender = SigningKey::from_bytes(&[7; 32]);
        let mut trust = TrustRegistry::new();
        trust.enroll(ISSUER, 1, owner.verifying_key()).unwrap();
        trust.enroll(CUSTODIAN, 1, custodian.verifying_key()).unwrap();
        trust.enroll(RECIPIENT, 1, recipient_signer.verifying_key()).unwrap();
        trust.enroll([7; 16], 1, sender.verifying_key()).unwrap();
        let (recipient_secret, recipient_public) = crypto_w3::new_recipient();
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
        Self { owner, custodian, sender_signer: sender, recipient_signer, recipient_secret, recipient_public, trust, packet, policy, claims }
    }

    fn provision(&self, path: &Path) {
        let mut journal = Journal::open(path).unwrap();
        journal.operator_provision_mailbox(self.policy, &self.trust).unwrap();
    }

    fn list(&self, since_seq: u64, max_items: u8) -> Vec<u8> {
        sign_list_for_lab(&self.recipient_signer, ListClaims {
            issuer: ISSUER,
            issuer_epoch: 1,
            custodian: CUSTODIAN,
            mailbox: MAILBOX,
            scope: SCOPE,
            recipient: RECIPIENT,
            recipient_epoch: 1,
            since_seq,
            grant_until_ms: 60_000,
            nonce: [17; 16],
            max_items,
        })
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
    // Two independently provisioned registries: do not share the client's
    // in-memory trust object with the custodian process.
    let mut trust = TrustRegistry::new();
    trust.enroll(ISSUER, 1, f.owner.verifying_key()).unwrap();
    trust.enroll(CUSTODIAN, 1, f.custodian.verifying_key()).unwrap();
    trust.enroll(RECIPIENT, 1, f.recipient_signer.verifying_key()).unwrap();
    trust.enroll([7; 16], 1, f.sender_signer.verifying_key()).unwrap();
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
    let mut invalid_read = f.fetch();
    *invalid_read.last_mut().unwrap() ^= 1;
    assert!(matches!(
        fetch_exchange(&f, &path, &invalid_read),
        Err(WireError::Denied)
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
    client.write_all(&((MAX_MESSAGE_BYTES + 545) as u32).to_be_bytes()).unwrap();
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

fn forged_reply(reply: Vec<u8>) -> (std::net::SocketAddr, thread::JoinHandle<()>) {
    let listener = bind_test_loopback().unwrap();
    let addr = listener.local_addr().unwrap();
    let worker = thread::spawn(move || {
        let (mut peer, _) = listener.accept().unwrap();
        let mut header = [0u8; 4];
        peer.read_exact(&mut header).unwrap();
        let len = u32::from_be_bytes(header) as usize;
        assert!(len <= MAX_MESSAGE_BYTES + 544);
        let mut request = vec![0u8; len];
        peer.read_exact(&mut request).unwrap();
        peer.write_all(&(reply.len() as u32).to_be_bytes()).unwrap();
        peer.write_all(&reply).unwrap();
    });
    (addr, worker)
}

#[test]
fn malicious_server_cannot_forge_custodian_stored_confirmation() {
    let f = Fixture::new();
    let mut forged = vec![1u8, 17u8];
    forged.extend_from_slice(&[0u8; 112]);
    let (addr, worker) = forged_reply(forged);
    let mut stream = TcpStream::connect(addr).unwrap();
    assert!(matches!(
        client_store(&mut stream, &f.store(), &f.packet, &f.trust),
        Err(WireError::Denied)
    ));
    worker.join().unwrap();
}

#[test]
fn malicious_server_cannot_replace_fetched_ciphertext() {
    let f = Fixture::new();
    let (addr, worker) = forged_reply(vec![1u8, 18u8, 9u8, 8u8, 7u8]);
    let mut stream = TcpStream::connect(addr).unwrap();
    assert!(matches!(
        client_fetch(&mut stream, &f.fetch(), f.claims.digest),
        Err(WireError::Invalid)
    ));
    worker.join().unwrap();
}


fn list_exchange(
    f: &Fixture,
    path: &Path,
    proof: &[u8],
) -> Result<Vec<ListedEntry>, WireError> {
    let (addr, worker) = serve(f, path);
    let mut client = TcpStream::connect(addr).unwrap();
    let response = client_list(&mut client, proof);
    assert!(worker.join().unwrap().is_ok());
    response
}

fn fetch_listed_exchange(
    f: &Fixture,
    path: &Path,
    proof: &[u8],
    item: ListedEntry,
) -> Result<Option<Vec<u8>>, WireError> {
    let (addr, worker) = serve(f, path);
    let mut client = TcpStream::connect(addr).unwrap();
    let response = client_fetch_listed(&mut client, proof, item);
    assert!(worker.join().unwrap().is_ok());
    response
}

#[test]
fn offline_recipient_can_discover_and_fetch_after_custodian_restart() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("recipient_list.sqlite");
    let f = Fixture::new();
    f.provision(&path);
    let stored = store_exchange(&f, &path, &f.store(), &f.packet).unwrap();
    // The sender's connection is gone. Recipient has no prior message/digest
    // and uses only its independently signed private LIST read permission.
    let list_proof = f.list(0, 2);
    let entries = list_exchange(&f, &path, &list_proof).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].message, MESSAGE);
    assert_eq!(entries[0].seq, stored.causal.seq);
    assert_eq!(entries[0].digest, f.claims.digest);
    let packet = fetch_listed_exchange(&f, &path, &list_proof, entries[0]).unwrap();
    assert_eq!(packet, Some(f.packet.clone()));
    assert_eq!(list_exchange(&f, &path, &f.list(entries[0].seq, 2)).unwrap().len(), 0);
    assert_eq!(count(&path, "receipt_outbox"), 0, "C cannot issue recipient W4");
}

#[test]
fn private_list_rejects_wrong_signer_epoch_scope_and_revocation() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("recipient_acl.sqlite");
    let f = Fixture::new();
    f.provision(&path);
    store_exchange(&f, &path, &f.store(), &f.packet).unwrap();
    let allowed = f.list(0, 1);
    let mut forged = allowed.clone();
    *forged.last_mut().unwrap() ^= 1;
    assert!(matches!(list_exchange(&f, &path, &forged), Err(WireError::Denied)));

    let mut wrong_claims = ListClaims {
        issuer: ISSUER, issuer_epoch: 1, custodian: CUSTODIAN,
        mailbox: [99; 16], scope: SCOPE, recipient: RECIPIENT,
        recipient_epoch: 1, since_seq: 0, grant_until_ms: 60_000,
        nonce: [21; 16], max_items: 1,
    };
    let wrong = sign_list_for_lab(&f.recipient_signer, wrong_claims);
    assert!(matches!(list_exchange(&f, &path, &wrong), Err(WireError::Denied)));

    wrong_claims.mailbox = MAILBOX;
    wrong_claims.issuer_epoch = 2;
    let wrong_epoch = sign_list_for_lab(&f.recipient_signer, wrong_claims);
    assert!(matches!(list_exchange(&f, &path, &wrong_epoch), Err(WireError::Denied)));

    wrong_claims.issuer_epoch = 1;
    wrong_claims.scope = [77; 16];
    let wrong_scope = sign_list_for_lab(&f.recipient_signer, wrong_claims);
    assert!(matches!(list_exchange(&f, &path, &wrong_scope), Err(WireError::Denied)));

    wrong_claims.scope = SCOPE;
    wrong_claims.nonce = [0; 16];
    let invalid = sign_list_for_lab(&f.recipient_signer, wrong_claims);
    assert!(matches!(list_exchange(&f, &path, &invalid), Err(WireError::Denied)));

    wrong_claims.nonce = [1; 16];
    wrong_claims.grant_until_ms = 1;
    let expired = sign_list_for_lab(&f.recipient_signer, wrong_claims);
    assert!(matches!(list_exchange(&f, &path, &expired), Err(WireError::Denied)));

    let mut journal = Journal::open(&path).unwrap();
    journal.operator_revoke_fetch(MAILBOX).unwrap();
    drop(journal);
    assert!(matches!(list_exchange(&f, &path, &allowed), Err(WireError::Denied)));
}

#[test]
fn listed_fetch_is_confined_to_exact_message_seq_and_digest() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("recipient_confined.sqlite");
    let f = Fixture::new();
    f.provision(&path);
    store_exchange(&f, &path, &f.store(), &f.packet).unwrap();
    let grant = f.list(0, 1);
    let entries = list_exchange(&f, &path, &grant).unwrap();
    let original = entries[0];
    let mut changed = original;
    changed.digest[0] ^= 1;
    assert!(matches!(
        fetch_listed_exchange(&f, &path, &grant, changed),
        Err(WireError::Denied)
    ));
    changed = original;
    changed.seq += 1;
    assert!(matches!(
        fetch_listed_exchange(&f, &path, &grant, changed),
        Ok(None)
    ));
    changed = original;
    changed.message = [42; 16];
    assert!(matches!(
        fetch_listed_exchange(&f, &path, &grant, changed),
        Ok(None)
    ));
    let after = f.list(original.seq, 1);
    assert!(matches!(
        fetch_listed_exchange(&f, &path, &after, original),
        Err(WireError::Denied)
    ));
    assert_eq!(count(&path, "receipt_outbox"), 0);
}


fn delegated_exchange(
    f: &Fixture,
    path: &Path,
    invitation: &[u8],
    sender_proof: &[u8],
    packet: &[u8],
) -> Result<CustodianStoredClaim, WireError> {
    let (addr, worker) = serve(f, path);
    let mut client = TcpStream::connect(addr).unwrap();
    let response = client_store_delegated(&mut client, invitation, sender_proof, packet, &f.trust);
    assert!(worker.join().unwrap().is_ok());
    response
}

fn invitation_hpke(f: &Fixture) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&f.recipient_public.to_bytes());
    bytes
}

fn invitation(f: &Fixture, max_packet_bytes: u32) -> Vec<u8> {
    sign_invitation_for_lab(&f.owner, MailboxInvitation {
        issuer: ISSUER,
        issuer_epoch: 1,
        custodian: CUSTODIAN,
        mailbox: MAILBOX,
        scope: SCOPE,
        recipient: RECIPIENT,
        sender: [7; 16],
        sender_epoch: 1,
        offer: [12; 16],
        slot: [13; 16],
        max_packet_bytes,
        valid_until_ms: EXPIRY,
        recipient_hpke_public: invitation_hpke(f),
        route_token: [9; 16],
    })
}

fn future_message(f: &Fixture, signed_invitation: &[u8]) -> (Vec<u8>, StoreClaims) {
    let invite = verify_invitation_for_sender(
        signed_invitation, ISSUER, CUSTODIAN, [7; 16], &f.trust, 2,
    ).unwrap();
    let recipient_public = invite.recipient_public().unwrap();
    let packet = private_route_w3::seal_private(
        &f.sender_signer,
        &recipient_public,
        invite.route_token,
        SignedHeader {
            sender_id: [7; 16],
            recipient_id: RECIPIENT,
            message_id: [16; 16],
            expiry: EXPIRY as u64,
            epoch: 1,
        },
        b"offline recipient can find this without prior message digest",
    ).unwrap();
    let mut claims = f.claims;
    claims.message = [16; 16];
    claims.packet_len = packet.len() as u32;
    claims.digest = *blake3::hash(&packet).as_bytes();
    (packet, claims)
}

#[test]
fn signed_invitation_precedes_future_message_and_recipient_discovers_it_offline() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("delegated.sqlite");
    let f = Fixture::new();
    f.provision(&path);
    // B issues this BEFORE A chooses a message ID or creates the ciphertext.
    let invite = invitation(&f, 1024);
    let (packet, claims) = future_message(&f, &invitation(&f, 1024));
    let proof = sign_store_for_lab(&f.sender_signer, claims);
    let first = delegated_exchange(&f, &path, &invite, &proof, &packet).unwrap();
    let replay = delegated_exchange(&f, &path, &invite, &proof, &packet).unwrap();
    assert_eq!(first, replay, "lost ACK cannot consume a second slot");
    assert_eq!(count(&path, "custodian_mailbox_offer"), 1);
    assert_eq!(count(&path, "custodian_mailbox_delegated_offer"), 1);
    assert_eq!(count(&path, "causal_w12_event"), 1);
    assert_eq!(count(&path, "receipt_outbox"), 0, "C cannot impersonate B");

    // B was offline during STORE and knows only its own mailbox invitation.
    let proof = f.list(0, 2);
    let entries = list_exchange(&f, &path, &proof).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].seq, first.causal.seq);
    assert_eq!(entries[0].message, claims.message);
    assert_eq!(entries[0].digest, claims.digest);
    let fetched = fetch_listed_exchange(&f, &path, &proof, entries[0])
        .unwrap().expect("recipient must fetch the unchanged W3");
    assert_eq!(fetched, packet);
    let verified = private_route_w3::open_authenticated(
        &fetched,
        akula_wire_lab::crypto_identity_w3::TrustedRecipient {
            secret: &f.recipient_secret,
            recipient_id: RECIPIENT,
            now: 2,
            registry: &f.trust,
        },
        [9; 16],
    ).expect("recipient must decrypt the exact message from signed invitation");
    assert_eq!(verified.header().message_id, claims.message);
    assert_eq!(verified.payload(), b"offline recipient can find this without prior message digest");
}

#[test]
fn delegated_offer_rejects_unauthorized_sender_tampering_and_second_message() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("delegated_denied.sqlite");
    let f = Fixture::new();
    f.provision(&path);
    let invite = invitation(&f, 1024);
    let (packet, claims) = future_message(&f, &invitation(&f, 1024));
    let proof = sign_store_for_lab(&f.sender_signer, claims);

    let mut bad_invite = invite.clone();
    *bad_invite.last_mut().unwrap() ^= 1;
    assert!(matches!(
        delegated_exchange(&f, &path, &bad_invite, &proof, &packet),
        Err(WireError::Denied)
    ));
    let bad_sender = SigningKey::from_bytes(&[44; 32]);
    assert!(matches!(
        delegated_exchange(&f, &path, &invite, &sign_store_for_lab(&bad_sender, claims), &packet),
        Err(WireError::Denied)
    ));
    let mut changed = packet.clone();
    *changed.last_mut().unwrap() ^= 1;
    assert!(matches!(
        delegated_exchange(&f, &path, &invite, &proof, &changed),
        Err(WireError::Denied)
    ));
    assert_eq!(count(&path, "custodian_mailbox_offer"), 0);
    assert_eq!(count(&path, "outbox"), 0);

    delegated_exchange(&f, &path, &invite, &proof, &packet).unwrap();
    let (_, other_public) = crypto_w3::new_recipient();
    let other_packet = private_route_w3::seal_private(
        &f.sender_signer, &other_public, [9;16],
        SignedHeader {
            sender_id: [7;16], recipient_id: RECIPIENT,
            message_id: [18;16], expiry: EXPIRY as u64, epoch: 1,
        }, b"second ciphertext must not reuse one-off slot",
    ).unwrap();
    let mut other_claims = claims;
    other_claims.message = [18;16];
    other_claims.packet_len = other_packet.len() as u32;
    other_claims.digest = *blake3::hash(&other_packet).as_bytes();
    assert!(matches!(
        delegated_exchange(&f, &path, &invite,
            &sign_store_for_lab(&f.sender_signer, other_claims), &other_packet),
        Err(WireError::Denied)
    ));
    assert_eq!(count(&path, "outbox"), 1);
    assert_eq!(count(&path, "custodian_mailbox_offer"), 1);
}

#[test]
fn delegated_store_is_fenced_by_invitation_limits_and_current_revocation() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("delegated_limits.sqlite");
    let f = Fixture::new();
    f.provision(&path);
    let (packet, claims) = future_message(&f, &invitation(&f, 1024));
    let proof = sign_store_for_lab(&f.sender_signer, claims);

    assert!(matches!(
        delegated_exchange(&f, &path, &invitation(&f, packet.len() as u32 - 1),
            &proof, &packet),
        Err(WireError::Denied)
    ));
    let expired = sign_invitation_for_lab(&f.owner, MailboxInvitation {
        issuer: ISSUER, issuer_epoch: 1, custodian: CUSTODIAN,
        mailbox: MAILBOX, scope: SCOPE, recipient: RECIPIENT,
        sender: [7; 16], sender_epoch: 1, offer: [12;16], slot: [13;16],
        max_packet_bytes: 1024, valid_until_ms: 1,
        recipient_hpke_public: invitation_hpke(&f),
        route_token: [9; 16],
    });
    assert!(matches!(
        delegated_exchange(&f, &path, &expired, &proof, &packet),
        Err(WireError::Denied)
    ));
    assert_eq!(count(&path, "custodian_mailbox_offer"), 0);

    let mut journal = Journal::open(&path).unwrap();
    journal.operator_revoke_store(MAILBOX).unwrap();
    drop(journal);
    assert!(matches!(
        delegated_exchange(&f, &path, &invitation(&f, 1024), &proof, &packet),
        Err(WireError::Denied)
    ));
    assert_eq!(count(&path, "outbox"), 0);
}
