//! CLOUD-07: crash/restart experiment using two isolated container workers.
//!
//! Each worker owns an independent SQLite journal, locally generated signing
//! and HPKE secret keys, and role-scoped MinIO credentials. The CI runner
//! transfers ONLY public keys and version/hash metadata as a trusted fixture.
//! This is NOT a production invitation or a two-physical-host test.
//!
//! The sender/recipient use the existing authenticated W3 v3, atomic recipient
//! SQLite W4 transaction, encrypted W4 return, and sender journal validator.
//! No route credit is created from S3 success or a W3 ciphertext read.
use akula_wire_lab::{
    cloud_mail_store::{CloudKey, CloudRevision},
    crypto_identity_w3::{SignedHeader, TrustedRecipient},
    crypto_w3::{new_recipient, RecipientPublic, RecipientSecret},
    journal_w4::{Delivery, Insert, Journal},
    private_return_w4::{self, ReturnInvitation},
    private_route_w3, trust_w3::TrustRegistry,
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use hpke::{Deserializable, Serializable};
use std::{
    env, fs,
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};
use wow_cloud_s3_lab::S3Lab;

const MSG: [u8; 16] = [5; 16];
const ALICE_ID: [u8; 16] = [9; 16];
const BOB_ID: [u8; 16] = [8; 16];
const ROUTE: [u8; 16] = [31; 16];
const RETURN_TAG: [u8; 16] = [41; 16];
const EXPIRY: u64 = 500_000;
const NOW: u64 = 100_000;

fn state(name: &str) -> PathBuf { PathBuf::from("/state").join(name) }

fn secret_write(path: &Path, bytes: &[u8]) {
    let mut f = fs::OpenOptions::new().write(true).create_new(true)
        .mode(0o600).open(path).unwrap();
    f.write_all(bytes).unwrap();
    f.sync_all().unwrap();
}

fn signing() -> SigningKey {
    let b: [u8; 32] = fs::read(state("private.sign")).unwrap()
        .try_into().unwrap();
    SigningKey::from_bytes(&b)
}
fn public_sign(name: &str) -> VerifyingKey {
    let b: [u8; 32] = fs::read(state(name)).unwrap()
        .try_into().unwrap();
    VerifyingKey::from_bytes(&b).unwrap()
}
fn secret_hpke() -> RecipientSecret {
    RecipientSecret::from_bytes(&fs::read(state("private.hpke")).unwrap()).unwrap()
}
fn peer_hpke() -> RecipientPublic {
    RecipientPublic::from_bytes(&fs::read(state("peer.hpke")).unwrap()).unwrap()
}
fn trust(role: &str) -> TrustRegistry {
    let local = public_sign("public.sign");
    let peer = public_sign("peer.sign");
    let (alice, bob) = if role == "alice" { (local, peer) } else { (peer, local) };
    let mut t = TrustRegistry::new();
    t.enroll(ALICE_ID, 4, alice).unwrap();
    t.enroll(BOB_ID, 6, bob).unwrap();
    t
}

fn init() {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).unwrap();
    let sign = SigningKey::from_bytes(&seed);
    secret_write(&state("private.sign"), &seed);
    fs::write(state("public.sign"), sign.verifying_key().to_bytes()).unwrap();
    let (hpke_secret, hpke_public) = new_recipient();
    secret_write(&state("private.hpke"), hpke_secret.to_bytes().as_ref());
    fs::write(state("public.hpke"), hpke_public.to_bytes().as_slice()).unwrap();
}

fn store() -> S3Lab {
    let endpoint = env::var("WOW_MINIO_ENDPOINT").unwrap();
    assert_eq!(endpoint, "http://wow-cloud02-minio:9000",
               "CLOUD-07 must use the isolated test-only Docker endpoint");
    S3Lab::new(
        &endpoint, "us-east-1", &env::var("WOW_MINIO_BUCKET").unwrap(),
        &env::var("WOW_SELF_ACCESS").unwrap(),
        &env::var("WOW_SELF_SECRET").unwrap(),
    )
}
fn forward_key() -> CloudKey {
    CloudKey { namespace: [21; 16], object: [107; 16] }
}
fn return_key() -> CloudKey {
    CloudKey { namespace: [61; 16], object: [108; 16] }
}
fn write_meta(name: &str, rev: CloudRevision, ciphertext: &[u8]) {
    let CloudRevision::S3VersionId(v) = rev else {
        panic!("CLOUD-07 requires MinIO bucket versioning");
    };
    assert!(!v.is_empty() && v != "null" && !v.contains('\n'));
    let manifest = format!("{}\n{}\n", v, blake3::hash(ciphertext).to_hex());
    fs::write(state(name), manifest).unwrap();
}
fn read_meta(name: &str) -> (CloudRevision, [u8; 32]) {
    let raw = fs::read_to_string(state(name)).unwrap();
    let mut lines = raw.lines();
    let version = lines.next().unwrap().to_owned();
    let hex = lines.next().unwrap();
    assert!(lines.next().is_none() && hex.len() == 64);
    assert!(!version.is_empty() && version != "null" && version.len() <= 128);
    let mut digest = [0u8; 32];
    for (i, b) in digest.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
    }
    (CloudRevision::S3VersionId(version), digest)
}
async fn read_exact(name: &str, key: CloudKey) -> Vec<u8> {
    let (version, digest) = read_meta(name);
    store().read_exact(key, &version, 16_384, digest).await.unwrap()
}

async fn alice_send() {
    let signed = private_route_w3::seal_private(
        &signing(), &peer_hpke(), ROUTE,
        SignedHeader { message_id: MSG, recipient_id: BOB_ID, sender_id: ALICE_ID,
                       epoch: 4, expiry: EXPIRY },
        b"CLOUD-07 encrypted and signed W3 from independent Alice",
    ).unwrap();
    {
        let mut alice = Journal::open(&state("journal.sqlite")).unwrap();
        assert_eq!(alice.enqueue(BOB_ID, MSG, EXPIRY as i64, &signed).unwrap(),
                   Insert::New);
    }
    let revision = store().put_once(forward_key(), &signed).await.unwrap();
    write_meta("forward.meta", revision, &signed);
}

async fn bob_wire() -> Vec<u8> { read_exact("forward.meta", forward_key()).await }

fn bob_authenticate(packet: &[u8]) {
    let secret = secret_hpke();
    let registry = trust("bob");
    private_route_w3::open_authenticated(
        packet, TrustedRecipient {
            secret: &secret, recipient_id: BOB_ID, now: NOW, registry: &registry,
        }, ROUTE,
    ).unwrap();
}
fn marker(name: &str) {
    let mut f = fs::File::create(state(name)).unwrap();
    f.write_all(b"ready\n").unwrap();
    f.sync_all().unwrap();
}
fn pause_until_killed() -> ! {
    loop { std::thread::park(); }
}
async fn bob_precommit_pause() -> ! {
    let packet = bob_wire().await;
    bob_authenticate(&packet); // no SQLite write, and no W4 is issued
    marker("verified_precommit.marker");
    pause_until_killed()
}
fn bob_check_none() {
    let bob = Journal::open(&state("journal.sqlite")).unwrap();
    assert!(bob.queued_recipient_receipt(ALICE_ID, MSG).unwrap().is_none());
}
async fn bob_commit_pause() -> ! {
    let packet = bob_wire().await;
    let secret = secret_hpke();
    let registry = trust("bob");
    {
        let mut bob = Journal::open(&state("journal.sqlite")).unwrap();
        let (kind, receipt) = bob.accept_private_authenticated_and_queue_receipt(
            &packet,
            TrustedRecipient {
                secret: &secret, recipient_id: BOB_ID, now: NOW,
                registry: &registry,
            },
            ROUTE, &signing(), 6,
        ).unwrap();
        assert_eq!(kind, Insert::New);
        assert_eq!(bob.queued_recipient_receipt(ALICE_ID, MSG).unwrap().unwrap(),
                   receipt);
    } // SQLite transaction committed before this marker is created
    marker("committed.marker");
    pause_until_killed()
}
/// Offline-after-commit check: no MinIO client, DNS or network access.
fn bob_verify_durable_offline() {
    let bob = Journal::open(&state("journal.sqlite")).unwrap();
    let receipt = bob.queued_recipient_receipt(ALICE_ID, MSG).unwrap().unwrap();
    assert!(!receipt.is_empty());
    assert!(!state("return.meta").exists(),
           "receipt must not be marked remotely published during outage");
}

/// After MinIO returns, re-fetching the original W3 must not create new W4.
async fn bob_verify_duplicate() {
    let packet = bob_wire().await;
    let secret = secret_hpke();
    let registry = trust("bob");
    let mut bob = Journal::open(&state("journal.sqlite")).unwrap();
    let saved = bob.queued_recipient_receipt(ALICE_ID, MSG).unwrap().unwrap();
    let (kind, again) = bob.accept_private_authenticated_and_queue_receipt(
        &packet,
        TrustedRecipient {
            secret: &secret, recipient_id: BOB_ID, now: NOW + 1,
            registry: &registry,
        },
        ROUTE, &signing(), 6,
    ).unwrap();
    assert_eq!(kind, Insert::Duplicate);
    assert_eq!(again, saved);
}

/// Preserve the immutable encrypted W4 locally BEFORE attempting S3.
/// Each actor invocation is a separate process; this also reuses identical
/// bytes after a crash between durable preparation and remote publication.
/// The standalone lab runs a single Bob writer; production needs an atomic
/// cross-process create-only reservation and durable upload-reconciliation.
fn bob_prepared_envelope() -> Vec<u8> {
    let final_path = state("return.envelope");
    if final_path.exists() {
        let stored = fs::read(&final_path).unwrap();
        assert!(!stored.is_empty());
        return stored;
    }
    let receipt = {
        let bob = Journal::open(&state("journal.sqlite")).unwrap();
        bob.queued_recipient_receipt(ALICE_ID, MSG).unwrap().unwrap()
    };
    let encrypted = private_return_w4::seal_signed_receipt(
        &receipt, &peer_hpke(), RETURN_TAG,
    ).unwrap();
    let mut nonce = [0u8; 8];
    getrandom::fill(&mut nonce).unwrap();
    let tmp_name = format!(
        "return.envelope.tmp.{}",
        nonce.iter().map(|n| format!("{n:02x}")).collect::<String>()
    );
    let tmp_path = state(&tmp_name);
    secret_write(&tmp_path, &encrypted); // mode 0600 and sync_all on file
    fs::rename(&tmp_path, &final_path).unwrap();
    fs::File::open("/state").unwrap().sync_all().unwrap();
    encrypted
}

fn bob_prepare_pause() -> ! {
    let ciphertext = bob_prepared_envelope();
    assert!(!ciphertext.is_empty());
    marker("envelope_prepared.marker");
    pause_until_killed()
}

fn bob_prepare_check() {
    let original = fs::read(state("return.envelope")).unwrap();
    assert!(!original.is_empty());
    assert_eq!(original, bob_prepared_envelope());
    assert!(!state("return.meta").exists());
    let bob = Journal::open(&state("journal.sqlite")).unwrap();
    assert!(bob.queued_recipient_receipt(ALICE_ID, MSG).unwrap().is_some());
}

/// Journal-first, with a durable return ciphertext envelope. MinIO does not
/// have to be available when the envelope is first prepared. A lost ACK
/// AFTER remote commit still requires an independently authorized reconciler.
async fn bob_resume() {
    let encrypted = bob_prepared_envelope();
    let rev = store().put_once(return_key(), &encrypted).await.unwrap();
    write_meta("return.meta", rev, &encrypted);
}

/// Bob's write-only account sees an ambiguous failed HTTP response.
async fn bob_lost_ack() {
    let encrypted = bob_prepared_envelope();
    let proxied = S3Lab::new(
        "http://wow-cloud07-proxy:9001", "us-east-1",
        &env::var("WOW_MINIO_BUCKET").unwrap(),
        &env::var("WOW_SELF_ACCESS").unwrap(),
        &env::var("WOW_SELF_SECRET").unwrap(),
    );
    let err = proxied.put_once(return_key(), &encrypted).await.unwrap_err();
    assert_eq!(err, akula_wire_lab::cloud_mail_store::CloudError::Ambiguous);
    assert!(!state("return.meta").exists());
    marker("ambiguous_upload.marker");
}

/// Alice has only scoped GET permission on Bob's return prefix. She can
/// independently verify the exact ciphertext/version and share a pin back.
/// In production, this proof needs an authenticated invitation/notification.
async fn alice_reconcile_return() {
    let opaque = fs::read(state("return.envelope")).unwrap();
    let pin = store().reconcile_unknown_put(return_key(), &opaque).await.unwrap();
    write_meta("return.meta", pin, &opaque);
}

/// Bob confirms a pin supplied by the authorized reader, without any second PUT.
fn bob_accept_return_pin() {
    let bytes = fs::read(state("return.envelope")).unwrap();
    let (_, digest) = read_meta("return.meta");
    assert_eq!(digest, *blake3::hash(&bytes).as_bytes());
    assert!(state("ambiguous_upload.marker").exists());
}

fn alice_verify_pending_offline() {
    let alice = Journal::open(&state("journal.sqlite")).unwrap();
    assert_eq!(alice.state(BOB_ID, MSG).unwrap(), Delivery::Queued);
}
fn invitation<'a>(secret: &'a RecipientSecret, registry: &'a TrustRegistry)
    -> ReturnInvitation<'a>
{
    ReturnInvitation {
        sender_secret: secret, expected_tag: RETURN_TAG,
        expires_at_ms: 250_000, now_ms: NOW + 5, recipient_trust: registry,
    }
}
async fn alice_confirm(tampered: bool) {
    let mut reply = read_exact("return.meta", return_key()).await;
    let secret = secret_hpke();
    let registry = trust("alice");
    let mut alice = Journal::open(&state("journal.sqlite")).unwrap();
    if tampered {
        let last = reply.len() - 1;
        reply[last] ^= 1;
        assert!(private_return_w4::open_verify_and_apply(
            &reply, invitation(&secret, &registry), &mut alice,
        ).is_err());
        assert_eq!(alice.state(BOB_ID, MSG).unwrap(), Delivery::Queued);
    } else {
        assert_eq!(private_return_w4::open_verify_and_apply(
            &reply, invitation(&secret, &registry), &mut alice,
        ).unwrap(), Delivery::Recipient);
        assert!(alice.retry_bytes(BOB_ID, MSG, NOW as i64 + 5).unwrap().is_none());
    }
}
fn alice_assert_final() {
    let alice = Journal::open(&state("journal.sqlite")).unwrap();
    assert_eq!(alice.state(BOB_ID, MSG).unwrap(), Delivery::Recipient);
    assert!(alice.retry_bytes(BOB_ID, MSG, NOW as i64 + 5).unwrap().is_none());
}
fn main() {
    let a: Vec<String> = env::args().collect();
    assert_eq!(a.len(), 3, "cloud07_actor alice|bob COMMAND");
    let role = a[1].as_str();
    assert!(role == "alice" || role == "bob");
    let command = a[2].as_str();
    if command == "init" { init(); return; }
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        match (role, command) {
            ("alice", "send") => alice_send().await,
            ("alice", "reject-corrupt") => alice_confirm(true).await,
            ("alice", "confirm") => alice_confirm(false).await,
            ("alice", "assert-final") => alice_assert_final(),
            ("bob", "precommit-pause") => bob_precommit_pause().await,
            ("bob", "check-none") => bob_check_none(),
            ("bob", "commit-pause") => bob_commit_pause().await,
            ("bob", "offline-receipt") => bob_verify_durable_offline(),
            ("bob", "verify-duplicate") => bob_verify_duplicate().await,
            ("bob", "prepare-pause") => bob_prepare_pause(),
            ("bob", "prepare-check") => bob_prepare_check(),
            ("bob", "resume") => bob_resume().await,
            ("bob", "lost-ack") => bob_lost_ack().await,
            ("bob", "accept-pin") => bob_accept_return_pin(),
            ("alice", "reconcile-return") => alice_reconcile_return().await,
            ("alice", "verify-pending") => alice_verify_pending_offline(),
            _ => panic!("unsupported CLOUD-07 actor command"),
        }
    });
}
