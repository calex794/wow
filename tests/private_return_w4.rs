//! Private reverse W4: HPKE hides recipient/message IDs from custodians.
use akula_wire_lab::crypto_identity_w3::{SignedHeader, TrustedRecipient};
use akula_wire_lab::crypto_w3::{new_recipient, RecipientSecret, RecipientPublic};
use akula_wire_lab::journal_w4::{Delivery, Insert, Journal, JournalError};
use akula_wire_lab::multipath_w5::{Lane, RouteError};
use akula_wire_lab::private_return_w4::{
    self, PrivateReturnError, ReturnInvitation, ENVELOPE_LEN,
};
use akula_wire_lab::private_route_w3;
use akula_wire_lab::receipt_w4::{self, ReceiptError};
use akula_wire_lab::trust_w3::TrustRegistry;
use ed25519_dalek::SigningKey;
use tempfile::tempdir;

fn id(n:u8)->[u8;16]{[n;16]}
fn key(n:u8)->SigningKey { SigningKey::from_bytes(&[n;32]) }

fn recipient_trust() -> TrustRegistry {
    let mut trust = TrustRegistry::new();
    trust.enroll(id(9), 4, key(9).verifying_key()).unwrap();
    trust.enroll(id(8), 6, key(8).verifying_key()).unwrap();
    trust.enroll(id(13), 7, key(13).verifying_key()).unwrap();
    trust
}
fn invitation<'a>(secret: &'a RecipientSecret, trust: &'a TrustRegistry,
                  token: [u8;16]) -> ReturnInvitation<'a> {
    ReturnInvitation {
        sender_secret: secret,
        expected_tag: token,
        expires_at_ms: 250_000,
        now_ms: 100_000,
        recipient_trust: trust,
    }
}
fn signed_receipt(packet: &[u8]) -> Vec<u8> {
    receipt_w4::sign(
        &key(8), id(8), id(5), *blake3::hash(packet).as_bytes(), 6,
    )
}

#[test]
fn real_hpke_w3_then_recipient_durable_w4_then_opaque_reverse_and_stop() {
    let dir = tempdir().unwrap();
    let trust = recipient_trust();
    // Independent HPKE keys: W3 destination Bob; W4 return destination Alice.
    let (bob_secret, bob_public) = new_recipient();
    let (return_secret, return_public) = new_recipient();
    let w3 = private_route_w3::seal_private(
        &key(9), &bob_public, id(4),
        SignedHeader {
            message_id:id(5), recipient_id:id(8),
            expiry:500_000, sender_id:id(9), epoch:4,
        }, b"private reverse receipt must not leak metadata",
    ).unwrap();
    let mut bob = Journal::open(&dir.path().join("bob.sqlite")).unwrap();
    let (insert, signed) = bob.accept_private_authenticated_and_queue_receipt(
        &w3, TrustedRecipient {
            secret:&bob_secret, recipient_id:id(8), now:100_000,
            registry:&trust,
        }, id(4), &key(8), 6,
    ).unwrap();
    assert_eq!(insert, Insert::New);
    drop(bob);
    let bob = Journal::open(&dir.path().join("bob.sqlite")).unwrap();
    assert_eq!(bob.queued_recipient_receipt(id(9),id(5)).unwrap(),Some(signed.clone()));

    // Fresh per-message route tag is NOT W3 public token.
    let tag=id(31);
    assert_ne!(tag,id(4));
    let sealed=private_return_w4::seal_signed_receipt(&signed,&return_public,tag).unwrap();
    assert_eq!(sealed.len(),ENVELOPE_LEN);
    assert_eq!(private_return_w4::inspect_route(&sealed).unwrap(),tag);
    assert_ne!(&sealed[0..],signed.as_slice());
    assert!(!sealed.windows(16).any(|x|x==id(8).as_slice() || x==id(5).as_slice()));
    // Nothing in the opaque frame says who signed W4 or which ciphertext.
    assert!(!sealed.windows(signed.len()).any(|x|x==signed.as_slice()));

    let mut alice=Journal::open(&dir.path().join("alice.sqlite")).unwrap();
    alice.enqueue(id(8),id(5),500_000,&w3).unwrap();
    alice.begin_multipath(id(8),id(5),&w3,500_000,3,100).unwrap();
    alice.reserve_multipath((id(8),id(5)),&w3,id(44),id(13),Lane::Gateway,101).unwrap();
    let observed=private_return_w4::open_verified(
        &sealed,invitation(&return_secret,&trust,tag),
    ).unwrap();
    assert_eq!(observed.message_id(),id(5));
    assert_eq!(observed.recipient_id(),id(8));
    assert_eq!(observed.packet_digest(),*blake3::hash(&w3).as_bytes());
    assert_eq!(private_return_w4::open_verify_and_apply(
        &sealed,invitation(&return_secret,&trust,tag),&mut alice,
    ).unwrap(),Delivery::Recipient);
    assert!(alice.multipath_snapshot(id(8),id(5)).unwrap().stopped);
    assert_eq!(alice.retry_bytes(id(8),id(5),102).unwrap(),None);
    assert!(matches!(alice.reserve_multipath(
        (id(8),id(5)),&w3,id(45),id(14),Lane::Forecast,103,
    ),Err(RouteError::RecipientConfirmed)));
    // Replay after restart cannot start route credits again.
    drop(alice);
    let mut alice=Journal::open(&dir.path().join("alice.sqlite")).unwrap();
    assert_eq!(private_return_w4::open_verify_and_apply(
        &sealed,invitation(&return_secret,&trust,tag),&mut alice,
    ).unwrap(),Delivery::Recipient);
    assert_eq!(alice.retry_bytes(id(8),id(5),102).unwrap(),None);
}

#[test]
fn changed_public_return_tag_and_wrong_route_are_denied() {
    let (secret,pubkey)=new_recipient();
    let trust=recipient_trust();
    let wire=private_return_w4::seal_signed_receipt(&signed_receipt(b"w3"),&pubkey,id(31)).unwrap();
    assert!(matches!(private_return_w4::open_verified(
        &wire,invitation(&secret,&trust,id(32)),
    ),Err(PrivateReturnError::WrongReturnTag)));
    let mut tampered=wire;
    tampered[3]^=1;
    assert!(matches!(private_return_w4::open_verified(
        &tampered,invitation(&secret,&trust,id(31)),
    ),Err(PrivateReturnError::WrongReturnTag)));
    assert!(matches!(private_return_w4::open_verified(
        &tampered,invitation(&secret,&trust,private_return_w4::inspect_route(&tampered).unwrap()),
    ),Err(PrivateReturnError::Crypto)));
}

#[test]
fn wrong_hpke_recipient_and_ciphertext_tamper_never_expose_plain_w4() {
    let (_,pubkey)=new_recipient();
    let (other_secret,_)=new_recipient();
    let (secret,_)=new_recipient();
    let trust=recipient_trust();
    let mut sealed=private_return_w4::seal_signed_receipt(
        &signed_receipt(b"packet"),&pubkey,id(31),
    ).unwrap();
    assert!(matches!(private_return_w4::open_verified(
        &sealed,invitation(&other_secret,&trust,id(31)),
    ),Err(PrivateReturnError::Crypto)));
    sealed[ENVELOPE_LEN-1]^=1;
    assert!(matches!(private_return_w4::open_verified(
        &sealed,invitation(&secret,&trust,id(31)),
    ),Err(PrivateReturnError::Crypto)));
}

#[test]
fn signed_by_custodian_not_bob_rejected_inside_hpke() {
    let (secret,pubkey)=new_recipient();
    let trust=recipient_trust();
    let raw=receipt_w4::sign(
        &key(13),id(8),id(5),*blake3::hash(b"packet").as_bytes(),6,
    );
    let envelope=private_return_w4::seal_signed_receipt(&raw,&pubkey,id(31)).unwrap();
    assert!(matches!(private_return_w4::open_verified(
        &envelope,invitation(&secret,&trust,id(31)),
    ),Err(PrivateReturnError::UntrustedReceipt(ReceiptError::InvalidSignature))));
}

#[test]
fn trusted_wrong_w3_digest_cannot_complete_sender_outbox() {
    let dir=tempdir().unwrap();
    let trust=recipient_trust();
    let (secret,pubkey)=new_recipient();
    let raw=receipt_w4::sign(
        &key(8),id(8),id(5),*blake3::hash(b"other W3").as_bytes(),6,
    );
    let sealed=private_return_w4::seal_signed_receipt(&raw,&pubkey,id(31)).unwrap();
    let mut alice=Journal::open(&dir.path().join("a.sqlite")).unwrap();
    alice.enqueue(id(8),id(5),300_000,b"actual original W3").unwrap();
    assert!(matches!(private_return_w4::open_verify_and_apply(
        &sealed,invitation(&secret,&trust,id(31)),&mut alice,
    ),Err(PrivateReturnError::Journal(JournalError::Conflict))));
    assert_eq!(alice.state(id(8),id(5)).unwrap(),Delivery::Queued);
}

#[test]
fn expired_invitation_and_revoked_recipient_are_not_accepted() {
    let (secret,pubkey)=new_recipient();
    let mut trust=recipient_trust();
    let wire=private_return_w4::seal_signed_receipt(&signed_receipt(b"w3"),&pubkey,id(31)).unwrap();
    let expired=ReturnInvitation {
        now_ms:250_000, ..invitation(&secret,&trust,id(31))
    };
    assert!(matches!(private_return_w4::open_verified(&wire,expired),
        Err(PrivateReturnError::ExpiredInvitation)));
    trust.revoke(id(8)).unwrap();
    assert!(matches!(private_return_w4::open_verified(
        &wire,invitation(&secret,&trust,id(31)),
    ),Err(PrivateReturnError::UntrustedReceipt(ReceiptError::UntrustedRecipient))));
}

#[test]
fn wrong_version_length_zero_tag_and_custody_claim_rejected() {
    let (secret,pubkey)=new_recipient();
    let trust=recipient_trust();
    let signed=signed_receipt(b"w3");
    let wire=private_return_w4::seal_signed_receipt(&signed,&pubkey,id(31)).unwrap();
    assert!(matches!(private_return_w4::seal_signed_receipt(&signed,&pubkey,[0;16]),
        Err(PrivateReturnError::InvalidEnvelope)));
    assert!(matches!(private_return_w4::seal_signed_receipt(b"not W4",&pubkey,id(31)),
        Err(PrivateReturnError::InvalidEnvelope)));
    for bad in [&wire[..ENVELOPE_LEN-1],&wire[..3]] {
        assert!(matches!(private_return_w4::inspect_route(bad),
            Err(PrivateReturnError::InvalidEnvelope)));
    }
    let mut version=wire;
    version[0]=7;
    assert!(matches!(private_return_w4::open_verified(
        &version,invitation(&secret,&trust,id(31)),
    ),Err(PrivateReturnError::InvalidEnvelope)));
}
