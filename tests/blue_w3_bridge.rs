//! Regression: real Blue W3 v2 codec is shared by WOW's public W3 facade.
//! No relayer, transport ACK or remote peer identity is sufficient for trust.

use akula_blue_w3::{
    open_verified, seal_v2, OpenContext, SignedHeader as BlueHeader, TrustedSenderKeys,
};
use akula_wire_lab::crypto_identity_w3::{
    open as wow_open, seal as wow_seal, SignedHeader as WowHeader, TrustedRecipient,
};
use akula_wire_lab::crypto_w3::new_recipient;
use akula_wire_lab::trust_w3::TrustRegistry;
use ed25519_dalek::{SigningKey, VerifyingKey};

struct PinnedSender {
    key: VerifyingKey,
}
impl TrustedSenderKeys for PinnedSender {
    fn key_for(&self, sender_id: [u8; 16], epoch: u64) -> Option<VerifyingKey> {
        if sender_id == [3; 16] && epoch == 7 {
            Some(self.key)
        } else {
            None
        }
    }
}

#[test]
fn wow_and_blue_cross_verify_exact_signed_encrypted_w3_bytes() {
    let signer = SigningKey::from_bytes(&[3; 32]);
    let (recipient_secret, recipient_public) = new_recipient();
    let old_header = WowHeader {
        message_id: [1; 16],
        recipient_id: [2; 16],
        expiry: 5_000,
        sender_id: [3; 16],
        epoch: 7,
    };
    let new_header = BlueHeader {
        message_id: old_header.message_id,
        recipient_id: old_header.recipient_id,
        expires_at_ms: old_header.expiry,
        sender_id: old_header.sender_id,
        epoch: old_header.epoch,
    };
    let blue_keys = PinnedSender {
        key: signer.verifying_key(),
    };
    let mut legacy_keys = TrustRegistry::new();
    legacy_keys
        .enroll(old_header.sender_id, old_header.epoch, signer.verifying_key())
        .unwrap();

    // WOW seal -> Blue independently verifies, preserving the original bytes.
    let wow_wire = wow_seal(&signer, &recipient_public, old_header, b"wow to Blue").unwrap();
    let blue_verified = open_verified(
        &wow_wire,
        OpenContext {
            secret: &recipient_secret,
            recipient_id: old_header.recipient_id,
            now_ms: 100,
            trusted_sender_keys: &blue_keys,
        },
    )
    .unwrap();
    assert_eq!(blue_verified.payload(), b"wow to Blue");
    assert_eq!(blue_verified.original_packet(), &wow_wire);
    assert_eq!(blue_verified.packet_digest(), *blake3::hash(&wow_wire).as_bytes());
    assert_eq!(blue_verified.header(), new_header);

    // Blue seal -> WOW public API verifies using the original trusted registry.
    let blue_wire = seal_v2(&signer, &recipient_public, new_header, b"Blue to wow").unwrap();
    let (wow_verified, plaintext) = wow_open(
        &blue_wire,
        TrustedRecipient {
            secret: &recipient_secret,
            recipient_id: old_header.recipient_id,
            now: 100,
            registry: &legacy_keys,
        },
    )
    .unwrap();
    assert_eq!(wow_verified.message_id, old_header.message_id);
    assert_eq!(wow_verified.sender_id, old_header.sender_id);
    assert_eq!(wow_verified.epoch, old_header.epoch);
    assert_eq!(plaintext, b"Blue to wow");
}

#[test]
fn wow_facade_still_rejects_revoked_and_wrong_epoch_sender() {
    let signer = SigningKey::from_bytes(&[3; 32]);
    let (recipient_secret, recipient_public) = new_recipient();
    let header = WowHeader {
        message_id: [1; 16],
        recipient_id: [2; 16],
        expiry: 5_000,
        sender_id: [3; 16],
        epoch: 7,
    };
    let wire = wow_seal(&signer, &recipient_public, header, b"secret").unwrap();
    let mut trust = TrustRegistry::new();
    let receive = |registry: &TrustRegistry| {
        wow_open(
            &wire,
            TrustedRecipient {
                secret: &recipient_secret,
                recipient_id: header.recipient_id,
                now: 100,
                registry,
            },
        )
    };
    assert!(receive(&trust).is_err());
    trust.enroll(header.sender_id, 7, signer.verifying_key()).unwrap();
    assert!(receive(&trust).is_ok());
    trust.revoke(header.sender_id).unwrap();
    assert!(receive(&trust).is_err());
    trust.enroll(header.sender_id, 8, signer.verifying_key()).unwrap();
    assert!(receive(&trust).is_err());
}
