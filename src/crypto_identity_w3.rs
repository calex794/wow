//! WOW W3 v2 compatibility facade backed by the common Blue verifier.
//!
//! This is an experimental packet format, not a production messaging protocol.
//! The underlying Rust crypto implementation now lives in calex794/blue.
//! The pre-existing WOW API remains stable for current W3/W6 lab consumers.
//!
//! TrustRegistry is currently in-memory and enrollment is external. A successful
//! W3 verification is NOT permission to commit an Akula W4 recipient receipt.
//! Akula must check current app identity/ACL/revocation under its commit fence.

use crate::crypto_w3::{CryptoError, RecipientPublic, RecipientSecret};
use crate::trust_w3::TrustRegistry;
use akula_blue_w3::{OpenContext, TrustedSenderKeys, W3Error};
use ed25519_dalek::{SigningKey, VerifyingKey};

pub const VERSION: u8 = akula_blue_w3::W3_VERSION;
pub const MAX_BYTES: usize = akula_blue_w3::MAX_MESSAGE_BYTES;

/// Existing public WOW W3 header: keep `expiry` for current consumers.
/// Blue calls the same on-wire field `expires_at_ms` (Unix milliseconds).
#[derive(Clone, Copy)]
pub struct SignedHeader {
    pub message_id: [u8; 16],
    pub recipient_id: [u8; 16],
    pub expiry: u64,
    pub sender_id: [u8; 16],
    pub epoch: u64,
}

impl From<SignedHeader> for akula_blue_w3::SignedHeader {
    fn from(header: SignedHeader) -> Self {
        Self {
            message_id: header.message_id,
            recipient_id: header.recipient_id,
            expires_at_ms: header.expiry,
            sender_id: header.sender_id,
            epoch: header.epoch,
        }
    }
}

impl From<akula_blue_w3::SignedHeader> for SignedHeader {
    fn from(header: akula_blue_w3::SignedHeader) -> Self {
        Self {
            message_id: header.message_id,
            recipient_id: header.recipient_id,
            expiry: header.expires_at_ms,
            sender_id: header.sender_id,
            epoch: header.epoch,
        }
    }
}

fn translate_error(error: W3Error) -> CryptoError {
    match error {
        W3Error::Oversized => CryptoError::Oversized,
        W3Error::InvalidPacket | W3Error::InvalidDescriptor => CryptoError::InvalidPacket,
        W3Error::UnsupportedVersion => CryptoError::UnknownSuite,
        W3Error::WrongRecipient => CryptoError::InvalidRecipient,
        W3Error::Expired => CryptoError::Expired,
        W3Error::UntrustedSender => CryptoError::UnauthorizedSender,
        W3Error::DecryptFailed => CryptoError::DecryptFailed,
        W3Error::InvalidSignature => CryptoError::InvalidSignature,
    }
}

/// Seal a WOW-compatible W3 v2 packet with a single implementation in Blue.
pub fn seal(
    signing: &SigningKey,
    recipient: &RecipientPublic,
    header: SignedHeader,
    payload: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    akula_blue_w3::seal_v2(signing, recipient, header.into(), payload).map_err(translate_error)
}

pub struct TrustedRecipient<'a> {
    pub secret: &'a RecipientSecret,
    pub recipient_id: [u8; 16],
    pub now: u64,
    pub registry: &'a TrustRegistry,
}

/// Legacy in-memory adapter for pre-provisioned sender keys. The actual sender
/// identity comes from Blue's COSE verification; never a QUIC endpoint claim.
struct TrustedRegistry<'a>(&'a TrustRegistry);
impl TrustedSenderKeys for TrustedRegistry<'_> {
    fn key_for(&self, sender_id: [u8; 16], epoch: u64) -> Option<VerifyingKey> {
        self.0.key_for(sender_id, epoch).ok().copied()
    }
}

/// Authenticate W3 sender and epoch using Blue. For backward compatibility
/// with the existing WOW API, expose the decoded payload after verification.
/// Do not use the result alone as authorization for Akula inbox/File Gate.
pub fn open(
    packet: &[u8],
    recipient: TrustedRecipient<'_>,
) -> Result<(SignedHeader, Vec<u8>), CryptoError> {
    let keys = TrustedRegistry(recipient.registry);
    let verified = akula_blue_w3::open_verified(
        packet,
        OpenContext {
            secret: recipient.secret,
            recipient_id: recipient.recipient_id,
            now_ms: recipient.now,
            trusted_sender_keys: &keys,
        },
    )
    .map_err(translate_error)?;

    Ok((verified.header().into(), verified.payload().to_vec()))
}
