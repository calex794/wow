//! Compatibility façade for the experimental WOW W3 v2 wire format.
//!
//! The only HPKE/COSE implementation for W3 v2 is the pinned, transport-free
//! akula-blue-w3 crate. This adapter preserves WOW's existing public API for
//! current labs while also exposing Blue's unforgeable VerifiedW3 result.
//!
//! Cryptographic verification is NOT application authorization: a trusted
//! enrollment/permission snapshot must be checked again at the durable Akula
//! W4 inbox commit. An iroh TLS EndpointId is NOT a W3 sender DeviceId.

use crate::crypto_w3::{CryptoError, RecipientPublic, RecipientSecret};
use crate::trust_w3::TrustRegistry;
use akula_blue_w3::{
    OpenContext, SignedHeader as BlueHeader, TrustedSenderKeys, W3Error,
};
use ed25519_dalek::{SigningKey, VerifyingKey};

pub use akula_blue_w3::VerifiedW3;

pub const VERSION: u8 = akula_blue_w3::W3_VERSION;
pub const MAX_BYTES: usize = akula_blue_w3::MAX_MESSAGE_BYTES;

/// Historical WOW W3 v2 public header. Wire expiry means Unix milliseconds.
/// Its fields alone are not evidence of sender authentication.
#[derive(Clone, Copy)]
pub struct SignedHeader {
    pub message_id: [u8; 16],
    pub recipient_id: [u8; 16],
    pub expiry: u64,
    pub sender_id: [u8; 16],
    pub epoch: u64,
}

impl From<SignedHeader> for BlueHeader {
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

impl From<BlueHeader> for SignedHeader {
    fn from(header: BlueHeader) -> Self {
        Self {
            message_id: header.message_id,
            recipient_id: header.recipient_id,
            expiry: header.expires_at_ms,
            sender_id: header.sender_id,
            epoch: header.epoch,
        }
    }
}

/// Existing WOW caller-provided local secret and explicitly enrolled sender
/// keys. No packet-supplied signing key or TOFU is allowed.
pub struct TrustedRecipient<'a> {
    pub secret: &'a RecipientSecret,
    pub recipient_id: [u8; 16],
    pub now: u64,
    pub registry: &'a TrustRegistry,
}

struct WowTrustView<'a>(&'a TrustRegistry);

impl TrustedSenderKeys for WowTrustView<'_> {
    fn key_for(&self, sender_id: [u8; 16], epoch: u64) -> Option<VerifyingKey> {
        self.0.key_for(sender_id, epoch).ok().copied()
    }
}

fn map_error(error: W3Error) -> CryptoError {
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

/// Serialize the exact existing W3 v2 header/HPKE/COSE wire format using Blue.
/// The signer and recipient encryption key are provisioned outside this crate.
pub fn seal(
    signing: &SigningKey,
    recipient: &RecipientPublic,
    header: SignedHeader,
    payload: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    akula_blue_w3::seal_v2(signing, recipient, header.into(), payload).map_err(map_error)
}

/// New security-conscious entry point: retain the private-field, authenticated
/// packet result from Blue. Akula MUST recheck current authorization and
/// revocation at the same linearization boundary as its inbox commit.
pub fn open_authenticated<'wire>(
    packet: &'wire [u8],
    recipient: TrustedRecipient<'_>,
) -> Result<VerifiedW3<'wire>, CryptoError> {
    let trusted = WowTrustView(recipient.registry);
    akula_blue_w3::open_verified(
        packet,
        OpenContext {
            secret: recipient.secret,
            recipient_id: recipient.recipient_id,
            now_ms: recipient.now,
            trusted_sender_keys: &trusted,
        },
    )
    .map_err(map_error)
}

/// Legacy laboratory API. The tuple is NOT a trusted authorization token;
/// only open_authenticated preserves Blue's verified private-field type.
pub fn open(
    packet: &[u8],
    recipient: TrustedRecipient<'_>,
) -> Result<(SignedHeader, Vec<u8>), CryptoError> {
    let verified = open_authenticated(packet, recipient)?;
    Ok((verified.header().into(), verified.payload().to_vec()))
}
