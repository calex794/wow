//! W4 private return envelope: encrypt Bob's *already durably signed* final
//! W4 for Alice, and expose only an invitation-scoped opaque return tag.
//!
//! This is a lab cryptographic boundary, not a service or deployment profile.
//! No forward W3 route token, recipient_id, message_id, W4 signature or
//! plaintext digest appears in the public return frame. Metadata such as
//! endpoint IPs, timing, packet size and repeated tags remain observable.
//!
//! The sender-provided HPKE public key and return tag MUST come from an
//! authenticated private invitation, not from relay input. The return tag is
//! a routing hint, never a read/write capability. Sender alone holds HPKE
//! private key; sender must verify signed W4 and outbox exact digest before
//! marking any message recipient-accepted. No automatic downgrade to clear W4.
use crate::crypto_w3::{RecipientPublic, RecipientSecret};
use crate::journal_w4::{Delivery, Journal, JournalError};
use crate::receipt_w4::{self, ReceiptError, VerifiedRecipientReceipt, RECEIPT_LEN};
use crate::trust_w3::TrustRegistry;
use hpke::{
    aead::ChaCha20Poly1305, kdf::HkdfSha256, kem::X25519HkdfSha256,
    Deserializable, Kem, OpModeR, OpModeS, Serializable,
};

type Aead = ChaCha20Poly1305;
type Kdf = HkdfSha256;
type KeyExchange = X25519HkdfSha256;
const INFO: &[u8] = b"Akula/WOW/private-recipient-W4/HPKE-v1";
const VERSION: u8 = 1;
const PUBLIC_BYTES: usize = 1 + 16;
const ENCAP_BYTES: usize = 32;
const AEAD_TAG_BYTES: usize = 16;
/// Fixed length prevents a public observer inferring message classes from
/// payload lengths. W4 inner receipt is fixed-size in the current protocol.
pub const ENVELOPE_LEN: usize = PUBLIC_BYTES + ENCAP_BYTES + RECEIPT_LEN + AEAD_TAG_BYTES;

#[derive(Debug)]
pub enum PrivateReturnError {
    InvalidEnvelope,
    WrongReturnTag,
    ExpiredInvitation,
    Crypto,
    UntrustedReceipt(ReceiptError),
    Journal(JournalError),
}
impl From<ReceiptError> for PrivateReturnError {
    fn from(error: ReceiptError) -> Self { Self::UntrustedReceipt(error) }
}
impl From<JournalError> for PrivateReturnError {
    fn from(error: JournalError) -> Self { Self::Journal(error) }
}

pub struct ReturnInvitation<'a> {
    /// Fresh per-message opaque route label; never reuse for another message.
    pub expected_tag: [u8;16],
    /// Sender-generated return HPKE key, bound in trusted invitation.
    pub sender_secret: &'a RecipientSecret,
    /// Trusted expiry and clock are local, not controlled by a relay.
    pub expires_at_ms: u64,
    pub now_ms: u64,
    /// Recipient verifying key and epoch are provisioned independently.
    pub recipient_trust: &'a TrustRegistry,
}

/// Forwarders can only parse this untrusted public routing hint.
/// It does not authorize storage, downloads, W4 verification, or Sync Core.
pub fn inspect_route(envelope: &[u8]) -> Result<[u8;16], PrivateReturnError> {
    if envelope.len() != ENVELOPE_LEN || envelope[0] != VERSION {
        return Err(PrivateReturnError::InvalidEnvelope);
    }
    let tag: [u8;16] = envelope[1..PUBLIC_BYTES]
        .try_into().map_err(|_| PrivateReturnError::InvalidEnvelope)?;
    if tag == [0;16] { return Err(PrivateReturnError::InvalidEnvelope); }
    Ok(tag)
}

/// Encrypt the exact existing recipient-signed W4 bytes AFTER recipient inbox
/// transaction commits. This does not create its own recipient W4.
pub fn seal_signed_receipt(
    signed_w4: &[u8],
    sender_public: &RecipientPublic,
    return_tag: [u8;16],
) -> Result<Vec<u8>, PrivateReturnError> {
    if return_tag == [0;16] || signed_w4.len() != RECEIPT_LEN {
        return Err(PrivateReturnError::InvalidEnvelope);
    }
    let mut header = Vec::with_capacity(PUBLIC_BYTES);
    header.push(VERSION);
    header.extend_from_slice(&return_tag);
    let (enc, ciphertext) = hpke::single_shot_seal::<Aead, Kdf, KeyExchange>(
        &OpModeS::Base, sender_public, INFO, signed_w4, &header,
    ).map_err(|_| PrivateReturnError::Crypto)?;
    let mut envelope = header;
    envelope.extend_from_slice(&enc.to_bytes());
    envelope.extend_from_slice(&ciphertext);
    if envelope.len() != ENVELOPE_LEN {
        return Err(PrivateReturnError::InvalidEnvelope);
    }
    Ok(envelope)
}

/// Alice decrypts and authenticates Bob's signed W4, after checking the
/// independently agreed return token and that it has not expired.
pub fn open_verified(
    envelope: &[u8],
    invitation: ReturnInvitation<'_>,
) -> Result<VerifiedRecipientReceipt, PrivateReturnError> {
    let tag = inspect_route(envelope)?;
    if tag != invitation.expected_tag {
        return Err(PrivateReturnError::WrongReturnTag);
    }
    if invitation.expires_at_ms == 0 || invitation.now_ms >= invitation.expires_at_ms {
        return Err(PrivateReturnError::ExpiredInvitation);
    }
    let enc = <KeyExchange as Kem>::EncappedKey::from_bytes(
        &envelope[PUBLIC_BYTES..PUBLIC_BYTES + ENCAP_BYTES],
    ).map_err(|_| PrivateReturnError::InvalidEnvelope)?;
    let plain = hpke::single_shot_open::<Aead, Kdf, KeyExchange>(
        &OpModeR::Base,
        invitation.sender_secret,
        &enc,
        INFO,
        &envelope[PUBLIC_BYTES + ENCAP_BYTES..],
        &envelope[..PUBLIC_BYTES],
    ).map_err(|_| PrivateReturnError::Crypto)?;
    if plain.len() != RECEIPT_LEN {
        return Err(PrivateReturnError::InvalidEnvelope);
    }
    Ok(receipt_w4::verify(&plain, invitation.recipient_trust)?)
}

/// This is the ONLY authorized way for an opaque W4 envelope to stop the
/// sender's journal. The existing Journal transaction independently checks
/// the exact W3 digest, recipient_id and message_id, and stops all route slots.
/// Idempotent replay is safe; no trusted state is inferred from relay metadata.
pub fn open_verify_and_apply(
    envelope: &[u8],
    invitation: ReturnInvitation<'_>,
    sender_journal: &mut Journal,
) -> Result<Delivery, PrivateReturnError> {
    let verified = open_verified(envelope, invitation)?;
    Ok(sender_journal.apply_recipient_receipt(&verified)?)
}
