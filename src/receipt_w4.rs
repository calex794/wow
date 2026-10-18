//! W4 experimental signed receipt: acknowledges receipt of ONE exact ciphertext.
//! Not a message application, file commit, delivery SLA or trustworthy key enrollment.
use crate::trust_w3::TrustRegistry;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};

const DOMAIN: &[u8] = b"Akula/WOW/recipient-ack/v1\0";
const VERSION: u8 = 1;
const SIGNED_LEN: usize = 1 + 16 + 16 + 32 + 8;
pub const RECEIPT_LEN: usize = SIGNED_LEN + 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptError {
    InvalidLength, UnsupportedVersion, UntrustedRecipient, InvalidSignature,
}

/// A signed receipt can be made by an endpoint, but cannot pass verification
/// unless its signing key was independently enrolled for the recipient identity.
pub fn sign(
    signing: &SigningKey,
    recipient_id: [u8;16],
    message_id: [u8;16],
    packet_digest: [u8;32],
    epoch: u64,
) -> Vec<u8> {
    let mut body = Vec::with_capacity(RECEIPT_LEN);
    body.push(VERSION);
    body.extend_from_slice(&recipient_id);
    body.extend_from_slice(&message_id);
    body.extend_from_slice(&packet_digest);
    body.extend_from_slice(&epoch.to_be_bytes());
    let mut to_sign = Vec::with_capacity(DOMAIN.len() + SIGNED_LEN);
    to_sign.extend_from_slice(DOMAIN);
    to_sign.extend_from_slice(&body);
    body.extend_from_slice(&signing.sign(&to_sign).to_bytes());
    body
}

/// The fields are private to prevent construction without a verified signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedRecipientReceipt {
    recipient_id: [u8;16],
    message_id: [u8;16],
    packet_digest: [u8;32],
}
impl VerifiedRecipientReceipt {
    pub fn recipient_id(&self) -> [u8;16] { self.recipient_id }
    pub fn message_id(&self) -> [u8;16] { self.message_id }
    pub fn packet_digest(&self) -> [u8;32] { self.packet_digest }
}
pub fn verify(packet: &[u8], trust: &TrustRegistry) -> Result<VerifiedRecipientReceipt,ReceiptError> {
    if packet.len() != RECEIPT_LEN { return Err(ReceiptError::InvalidLength); }
    if packet[0] != VERSION { return Err(ReceiptError::UnsupportedVersion); }
    let recipient_id: [u8;16] = packet[1..17].try_into().expect("length checked");
    let message_id: [u8;16] = packet[17..33].try_into().expect("length checked");
    let packet_digest: [u8;32] = packet[33..65].try_into().expect("length checked");
    let epoch = u64::from_be_bytes(packet[65..73].try_into().expect("length checked"));
    let key = trust.key_for(recipient_id, epoch)
        .map_err(|_| ReceiptError::UntrustedRecipient)?;
    let signature=Signature::from_slice(&packet[SIGNED_LEN..])
        .map_err(|_| ReceiptError::InvalidSignature)?;
    let mut message=Vec::with_capacity(DOMAIN.len()+SIGNED_LEN);
    message.extend_from_slice(DOMAIN);
    message.extend_from_slice(&packet[..SIGNED_LEN]);
    key.verify(&message, &signature).map_err(|_| ReceiptError::InvalidSignature)?;
    Ok(VerifiedRecipientReceipt {recipient_id,message_id,packet_digest})
}
