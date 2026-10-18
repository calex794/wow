//! W3 isolated crypto experiment: signed COSE_Sign1 INSIDE HPKE RFC 9180.
//! NOT the final AkulaNetEnvelopeV0 wire format, key registry or replay store.
use coset::{iana, CborSerializable, CoseSign1, CoseSign1Builder, HeaderBuilder};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hpke::{
    aead::ChaCha20Poly1305, kdf::HkdfSha256, kem::X25519HkdfSha256,
    Deserializable, Kem, OpModeR, OpModeS, Serializable,
};

type Aead = ChaCha20Poly1305;
type Kdf = HkdfSha256;
type KeyExchange = X25519HkdfSha256;
pub type RecipientSecret = <KeyExchange as Kem>::PrivateKey;
pub type RecipientPublic = <KeyExchange as Kem>::PublicKey;

/// Identity mapping must come from an authenticated invitation, NOT this packet.
pub fn new_recipient() -> (RecipientSecret, RecipientPublic) {
    KeyExchange::gen_keypair()
}

pub const VERSION: u8 = 1;
const INFO: &[u8] = b"Akula/WOW/W3/HPKE-v1/COSE-Sign1-Ed25519";
const HEADER_BYTES: usize = 1 + 16 + 16 + 8;
const ENCAP_BYTES: usize = 32;
const MAX_BYTES: usize = crate::MAX_MESSAGE_BYTES;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum CryptoError {
    Oversized, InvalidPacket, UnknownSuite, DecryptFailed, InvalidSignature,
    UnauthorizedSender, InvalidRecipient, Expired,
}

/// Signed message is bound to a recipient, an expiry time, and a stable ID.
/// HPKE AAD uses the exact header bytes to detect header manipulation.
pub struct RecipientContext<'a> {
    pub secret: &'a RecipientSecret,
    pub expected_sender: &'a VerifyingKey,
    pub expected_recipient: [u8; 16],
    pub now: u64,
}

pub fn seal(
    signing: &SigningKey,
    recipient: &RecipientPublic,
    message_id: [u8; 16],
    recipient_id: [u8; 16],
    expiry: u64,
    payload: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if payload.len() > MAX_BYTES.saturating_sub(512) {
        return Err(CryptoError::Oversized);
    }
    let mut header = Vec::with_capacity(HEADER_BYTES);
    header.push(VERSION);
    header.extend_from_slice(&message_id);
    header.extend_from_slice(&recipient_id);
    header.extend_from_slice(&expiry.to_be_bytes());
    let cose = CoseSign1Builder::new()
        .protected(HeaderBuilder::new().algorithm(iana::Algorithm::EdDSA).build())
        .payload(payload.to_vec())
        .create_signature(&header, |tbs| signing.sign(tbs).to_bytes().to_vec())
        .build()
        .to_vec()
        .map_err(|_| CryptoError::InvalidPacket)?;
    let (enc, ciphertext) =
        hpke::single_shot_seal::<Aead, Kdf, KeyExchange>(&OpModeS::Base, recipient, INFO, &cose, &header)
            .map_err(|_| CryptoError::InvalidPacket)?;
    let mut encoded = header;
    encoded.extend_from_slice(&enc.to_bytes());
    encoded.extend_from_slice(&ciphertext);
    if encoded.len() > MAX_BYTES { return Err(CryptoError::Oversized); }
    Ok(encoded)
}

pub fn open(packet: &[u8], recipient: RecipientContext<'_>) -> Result<([u8;16],Vec<u8>), CryptoError> {
    if packet.len() > MAX_BYTES { return Err(CryptoError::Oversized); }
    if packet.len() <= HEADER_BYTES + ENCAP_BYTES + 16 { return Err(CryptoError::InvalidPacket); }
    if packet[0] != VERSION { return Err(CryptoError::UnknownSuite); }
    let mut message_id = [0u8;16];
    message_id.copy_from_slice(&packet[1..17]);
    if packet[17..33] != recipient.expected_recipient { return Err(CryptoError::InvalidRecipient); }
    let expiry = u64::from_be_bytes(packet[33..41].try_into().map_err(|_|CryptoError::InvalidPacket)?);
    if recipient.now >= expiry { return Err(CryptoError::Expired); }
    let enc = <KeyExchange as Kem>::EncappedKey::from_bytes(&packet[HEADER_BYTES..HEADER_BYTES+ENCAP_BYTES])
        .map_err(|_| CryptoError::InvalidPacket)?;
    let plain = hpke::single_shot_open::<Aead, Kdf, KeyExchange>(
        &OpModeR::Base, recipient.secret, &enc, INFO,
        &packet[HEADER_BYTES+ENCAP_BYTES..], &packet[..HEADER_BYTES],
    ).map_err(|_| CryptoError::DecryptFailed)?;
    let signed = CoseSign1::from_slice(&plain).map_err(|_| CryptoError::InvalidSignature)?;
    if signed.protected.header.alg != Some(coset::Algorithm::Assigned(iana::Algorithm::EdDSA))
        || signed.unprotected != coset::Header::default()
    {
        return Err(CryptoError::InvalidSignature);
    }
    let sig_key = recipient.expected_sender;
    signed.verify_signature(&packet[..HEADER_BYTES], |signature, bytes| {
        let signature = Signature::from_slice(signature).map_err(|_| ())?;
        sig_key.verify(bytes, &signature).map_err(|_| ())
    }).map_err(|_|CryptoError::InvalidSignature)?;
    let payload = signed.payload.ok_or(CryptoError::InvalidSignature)?;
    Ok((message_id, payload))
}
