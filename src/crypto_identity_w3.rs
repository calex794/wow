//! W3 v2 research packet: binds sender DeviceId + key epoch to COSE signature and HPKE AAD.
//! NOT a production format. The trust registry is in-memory and enrollment is external.
use crate::crypto_w3::{CryptoError, RecipientPublic, RecipientSecret};
use crate::trust_w3::TrustRegistry;
use coset::{iana, CborSerializable, CoseSign1, CoseSign1Builder, HeaderBuilder};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use hpke::{aead::ChaCha20Poly1305, kdf::HkdfSha256, kem::X25519HkdfSha256,
    Deserializable, OpModeR, OpModeS, Serializable, Kem};

pub const VERSION: u8 = 2;
const INFO: &[u8] = b"Akula/WOW/W3/device-epoch-v2/HPKE-COSE";
const HEADER: usize = 1+16+16+8+16+8;
const ENC: usize = 32;
pub const MAX_BYTES: usize = crate::MAX_MESSAGE_BYTES;
#[derive(Clone, Copy)]
pub struct SignedHeader {
    pub message_id: [u8;16],
    pub recipient_id: [u8;16],
    pub expiry: u64,
    pub sender_id: [u8;16],
    pub epoch: u64,
}
fn header(h: SignedHeader) -> Vec<u8> {
    let mut b=Vec::with_capacity(HEADER);
    b.push(VERSION);
    b.extend_from_slice(&h.message_id);
    b.extend_from_slice(&h.recipient_id);
    b.extend_from_slice(&h.expiry.to_be_bytes());
    b.extend_from_slice(&h.sender_id);
    b.extend_from_slice(&h.epoch.to_be_bytes());
    b
}
pub fn seal(signing: &SigningKey, recipient: &RecipientPublic, h: SignedHeader,
    payload: &[u8]) -> Result<Vec<u8>,CryptoError> {
    if payload.len() > MAX_BYTES.saturating_sub(512) {return Err(CryptoError::Oversized);}
    let aad=header(h);
    let signed=CoseSign1Builder::new()
        .protected(HeaderBuilder::new().algorithm(iana::Algorithm::EdDSA).build())
        .payload(payload.to_vec())
        .create_signature(&aad, |bytes| signing.sign(bytes).to_bytes().to_vec())
        .build().to_vec().map_err(|_|CryptoError::InvalidPacket)?;
    let (enc,ciphertext)=hpke::single_shot_seal::<ChaCha20Poly1305,HkdfSha256,X25519HkdfSha256>(
        &OpModeS::Base,recipient,INFO,&signed,&aad).map_err(|_|CryptoError::InvalidPacket)?;
    let mut output=aad;
    output.extend_from_slice(&enc.to_bytes());
    output.extend_from_slice(&ciphertext);
    if output.len()>MAX_BYTES {return Err(CryptoError::Oversized);}
    Ok(output)
}
pub struct TrustedRecipient<'a> {
    pub secret: &'a RecipientSecret,
    pub recipient_id: [u8;16],
    pub now: u64,
    pub registry: &'a TrustRegistry,
}
/// Returns authenticated sender identity and epoch, not authorization for file access.
/// The registry chooses the key. Caller does not supply a purported sender key/epoch.
pub fn open(packet: &[u8], recipient: TrustedRecipient<'_>)
    -> Result<(SignedHeader,Vec<u8>),CryptoError> {
    if packet.len()>MAX_BYTES{return Err(CryptoError::Oversized);}
    if packet.len()<=HEADER+ENC+16{return Err(CryptoError::InvalidPacket);}
    if packet[0]!=VERSION{return Err(CryptoError::UnknownSuite);}
    let array16=|start:usize| -> [u8;16] {
        packet[start..start+16].try_into().expect("validated packet size")
    };
    let h=SignedHeader{
        message_id:array16(1), recipient_id:array16(17),
        expiry:u64::from_be_bytes(packet[33..41].try_into().expect("size")),
        sender_id:array16(41),
        epoch:u64::from_be_bytes(packet[57..65].try_into().expect("size")),
    };
    if h.recipient_id!=recipient.recipient_id{return Err(CryptoError::InvalidRecipient);}
    if recipient.now>=h.expiry{return Err(CryptoError::Expired);}
    let key=recipient.registry.key_for(h.sender_id,h.epoch)
        .map_err(|_|CryptoError::UnauthorizedSender)?;
    let enc=<X25519HkdfSha256 as Kem>::EncappedKey::from_bytes(&packet[HEADER..HEADER+ENC])
        .map_err(|_|CryptoError::InvalidPacket)?;
    let plaintext=hpke::single_shot_open::<ChaCha20Poly1305,HkdfSha256,X25519HkdfSha256>(
        &OpModeR::Base,recipient.secret,&enc,INFO,&packet[HEADER+ENC..],&packet[..HEADER])
        .map_err(|_|CryptoError::DecryptFailed)?;
    let signed=CoseSign1::from_slice(&plaintext).map_err(|_|CryptoError::InvalidSignature)?;
    if signed.protected.header.alg!=Some(coset::Algorithm::Assigned(iana::Algorithm::EdDSA))
        || signed.unprotected!=coset::Header::default() {
        return Err(CryptoError::InvalidSignature);
    }
    signed.verify_signature(&packet[..HEADER], |sig,data| {
        let signature=Signature::from_slice(sig).map_err(|_|())?;
        key.verify(data,&signature).map_err(|_|())
    }).map_err(|_|CryptoError::InvalidSignature)?;
    Ok((h,signed.payload.ok_or(CryptoError::InvalidSignature)?))
}
