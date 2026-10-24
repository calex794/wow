//! Confidential, fixed-size CLOUD control locator envelope (LAB ONLY).
//!
//! Signed pins contain private message and recipient identifiers. Never
//! publish them as cleartext S3 objects. HPKE hides their content from
//! an untrusted MinIO/S3 operator; Ed25519 of the inner pin separately
//! authenticates the pinned sender after decryption. A known control key
//! is used as associated data; the object key must be provisioned through
//! an authenticated invitation. This does not solve key bootstrap, traffic
//! analysis, anti-rollback, or authorized capability issuance.
use akula_wire_lab::{
    cloud_mail_store::{CloudError, CloudKey},
    crypto_w3::{RecipientPublic, RecipientSecret},
};
use hpke::{
    aead::ChaCha20Poly1305, kdf::HkdfSha256, kem::X25519HkdfSha256,
    Deserializable, Kem, OpModeR, OpModeS, Serializable,
};

type Aead = ChaCha20Poly1305;
type Kdf = HkdfSha256;
type KeyExchange = X25519HkdfSha256;
const INFO: &[u8] = b"Akula/WOW/cloud/signed-control/HPKE-v1";
const PADDED_LEN: usize = 512;
const ENCAP_LEN: usize = 32;
pub const ENVELOPE_LEN: usize = 1 + ENCAP_LEN + PADDED_LEN + 16;
const VERSION: u8 = 1;
pub const MAX_SIGNED_PIN_LEN: usize = PADDED_LEN - 2;

fn aad(key: CloudKey) -> Vec<u8> {
    let mut out = Vec::with_capacity(INFO.len() + 32);
    out.extend_from_slice(INFO);
    out.extend_from_slice(&key.namespace);
    out.extend_from_slice(&key.object);
    out
}

/// Padded HPKE envelope: no recipient/message identity in public bytes.
/// The caller must publish this only to the intended scoped control key.
pub fn seal(
    recipient: &RecipientPublic, control_key: CloudKey, signed_pin: &[u8],
) -> Result<Vec<u8>, CloudError> {
    if signed_pin.is_empty() || signed_pin.len() > MAX_SIGNED_PIN_LEN {
        return Err(CloudError::InvalidGrant);
    }
    let mut padded = vec![0u8; PADDED_LEN];
    padded[..2].copy_from_slice(&(signed_pin.len() as u16).to_be_bytes());
    padded[2..2 + signed_pin.len()].copy_from_slice(signed_pin);
    let (enc, ciphertext) = hpke::single_shot_seal::<Aead, Kdf, KeyExchange>(
        &OpModeS::Base, recipient, INFO, &padded, &aad(control_key),
    ).map_err(|_| CloudError::Corrupt)?;
    let mut out = Vec::with_capacity(ENVELOPE_LEN);
    out.push(VERSION);
    out.extend_from_slice(&enc.to_bytes());
    out.extend_from_slice(&ciphertext);
    if out.len() != ENVELOPE_LEN {
        return Err(CloudError::Corrupt);
    }
    Ok(out)
}

/// Decryption is NOT sender authentication. Always verify the recovered
/// Ed25519 signed pin with an independently enrolled sender key.
pub fn open(
    recipient: &RecipientSecret, control_key: CloudKey, envelope: &[u8],
) -> Result<Vec<u8>, CloudError> {
    if envelope.len() != ENVELOPE_LEN || envelope[0] != VERSION {
        return Err(CloudError::InvalidGrant);
    }
    let enc = <KeyExchange as Kem>::EncappedKey::from_bytes(&envelope[1..1 + ENCAP_LEN])
        .map_err(|_| CloudError::Corrupt)?;
    let padded = hpke::single_shot_open::<Aead, Kdf, KeyExchange>(
        &OpModeR::Base, recipient, &enc, INFO,
        &envelope[1 + ENCAP_LEN..], &aad(control_key),
    ).map_err(|_| CloudError::Corrupt)?;
    if padded.len() != PADDED_LEN {
        return Err(CloudError::Corrupt);
    }
    let count = u16::from_be_bytes([padded[0], padded[1]]) as usize;
    if count == 0 || count > MAX_SIGNED_PIN_LEN ||
       padded[2 + count..].iter().any(|b| *b != 0)
    {
        return Err(CloudError::Corrupt);
    }
    Ok(padded[2..2 + count].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use akula_wire_lab::crypto_w3::new_recipient;

    #[test]
    fn confidential_control_is_fixed_length_and_bound_to_key_and_recipient() {
        let (alice_secret, alice_public) = new_recipient();
        let (bob_secret, _) = new_recipient();
        let key = CloudKey { namespace: [7; 16], object: [8; 16] };
        let pin = b"signed Ed25519 locator (fixture)";
        let wire = seal(&alice_public, key, pin).unwrap();
        assert_eq!(wire.len(), ENVELOPE_LEN);
        assert!(!wire.windows(pin.len()).any(|w| w == pin));
        assert_eq!(open(&alice_secret, key, &wire).unwrap(), pin);
        let mut other = key;
        other.object = [9; 16];
        assert_eq!(open(&alice_secret, other, &wire), Err(CloudError::Corrupt));
        assert_eq!(open(&bob_secret, key, &wire), Err(CloudError::Corrupt));
        let mut damaged = wire.clone();
        let last = damaged.len() - 1;
        damaged[last] ^= 1;
        assert_eq!(open(&alice_secret, key, &damaged), Err(CloudError::Corrupt));
        assert_eq!(open(&alice_secret, key, &wire[..wire.len() - 1]),
                   Err(CloudError::InvalidGrant));
        assert_eq!(seal(&alice_public, key, &[]), Err(CloudError::InvalidGrant));
        assert_eq!(seal(&alice_public, key, &vec![1; MAX_SIGNED_PIN_LEN + 1]),
                   Err(CloudError::InvalidGrant));
    }
}
