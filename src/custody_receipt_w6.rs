//! Separate Ed25519 proof of *custodian storage* for EXP-017.
//!
//! Sign ONLY after an exact W3 packet has durably committed to the custodian
//! mailbox. A signature proves the custodian claims storage, not that bytes
//! remain available under a malicious operator or that the recipient accepted.
//! There is intentionally NO conversion to VerifiedRecipientReceipt (W4).
//! The proof exposes a pseudonymous custodian identity and message identifier;
//! do not broadcast it as an anonymous return receipt.
use crate::trust_w3::TrustRegistry;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};

const DOMAIN: &[u8] = b"Akula/WOW/custodian-stored/exp017/Ed25519-v1\0";
const VERSION: u8 = 1;
const BODY_LEN: usize = 1 + 16 + 16 + 16 + 32 + 8 + 8;
pub const PROOF_LEN: usize = BODY_LEN + 64;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum CustodyProofError {
    InvalidLength, InvalidClaims, WrongScope, Expired,
    UntrustedCustodian, InvalidSignature, WrongCiphertext,
}

/// Verified only with separately provisioned custodian keys; W3 keys and
/// QUIC EndpointId are never inferred from incoming receipt bytes.
pub struct ExpectedCustody<'a> {
    pub custodian_id: [u8;16],
    pub slot_id: [u8;16],
    pub message_id: [u8;16],
    pub ciphertext: &'a [u8],
    pub now_ms: u64,
}

pub struct VerifiedCustodyProof {
    custodian_id: [u8; 16],
    slot_id: [u8; 16],
    message_id: [u8; 16],
    ciphertext_digest: [u8; 32],
}
impl VerifiedCustodyProof {
    pub fn custodian_id(&self) -> [u8;16] { self.custodian_id }
    pub fn slot_id(&self) -> [u8;16] { self.slot_id }
    pub fn message_id(&self) -> [u8;16] { self.message_id }
    pub fn ciphertext_digest(&self) -> [u8;32] { self.ciphertext_digest }
}

/// Laboratory key used only by an independently authorized custodian.
/// The caller must invoke this AFTER durable store and apply its own role
/// and signed-lease permission checks. This function cannot verify storage.
pub fn sign_after_store(
    signer: &SigningKey,
    custodian_id: [u8;16],
    slot_id: [u8;16],
    message_id: [u8;16],
    exact_ciphertext: &[u8],
    epoch: u64,
    expires_at_ms: u64,
) -> Result<Vec<u8>, CustodyProofError> {
    if custodian_id == [0;16] || slot_id == [0;16] || message_id == [0;16]
        || exact_ciphertext.is_empty() || exact_ciphertext.len() > crate::MAX_MESSAGE_BYTES
        || epoch == 0 || expires_at_ms == 0 || expires_at_ms > i64::MAX as u64
    {
        return Err(CustodyProofError::InvalidClaims);
    }
    let mut body = Vec::with_capacity(PROOF_LEN);
    body.push(VERSION);
    body.extend_from_slice(&custodian_id);
    body.extend_from_slice(&slot_id);
    body.extend_from_slice(&message_id);
    body.extend_from_slice(blake3::hash(exact_ciphertext).as_bytes());
    body.extend_from_slice(&epoch.to_be_bytes());
    body.extend_from_slice(&expires_at_ms.to_be_bytes());
    debug_assert_eq!(body.len(), BODY_LEN);
    let mut signed = Vec::with_capacity(DOMAIN.len() + BODY_LEN);
    signed.extend_from_slice(DOMAIN);
    signed.extend_from_slice(&body);
    body.extend_from_slice(&signer.sign(&signed).to_bytes());
    Ok(body)
}

/// Verify a bounded, role-separated proof for exactly the stored W3 bytes.
/// Knowing this proof never establishes a final delivery or read capability.
pub fn verify(
    proof: &[u8],
    expected: ExpectedCustody<'_>,
    trust: &TrustRegistry,
) -> Result<VerifiedCustodyProof, CustodyProofError> {
    if proof.len() != PROOF_LEN { return Err(CustodyProofError::InvalidLength); }
    if proof[0] != VERSION { return Err(CustodyProofError::InvalidClaims); }
    let node: [u8;16] = proof[1..17].try_into().expect("checked length");
    let slot: [u8;16] = proof[17..33].try_into().expect("checked length");
    let message: [u8;16] = proof[33..49].try_into().expect("checked length");
    let digest: [u8;32] = proof[49..81].try_into().expect("checked length");
    let epoch = u64::from_be_bytes(proof[81..89].try_into().expect("checked length"));
    let expiry = u64::from_be_bytes(proof[89..97].try_into().expect("checked length"));
    if node != expected.custodian_id || slot != expected.slot_id
        || message != expected.message_id || epoch == 0 {
        return Err(CustodyProofError::WrongScope);
    }
    if expiry <= expected.now_ms || expiry > i64::MAX as u64 {
        return Err(CustodyProofError::Expired);
    }
    if expected.ciphertext.is_empty()
        || *blake3::hash(expected.ciphertext).as_bytes() != digest {
        return Err(CustodyProofError::WrongCiphertext);
    }
    let enrolled = trust.key_for(node, epoch)
        .map_err(|_| CustodyProofError::UntrustedCustodian)?;
    let signature=Signature::from_slice(&proof[BODY_LEN..])
        .map_err(|_| CustodyProofError::InvalidSignature)?;
    let mut signed = Vec::with_capacity(DOMAIN.len() + BODY_LEN);
    signed.extend_from_slice(DOMAIN);
    signed.extend_from_slice(&proof[..BODY_LEN]);
    enrolled.verify(&signed, &signature)
        .map_err(|_| CustodyProofError::InvalidSignature)?;
    Ok(VerifiedCustodyProof{
        custodian_id:node, slot_id:slot,
        message_id:message, ciphertext_digest:digest,
    })
}
