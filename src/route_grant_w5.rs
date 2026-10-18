//! W5 laboratory route admission for an opaque W3 ciphertext.
//!
//! One detached, domain-separated Ed25519 grant authorizes a *single* byte-exact
//! packet for a pinned relay, namespace, route token and MessageId. The relay
//! verifies it without decrypting the end-to-end message. This is deliberately
//! NOT an AkulaNetEnvelopeV0 schema or peer-session authentication.
//!
//! Issuer key enrollment and role authorization MUST be performed by a trusted
//! control plane. Never construct RelayPolicy from a claimed network identity.
//! Possession of a valid grant is bearer authority to submit only that exact
//! ciphertext until expiry; this model cannot identify the actual TCP peer.
use crate::trust_w3::TrustRegistry;
use crate::MAX_MESSAGE_BYTES;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};

const DOMAIN: &[u8] = b"Akula/WOW/W5/relay-grant/lab-v1\0";
const VERSION: u8 = 1;
const BODY_LEN: usize = 1 + 16 + 8 + 16 + 16 + 16 + 16 + 8 + 4 + 32;
pub const SIGNED_GRANT_LEN: usize = BODY_LEN + 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantError {
    InvalidLength,
    UnsupportedVersion,
    InvalidClaims,
    WrongIssuer,
    WrongRelay,
    WrongNamespace,
    WrongRoute,
    Expired,
    UntrustedIssuer,
    InvalidSignature,
    PacketMismatch,
}

/// Privileged *local* issuance input. Grant authority is only established at
/// the relay by verifying the signature against an independently pinned owner.
#[derive(Clone, Copy)]
pub struct RelayGrantClaims {
    pub issuer_id: [u8; 16],
    pub issuer_epoch: u64,
    pub relay_id: [u8; 16],
    pub namespace: [u8; 16],
    pub route_token: [u8; 16],
    pub message_id: [u8; 16],
    pub expires_at: i64,
    pub ciphertext_len: u32,
    pub ciphertext_digest: [u8; 32],
}

/// Configuration from a *trusted relay operator*, not sender-provided bytes.
/// Registry enrollment alone does NOT grant authority to issue for this route.
#[derive(Clone, Copy)]
pub struct RelayPolicy {
    pub issuer_id: [u8; 16],
    pub relay_id: [u8; 16],
    pub namespace: [u8; 16],
    pub route_token: [u8; 16],
}

/// Created only after checking pinned issuer, current epoch, scope, signature,
/// trusted local clock, and the complete opaque packet digest.
pub struct VerifiedRelayGrant {
    route_token: [u8; 16],
    message_id: [u8; 16],
    expires_at: i64,
}
impl VerifiedRelayGrant {
    pub fn route_token(&self) -> [u8; 16] { self.route_token }
    pub fn message_id(&self) -> [u8; 16] { self.message_id }
    pub fn expires_at(&self) -> i64 { self.expires_at }
}

/// Only a trusted grant issuer should call this. This routine has no key store
/// or network service; it cannot authorize itself on the verifying relay.
pub fn sign_for_lab(
    signer: &SigningKey,
    claims: RelayGrantClaims,
) -> Result<Vec<u8>, GrantError> {
    if claims.expires_at <= 0 || claims.ciphertext_len == 0
        || claims.ciphertext_len as usize > MAX_MESSAGE_BYTES
    {
        return Err(GrantError::InvalidClaims);
    }
    let mut body = Vec::with_capacity(SIGNED_GRANT_LEN);
    body.push(VERSION);
    body.extend_from_slice(&claims.issuer_id);
    body.extend_from_slice(&claims.issuer_epoch.to_be_bytes());
    body.extend_from_slice(&claims.relay_id);
    body.extend_from_slice(&claims.namespace);
    body.extend_from_slice(&claims.route_token);
    body.extend_from_slice(&claims.message_id);
    body.extend_from_slice(&claims.expires_at.to_be_bytes());
    body.extend_from_slice(&claims.ciphertext_len.to_be_bytes());
    body.extend_from_slice(&claims.ciphertext_digest);
    debug_assert_eq!(body.len(), BODY_LEN);
    let mut to_sign = Vec::with_capacity(DOMAIN.len() + BODY_LEN);
    to_sign.extend_from_slice(DOMAIN);
    to_sign.extend_from_slice(&body);
    body.extend_from_slice(&signer.sign(&to_sign).to_bytes());
    Ok(body)
}

/// Verify afresh at the trust boundary for EACH request. Network bytes must
/// not supply policy, clock, or registry. Rechecking revocation on every
/// request prevents reusing an old cached "verified" grant after revoke.
pub fn verify_for_mailbox(
    signed: &[u8],
    expected: &RelayPolicy,
    trust: &TrustRegistry,
    now: i64,
    opaque_packet: &[u8],
) -> Result<VerifiedRelayGrant, GrantError> {
    if signed.len() != SIGNED_GRANT_LEN { return Err(GrantError::InvalidLength); }
    if signed[0] != VERSION { return Err(GrantError::UnsupportedVersion); }
    if now < 0 { return Err(GrantError::Expired); }
    let bytes16 = |start: usize| -> [u8; 16] {
        signed[start..start + 16].try_into().expect("signed length checked")
    };
    let issuer = bytes16(1);
    let epoch = u64::from_be_bytes(signed[17..25].try_into().expect("length"));
    let relay = bytes16(25);
    let namespace = bytes16(41);
    let token = bytes16(57);
    let message = bytes16(73);
    let expires_at = i64::from_be_bytes(signed[89..97].try_into().expect("length"));
    let ciphertext_len = u32::from_be_bytes(signed[97..101].try_into().expect("length")) as usize;
    let ciphertext_digest: [u8; 32] = signed[101..133].try_into().expect("length");

    if issuer != expected.issuer_id { return Err(GrantError::WrongIssuer); }
    if relay != expected.relay_id { return Err(GrantError::WrongRelay); }
    if namespace != expected.namespace { return Err(GrantError::WrongNamespace); }
    if token != expected.route_token { return Err(GrantError::WrongRoute); }
    if expires_at <= now { return Err(GrantError::Expired); }
    if ciphertext_len == 0 || ciphertext_len > MAX_MESSAGE_BYTES
        || ciphertext_len != opaque_packet.len()
    {
        return Err(GrantError::PacketMismatch);
    }

    let issuer_key = trust.key_for(issuer, epoch)
        .map_err(|_| GrantError::UntrustedIssuer)?;
    let signature = Signature::from_slice(&signed[BODY_LEN..])
        .map_err(|_| GrantError::InvalidSignature)?;
    let mut authenticated = Vec::with_capacity(DOMAIN.len() + BODY_LEN);
    authenticated.extend_from_slice(DOMAIN);
    authenticated.extend_from_slice(&signed[..BODY_LEN]);
    issuer_key.verify(&authenticated, &signature)
        .map_err(|_| GrantError::InvalidSignature)?;

    if ciphertext_digest != *blake3::hash(opaque_packet).as_bytes() {
        return Err(GrantError::PacketMismatch);
    }
    Ok(VerifiedRelayGrant {
        route_token: token, message_id: message, expires_at,
    })
}
