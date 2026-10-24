//! W7-CUSTODIAN P0-5: purpose-separated, single-W3 AUDIT read capability.
//!
//! LAB ONLY. This is NOT the W5/W6 STORE RelayGrant: an issuer's authority
//! to sign one kind of grant does not silently grant a different operation.
//! A client-supplied 16-byte W3 route tag or old W7 shared AUDIT_CAP never
//! authorizes an AUDIT in the new grant-only laboratory mode.
//!
//! TrustRegistry only authenticates the issuer's Ed25519 key. The trusted
//! local operator must independently authorize that issuer for this exact
//! (service, route, message, peer) scope in AuditGrantExpectation.
//! The auditor is bound to a concrete TLS EndpointId; revocation and clock
//! checks must be redone for every use. This grant is replayable by that SAME
//! auditor until expiry: it is not a once-only authorization or an HSM policy.
//! No production protocol, public directory, Vault access or W4 is created.
use crate::trust_w3::TrustRegistry;
use ed25519_dalek::{Signature, Signer, SigningKey};
use iroh::EndpointId;

const DOMAIN: &[u8] = b"Akula/WOW/W7/audit-read-grant/lab-v0\0";
const VERSION: u8 = 1;
const BODY_LEN: usize = 205;
pub const SIGNED_AUDIT_GRANT_LEN: usize = BODY_LEN + 64;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum AuditGrantError {
    InvalidLength,
    InvalidClaims,
    WrongIssuer,
    WrongService,
    WrongEndpoint,
    WrongRoute,
    WrongMessage,
    WrongCiphertext,
    Expired,
    UntrustedIssuer,
    BadSignature,
}

#[derive(Clone, Copy)]
pub struct AuditGrantClaims {
    pub issuer_id: [u8; 16],
    pub issuer_epoch: u64,
    pub service_id: [u8; 16],
    pub service_epoch: u64,
    pub service_endpoint: EndpointId,
    pub auditor_endpoint: EndpointId,
    pub route_token: [u8; 16],
    pub message_id: [u8; 16],
    pub ciphertext_len: u32,
    pub ciphertext_digest: [u8; 32],
    pub expires_at_ms: u64,
    /// Nonzero opaque grant nonce. Does not provide one-time replay protection.
    pub nonce: [u8; 16],
}

/// Pinned local admission policy, never fields copied from the untrusted
/// request. Caller must check the issuer is allowed to grant this route.
#[derive(Clone, Copy)]
pub struct AuditGrantExpectation {
    pub issuer_id: [u8; 16],
    pub service_id: [u8; 16],
    pub service_epoch: u64,
    pub service_endpoint: EndpointId,
    pub auditor_endpoint: EndpointId,
    pub route_token: [u8; 16],
    pub message_id: [u8; 16],
    pub ciphertext_len: u32,
    pub ciphertext_digest: [u8; 32],
}

fn valid(c: &AuditGrantClaims) -> bool {
    c.issuer_id != [0; 16] && c.issuer_epoch > 0
        && c.issuer_epoch <= i64::MAX as u64
        && c.service_id != [0; 16] && c.service_epoch > 0
        && c.service_epoch <= i64::MAX as u64
        && c.route_token != [0; 16] && c.message_id != [0; 16]
        && c.ciphertext_len > 0
        && c.ciphertext_len as usize <= crate::MAX_MESSAGE_BYTES
        && c.ciphertext_digest != [0; 32]
        && c.expires_at_ms > 0 && c.expires_at_ms <= i64::MAX as u64
        && c.nonce != [0; 16]
}

fn signing_input(body: &[u8]) -> Vec<u8> {
    let mut buffer = Vec::with_capacity(DOMAIN.len() + body.len());
    buffer.extend_from_slice(DOMAIN);
    buffer.extend_from_slice(body);
    buffer
}

/// Offline, trusted issuer-only helper. No remote API signs arbitrary grants.
pub fn sign_for_lab(
    signer: &SigningKey, claims: AuditGrantClaims,
) -> Result<Vec<u8>, AuditGrantError> {
    if !valid(&claims) { return Err(AuditGrantError::InvalidClaims); }
    let mut body = Vec::with_capacity(SIGNED_AUDIT_GRANT_LEN);
    body.push(VERSION);
    body.extend_from_slice(&claims.issuer_id);
    body.extend_from_slice(&claims.issuer_epoch.to_be_bytes());
    body.extend_from_slice(&claims.service_id);
    body.extend_from_slice(&claims.service_epoch.to_be_bytes());
    body.extend_from_slice(claims.service_endpoint.as_bytes());
    body.extend_from_slice(claims.auditor_endpoint.as_bytes());
    body.extend_from_slice(&claims.route_token);
    body.extend_from_slice(&claims.message_id);
    body.extend_from_slice(&claims.ciphertext_len.to_be_bytes());
    body.extend_from_slice(&claims.ciphertext_digest);
    body.extend_from_slice(&claims.expires_at_ms.to_be_bytes());
    body.extend_from_slice(&claims.nonce);
    debug_assert_eq!(body.len(), BODY_LEN);
    let signature = signer.sign(&signing_input(&body));
    body.extend_from_slice(&signature.to_bytes());
    Ok(body)
}

/// Check at each read boundary with trusted local time and TLS identities.
/// A valid W5/W6 STORE RelayGrant cannot be parsed as this W7 AUDIT grant.
pub fn verify_for_audit(
    signed: &[u8], expected: AuditGrantExpectation,
    trust: &TrustRegistry, now_ms: u64,
) -> Result<(), AuditGrantError> {
    if signed.len() != SIGNED_AUDIT_GRANT_LEN {
        return Err(AuditGrantError::InvalidLength);
    }
    if signed[0] != VERSION { return Err(AuditGrantError::InvalidClaims); }
    let sixteen = |offset: usize| -> [u8; 16] {
        signed[offset..offset + 16].try_into().expect("fixed length validated")
    };
    let number = |offset: usize| -> u64 {
        u64::from_be_bytes(signed[offset..offset + 8].try_into().expect("length"))
    };
    let issuer = sixteen(1);
    let issuer_epoch = number(17);
    let service = sixteen(25);
    let service_epoch = number(41);
    if issuer != expected.issuer_id {
        return Err(AuditGrantError::WrongIssuer);
    }
    if service != expected.service_id || service_epoch != expected.service_epoch {
        return Err(AuditGrantError::WrongService);
    }
    if signed[49..81] != *expected.service_endpoint.as_bytes()
        || signed[81..113] != *expected.auditor_endpoint.as_bytes()
    {
        return Err(AuditGrantError::WrongEndpoint);
    }
    if sixteen(113) != expected.route_token {
        return Err(AuditGrantError::WrongRoute);
    }
    if sixteen(129) != expected.message_id {
        return Err(AuditGrantError::WrongMessage);
    }
    let packet_len = u32::from_be_bytes(signed[145..149].try_into().expect("length"));
    if packet_len != expected.ciphertext_len
        || signed[149..181] != expected.ciphertext_digest
    {
        return Err(AuditGrantError::WrongCiphertext);
    }
    let expires = number(181);
    if now_ms == 0 || now_ms > i64::MAX as u64 || expires <= now_ms {
        return Err(AuditGrantError::Expired);
    }
    if issuer_epoch == 0 || issuer_epoch > i64::MAX as u64
        || service_epoch == 0 || service_epoch > i64::MAX as u64
        || expires > i64::MAX as u64 || sixteen(189) == [0; 16]
        || issuer == [0; 16] || service == [0; 16]
    {
        return Err(AuditGrantError::InvalidClaims);
    }
    let issuer_key = trust.key_for(issuer, issuer_epoch)
        .map_err(|_| AuditGrantError::UntrustedIssuer)?;
    let signature = Signature::from_slice(&signed[BODY_LEN..])
        .map_err(|_| AuditGrantError::BadSignature)?;
    issuer_key.verify_strict(&signing_input(&signed[..BODY_LEN]), &signature)
        .map_err(|_| AuditGrantError::BadSignature)
}
