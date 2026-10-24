//! W7 P0-5: separate signed AUDIT authority is never a W6 STORE grant.
#![cfg(feature = "iroh-transport")]
use akula_wire_lab::custodian_audit_grant_w7::{
    sign_for_lab, verify_for_audit, AuditGrantClaims,
    AuditGrantError, AuditGrantExpectation,
};
use akula_wire_lab::route_grant_w5::{
    sign_for_lab as sign_store, RelayGrantClaims,
};
use akula_wire_lab::trust_w3::TrustRegistry;
use ed25519_dalek::SigningKey;
use iroh::{EndpointId, SecretKey};

fn id(value: u8) -> [u8; 16] { [value; 16] }
fn key(value: u8) -> SigningKey { SigningKey::from_bytes(&[value; 32]) }
fn endpoint(value: u8) -> EndpointId {
    SecretKey::from_bytes(&[value; 32]).public()
}
fn trust() -> TrustRegistry {
    let mut registry = TrustRegistry::new();
    registry.enroll(id(9), 4, key(9).verifying_key()).unwrap();
    registry
}
fn claims() -> AuditGrantClaims {
    AuditGrantClaims {
        issuer_id: id(9),
        issuer_epoch: 4,
        service_id: id(13),
        service_epoch: 7,
        service_endpoint: endpoint(13),
        auditor_endpoint: endpoint(14),
        route_token: id(4),
        message_id: id(5),
        ciphertext_len: 7,
        ciphertext_digest: [7; 32],
        expires_at_ms: 150_000,
        nonce: id(42),
    }
}
fn expected() -> AuditGrantExpectation {
    let c = claims();
    AuditGrantExpectation {
        issuer_id: c.issuer_id,
        service_id: c.service_id,
        service_epoch: c.service_epoch,
        service_endpoint: c.service_endpoint,
        auditor_endpoint: c.auditor_endpoint,
        route_token: c.route_token,
        message_id: c.message_id,
        ciphertext_len: c.ciphertext_len,
        ciphertext_digest: c.ciphertext_digest,
    }
}
#[test]
fn valid_exact_audit_and_replayed_same_auditor_until_expiry() {
    let grant = sign_for_lab(&key(9), claims()).unwrap();
    assert_eq!(verify_for_audit(&grant, expected(), &trust(), 100_000), Ok(()));
    assert_eq!(verify_for_audit(&grant, expected(), &trust(), 100_001), Ok(()));
    assert_eq!(
        verify_for_audit(&grant, expected(), &trust(), 150_000),
        Err(AuditGrantError::Expired)
    );
}
#[test]
fn wrong_scope_peer_ciphertext_revocation_and_forgery_are_denied() {
    let grant = sign_for_lab(&key(9), claims()).unwrap();
    let mut e = expected();
    e.auditor_endpoint = endpoint(21);
    assert_eq!(verify_for_audit(&grant, e, &trust(), 100_000),
        Err(AuditGrantError::WrongEndpoint));
    e = expected();
    e.service_endpoint = endpoint(21);
    assert_eq!(verify_for_audit(&grant, e, &trust(), 100_000),
        Err(AuditGrantError::WrongEndpoint));
    e = expected();
    e.service_epoch = 8;
    assert_eq!(verify_for_audit(&grant, e, &trust(), 100_000),
        Err(AuditGrantError::WrongService));
    e = expected();
    e.route_token = id(6);
    assert_eq!(verify_for_audit(&grant, e, &trust(), 100_000),
        Err(AuditGrantError::WrongRoute));
    e = expected();
    e.message_id = id(8);
    assert_eq!(verify_for_audit(&grant, e, &trust(), 100_000),
        Err(AuditGrantError::WrongMessage));
    e = expected();
    e.ciphertext_digest = [8; 32];
    assert_eq!(verify_for_audit(&grant, e, &trust(), 100_000),
        Err(AuditGrantError::WrongCiphertext));
    let mut tampered = grant.clone();
    tampered[200] ^= 1;
    assert_eq!(verify_for_audit(&tampered, expected(), &trust(), 100_000),
        Err(AuditGrantError::BadSignature));
    let mut revoked = trust();
    revoked.revoke(id(9)).unwrap();
    assert_eq!(verify_for_audit(&grant, expected(), &revoked, 100_000),
        Err(AuditGrantError::UntrustedIssuer));
    let forged = sign_for_lab(&key(14), claims()).unwrap();
    assert_eq!(verify_for_audit(&forged, expected(), &trust(), 100_000),
        Err(AuditGrantError::BadSignature));
}
#[test]
fn a_store_relay_grant_is_never_accepted_as_read_authority() {
    let store = sign_store(&key(9), RelayGrantClaims {
        issuer_id: id(9),
        issuer_epoch: 4,
        relay_id: id(13),
        namespace: id(22),
        route_token: id(4),
        message_id: id(5),
        ciphertext_len: 7,
        ciphertext_digest: [7; 32],
        expires_at: 150_000,
    }).unwrap();
    assert_eq!(verify_for_audit(&store, expected(), &trust(), 100_000),
        Err(AuditGrantError::InvalidLength));
}
#[test]
fn an_unsigned_or_invalid_audit_grant_cannot_authorize_any_read() {
    let mut c = claims();
    c.nonce = [0; 16];
    assert!(sign_for_lab(&key(9), c).is_err());
    c = claims();
    c.ciphertext_len = 0;
    assert!(sign_for_lab(&key(9), c).is_err());
    c = claims();
    c.service_epoch = 0;
    assert!(sign_for_lab(&key(9), c).is_err());
    let grant = sign_for_lab(&key(9), claims()).unwrap();
    assert_eq!(verify_for_audit(&grant, expected(), &trust(), 0),
        Err(AuditGrantError::Expired));
}
