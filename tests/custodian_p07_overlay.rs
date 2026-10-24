//! P07 policy tests; signatures and ordinary routes never grant AUDIT.
#![cfg(feature = "iroh-transport")]
use akula_wire_lab::custodian_audit_grant_w7::{sign_for_lab, AuditGrantClaims, AuditGrantExpectation};
use akula_wire_lab::custodian_p07_overlay::{
    check_and_respond, validate_bind_address, validate_synthetic_fixture,
    Decision, HostAuditPolicy, OverlayError, ProbeFault,
};
use akula_wire_lab::route_grant_w5::{sign_for_lab as sign_write, RelayGrantClaims};
use akula_wire_lab::trust_w3::TrustRegistry;
use ed25519_dalek::SigningKey;
use iroh::{EndpointId, SecretKey};
use std::net::SocketAddr;
const NOW: u64 = 5_000;

fn key(n: u8) -> SigningKey { SigningKey::from_bytes(&[n; 32]) }
fn id(n: u8) -> [u8; 16] { [n; 16] }
fn tls(n: u8) -> EndpointId { SecretKey::from_bytes(&[n; 32]).public() }
fn bytes() -> Vec<u8> { b"synthetic encrypted W3 fixture only".to_vec() }
fn trust() -> TrustRegistry {
    let mut t = TrustRegistry::new();
    t.enroll(id(9), 4, key(9).verifying_key()).unwrap();
    t
}
fn policy(w3: &[u8], fault: ProbeFault) -> HostAuditPolicy<'_> {
    HostAuditPolicy {
        expected: AuditGrantExpectation {
            issuer_id: id(9), service_id: id(13), service_epoch: 7,
            service_endpoint: tls(13), auditor_endpoint: tls(50),
            route_token: id(4), message_id: id(5),
            ciphertext_len: w3.len() as u32,
            ciphertext_digest: *blake3::hash(w3).as_bytes(),
        },
        actual_service_endpoint: tls(13),
        synthetic_w3: Some(w3),
        fault,
    }
}
fn signed(w3: &[u8]) -> Vec<u8> {
    let p = policy(w3, ProbeFault::Honest);
    let claims = AuditGrantClaims {
        issuer_id: p.expected.issuer_id, issuer_epoch: 4,
        service_id: p.expected.service_id, service_epoch: p.expected.service_epoch,
        service_endpoint: p.expected.service_endpoint,
        auditor_endpoint: p.expected.auditor_endpoint,
        route_token: p.expected.route_token, message_id: p.expected.message_id,
        ciphertext_len: p.expected.ciphertext_len,
        ciphertext_digest: p.expected.ciphertext_digest,
        expires_at_ms: 10_000, nonce: id(51),
    };
    let mut request = vec![5];
    request.extend_from_slice(&sign_for_lab(&key(9), claims).unwrap());
    request
}
fn respond(p: &HostAuditPolicy<'_>, frame: &[u8], remote: EndpointId) -> (Decision, Vec<u8>) {
    check_and_respond(p, remote, frame, &trust(), NOW)
}

#[test]
fn only_explicit_private_overlay_interfaces_may_bind() {
    for ip in ["127.0.0.1:1111","[::1]:2222"] {
        let addr: SocketAddr = ip.parse().unwrap();
        assert_eq!(validate_bind_address(addr, false), Ok(()));
    }
    for ip in ["10.0.1.22:1234","172.18.9.1:1234","192.168.0.1:1234",
        "100.64.1.99:1234","[fd00::1]:1234"]
    {
        let addr: SocketAddr = ip.parse().unwrap();
        assert_eq!(validate_bind_address(addr, false),
            Err(OverlayError::NonLoopbackRequiresOptIn));
        assert_eq!(validate_bind_address(addr, true), Ok(()));
    }
    for ip in ["0.0.0.0:5555","8.8.8.8:4444","1.1.1.1:5555",
        "224.0.0.1:5555","[::]:1234","[2606:4700:4700::1111]:2222"]
    {
        let addr: SocketAddr = ip.parse().unwrap();
        assert_eq!(validate_bind_address(addr, true),
            Err(OverlayError::PublicOrUnspecifiedBind));
    }
}

#[test]
fn signed_exact_w3_audit_does_not_issue_w4_or_any_store_right() {
    let w3 = bytes();
    let cfg = policy(&w3, ProbeFault::Honest);
    let (decision, payload) = respond(&cfg, &signed(&w3), tls(50));
    assert_eq!(decision, Decision::Exact);
    assert_eq!(&payload[..1], &[2]);
    assert_eq!(&payload[1..], w3.as_slice());
    assert!(payload.len() <= akula_wire_lab::MAX_MESSAGE_BYTES + 1);
}
#[test]
fn unknown_signed_issuer_and_wrong_tlspins_never_leak_mailbox() {
    let w3 = bytes();
    let cfg = policy(&w3, ProbeFault::Honest);
    let grant = signed(&w3);
    let (a, body) = respond(&cfg, &grant, tls(25));
    assert_eq!((a, body), (Decision::Denied, vec![255]));
    let mut wrong_server = policy(&w3, ProbeFault::Honest);
    wrong_server.actual_service_endpoint = tls(25);
    assert_eq!(respond(&wrong_server, &grant, tls(50)),
        (Decision::Denied, vec![255]));
    let mut altered = grant.clone();
    altered[20] ^= 1;
    assert_eq!(respond(&cfg, &altered, tls(50)),
        (Decision::Denied, vec![255]));
    let revoked = TrustRegistry::new();
    assert_eq!(check_and_respond(&cfg, tls(50), &grant, &revoked, NOW),
        (Decision::Denied, vec![255]));
}
#[test]
fn old_shared_cap_and_write_grants_do_not_authorize_read() {
    let w3 = bytes();
    let cfg = policy(&w3, ProbeFault::Honest);
    assert_eq!(respond(&cfg, &[2, 22, 22, 22], tls(50)),
        (Decision::Denied, vec![255]));
    assert_eq!(respond(&cfg, &[5, 4, 4, 4], tls(50)),
        (Decision::Denied, vec![255]));
    let store = sign_write(&key(9), RelayGrantClaims {
        issuer_id: id(9), issuer_epoch: 4,
        relay_id: id(13), namespace: id(41),
        route_token: id(4), message_id: id(5),
        ciphertext_len: w3.len() as u32,
        ciphertext_digest: *blake3::hash(&w3).as_bytes(),
        expires_at: 10_000,
    }).unwrap();
    let mut frame = vec![5];
    frame.extend_from_slice(&store);
    assert_eq!(respond(&cfg, &frame, tls(50)),
        (Decision::Denied, vec![255]));
}
#[test]
fn bad_w3_or_unavailable_response_never_counts_as_verified_success() {
    let w3 = bytes();
    let grant = signed(&w3);
    let honest = policy(&w3, ProbeFault::Honest);
    let mut missing = policy(&w3, ProbeFault::Missing);
    missing.synthetic_w3 = None;
    assert_eq!(respond(&missing, &grant, tls(50)),
        (Decision::Unavailable, vec![0]));
    let mut changed = w3.clone();
    changed[0] ^= 1;
    let policy_wrong_bytes = HostAuditPolicy {
        synthetic_w3: Some(&changed), ..honest
    };
    assert_eq!(respond(&policy_wrong_bytes, &grant, tls(50)),
        (Decision::Unavailable, vec![0]));
    let corrupt = policy(&w3, ProbeFault::Corrupt);
    let (decision, body) = respond(&corrupt, &grant, tls(50));
    assert_eq!(decision, Decision::SyntheticCorruption);
    assert_ne!(&body[1..], w3.as_slice());
    assert_eq!(respond(&policy(&w3, ProbeFault::Reject), &grant, tls(50)),
        (Decision::Denied, vec![255]));
}
#[test]
fn invalid_time_and_unbounded_fixture_fail_closed() {
    let w3 = bytes();
    let cfg = policy(&w3, ProbeFault::Honest);
    let frame = signed(&w3);
    assert_eq!(check_and_respond(&cfg, tls(50), &frame, &trust(), 10_000),
        (Decision::Denied, vec![255]));
    assert_eq!(validate_synthetic_fixture(&[]), Err(OverlayError::InvalidFixture));
    assert_eq!(validate_synthetic_fixture(&vec![1; akula_wire_lab::MAX_MESSAGE_BYTES+1]),
        Err(OverlayError::InvalidFixture));
}
