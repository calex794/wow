//! Two different signatures are NOT proof of physically independent operators.
use akula_wire_lab::custodian_two_host_preflight::{
    sign_for_lab, verify_pair, ExpectedHost, HostStatement, Independence,
    PreflightError, RunChallenge, SignedHostStatement,
};
use akula_wire_lab::trust_w3::TrustRegistry;
use ed25519_dalek::SigningKey;

const NOW: u64 = 5_000;
fn key(v: u8) -> SigningKey { SigningKey::from_bytes(&[v; 32]) }
fn id(v: u8) -> [u8; 16] { [v; 16] }
fn endpoint(v: u8) -> [u8; 32] { [v; 32] }

fn challenge() -> RunChallenge {
    RunChallenge { nonce: [91; 32], issued_at_ms: 1_000, deadline_ms: 10_000 }
}
fn statement(n: u8) -> HostStatement {
    let (service, epoch, tls, operator, domain) = if n == 1 {
        (11, 1, 71, 31, 51)
    } else {
        (12, 2, 72, 32, 52)
    };
    HostStatement {
        run_nonce: challenge().nonce,
        service_id: id(service),
        service_epoch: epoch,
        claimed_tls_endpoint: endpoint(tls),
        operator_id: id(operator),
        claimed_failure_domain: id(domain),
        attested_at_ms: 2_000,
        expires_at_ms: 8_000,
    }
}
fn signed(n: u8) -> SignedHostStatement {
    let s = statement(n);
    let service_key = if n == 1 { 11 } else { 12 };
    let operator_key = if n == 1 { 31 } else { 32 };
    sign_for_lab(s, &key(service_key), &key(operator_key)).unwrap()
}
fn trusted() -> TrustRegistry {
    let mut trust = TrustRegistry::new();
    trust.enroll(id(11), 1, key(11).verifying_key()).unwrap();
    trust.enroll(id(12), 2, key(12).verifying_key()).unwrap();
    trust
}
fn expected<'a>(n: u8, operator: &'a ed25519_dalek::VerifyingKey) -> ExpectedHost<'a> {
    let s = statement(n);
    ExpectedHost {
        service_id: s.service_id,
        service_epoch: s.service_epoch,
        tls_endpoint: s.claimed_tls_endpoint,
        operator_id: s.operator_id,
        pinned_operator_key: operator,
        expected_claimed_domain: s.claimed_failure_domain,
    }
}
fn verify(
    first: &SignedHostStatement, second: &SignedHostStatement,
    op1: &ed25519_dalek::VerifyingKey,
    op2: &ed25519_dalek::VerifyingKey,
    trust: &TrustRegistry,
) -> Result<akula_wire_lab::custodian_two_host_preflight::PreflightReport, PreflightError> {
    verify_pair(challenge(), NOW, first, second, &expected(1, op1), &expected(2, op2), trust)
}
#[test]
fn two_fresh_distinct_signed_hosts_still_require_real_world_review() {
    let op1 = key(31).verifying_key();
    let op2 = key(32).verifying_key();
    let a = signed(1);
    let b = signed(2);
    let report = verify(&a, &b, &op1, &op2, &trusted()).unwrap();
    assert!(report.cryptographically_distinct_signers);
    assert_eq!(report.independence, Independence::RequiresOutOfBandVerification);
    assert!(!report.permits_automatic_store_or_suspension);
    assert_ne!(report.private_transcript_digest, [0; 32]);
    assert_eq!(report, verify(&a, &b, &op1, &op2, &trusted()).unwrap());
}
#[test]
fn tampered_service_signature_and_operator_signature_fail_closed() {
    let a = signed(1);
    let b = signed(2);
    let op1 = key(31).verifying_key();
    let op2 = key(32).verifying_key();
    let mut altered = a;
    altered.service_signature[0] ^= 1;
    assert_eq!(verify(&altered, &b, &op1, &op2, &trusted()),
        Err(PreflightError::InvalidServiceSignature));
    altered = a;
    altered.operator_signature[0] ^= 1;
    assert_eq!(verify(&altered, &b, &op1, &op2, &trusted()),
        Err(PreflightError::InvalidOperatorSignature));
    altered = a;
    altered.statement.claimed_failure_domain[0] ^= 1;
    assert_eq!(verify(&altered, &b, &op1, &op2, &trusted()),
        Err(PreflightError::WrongDomainClaim));
}
#[test]
fn wrong_pinned_endpoint_and_wrong_operator_pin_are_rejected() {
    let op1 = key(31).verifying_key();
    let op2 = key(32).verifying_key();
    let bad_op = key(34).verifying_key();
    let a = signed(1);
    let b = signed(2);
    assert_eq!(verify(&a, &b, &op1, &bad_op, &trusted()),
        Err(PreflightError::InvalidOperatorSignature));
    let mut wrong = expected(1, &op1);
    wrong.tls_endpoint = endpoint(99);
    assert_eq!(verify_pair(challenge(), NOW, &a, &b, &wrong,
        &expected(2, &op2), &trusted()), Err(PreflightError::WrongTlsEndpoint));
}
#[test]
fn prior_run_replay_expired_challenge_and_future_attestation_fail() {
    let op1 = key(31).verifying_key();
    let op2 = key(32).verifying_key();
    let a = signed(1);
    let b = signed(2);
    let another = RunChallenge {
        nonce: [92; 32], ..challenge()
    };
    assert_eq!(verify_pair(another, NOW, &a, &b,
        &expected(1, &op1), &expected(2, &op2), &trusted()),
        Err(PreflightError::WrongChallenge));
    assert_eq!(verify_pair(challenge(), 10_001, &a, &b,
        &expected(1, &op1), &expected(2, &op2), &trusted()),
        Err(PreflightError::StaleOrFutureStatement));
    assert_eq!(verify_pair(challenge(), 8_000, &a, &b,
        &expected(1, &op1), &expected(2, &op2), &trusted()),
        Err(PreflightError::StaleOrFutureStatement));
    let mut future = statement(1);
    future.attested_at_ms = NOW + 1;
    let future_signed = sign_for_lab(future, &key(11), &key(31)).unwrap();
    assert_eq!(verify(&future_signed, &b, &op1, &op2, &trusted()),
        Err(PreflightError::StaleOrFutureStatement));
}
#[test]
fn reused_operator_key_even_under_different_names_is_detected() {
    let op1 = key(31).verifying_key();
    let b_op1 = sign_for_lab(statement(2), &key(12), &key(31)).unwrap();
    assert_eq!(verify(&signed(1), &b_op1, &op1, &op1, &trusted()),
        Err(PreflightError::DuplicateOperatorIdentity));
}
#[test]
fn shared_service_key_even_with_different_service_ids_is_rejected() {
    let op1 = key(31).verifying_key();
    let op2 = key(32).verifying_key();
    let mut trust = trusted();
    // A distinct local trust registry still accepts enrollment under another
    // service ID with the first service's Ed25519 key; this MUST not certify two.
    trust.enroll(id(12), 3, key(11).verifying_key()).unwrap();
    let mut s = statement(2);
    s.service_epoch = 3;
    let signed_b = sign_for_lab(s, &key(11), &key(32)).unwrap();
    let mut expected_b = expected(2, &op2);
    expected_b.service_epoch = 3;
    assert_eq!(verify_pair(challenge(), NOW, &signed(1), &signed_b,
        &expected(1, &op1), &expected_b, &trust),
        Err(PreflightError::DuplicateServiceIdentity));
}
#[test]
fn same_tls_key_or_same_claimed_domain_are_not_two_sites() {
    let op1 = key(31).verifying_key();
    let op2 = key(32).verifying_key();
    let mut duplicate = statement(2);
    duplicate.claimed_tls_endpoint = statement(1).claimed_tls_endpoint;
    let signed_b = sign_for_lab(duplicate, &key(12), &key(32)).unwrap();
    let mut expected_b = expected(2, &op2);
    expected_b.tls_endpoint = duplicate.claimed_tls_endpoint;
    assert_eq!(verify_pair(challenge(), NOW, &signed(1), &signed_b,
        &expected(1, &op1), &expected_b, &trusted()),
        Err(PreflightError::DuplicateTlsIdentity));

    duplicate = statement(2);
    duplicate.claimed_failure_domain = statement(1).claimed_failure_domain;
    let signed_b = sign_for_lab(duplicate, &key(12), &key(32)).unwrap();
    expected_b = expected(2, &op2);
    expected_b.expected_claimed_domain = duplicate.claimed_failure_domain;
    assert_eq!(verify_pair(challenge(), NOW, &signed(1), &signed_b,
        &expected(1, &op1), &expected_b, &trusted()),
        Err(PreflightError::SameClaimedFailureDomain));
}
#[test]
fn revoked_service_and_wrong_epoch_fail_instead_of_demoting() {
    let op1 = key(31).verifying_key();
    let op2 = key(32).verifying_key();
    let a = signed(1);
    let b = signed(2);
    let mut trust = trusted();
    trust.revoke(id(11)).unwrap();
    assert_eq!(verify(&a, &b, &op1, &op2, &trust),
        Err(PreflightError::UntrustedOrRevokedService));
    let mut trust = trusted();
    trust.enroll(id(11), 2, key(11).verifying_key()).unwrap();
    assert_eq!(verify(&a, &b, &op1, &op2, &trust),
        Err(PreflightError::UntrustedOrRevokedService));
}
#[test]
fn service_and_operator_must_not_share_keys_within_or_across_hosts() {
    let a = statement(1);
    assert_eq!(sign_for_lab(a, &key(11), &key(11)),
        Err(PreflightError::ReusedKeyAcrossRoles));
    let s1 = signed(1);
    let mut second = statement(2);
    second.operator_id = id(32);
    let s2 = sign_for_lab(second, &key(12), &key(11)).unwrap();
    let op1 = key(31).verifying_key();
    let cross_role = key(11).verifying_key();
    assert_eq!(verify_pair(challenge(), NOW, &s1, &s2,
        &expected(1, &op1), &expected(2, &cross_role), &trusted()),
        Err(PreflightError::ReusedKeyAcrossRoles));
    // A separately pinned signing key is required even if a claimed
    // independent operator uses a brand-new label.
}

#[test]
fn verifier_generates_fresh_nonzero_challenges_from_system_csprng() {
    let a = RunChallenge::generate(1_000, 10_000).unwrap();
    let b = RunChallenge::generate(1_000, 10_000).unwrap();
    assert_ne!(a.nonce, [0; 32]);
    assert_ne!(a.nonce, b.nonce);
    assert_eq!(a.validate(5_000), Ok(()));
    assert_eq!(RunChallenge::generate(1_000, 1_000 + 700_000),
        Err(PreflightError::InvalidChallenge));
}

#[test]
fn invalid_nonce_expiry_zero_identity_and_long_window_are_rejected() {
    let mut run = challenge();
    run.nonce = [0; 32];
    assert_eq!(run.validate(NOW), Err(PreflightError::InvalidChallenge));
    run = challenge();
    run.deadline_ms = run.issued_at_ms + 700_000;
    assert_eq!(run.validate(NOW), Err(PreflightError::InvalidChallenge));

    let mut s = statement(1);
    s.operator_id = [0; 16];
    assert_eq!(sign_for_lab(s, &key(11), &key(31)),
        Err(PreflightError::InvalidStatement));
    s = statement(1);
    s.expires_at_ms = s.attested_at_ms;
    assert_eq!(sign_for_lab(s, &key(11), &key(31)),
        Err(PreflightError::InvalidStatement));
}
