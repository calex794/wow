//! WOW-CUSTODIAN-05 P0-4: REAL mutual TLS/QUIC W7 audit on loopback.
//!
//! LABORATORY ONLY: the ALPN, fixed capability framing and deterministic
//! test identities here are NOT the production W6 RelayGrant/FETCH protocol.
//! The caller's separately pinned service/endpoint policy remains mandatory.
//! A custodian signature is a claim of endpoint ownership, NOT evidence of
//! independent hosts, honest disk retention, delivery or recipient W4.
//! All network errors and malformed replies remain unknown, not accusations.
use crate::custodian_audit_grant_w7::{
    verify_for_audit, AuditGrantExpectation, AuditGrantError,
    SIGNED_AUDIT_GRANT_LEN,
};
use crate::custodian_evidence_bridge::{BridgeError, LocalEvidenceContext};
use crate::custodian_observation::{AppendResult, LocalObservationStore};
use crate::custody_audit_w7::{AuditError, AuditReference};
use crate::trust_w3::TrustRegistry;
use ed25519_dalek::Signature;
use iroh::{Endpoint, EndpointAddr, EndpointId};
use std::time::Duration;

pub const LAB_W7_ALPN: &[u8] = b"akula-wow/w7-hostile-custodian-local-only/1";
const DOMAIN: &[u8] = b"WOW/W7/AuthenticatedLabEndpointBinding/v0\0";

/// The bytes signed by the custodian's separately pinned Ed25519 service key.
/// A remote TLS EndpointId is not automatically the custodial signing key.
pub fn endpoint_binding_message(
    service_id: [u8; 16], service_epoch: u64, endpoint_id: &EndpointId,
) -> Vec<u8> {
    let name = endpoint_id.to_string();
    let mut bytes = Vec::with_capacity(DOMAIN.len() + 16 + 8 + name.len());
    bytes.extend_from_slice(DOMAIN);
    bytes.extend_from_slice(&service_id);
    bytes.extend_from_slice(&service_epoch.to_be_bytes());
    bytes.extend_from_slice(name.as_bytes());
    bytes
}

#[derive(Clone, Debug)]
pub struct SignedEndpointBinding {
    pub service_id: [u8; 16],
    pub service_epoch: u64,
    pub endpoint_id: EndpointId,
    pub signature: [u8; 64],
}

#[derive(Debug)]
pub enum LabAuditError {
    InvalidBinding,
    UntrustedService,
    WrongEndpoint,
    TransportUnknown,
    MalformedResponse,
    Bridge(BridgeError),
    Grant(AuditGrantError),
}
impl From<BridgeError> for LabAuditError {
    fn from(value: BridgeError) -> Self { Self::Bridge(value) }
}
impl From<AuditGrantError> for LabAuditError {
    fn from(value: AuditGrantError) -> Self { Self::Grant(value) }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LabAuditOutcome {
    /// One exact-W3 observation made over this authenticated QUIC session.
    ExactBytes(AppendResult),
    /// No bytes were returned; a drop, delete, sleep, ACL denial or censor
    /// cannot be distinguished here. No penalty or negative event is saved.
    Unavailable,
    /// A peer rejected this request; no proven service failure.
    Rejected,
    /// A mismatched W3 arrived on the authenticated session; it is NOT
    /// yet independent evidence of malicious storage or client-side error.
    UnattributedMismatch,
}

pub struct LabAuditRequest<'a> {
    pub client: &'a Endpoint,
    pub address: EndpointAddr,
    /// The out-of-band local pin, not an ID copied from the remote response.
    pub expected_pinned_endpoint: EndpointId,
    pub signed_binding: &'a SignedEndpointBinding,
    /// The test-only private AUDIT capability; not a production grant.
    pub audit_cap: [u8; 16],
    pub trusted_reference: &'a AuditReference,
}

/// Transport proof only. The signed READ grant is a separate permission
/// checked by the grant-specific path; it is never inferred from TLS.
fn verify_binding_parts(
    ctx: &LocalEvidenceContext<'_>, trust: &TrustRegistry,
    signed: &SignedEndpointBinding, expected: EndpointId,
    addr: &EndpointAddr,
) -> Result<(), LabAuditError> {
    if signed.service_id == [0; 16] || signed.service_epoch == 0
        || signed.service_epoch != ctx.scope().epoch
        || signed.endpoint_id != expected || addr.id != expected
    {
        return Err(LabAuditError::InvalidBinding);
    }
    let key = trust.key_for(signed.service_id, signed.service_epoch)
        .map_err(|_| LabAuditError::UntrustedService)?;
    if key.to_bytes() != ctx.scope().service_key {
        return Err(LabAuditError::UntrustedService);
    }
    let signature = Signature::from_bytes(&signed.signature);
    key.verify_strict(
        &endpoint_binding_message(
            signed.service_id, signed.service_epoch, &signed.endpoint_id,
        ),
        &signature,
    ).map_err(|_| LabAuditError::InvalidBinding)
}

fn verify_binding(
    ctx: &LocalEvidenceContext<'_>, trust: &TrustRegistry,
    request: &LabAuditRequest<'_>,
) -> Result<(), LabAuditError> {
    if request.audit_cap == [0; 16] {
        return Err(LabAuditError::InvalidBinding);
    }
    verify_binding_parts(ctx, trust, request.signed_binding,
        request.expected_pinned_endpoint, &request.address)
}

/// A signed grant carries the AUDIT capability itself, unlike the old shared
/// 16-byte secret used by the hostile W7 laboratory test. The trusted local
/// caller pins issuer identity, exact W3 reference and both EndpointIds.
pub struct GrantedLabAuditRequest<'a> {
    pub client: &'a Endpoint,
    pub address: EndpointAddr,
    pub expected_pinned_endpoint: EndpointId,
    pub signed_binding: &'a SignedEndpointBinding,
    pub signed_grant: &'a [u8],
    pub trusted_issuer_id: [u8; 16],
    pub route_token: [u8; 16],
    pub message_id: [u8; 16],
    pub trusted_reference: &'a AuditReference,
    /// Trusted local time, never a field supplied by the QUIC peer.
    pub now_ms: u64,
}

/// The signed AUDIT grant cannot be reused as a W6 STORE grant, and a plain
/// route token or test-only AUDIT_CAP cannot authorize this operation.
pub async fn audit_and_record_granted(
    store: &mut LocalObservationStore,
    ctx: &LocalEvidenceContext<'_>,
    trust: &TrustRegistry,
    request: GrantedLabAuditRequest<'_>,
) -> Result<LabAuditOutcome, LabAuditError> {
    verify_binding_parts(
        ctx, trust, request.signed_binding,
        request.expected_pinned_endpoint, &request.address,
    )?;
    if request.signed_grant.len() != SIGNED_AUDIT_GRANT_LEN
        || request.now_ms == 0 || request.now_ms < ctx.observed_at_ms()
        || request.trusted_reference.ciphertext_len() > u32::MAX as usize
    {
        return Err(LabAuditError::InvalidBinding);
    }
    verify_for_audit(
        request.signed_grant,
        AuditGrantExpectation {
            issuer_id: request.trusted_issuer_id,
            service_id: request.signed_binding.service_id,
            service_epoch: ctx.scope().epoch,
            service_endpoint: request.expected_pinned_endpoint,
            auditor_endpoint: request.client.id(),
            route_token: request.route_token,
            message_id: request.message_id,
            ciphertext_len: request.trusted_reference.ciphertext_len() as u32,
            ciphertext_digest: request.trusted_reference.ciphertext_digest(),
        },
        trust, request.now_ms,
    )?;
    let mut payload = Vec::with_capacity(1 + SIGNED_AUDIT_GRANT_LEN);
    payload.push(5); // AUDIT_WITH_GRANT: never STORE, FETCH or W4.
    payload.extend_from_slice(request.signed_grant);
    audit_frame(
        store, ctx, request.client, request.address,
        request.expected_pinned_endpoint, request.trusted_reference,
        &payload,
    ).await
}

/// Performs its own QUIC request and verifies *the response received on that
/// very session*. Passing arbitrary, previously downloaded W3 bytes to the
/// legacy local W7 checker is NOT sufficient to establish provenance.
/// Connection errors are returned without touching the local verified index.
pub async fn audit_and_record(
    store: &mut LocalObservationStore,
    ctx: &LocalEvidenceContext<'_>,
    trust: &TrustRegistry,
    request: LabAuditRequest<'_>,
) -> Result<LabAuditOutcome, LabAuditError> {
    verify_binding(ctx, trust, &request)?;
    let mut wire = [0u8; 17];
    wire[0] = 2; // Legacy W7 lab AUDIT with private 16-byte capability.
    wire[1..].copy_from_slice(&request.audit_cap);
    audit_frame(
        store, ctx, request.client, request.address,
        request.expected_pinned_endpoint, request.trusted_reference,
        &wire,
    ).await
}

async fn audit_frame(
    store: &mut LocalObservationStore,
    ctx: &LocalEvidenceContext<'_>,
    client: &Endpoint,
    address: EndpointAddr,
    pinned_endpoint: EndpointId,
    reference: &AuditReference,
    payload: &[u8],
) -> Result<LabAuditOutcome, LabAuditError> {
    let connection = tokio::time::timeout(
        Duration::from_secs(10),
        client.connect(address, LAB_W7_ALPN),
    ).await.map_err(|_| LabAuditError::TransportUnknown)?
        .map_err(|_| LabAuditError::TransportUnknown)?;
    if connection.remote_id() != pinned_endpoint {
        connection.close(0u32.into(), b"pinned endpoint mismatch");
        return Err(LabAuditError::WrongEndpoint);
    }
    let (mut tx, mut rx) = tokio::time::timeout(
        Duration::from_secs(5), connection.open_bi(),
    ).await.map_err(|_| LabAuditError::TransportUnknown)?
        .map_err(|_| LabAuditError::TransportUnknown)?;
    tx.write_all(payload).await.map_err(|_| LabAuditError::TransportUnknown)?;
    tx.finish().map_err(|_| LabAuditError::TransportUnknown)?;
    let response = tokio::time::timeout(
        Duration::from_secs(5),
        rx.read_to_end(crate::MAX_MESSAGE_BYTES + 1),
    ).await.map_err(|_| LabAuditError::TransportUnknown)?
        .map_err(|_| LabAuditError::TransportUnknown)?;
    connection.close(0u32.into(), b"lab audit finished");

    match response.split_first() {
        Some((0, [])) => Ok(LabAuditOutcome::Unavailable),
        Some((255, [])) => Ok(LabAuditOutcome::Rejected),
        Some((2, bytes)) => {
            match reference.observe(
                Some(bytes), ctx.observed_at_ms(),
            ) {
                Ok(observed) => Ok(LabAuditOutcome::ExactBytes(
                    store.record_w7_exact(ctx, &observed)?,
                )),
                Err(AuditError::WrongLength | AuditError::WrongCiphertext) => {
                    Ok(LabAuditOutcome::UnattributedMismatch)
                }
                Err(_) => Err(LabAuditError::MalformedResponse),
            }
        }
        _ => Err(LabAuditError::MalformedResponse),
    }
}
