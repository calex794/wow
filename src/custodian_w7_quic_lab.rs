//! WOW-CUSTODIAN-05 P0-4: REAL mutual TLS/QUIC W7 audit on loopback.
//!
//! LABORATORY ONLY: the ALPN, fixed capability framing and deterministic
//! test identities here are NOT the production W6 RelayGrant/FETCH protocol.
//! The caller's separately pinned service/endpoint policy remains mandatory.
//! A custodian signature is a claim of endpoint ownership, NOT evidence of
//! independent hosts, honest disk retention, delivery or recipient W4.
//! All network errors and malformed replies remain unknown, not accusations.
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
}
impl From<BridgeError> for LabAuditError {
    fn from(value: BridgeError) -> Self { Self::Bridge(value) }
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

fn verify_binding(
    ctx: &LocalEvidenceContext<'_>, trust: &TrustRegistry,
    request: &LabAuditRequest<'_>,
) -> Result<(), LabAuditError> {
    let signed = request.signed_binding;
    if signed.service_id == [0; 16] || signed.service_epoch == 0
        || signed.service_epoch != ctx.scope().epoch
        || signed.endpoint_id != request.expected_pinned_endpoint
        || request.address.id != request.expected_pinned_endpoint
        || request.audit_cap == [0; 16]
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
    let connection = tokio::time::timeout(
        Duration::from_secs(10),
        request.client.connect(request.address, LAB_W7_ALPN),
    ).await.map_err(|_| LabAuditError::TransportUnknown)?
        .map_err(|_| LabAuditError::TransportUnknown)?;
    if connection.remote_id() != request.expected_pinned_endpoint {
        connection.close(0u32.into(), b"pinned endpoint mismatch");
        return Err(LabAuditError::WrongEndpoint);
    }
    let (mut tx, mut rx) = tokio::time::timeout(
        Duration::from_secs(5), connection.open_bi(),
    ).await.map_err(|_| LabAuditError::TransportUnknown)?
        .map_err(|_| LabAuditError::TransportUnknown)?;
    let mut wire = [0u8; 17];
    wire[0] = 2; // AUDIT — separate from the recipient's FETCH capability.
    wire[1..].copy_from_slice(&request.audit_cap);
    tx.write_all(&wire).await.map_err(|_| LabAuditError::TransportUnknown)?;
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
            match request.trusted_reference.observe(
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
