//! WOW-CUSTODIAN-05 P0-7: bounded private-overlay W7 audit ONLY.
//!
//! Unlike the intentionally malicious W7 localhost helper, this module is
//! designed for explicitly opted-in lab hosts on private/WireGuard overlays.
//! It never accepts W5/W6 STORE grants, bare route tokens or shared AUDIT_CAP.
//! It never accesses a user's Vault, mails, keys or real W4. All response
//! decisions use a separately configured local policy and a pinned issuer.
//! Auth happens BEFORE any fixture access: a denied peer cannot probe mail
//! presence. All network/time failures are UNKNOWN, never evidence of fraud.
//!
//! It does NOT verify independent operators, physical machines or durable
//! custody. An operator can control two hosts, keys and fake witnesses.
use crate::custodian_audit_grant_w7::{
    verify_for_audit, AuditGrantExpectation, SIGNED_AUDIT_GRANT_LEN,
};
use crate::trust_w3::TrustRegistry;
use iroh::EndpointId;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{SystemTime, UNIX_EPOCH};

pub const P07_ALPN: &[u8] = b"akula-wow/w7-private-overlay-audit-lab/1";
const MAX_FRAME: usize = SIGNED_AUDIT_GRANT_LEN + 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OverlayError {
    PublicOrUnspecifiedBind,
    NonLoopbackRequiresOptIn,
    InvalidFixture,
    UntrustedSystemClock,
}

/// Reject all public/unspecified/multicast interfaces. Non-loopback hosts
/// need an explicit operator opt-in; they should bind only a VPN interface.
/// Firewall, wireguard peer authentication and independent host ownership
/// remain separate infrastructure duties.
pub fn validate_bind_address(
    socket: SocketAddr, allow_private_overlay: bool,
) -> Result<(), OverlayError> {
    let ip = socket.ip();
    if ip.is_loopback() { return Ok(()); }
    if !allow_private_overlay {
        return Err(OverlayError::NonLoopbackRequiresOptIn);
    }
    let restricted = match ip {
        IpAddr::V4(v4) => v4.is_private() || is_shared_v4(v4),
        IpAddr::V6(v6) => v6.is_unique_local(),
    };
    if restricted { Ok(()) } else { Err(OverlayError::PublicOrUnspecifiedBind) }
}
fn is_shared_v4(addr: Ipv4Addr) -> bool {
    let [a, b, _, _] = addr.octets();
    a == 100 && (64..=127).contains(&b)
}

/// Clock input must come from the verifier/host itself, never from the peer.
/// NTP skew and rollback need monitoring; this is NOT a secure time oracle.
pub fn local_wall_clock_ms() -> Result<u64, OverlayError> {
    let duration = SystemTime::now().duration_since(UNIX_EPOCH)
        .map_err(|_| OverlayError::UntrustedSystemClock)?;
    u64::try_from(duration.as_millis())
        .ok().filter(|&x| x > 0 && x <= i64::MAX as u64)
        .ok_or(OverlayError::UntrustedSystemClock)
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProbeFault {
    Honest,
    Missing,
    Corrupt,
    Reject,
    /// Delay happens ONLY after authorization; caller applies it to network.
    Delay,
}
impl std::str::FromStr for ProbeFault {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "honest" => Ok(Self::Honest),
            "missing" => Ok(Self::Missing),
            "corrupt" => Ok(Self::Corrupt),
            "reject" => Ok(Self::Reject),
            "delay" => Ok(Self::Delay),
            _ => Err("fault must be honest/missing/corrupt/reject/delay"),
        }
    }
}

pub struct HostAuditPolicy<'a> {
    pub expected: AuditGrantExpectation,
    /// Must equal the actual endpoint's TLS identity from the QUIC session.
    pub actual_service_endpoint: EndpointId,
    /// The operator-provisioned synthetic W3 reference; no public mailbox.
    pub synthetic_w3: Option<&'a [u8]>,
    pub fault: ProbeFault,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Decision {
    Denied,
    Unavailable,
    Exact,
    SyntheticCorruption,
}

/// The caller performs transport TLS authentication and must take the
/// peer_id from connection.remote_id(), not from a request or a header.
/// Only exact purpose-separated, issuer-signed P0-5 AUDIT grant is accepted.
/// For unauthorized/invalid requests the body is always [255], irrespective
/// of whether fixture exists, avoiding a W3 existence oracle.
///
/// Decision is returned only to the LOCAL test harness for telemetry; the
/// remote peer receives only a bounded byte frame.
pub fn check_and_respond(
    policy: &HostAuditPolicy<'_>, caller_tls: EndpointId,
    frame: &[u8], trust: &TrustRegistry, now_ms: u64,
) -> (Decision, Vec<u8>) {
    if frame.len() != MAX_FRAME || frame[0] != 5
        || caller_tls != policy.expected.auditor_endpoint
        || policy.actual_service_endpoint != policy.expected.service_endpoint
    {
        return (Decision::Denied, vec![255]);
    }
    // Never use claims parsed from the untrusted frame as policy inputs.
    // All expected IDs/digests/epochs come from operator-provisioned policy.
    if verify_for_audit(&frame[1..], policy.expected, trust, now_ms).is_err() {
        return (Decision::Denied, vec![255]);
    }
    if matches!(policy.fault, ProbeFault::Missing) {
        return (Decision::Unavailable, vec![0]);
    }
    if matches!(policy.fault, ProbeFault::Reject) {
        return (Decision::Denied, vec![255]);
    }
    let Some(w3) = policy.synthetic_w3 else {
        return (Decision::Unavailable, vec![0]);
    };
    if w3.is_empty() || w3.len() > crate::MAX_MESSAGE_BYTES
        || w3.len() != policy.expected.ciphertext_len as usize
        || *blake3::hash(w3).as_bytes() != policy.expected.ciphertext_digest
    {
        // Cannot return a different W3 under an otherwise valid grant.
        return (Decision::Unavailable, vec![0]);
    }
    let mut response = Vec::with_capacity(w3.len() + 1);
    response.push(2);
    response.extend_from_slice(w3);
    if matches!(policy.fault, ProbeFault::Corrupt) {
        if let Some(last) = response.last_mut() { *last ^= 1; }
        (Decision::SyntheticCorruption, response)
    } else {
        (Decision::Exact, response)
    }
}
pub fn validate_synthetic_fixture(data: &[u8]) -> Result<(), OverlayError> {
    if data.is_empty() || data.len() > crate::MAX_MESSAGE_BYTES {
        Err(OverlayError::InvalidFixture)
    } else {
        Ok(())
    }
}
