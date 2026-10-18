//! W6: actual iroh 1.3 QUIC/TLS identity-gated Mailbox ingress lab.
//!
//! This module only compiles with --features iroh-transport. In contrast to
//! the W5 signed-nonce demo, iroh's completed QUIC/TLS handshake authenticates
//! the remote EndpointId. We authorize the *actual* connection.remote_id(),
//! NOT an identity string supplied in the packet.
//!
//! The EndpointId <-> W3 DeviceId/epoch mapping is pinned by the trusted
//! operator and must be independently provisioned and kept current. An iroh
//! EndpointId is NOT a W3 identity and must not be inferred from remote input.
//! A separate issuer-signed, exact-ciphertext RelayGrant still controls WHICH
//! route/message can be written. Neither layer confers a Sync Core operation.
//!
//! Only a lab server deliberately bound to loopback should call this handler.
//! It is not an accept loop, worker scheduler, deployment profile or protocol
//! freeze. No remote endpoint may choose policy, clock, ALPN or DeviceId.
use crate::guarded_tcp_w5::GuardedTcpClock;
use crate::ingress_bridge_w5::{self, BridgeError, IngressOutcome};
use crate::ingress_guard_w5::{AdmissionError, IngressGuard, Lane, Ticket};
use crate::mailbox_w5::Mailbox;
use crate::route_grant_w5::{RelayPolicy, SIGNED_GRANT_LEN};
use crate::trust_w3::TrustRegistry;
use crate::MAX_MESSAGE_BYTES;
use iroh::{Endpoint, EndpointId, endpoint::Connection};
use std::sync::Mutex;
use std::time::Duration;

pub const W6_LAB_ALPN: &[u8] = b"akula-wow/iroh-mailbox-lab/1";
pub const MAX_IROH_LAB_WIRE: usize = 4 + SIGNED_GRANT_LEN + 4 + MAX_MESSAGE_BYTES;

#[derive(Debug)]
pub enum IrohIngressError {
    WrongLocalEndpoint,
    WrongRemoteEndpoint,
    WrongAlpn,
    RevokedOrStaleDevice,
    InvalidDeadline,
    DeadlineExceeded,
    LockPoisoned,
    StorageLockPoisoned,
    InvalidFrame,
    Admission(AdmissionError),
    Bridge(BridgeError),
    Transport(String),
}
impl From<AdmissionError> for IrohIngressError {
    fn from(error: AdmissionError) -> Self { Self::Admission(error) }
}
impl From<BridgeError> for IrohIngressError {
    fn from(error: BridgeError) -> Self { Self::Bridge(error) }
}

/// Trusted owner-issued association. An iroh EndpointId is a cryptographic
/// QUIC/TLS public-key identity, distinct from the pre-existing W3 DeviceId.
/// This mapping MUST NOT be constructed from the client's packet contents.
#[derive(Clone, Debug)]
pub struct IrohAuthorizedPeer {
    pub endpoint_id: EndpointId,
    pub w3_device_id: [u8; 16],
    pub w3_epoch: u64,
}

/// Borrowed trusted server configuration; only the caller controls it.
/// Local endpoint should be bound to 127.0.0.1 in the CI laboratory.
pub struct IrohMailboxContext<'a> {
    pub local: &'a Endpoint,
    pub expected_local_id: EndpointId,
    pub peer: &'a IrohAuthorizedPeer,
    pub devices: &'a TrustRegistry,
    pub issuer_trust: &'a TrustRegistry,
    pub relay_policy: &'a RelayPolicy,
    pub guard: &'a Mutex<IngressGuard>,
    pub mailbox: &'a Mutex<Mailbox>,
    pub clock: GuardedTcpClock,
}

struct Lease<'a> {
    guard: &'a Mutex<IngressGuard>,
    ticket: Ticket,
}
impl Drop for Lease<'_> {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.guard.lock() {
            let _ = guard.cancel(self.ticket);
        }
    }
}

/// Decode EXACTLY two W2 length-prefixed frames in one completed QUIC stream.
/// No additional frame, trailing bytes, empty body or oversized allocation.
fn decode_one_lab_submission(buf: &[u8]) -> Result<(&[u8], &[u8]), IrohIngressError> {
    if buf.len() < 8 + SIGNED_GRANT_LEN || buf.len() > MAX_IROH_LAB_WIRE {
        return Err(IrohIngressError::InvalidFrame);
    }
    let grant_len = u32::from_be_bytes(
        buf[..4].try_into().map_err(|_| IrohIngressError::InvalidFrame)?,
    ) as usize;
    if grant_len != SIGNED_GRANT_LEN {
        return Err(IrohIngressError::InvalidFrame);
    }
    let after_grant = 4 + SIGNED_GRANT_LEN;
    let body_len = u32::from_be_bytes(
        buf[after_grant..after_grant+4].try_into()
            .map_err(|_| IrohIngressError::InvalidFrame)?,
    ) as usize;
    if body_len == 0 || body_len > MAX_MESSAGE_BYTES
        || buf.len() != after_grant + 4 + body_len
    {
        return Err(IrohIngressError::InvalidFrame);
    }
    Ok((
        &buf[4..after_grant],
        &buf[after_grant+4..],
    ))
}

/// Handle ONE stream of a handshake-completed iroh Connection. No early-data
/// or 0-RTT API is used. Fully authenticated QUIC/TLS remote EndpointId is
/// pinned to a separate W3 DeviceId/epoch enrollment and exact route policy.
///
/// Admission ticket starts BEFORE accepting or reading a QUIC application
/// stream (but AFTER the TLS handshake; QUIC handshake/socket limits remain
/// the deployment's responsibility). The entire receive has one absolute
/// budget; a slow stream cannot reset the deadline by sending fragments.
/// Signed-grant validation and SQLite commit happen only after all guards.
///
/// This function never sends a recipient ACK or writes a QUIC response.
/// Intermediate MailboxStored is NOT RecipientAccepted/Sync-applied.
pub async fn receive_authenticated_iroh_mailbox(
    connection: &Connection,
    context: IrohMailboxContext<'_>,
) -> Result<IngressOutcome, IrohIngressError> {
    if context.local.id() != context.expected_local_id {
        return Err(IrohIngressError::WrongLocalEndpoint);
    }
    if connection.alpn() != W6_LAB_ALPN {
        return Err(IrohIngressError::WrongAlpn);
    }
    if connection.remote_id() != context.peer.endpoint_id {
        return Err(IrohIngressError::WrongRemoteEndpoint);
    }
    // Current W3 epoch/revocation is independently enforced; this cannot
    // self-authorize an EndpointId <-> DeviceId mapping from network bytes.
    context.devices.key_for(context.peer.w3_device_id, context.peer.w3_epoch)
        .map_err(|_| IrohIngressError::RevokedOrStaleDevice)?;

    let timeout = context.clock.read_budget;
    if timeout.is_zero() || timeout > Duration::from_secs(5) {
        return Err(IrohIngressError::InvalidDeadline);
    }
    let ticket = {
        let mut guard = context.guard.lock()
            .map_err(|_| IrohIngressError::LockPoisoned)?;
        guard.advance_tick(context.clock.monotonic_tick)?;
        // Do not trust a claimed network DeviceId or use it to reset quotas.
        guard.begin(Lane::LocalNetwork, [0;16])?
    };
    let _lease = Lease { guard: context.guard, ticket };

    let end = tokio::time::Instant::now() + timeout;
    let wire = tokio::time::timeout_at(end, async {
        let (_send, mut recv) = connection.accept_bi().await
            .map_err(|err| IrohIngressError::Transport(err.to_string()))?;
        recv.read_to_end(MAX_IROH_LAB_WIRE).await
            .map_err(|err| IrohIngressError::Transport(err.to_string()))
    }).await.map_err(|_| IrohIngressError::DeadlineExceeded)??;

    let (signed_grant, ciphertext) = decode_one_lab_submission(&wire)?;
    {
        let mut guard = context.guard.lock()
            .map_err(|_| IrohIngressError::LockPoisoned)?;
        guard.offer_fragment(ticket, signed_grant)?;
        guard.ensure_pending(ticket)?;
    }
    if tokio::time::Instant::now() >= end {
        return Err(IrohIngressError::DeadlineExceeded);
    }
    // Reconfirm key is still current at the storage boundary. The registry
    // here is a snapshot; multi-process revocation needs a live trust source.
    context.devices.key_for(context.peer.w3_device_id, context.peer.w3_epoch)
        .map_err(|_| IrohIngressError::RevokedOrStaleDevice)?;
    let mut mailbox = context.mailbox.lock()
        .map_err(|_| IrohIngressError::StorageLockPoisoned)?;
    let stored = ingress_bridge_w5::store_authorized_mailbox_packet(
        &mut mailbox, signed_grant, context.relay_policy,
        context.issuer_trust, context.clock.now_seconds, ciphertext,
    )?;
    Ok(IngressOutcome::MailboxStored(stored))
}
