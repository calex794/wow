//! W5 pre-auth transport admission, staged in front of the W4/W5 bridge.
//!
//! This is a loopback-only experiment, not a public server or a peer identity
//! protocol. It uses the existing W2 length prefix twice: first a hop-local,
//! fixed-size signed relay grant, then the unchanged E2E opaque ciphertext.
//! Do not confuse the first frame with the end-to-end W3 packet.
//!
//! The PRE-AUTH guard from PR #20 charges connections independent of remote
//! DeviceId. It caps active LAN tickets at eight and bounded grant bytes;
//! the following E2E packet is separately capped at MAX_MESSAGE_BYTES.
//! Signed grants are verified before any Mailbox::put, but a valid grant is
//! bearer authority and does NOT authenticate the TCP peer. A real multi-host
//! adapter must separately authenticate a session, constrain kernel sockets,
//! persist issuer policy and enforce route ACL + independent operator limits.
use crate::ingress_bridge_w5::{self, BridgeError, IngressOutcome};
use crate::ingress_guard_w5::{AdmissionError, IngressGuard, Lane, Ticket};
use crate::mailbox_w5::Mailbox;
use crate::peer_proof_w5::{self, PeerProofError, PeerRouteScope, SIGNED_RESPONSE_LEN};
use crate::route_grant_w5::{RelayPolicy, SIGNED_GRANT_LEN};
use crate::trust_w3::TrustRegistry;
use crate::{WireError, MAX_MESSAGE_BYTES};
use ed25519_dalek::SigningKey;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Debug)]
pub enum GuardedTcpError {
    Admission(AdmissionError),
    Bridge(BridgeError),
    Io(io::Error),
    Wire(WireError),
    LockPoisoned,
    StorageLockPoisoned,
    PeerProof(PeerProofError),
    NotLoopback,
    InvalidDeadline,
    DeadlineExceeded,
    InvalidGrantFrameLength,
}

impl From<AdmissionError> for GuardedTcpError {
    fn from(value: AdmissionError) -> Self { Self::Admission(value) }
}
impl From<BridgeError> for GuardedTcpError {
    fn from(value: BridgeError) -> Self { Self::Bridge(value) }
}
impl From<PeerProofError> for GuardedTcpError {
    fn from(value: PeerProofError) -> Self { Self::PeerProof(value) }
}
impl From<io::Error> for GuardedTcpError {
    fn from(value: io::Error) -> Self { Self::Io(value) }
}

/// All fields MUST come from a trusted local server clock/configuration,
/// never untrusted TCP headers or the sender's claimed DeviceId.
#[derive(Clone, Copy)]
pub struct GuardedTcpClock {
    /// Monotonic counter for shared IngressGuard; equal ticks do not refill
    /// attempt/byte quotas, a backwards tick is refused.
    pub monotonic_tick: u64,
    /// Trusted wall-clock epoch seconds for expiry validation.
    pub now_seconds: i64,
    /// Total time to read BOTH W2 frames, not a timeout reset per fragment.
    pub read_budget: Duration,
}

struct TicketLease<'a> {
    shared: &'a Mutex<IngressGuard>,
    ticket: Ticket,
}
impl Drop for TicketLease<'_> {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.shared.lock() {
            let _ = guard.cancel(self.ticket);
        }
    }
}

fn lock<'a>(
    shared: &'a Mutex<IngressGuard>,
) -> Result<std::sync::MutexGuard<'a, IngressGuard>, GuardedTcpError> {
    shared.lock().map_err(|_| GuardedTcpError::LockPoisoned)
}

/// Exact-total monotonic deadline, not a per-byte idle timeout. No attacker
/// can keep a slot indefinitely merely by dribbling a byte before each read.
fn read_exact_before(
    socket: &mut TcpStream,
    mut remaining: &mut [u8],
    deadline: Instant,
) -> Result<(), GuardedTcpError> {
    while !remaining.is_empty() {
        let time_left = deadline.saturating_duration_since(Instant::now());
        if time_left.is_zero() { return Err(GuardedTcpError::DeadlineExceeded); }
        socket.set_read_timeout(Some(time_left))?;
        match socket.read(remaining) {
            Ok(0) => return Err(GuardedTcpError::Io(
                io::Error::from(io::ErrorKind::UnexpectedEof)
            )),
            Ok(n) => {
                let (_, rest) = remaining.split_at_mut(n);
                remaining = rest;
            }
            Err(e) if matches!(e.kind(), io::ErrorKind::Interrupted) => continue,
            Err(e) if matches!(
                e.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
            ) => return Err(GuardedTcpError::DeadlineExceeded),
            Err(e) => return Err(GuardedTcpError::Io(e)),
        }
    }
    if Instant::now() >= deadline {
        return Err(GuardedTcpError::DeadlineExceeded);
    }
    Ok(())
}

/// Writes one short signed challenge against the SAME absolute deadline
/// used to read the grant, client proof and E2E packet.
fn write_before(
    socket: &mut TcpStream,
    mut remaining: &[u8],
    deadline: Instant,
) -> Result<(), GuardedTcpError> {
    while !remaining.is_empty() {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() { return Err(GuardedTcpError::DeadlineExceeded); }
        socket.set_write_timeout(Some(left))?;
        match socket.write(remaining) {
            Ok(0) => return Err(GuardedTcpError::Io(
                io::Error::from(io::ErrorKind::WriteZero)
            )),
            Ok(n) => remaining = &remaining[n..],
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) if matches!(
                e.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
            ) => return Err(GuardedTcpError::DeadlineExceeded),
            Err(e) => return Err(GuardedTcpError::Io(e)),
        }
    }
    if Instant::now() >= deadline {
        return Err(GuardedTcpError::DeadlineExceeded);
    }
    Ok(())
}

fn read_frame_before(
    socket: &mut TcpStream,
    deadline: Instant,
    max_len: usize,
    exact_len: Option<usize>,
) -> Result<Vec<u8>, GuardedTcpError> {
    let mut prefix = [0u8; 4];
    read_exact_before(socket, &mut prefix, deadline)?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length == 0 { return Err(GuardedTcpError::Wire(WireError::InvalidEncoding)); }
    if length > max_len { return Err(GuardedTcpError::Wire(WireError::TooLarge)); }
    if exact_len.is_some_and(|required| required != length) {
        return Err(GuardedTcpError::InvalidGrantFrameLength);
    }
    let mut bytes = vec![0u8; length];
    read_exact_before(socket, &mut bytes, deadline)?;
    Ok(bytes)
}

/// Accept exactly one signed relay grant and one E2E ciphertext over a real
/// LOCAL LOOPBACK TCP socket. A slot is reserved before reading even 4 bytes.
/// No signed recipient ACK is EVER written by this function.
///
/// IngressGuard is shared via e.g. Arc<Mutex<IngressGuard>> across handlers.
/// Lane is fixed to LocalNetwork by the adapter; the remote side cannot
/// self-select a more permissive budget or reset quotas with fake DeviceIds.
/// Dropping the TicketLease releases capacity on success and ALL error paths.
/// The lock is never held across socket I/O, cryptography or SQLite writes.
///
/// This endpoint is intentionally restricted to loopback until genuine peer
/// session auth is implemented. Caller must ensure unprivileged local
/// processes cannot access trusted relay grants.
pub fn serve_guarded_loopback_mailbox_tcp(
    socket: TcpStream,
    admission: &Mutex<IngressGuard>,
    clock: GuardedTcpClock,
    store: &mut Mailbox,
    policy: &RelayPolicy,
    issuer_trust: &TrustRegistry,
) -> Result<IngressOutcome, GuardedTcpError> {
    serve_bounded_one(socket, admission, clock, |_, _, _, _, _| Ok(()), |grant, ciphertext| {
        let stored = ingress_bridge_w5::store_authorized_mailbox_packet(
            store, grant, policy, issuer_trust, clock.now_seconds, ciphertext,
        )?;
        Ok(IngressOutcome::MailboxStored(stored))
    })
}

/// Concurrent variant: many connections may be reading their bounded inputs
/// simultaneously, but the SQLite handle is locked only AFTER pre-auth
/// admission, framed reads and ticket lifetime validation. This does NOT
/// bound OS accept queues or provide authenticated network sessions.
///
/// Callers MUST share ONE Arc<Mutex<IngressGuard>> for the entire service,
/// and must keep a consistent, independently trusted RelayPolicy and registry.
pub fn serve_guarded_loopback_mailbox_tcp_shared(
    socket: TcpStream,
    admission: &Mutex<IngressGuard>,
    clock: GuardedTcpClock,
    store: &Mutex<Mailbox>,
    policy: &RelayPolicy,
    issuer_trust: &TrustRegistry,
) -> Result<IngressOutcome, GuardedTcpError> {
    serve_bounded_one(socket, admission, clock, |_, _, _, _, _| Ok(()), |grant, ciphertext| {
        let mut db = store.lock().map_err(|_| GuardedTcpError::StorageLockPoisoned)?;
        let stored = ingress_bridge_w5::store_authorized_mailbox_packet(
            &mut db, grant, policy, issuer_trust, clock.now_seconds, ciphertext,
        )?;
        Ok(IngressOutcome::MailboxStored(stored))
    })
}

/// Extra lab-only endpoint: the relay proves its currently trusted key and
/// the caller answers a NEW unpredictable challenge using a pinned enrolled
/// peer key, BEFORE the relay accepts the 16-KiB W3 packet. Both signatures
/// are bound to this route and the byte-exact signed grant. A valid grant
/// alone cannot authorize an unknown/revoked peer.
///
/// IMPORTANT: challenge-response over unauthenticated TCP is susceptible to
/// live relaying. There is NO encrypted/channel-bound session, forward secrecy,
/// protected peer IP identity, certificate provisioning or production ACL.
/// This endpoint remains 127.0.0.1-only pending vetted mTLS/Noise/iroh use.
pub fn serve_mutual_peer_proof_loopback_mailbox_tcp_shared(
    socket: TcpStream,
    admission: &Mutex<IngressGuard>,
    clock: GuardedTcpClock,
    store: &Mutex<Mailbox>,
    policy: &RelayPolicy,
    issuer_trust: &TrustRegistry,
    device_trust: &TrustRegistry,
    relay_signer: &SigningKey,
    permitted_peer: PeerRouteScope,
) -> Result<IngressOutcome, GuardedTcpError> {
    serve_bounded_one(
        socket, admission, clock,
        |socket, deadline, signed_grant, shared, ticket| {
            let challenge = peer_proof_w5::sign_fresh_relay_challenge(
                relay_signer, device_trust, policy, permitted_peer, signed_grant,
            )?;
            // One framed relay-authenticated challenge; no recipient ACK.
            let challenge_frame = crate::stream_frame(&challenge)
                .map_err(GuardedTcpError::Wire)?;
            write_before(socket, &challenge_frame, deadline)?;

            // Only an exact small signed response is accepted as pre-auth
            // input; its bytes are charged under the SAME active ticket.
            let response = read_frame_before(
                socket, deadline, SIGNED_RESPONSE_LEN, Some(SIGNED_RESPONSE_LEN),
            )?;
            lock(shared)?.offer_fragment(ticket, &response)?;
            peer_proof_w5::verify_peer_answer(
                &challenge, &response, permitted_peer, device_trust,
            )?;
            Ok(())
        },
        |signed_grant, ciphertext| {
            // Re-evaluate the peer epoch/revocation at the storage boundary.
            device_trust.key_for(
                permitted_peer.device_id, permitted_peer.device_epoch,
            ).map_err(|_| PeerProofError::UntrustedPeer)?;
            let mut db = store.lock().map_err(
                |_| GuardedTcpError::StorageLockPoisoned
            )?;
            let stored = ingress_bridge_w5::store_authorized_mailbox_packet(
                &mut db, signed_grant, policy, issuer_trust,
                clock.now_seconds, ciphertext,
            )?;
            Ok(IngressOutcome::MailboxStored(stored))
        },
    )
}

/// Shared admission + bounded network-read path. The storage callback is
/// called at most once, only after all admission checks succeed. Never hold
/// the shared ingress guard lock over blocking network I/O or SQLite.
/// An optional lab mutual-key proof runs after the bounded grant frame and
/// before body allocation, but never elevates a peer without signed grant.
fn serve_bounded_one<F, A>(
    mut socket: TcpStream,
    admission: &Mutex<IngressGuard>,
    clock: GuardedTcpClock,
    authenticate: A,
    store_packet: F,
) -> Result<IngressOutcome, GuardedTcpError>
where
    A: FnOnce(
        &mut TcpStream, Instant, &[u8], &Mutex<IngressGuard>, Ticket
    ) -> Result<(), GuardedTcpError>,
    F: FnOnce(&[u8], &[u8]) -> Result<IngressOutcome, GuardedTcpError>,
{
    if !socket.peer_addr()?.ip().is_loopback()
        || !socket.local_addr()?.ip().is_loopback()
    {
        return Err(GuardedTcpError::NotLoopback);
    }
    if clock.read_budget.is_zero() || clock.read_budget > Duration::from_secs(5) {
        return Err(GuardedTcpError::InvalidDeadline);
    }
    let deadline = Instant::now()
        .checked_add(clock.read_budget)
        .ok_or(GuardedTcpError::InvalidDeadline)?;

    let ticket = {
        let mut guard = lock(admission)?;
        guard.advance_tick(clock.monotonic_tick)?;
        // No claimed identity is used as a quota key. This is a LAN socket.
        guard.begin(Lane::LocalNetwork, [0u8; 16])?
    };
    let _lease = TicketLease { shared: admission, ticket };

    // Hop-local capability frame: EXACTLY fixed signed size, before any
    // 16-KiB body allocation. Offer actual untrusted bytes to the shared
    // PRE-AUTH guard. It is still NOT an authenticated handshake.
    let signed_grant = read_frame_before(
        &mut socket, deadline, SIGNED_GRANT_LEN, Some(SIGNED_GRANT_LEN),
    )?;
    lock(admission)?.offer_fragment(ticket, &signed_grant)?;

    // Optional proof binds an enrolled peer's signing key to a fresh,
    // relay-signed challenge and the exact grant. No W3 bytes read before it.
    authenticate(&mut socket, deadline, &signed_grant, admission, ticket)?;
    lock(admission)?.ensure_pending(ticket)?;
    if Instant::now() >= deadline {
        return Err(GuardedTcpError::DeadlineExceeded);
    }

    // The *existing* W3 ciphertext bytes are transported unchanged.
    let ciphertext = read_frame_before(
        &mut socket, deadline, MAX_MESSAGE_BYTES, None,
    )?;
    lock(admission)?.ensure_pending(ticket)?;
    if Instant::now() >= deadline {
        return Err(GuardedTcpError::DeadlineExceeded);
    }

    // Storage is called only after all pre-auth checks. The callback must
    // still verify the signed grant against trusted issuer/scope policy.
    // A Mailbox return value is never a final-recipient acknowledgement.
    store_packet(&signed_grant, &ciphertext)
}
