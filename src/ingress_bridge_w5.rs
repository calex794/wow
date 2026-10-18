//! W4/W5 lab stream bridge. Not a public TCP listener or production network
//! service: the caller must supply trusted route-owner configuration,
//! deadlines, connection limits, and a local clock. A signed relay grant
//! is verified on EACH message before mailbox storage. The TCP peer itself
//! remains unauthenticated here; the signed grant is a narrow bearer permit.
//!
//! The same bounded W2 stream frame carries opaque W3 ciphertext. A relay
//! has no recipient signing key and can NEVER emit an end-recipient receipt.
//! Only W4's authenticated and COMMITTED inbox+receipt-outbox transaction
//! can produce a signed recipient acknowledgement.
//!
//! This module does not create another wire schema, Sync Core or trust root.
use crate::crypto_identity_w3::TrustedRecipient;
use crate::journal_w4::{Delivery, Insert, Journal, JournalError};
use crate::mailbox_w5::{MailError, Mailbox, PutStatus};
use crate::receipt_w4::{self, ReceiptError};
use crate::route_grant_w5::{self, GrantError, RelayPolicy};
use crate::trust_w3::TrustRegistry;
use crate::{stream_frame, WireError, MAX_MESSAGE_BYTES};
use ed25519_dalek::SigningKey;
use std::io::{self, Read, Write};
use std::net::TcpStream;

#[derive(Debug)]
pub enum BridgeError {
    Io(io::Error),
    Wire(WireError),
    Mailbox(MailError),
    Recipient(JournalError),
    Receipt(ReceiptError),
    Grant(GrantError),
}
impl From<io::Error> for BridgeError {
    fn from(value: io::Error) -> Self { Self::Io(value) }
}
impl From<WireError> for BridgeError {
    fn from(value: WireError) -> Self { Self::Wire(value) }
}
impl From<MailError> for BridgeError {
    fn from(value: MailError) -> Self { Self::Mailbox(value) }
}
impl From<JournalError> for BridgeError {
    fn from(value: JournalError) -> Self { Self::Recipient(value) }
}
impl From<ReceiptError> for BridgeError {
    fn from(value: ReceiptError) -> Self { Self::Receipt(value) }
}
impl From<GrantError> for BridgeError {
    fn from(value: GrantError) -> Self { Self::Grant(value) }
}

pub enum IngressRoute<'a> {
    /// Intermediate encrypted-byte storage. The relay's pinned issuer,
    /// namespace, route token and identity come from trusted configuration.
    /// Grant bytes can be untrusted; verification happens after bounded read
    /// but BEFORE any call to Mailbox::put. No recipient signer is available.
    Mailbox {
        store: &'a mut Mailbox,
        signed_grant: &'a [u8],
        policy: &'a RelayPolicy,
        trust: &'a TrustRegistry,
        now: i64,
    },
    /// End-recipient acceptance. The authenticated W3 envelope identifies
    /// sender, receiver, key epoch and message; W4 performs atomic persistence.
    Recipient {
        journal: &'a mut Journal,
        context: TrustedRecipient<'a>,
        signer: &'a SigningKey,
        signer_epoch: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngressOutcome {
    /// This is a local mailbox result, NOT end-recipient delivery.
    MailboxStored(PutStatus),
    /// The signed recipient ACK was persisted and transmitted only after
    /// W4's SQLite COMMIT; this is not an applied-document acknowledgement.
    RecipientAccepted(Insert),
}

/// Read exactly ONE existing W2 size-prefixed frame with a hard size bound.
/// No unauthenticated variable-size allocations and no second frame handled
/// on the same connection. A caller must close the TCP session after this.
pub fn read_one_frame<R: Read>(reader: &mut R) -> Result<Vec<u8>, BridgeError> {
    let mut prefix = [0u8;4];
    reader.read_exact(&mut prefix)?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length == 0 { return Err(BridgeError::Wire(WireError::InvalidEncoding)); }
    if length > MAX_MESSAGE_BYTES {
        return Err(BridgeError::Wire(WireError::TooLarge));
    }
    let mut bytes = vec![0u8; length];
    reader.read_exact(&mut bytes)?;
    Ok(bytes)
}

/// One-shot ingress on a trusted, already selected endpoint. For mailbox
/// storage NO bytes are written to reply; caller may log a local result but
/// must never translate it into recipient-delivered authority.
///
/// On the recipient path, a signed ACK is only written AFTER an authenticated
/// W4 transaction commits both inbox deduplication and receipt outbox. If
/// writing the ACK fails, the committed receipt is still durable for retry.
pub fn receive_and_route<R: Read, W: Write>(
    input: &mut R,
    reply: &mut W,
    route: IngressRoute<'_>,
) -> Result<IngressOutcome, BridgeError> {
    let encrypted_packet = read_one_frame(input)?;
    match route {
        IngressRoute::Mailbox {store, signed_grant, policy, trust, now} => {
            let verified = route_grant_w5::verify_for_mailbox(
                signed_grant, policy, trust, now, &encrypted_packet,
            )?;
            let status = store.put(
                verified.route_token(),
                verified.message_id(),
                now,
                verified.expires_at(),
                &encrypted_packet,
            )?;
            Ok(IngressOutcome::MailboxStored(status))
        }
        IngressRoute::Recipient {
            journal, context, signer, signer_epoch,
        } => {
            let (insert, signed_ack) = journal.accept_authenticated_and_queue_receipt(
                &encrypted_packet,
                context,
                signer,
                signer_epoch,
            )?;
            let wire = stream_frame(&signed_ack)?;
            reply.write_all(&wire)?;
            reply.flush()?;
            Ok(IngressOutcome::RecipientAccepted(insert))
        }
    }
}

/// The TCP specialization is intentionally one request/connection. The test
/// binds ONLY 127.0.0.1. This does not perform mTLS, iroh handshake,
/// certificate-to-device binding, peer quota, rate limit or routing ACL.
pub fn serve_one_tcp(
    mut socket: TcpStream,
    route: IngressRoute<'_>,
) -> Result<IngressOutcome, BridgeError> {
    let mut response = socket.try_clone()?;
    receive_and_route(&mut socket, &mut response, route)
}

/// Sender-side gate: a framed ACK cannot advance the outbox without the
/// enrolled recipient's current signature AND exact packet digest. No relay,
/// transport ACK, mailbox storage result or unverified bytes can pass this.
pub fn receive_verified_recipient_ack<R: Read>(
    input: &mut R,
    outbox: &mut Journal,
    trust: &TrustRegistry,
) -> Result<Delivery, BridgeError> {
    let raw_receipt = read_one_frame(input)?;
    let validated = receipt_w4::verify(&raw_receipt, trust)?;
    Ok(outbox.apply_recipient_receipt(&validated)?)
}
