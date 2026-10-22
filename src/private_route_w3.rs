//! W3 private-route v3 adapter for the pinned Blue implementation.
//! This is an EXPERIMENTAL cryptographic boundary, not public Akula service.
//!
//! The opaque token is supplied by an authenticated recipient invitation;
//! it is visible to anyone forwarding W3 and is NOT a storage capability.
//! Verifying W3 is not permission to write Vault/Sync Core. The recipient
//! must check current trust/permissions at its durable W4 commit.
//! NEVER silently downgrade private-route v3 to public-identity v2.
use crate::crypto_identity_w3::{SignedHeader, TrustedRecipient};
use crate::crypto_w3::{CryptoError, RecipientPublic};
use crate::trust_w3::TrustRegistry;
use akula_blue_w3::{
    private_route_v3::{self, RouteHint}, OpenContext, TrustedSenderKeys, VerifiedW3, W3Error,
};
use ed25519_dalek::{SigningKey, VerifyingKey};

pub const VERSION: u8 = private_route_v3::VERSION;
pub const PUBLIC_HEADER_BYTES: usize = private_route_v3::PUBLIC_HEADER_BYTES;

struct TrustView<'a>(&'a TrustRegistry);
impl TrustedSenderKeys for TrustView<'_> {
    fn key_for(&self, device: [u8; 16], epoch: u64) -> Option<VerifyingKey> {
        self.0.key_for(device, epoch).ok().copied()
    }
}

fn map_error(error: W3Error) -> CryptoError {
    match error {
        W3Error::Oversized => CryptoError::Oversized,
        W3Error::InvalidPacket | W3Error::InvalidDescriptor => CryptoError::InvalidPacket,
        W3Error::UnsupportedVersion => CryptoError::UnknownSuite,
        W3Error::WrongRecipient => CryptoError::InvalidRecipient,
        W3Error::Expired => CryptoError::Expired,
        W3Error::UntrustedSender => CryptoError::UnauthorizedSender,
        W3Error::DecryptFailed => CryptoError::DecryptFailed,
        W3Error::InvalidSignature => CryptoError::InvalidSignature,
    }
}

/// The public header is deliberately *unauthenticated* until HPKE is opened.
/// A route hint is not authority to accept/store or to fetch a mailbox.
pub fn inspect_route(packet: &[u8]) -> Result<RouteHint, CryptoError> {
    private_route_v3::inspect_route(packet).map_err(map_error)
}

pub fn seal_private(
    signing: &SigningKey,
    recipient: &RecipientPublic,
    route_token: [u8; 16],
    header: SignedHeader,
    payload: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    private_route_v3::seal_private_v3(signing, recipient, route_token, header.into(), payload)
        .map_err(map_error)
}

/// No TOFU: recipient independently provisioned the sender verification key,
/// epoch, HPKE secret and expected route token. Neither remote endpoint ID
/// nor a packet-supplied value is treated as identity or authorization.
pub fn open_authenticated<'wire>(
    packet: &'wire [u8],
    recipient: TrustedRecipient<'_>,
    expected_route_token: [u8; 16],
) -> Result<VerifiedW3<'wire>, CryptoError> {
    let keys = TrustView(recipient.registry);
    private_route_v3::open_private_v3(
        packet,
        OpenContext {
            secret: recipient.secret,
            recipient_id: recipient.recipient_id,
            now_ms: recipient.now,
            trusted_sender_keys: &keys,
        },
        expected_route_token,
    )
    .map_err(map_error)
}
