//! Laboratory, bounded mutual Ed25519 proof of key possession for one W5
//! relay-grant submission. This is NOT TLS, Noise, secure session key exchange,
//! confidentiality, channel binding, or resistance to a live relay attacker.
//! It must remain loopback-only until a vetted authenticated transport exists.
//!
//! A relay signs a fresh OS-CSPRNG nonce bound to its pinned identity, the
//! locally authorized peer identity/epoch, route scope, and exact signed grant.
//! The client verifies the relay signature before signing a response over the
//! full signed challenge. The relay checks the pinned peer's current W3 key
//! epoch/revocation before forwarding bytes to W5 storage.
//!
//! No network-supplied device ID, epoch, route policy or clock may become trust.
use crate::route_grant_w5::{RelayPolicy, SIGNED_GRANT_LEN};
use crate::trust_w3::TrustRegistry;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};

const CHALLENGE_DOMAIN: &[u8] = b"Akula/WOW/W5/peer-challenge/lab-v1\0";
const RESPONSE_DOMAIN: &[u8] = b"Akula/WOW/W5/peer-response/lab-v1\0";
const VERSION: u8 = 1;
const CHALLENGE_BODY_LEN: usize = 1 + 16 + 8 + 16 + 8 + 16 + 16 + 32 + 32;
pub const SIGNED_CHALLENGE_LEN: usize = CHALLENGE_BODY_LEN + 64;
const RESPONSE_BODY_LEN: usize = 1 + 16 + 8;
pub const SIGNED_RESPONSE_LEN: usize = RESPONSE_BODY_LEN + 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerProofError {
    EntropyUnavailable,
    InvalidLength,
    UnsupportedVersion,
    UntrustedRelay,
    UntrustedPeer,
    WrongRelay,
    WrongPeer,
    WrongScope,
    WrongGrant,
    InvalidSignature,
}

/// A privileged, independent allowlist decision: this exact device and key
/// epoch may submit a signed capability to THIS pinned relay/namespace/route.
/// The TCP client's claimed ID must NEVER construct this structure.
#[derive(Clone, Copy, Debug)]
pub struct PeerRouteScope {
    pub device_id: [u8; 16],
    pub device_epoch: u64,
    pub relay_epoch: u64,
}

fn signed_material(domain: &[u8], body: &[u8]) -> Vec<u8> {
    let mut material = Vec::with_capacity(domain.len() + body.len());
    material.extend_from_slice(domain);
    material.extend_from_slice(body);
    material
}

fn value16(bytes: &[u8], from: usize) -> [u8;16] {
    bytes[from..from+16].try_into().expect("fixed input size already checked")
}
fn value64(bytes: &[u8], from: usize) -> u64 {
    u64::from_be_bytes(
        bytes[from..from+8].try_into().expect("fixed input size already checked")
    )
}

/// Relay-side proof of its own pinned key. Grant bytes are covered by BLAKE3
/// to avoid signing/forwarding altered route capabilities. Call only AFTER
/// reserving a bounded pre-auth ticket; the nonce comes from OS entropy.
pub fn sign_fresh_relay_challenge(
    local_signer: &SigningKey,
    trust: &TrustRegistry,
    policy: &RelayPolicy,
    allowed_peer: PeerRouteScope,
    signed_grant: &[u8],
) -> Result<Vec<u8>, PeerProofError> {
    if signed_grant.len() != SIGNED_GRANT_LEN {
        return Err(PeerProofError::InvalidLength);
    }
    trust.verify(
        policy.relay_id, allowed_peer.relay_epoch,
        &local_signer.verifying_key()
    ).map_err(|_| PeerProofError::UntrustedRelay)?;
    // Do not issue signed challenges for a revoked/unknown peer or epoch.
    trust.key_for(allowed_peer.device_id, allowed_peer.device_epoch)
        .map_err(|_| PeerProofError::UntrustedPeer)?;

    let mut nonce = [0u8; 32];
    getrandom::fill(&mut nonce)
        .map_err(|_| PeerProofError::EntropyUnavailable)?;

    let mut msg = Vec::with_capacity(SIGNED_CHALLENGE_LEN);
    msg.push(VERSION);
    msg.extend_from_slice(&policy.relay_id);
    msg.extend_from_slice(&allowed_peer.relay_epoch.to_be_bytes());
    msg.extend_from_slice(&allowed_peer.device_id);
    msg.extend_from_slice(&allowed_peer.device_epoch.to_be_bytes());
    msg.extend_from_slice(&policy.namespace);
    msg.extend_from_slice(&policy.route_token);
    msg.extend_from_slice(blake3::hash(signed_grant).as_bytes());
    msg.extend_from_slice(&nonce);
    debug_assert_eq!(msg.len(), CHALLENGE_BODY_LEN);
    let signed = local_signer.sign(&signed_material(CHALLENGE_DOMAIN, &msg));
    msg.extend_from_slice(&signed.to_bytes());
    Ok(msg)
}

/// Client-side lab helper. It validates the relay against a separately
/// provisioned registry BEFORE signing. The response cannot be reused with a
/// fresh nonce or another route, grant, peer, or relay ID.
pub fn verify_relay_and_answer(
    challenge: &[u8],
    signed_grant: &[u8],
    policy: &RelayPolicy,
    scope: PeerRouteScope,
    trusted_relay: &TrustRegistry,
    local_peer_signer: &SigningKey,
) -> Result<Vec<u8>, PeerProofError> {
    if challenge.len() != SIGNED_CHALLENGE_LEN
        || signed_grant.len() != SIGNED_GRANT_LEN
    {
        return Err(PeerProofError::InvalidLength);
    }
    if challenge[0] != VERSION {
        return Err(PeerProofError::UnsupportedVersion);
    }
    if value16(challenge, 1) != policy.relay_id
        || value64(challenge, 17) != scope.relay_epoch
    {
        return Err(PeerProofError::WrongRelay);
    }
    if value16(challenge, 25) != scope.device_id
        || value64(challenge, 41) != scope.device_epoch
    {
        return Err(PeerProofError::WrongPeer);
    }
    if value16(challenge, 49) != policy.namespace
        || value16(challenge, 65) != policy.route_token
    {
        return Err(PeerProofError::WrongScope);
    }
    if challenge[81..113] != blake3::hash(signed_grant).as_bytes()[..] {
        return Err(PeerProofError::WrongGrant);
    }

    let key = trusted_relay.key_for(policy.relay_id, scope.relay_epoch)
        .map_err(|_| PeerProofError::UntrustedRelay)?;
    let signature = Signature::from_slice(&challenge[CHALLENGE_BODY_LEN..])
        .map_err(|_| PeerProofError::InvalidSignature)?;
    key.verify(
        &signed_material(CHALLENGE_DOMAIN, &challenge[..CHALLENGE_BODY_LEN]),
        &signature,
    ).map_err(|_| PeerProofError::InvalidSignature)?;

    let mut response = Vec::with_capacity(SIGNED_RESPONSE_LEN);
    response.push(VERSION);
    response.extend_from_slice(&scope.device_id);
    response.extend_from_slice(&scope.device_epoch.to_be_bytes());
    let mut transcript = signed_material(RESPONSE_DOMAIN, challenge);
    transcript.extend_from_slice(&response);
    response.extend_from_slice(&local_peer_signer.sign(&transcript).to_bytes());
    Ok(response)
}

/// Relay-side validation of proof of the configured peer's private signing
/// key. The response signature covers the entire *fresh signed* challenge.
/// It does NOT prove absence of an active network proxy/MITM relay.
pub fn verify_peer_answer(
    challenge: &[u8],
    response: &[u8],
    allowed_peer: PeerRouteScope,
    trust: &TrustRegistry,
) -> Result<(), PeerProofError> {
    if challenge.len() != SIGNED_CHALLENGE_LEN
        || response.len() != SIGNED_RESPONSE_LEN
    {
        return Err(PeerProofError::InvalidLength);
    }
    if response[0] != VERSION {
        return Err(PeerProofError::UnsupportedVersion);
    }
    if value16(response, 1) != allowed_peer.device_id
        || value64(response, 17) != allowed_peer.device_epoch
    {
        return Err(PeerProofError::WrongPeer);
    }
    let key = trust.key_for(allowed_peer.device_id, allowed_peer.device_epoch)
        .map_err(|_| PeerProofError::UntrustedPeer)?;
    let signature = Signature::from_slice(&response[RESPONSE_BODY_LEN..])
        .map_err(|_| PeerProofError::InvalidSignature)?;
    let mut transcript = signed_material(RESPONSE_DOMAIN, challenge);
    transcript.extend_from_slice(&response[..RESPONSE_BODY_LEN]);
    key.verify(&transcript, &signature)
        .map_err(|_| PeerProofError::InvalidSignature)?;
    Ok(())
}
