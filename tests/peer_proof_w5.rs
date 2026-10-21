//! W5 laboratory mutual Ed25519 key-possession proof. This verifies a
//! fresh challenge and pinned roles, but is NOT a channel-bound TLS session.
use akula_wire_lab::peer_proof_w5::{
    sign_fresh_relay_challenge, verify_peer_answer, verify_relay_and_answer,
    PeerProofError, PeerRouteScope, SIGNED_CHALLENGE_LEN, SIGNED_RESPONSE_LEN,
};
use akula_wire_lab::route_grant_w5::{
    sign_for_lab, RelayGrantClaims, RelayPolicy,
};
use akula_wire_lab::trust_w3::TrustRegistry;
use ed25519_dalek::SigningKey;

fn id(n: u8) -> [u8;16] { [n;16] }

fn fixture() -> (
    SigningKey, SigningKey, TrustRegistry, TrustRegistry,
    RelayPolicy, PeerRouteScope, Vec<u8>,
) {
    let issuer=SigningKey::from_bytes(&[11;32]);
    let relay=SigningKey::from_bytes(&[12;32]);
    let peer=SigningKey::from_bytes(&[13;32]);
    let mut issuer_trust=TrustRegistry::new();
    issuer_trust.enroll(id(1),3,issuer.verifying_key()).unwrap();
    let mut devices=TrustRegistry::new();
    devices.enroll(id(2),7,relay.verifying_key()).unwrap();
    devices.enroll(id(3),9,peer.verifying_key()).unwrap();
    let policy=RelayPolicy {
        issuer_id:id(1),relay_id:id(2),namespace:id(4),route_token:id(5),
    };
    let scope=PeerRouteScope{
        device_id:id(3),device_epoch:9,relay_epoch:7,
    };
    let packet=b"opaque encrypted ciphertext";
    let grant=sign_for_lab(&issuer,RelayGrantClaims{
        issuer_id:id(1),issuer_epoch:3,relay_id:id(2),namespace:id(4),
        route_token:id(5),message_id:id(6),expires_at:200,
        ciphertext_len:u32::try_from(packet.len()).unwrap(),
        ciphertext_digest:*blake3::hash(packet).as_bytes(),
    }).unwrap();
    (peer,relay,issuer_trust,devices,policy,scope,grant)
}

#[test]
fn pinned_mutual_keys_sign_one_fresh_grant_bound_transcript() {
    let (peer,relay,_,devices,policy,scope,grant)=fixture();
    let challenge=sign_fresh_relay_challenge(
        &relay,&devices,&policy,scope,&grant
    ).unwrap();
    assert_eq!(challenge.len(),SIGNED_CHALLENGE_LEN);
    let response=verify_relay_and_answer(
        &challenge,&grant,&policy,scope,&devices,&peer
    ).unwrap();
    assert_eq!(response.len(),SIGNED_RESPONSE_LEN);
    verify_peer_answer(&challenge,&response,scope,&devices).unwrap();
}

#[test]
fn fresh_challenges_invalidate_old_signed_responses() {
    let (peer,relay,_,devices,policy,scope,grant)=fixture();
    let first=sign_fresh_relay_challenge(
        &relay,&devices,&policy,scope,&grant
    ).unwrap();
    let second=sign_fresh_relay_challenge(
        &relay,&devices,&policy,scope,&grant
    ).unwrap();
    assert_ne!(first,second,"random nonce must yield different session transcript");
    let response=verify_relay_and_answer(
        &first,&grant,&policy,scope,&devices,&peer
    ).unwrap();
    assert!(matches!(
        verify_peer_answer(&second,&response,scope,&devices),
        Err(PeerProofError::InvalidSignature)
    ));
}

#[test]
fn client_rejects_untrusted_relay_signature_wrong_scope_and_grant() {
    let (peer,relay,_,devices,policy,scope,grant)=fixture();
    let original=sign_fresh_relay_challenge(
        &relay,&devices,&policy,scope,&grant
    ).unwrap();
    let mut forged=original.clone();
    *forged.last_mut().unwrap() ^= 1;
    assert!(matches!(
        verify_relay_and_answer(&forged,&grant,&policy,scope,&devices,&peer),
        Err(PeerProofError::InvalidSignature)
    ));
    let wrong=RelayPolicy{route_token:id(99),..policy};
    assert!(matches!(
        verify_relay_and_answer(&original,&grant,&wrong,scope,&devices,&peer),
        Err(PeerProofError::WrongScope)
    ));
    let mut swapped=grant.clone();
    swapped[99]^=1;
    assert!(matches!(
        verify_relay_and_answer(&original,&swapped,&policy,scope,&devices,&peer),
        Err(PeerProofError::WrongGrant)
    ));
}

#[test]
fn dishonest_peer_key_cannot_answer_even_with_real_bearer_grant() {
    let (_peer,relay,_,devices,policy,scope,grant)=fixture();
    let impostor=SigningKey::from_bytes(&[14;32]);
    let challenge=sign_fresh_relay_challenge(
        &relay,&devices,&policy,scope,&grant
    ).unwrap();
    let forged=verify_relay_and_answer(
        &challenge,&grant,&policy,scope,&devices,&impostor
    ).unwrap();
    assert!(matches!(
        verify_peer_answer(&challenge,&forged,scope,&devices),
        Err(PeerProofError::InvalidSignature)
    ));
    let other_scope=PeerRouteScope{device_id:id(99),..scope};
    assert!(matches!(
        verify_peer_answer(&challenge,&forged,other_scope,&devices),
        Err(PeerProofError::WrongPeer)
    ));
}

#[test]
fn revoked_or_rotated_peer_and_unknown_relay_fail_closed() {
    let (_peer,relay,_,mut devices,policy,scope,grant)=fixture();
    let impostor=SigningKey::from_bytes(&[14;32]);
    assert!(matches!(
        sign_fresh_relay_challenge(&impostor,&devices,&policy,scope,&grant),
        Err(PeerProofError::UntrustedRelay)
    ));
    devices.revoke(id(3)).unwrap();
    assert!(matches!(
        sign_fresh_relay_challenge(&relay,&devices,&policy,scope,&grant),
        Err(PeerProofError::UntrustedPeer)
    ));
    devices.enroll(id(3),10,impostor.verifying_key()).unwrap();
    assert!(matches!(
        sign_fresh_relay_challenge(&relay,&devices,&policy,scope,&grant),
        Err(PeerProofError::UntrustedPeer)
    ));
}
