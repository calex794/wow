use akula_wire_lab::route_grant_w5::{
    sign_for_lab, verify_for_mailbox, GrantError, RelayGrantClaims, RelayPolicy,
    SIGNED_GRANT_LEN,
};
use akula_wire_lab::trust_w3::TrustRegistry;
use ed25519_dalek::SigningKey;

fn id(n:u8) -> [u8;16] {[n;16]}

fn fixture() -> (SigningKey,TrustRegistry,RelayPolicy,RelayGrantClaims,&'static [u8]) {
    let owner=SigningKey::from_bytes(&[10;32]);
    let mut registry=TrustRegistry::new();
    registry.enroll(id(1),3,owner.verifying_key()).unwrap();
    let policy=RelayPolicy {
        issuer_id:id(1),relay_id:id(2),namespace:id(3),route_token:id(4)
    };
    let packet=b"opaque-packet-with-no-readable-W3-header";
    let claims=RelayGrantClaims {
        issuer_id:id(1),issuer_epoch:3,relay_id:id(2),namespace:id(3),
        route_token:id(4),message_id:id(5),expires_at:800,
        ciphertext_len:u32::try_from(packet.len()).unwrap(),
        ciphertext_digest:*blake3::hash(packet).as_bytes(),
    };
    (owner,registry,policy,claims,packet)
}

#[test]
fn exact_signed_grant_is_domain_bound_and_has_fixed_length() {
    let (owner,registry,policy,claims,packet)=fixture();
    let signed=sign_for_lab(&owner,claims).unwrap();
    assert_eq!(signed.len(),SIGNED_GRANT_LEN);
    let allowed=verify_for_mailbox(&signed,&policy,&registry,100,packet).unwrap();
    assert_eq!(allowed.route_token(),policy.route_token);
    assert_eq!(allowed.message_id(),id(5));
    assert_eq!(allowed.expires_at(),800);
    assert!(matches!(
        verify_for_mailbox(&signed[..SIGNED_GRANT_LEN-1],&policy,&registry,100,packet),
        Err(GrantError::InvalidLength)
    ));
    let mut wrong_version=signed.clone();wrong_version[0]=2;
    assert!(matches!(
        verify_for_mailbox(&wrong_version,&policy,&registry,100,packet),
        Err(GrantError::UnsupportedVersion)
    ));
}

#[test]
fn route_scope_must_be_pinned_independently_of_claims() {
    let (owner,registry,policy,claims,packet)=fixture();
    let signed=sign_for_lab(&owner,claims).unwrap();
    for (altered,error) in [
        (RelayPolicy{issuer_id:id(99),..policy},GrantError::WrongIssuer),
        (RelayPolicy{relay_id:id(99),..policy},GrantError::WrongRelay),
        (RelayPolicy{namespace:id(99),..policy},GrantError::WrongNamespace),
        (RelayPolicy{route_token:id(99),..policy},GrantError::WrongRoute),
    ] {
        assert!(matches!(
            verify_for_mailbox(&signed,&altered,&registry,100,packet),
            Err(found) if found==error
        ));
    }
}

#[test]
fn rotated_or_revoked_issuer_and_forged_key_cannot_authorize_storage() {
    let (owner,mut registry,policy,claims,packet)=fixture();
    let signed=sign_for_lab(&owner,claims).unwrap();
    let impostor=SigningKey::from_bytes(&[12;32]);
    let fake=sign_for_lab(&impostor,claims).unwrap();
    assert!(matches!(
        verify_for_mailbox(&fake,&policy,&registry,100,packet),
        Err(GrantError::InvalidSignature)
    ));
    registry.enroll(id(1),4,impostor.verifying_key()).unwrap();
    assert!(matches!(
        verify_for_mailbox(&signed,&policy,&registry,100,packet),
        Err(GrantError::UntrustedIssuer)
    ));
    registry.revoke(id(1)).unwrap();
    assert!(matches!(
        verify_for_mailbox(&fake,&policy,&registry,100,packet),
        Err(GrantError::UntrustedIssuer)
    ));
}

#[test]
fn same_message_id_with_changed_ciphertext_is_not_authorized() {
    let (owner,registry,policy,claims,packet)=fixture();
    let signed=sign_for_lab(&owner,claims).unwrap();
    let mut changed=packet.to_vec();
    changed[0]^=1;
    assert!(matches!(
        verify_for_mailbox(&signed,&policy,&registry,100,&changed),
        Err(GrantError::PacketMismatch)
    ));
    assert!(matches!(
        verify_for_mailbox(&signed,&policy,&registry,800,packet),
        Err(GrantError::Expired)
    ));
    assert!(matches!(
        verify_for_mailbox(&signed,&policy,&registry,-1,packet),
        Err(GrantError::Expired)
    ));
    let invalid=RelayGrantClaims{ciphertext_len:0,..claims};
    assert!(matches!(sign_for_lab(&owner,invalid),Err(GrantError::InvalidClaims)));
}
