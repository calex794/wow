use akula_wire_lab::crypto_identity_w3::{seal,open,SignedHeader,TrustedRecipient};
use akula_wire_lab::crypto_w3::{new_recipient,CryptoError};
use akula_wire_lab::trust_w3::TrustRegistry;
use ed25519_dalek::SigningKey;
fn sk(v:u8)->SigningKey{SigningKey::from_bytes(&[v;32])}
fn hdr()->SignedHeader{SignedHeader{message_id:[1;16],recipient_id:[2;16],
 expiry:5000,sender_id:[3;16],epoch:7}}
#[test] fn signed_identity_and_epoch_verified() {
 let alice=sk(3);let (secret,public)=new_recipient();let h=hdr();
 let mut trust=TrustRegistry::new();trust.enroll(h.sender_id,h.epoch,alice.verifying_key()).unwrap();
 let wire=seal(&alice,&public,h,b"hello").unwrap();
 let (decoded,payload)=open(&wire,TrustedRecipient{secret:&secret,recipient_id:h.recipient_id,now:100,registry:&trust}).unwrap();
 assert_eq!(decoded.sender_id,h.sender_id);assert_eq!(decoded.epoch,7);
 assert_eq!(decoded.message_id,h.message_id);assert_eq!(payload,b"hello");
}
#[test] fn unknown_revoked_and_older_epoch_fail() {
 let alice=sk(3);let (secret,public)=new_recipient();let h=hdr();let wire=seal(&alice,&public,h,b"hi").unwrap();
 let mut trust=TrustRegistry::new();
 let receive=|t:&TrustRegistry|open(&wire,TrustedRecipient{secret:&secret,
  recipient_id:h.recipient_id,now:100,registry:t});
 assert!(matches!(receive(&trust),Err(CryptoError::UnauthorizedSender)));
 trust.enroll(h.sender_id,h.epoch,alice.verifying_key()).unwrap();
 assert!(receive(&trust).is_ok());
 trust.revoke(h.sender_id).unwrap();
 assert!(matches!(receive(&trust),Err(CryptoError::UnauthorizedSender)));
 trust.enroll(h.sender_id,8,sk(4).verifying_key()).unwrap();
 assert!(matches!(receive(&trust),Err(CryptoError::UnauthorizedSender)));
}
#[test] fn mutating_any_identity_header_is_rejected() {
 let alice=sk(3);let (secret,public)=new_recipient();let h=hdr();
 let mut trust=TrustRegistry::new();trust.enroll(h.sender_id,h.epoch,alice.verifying_key()).unwrap();
 let wire=seal(&alice,&public,h,b"hi").unwrap();
 for idx in [1usize,20,34,42,58,wire.len()-1]{
  let mut bad=wire.clone();bad[idx]^=1;
  assert!(open(&bad,TrustedRecipient{secret:&secret,recipient_id:h.recipient_id,
   now:100,registry:&trust}).is_err());
 }
 let other=sk(8);let forged=seal(&other,&public,h,b"hi").unwrap();
 assert!(matches!(open(&forged,TrustedRecipient{secret:&secret,recipient_id:h.recipient_id,
 now:100,registry:&trust}),Err(CryptoError::InvalidSignature)));
}
#[test] fn expired_and_bad_version_are_rejected() {
 let alice=sk(3);let (secret,public)=new_recipient();let h=hdr();
 let mut trust=TrustRegistry::new();trust.enroll(h.sender_id,h.epoch,alice.verifying_key()).unwrap();
 let wire=seal(&alice,&public,h,b"hi").unwrap();
 assert!(matches!(open(&wire,TrustedRecipient{secret:&secret,recipient_id:h.recipient_id,
 now:5000,registry:&trust}),Err(CryptoError::Expired)));
 let mut old=wire;old[0]=1;
 assert!(matches!(open(&old,TrustedRecipient{secret:&secret,recipient_id:h.recipient_id,
 now:100,registry:&trust}),Err(CryptoError::UnknownSuite)));
}

#[test]
fn verified_blue_boundary_keeps_exact_ciphertext_and_digest() {
    use akula_wire_lab::crypto_identity_w3::open_authenticated;

    let sender = sk(3);
    let (secret, recipient) = new_recipient();
    let header = hdr();
    let mut trust = TrustRegistry::new();
    trust
        .enroll(header.sender_id, header.epoch, sender.verifying_key())
        .unwrap();
    let wire = seal(&sender, &recipient, header, b"shared Blue crypto").unwrap();
    let verified = open_authenticated(
        &wire,
        TrustedRecipient {
            secret: &secret,
            recipient_id: header.recipient_id,
            now: 100,
            registry: &trust,
        },
    )
    .unwrap();
    assert_eq!(verified.original_packet(), wire.as_slice());
    assert_eq!(verified.packet_digest(), *blake3::hash(&wire).as_bytes());
    assert_eq!(verified.payload(), b"shared Blue crypto");
    assert_eq!(verified.header().sender_id, header.sender_id);
    assert_eq!(verified.header().epoch, header.epoch);

    // Removing trusted enrollment must block the EXACT same signed packet.
    let empty = TrustRegistry::new();
    assert!(open_authenticated(
        &wire,
        TrustedRecipient {
            secret: &secret,
            recipient_id: header.recipient_id,
            now: 100,
            registry: &empty,
        }
    )
    .is_err());
}
