use akula_wow_w3_crypto::crypto_w3::{new_recipient,seal,open,RecipientContext,CryptoError};
use ed25519_dalek::SigningKey;
use hpke::Serializable;

fn signer(b: u8) -> SigningKey { SigningKey::from_bytes(&[b;32]) }

#[test]
fn signed_encrypted_delivery_and_route_bytes() {
    let alice=signer(3);
    let (bob_secret,bob_public)=new_recipient();
    let id=[7;16]; let bob=[9;16];
    let packet=seal(&alice,&bob_public,id,bob,500,b"hello offline network").unwrap();
    let context=RecipientContext{secret:&bob_secret,expected_sender:&alice.verifying_key(),expected_recipient:bob,now:400};
    assert_eq!(open(&packet,context).unwrap(),(id,b"hello offline network".to_vec()));
    assert_eq!(packet,packet.clone()); // relay forwards unchanged ciphertext
}

#[test]
fn modified_header_ciphertext_and_wrong_recipient_rejected() {
    let alice=signer(3);
    let (bob_secret,bob_public)=new_recipient();
    let (_,other_public)=new_recipient();
    let id=[7;16]; let bob=[9;16];
    let packet=seal(&alice,&bob_public,id,bob,500,b"hello").unwrap();
    let verify=|bytes:&[u8]|open(bytes,RecipientContext{
        secret:&bob_secret,expected_sender:&alice.verifying_key(),expected_recipient:bob,now:400
    });
    for i in [1usize,20,38,packet.len()-1] {
        let mut tampered=packet.clone();tampered[i]^=1;
        assert!(verify(&tampered).is_err());
    }
    let mut version=packet.clone();version[0]=2;
    assert_eq!(verify(&version),Err(CryptoError::UnknownSuite));
    assert_eq!(open(&packet,RecipientContext{
        secret:&bob_secret,expected_sender:&alice.verifying_key(),expected_recipient:[8;16],now:400
    }),Err(CryptoError::InvalidRecipient));
    let (_,wrong_secret)={
        let (secret,pubkey)=new_recipient();(pubkey,secret)
    };
    assert!(open(&packet,RecipientContext{
        secret:&wrong_secret,expected_sender:&alice.verifying_key(),expected_recipient:bob,now:400
    }).is_err());
    // Another destination key cannot read this packet.
    assert_ne!(bob_public.to_bytes(),other_public.to_bytes());
}

#[test]
fn sender_identity_must_be_pretrusted_and_expiry_is_checked() {
    let alice=signer(3);
    let mallory=signer(4);
    let (bob_secret,bob_public)=new_recipient();
    let packet=seal(&alice,&bob_public,[7;16],[9;16],500,b"hello").unwrap();
    assert_eq!(open(&packet,RecipientContext{secret:&bob_secret,expected_sender:&mallory.verifying_key(),
        expected_recipient:[9;16],now:400}),Err(CryptoError::InvalidSignature));
    assert_eq!(open(&packet,RecipientContext{secret:&bob_secret,expected_sender:&alice.verifying_key(),
        expected_recipient:[9;16],now:500}),Err(CryptoError::Expired));
}

#[test]
fn excessive_packet_refuses_allocation() {
    let (secret,_pubkey)=new_recipient();
    let sender=signer(1);
    let big=vec![0u8;16*1024+1];
    assert_eq!(open(&big,RecipientContext{secret:&secret,expected_sender:&sender.verifying_key(),
        expected_recipient:[0;16],now:1}),Err(CryptoError::Oversized));
}
