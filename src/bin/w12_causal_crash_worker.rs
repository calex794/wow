//! Child process for deterministic WAL crash points. NEVER use in production.
use akula_wire_lab::{causal_w12::{CausalRequest},journal_w4::Journal,private_route_w3,crypto_identity_w3::SignedHeader,crypto_w3,trust_w3::TrustRegistry};
use ed25519_dalek::SigningKey;
use std::{env,path::Path};

fn main(){
 let args:Vec<_>=env::args().collect();
 assert_eq!(args.len(),3);
 let filename=Path::new(&args[1]);
 let mode=&args[2];
 let sender=SigningKey::from_bytes(&[7;32]);
 let signer=SigningKey::from_bytes(&[8;32]);
 let mut trust=TrustRegistry::new();
 trust.enroll([8;16],1,signer.verifying_key()).unwrap();
 let (_,pk)=crypto_w3::new_recipient();
 let packet=private_route_w3::seal_private(&sender,&pk,[9;16],SignedHeader{
    sender_id:[7;16],recipient_id:[3;16],message_id:[4;16],
    expiry:10_000_000,epoch:1
 },b"w12 exact encrypted W3").unwrap();
 // random HPKE ciphertext must be stable across retries. This worker
 // writes it once to a sibling file for the recovery process.
 let packet_file=filename.with_extension("w3");
 let bytes=if packet_file.exists(){std::fs::read(&packet_file).unwrap()}
 else {
    std::fs::write(&packet_file,&packet).unwrap();
    packet
 };
 let mut j=Journal::open(filename).unwrap();
 let r=CausalRequest{private_scope:[5;16],custodian_id:[8;16],
 custodian_epoch:1,recipient:[3;16],message:[4;16],expiry_ms:10_000_000};
 if mode=="before" {std::env::set_var("LABO_W12_ABORT_BEFORE_COMMIT","1");}
 if mode=="after" {std::env::set_var("LABO_W12_ABORT_AFTER_COMMIT","1");}
 let status=j.enqueue_w3_with_causal(r,&bytes,&signer,&trust).unwrap();
 let audit=j.audit_w12([5;16],[8;16],&trust).unwrap().unwrap();
 assert_eq!(status,audit);
 println!("COMMITTED {}",status.seq);
}
