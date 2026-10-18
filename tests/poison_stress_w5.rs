use akula_wire_lab::sim_w5::{Simulation,Node,Flow,Fault,SimError};
use akula_wire_lab::crypto_identity_w3::{seal,SignedHeader,TrustedRecipient};
use akula_wire_lab::crypto_w3::new_recipient;
use akula_wire_lab::trust_w3::TrustRegistry;
use ed25519_dalek::SigningKey;
fn id(n:u8)->[u8;16]{[n;16]}
fn prepare()->(Simulation,Vec<u8>,akula_wire_lab::crypto_w3::RecipientSecret,TrustRegistry) {
 let sender=SigningKey::from_bytes(&[3;32]);let(secret,public)=new_recipient();
 let mut trust=TrustRegistry::new();trust.enroll(id(3),7,sender.verifying_key()).unwrap();
 let packet=seal(&sender,&public,SignedHeader{
  message_id:id(1),recipient_id:id(6),expiry:950,sender_id:id(3),epoch:7,
 },b"trusted test payload").unwrap();
 let mut sim=Simulation::new(15);
 for(a,b) in [(Node::A,Node::B),(Node::B,Node::V),
 (Node::V,Node::Mailbox),(Node::Mailbox,Node::G)] {sim.connect(a,b,true);}
 for n in [Node::B,Node::V] {sim.relay_opt_in(n,true);}
 sim.submit_data(id(1),950,&packet).unwrap();sim.run(3).unwrap();
 (sim,packet,secret,trust)
}
#[test]
fn thousands_of_corrupt_offers_are_bounded_and_good_packet_recovers() {
 let(mut sim,packet,secret,trust)=prepare();
 let mut admitted=0usize;let mut denied=0usize;
 for tick in 0..160 {
  for n in 0..25 {
   let mut corrupt=packet.clone();
   let pos=corrupt.len()-1;
   corrupt[pos]^=((tick*25+n)%255+1)as u8;
   match sim.offer_untrusted_mailbox_frame(id(1),950,&corrupt) {
    Ok(())=>admitted+=1,
    Err(SimError::ResourceLimit)=>denied+=1,
    other=>panic!("unexpected result: {other:?}"),
   }
   if n%2==0 {
    let _=sim.verify_data_at_g(id(1),TrustedRecipient{
     secret:&secret,recipient_id:id(6),now:sim.tick(),registry:&trust,
    });
   }
  }
  sim.step().unwrap();
  assert!(sim.cached_bytes()<=1024*1024);
  assert!(sim.buffered_bytes()<=1024*1024);
  assert!(sim.rejected_fingerprints()<=4);
  assert!(sim.events().len()<=4096);
 }
 assert!(admitted>0); assert!(denied>0);
 // Eventually the clean mailbox copy must win over poison attempts.
 sim.run(3).unwrap();
 assert_eq!(sim.verify_data_at_g(id(1),TrustedRecipient{
  secret:&secret,recipient_id:id(6),now:sim.tick(),registry:&trust
 }).unwrap(),Some(b"trusted test payload".to_vec()));
}
#[test]
fn adversarial_fault_queue_and_event_history_are_bounded() {
 let(mut sim,packet,_secret,_trust)=prepare();
 let mut accepted=0;
 for _ in 0..5000 {
   if sim.inject_once(Node::A,Node::B,Flow::Data,Fault::Drop) {accepted+=1;}
 }
 assert_eq!(accepted,64);
 assert_eq!(sim.fault_queue_len(),64);
 // Repeated existing-data copies fill the trace ring without a hard stop.
 for _ in 0..700 {
  for _ in 0..8 {
   assert!(sim.offer_untrusted_mailbox_frame(id(1),950,&packet).is_ok());
  }
  sim.step().unwrap();
 }
 assert_eq!(sim.events().len(),4096);
 assert!(sim.dropped_trace_events()>0);
 assert!(sim.buffered_bytes()<=1024*1024);
}
