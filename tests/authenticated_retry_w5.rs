use akula_wire_lab::sim_w5::{Simulation,Node,Flow,Fault,SimError};
use akula_wire_lab::crypto_identity_w3::{seal,open,SignedHeader,TrustedRecipient};
use akula_wire_lab::crypto_w3::new_recipient;
use akula_wire_lab::trust_w3::TrustRegistry;
use ed25519_dalek::SigningKey;
fn id(n:u8)->[u8;16]{[n;16]}
fn setup(sim:&mut Simulation){
 for (a,b) in [(Node::A,Node::B),(Node::B,Node::V),
  (Node::V,Node::Mailbox),(Node::Mailbox,Node::G)]{sim.connect(a,b,true);}
 sim.relay_opt_in(Node::B,true);
 sim.relay_opt_in(Node::V,true);
}
#[test] fn corrupt_terminal_copy_can_be_evicted_and_recovered(){
 let sender=SigningKey::from_bytes(&[3;32]);let (secret,pubkey)=new_recipient();
 let mut trust=TrustRegistry::new();trust.enroll(id(3),7,sender.verifying_key()).unwrap();
 let packet=seal(&sender,&pubkey,SignedHeader{
  message_id:id(1),recipient_id:id(6),expiry:100,
  sender_id:id(3),epoch:7},b"hello").unwrap();
 let mut sim=Simulation::new(5);setup(&mut sim);
 sim.inject_once(Node::Mailbox,Node::G,Flow::Data,Fault::Corrupt);
 sim.submit_data(id(1),100,&packet).unwrap();sim.run(4).unwrap();
 let poisoned=sim.packet(Node::G,Flow::Data,id(1)).unwrap();
 assert!(open(poisoned,TrustedRecipient{secret:&secret,recipient_id:id(6),
  now:sim.tick(),registry:&trust}).is_err());
 sim.reject_terminal_copy(Node::G,Flow::Data,id(1)).unwrap();
 assert!(!sim.is_terminal_quarantined(Node::G,Flow::Data,id(1)));
 sim.run(1).unwrap();
 let repaired=sim.packet(Node::G,Flow::Data,id(1)).unwrap();
 assert_eq!(repaired,packet);
 assert_eq!(open(repaired,TrustedRecipient{secret:&secret,recipient_id:id(6),
  now:sim.tick(),registry:&trust}).unwrap().1,b"hello");
}
#[test] fn terminal_reject_has_no_authority_over_relay_copies(){
 let mut sim=Simulation::new(6);setup(&mut sim);
 sim.submit_data(id(1),100,b"opaque").unwrap();sim.run(4).unwrap();
 assert_eq!(sim.reject_terminal_copy(Node::V,Flow::Data,id(1)),Err(SimError::InvalidTerminal));
 assert!(sim.packet(Node::V,Flow::Data,id(1)).is_some());
 assert_eq!(sim.reject_terminal_copy(Node::G,Flow::Receipt,id(1)),Err(SimError::InvalidTerminal));
 assert_eq!(sim.reject_terminal_copy(Node::A,Flow::Receipt,id(1)),Err(SimError::MissingPacket));
}
#[test] fn repeated_terminal_rejects_bounded_by_quarantine(){
 let mut sim=Simulation::new(7);setup(&mut sim);
 sim.submit_data(id(1),100,b"sealed bytes").unwrap();sim.run(4).unwrap();
 for attempt in 0..3 {
  sim.reject_terminal_copy(Node::G,Flow::Data,id(1)).unwrap();
  if attempt<2 {sim.run(1).unwrap();}
 }
 assert!(sim.is_terminal_quarantined(Node::G,Flow::Data,id(1)));
 sim.run(10).unwrap();
 assert!(sim.packet(Node::G,Flow::Data,id(1)).is_none());
 assert!(sim.trace_jsonl().contains("quarantined"));
}
