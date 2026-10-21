use akula_wire_lab::sim_w5::{Simulation,Node,Flow,Fault,SimError};
use akula_wire_lab::crypto_identity_w3::{seal,open,SignedHeader,TrustedRecipient};
use akula_wire_lab::crypto_w3::new_recipient;
use akula_wire_lab::journal_w4::{Journal,Delivery};
use akula_wire_lab::receipt_w4::{sign,verify};
use akula_wire_lab::trust_w3::TrustRegistry;
use ed25519_dalek::SigningKey;
use tempfile::tempdir;

fn id(n:u8)->[u8;16]{[n;16]}
fn links(sim:&mut Simulation, backup:bool){
 for (a,b) in [(Node::A,Node::B),(Node::B,Node::V),
   (Node::V,Node::Mailbox),(Node::Mailbox,Node::G)]{
   sim.connect(a,b,true);
 }
 if backup {
   sim.connect(Node::B,Node::W,true);
   sim.connect(Node::W,Node::Mailbox,true);
 }
 sim.relay_opt_in(Node::B,true);
 sim.relay_opt_in(Node::V,true);
 if backup {sim.relay_opt_in(Node::W,true);}
}
struct Fixture {
 packet:Vec<u8>,secret:akula_wire_lab::crypto_w3::RecipientSecret,
 sender:SigningKey,recipient:SigningKey,trust:TrustRegistry,
}
fn fixture()->Fixture{
 let sender=SigningKey::from_bytes(&[3;32]);
 let recipient=SigningKey::from_bytes(&[4;32]);
 let (secret,public)=new_recipient();
 let mut trust=TrustRegistry::new();
 trust.enroll(id(3),7,sender.verifying_key()).unwrap();
 trust.enroll(id(6),8,recipient.verifying_key()).unwrap();
 let packet=seal(&sender,&public,SignedHeader{
   message_id:id(1),recipient_id:id(6),expiry:200,
   sender_id:id(3),epoch:7,
 },b"short synthetic message").unwrap();
 Fixture {packet,secret,sender,recipient,trust}
}
#[test]
fn four_nodes_offline_to_gateway_mailbox_then_signed_ack(){
 let f=fixture();
 let temp=tempdir().unwrap();
 let path=temp.path().join("outbox.sqlite");
 let mut journal=Journal::open(&path).unwrap();
 journal.enqueue(id(6),id(1),200,&f.packet).unwrap();
 let mut sim=Simulation::new(55);links(&mut sim,false);
 sim.submit_data(id(1),200,&f.packet).unwrap();
 sim.run(4).unwrap();
 assert_eq!(sim.packet(Node::G,Flow::Data,id(1)),Some(f.packet.as_slice()));
 assert_eq!(journal.state(id(6),id(1)).unwrap(),Delivery::Queued);
 let incoming=sim.packet(Node::G,Flow::Data,id(1)).unwrap();
 let (header,body)=open(incoming,TrustedRecipient{
   secret:&f.secret,recipient_id:id(6),now:sim.tick(),registry:&f.trust
 }).unwrap();
 assert_eq!(header.sender_id,id(3));
 assert_eq!(body,b"short synthetic message");
 let signed=sign(&f.recipient,id(6),id(1),*blake3::hash(incoming).as_bytes(),8);
 sim.submit_receipt(id(1),200,&signed).unwrap();
 sim.run(4).unwrap();
 let ack=sim.packet(Node::A,Flow::Receipt,id(1)).unwrap();
 assert_eq!(journal.state(id(6),id(1)).unwrap(),Delivery::Queued);
 let verified=verify(ack,&f.trust).unwrap();
 assert_eq!(journal.apply_recipient_receipt(&verified).unwrap(),Delivery::Recipient);
 assert!(journal.retry_bytes(id(6),id(1),sim.tick() as i64).unwrap().is_none());
 assert_eq!(sim.packet(Node::B,Flow::Data,id(1)),Some(f.packet.as_slice()));
 assert_eq!(sim.trace_jsonl().lines().count(),sim.events().len());
 let _=&f.sender; // sender key fixture is independently provisioned
}
#[test]
fn failed_gateway_switch_and_dropped_ack_never_cause_false_delivery(){
 let f=fixture();let temp=tempdir().unwrap();let p=temp.path().join("j.sqlite");
 let mut journal=Journal::open(&p).unwrap();
 journal.enqueue(id(6),id(1),200,&f.packet).unwrap();
 let mut sim=Simulation::new(41);links(&mut sim,true);
 sim.set_alive(Node::W,false);
 sim.submit_data(id(1),200,&f.packet).unwrap();
 sim.run(2).unwrap();
 sim.set_alive(Node::V,false);
 sim.run(3).unwrap();
 assert!(sim.packet(Node::G,Flow::Data,id(1)).is_none());
 assert_eq!(journal.state(id(6),id(1)).unwrap(),Delivery::Queued);
 sim.set_alive(Node::W,true);
 sim.inject_once(Node::W,Node::Mailbox,Flow::Data,Fault::Drop);
 sim.run(5).unwrap();
 assert_eq!(sim.packet(Node::G,Flow::Data,id(1)),Some(f.packet.as_slice()));
 assert_eq!(journal.state(id(6),id(1)).unwrap(),Delivery::Queued);
 let signed=sign(&f.recipient,id(6),id(1),*blake3::hash(&f.packet).as_bytes(),8);
 sim.inject_once(Node::Mailbox,Node::W,Flow::Receipt,Fault::Drop);
 sim.submit_receipt(id(1),200,&signed).unwrap();
 sim.run(5).unwrap();
 assert!(sim.packet(Node::A,Flow::Receipt,id(1)).is_some());
 assert_eq!(journal.state(id(6),id(1)).unwrap(),Delivery::Queued);
 // Restart can only replay identical saved ciphertext.
 drop(journal);
 let journal=Journal::open(&p).unwrap();
 assert_eq!(journal.retry_bytes(id(6),id(1),sim.tick() as i64).unwrap(),Some(f.packet));
}
#[test]
fn partitions_ttl_opt_in_and_resource_limits(){
 let mut sim=Simulation::new(7);
 sim.connect(Node::A,Node::B,true);
 sim.submit_data(id(1),3,b"opaque").unwrap();
 sim.run(5).unwrap();
 assert!(sim.packet(Node::B,Flow::Data,id(1)).is_some());
 assert!(sim.packet(Node::G,Flow::Data,id(1)).is_none());
 assert_eq!(sim.submit_data(id(2),sim.tick(),b"expired"),Err(SimError::Expired));
 assert_eq!(sim.submit_data(id(1),100,b"different"),Err(SimError::Conflict));
 assert_eq!(sim.submit_data(id(3),100,&vec![0;16385]),Err(SimError::InvalidPayload));
 for n in 4..19 {sim.submit_data(id(n),100,b"x").unwrap();}
 assert_eq!(sim.submit_data(id(19),100,b"x"),Err(SimError::ResourceLimit));
}
#[test]
fn corruption_cannot_become_a_verified_ciphertext_or_receipt(){
 let f=fixture();let mut sim=Simulation::new(88);links(&mut sim,false);
 sim.inject_once(Node::Mailbox,Node::G,Flow::Data,Fault::Corrupt);
 sim.submit_data(id(1),200,&f.packet).unwrap();
 sim.run(4).unwrap();
 let arrived=sim.packet(Node::G,Flow::Data,id(1)).unwrap();
 assert_ne!(arrived,f.packet);
 assert!(open(arrived,TrustedRecipient{
   secret:&f.secret,recipient_id:id(6),now:sim.tick(),registry:&f.trust,
 }).is_err());
 let fake=sign(&f.recipient,id(6),id(1),*blake3::hash(arrived).as_bytes(),8);
 // An authentic recipient could only acknowledge the exact bytes it saw;
 // digest mismatch with sender's journal prevents false 'delivered'.
 let temp=tempdir().unwrap();let mut journal=Journal::open(&temp.path().join("j")).unwrap();
 journal.enqueue(id(6),id(1),200,&f.packet).unwrap();
 let verified=verify(&fake,&f.trust).unwrap();
 assert!(journal.apply_recipient_receipt(&verified).is_err());
 assert_eq!(journal.state(id(6),id(1)).unwrap(),Delivery::Queued);
}
#[test]
fn deterministic_trace_and_duplicate_and_delayed_frames(){
 fn run()->String{
  let mut sim=Simulation::new(22);links(&mut sim,false);
  sim.inject_once(Node::A,Node::B,Flow::Data,Fault::Duplicate);
  sim.inject_once(Node::B,Node::V,Flow::Data,Fault::Delay(2));
  sim.submit_data(id(1),100,b"fixed opaque bytes").unwrap();
  sim.run(8).unwrap();
  assert_eq!(sim.packet(Node::G,Flow::Data,id(1)),Some(&b"fixed opaque bytes"[..]));
  sim.trace_jsonl()
 }
 let a=run(); assert_eq!(a,run());
 assert!(a.contains("duplicate"));assert!(a.contains("delayed"));
}

#[test]
fn revoked_sender_epoch_blocks_forwarded_ciphertext_even_after_delivery(){
 let f=fixture();
 let mut sim=Simulation::new(81); links(&mut sim,true);
 sim.submit_data(id(1),200,&f.packet).unwrap();
 sim.run(4).unwrap();
 let mut revoked=TrustRegistry::new();
 revoked.enroll(id(3),7,f.sender.verifying_key()).unwrap();
 revoked.revoke(id(3)).unwrap();
 let incoming=sim.packet(Node::G,Flow::Data,id(1)).unwrap();
 assert!(open(incoming,TrustedRecipient{
   secret:&f.secret,recipient_id:id(6),now:sim.tick(),registry:&revoked
 }).is_err());
 revoked.enroll(id(3),8,SigningKey::from_bytes(&[9;32]).verifying_key()).unwrap();
 assert!(open(incoming,TrustedRecipient{
   secret:&f.secret,recipient_id:id(6),now:sim.tick(),registry:&revoked
 }).is_err());
}
#[test]
fn malicious_relay_claim_cannot_authenticate_recipient_receipt(){
 let f=fixture();let temp=tempdir().unwrap();
 let mut journal=Journal::open(&temp.path().join("outbox.sqlite")).unwrap();
 journal.enqueue(id(6),id(1),200,&f.packet).unwrap();
 let attacker=SigningKey::from_bytes(&[99;32]);
 let forged=sign(&attacker,id(6),id(1),*blake3::hash(&f.packet).as_bytes(),8);
 let mut sim=Simulation::new(44);links(&mut sim,false);
 sim.submit_receipt(id(1),200,&forged).unwrap();
 sim.run(4).unwrap();
 let delivered=sim.packet(Node::A,Flow::Receipt,id(1)).unwrap();
 assert!(verify(delivered,&f.trust).is_err());
 assert_eq!(journal.state(id(6),id(1)).unwrap(),Delivery::Queued);
}
#[test]
fn intermediate_receipt_and_offline_recipient_never_mean_delivered(){
 let f=fixture();let temp=tempdir().unwrap();
 let mut journal=Journal::open(&temp.path().join("outbox.sqlite")).unwrap();
 journal.enqueue(id(6),id(1),200,&f.packet).unwrap();
 let mut sim=Simulation::new(92);links(&mut sim,false);
 sim.set_alive(Node::G,false);
 sim.submit_data(id(1),200,&f.packet).unwrap();
 sim.run(12).unwrap();
 assert_eq!(sim.packet(Node::Mailbox,Flow::Data,id(1)),Some(f.packet.as_slice()));
 assert!(sim.packet(Node::G,Flow::Data,id(1)).is_none());
 // Mailbox may have stored the opaque bytes, but only the recipient can sign.
 assert_eq!(journal.state(id(6),id(1)).unwrap(),Delivery::Queued);
 assert_eq!(journal.retry_bytes(id(6),id(1),sim.tick() as i64).unwrap(),Some(f.packet));
}

#[test]
fn both_gateways_fail_then_backup_returns_and_recipient_reconnects(){
 let f=fixture();let mut sim=Simulation::new(123);links(&mut sim,true);
 sim.set_alive(Node::W,false);
 sim.set_alive(Node::G,false);
 sim.submit_data(id(1),200,&f.packet).unwrap();
 sim.run(2).unwrap();
 sim.set_alive(Node::V,false);
 sim.run(5).unwrap();
 assert!(sim.packet(Node::Mailbox,Flow::Data,id(1)).is_none());
 sim.set_alive(Node::W,true);
 sim.run(2).unwrap();
 sim.set_alive(Node::W,false);
 sim.run(2).unwrap();
 assert_eq!(sim.packet(Node::Mailbox,Flow::Data,id(1)),Some(f.packet.as_slice()));
 sim.set_alive(Node::Mailbox,false);
 sim.run(2).unwrap();
 sim.set_alive(Node::Mailbox,true);
 assert_eq!(sim.packet(Node::Mailbox,Flow::Data,id(1)),Some(f.packet.as_slice()));
 assert!(sim.packet(Node::G,Flow::Data,id(1)).is_none());
 sim.set_alive(Node::G,true);
 sim.run(1).unwrap();
 assert_eq!(sim.packet(Node::G,Flow::Data,id(1)),Some(f.packet.as_slice()));
 let verified=open(sim.packet(Node::G,Flow::Data,id(1)).unwrap(),TrustedRecipient{
   secret:&f.secret,recipient_id:id(6),now:sim.tick(),registry:&f.trust
 }).unwrap();
 assert_eq!(verified.1,b"short synthetic message");
 // V and W are still offline: data delivered does not imply return of ACK.
 let receipt=sign(&f.recipient,id(6),id(1),*blake3::hash(&f.packet).as_bytes(),8);
 sim.submit_receipt(id(1),200,&receipt).unwrap();
 sim.run(2).unwrap();
 assert!(sim.packet(Node::A,Flow::Receipt,id(1)).is_none());
 sim.set_alive(Node::V,true);
 sim.run(3).unwrap();
 assert_eq!(sim.packet(Node::A,Flow::Receipt,id(1)),Some(receipt.as_slice()));
}
#[test]
fn expired_message_is_never_transmitted_after_reconnection(){
 let mut sim=Simulation::new(21);
 sim.submit_data(id(1),3,b"expires soon").unwrap();
 sim.run(4).unwrap();
 links(&mut sim,true);
 sim.run(5).unwrap();
 assert!(sim.packet(Node::B,Flow::Data,id(1)).is_none());
 assert!(sim.packet(Node::G,Flow::Data,id(1)).is_none());
}
#[test]
fn revoking_relay_consent_prevents_future_transfers(){
 let mut sim=Simulation::new(32);
 sim.connect(Node::A,Node::B,true);
 sim.connect(Node::B,Node::V,true);
 sim.connect(Node::V,Node::Mailbox,true);
 sim.connect(Node::Mailbox,Node::G,true);
 sim.submit_data(id(1),100,b"private test").unwrap();
 sim.run(1).unwrap();
 assert!(sim.packet(Node::B,Flow::Data,id(1)).is_some());
 sim.relay_opt_in(Node::B,false);
 sim.relay_opt_in(Node::V,true);
 sim.run(8).unwrap();
 assert!(sim.packet(Node::V,Flow::Data,id(1)).is_none());
 assert!(sim.packet(Node::G,Flow::Data,id(1)).is_none());
}
