use akula_wire_lab::sim_w5::{Simulation, Node, Flow, SimError};
fn id(n:u8)->[u8;16]{[n;16]}
#[test]
fn three_hostile_edges_share_global_budget_and_cannot_replace_clean_mailbox_copy(){
 let mut sim=Simulation::new(89);
 for (a,b) in [(Node::A,Node::B),(Node::B,Node::V),(Node::B,Node::W),
 (Node::V,Node::Mailbox),(Node::W,Node::Mailbox),(Node::Mailbox,Node::G)] {
  sim.connect(a,b,true);
 }
 for n in [Node::B,Node::V,Node::W]{sim.relay_opt_in(n,true);}
 // Eight independent identities: 8 offers each per tick.
 for i in 1..=8 {sim.submit_data(id(i),900,&[i;512]).unwrap();}
 sim.run(4).unwrap();
 // Establish genuine copies before hostile alternatives are offered.
 let mut permitted=0;let mut denied=0;
 for from in [Node::V,Node::W,Node::Mailbox] {
  for i in 1..=8 {
   let mut corrupt=vec![i;512];corrupt[0]=(i+1) as u8;
   for _ in 0..3 {
    match sim.offer_untrusted_from(from,id(i),900,&corrupt) {
      Ok(())=>permitted+=1,
      Err(SimError::ResourceLimit)=>denied+=1,
      other=>panic!("Unexpected response: {other:?}"),
    }
   }
  }
 }
 assert!(permitted>0 && denied>0);
 assert!(sim.untrusted_offers_this_tick()<=32);
 for n in [Node::V,Node::W,Node::Mailbox] {
  assert!(sim.source_offers_this_tick(n)<=12);
 }
 assert!(sim.buffered_bytes()<=1024*1024);
 sim.run(4).unwrap();
 // Bad alternatives must not silently overwrite the first correct bytes.
 assert_eq!(sim.packet(Node::Mailbox,Flow::Data,id(1)), Some(&[1u8;512][..]));
 assert_eq!(sim.packet(Node::G,Flow::Data,id(1)),Some(&[1u8;512][..]));
}
#[test]
fn disabled_relay_cannot_inject_using_old_link_and_tick_budget_recovers(){
 let mut sim=Simulation::new(55);
 for (a,b) in [(Node::A,Node::B),(Node::B,Node::V),(Node::V,Node::Mailbox),
 (Node::Mailbox,Node::G)]{sim.connect(a,b,true);}
 sim.relay_opt_in(Node::B,true);
 sim.relay_opt_in(Node::V,true);
 sim.submit_data(id(1),850,&[7;64]).unwrap();
 sim.run(2).unwrap();
 for _ in 0..9 {
  let _=sim.offer_untrusted_from(Node::V,id(1),850,&[9;64]);
 }
 assert_eq!(sim.offer_untrusted_from(Node::V,id(1),850,&[9;64]),Err(SimError::ResourceLimit));
 sim.step().unwrap();
 assert_eq!(sim.untrusted_offers_this_tick(),0);
 sim.relay_opt_in(Node::V,false);
 assert_eq!(sim.offer_untrusted_from(Node::V,id(1),850,&[8;64]),Err(SimError::InvalidOrigin));
 assert_eq!(sim.offer_untrusted_from(Node::A,id(1),850,&[8;64]),Err(SimError::InvalidOrigin));
}
