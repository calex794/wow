use akula_wire_lab::sim_w5::{Simulation,Node,SimError};
fn id(n:u8)->[u8;16]{[n;16]}
#[test]
fn rotating_message_ids_cannot_evade_per_link_budget(){
 let mut sim=Simulation::new(77);
 for (a,b) in [(Node::A,Node::B),(Node::B,Node::V),
   (Node::V,Node::Mailbox),(Node::Mailbox,Node::G)] {
   sim.connect(a,b,true);
 }
 sim.relay_opt_in(Node::B,true);
 sim.relay_opt_in(Node::V,true);
 for i in 1u8..=16 {
   sim.submit_data(id(i),900,&[i;32]).unwrap();
 }
 sim.run(4).unwrap();
 let mut accepted=0;
 let mut rejected=0;
 for i in 1u8..=16 {
   let corrupted=[i.wrapping_add(1);32];
   match sim.offer_untrusted_from(Node::V,id(i),900,&corrupted) {
    Ok(())=>accepted+=1,
    Err(SimError::ResourceLimit)=>rejected+=1,
    other=>panic!("unexpected: {other:?}"),
   }
 }
 assert_eq!(accepted,12);
 assert_eq!(rejected,4);
 assert_eq!(sim.source_offers_this_tick(Node::V),12);
 assert!(sim.buffered_bytes()<=1024*1024);
 // V's budget is independent of a different incoming link; the global
 // 32-per-tick budget remains shared across all modeled links.
 let mut other=0;
 for i in 1u8..=16 {
   let corrupted=[i.wrapping_add(2);32];
   if sim.offer_untrusted_from(Node::Mailbox,id(i),900,&corrupted).is_ok() { other+=1; }
 }
 assert_eq!(other,12);
 assert_eq!(sim.untrusted_offers_this_tick(),24);
 sim.step().unwrap();
 assert_eq!(sim.source_offers_this_tick(Node::V),0);
}
