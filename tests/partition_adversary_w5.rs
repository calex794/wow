use akula_wire_lab::sim_w5::{Simulation,Node,Flow,Fault};
fn id(n:u8)->[u8;16]{[n;16]}
fn setup(sim:&mut Simulation){
 for (a,b) in [(Node::A,Node::B),(Node::B,Node::V),
 (Node::V,Node::Mailbox),(Node::Mailbox,Node::G)] {sim.connect(a,b,true);}
 sim.relay_opt_in(Node::B,true);
 sim.relay_opt_in(Node::V,true);
}
#[test] fn mailbox_keeps_ciphertext_during_restart_and_reconnect(){
 let mut sim=Simulation::new(13);setup(&mut sim);
 sim.submit_data(id(1),100,b"sealed object").unwrap();
 sim.run(3).unwrap();
 assert_eq!(sim.packet(Node::Mailbox,Flow::Data,id(1)),Some(&b"sealed object"[..]));
 sim.set_alive(Node::Mailbox,false);
 sim.run(2).unwrap();
 assert_eq!(sim.packet(Node::Mailbox,Flow::Data,id(1)),Some(&b"sealed object"[..]));
 assert_eq!(sim.packet(Node::G,Flow::Data,id(1)),None);
 sim.set_alive(Node::Mailbox,true);
 sim.run(2).unwrap();
 assert_eq!(sim.packet(Node::G,Flow::Data,id(1)),Some(&b"sealed object"[..]));
}
#[test] fn opt_out_cancels_in_flight_and_cached_relay(){
 let mut sim=Simulation::new(14);setup(&mut sim);
 sim.inject_once(Node::B,Node::V,Flow::Data,Fault::Delay(8));
 sim.submit_data(id(1),100,b"ciphertext").unwrap();
 sim.run(2).unwrap();
 assert!(sim.packet(Node::B,Flow::Data,id(1)).is_some());
 sim.relay_opt_in(Node::B,false);
 assert!(sim.packet(Node::B,Flow::Data,id(1)).is_none());
 sim.run(11).unwrap();
 assert_eq!(sim.packet(Node::V,Flow::Data,id(1)),None);
 assert_eq!(sim.packet(Node::G,Flow::Data,id(1)),None);
}
#[test] fn disconnected_gateway_does_not_emit_pending_frames(){
 let mut sim=Simulation::new(15);setup(&mut sim);
 sim.inject_once(Node::V,Node::Mailbox,Flow::Data,Fault::Delay(10));
 sim.submit_data(id(1),100,b"ciphertext").unwrap();
 sim.run(3).unwrap();
 sim.set_alive(Node::V,false);
 sim.run(12).unwrap();
 assert_eq!(sim.packet(Node::Mailbox,Flow::Data,id(1)),None);
 assert_eq!(sim.packet(Node::G,Flow::Data,id(1)),None);
}
#[test] fn opt_out_while_delayed_prevents_late_arrival(){
 let mut sim=Simulation::new(16);setup(&mut sim);
 sim.inject_once(Node::B,Node::V,Flow::Data,Fault::Delay(7));
 sim.submit_data(id(1),100,b"ciphertext").unwrap();
 sim.run(2).unwrap();
 sim.relay_opt_in(Node::V,false);
 sim.run(9).unwrap();
 assert_eq!(sim.packet(Node::V,Flow::Data,id(1)),None);
 assert_eq!(sim.packet(Node::G,Flow::Data,id(1)),None);
}
