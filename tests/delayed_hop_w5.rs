//! W5 regression: store-and-forward links require a separate virtual tick.
use akula_wire_lab::sim_w5::{Fault, Flow, Node, Simulation};

fn id(byte: u8) -> [u8; 16] { [byte; 16] }

#[test]
fn delayed_data_arrival_cannot_forward_in_the_same_tick() {
    let mut sim = Simulation::new(11);
    sim.connect(Node::A, Node::B, true);
    sim.connect(Node::B, Node::V, true);
    sim.relay_opt_in(Node::B, true);
    sim.relay_opt_in(Node::V, true);
    sim.inject_once(Node::A, Node::B, Flow::Data, Fault::Delay(2));
    sim.submit_data(id(1), 100, b"opaque packet").unwrap();

    sim.run(2).unwrap();
    assert!(sim.packet(Node::B, Flow::Data, id(1)).is_none());
    sim.run(1).unwrap();
    assert_eq!(sim.packet(Node::B, Flow::Data, id(1)), Some(&b"opaque packet"[..]));
    assert!(sim.packet(Node::V, Flow::Data, id(1)).is_none());
    sim.run(1).unwrap();
    assert_eq!(sim.packet(Node::V, Flow::Data, id(1)), Some(&b"opaque packet"[..]));
}

#[test]
fn delayed_receipt_arrival_cannot_forward_in_the_same_tick() {
    let mut sim = Simulation::new(12);
    sim.connect(Node::G, Node::Mailbox, true);
    sim.connect(Node::Mailbox, Node::V, true);
    sim.relay_opt_in(Node::V, true);
    sim.inject_once(Node::G, Node::Mailbox, Flow::Receipt, Fault::Delay(2));
    // The payload is untrusted; this test never applies it to the journal.
    sim.submit_receipt(id(2), 100, b"unverified claim").unwrap();

    sim.run(3).unwrap();
    assert!(sim.packet(Node::Mailbox, Flow::Receipt, id(2)).is_some());
    assert!(sim.packet(Node::V, Flow::Receipt, id(2)).is_none());
    sim.run(1).unwrap();
    assert_eq!(sim.packet(Node::V, Flow::Receipt, id(2)), Some(&b"unverified claim"[..]));
}
