use akula_wire_lab::sim_w5::{Simulation, Node, Flow, Fault};
use akula_wire_lab::crypto_identity_w3::{seal, SignedHeader, TrustedRecipient};
use akula_wire_lab::crypto_w3::new_recipient;
use akula_wire_lab::trust_w3::TrustRegistry;
use ed25519_dalek::SigningKey;

fn id(n: u8) -> [u8; 16] { [n; 16] }
fn setup() -> (Simulation, Vec<u8>, akula_wire_lab::crypto_w3::RecipientSecret, TrustRegistry) {
    let sender = SigningKey::from_bytes(&[3; 32]);
    let (secret, public) = new_recipient();
    let mut trust = TrustRegistry::new();
    trust.enroll(id(3), 7, sender.verifying_key()).unwrap();
    let packet = seal(&sender, &public, SignedHeader {
        message_id: id(1), recipient_id: id(6), expiry: 200, sender_id: id(3), epoch: 7,
    }, b"known-good-payload").unwrap();
    let mut sim = Simulation::new(123);
    for (a,b) in [(Node::A,Node::B),(Node::B,Node::V),(Node::B,Node::W),
        (Node::V,Node::Mailbox),(Node::W,Node::Mailbox),(Node::Mailbox,Node::G)] {
        sim.connect(a,b,true);
    }
    for node in [Node::B,Node::V,Node::W] { sim.relay_opt_in(node,true); }
    (sim,packet,secret,trust)
}

#[test]
fn damaged_first_copy_does_not_permanently_block_valid_retransmission() {
    let (mut sim, packet, secret, trust) = setup();
    sim.inject_once(Node::Mailbox,Node::G,Flow::Data,Fault::Corrupt);
    sim.submit_data(id(1),200,&packet).unwrap();
    sim.run(4).unwrap();
    assert_ne!(sim.packet(Node::G,Flow::Data,id(1)),Some(packet.as_slice()));
    assert!(sim.verify_data_at_g(id(1),TrustedRecipient {
        secret:&secret, recipient_id:id(6), now:sim.tick(),registry:&trust
    }).is_err());
    sim.run(2).unwrap();
    assert_eq!(sim.packet(Node::G,Flow::Data,id(1)),Some(packet.as_slice()));
    assert_eq!(sim.verify_data_at_g(id(1),TrustedRecipient {
        secret:&secret, recipient_id:id(6),now:sim.tick(),registry:&trust
    }).unwrap(),Some(b"known-good-payload".to_vec()));
    assert!(sim.trace_jsonl().contains("quarantined"));
}
#[test]
fn loss_of_trust_does_not_delete_good_ciphertext() {
    let (mut sim, packet, secret, mut trust) = setup();
    sim.submit_data(id(1),200,&packet).unwrap();
    sim.run(4).unwrap();
    trust.revoke(id(3)).unwrap();
    assert!(sim.verify_data_at_g(id(1),TrustedRecipient {
        secret:&secret,recipient_id:id(6),now:sim.tick(),registry:&trust
    }).is_err());
    assert_eq!(sim.packet(Node::G,Flow::Data,id(1)),Some(packet.as_slice()));
}
#[test]
fn bad_alternative_cannot_replace_valid_primary_without_verified_failure() {
    let (mut sim, packet, secret, trust) = setup();
    sim.submit_data(id(1),200,&packet).unwrap();
    sim.run(4).unwrap();
    sim.inject_once(Node::W,Node::Mailbox,Flow::Data,Fault::Corrupt);
    sim.run(3).unwrap();
    assert_eq!(sim.packet(Node::G,Flow::Data,id(1)),Some(packet.as_slice()));
    assert_eq!(sim.verify_data_at_g(id(1),TrustedRecipient {
        secret:&secret,recipient_id:id(6),now:sim.tick(),registry:&trust
    }).unwrap(),Some(b"known-good-payload".to_vec()));
}
