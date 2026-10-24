//! EXP-018/WOW integration gate: real W3 v3, signed W8 custody, durable
//! recipient W4, opaque reverse W4 and independent SQLite files.
//! The outage schedule is deterministic LABO-style *injection*, NOT
//! an actual replay of SFHH/InVS contacts or a test with two computers.

use akula_wire_lab::crypto_identity_w3::{SignedHeader, TrustedRecipient};
use akula_wire_lab::crypto_w3::new_recipient;
use akula_wire_lab::custody_transfer_w8::{
    OfferIssue, PeerConsent, PeerCustodyStore, TransferPhase,
};
use akula_wire_lab::journal_w4::{Delivery, Insert, Journal};
use akula_wire_lab::multipath_w5::{Lane, RouteError};
use akula_wire_lab::private_return_w4::{
    self, PrivateReturnError, ReturnInvitation,
};
use akula_wire_lab::private_route_w3;
use akula_wire_lab::receipt_w4::{self, ReceiptError};
use akula_wire_lab::trust_w3::TrustRegistry;
use ed25519_dalek::SigningKey;
use rusqlite::{params, Connection};
use std::path::Path;
use tempfile::tempdir;

fn id(n: u8) -> [u8; 16] { [n; 16] }
fn key(n: u8) -> SigningKey { SigningKey::from_bytes(&[n; 32]) }

fn trust() -> TrustRegistry {
    let mut t = TrustRegistry::new();
    t.enroll(id(9), 4, key(9).verifying_key()).unwrap();  // W3 sender
    t.enroll(id(21), 3, key(21).verifying_key()).unwrap(); // custody issuer
    t.enroll(id(8), 6, key(8).verifying_key()).unwrap();  // final recipient
    t.enroll(id(13), 7, key(13).verifying_key()).unwrap(); // gateway A
    t.enroll(id(14), 8, key(14).verifying_key()).unwrap(); // gateway B
    t
}

fn offer(source: &mut Journal, attempt: u8, offer_id: u8, peer: u8,
         epoch: u64, now: i64, registry: &TrustRegistry) -> Vec<u8> {
    source.issue_custody_offer(OfferIssue {
        recipient: id(8), message: id(5), attempt_id: id(attempt),
        offer_id: id(offer_id), source_id: id(21), source_epoch: 3,
        target_id: id(peer), target_epoch: epoch, now_ms: now,
    }, &key(21), registry).unwrap()
}

fn custody_ack(path: &Path, offer: &[u8], packet: &[u8],
               peer: u8, epoch: u64, registry: &TrustRegistry) -> Vec<u8> {
    let mut store = PeerCustodyStore::open(path).unwrap();
    store.accept(offer, packet, PeerConsent {
        expected_source: id(21), target_id: id(peer), target_epoch: epoch,
        signer: &key(peer), trust: registry, now_ms: 110,
    }).unwrap()
}

fn gateway_packet(path: &Path, offer_id: u8) -> Vec<u8> {
    Connection::open(path).unwrap().query_row(
        "SELECT packet FROM custody_inbox WHERE offer_id=?1",
        params![id(offer_id).as_slice()], |row| row.get(0),
    ).unwrap()
}

fn reverse_invitation<'a>(
    secret: &'a akula_wire_lab::crypto_w3::RecipientSecret,
    registry: &'a TrustRegistry, now: u64,
) -> ReturnInvitation<'a> {
    ReturnInvitation {
        sender_secret: secret,
        expected_tag: id(61),
        expires_at_ms: 700_000,
        now_ms: now,
        recipient_trust: registry,
    }
}

#[test]
fn first_gateway_loses_sqlite_second_delivers_and_only_private_w4_confirms() {
    let dir = tempdir().unwrap();
    let registry = trust();
    let source_path = dir.path().join("source.sqlite");
    let a_path = dir.path().join("gateway-a.sqlite");
    let b_path = dir.path().join("gateway-b.sqlite");
    let recipient_path = dir.path().join("recipient.sqlite");
    let (bob_secret, bob_public) = new_recipient();
    let (return_secret, return_public) = new_recipient();
    let packet = private_route_w3::seal_private(
        &key(9), &bob_public, id(4),
        SignedHeader {
            message_id: id(5), recipient_id: id(8), sender_id: id(9),
            epoch: 4, expiry: 500_000,
        },
        b"EXP-018 redundant gateway exact ciphertext",
    ).unwrap();

    let mut sender = Journal::open(&source_path).unwrap();
    sender.enqueue(id(8), id(5), 500_000, &packet).unwrap();
    sender.begin_multipath(id(8), id(5), &packet, 500_000, 4, 100).unwrap();
    sender.reserve_multipath((id(8), id(5)), &packet,
                            id(44), id(13), Lane::Gateway, 101).unwrap();
    sender.reserve_multipath((id(8), id(5)), &packet,
                            id(45), id(14), Lane::Gateway, 102).unwrap();
    let first = offer(&mut sender, 44, 31, 13, 7, 103, &registry);
    let second = offer(&mut sender, 45, 32, 14, 8, 104, &registry);
    let ack_a = custody_ack(&a_path, &first, &packet, 13, 7, &registry);
    let ack_b = custody_ack(&b_path, &second, &packet, 14, 8, &registry);

    // A claimed custody before losing its disk. This does not guarantee
    // future storage or entitle it to issue a terminal recipient receipt.
    assert_eq!(sender.accept_peer_custody_claim(&ack_a, &registry).unwrap(),
               TransferPhase::PeerClaimed);
    assert_eq!(sender.accept_peer_custody_claim(&ack_b, &registry).unwrap(),
               TransferPhase::PeerClaimed);
    assert_eq!(sender.state(id(8), id(5)).unwrap(), Delivery::Queued);
    assert_eq!(sender.multipath_snapshot(id(8), id(5)).unwrap().allocated, 3);
    assert_eq!(gateway_packet(&b_path, 32), packet);

    std::fs::remove_file(&a_path).unwrap(); // controlled disk reset after commit
    let empty_a = PeerCustodyStore::open(&a_path).unwrap();
    drop(empty_a);
    let left: i64 = Connection::open(&a_path).unwrap()
        .query_row("SELECT COUNT(*) FROM custody_inbox", [], |r| r.get(0))
        .unwrap();
    assert_eq!(left, 0);
    // B is independently durable and still holds precisely the original W3.
    let surviving_packet = gateway_packet(&b_path, 32);
    assert_eq!(surviving_packet, packet);
    drop(sender); // sender is unavailable when Bob receives the W3

    let mut bob = Journal::open(&recipient_path).unwrap();
    let (new, signed) = bob.accept_private_authenticated_and_queue_receipt(
        &surviving_packet,
        TrustedRecipient {
            secret: &bob_secret, recipient_id: id(8),
            now: 200_000, registry: &registry,
        },
        id(4), &key(8), 6,
    ).unwrap();
    assert_eq!(new, Insert::New);
    drop(bob);
    let bob = Journal::open(&recipient_path).unwrap();
    assert_eq!(bob.queued_recipient_receipt(id(9), id(5)).unwrap(),
               Some(signed.clone()));

    let opaque = private_return_w4::seal_signed_receipt(
        &signed, &return_public, id(61),
    ).unwrap();
    assert!(!opaque.windows(16).any(|w|
        w == id(8).as_slice() || w == id(5).as_slice()));
    let mut sender = Journal::open(&source_path).unwrap();
    assert_eq!(sender.state(id(8), id(5)).unwrap(), Delivery::Queued);
    assert!(!sender.multipath_snapshot(id(8), id(5)).unwrap().stopped);

    // A custodian can sign bytes, but not an accepted terminal W4 for Bob.
    let fake = receipt_w4::sign(
        &key(13), id(8), id(5), *blake3::hash(&packet).as_bytes(), 6,
    );
    let forged = private_return_w4::seal_signed_receipt(
        &fake, &return_public, id(61),
    ).unwrap();
    assert!(matches!(
        private_return_w4::open_verify_and_apply(
            &forged, reverse_invitation(&return_secret, &registry, 200_010),
            &mut sender,
        ),
        Err(PrivateReturnError::UntrustedReceipt(ReceiptError::InvalidSignature))
    ));
    assert_eq!(sender.state(id(8), id(5)).unwrap(), Delivery::Queued);

    // The return channel is unavailable; the already signed receipt waits.
    drop(sender);
    let mut sender = Journal::open(&source_path).unwrap();
    assert_eq!(sender.retry_bytes(id(8), id(5), 200_020).unwrap(),
               Some(packet.clone()));
    assert_eq!(private_return_w4::open_verify_and_apply(
        &opaque, reverse_invitation(&return_secret, &registry, 200_100),
        &mut sender,
    ).unwrap(), Delivery::Recipient);
    let plan = sender.multipath_snapshot(id(8), id(5)).unwrap();
    assert_eq!(plan.budget, 4);
    assert_eq!(plan.allocated, 3);
    assert!(plan.stopped);
    assert_eq!(sender.retry_bytes(id(8), id(5), 200_101).unwrap(), None);
    assert!(matches!(
        sender.reserve_multipath((id(8), id(5)), &packet,
                                 id(46), id(14), Lane::Gateway, 200_102),
        Err(RouteError::RecipientConfirmed)
    ));
    // Idempotent even across another process restart.
    drop(sender);
    let mut sender = Journal::open(&source_path).unwrap();
    assert_eq!(private_return_w4::open_verify_and_apply(
        &opaque, reverse_invitation(&return_secret, &registry, 200_200),
        &mut sender,
    ).unwrap(), Delivery::Recipient);
}

#[test]
fn two_lost_gateways_and_peer_ack_cannot_fabricate_final_delivery() {
    let dir = tempdir().unwrap();
    let registry = trust();
    let (bob_secret, bob_public) = new_recipient();
    let packet = private_route_w3::seal_private(
        &key(9), &bob_public, id(4),
        SignedHeader {
            message_id: id(5), recipient_id: id(8), sender_id: id(9),
            epoch: 4, expiry: 500_000,
        },
        b"no recipient when both independent gateways disappear",
    ).unwrap();
    let mut sender = Journal::open(&dir.path().join("source.sqlite")).unwrap();
    sender.enqueue(id(8), id(5), 500_000, &packet).unwrap();
    sender.begin_multipath(id(8), id(5), &packet, 500_000, 4, 100).unwrap();
    for (attempt, offer_id, peer, epoch, now) in [
        (44, 31, 13, 7, 103), (45, 32, 14, 8, 104)
    ] {
        sender.reserve_multipath(
            (id(8), id(5)), &packet, id(attempt), id(peer), Lane::Gateway,
            now - 1,
        ).unwrap();
        let offered = offer(&mut sender, attempt, offer_id, peer, epoch, now, &registry);
        let db = dir.path().join(format!("gateway-{peer}.sqlite"));
        let ack = custody_ack(&db, &offered, &packet, peer, epoch, &registry);
        assert_eq!(sender.accept_peer_custody_claim(&ack, &registry).unwrap(),
                   TransferPhase::PeerClaimed);
        std::fs::remove_file(db).unwrap();
    }
    assert_eq!(sender.state(id(8), id(5)).unwrap(), Delivery::Queued);
    assert_eq!(sender.multipath_snapshot(id(8), id(5)).unwrap().allocated, 3);
    assert_eq!(sender.retry_bytes(id(8), id(5), 200).unwrap(), Some(packet));
    let recipient = Journal::open(&dir.path().join("recipient.sqlite")).unwrap();
    assert_eq!(recipient.queued_recipient_receipt(id(9), id(5)).unwrap(), None);
    drop(recipient);
    drop(bob_secret);
    // The original source copy remains: the model makes NO assertion that
    // both lost gateways imply permanent loss while source is still online.
}

#[test]
fn signed_recipient_w4_can_arrive_after_forward_ttl_but_not_after_return_invite() {
    let dir = tempdir().unwrap();
    let registry = trust();
    let (bob_secret, bob_public) = new_recipient();
    let (return_secret, return_public) = new_recipient();
    let packet = private_route_w3::seal_private(
        &key(9), &bob_public, id(4),
        SignedHeader {
            message_id: id(5), recipient_id: id(8), sender_id: id(9),
            epoch: 4, expiry: 500_000,
        },
        b"late real W4 while forward copy already expired",
    ).unwrap();
    let mut alice = Journal::open(&dir.path().join("alice.sqlite")).unwrap();
    alice.enqueue(id(8), id(5), 500_000, &packet).unwrap();
    alice.begin_multipath(id(8), id(5), &packet, 500_000, 4, 100).unwrap();
    let mut bob = Journal::open(&dir.path().join("bob.sqlite")).unwrap();
    let (_, signed) = bob.accept_private_authenticated_and_queue_receipt(
        &packet,
        TrustedRecipient {
            secret: &bob_secret, recipient_id: id(8),
            now: 400_000, registry: &registry,
        }, id(4), &key(8), 6,
    ).unwrap();
    let opaque = private_return_w4::seal_signed_receipt(
        &signed, &return_public, id(61),
    ).unwrap();

    assert_eq!(alice.state(id(8), id(5)).unwrap(), Delivery::Queued);
    assert_eq!(alice.retry_bytes(id(8), id(5), 500_001).unwrap(), None);
    // Forward TTL and opaque return invitation expiry are separate.
    assert_eq!(private_return_w4::open_verify_and_apply(
        &opaque, reverse_invitation(&return_secret, &registry, 600_000),
        &mut alice,
    ).unwrap(), Delivery::Recipient);
    assert_eq!(alice.state(id(8), id(5)).unwrap(), Delivery::Recipient);

    let mut next = Journal::open(&dir.path().join("next.sqlite")).unwrap();
    next.enqueue(id(8), id(5), 500_000, &packet).unwrap();
    assert!(matches!(
        private_return_w4::open_verify_and_apply(
            &opaque, reverse_invitation(&return_secret, &registry, 700_000),
            &mut next,
        ),
        Err(PrivateReturnError::ExpiredInvitation)
    ));
    assert_eq!(next.state(id(8), id(5)).unwrap(), Delivery::Queued);
}
