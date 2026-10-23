//! W11 network trial: a SEPARATE anchor OS process signs after independent
//! SQLite commit. Independent QUIC clients check both witness/anchor keys,
//! detect client-SQLite rollback, and gossip conflicting legitimate signatures.
//! All endpoints bind localhost on ONE GitHub runner: not physical hosts.
#![cfg(feature = "iroh-transport")]

use akula_wire_lab::custody_transfer_w8::{self, OfferClaims};
use akula_wire_lab::custody_witness_w9::{WitnessObservation, WitnessStore, CHECKPOINT_LEN};
use akula_wire_lab::trust_w3::TrustRegistry;
use akula_wire_lab::witness_anchor_w11::{
    self, AnchorComparison, AnchorGossip, AnchorIdentity, AnchorStore,
    ANCHOR_RECEIPT_LEN,
};
use akula_wire_lab::witness_pin_w10::{PinOutcome, WitnessPinStore};
use ed25519_dalek::SigningKey;
use iroh::{Endpoint, EndpointAddr, EndpointId, endpoint::presets};
use rusqlite::{params, Connection as Sqlite};
use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use tempfile::{tempdir, TempDir};

const ANCHOR_ALPN: &[u8] = b"akula-wow/w11-independent-anchor-local-only/1";
const GOSSIP_ALPN: &[u8] = b"akula-wow/w11-anchor-gossip-local-only/1";
fn id(n: u8) -> [u8; 16] { [n; 16] }
fn key(n: u8) -> SigningKey { SigningKey::from_bytes(&[n; 32]) }
fn scope() -> AnchorIdentity {
    AnchorIdentity {
        anchor_id: id(19), anchor_epoch: 11,
        witness_id: id(17), witness_epoch: 9,
    }
}
fn trust() -> TrustRegistry {
    let mut t = TrustRegistry::new();
    t.enroll(id(21), 3, key(21).verifying_key()).unwrap();
    t.enroll(id(17), 9, key(17).verifying_key()).unwrap();
    t.enroll(id(19), 11, key(19).verifying_key()).unwrap();
    t
}
fn offer(slot: u8, target: u8) -> Vec<u8> {
    custody_transfer_w8::sign_offer(
        OfferClaims {
            source_id: id(21), source_epoch: 3,
            target_id: id(target), target_epoch: if target==13 {7} else {8},
            slot_alias: id(slot), offer_id: id(slot+50),
            ciphertext_digest: [71; 32], expires_at_ms: 500_000,
        }, &key(21),
    ).unwrap()
}
fn signed_cp(witness: &mut WitnessStore, slot: u8, target: u8) -> Vec<u8> {
    match witness.observe(&offer(slot,target), &key(17), &trust()).unwrap() {
        WitnessObservation::FirstSeen(cp) => cp,
        WitnessObservation::Conflict(_) => panic!("unexpected conflicting slot"),
    }
}
async fn endpoint() -> Endpoint {
    Endpoint::builder(presets::Minimal)
        .clear_ip_transports().bind_addr("127.0.0.1:0").unwrap()
        .alpns(vec![GOSSIP_ALPN.to_vec()])
        .bind().await.unwrap()
}
struct AnchorProcess {
    child: Child,
    addr: EndpointAddr,
    dir: TempDir,
}
impl AnchorProcess {
    fn start(mode: &str, left: EndpointId, right: EndpointId) -> Self {
        let dir = tempdir().unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_w11_anchor"))
            .arg(mode).arg(dir.path())
            .arg(left.to_string()).arg(right.to_string())
            .stdout(Stdio::piped()).stderr(Stdio::inherit())
            .spawn().expect("spawn separate anchor OS process");
        let stdout = child.stdout.take().unwrap();
        let mut ready = String::new();
        BufReader::new(stdout).read_line(&mut ready).unwrap();
        let parts = ready.split_whitespace().collect::<Vec<_>>();
        assert_eq!(parts.len(), 3, "bad anchor ready line: {ready}");
        assert_eq!(parts[0], "READY");
        let id: EndpointId = parts[1].parse().unwrap();
        let socket: SocketAddr = parts[2].parse().unwrap();
        assert!(socket.ip().is_loopback());
        Self {
            child,
            addr: EndpointAddr::new(id).with_ip_addr(socket),
            dir,
        }
    }
    fn path(&self, name: &str) -> PathBuf { self.dir.path().join(name) }
}
impl Drop for AnchorProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
async fn rpc(client: &Endpoint, server: &AnchorProcess, request: &[u8]) -> Vec<u8> {
    let conn = tokio::time::timeout(
        Duration::from_secs(10), client.connect(server.addr.clone(), ANCHOR_ALPN),
    ).await.expect("anchor QUIC connect timeout").expect("anchor QUIC handshake");
    assert_eq!(conn.remote_id(), server.addr.id);
    let (mut tx, mut rx) = conn.open_bi().await.unwrap();
    tx.write_all(request).await.unwrap();
    tx.finish().unwrap();
    let reply = tokio::time::timeout(
        Duration::from_secs(5),
        rx.read_to_end(1+CHECKPOINT_LEN+ANCHOR_RECEIPT_LEN),
    ).await.expect("anchor QUIC response timeout").unwrap();
    conn.close(0u32.into(), b"anchor reply read");
    reply
}
async fn store(client: &Endpoint, server: &AnchorProcess, checkpoint: &[u8]) -> Vec<u8> {
    let mut msg = vec![1];
    msg.extend_from_slice(checkpoint);
    rpc(client, server, &msg).await
}
fn anchor_receipt(response: &[u8], checkpoint: &[u8]) -> Vec<u8> {
    assert_eq!(response.len(), 1 + ANCHOR_RECEIPT_LEN);
    assert_eq!(response[0], 0x11);
    let signed = response[1..].to_vec();
    witness_anchor_w11::verify_anchor(&signed, checkpoint, scope(), &trust()).unwrap();
    signed
}
fn latest(response: &[u8]) -> (Vec<u8>, Vec<u8>) {
    assert_eq!(response.len(), 1 + CHECKPOINT_LEN + ANCHOR_RECEIPT_LEN);
    assert_eq!(response[0], 0x21);
    let cp = response[1..1+CHECKPOINT_LEN].to_vec();
    let receipt = response[1+CHECKPOINT_LEN..].to_vec();
    witness_anchor_w11::verify_anchor(&receipt, &cp, scope(), &trust()).unwrap();
    (cp, receipt)
}
/// Real peer-to-peer authenticated QUIC exchanges a signed witness checkpoint
/// AND its separately signed anchor receipt. The remote peer's signature is
/// not used as an authority: verification pins W9 and W11 independent keys.
async fn gossip(from: &Endpoint, to: &Endpoint, bundle: &[u8]) -> Vec<u8> {
    let (client, server) = tokio::join!(
        async {
            tokio::time::timeout(
                Duration::from_secs(10), from.connect(to.addr(), GOSSIP_ALPN),
            ).await.unwrap().unwrap()
        },
        async {
            tokio::time::timeout(
                Duration::from_secs(10),
                async { to.accept().await.unwrap().await },
            ).await.unwrap().unwrap()
        },
    );
    assert_eq!(client.remote_id(), to.id());
    assert_eq!(server.remote_id(), from.id());
    let ((), packet) = tokio::join!(
        async {
            let (mut tx, mut rx) = client.open_bi().await.unwrap();
            tx.write_all(bundle).await.unwrap();
            tx.finish().unwrap();
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(5), rx.read_to_end(1))
                    .await.unwrap().unwrap(),
                vec![1],
            );
            client.close(0u32.into(), b"checkpoint gossip done");
        },
        async {
            let (mut tx, mut rx) = server.accept_bi().await.unwrap();
            let packet = tokio::time::timeout(
                Duration::from_secs(5),
                rx.read_to_end(CHECKPOINT_LEN+ANCHOR_RECEIPT_LEN),
            ).await.unwrap().unwrap();
            tx.write_all(&[1]).await.unwrap();
            tx.finish().unwrap();
            let _ = tokio::time::timeout(Duration::from_secs(2), server.closed()).await;
            packet
        },
    );
    packet
}
fn pack(checkpoint: &[u8], receipt: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(CHECKPOINT_LEN+ANCHOR_RECEIPT_LEN);
    out.extend_from_slice(checkpoint);
    out.extend_from_slice(receipt);
    out
}

#[tokio::test(flavor="multi_thread",worker_threads=2)]
async fn real_quic_independent_anchor_catches_client_pin_rollback() {
    let left = endpoint().await;
    let right = endpoint().await;
    let intruder = endpoint().await;
    let anchor = AnchorProcess::start("honest", left.id(), right.id());
    let dir = tempdir().unwrap();
    let trusted = trust();
    let mut witness = WitnessStore::open(&dir.path().join("w.sqlite"), id(17), 9).unwrap();
    let cp1 = signed_cp(&mut witness, 41, 13);
    let cp2 = signed_cp(&mut witness, 42, 13);
    assert_eq!(rpc(&intruder, &anchor, &[2]).await, vec![255]);
    assert_eq!(rpc(&right, &anchor, &[2]).await, vec![0]);
    let r1 = anchor_receipt(&store(&left, &anchor, &cp1).await, &cp1);
    assert_eq!(latest(&rpc(&right, &anchor, &[2]).await), (cp1.clone(), r1.clone()));
    let r2 = anchor_receipt(&store(&left, &anchor, &cp2).await, &cp2);
    assert_ne!(r1, r2);
    assert_eq!(latest(&rpc(&right, &anchor, &[2]).await), (cp2.clone(), r2.clone()));
    let pin_path = dir.path().join("client.sqlite");
    let mut client_pin = WitnessPinStore::open(&pin_path, id(17), 9).unwrap();
    assert_eq!(client_pin.pin(&cp1, &trusted).unwrap(), PinOutcome::First);
    assert_eq!(client_pin.pin(&cp2, &trusted).unwrap(), PinOutcome::Advanced);
    witness_anchor_w11::require_matched(
        &r2, &cp2, scope(), &client_pin, &trusted,
    ).unwrap();

    // Malicious restore of the LOCAL client pin, but not the remote anchor.
    drop(client_pin);
    let attacker = Sqlite::open(&pin_path).unwrap();
    attacker.execute(
        "UPDATE pinned_witness SET checkpoint=?1 WHERE singleton=1",
        params![cp1.as_slice()],
    ).unwrap();
    drop(attacker);
    let mut client_pin = WitnessPinStore::open(&pin_path, id(17), 9).unwrap();
    // The key fact is fetched over TLS from a separate real OS process.
    let (fresh, signed_anchor) = latest(&rpc(&right, &anchor, &[2]).await);
    assert_eq!(fresh, cp2);
    assert_eq!(signed_anchor, r2);
    assert_eq!(witness_anchor_w11::compare_with_pin(
        &signed_anchor, &fresh, scope(), &client_pin, &trusted,
    ).unwrap(), AnchorComparison::LocalBehind);
    assert!(witness_anchor_w11::require_matched(
        &signed_anchor, &fresh, scope(), &client_pin, &trusted,
    ).is_err());
    // Client replays the actual missing W9 checkpoint, not just some claimed
    // latest sequence number from the network.
    assert_eq!(client_pin.pin(&cp2, &trusted).unwrap(), PinOutcome::Advanced);
    witness_anchor_w11::require_matched(
        &signed_anchor, &fresh, scope(), &client_pin, &trusted,
    ).unwrap();

    let local_anchor = AnchorStore::open(&anchor.path("anchor.sqlite"), scope()).unwrap();
    assert_eq!(local_anchor.latest().unwrap(), Some((cp2, r2)));
}

#[tokio::test(flavor="multi_thread",worker_threads=2)]
async fn malicious_anchor_same_ed25519_signer_split_views_detected_by_peer_quic_gossip() {
    let left = endpoint().await;
    let right = endpoint().await;
    let anchor = AnchorProcess::start("split", left.id(), right.id());
    let dir = tempdir().unwrap();
    let trusted = trust();
    // Malicious witness fork: two valid seq=1 checkpoint statements. Malicious
    // anchor uses THE SAME own signer key but two separate SQLite forks.
    let mut witness_a = WitnessStore::open(&dir.path().join("wa.sqlite"), id(17), 9).unwrap();
    let mut witness_b = WitnessStore::open(&dir.path().join("wb.sqlite"), id(17), 9).unwrap();
    let cp_a = signed_cp(&mut witness_a, 41, 13);
    let cp_b = signed_cp(&mut witness_b, 42, 13);
    let ra = anchor_receipt(&store(&left, &anchor, &cp_a).await, &cp_a);
    let rb = anchor_receipt(&store(&right, &anchor, &cp_b).await, &cp_b);
    assert_eq!(witness_anchor_w11::compare_anchor_receipts(
        (&ra, &cp_a), (&rb, &cp_b), scope(), &trusted,
    ).unwrap(), AnchorGossip::SameHeightEquivocation);
    let received = gossip(&left, &right, &pack(&cp_a, &ra)).await;
    assert_eq!(received, pack(&cp_a, &ra));
    let got_cp = &received[..CHECKPOINT_LEN];
    let got_receipt = &received[CHECKPOINT_LEN..];
    assert_eq!(witness_anchor_w11::compare_anchor_receipts(
        (got_receipt, got_cp), (&rb, &cp_b), scope(), &trusted,
    ).unwrap(), AnchorGossip::SameHeightEquivocation);
    // External gossip reveals incompatible statements of witness+anchor; it
    // cannot stop the malicious operator from hiding another branch.
    assert_eq!(latest(&rpc(&left, &anchor, &[2]).await), (cp_a, ra));
    assert_eq!(latest(&rpc(&right, &anchor, &[2]).await), (cp_b, rb));
}

#[tokio::test(flavor="multi_thread",worker_threads=2)]
async fn persisted_anchor_after_dropped_ack_is_recoverable_but_not_final_delivery() {
    let left = endpoint().await;
    let right = endpoint().await;
    let anchor = AnchorProcess::start("drop-ack", left.id(), right.id());
    let dir = tempdir().unwrap();
    let trusted = trust();
    let mut w = WitnessStore::open(&dir.path().join("w.sqlite"), id(17), 9).unwrap();
    let cp = signed_cp(&mut w, 41, 13);
    // Missing response is ambiguous; source must not automatically refund
    // custody slots or accept the witness as recipient W4.
    let unanswered = store(&left, &anchor, &cp).await;
    assert!(unanswered.is_empty());
    let (returned_cp, receipt) = latest(&rpc(&right, &anchor, &[2]).await);
    assert_eq!(returned_cp, cp);
    witness_anchor_w11::verify_anchor(&receipt, &cp, scope(), &trusted).unwrap();
    let reopened = AnchorStore::open(&anchor.path("anchor.sqlite"), scope()).unwrap();
    assert_eq!(reopened.latest().unwrap(), Some((cp, receipt)));
}
