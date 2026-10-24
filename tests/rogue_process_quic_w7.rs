//! W7-CUST-BYZ-02: a SEPARATE intentionally modified custodian OS process
//! over real Roha/noq QUIC/TLS on loopback, with independently pinned IDs.
//! This does not test two physical hosts or a production W6 RelayGrant.
//! It shows trust boundaries even when the custodian has a legitimate key.
#![cfg(feature = "iroh-transport")]

use akula_wire_lab::crypto_identity_w3::{SignedHeader, TrustedRecipient};
use akula_wire_lab::crypto_w3::new_recipient;
use akula_wire_lab::custody_audit_w7::{AuditError, AuditReference};
use akula_wire_lab::custodian_evidence_bridge::{
    LocalEvidenceContext, ServiceIdentity,
};
use akula_wire_lab::custodian_observation::{
    AppendResult, LocalObservationStore, ServiceRole,
};
use akula_wire_lab::custodian_w7_quic_lab::{
    audit_and_record, LabAuditError, LabAuditOutcome, LabAuditRequest,
    SignedEndpointBinding, LAB_W7_ALPN,
};
use akula_wire_lab::custody_receipt_w6::{self, ExpectedCustody};
use akula_wire_lab::journal_w4::{Delivery, Insert, Journal};
use akula_wire_lab::private_route_w3::{open_authenticated, seal_private};
use akula_wire_lab::receipt_w4::{self, ReceiptError};
use akula_wire_lab::trust_w3::TrustRegistry;
use ed25519_dalek::SigningKey;
use iroh::{Endpoint, EndpointAddr, EndpointId, endpoint::presets};
use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use tempfile::{tempdir, TempDir};

const ALPN: &[u8] = LAB_W7_ALPN;
const AUDIT_CAP: [u8; 16] = [22; 16];
const RECIPIENT_CAP: [u8; 16] = [23; 16];
fn id(n: u8) -> [u8; 16] { [n; 16] }
fn key(n: u8) -> SigningKey { SigningKey::from_bytes(&[n; 32]) }

async fn bind_client() -> Endpoint {
    Endpoint::builder(presets::Minimal)
        .clear_ip_transports()
        .bind_addr("127.0.0.1:0").unwrap()
        .bind().await.unwrap()
}

struct Rogue {
    process: Child,
    addr: EndpointAddr,
    binding: SignedEndpointBinding,
    _dir: TempDir,
}
impl Rogue {
    fn start(mode: &str, sender: EndpointId, auditor: EndpointId, bob: EndpointId) -> Self {
        let dir = tempdir().unwrap();
        let mut process = Command::new(env!("CARGO_BIN_EXE_w7_rogue_custodian"))
            .arg(mode)
            .arg(dir.path().join("custodian.sqlite"))
            .arg(sender.to_string())
            .arg(auditor.to_string())
            .arg(bob.to_string())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn().expect("spawn separate modified custodian process");
        let output = process.stdout.take().expect("ready output");
        let mut line = String::new();
        BufReader::new(output).read_line(&mut line)
            .expect("custodian must announce ready endpoint");
        let fields = line.split_whitespace().collect::<Vec<_>>();
        assert_eq!(fields.first().copied(), Some("READY"), "{mode}: {line}");
        assert_eq!(fields.len(), 4, "{mode}: {line}");
        let endpoint_id: EndpointId = fields[1].parse().unwrap();
        let socket: SocketAddr = fields[2].parse().unwrap();
        assert!(socket.ip().is_loopback());
        let hex = fields[3].as_bytes();
        assert_eq!(hex.len(), 128, "signed TLS binding must contain 64 bytes");
        let mut signature = [0u8; 64];
        for (position, pair) in hex.chunks_exact(2).enumerate() {
            signature[position] = u8::from_str_radix(
                std::str::from_utf8(pair).unwrap(), 16,
            ).unwrap();
        }
        let binding = SignedEndpointBinding {
            service_id: id(13), service_epoch: 7,
            endpoint_id, signature,
        };
        let addr = EndpointAddr::new(endpoint_id).with_ip_addr(socket);
        Self { process, addr, binding, _dir: dir }
    }

    fn db_path(&self) -> &Path {
        self._dir.path()
    }
}
impl Drop for Rogue {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

/// Every request establishes fresh authenticated Roha/noq QUIC/TLS state and
/// independently verifies the server's pinned EndpointId. The server must
/// independently pin the sender/auditor/recipient EndpointIds.
async fn rpc(endpoint: &Endpoint, rogue: &Rogue, payload: &[u8]) -> Vec<u8> {
    let conn = tokio::time::timeout(Duration::from_secs(10),
        endpoint.connect(rogue.addr.clone(), ALPN))
        .await.expect("QUIC connect timeout").expect("QUIC handshake failed");
    assert_eq!(conn.remote_id(), rogue.addr.id);
    let (mut tx, mut rx) = conn.open_bi().await.unwrap();
    tx.write_all(payload).await.unwrap();
    tx.finish().unwrap();
    let response = tokio::time::timeout(
        Duration::from_secs(5),
        rx.read_to_end(akula_wire_lab::MAX_MESSAGE_BYTES + 512),
    ).await.expect("QUIC fetch deadline").expect("QUIC response read failed");
    // QUIC application close marks the response as read; allow the
    // independent server process to finish its connection cleanly.
    conn.close(0u32.into(), b"response consumed");
    response
}

/// No application data is sent to untrusted custodians in plaintext.
fn make_packet() -> (Vec<u8>, akula_wire_lab::crypto_w3::RecipientSecret) {
    let (secret, public) = new_recipient();
    let packet = seal_private(
        &key(9), &public, id(4),
        SignedHeader {
            message_id: id(5), recipient_id: id(8),
            expiry: 500_000, sender_id: id(9), epoch: 4,
        },
        b"genuine encrypted private WOW message",
    ).unwrap();
    (packet, secret)
}

fn trust() -> TrustRegistry {
    let mut registry = TrustRegistry::new();
    registry.enroll(id(9), 4, key(9).verifying_key()).unwrap();
    registry.enroll(id(8), 6, key(8).verifying_key()).unwrap();
    registry.enroll(id(13), 7, key(13).verifying_key()).unwrap();
    registry
}

fn store_frame(packet: &[u8]) -> Vec<u8> {
    let mut out = vec![1];
    out.extend_from_slice(&id(4));
    out.extend_from_slice(&id(5));
    out.extend_from_slice(packet);
    out
}

fn refetched(response: &[u8]) -> Option<&[u8]> {
    match response.split_first() {
        Some((2, data)) => Some(data),
        Some((0, [])) => None,
        otherwise => panic!("unexpected test-only FETCH response: {otherwise:?}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn separate_hostile_process_over_real_quic_does_not_steal_recipient_authority() {
    for mode in ["fake", "delete", "censor", "corrupt", "honest", "drop-ack"] {
        let source = bind_client().await;
        let auditor = bind_client().await;
        let bob_endpoint = bind_client().await;
        let stranger = bind_client().await;
        let rogue = Rogue::start(mode, source.id(), auditor.id(), bob_endpoint.id());
        assert_ne!(rogue.addr.id, source.id());
        assert_ne!(rogue.addr.id, auditor.id());
        assert_ne!(source.id(), bob_endpoint.id());

        let (packet, recipient_secret) = make_packet();
        let reference = AuditReference::from_trusted_ciphertext(&packet).unwrap();
        let trust = trust();
        let work = tempdir().unwrap();
        let mut alice = Journal::open(&work.path().join("sender.sqlite")).unwrap();
        alice.enqueue(id(8), id(5), 500_000, &packet).unwrap();
        assert_eq!(alice.state(id(8), id(5)).unwrap(), Delivery::Queued);

        let stored = rpc(&source, &rogue, &store_frame(&packet)).await;
        if mode == "drop-ack" {
            // No receipt is not proof of no write: C can keep actual bytes.
            assert!(stored.is_empty(), "lost ACK should not claim success");
        } else {
            assert_eq!(stored.first().copied(), Some(1), "{mode}");
            let proof = &stored[1..];
            let verified = custody_receipt_w6::verify(
                proof, ExpectedCustody {
                    custodian_id: id(13), slot_id: id(41),
                    message_id: id(5), ciphertext: &packet,
                    now_ms: 100_000,
                }, &trust,
            ).unwrap();
            assert_eq!(verified.ciphertext_digest(), *blake3::hash(&packet).as_bytes());
            assert!(matches!(receipt_w4::verify(proof, &trust),
                Err(ReceiptError::InvalidLength)));
        }
        if mode == "fake" {
            assert!(!rogue.db_path().join("custodian.sqlite").exists(),
                "fake-store must never write a local data file");
        }

        // Capability and authenticated TLS identity are both required:
        // route tag / correct read token alone are NOT read authority.
        let mut read_req = vec![3];
        read_req.extend_from_slice(&RECIPIENT_CAP);
        assert_eq!(rpc(&stranger, &rogue, &read_req).await, vec![255]);
        assert_eq!(rpc(&auditor, &rogue, &read_req).await, vec![255]);
        let mut wrong_cap = vec![3];
        wrong_cap.extend_from_slice(&[4; 16]); // public route token!
        assert_eq!(rpc(&bob_endpoint, &rogue, &wrong_cap).await, vec![255]);
        let mut audit_req = vec![2];
        audit_req.extend_from_slice(&AUDIT_CAP);
        assert_eq!(rpc(&source, &rogue, &audit_req).await, vec![255]);

        // Custodian's separate Ed25519 key cannot forge Bob's signed W4,
        // even when his own valid storage proof arrived on genuine QUIC.
        let fake_w4 = rpc(&source, &rogue, &[4]).await;
        assert_eq!(fake_w4.first().copied(), Some(3));
        assert!(matches!(receipt_w4::verify(&fake_w4[1..], &trust),
            Err(ReceiptError::InvalidSignature)));
        assert_eq!(alice.state(id(8), id(5)).unwrap(), Delivery::Queued);

        let audit = rpc(&auditor, &rogue, &audit_req).await;
        let availability = reference.observe(refetched(&audit), 100_010);
        match mode {
            "fake" | "delete" => assert_eq!(availability, Err(AuditError::Unavailable)),
            "corrupt" => assert_eq!(availability, Err(AuditError::WrongCiphertext)),
            "censor" | "honest" | "drop-ack" => assert!(availability.is_ok()),
            _ => unreachable!(),
        }
        // P0-4: the separately authenticated network response, rather than
        // arbitrary locally supplied bytes, enters the VERIFIED journal.
        let observer_key = key(31);
        let context = LocalEvidenceContext::bind(
            ServiceIdentity {
                id: id(13), epoch: 7, role: ServiceRole::Public,
            },
            &observer_key, 1, id(91), 100_010, &trust,
        ).unwrap();
        let mut service_events = LocalObservationStore::open(
            &work.path().join("private-audit.sqlite"),
        ).unwrap();

        // An altered custodian->EndpointId signature or wrong locally pinned
        // TLS endpoint must be rejected BEFORE issuing a QUIC request.
        let mut forged_binding = rogue.binding.clone();
        forged_binding.signature[0] ^= 1;
        let bad_signature = audit_and_record(
            &mut service_events, &context, &trust,
            LabAuditRequest {
                client: &auditor, address: rogue.addr.clone(),
                expected_pinned_endpoint: rogue.addr.id,
                signed_binding: &forged_binding,
                audit_cap: AUDIT_CAP,
                trusted_reference: &reference,
            },
        ).await;
        assert!(matches!(bad_signature, Err(LabAuditError::InvalidBinding)));
        let wrong_pin = audit_and_record(
            &mut service_events, &context, &trust,
            LabAuditRequest {
                client: &auditor, address: rogue.addr.clone(),
                expected_pinned_endpoint: stranger.id(),
                signed_binding: &rogue.binding,
                audit_cap: AUDIT_CAP,
                trusted_reference: &reference,
            },
        ).await;
        assert!(matches!(wrong_pin, Err(LabAuditError::InvalidBinding)));

        // Even the correct private AUDIT cap is rejected when the TLS client
        // has a different EndpointId; source cannot impersonate the auditor.
        let wrong_client = audit_and_record(
            &mut service_events, &context, &trust,
            LabAuditRequest {
                client: &source, address: rogue.addr.clone(),
                expected_pinned_endpoint: rogue.addr.id,
                signed_binding: &rogue.binding,
                audit_cap: AUDIT_CAP,
                trusted_reference: &reference,
            },
        ).await.unwrap();
        assert_eq!(wrong_client, LabAuditOutcome::Rejected);

        let real = audit_and_record(
            &mut service_events, &context, &trust,
            LabAuditRequest {
                client: &auditor, address: rogue.addr.clone(),
                expected_pinned_endpoint: rogue.addr.id,
                signed_binding: &rogue.binding,
                audit_cap: AUDIT_CAP,
                trusted_reference: &reference,
            },
        ).await.unwrap();
        match mode {
            "fake" | "delete" =>
                assert_eq!(real, LabAuditOutcome::Unavailable),
            "corrupt" =>
                assert_eq!(real, LabAuditOutcome::UnattributedMismatch),
            "censor" | "honest" | "drop-ack" =>
                assert_eq!(real, LabAuditOutcome::ExactBytes(AppendResult::Stored)),
            _ => unreachable!(),
        }
        let score = service_events.verified_report(
            context.scope(), 100_010,
        ).unwrap();
        let successes = u64::from(matches!(real, LabAuditOutcome::ExactBytes(_)));
        assert_eq!(score.last_24h.storage.successes, successes);
        assert_eq!(score.last_24h.storage.failures, 0);
        assert_eq!(score.last_24h.recipient_w4_observations, 0);

        // Repeated authenticated observations of the same W3 in one local
        // day are idempotent, even with a new event sequence and TLS session.
        if successes == 1 {
            let second_ctx = LocalEvidenceContext::bind(
                ServiceIdentity { id: id(13), epoch: 7, role: ServiceRole::Public },
                &observer_key, 2, id(92), 100_012, &trust,
            ).unwrap();
            assert_eq!(
                audit_and_record(
                    &mut service_events, &second_ctx, &trust,
                    LabAuditRequest {
                        client: &auditor, address: rogue.addr.clone(),
                        expected_pinned_endpoint: rogue.addr.id,
                        signed_binding: &rogue.binding,
                        audit_cap: AUDIT_CAP, trusted_reference: &reference,
                    },
                ).await.unwrap(),
                LabAuditOutcome::ExactBytes(AppendResult::ExactReplay)
            );
            assert_eq!(service_events.verified_report(
                context.scope(), 100_012,
            ).unwrap().last_24h.storage.eligible, 1);
        }

        // Even a successful independent audit cannot advance Alice to W4.
        assert_eq!(alice.state(id(8), id(5)).unwrap(), Delivery::Queued);

        let delivered = rpc(&bob_endpoint, &rogue, &read_req).await;
        let fetched = refetched(&delivered);
        match mode {
            "honest" | "drop-ack" => {
                let bytes = fetched.expect("honest or lost-ACK record should still exist");
                assert_eq!(bytes, packet);
                assert!(reference.observe(Some(bytes), 100_011).is_ok());
                let authenticated = open_authenticated(
                    bytes, TrustedRecipient {
                        secret: &recipient_secret, recipient_id: id(8),
                        now: 100_000, registry: &trust,
                    }, id(4),
                ).unwrap();
                assert_eq!(authenticated.payload(), b"genuine encrypted private WOW message");
                let mut recipient = Journal::open(
                    &work.path().join("recipient.sqlite"),
                ).unwrap();
                let (insert, signed_w4) = recipient
                    .accept_private_authenticated_and_queue_receipt(
                        bytes, TrustedRecipient {
                            secret: &recipient_secret, recipient_id: id(8),
                            now: 100_000, registry: &trust,
                        }, id(4), &key(8), 6,
                    ).unwrap();
                assert_eq!(insert, Insert::New);
                let final_ack = receipt_w4::verify(&signed_w4, &trust).unwrap();
                assert_eq!(final_ack.packet_digest(), *blake3::hash(&packet).as_bytes());
                assert_eq!(alice.apply_recipient_receipt(&final_ack).unwrap(),
                    Delivery::Recipient);
            }
            "corrupt" => {
                let bytes = fetched.expect("corrupt mode returns tampered bytes");
                assert_eq!(reference.observe(Some(bytes), 100_011),
                    Err(AuditError::WrongCiphertext));
                assert!(open_authenticated(
                    bytes, TrustedRecipient {
                        secret: &recipient_secret, recipient_id: id(8),
                        now: 100_000, registry: &trust,
                    }, id(4),
                ).is_err());
            }
            "censor" | "fake" | "delete" => {
                assert!(fetched.is_none(), "attacking node must block recipient");
            }
            _ => unreachable!(),
        }
        if mode == "honest" || mode == "drop-ack" {
            assert_eq!(alice.state(id(8), id(5)).unwrap(), Delivery::Recipient);
            assert!(alice.retry_bytes(id(8), id(5), 101).unwrap().is_none());
        } else {
            assert_eq!(alice.state(id(8), id(5)).unwrap(), Delivery::Queued);
            assert_eq!(alice.retry_bytes(id(8), id(5), 101).unwrap(),
                Some(packet.clone()));
        }
        drop(rogue); // Kill the separate intentionally modified OS process.
    }
}
