//! W6: real, separate OS receiver for an authenticated Roha/noq Mailbox message.
//!
//! The test uses two independent processes, a real loopback QUIC/TLS socket,
//! pinned endpoint identity, operator-signed enrollment, exact signed grant,
//! persistent SQLite and ciphertext byte-for-byte readback after process exit.
//! No shared Mutex/Arc, TCP shortcuts, or in-process receiver.
//!
//! Test-only fixed keys and a test-only in-memory policy anchor are NOT a
//! physical-host, anti-rollback or public-listener trust boundary.
//! Never expose this fixture to LAN/WAN or real user data.
#![cfg(feature = "iroh-transport")]

#[path = "support/w6_memory_anchor.rs"]
mod w6_memory_anchor;

use akula_wire_lab::{
    anchor_admission_w6::{anchor_incoming_limits, anchor_transport_config},
    crypto_identity_w3::{seal, SignedHeader},
    crypto_w3::new_recipient,
    guarded_tcp_w5::GuardedTcpClock,
    ingress_bridge_w5::IngressOutcome,
    ingress_guard_w5::IngressGuard,
    iroh_mailbox_w6::{
        receive_authenticated_iroh_mailbox, IrohIngressError, IrohMailboxContext,
        W6_LAB_ALPN,
    },
    mailbox_w5::{Mailbox, MailboxLimits, PutStatus},
    peer_enrollment_w6::{
        sign_operator_change, EndpointRouteBinding, OperatorChange,
        PeerEnrollmentDb, PolicyOperation,
    },
    route_grant_w5::{sign_for_lab, RelayGrantClaims, RelayPolicy},
    stream_frame,
    trust_w3::TrustRegistry,
};
use ed25519_dalek::SigningKey;
use iroh::{
    endpoint::{presets, Connection},
    Endpoint, EndpointAddr, SecretKey,
};
use std::{
    fs,
    net::SocketAddr,
    path::Path,
    process::{Child, Command, Stdio},
    sync::Mutex,
    thread,
    time::{Duration, Instant},
};
use tempfile::tempdir;
use w6_memory_anchor::MemoryAnchor;

const CHILD_ROOT: &str = "STAYA_W6_MAILBOX_PROCESS_ROOT";
const READY: &str = "receiver-ready";
const MAX_WAIT: Duration = Duration::from_secs(12);

fn id(x: u8) -> [u8; 16] {
    [x; 16]
}
fn key(x: u8) -> SecretKey {
    SecretKey::from_bytes(&[x; 32])
}
fn signing(x: u8) -> SigningKey {
    SigningKey::from_bytes(&[x; 32])
}
fn route() -> RelayPolicy {
    RelayPolicy {
        issuer_id: id(1),
        relay_id: id(2),
        namespace: id(3),
        route_token: id(4),
    }
}

fn sealed_wire() -> (Vec<u8>, Vec<u8>) {
    // All contents are synthetic. There is no insecure plaintext fallback.
    let (_, recipient) = new_recipient();
    let sealed = seal(
        &signing(12),
        &recipient,
        SignedHeader {
            message_id: id(5),
            recipient_id: id(8),
            expiry: 8000,
            sender_id: id(9),
            epoch: 4,
        },
        b"synthetic W6 two-process encrypted packet",
    )
    .unwrap();
    let scope = route();
    let grant = sign_for_lab(
        &signing(10),
        RelayGrantClaims {
            issuer_id: scope.issuer_id,
            issuer_epoch: 3,
            relay_id: scope.relay_id,
            namespace: scope.namespace,
            route_token: scope.route_token,
            message_id: id(5),
            expires_at: 200,
            ciphertext_len: u32::try_from(sealed.len()).unwrap(),
            ciphertext_digest: *blake3::hash(&sealed).as_bytes(),
        },
    )
    .unwrap();
    let wire = [stream_frame(&grant).unwrap(), stream_frame(&sealed).unwrap()].concat();
    (wire, sealed)
}

fn wait_marker(root: &Path, name: &str) {
    let until = Instant::now() + MAX_WAIT;
    while !root.join(name).exists() {
        assert!(
            Instant::now() < until,
            "independent receiver never produced marker {name}"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

struct ReceiverChild(Option<Child>);
impl Drop for ReceiverChild {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
impl ReceiverChild {
    fn wait_success(&mut self) {
        let until = Instant::now() + MAX_WAIT;
        loop {
            let child = self.0.as_mut().expect("receiver exists");
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success(), "child receiver process failed: {status}");
                self.0.take();
                return;
            }
            assert!(Instant::now() < until, "independent receiver did not exit");
            thread::sleep(Duration::from_millis(10));
        }
    }
}

/// Executed only in a child OS process selected via --exact.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn child_w6_mailbox_receiver_process() {
    let Some(root) = std::env::var_os(CHILD_ROOT) else {
        return;
    };
    let root = std::path::PathBuf::from(root);
    let endpoint = Endpoint::builder(presets::Minimal)
        .clear_ip_transports()
        .bind_addr("127.0.0.1:0")
        .unwrap()
        .secret_key(key(43))
        .alpns(vec![W6_LAB_ALPN.to_vec()])
        .transport_config(anchor_transport_config())
        .server_incoming_limits(anchor_incoming_limits())
        .bind()
        .await
        .unwrap();
    assert!(
        endpoint
            .bound_sockets()
            .iter()
            .all(|addr| addr.ip().is_loopback())
    );
    let bound = *endpoint
        .bound_sockets()
        .iter()
        .find(|addr| addr.is_ipv4())
        .expect("IPv4 loopback receiver");
    let mut devices = TrustRegistry::new();
    devices
        .enroll(id(7), 9, signing(11).verifying_key())
        .unwrap();
    let mut issuers = TrustRegistry::new();
    issuers
        .enroll(id(1), 3, signing(10).verifying_key())
        .unwrap();

    let scope = route();
    let mut policy = PeerEnrollmentDb::open(
        &root.join("peer-policy.sqlite"),
        signing(20).verifying_key(),
    )
    .unwrap();
    let signed_allow = sign_operator_change(
        &signing(20),
        &OperatorChange {
            operation: PolicyOperation::Allow,
            revision: 1,
            binding: EndpointRouteBinding {
                endpoint_id: key(41).public(),
                w3_device_id: id(7),
                w3_epoch: 9,
                relay_id: scope.relay_id,
                namespace: scope.namespace,
                route_token: scope.route_token,
                issuer_id: scope.issuer_id,
            },
        },
    )
    .unwrap();
    policy.apply_signed(&signed_allow).unwrap();

    // For this isolated transport/storage scenario ONLY: not an externally
    // durable authority. RemoteAnchorLedger tests own the real fence contract.
    let anchor = MemoryAnchor::new(policy.checkpoint().unwrap());
    let enrollment = Mutex::new(policy);
    let mut store = Mailbox::open_recovery_gated(
        &root.join("mail.sqlite"),
        MailboxLimits::default(),
    )
    .unwrap();
    store.try_resume_after_maintenance().unwrap();
    let mailbox = Mutex::new(store);
    let guard = Mutex::new(IngressGuard::new());

    fs::write(root.join("receiver-ready.tmp"), bound.to_string()).unwrap();
    fs::rename(root.join("receiver-ready.tmp"), root.join(READY)).unwrap();

    // Three *distinct* TLS connections: unauthorized, stored, identical replay.
    // An intermediate MailboxStored is NOT a recipient delivery receipt.
    for attempt in 0..3u8 {
        let incoming = tokio::time::timeout(Duration::from_secs(8), endpoint.accept())
            .await
            .expect("receiver accept timed out")
            .expect("receiver closed unexpectedly");
        let connection = tokio::time::timeout(Duration::from_secs(8), incoming)
            .await
            .expect("TLS timed out")
            .expect("TLS failed");
        let ctx = IrohMailboxContext {
            local: &endpoint,
            expected_local_id: endpoint.id(),
            enrollments: &enrollment,
            policy_anchor: &anchor,
            devices: &devices,
            issuer_trust: &issuers,
            relay_policy: &scope,
            guard: &guard,
            mailbox: &mailbox,
            clock: GuardedTcpClock {
                monotonic_tick: u64::from(attempt),
                now_seconds: 100,
                read_budget: Duration::from_secs(5),
            },
        };
        let result = receive_authenticated_iroh_mailbox(&connection, ctx).await;
        match attempt {
            0 => assert!(
                matches!(result, Err(IrohIngressError::Enrollment(_))),
                "unauthorized TLS peer must not gain an enrolled W3 device"
            ),
            1 => assert!(
                matches!(
                    result,
                    Ok(IngressOutcome::MailboxStored(PutStatus::Stored))
                ),
                "authorized ciphertext must commit exactly once"
            ),
            _ => assert!(
                matches!(
                    result,
                    Ok(IngressOutcome::MailboxStored(PutStatus::Duplicate))
                ),
                "same ID and exact sealed bytes must be idempotent"
            ),
        }
        assert_eq!(
            mailbox.lock().unwrap().stats().unwrap().messages,
            usize::from(attempt > 0)
        );
        assert_eq!(guard.lock().unwrap().stats().active, 0);
        fs::write(root.join(format!("receiver-completed-{attempt}")), b"done").unwrap();
        drop(connection);
    }
    endpoint.close().await;
}

async fn submit_wire(connection: &Connection, bytes: &[u8]) -> bool {
    let Ok((mut send, _recv)) = connection.open_bi().await else {
        return false;
    };
    send.write_all(bytes).await.is_ok() && send.finish().is_ok()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_os_processes_reject_unauthorized_and_persist_one_verified_ciphertext() {
    let root = tempdir().unwrap();
    let child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "child_w6_mailbox_receiver_process", "--nocapture"])
        .env(CHILD_ROOT, root.path())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let mut child = ReceiverChild(Some(child));
    wait_marker(root.path(), READY);
    let server_address: SocketAddr = fs::read_to_string(root.path().join(READY))
        .unwrap()
        .parse()
        .unwrap();
    assert!(server_address.ip().is_loopback());
    let server = EndpointAddr::new(key(43).public()).with_ip_addr(server_address);
    let (wire, sealed) = sealed_wire();

    for (attempt, identity) in [44u8, 41, 41].into_iter().enumerate() {
        let client = Endpoint::builder(presets::Minimal)
            .clear_ip_transports()
            .bind_addr("127.0.0.1:0")
            .unwrap()
            .secret_key(key(identity))
            .bind()
            .await
            .unwrap();
        let conn = tokio::time::timeout(
            Duration::from_secs(8),
            client.connect(server.clone(), W6_LAB_ALPN),
        )
        .await
        .expect("separate QUIC client timed out")
        .expect("separate QUIC handshake failed");
        assert_eq!(conn.remote_id(), key(43).public());

        // A stolen signed grant cannot authorize the *wrong TLS identity*.
        // The receiver may close before it reads the stranger's stream.
        let sent = tokio::time::timeout(
            Duration::from_secs(3),
            submit_wire(&conn, &wire),
        )
        .await;
        if attempt > 0 {
            assert_eq!(sent.unwrap(), true, "authorized QUIC write failed");
        }
        wait_marker(root.path(), &format!("receiver-completed-{attempt}"));
        drop(conn);
        client.close().await;
    }

    // The independent process has exited. Reopen its on-disk SQLite state
    // rather than trusting a shared in-memory object or a transport ACK.
    child.wait_success();
    let db = Mailbox::open(&root.path().join("mail.sqlite"), MailboxLimits::default()).unwrap();
    assert_eq!(db.stats().unwrap().messages, 1);
    let records = db.get_page(id(4), 101, None, 2).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].id, id(5));
    assert_eq!(records[0].expires_at, 200);
    assert_eq!(records[0].bytes, sealed);
}
