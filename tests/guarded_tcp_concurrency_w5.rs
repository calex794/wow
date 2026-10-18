//! Real concurrent kernel-TCP clients against one W5 ingress guard and one
//! SQLite Mailbox. Binds only 127.0.0.1; no production session authentication.
use akula_wire_lab::guarded_tcp_w5::{
    serve_guarded_loopback_mailbox_tcp_shared, GuardedTcpClock, GuardedTcpError,
};
use akula_wire_lab::ingress_bridge_w5::IngressOutcome;
use akula_wire_lab::ingress_guard_w5::{AdmissionError, IngressGuard};
use akula_wire_lab::mailbox_w5::{Mailbox, MailboxLimits, PutStatus};
use akula_wire_lab::route_grant_w5::{
    sign_for_lab, RelayGrantClaims, RelayPolicy, SIGNED_GRANT_LEN,
};
use akula_wire_lab::trust_w3::TrustRegistry;
use akula_wire_lab::stream_frame;
use ed25519_dalek::SigningKey;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::tempdir;

fn id(n: u8) -> [u8; 16] { [n; 16] }

fn fixture(packet: &[u8]) -> (Arc<TrustRegistry>, RelayPolicy, Vec<u8>) {
    let issuer = SigningKey::from_bytes(&[10; 32]);
    let mut registry = TrustRegistry::new();
    registry.enroll(id(1), 3, issuer.verifying_key()).unwrap();
    let policy = RelayPolicy {
        issuer_id: id(1),
        relay_id: id(2),
        namespace: id(3),
        route_token: id(4),
    };
    let signed = sign_for_lab(&issuer, RelayGrantClaims {
        issuer_id: policy.issuer_id,
        issuer_epoch: 3,
        relay_id: policy.relay_id,
        namespace: policy.namespace,
        route_token: policy.route_token,
        message_id: id(5),
        expires_at: 200,
        ciphertext_len: u32::try_from(packet.len()).unwrap(),
        ciphertext_digest: *blake3::hash(packet).as_bytes(),
    }).unwrap();
    assert_eq!(signed.len(), SIGNED_GRANT_LEN);
    (Arc::new(registry), policy, signed)
}

fn wire(grant: &[u8], packet: &[u8]) -> Vec<u8> {
    [stream_frame(grant).unwrap(), stream_frame(packet).unwrap()].concat()
}

fn clock() -> GuardedTcpClock {
    GuardedTcpClock {
        monotonic_tick: 0,
        now_seconds: 100,
        read_budget: Duration::from_secs(5),
    }
}

fn init_mailbox(path: &std::path::Path) -> Arc<Mutex<Mailbox>> {
    let mut mail = Mailbox::open_recovery_gated(path, MailboxLimits::default()).unwrap();
    mail.try_resume_after_maintenance().unwrap();
    Arc::new(Mutex::new(mail))
}

fn spawn_handler(
    socket: TcpStream,
    guard: &Arc<Mutex<IngressGuard>>,
    mailbox: &Arc<Mutex<Mailbox>>,
    trust: &Arc<TrustRegistry>,
    policy: RelayPolicy,
) -> thread::JoinHandle<Result<IngressOutcome, GuardedTcpError>> {
    let guard = Arc::clone(guard);
    let mailbox = Arc::clone(mailbox);
    let trust = Arc::clone(trust);
    thread::spawn(move || {
        serve_guarded_loopback_mailbox_tcp_shared(
            socket, &guard, clock(), &mailbox, &policy, &trust,
        )
    })
}

fn await_active(guard: &Arc<Mutex<IngressGuard>>, count: usize) {
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if guard.lock().unwrap().stats().active == count { return; }
        thread::sleep(Duration::from_millis(5));
    }
    panic!("expected {count} live tickets, got {}", guard.lock().unwrap().stats().active);
}

fn await_buffered(guard: &Arc<Mutex<IngressGuard>>, minimum: usize) {
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if guard.lock().unwrap().stats().buffered_bytes >= minimum { return; }
        thread::sleep(Duration::from_millis(5));
    }
    panic!(
        "expected {minimum} buffered grant bytes, got {}",
        guard.lock().unwrap().stats().buffered_bytes
    );
}

#[test]
fn eight_simultaneous_partial_clients_block_ninth_without_locking_sqlite() {
    let tmp = tempdir().unwrap();
    let mailbox = init_mailbox(&tmp.path().join("mail.sqlite"));
    let guard = Arc::new(Mutex::new(IngressGuard::new()));
    let packet = b"one encrypted blob";
    let (trust, policy, signed) = fixture(packet);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();

    let mut blocked_clients = Vec::new();
    let mut blocked_handlers = Vec::new();
    for _ in 0..8 {
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        client.write_all(&[0]).unwrap(); // Only one byte of the 4-byte prefix
        let (accepted, _) = listener.accept().unwrap();
        blocked_handlers.push(spawn_handler(
            accepted, &guard, &mailbox, &trust, policy,
        ));
        blocked_clients.push(client); // Keep the write halves OPEN
    }
    await_active(&guard, 8);
    assert!(mailbox.try_lock().is_ok(), "socket I/O must not lock SQLite");
    assert_eq!(guard.lock().unwrap().stats().buffered_bytes, 0);

    let mut ninth = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    ninth.write_all(&wire(&signed, packet)).unwrap();
    ninth.shutdown(Shutdown::Write).unwrap();
    let (accepted, _) = listener.accept().unwrap();
    let rejected = serve_guarded_loopback_mailbox_tcp_shared(
        accepted, &guard, clock(), &mailbox, &policy, &trust,
    );
    assert!(matches!(
        rejected, Err(GuardedTcpError::Admission(AdmissionError::AtCapacity))
    ));
    let mut no_ack = Vec::new();
    let _ = ninth.read_to_end(&mut no_ack);
    assert!(no_ack.is_empty());
    assert_eq!(mailbox.lock().unwrap().stats().messages, 0);

    // Cancelling slow clients must release all eight slots even when
    // the mailbox has not received any ciphertext.
    drop(blocked_clients);
    for handler in blocked_handlers {
        assert!(matches!(handler.join().unwrap(), Err(GuardedTcpError::Io(_))));
    }
    let stats = guard.lock().unwrap().stats();
    assert_eq!(stats.active, 0);
    assert_eq!(stats.buffered_bytes, 0);
    assert_eq!(stats.attempts_this_tick, 9);

    let mut accepted_client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    accepted_client.write_all(&wire(&signed, packet)).unwrap();
    accepted_client.shutdown(Shutdown::Write).unwrap();
    let (accepted, _) = listener.accept().unwrap();
    assert!(matches!(
        serve_guarded_loopback_mailbox_tcp_shared(
            accepted, &guard, clock(), &mailbox, &policy, &trust
        ),
        Ok(IngressOutcome::MailboxStored(PutStatus::Stored))
    ));
    let mut no_ack = Vec::new();
    accepted_client.read_to_end(&mut no_ack).unwrap();
    assert!(no_ack.is_empty());
    assert_eq!(mailbox.lock().unwrap().stats().messages, 1);
}

#[test]
fn concurrent_identical_signed_packets_commit_once_without_recipient_ack() {
    let tmp = tempdir().unwrap();
    let mailbox = init_mailbox(&tmp.path().join("mail.sqlite"));
    let guard = Arc::new(Mutex::new(IngressGuard::new()));
    let packet = b"immutable ciphertext across all eight sessions";
    let (trust, policy, signed) = fixture(packet);
    let frame = wire(&signed, packet);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let barrier = Arc::new(Barrier::new(9));

    let mut clients = Vec::new();
    let mut handlers = Vec::new();
    for _ in 0..8 {
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        client.write_all(&frame).unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        clients.push(client);
        let (accepted, _) = listener.accept().unwrap();

        let local_guard = Arc::clone(&guard);
        let local_store = Arc::clone(&mailbox);
        let local_trust = Arc::clone(&trust);
        let local_barrier = Arc::clone(&barrier);
        handlers.push(thread::spawn(move || {
            local_barrier.wait();
            serve_guarded_loopback_mailbox_tcp_shared(
                accepted, &local_guard, clock(),
                &local_store, &policy, &local_trust,
            )
        }));
    }
    barrier.wait();
    let mut stored = 0;
    let mut duplicates = 0;
    for handler in handlers {
        match handler.join().unwrap().unwrap() {
            IngressOutcome::MailboxStored(PutStatus::Stored) => stored += 1,
            IngressOutcome::MailboxStored(PutStatus::Duplicate) => duplicates += 1,
            other => panic!("unexpected concurrent TCP result: {other:?}"),
        }
    }
    for mut client in clients {
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).unwrap();
        assert!(reply.is_empty(), "relay must never issue end-recipient ACK");
    }
    assert_eq!((stored, duplicates), (1, 7));
    assert_eq!(mailbox.lock().unwrap().stats().messages, 1);
    let stats = guard.lock().unwrap().stats();
    assert_eq!(stats.active, 0);
    assert_eq!(stats.buffered_bytes, 0);
    assert_eq!(stats.attempts_this_tick, 8);
    assert_eq!(stats.accepted_bytes_this_tick, 8 * SIGNED_GRANT_LEN);
}

#[test]
fn blocked_sqlite_writer_does_not_block_shared_ingress_accounting() {
    let tmp = tempdir().unwrap();
    let mailbox = init_mailbox(&tmp.path().join("mail.sqlite"));
    let guard = Arc::new(Mutex::new(IngressGuard::new()));
    let packet = b"valid ciphertext committed only after writer unlocked";
    let (trust, policy, signed) = fixture(packet);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();

    // This lock represents a slow SQLite transaction/commit.
    let db_busy = mailbox.lock().unwrap();
    let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    client.write_all(&wire(&signed, packet)).unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let (accepted, _) = listener.accept().unwrap();
    let handler = spawn_handler(accepted, &guard, &mailbox, &trust, policy);

    await_buffered(&guard, SIGNED_GRANT_LEN);
    assert_eq!(guard.lock().unwrap().stats().active, 1);
    assert!(guard.try_lock().is_ok(), "storage lock must not hold guard lock");
    drop(db_busy);
    assert!(matches!(
        handler.join().unwrap(),
        Ok(IngressOutcome::MailboxStored(PutStatus::Stored))
    ));
    let mut reply = Vec::new();
    client.read_to_end(&mut reply).unwrap();
    assert!(reply.is_empty());
    assert_eq!(guard.lock().unwrap().stats().active, 0);
    assert_eq!(mailbox.lock().unwrap().stats().messages, 1);
}
