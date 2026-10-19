//! W7/F14: bounded, deterministic malformed UDP ingress against real pinned Roha/noq.
//!
//! This is a loopback-only parser/recovery regression and an OBSERVATIONAL
//! process-resource measurement, not proof of Internet-scale DoS protection.
//! In particular, it does not bound kernel queues or a flood of VALID Initials.
#![cfg(feature = "iroh-transport")]

use akula_wire_lab::anchor_admission_w6::anchor_transport_config;
use akula_wire_lab::remote_anchor_w6::ANCHOR_ALPN;
use iroh::{
    endpoint::{presets, ServerIncomingLimits},
    Endpoint, SecretKey,
};
use std::{net::UdpSocket, time::{Duration, Instant}};

fn key(n: u8) -> SecretKey {
    SecretKey::from_bytes(&[n; 32])
}

/// Linux process-wide resident memory. Never use this approximate metric as a
/// security gate: shared runtime allocations and allocator retention vary.
fn linux_rss_kib() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let s = std::fs::read_to_string("/proc/self/status").ok()?;
        let line = s.lines().find(|line| line.starts_with("VmRSS:"))?;
        line.split_whitespace().nth(1)?.parse().ok()
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// Linux process-wide CPU ticks (utime + stime). Units are deliberately not
/// converted to milliseconds without a platform-specific ticks-per-second.
fn linux_cpu_ticks() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let s = std::fs::read_to_string("/proc/self/stat").ok()?;
        // comm (field 2) may contain spaces and parentheses; use the LAST
        // closing parenthesis. The rest starts at field 3 (state).
        let (_, fields) = s.rsplit_once(") ")?;
        let mut fields = fields.split_whitespace();
        let user: u64 = fields.nth(11)?.parse().ok()?; // field 14, utime
        let system: u64 = fields.next()?.parse().ok()?; // field 15, stime
        user.checked_add(system)
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// Syntactically plausible version-1 Initial with an impossible random AEAD
/// payload. This does NOT contain any usable QUIC crypto frames or secrets.
/// The long header's length covers the packet-number byte and remainder.
fn forged_initial_without_valid_crypto(seed: u8) -> [u8; 1200] {
    let mut packet = [0u8; 1200];
    packet[0] = 0xc0; // long header, Initial, one-byte packet number
    packet[1..5].copy_from_slice(&[0, 0, 0, 1]); // QUIC version 1
    packet[5] = 8; // destination connection ID length
    for (i, byte) in packet[6..14].iter_mut().enumerate() {
        *byte = seed.wrapping_add(i as u8);
    }
    packet[14] = 8; // source connection ID length
    for (i, byte) in packet[15..23].iter_mut().enumerate() {
        *byte = seed.wrapping_add(37).wrapping_add(i as u8);
    }
    packet[23] = 0; // zero-length token
    packet[24] = 0x44; // two-byte QUIC varint: 0x0496 == 1174
    packet[25] = 0x96; // 1200 - 26 = 1174
    packet[26] = seed;
    for (i, byte) in packet[27..].iter_mut().enumerate() {
        *byte = seed.wrapping_mul(17).wrapping_add(i as u8);
    }
    packet
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn malformed_udp_initials_do_not_surface_incoming_and_valid_peer_recovers() {
    let server = Endpoint::builder(presets::Minimal)
        .clear_ip_transports()
        .bind_addr("127.0.0.1:0")
        .unwrap()
        .secret_key(key(43))
        .alpns(vec![ANCHOR_ALPN.to_vec()])
        .transport_config(anchor_transport_config())
        .server_incoming_limits(ServerIncomingLimits::new(2, 4096, 8192).unwrap())
        .bind()
        .await
        .unwrap();

    // Use an actual bound UDP socket, not the advertised or relay address.
    // Refuse ever to send packets to an address other than IPv4 loopback.
    let bound = server.bound_sockets();
    let addr = *bound
        .iter()
        .find(|addr| addr.is_ipv4() && addr.ip().is_loopback())
        .expect("expected IPv4 loopback socket");
    assert!(
        bound.iter().all(|addr| addr.ip().is_loopback()),
        "test must not bind a public network interface"
    );
    let source = UdpSocket::bind("127.0.0.1:0").unwrap();
    source.set_write_timeout(Some(Duration::from_secs(1))).unwrap();

    // Send only structurally impossible packets in this negative gate.
    // A syntactically plausible (but cryptographically invalid) Initial can
    // legitimately surface as Incoming; its rejection happens at handshake.
    const ROUNDS: usize = 96;
    let rss_before = linux_rss_kib();
    let cpu_before = linux_cpu_ticks();
    let started = Instant::now();
    let mut sent = 0usize;
    for n in 0..ROUNDS {
        let mut invalid_fixed_bit = [0u8; 1200];
        invalid_fixed_bit[1199] = n as u8;
        let invalid = [
            &([0u8][..]),
            &([0xc0, 0, 0, 0, 1][..]), // incomplete v1 long header
            &invalid_fixed_bit[..],
        ];
        for packet in invalid {
            assert_eq!(source.send_to(packet, addr).unwrap(), packet.len());
            sent += 1;
        }
        if n % 16 == 0 {
            tokio::task::yield_now().await;
        }
    }

    assert!(
        tokio::time::timeout(Duration::from_millis(400), server.accept())
            .await
            .is_err(),
        "structurally invalid UDP was surfaced as a transport Incoming"
    );
    let wall_ms = started.elapsed().as_millis();
    let rss_after = linux_rss_kib();
    let cpu_after = linux_cpu_ticks();
    let cpu_delta = cpu_before.zip(cpu_after).map(|(a, b)| b.saturating_sub(a));
    eprintln!(
        "W7_UDP_INITIAL_PRESSURE packets={sent} wall_ms={wall_ms} cpu_ticks_delta={cpu_delta:?} rss_kib_before={rss_before:?} rss_kib_after={rss_after:?} bind=loopback verdict=structural_invalid_rejected"
    );

    // Positive control: reject-only or broken servers must NOT pass. Keep the
    // real client alive until the server has finished TLS authentication.
    let client = Endpoint::builder(presets::Minimal)
        .clear_ip_transports()
        .bind_addr("127.0.0.1:0")
        .unwrap()
        .secret_key(key(50))
        .bind()
        .await
        .unwrap();
    let client_ep = client.clone();
    let server_addr = server.addr();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
    let peer = tokio::spawn(async move {
        let result = client_ep.connect(server_addr, ANCHOR_ALPN).await;
        let _ = release_rx.await;
        result.map(|_| ())
    });
    let pending = tokio::time::timeout(Duration::from_secs(5), server.accept())
        .await
        .expect("valid Initial not admitted after invalid ingress")
        .expect("server endpoint closed");
    let connected = tokio::time::timeout(Duration::from_secs(5), pending)
        .await
        .expect("valid TLS handshake timed out")
        .expect("valid TLS handshake failed");
    assert_eq!(connected.remote_id(), key(50).public());
    drop(connected);
    let _ = release_tx.send(());
    assert!(peer.await.unwrap().is_ok(), "valid QUIC client failed");
    client.close().await;
    server.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn syntactically_valid_but_unauthenticated_initial_is_not_an_authenticated_peer() {
    // Security boundary: surfacing an Incoming is not TLS acceptance.
    // The previous test falsely treated all Incoming as authenticated.
    let server = Endpoint::builder(presets::Minimal)
        .clear_ip_transports()
        .bind_addr("127.0.0.1:0")
        .unwrap()
        .secret_key(key(43))
        .alpns(vec![ANCHOR_ALPN.to_vec()])
        .transport_config(anchor_transport_config())
        .server_incoming_limits(ServerIncomingLimits::new(1, 4096, 4096).unwrap())
        .bind()
        .await
        .unwrap();
    let addr = *server
        .bound_sockets()
        .iter()
        .find(|addr| addr.is_ipv4() && addr.ip().is_loopback())
        .expect("loopback only");
    let raw = UdpSocket::bind("127.0.0.1:0").unwrap();
    let invalid_crypto = forged_initial_without_valid_crypto(17);
    assert_eq!(raw.send_to(&invalid_crypto, addr).unwrap(), invalid_crypto.len());

    // Both results are allowed: parser-level drop, or a pending Incoming
    // that can NEVER become a successfully authenticated TLS Connection.
    // Keep this gate bounded even if an unauthenticated peer never responds.
    let surfaced = match tokio::time::timeout(
        Duration::from_millis(500),
        server.accept(),
    ).await {
        Err(_) => false, // rejected before Incoming
        Ok(Some(pending)) => {
            let result = tokio::time::timeout(
                Duration::from_millis(300), pending
            ).await;
            assert!(
                !matches!(result, Ok(Ok(_))),
                "forged unauthenticated Initial completed QUIC/TLS"
            );
            true
        }
        Ok(None) => panic!("server closed after one invalid Initial"),
    };
    eprintln!(
        "W7_FORGED_INITIAL_AUTH invalid_initials=1 surfaced_pending={surfaced} authenticated=0 max_pending=1"
    );

    // One real independent endpoint must still succeed afterward.
    let client = Endpoint::builder(presets::Minimal)
        .clear_ip_transports()
        .bind_addr("127.0.0.1:0")
        .unwrap()
        .secret_key(key(51))
        .bind()
        .await
        .unwrap();
    let src = client.clone();
    let server_addr = server.addr();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
    let peer = tokio::spawn(async move {
        let outcome = src.connect(server_addr, ANCHOR_ALPN).await;
        let _ = release_rx.await;
        outcome.map(|_| ())
    });
    let pending = tokio::time::timeout(Duration::from_secs(5), server.accept())
        .await.expect("genuine Initial not admitted").expect("closed");
    let connection = tokio::time::timeout(Duration::from_secs(5), pending)
        .await.expect("genuine handshake timeout").expect("invalid genuine handshake");
    assert_eq!(connection.remote_id(), key(51).public());
    drop(connection);
    let _ = release_tx.send(());
    assert!(peer.await.unwrap().is_ok());
    client.close().await;
    server.close().await;
}


#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn burst_of_genuine_quic_initials_obeys_pending_cap_then_recovers() {
    // W7/F14 follow-up to W6's single-pending gate: multiple real client
    // QUIC Initials, not forged UDP payloads. Every endpoint is loopback
    // only, and the number of clients and test duration are fixed.
    const MAX_PENDING: usize = 2;
    const CONTENDERS: usize = 8;
    let server = Endpoint::builder(presets::Minimal)
        .clear_ip_transports()
        .bind_addr("127.0.0.1:0")
        .unwrap()
        .secret_key(key(43))
        .alpns(vec![ANCHOR_ALPN.to_vec()])
        .transport_config(anchor_transport_config())
        .server_incoming_limits(
            ServerIncomingLimits::new(MAX_PENDING, 4096, 8192).unwrap(),
        )
        .bind()
        .await
        .unwrap();
    assert!(
        server.bound_sockets().iter().all(|addr| addr.ip().is_loopback()),
        "no public listener is permitted in the pressure lab"
    );
    let server_addr = server.addr();
    let rss_before = linux_rss_kib();
    let cpu_before = linux_cpu_ticks();
    let started = Instant::now();

    // Deliberately keep two real transport Incoming objects unaccepted.
    // Neither one has passed TLS authentication yet.
    let mut held = Vec::new();
    let mut holders = Vec::new();
    for n in 0..MAX_PENDING {
        let client = Endpoint::builder(presets::Minimal)
            .clear_ip_transports()
            .bind_addr("127.0.0.1:0")
            .unwrap()
            .secret_key(key(60 + n as u8))
            .bind()
            .await
            .unwrap();
        let client_ep = client.clone();
        let addr = server_addr.clone();
        let task = tokio::spawn(async move {
            let _ = client_ep.connect(addr, ANCHOR_ALPN).await;
        });
        let incoming = tokio::time::timeout(Duration::from_secs(5), server.accept())
            .await
            .expect("genuine QUIC Initial did not reach the server")
            .expect("server stopped accepting");
        held.push(incoming);
        holders.push((client, task));
    }
    assert_eq!(held.len(), MAX_PENDING);

    // Eight independent, valid Iroh clients now compete for capacity.
    // None can surface another Pending Incoming while both slots are held.
    let mut contenders = Vec::new();
    for n in 0..CONTENDERS {
        let client = Endpoint::builder(presets::Minimal)
            .clear_ip_transports()
            .bind_addr("127.0.0.1:0")
            .unwrap()
            .secret_key(key(70 + n as u8))
            .bind()
            .await
            .unwrap();
        let client_ep = client.clone();
        let addr = server_addr.clone();
        let task = tokio::spawn(async move {
            let _ = client_ep.connect(addr, ANCHOR_ALPN).await;
        });
        contenders.push((client, task));
    }
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(500), server.accept())
            .await
            .is_err(),
        "a third Incoming bypassed max_incoming=2 during genuine Initial burst"
    );

    let wall_ms = started.elapsed().as_millis();
    let rss_after = linux_rss_kib();
    let cpu_after = linux_cpu_ticks();
    let cpu_delta = cpu_before
        .zip(cpu_after)
        .map(|(before, after)| after.saturating_sub(before));
    eprintln!(
        "W7_VALID_INITIAL_PRESSURE held={MAX_PENDING} competing={CONTENDERS} \
         wall_ms={wall_ms} cpu_ticks_delta={cpu_delta:?} \
         rss_kib_before={rss_before:?} rss_kib_after={rss_after:?} \
         listener=loopback verdict=pending_cap_observed"
    );

    // Close all refused peers BEFORE releasing the two pending slots.
    // Otherwise their automatic QUIC retransmissions could legitimately
    // grab newly freed capacity and make the recovery assertion race.
    for (client, task) in contenders {
        task.abort();
        client.close().await;
    }
    for (client, task) in holders {
        task.abort();
        client.close().await;
    }
    drop(held);

    // Independent positive control: a new, genuinely authenticated peer
    // must still be able to connect after the pending slots are released.
    let client = Endpoint::builder(presets::Minimal)
        .clear_ip_transports()
        .bind_addr("127.0.0.1:0")
        .unwrap()
        .secret_key(key(90))
        .bind()
        .await
        .unwrap();
    let client_ep = client.clone();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
    let peer = tokio::spawn(async move {
        let result = client_ep.connect(server_addr, ANCHOR_ALPN).await;
        let _ = release_rx.await;
        result.map(|_| ())
    });
    let pending = tokio::time::timeout(Duration::from_secs(5), server.accept())
        .await
        .expect("fresh Initial blocked after pending capacity was released")
        .expect("server closed after pressure");
    let connected = tokio::time::timeout(Duration::from_secs(5), pending)
        .await
        .expect("fresh TLS handshake timed out")
        .expect("fresh TLS handshake failed");
    assert_eq!(connected.remote_id(), key(90).public());
    drop(connected);
    let _ = release_tx.send(());
    assert!(peer.await.unwrap().is_ok(), "recovery client failed");
    client.close().await;
    server.close().await;
}
