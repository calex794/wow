//! Separate lab crate against the TEMPORARILY patched, pinned Roha
//! worktree. It is not part of normal wow builds using the original
//! Git dependency until the audited patch is merged upstream.
use iroh::{
    endpoint::{ServerIncomingLimits, ServerIncomingLimitsError, presets},
    Endpoint, SecretKey,
};
use std::time::Duration;

#[test]
fn quotas_reject_zero_or_inconsistent_buffer_budgets() {
    assert_eq!(
        ServerIncomingLimits::new(0, 4096, 8192),
        Err(ServerIncomingLimitsError::Zero)
    );
    assert_eq!(
        ServerIncomingLimits::new(2, 8192, 4096),
        Err(ServerIncomingLimitsError::TotalBelowPerIncoming)
    );
    let q = ServerIncomingLimits::new(2, 4096, 8192).unwrap();
    assert_eq!((q.max_incoming(), q.per_incoming_bytes(), q.total_incoming_bytes()), (2, 4096, 8192));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn protected_endpoint_binds_and_rebuilds_alpn_without_breaking_tls() {
    let limits = ServerIncomingLimits::new(2, 4096, 8192).unwrap();
    let alpn = b"wow/w6/preincoming-probe".to_vec();
    let server = Endpoint::builder(presets::Minimal)
        .clear_ip_transports()
        .bind_addr("127.0.0.1:0").unwrap()
        .secret_key(SecretKey::from_bytes(&[43; 32]))
        .alpns(vec![b"wow/preincoming/old".to_vec()])
        .server_incoming_limits(limits)
        .bind().await.unwrap();
    // Roha set_alpns() reconstructs the underlying noq server config.
    // Our limits must be reapplied in StaticConfig::create_server_config.
    server.set_alpns(vec![alpn.clone()]);
    let reader = Endpoint::builder(presets::Minimal)
        .clear_ip_transports()
        .bind_addr("127.0.0.1:0").unwrap()
        .secret_key(SecretKey::from_bytes(&[41; 32]))
        .bind().await.unwrap();
    let expected_reader = reader.id();
    let host = server.clone();
    let responder = tokio::spawn(async move {
        let incoming = tokio::time::timeout(Duration::from_secs(8), host.accept())
            .await.unwrap().unwrap();
        let accepted = tokio::time::timeout(Duration::from_secs(8), incoming)
            .await.unwrap().unwrap();
        assert_eq!(accepted.remote_id(), expected_reader);
    });
    let accepted = tokio::time::timeout(
        Duration::from_secs(8),
        reader.connect(server.addr(), &alpn),
    ).await.unwrap().unwrap();
    assert_eq!(accepted.remote_id(), server.id());
    responder.await.unwrap();
    drop(accepted);
    reader.close().await;
    server.close().await;
}
