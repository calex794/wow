// This Rust source is appended only to the temporary pinned-source test
// checkout in CI. It is not production code and does not ship in noq.
// Regression scenario: asymmetric path keepalives, no application traffic.
#[test]
fn fork_audit_secondary_path_survives_asymmetric_keepalives() -> TestResult {
    let _guard = subscribe();
    let mut builder = ConnPair::builder().enable_multipath();
    let client_interval = Duration::from_millis(900);
    let server_interval = Duration::from_millis(1000);
    builder
        .client_transport_cfg
        .default_path_keep_alive_interval(Some(client_interval));
    builder
        .server_transport_cfg
        .default_path_keep_alive_interval(Some(server_interval));
    builder
        .client_transport_cfg
        .default_path_max_idle_timeout(Some(Duration::from_secs(3)));
    builder
        .server_transport_cfg
        .default_path_max_idle_timeout(Some(Duration::from_secs(3)));

    let mut pair = builder.connect();
    let remote = pair.routes.public_server_addr();
    let secondary = pair.open_path(
        Client,
        FourTuple::from_remote(remote),
        PathStatus::Available,
    )?;
    pair.drive_bounded(50);
    assert_matches!(
        pair.poll(Client),
        Some(Event::Path(PathEvent::Established { id })) if id == secondary
    );
    assert_matches!(
        pair.poll(Server),
        Some(Event::Path(PathEvent::Established { id })) if id == secondary
    );
    let start = pair.time;
    let mut steps = 0usize;
    while pair.time - start < Duration::from_secs(12) {
        if !pair.step() {
            assert!(pair.advance_time(), "no pending timer during keepalive");
        }
        steps += 1;
        assert!(steps < 5000, "event loop failed to advance");
        for side in [Client, Server] {
            while let Some(event) = pair.poll(side) {
                assert!(
                    !matches!(event, Event::Path(PathEvent::Abandoned { .. })),
                    "fork audit: secondary path abandoned during keepalive-only traffic: {event:?}"
                );
            }
        }
    }
    assert!(!pair.is_closed(Client) && !pair.is_closed(Server));
    Ok(())
}
