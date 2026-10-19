// Append to the pinned noq-proto/src/tests/multipath.rs in the isolated audit
// checkout only. The peer never learns about this candidate path, so it
// cannot echo PATH_ABANDON. Local close must eventually reclaim its state.
#[test]
fn fork_audit_abandoned_unseen_path_must_be_discarded() -> TestResult {
    let _guard = subscribe();
    let mut pair = ConnPair::builder().enable_multipath().connect();
    let mut second_client_addr = pair.routes.as_basic().client_addr;
    let mut second_server_addr = pair.routes.as_basic().server_addr;
    second_client_addr.set_port(second_client_addr.port() + 1);
    second_server_addr.set_port(second_server_addr.port() + 1);
    pair.routes = ManyToManyRouting::simple_symmetric(
        [pair.routes.as_basic().client_addr, second_client_addr],
        [pair.routes.as_basic().server_addr, second_server_addr],
    )
    .into();

    let unknown_path = FourTuple {
        local_ip: Some(second_client_addr.ip()),
        remote: second_server_addr,
    };
    let id = pair.open_path(Client, unknown_path, PathStatus::Available)?;
    pair.close_path(Client, id, 0u8.into())?;
    pair.drive();

    assert_matches!(
        pair.poll(Client),
        Some(Event::Path(PathEvent::Abandoned { id: abandoned, .. }))
            if abandoned == id
    );

    let mut discarded = false;
    while let Some(event) = pair.poll(Client) {
        if matches!(event, Event::Path(PathEvent::Discarded { id: seen, .. }) if seen == id) {
            discarded = true;
        }
    }
    assert!(
        discarded,
        "fork audit: locally abandoned unseen path was never discarded"
    );
    assert!(!pair.paths(Client).contains(&id));
    assert!(pair.path_status(Client, id).is_err());
    Ok(())
}
