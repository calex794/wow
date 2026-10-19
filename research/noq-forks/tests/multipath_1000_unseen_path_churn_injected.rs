// Research-only stress regression. Inject into noq-proto/src/tests/multipath.rs
// of exact combined noq SHA 538346e... on a disposable GitHub Actions checkout.
// Each iteration starts a fresh QUIC connection pair, opens a candidate path
// the peer never learns about, abandons it and checks that all local state
// of that candidate disappears. No patch is shipped by this fixture.
#[test]
fn fork_audit_1000_unseen_paths_are_reclaimed() -> TestResult {
    let _guard = subscribe();
    for attempt in 0..1000usize {
        let mut pair = ConnPair::builder().enable_multipath().connect();
        let initial_paths = pair.paths(Client).len();

        let mut second_client_addr = pair.routes.as_basic().client_addr;
        let mut second_server_addr = pair.routes.as_basic().server_addr;
        second_client_addr.set_port(second_client_addr.port() + 1);
        second_server_addr.set_port(second_server_addr.port() + 1);
        pair.routes = ManyToManyRouting::simple_symmetric(
            [pair.routes.as_basic().client_addr, second_client_addr],
            [pair.routes.as_basic().server_addr, second_server_addr],
        )
        .into();

        let unobserved = FourTuple {
            local_ip: Some(second_client_addr.ip()),
            remote: second_server_addr,
        };
        let id = pair.open_path(Client, unobserved, PathStatus::Available)?;
        pair.close_path(Client, id, 0u8.into())?;
        pair.drive();

        assert_matches!(
            pair.poll(Client),
            Some(Event::Path(PathEvent::Abandoned { id: seen, .. })) if seen == id
        );

        let mut discarded = false;
        while let Some(event) = pair.poll(Client) {
            if matches!(event, Event::Path(PathEvent::Discarded { id: seen, .. }) if seen == id) {
                discarded = true;
            }
        }
        assert!(discarded, "trial {attempt}: missing Discarded event for candidate path");
        assert!(
            !pair.paths(Client).contains(&id),
            "trial {attempt}: abandoned path still visible"
        );
        assert!(
            pair.path_status(Client, id).is_err(),
            "trial {attempt}: abandoned path status still alive"
        );
        assert_eq!(
            pair.paths(Client).len(),
            initial_paths,
            "trial {attempt}: path count did not return to baseline"
        );
    }
    Ok(())
}
