use akula_wire_lab::custodian_observation::{
    AppendResult, Counters, EventKind, EvidenceLevel, LocalObservationStore,
    ObservationError, ServiceEvent, ServiceRole, ServiceScope,
};
use tempfile::tempdir;

const DAY: u64 = 86_400_000;
const NOW: u64 = 50 * DAY;

fn scope(role: ServiceRole, epoch: u64) -> ServiceScope {
    ServiceScope {
        service_key: [7; 32],
        epoch,
        role,
    }
}
fn event(kind: EventKind, seq: u64, at: u64) -> ServiceEvent {
    use EventKind::*;
    let strong = matches!(
        kind,
        AuditBadBytes | FetchBadBytes | FetchRefusedValid
            | HandoffRefusedValid | CheckpointConflict | RecipientW4Observed
            | ServiceMissedInPromisedWindow
    );
    let level = if strong {
        EvidenceLevel::SignedExchange
    } else if kind == StoreClaimed {
        EvidenceLevel::Claimed
    } else {
        EvidenceLevel::LocalObservation
    };
    ServiceEvent {
        scope: scope(ServiceRole::Public, 1),
        observer_key: [5; 32],
        event_seq: seq,
        operation_alias: [(seq & 0xff) as u8; 16],
        lease_alias: [3; 16],
        session_nonce: [4; 16],
        observed_at_ms: at,
        kind,
        evidence_level: level,
        evidence_digest: strong.then_some([9; 32]),
    }
}
fn store() -> (tempfile::TempDir, LocalObservationStore) {
    let folder = tempdir().unwrap();
    let opened = LocalObservationStore::open(&folder.path().join("observation.db")).unwrap();
    (folder, opened)
}
#[test]
fn no_authorized_fetch_is_no_evidence_not_failed_delivery() {
    let (_folder, mut store) = store();
    for seq in 1..=100 {
        store.record(event(EventKind::StoreClaimed, seq, NOW - DAY / 2)).unwrap();
    }
    for seq in 101..=110 {
        store.record(event(EventKind::AuditExactW3, seq, NOW - DAY / 2)).unwrap();
    }
    let report = store.report(scope(ServiceRole::Public, 1), NOW).unwrap();
    assert_eq!(report.last_24h.store_claims, 100);
    assert_eq!(report.last_24h.storage.successes, 10);
    assert_eq!(report.last_24h.storage.eligible, 10);
    assert_eq!(report.last_24h.authorized_fetch.eligible, 0);
    assert_eq!(report.last_24h.authorized_fetch.wilson_lower_bound(), None);
    assert_eq!(report.last_24h.recipient_w4_observations, 0);
}

#[test]
fn valid_refusals_and_unknown_timeouts_are_not_conflated() {
    let (_folder, mut store) = store();
    for seq in 1..=5 {
        store.record(event(EventKind::FetchExactW3, seq, NOW)).unwrap();
    }
    for seq in 6..=75 {
        store.record(event(EventKind::FetchRefusedValid, seq, NOW)).unwrap();
    }
    for seq in 76..=80 {
        store.record(event(EventKind::FetchTimeout, seq, NOW)).unwrap();
    }
    let fetch = store.report(scope(ServiceRole::Public, 1), NOW).unwrap()
        .last_24h.authorized_fetch;
    assert_eq!(fetch.successes, 5);
    assert_eq!(fetch.failures, 70);
    assert_eq!(fetch.eligible, 75);
    assert_eq!(fetch.unknown, 5);
    assert!(fetch.wilson_lower_bound().unwrap() < 0.15);
}

#[test]
fn a_service_claim_is_not_an_exact_byte_audit() {
    let (_folder, mut store) = store();
    let mut bad = event(EventKind::AuditBadBytes, 1, NOW);
    bad.evidence_level = EvidenceLevel::LocalObservation;
    assert!(matches!(store.record(bad), Err(ObservationError::UnverifiedClaim)));
    bad.evidence_level = EvidenceLevel::SignedExchange;
    bad.evidence_digest = None;
    assert!(matches!(store.record(bad), Err(ObservationError::UnverifiedClaim)));
    bad.evidence_digest = Some([8; 32]);
    assert_eq!(store.record(bad).unwrap(), AppendResult::Stored);
    let report = store.report(scope(ServiceRole::Public, 1), NOW).unwrap();
    assert_eq!(report.last_24h.storage.failures, 1);
    assert_eq!(report.last_24h.authorized_fetch.eligible, 0);
    assert_eq!(report.last_24h.recipient_w4_observations, 0);
}

#[test]
fn duplicate_replay_is_idempotent_but_conflicting_evidence_is_rejected() {
    let (_folder, mut store) = store();
    let evt = event(EventKind::AuditExactW3, 1, NOW);
    assert_eq!(store.record(evt).unwrap(), AppendResult::Stored);
    assert_eq!(store.record(evt).unwrap(), AppendResult::ExactReplay);
    let mut conflict = evt;
    conflict.observed_at_ms += 1;
    assert!(matches!(store.record(conflict), Err(ObservationError::Conflict)));
    let mut duplicated_operation = evt;
    duplicated_operation.event_seq = 2;
    assert!(matches!(
        store.record(duplicated_operation),
        Err(ObservationError::Conflict)
    ));
    assert_eq!(
        store.report(scope(ServiceRole::Public, 1), NOW).unwrap()
            .last_24h.storage.eligible,
        1
    );
}

#[test]
fn durable_reopen_keeps_events_and_replay_semantics() {
    let folder = tempdir().unwrap();
    let path = folder.path().join("observations.db");
    let evt = event(EventKind::HandoffAmbiguous, 1, NOW);
    {
        let mut store = LocalObservationStore::open(&path).unwrap();
        store.record(evt).unwrap();
    }
    let mut restored = LocalObservationStore::open(&path).unwrap();
    assert_eq!(restored.record(evt).unwrap(), AppendResult::ExactReplay);
    let counters = restored.report(scope(ServiceRole::Public, 1), NOW).unwrap();
    assert_eq!(counters.last_24h.handoff.unknown, 1);
    assert_eq!(counters.last_24h.handoff.eligible, 0);
}

#[test]
fn report_windows_are_disjoint_and_clock_rollback_is_not_a_failure() {
    let (_folder, mut store) = store();
    store.record(event(EventKind::AuditExactW3, 1, NOW)).unwrap();
    store.record(event(EventKind::AuditExactW3, 2, NOW - DAY)).unwrap();
    store.record(event(EventKind::AuditExactW3, 3, NOW - 7 * DAY)).unwrap();
    store.record(event(EventKind::AuditExactW3, 4, NOW - 30 * DAY)).unwrap();
    let r = store.report(scope(ServiceRole::Public, 1), NOW).unwrap();
    assert_eq!(r.last_24h.storage.eligible, 1);
    assert_eq!(r.days_2_to_7.storage.eligible, 1);
    assert_eq!(r.days_8_to_30.storage.eligible, 1);
    assert!(matches!(
        store.report(scope(ServiceRole::Public, 1), NOW - 1),
        Err(ObservationError::ClockUncertain)
    ));
}

#[test]
fn personal_public_and_service_epochs_are_scoped_separately() {
    let (_folder, mut store) = store();
    let evt = event(EventKind::AuditExactW3, 1, NOW);
    store.record(evt).unwrap();
    let mut personal = evt;
    personal.scope = scope(ServiceRole::Personal, 1);
    store.record(personal).unwrap();
    let mut next_epoch = evt;
    next_epoch.scope = scope(ServiceRole::Public, 2);
    store.record(next_epoch).unwrap();
    assert_eq!(
        store.report(scope(ServiceRole::Community, 1), NOW).unwrap()
            .last_24h.storage.eligible,
        0
    );
    assert_eq!(
        store.report(scope(ServiceRole::Personal, 1), NOW).unwrap()
            .last_24h.storage.eligible,
        1
    );
    assert_eq!(
        store.report(scope(ServiceRole::Public, 2), NOW).unwrap()
            .last_24h.storage.eligible,
        1
    );
}

#[test]
fn signed_w4_and_checkpoint_conflict_never_merge_into_service_score() {
    let (_folder, mut store) = store();
    store.record(event(EventKind::RecipientW4Observed, 1, NOW)).unwrap();
    store.record(event(EventKind::CheckpointConflict, 2, NOW)).unwrap();
    store.record(event(EventKind::UnattributedFailure, 3, NOW)).unwrap();
    store.record(event(EventKind::FetchDeniedCorrectly, 4, NOW)).unwrap();
    let window = store.report(scope(ServiceRole::Public, 1), NOW).unwrap().last_24h;
    assert_eq!(window.recipient_w4_observations, 1);
    assert_eq!(window.checkpoint_conflicts, 1);
    assert_eq!(window.unattributed_failures, 1);
    assert_eq!(window.correctly_denied, 1);
    assert_eq!(window.authorized_fetch.eligible, 0);
}

#[test]
fn a_handful_of_successes_do_not_equal_extensive_evidence() {
    let one = Counters { successes: 1, eligible: 1, failures: 0, unknown: 0 };
    let hundred = Counters { successes: 100, eligible: 100, failures: 0, unknown: 0 };
    let low = one.wilson_lower_bound().unwrap();
    let high = hundred.wilson_lower_bound().unwrap();
    assert!(low < high && high < 1.0);
}

#[test]
fn malformed_identifiers_and_zero_evidence_are_rejected() {
    let (_folder, mut store) = store();
    let mut evt = event(EventKind::AuditExactW3, 1, NOW);
    evt.scope.service_key = [0; 32];
    assert!(matches!(store.record(evt), Err(ObservationError::Invalid)));
    evt = event(EventKind::AuditBadBytes, 2, NOW);
    evt.evidence_digest = Some([0; 32]);
    assert!(matches!(store.record(evt), Err(ObservationError::Invalid)));
    evt = event(EventKind::FetchExactW3, 3, NOW);
    evt.observed_at_ms = 0;
    assert!(matches!(store.record(evt), Err(ObservationError::Invalid)));
}
