//! W7 threat-model laboratory: a custodian runs arbitrary modified code.
//! The attacker owns its Ed25519 signing key, disk, logs and response policy.
//! These tests validate HONEST client boundaries, not honesty of remote code.
//! They use real Blue W3 v3 ciphertext, Ed25519 and SQLite on one CI host.
//! Tests explicitly show that signed claims and spot audits do NOT prove
//! continuous availability, independent disks or bounded physical copies.
use akula_wire_lab::crypto_identity_w3::{SignedHeader, TrustedRecipient};
use akula_wire_lab::crypto_w3::new_recipient;
use akula_wire_lab::custody_audit_w7::{AuditError, AuditReference};
use akula_wire_lab::custody_receipt_w6::{self, CustodyProofError, ExpectedCustody};
use akula_wire_lab::journal_w4::{Delivery, Insert, Journal, JournalError};
use akula_wire_lab::mailbox_w5::{MailError, Mailbox, MailboxLimits, PutStatus};
use akula_wire_lab::multipath_w5::{Lane, RouteError};
use akula_wire_lab::private_route_w3::{open_authenticated, seal_private};
use akula_wire_lab::receipt_w4::{self, ReceiptError};
use akula_wire_lab::trust_w3::TrustRegistry;
use ed25519_dalek::SigningKey;
use rusqlite::Connection;
use tempfile::{tempdir, TempDir};

fn id(value: u8) -> [u8; 16] {
    [value; 16]
}
fn key(value: u8) -> SigningKey {
    SigningKey::from_bytes(&[value; 32])
}

struct Case {
    dir: TempDir,
    wire: Vec<u8>,
    trust: TrustRegistry,
    custodian: SigningKey,
    second_custodian: SigningKey,
    bob: SigningKey,
}
impl Case {
    fn new() -> Self {
        let alice = key(9);
        let bob = key(8);
        let custodian = key(13);
        let second_custodian = key(14);
        let mut trust = TrustRegistry::new();
        trust.enroll(id(9), 4, alice.verifying_key()).unwrap();
        trust.enroll(id(8), 6, bob.verifying_key()).unwrap();
        trust.enroll(id(13), 7, custodian.verifying_key()).unwrap();
        trust.enroll(id(14), 8, second_custodian.verifying_key()).unwrap();
        let (_bob_secret, bob_pub) = new_recipient();
        let wire = seal_private(
            &alice,
            &bob_pub,
            id(4),
            SignedHeader {
                message_id: id(5),
                recipient_id: id(8),
                expiry: 500_000,
                sender_id: id(9),
                epoch: 4,
            },
            b"W7 deliberately opaque real W3 v3",
        ).unwrap();
        Self {
            dir: tempdir().unwrap(), wire, trust,
            custodian, second_custodian, bob,
        }
    }

    fn reference(&self) -> AuditReference {
        AuditReference::from_trusted_ciphertext(&self.wire).unwrap()
    }

    fn alice(&self) -> Journal {
        let mut journal = Journal::open(&self.dir.path().join("alice.sqlite")).unwrap();
        journal.enqueue(id(8), id(5), 500_000, &self.wire).unwrap();
        journal
    }

    fn proof(&self, signer: &SigningKey, node_id: u8, slot_id: u8) -> Vec<u8> {
        custody_receipt_w6::sign_after_store(
            signer, id(node_id), id(slot_id), id(5), &self.wire,
            if node_id == 13 { 7 } else { 8 }, 300_000,
        ).unwrap()
    }

    fn expected(&self, node_id: u8, slot_id: u8, now: u64) -> ExpectedCustody<'_> {
        ExpectedCustody {
            custodian_id: id(node_id),
            slot_id: id(slot_id),
            message_id: id(5),
            ciphertext: &self.wire,
            now_ms: now,
        }
    }

    fn assert_not_delivered(&self, journal: &Journal) {
        assert_eq!(journal.state(id(8), id(5)).unwrap(), Delivery::Queued);
        assert_eq!(
            journal.retry_bytes(id(8), id(5), 101).unwrap().as_deref(),
            Some(self.wire.as_slice()),
        );
    }
}

#[test]
fn fake_stored_valid_ed25519_receipt_without_any_bytes_is_not_recipient_w4() {
    let case = Case::new();
    // Rogue code calls public signing function without persisting anything.
    let lie = case.proof(&case.custodian, 13, 41);
    assert!(custody_receipt_w6::verify(
        &lie, case.expected(13, 41, 100_000), &case.trust,
    ).is_ok());
    assert_eq!(case.reference().observe(None, 100_100),
        Err(AuditError::Unavailable));
    assert!(matches!(receipt_w4::verify(&lie, &case.trust),
        Err(ReceiptError::InvalidLength)));
    let journal = case.alice();
    case.assert_not_delivered(&journal);
}

#[test]
fn store_then_delete_even_after_valid_claim_fails_later_exact_read() {
    let case = Case::new();
    let path = case.dir.path().join("rogue.sqlite");
    {
        let mut mailbox = Mailbox::open(&path, MailboxLimits::default()).unwrap();
        assert_eq!(mailbox.put(id(4), id(5), 100, 200, &case.wire).unwrap(),
            PutStatus::Stored);
    }
    let claim = case.proof(&case.custodian, 13, 41);
    assert!(custody_receipt_w6::verify(
        &claim, case.expected(13, 41, 100_000), &case.trust,
    ).is_ok());
    // Modified custodian code bypasses its public API and deletes directly.
    let db = Connection::open(&path).unwrap();
    assert_eq!(db.execute("DELETE FROM mailbox_entries", []).unwrap(), 1);
    drop(db);
    let mailbox = Mailbox::open(&path, MailboxLimits::default()).unwrap();
    assert!(mailbox.get_page(id(4), 101, None, 1).unwrap().is_empty());
    assert_eq!(case.reference().observe(None, 100_200),
        Err(AuditError::Unavailable));
    case.assert_not_delivered(&case.alice());
}

#[test]
fn selective_censorship_passes_audit_but_bob_still_has_no_w4() {
    let case = Case::new();
    let mut store = Mailbox::open(
        &case.dir.path().join("selective.sqlite"),
        MailboxLimits::default(),
    ).unwrap();
    store.put(id(4), id(5), 100, 200, &case.wire).unwrap();
    // Rogue custodian gives correct bytes to auditor at time t.
    let retrieved = store.get_page(id(4), 101, None, 1).unwrap();
    let observed = case.reference().observe(Some(&retrieved[0].bytes), 100_101).unwrap();
    assert_eq!(observed.observed_at_ms(), 100_101);
    // ...but it silently refuses Bob's independent request after the audit.
    let bob_fetched: Option<&[u8]> = None;
    assert_eq!(case.reference().observe(bob_fetched, 100_102),
        Err(AuditError::Unavailable));
    case.assert_not_delivered(&case.alice());
}

#[test]
fn tampered_ciphertext_is_rejected_by_independent_digest_and_hpke() {
    let alice = key(9);
    let bob = key(8);
    let mut trust = TrustRegistry::new();
    trust.enroll(id(9), 4, alice.verifying_key()).unwrap();
    trust.enroll(id(8), 6, bob.verifying_key()).unwrap();
    let (bob_secret, public) = new_recipient();
    let wire = seal_private(&alice, &public, id(4), SignedHeader {
        message_id: id(5), recipient_id: id(8), expiry: 500_000,
        sender_id: id(9), epoch: 4,
    }, b"confidential").unwrap();
    let known = AuditReference::from_trusted_ciphertext(&wire).unwrap();
    let mut rogue = wire.clone();
    *rogue.last_mut().unwrap() ^= 1;
    assert_eq!(known.observe(Some(&rogue), 100), Err(AuditError::WrongCiphertext));
    assert!(open_authenticated(&rogue, TrustedRecipient {
        secret: &bob_secret, recipient_id: id(8), now: 100,
        registry: &trust,
    }, id(4)).is_err());
    let mut short = wire;
    short.pop();
    assert_eq!(known.observe(Some(&short), 101), Err(AuditError::WrongLength));
}

#[test]
fn rogue_custodian_key_cannot_forge_final_recipient_w4() {
    let case = Case::new();
    let digest = *blake3::hash(&case.wire).as_bytes();
    // Custodian claims Bob's ID, but signature comes from custodian key.
    let fake = receipt_w4::sign(&case.custodian, id(8), id(5), digest, 6);
    assert!(matches!(receipt_w4::verify(&fake, &case.trust),
        Err(ReceiptError::InvalidSignature)));
    // A perfectly valid W4 for C's OWN ID cannot complete a message to Bob.
    let for_self = receipt_w4::sign(&case.custodian, id(13), id(5), digest, 7);
    let checked = receipt_w4::verify(&for_self, &case.trust).unwrap();
    let mut alice = case.alice();
    assert!(matches!(alice.apply_recipient_receipt(&checked),
        Err(JournalError::NotFound)));
    case.assert_not_delivered(&alice);
}

#[test]
fn replay_wrong_slot_and_expired_custodial_proof_are_rejected() {
    let case = Case::new();
    let signed = case.proof(&case.custodian, 13, 41);
    assert!(matches!(custody_receipt_w6::verify(
        &signed, case.expected(13, 42, 100_000), &case.trust,
    ), Err(CustodyProofError::WrongScope)));
    assert!(matches!(custody_receipt_w6::verify(
        &signed, case.expected(13, 41, 300_000), &case.trust,
    ), Err(CustodyProofError::Expired)));
    let mut changed = signed.clone();
    *changed.last_mut().unwrap() ^= 1;
    assert!(matches!(custody_receipt_w6::verify(
        &changed, case.expected(13, 41, 100_000), &case.trust,
    ), Err(CustodyProofError::InvalidSignature)));
}

#[test]
fn forked_code_can_clone_bytes_beyond_k3_even_while_honest_ledger_fences() {
    let case = Case::new();
    let mut alice = case.alice();
    alice.begin_multipath(id(8), id(5), &case.wire, 500_000, 3, 100).unwrap();
    alice.reserve_multipath((id(8), id(5)), &case.wire,
        id(21), id(13), Lane::Gateway, 101).unwrap();
    alice.reserve_multipath((id(8), id(5)), &case.wire,
        id(22), id(14), Lane::Explore, 102).unwrap();
    assert!(matches!(
        alice.reserve_multipath((id(8), id(5)), &case.wire,
            id(23), id(15), Lane::Forecast, 103),
        Err(RouteError::Exhausted)
    ));
    assert_eq!(alice.multipath_snapshot(id(8), id(5)).unwrap().allocated, 3);
    // A fork on an untrusted host can still write 10 unauthorized physical files.
    let clones: Vec<Vec<u8>> = (0..10).map(|_| case.wire.clone()).collect();
    assert_eq!(clones.len(), 10);
    assert!(clones.iter().all(|data| data == &case.wire));
    case.assert_not_delivered(&alice);
}

#[test]
fn two_sybil_keys_can_pass_audits_using_the_same_physical_file() {
    let case = Case::new();
    let path = case.dir.path().join("one-disk.sqlite");
    {
        let mut store = Mailbox::open(&path, MailboxLimits::default()).unwrap();
        store.put(id(4), id(5), 100, 200, &case.wire).unwrap();
    }
    let left = case.proof(&case.custodian, 13, 41);
    let right = case.proof(&case.second_custodian, 14, 42);
    assert!(custody_receipt_w6::verify(
        &left, case.expected(13, 41, 100_000), &case.trust,
    ).is_ok());
    assert!(custody_receipt_w6::verify(
        &right, case.expected(14, 42, 100_000), &case.trust,
    ).is_ok());
    // One shared SQLite row answers both pretend operators' audit probes.
    let store = Mailbox::open(&path, MailboxLimits::default()).unwrap();
    let bytes = store.get_page(id(4), 101, None, 1).unwrap().remove(0).bytes;
    assert!(case.reference().observe(Some(&bytes), 100_101).is_ok());
    assert!(case.reference().observe(Some(&bytes), 100_102).is_ok());
    drop(store);
    let db = Connection::open(&path).unwrap();
    db.execute("DELETE FROM mailbox_entries", []).unwrap();
    drop(db);
    let store = Mailbox::open(&path, MailboxLimits::default()).unwrap();
    assert!(store.get_page(id(4), 102, None, 1).unwrap().is_empty());
    // Two signatures still cannot guarantee independent failure domains.
    assert_eq!(case.reference().observe(None, 100_103),
        Err(AuditError::Unavailable));
}

#[test]
fn competing_same_slot_claims_are_potential_fork_not_final_delivery() {
    let case = Case::new();
    let one = case.proof(&case.custodian, 13, 41);
    let two = case.proof(&case.second_custodian, 14, 41);
    let v1 = custody_receipt_w6::verify(
        &one, case.expected(13, 41, 100_000), &case.trust,
    ).unwrap();
    let v2 = custody_receipt_w6::verify(
        &two, case.expected(14, 41, 100_000), &case.trust,
    ).unwrap();
    // Current signatures contain NO chain of handoff history. A separate
    // coordinator must reconcile this potential fork; it may be in flight.
    assert_eq!(v1.slot_id(), v2.slot_id());
    assert_eq!(v1.message_id(), v2.message_id());
    assert_ne!(v1.custodian_id(), v2.custodian_id());
    case.assert_not_delivered(&case.alice());
}

#[test]
fn revoked_or_old_epoch_custodian_proof_must_not_restore_trust() {
    let case = Case::new();
    let signed = case.proof(&case.custodian, 13, 41);
    let mut registry = case.trust.clone();
    registry.enroll(id(13), 8, case.custodian.verifying_key()).unwrap();
    assert!(matches!(custody_receipt_w6::verify(
        &signed, case.expected(13, 41, 100_000), &registry,
    ), Err(CustodyProofError::UntrustedCustodian)));
    registry.revoke(id(13)).unwrap();
    assert!(matches!(custody_receipt_w6::verify(
        &signed, case.expected(13, 41, 100_000), &registry,
    ), Err(CustodyProofError::UntrustedCustodian)));
}

#[test]
fn honest_offline_and_malicious_withholding_are_both_unknown_not_fraud() {
    let case = Case::new();
    // The response None may be network loss, sleeping phone or censorship.
    let reference = case.reference();
    assert_eq!(reference.observe(None, 100), Err(AuditError::Unavailable));
    assert_eq!(reference.observe(None, 101), Err(AuditError::Unavailable));
    case.assert_not_delivered(&case.alice());
}

#[test]
fn fake_official_build_advertisement_does_not_grant_further_authority() {
    let case = Case::new();
    let claimed_version = "WOW official release; healthy; verified; 99.99% SLA";
    assert!(claimed_version.contains("official"));
    // Verification uses trusted exact packet and independently provisioned
    // public keys, never untrusted self-advertised version strings.
    let forged_storage_claim = case.proof(&case.custodian, 13, 41);
    assert!(custody_receipt_w6::verify(
        &forged_storage_claim, case.expected(13, 41, 100_000), &case.trust,
    ).is_ok());
    assert_eq!(case.reference().observe(None, 100_001),
        Err(AuditError::Unavailable));
    case.assert_not_delivered(&case.alice());
}

#[test]
fn corruption_in_altered_sqlite_is_detected_even_if_local_stored_digest_remains() {
    let case = Case::new();
    let path = case.dir.path().join("altered.sqlite");
    {
        let mut store = Mailbox::open(&path, MailboxLimits::default()).unwrap();
        store.put(id(4), id(5), 100, 200, &case.wire).unwrap();
    }
    let db = Connection::open(&path).unwrap();
    let mut changed = case.wire.clone();
    *changed.last_mut().unwrap() ^= 1;
    db.execute("UPDATE mailbox_entries SET sealed=?1",
        rusqlite::params![changed]).unwrap();
    drop(db);
    let store = Mailbox::open(&path, MailboxLimits::default()).unwrap();
    assert!(matches!(store.get_page(id(4), 101, None, 1),
        Err(MailError::CorruptStorage)));
    case.assert_not_delivered(&case.alice());
}

#[test]
fn independent_audit_observation_does_not_issue_recipient_w4() {
    let case = Case::new();
    let observed = case.reference().observe(Some(&case.wire), 100_777).unwrap();
    assert_eq!(observed.ciphertext_digest(), *blake3::hash(&case.wire).as_bytes());
    let mut alice = case.alice();
    assert!(matches!(alice.record_verified_receipt(
        id(8), id(5), Delivery::Recipient,
    ), Err(JournalError::InvalidState)));
    case.assert_not_delivered(&alice);
}

#[test]
fn actual_bob_commit_is_required_before_true_signed_final_w4() {
    let alice_key = key(9);
    let bob_key = key(8);
    let (secret, bob_pub) = new_recipient();
    let mut trust = TrustRegistry::new();
    trust.enroll(id(9), 4, alice_key.verifying_key()).unwrap();
    trust.enroll(id(8), 6, bob_key.verifying_key()).unwrap();
    let wire = seal_private(&alice_key, &bob_pub, id(4), SignedHeader {
        message_id: id(5), recipient_id: id(8), expiry: 500_000,
        sender_id: id(9), epoch: 4,
    }, b"verified by actual B").unwrap();
    let dir = tempdir().unwrap();
    let mut alice = Journal::open(&dir.path().join("alice.sqlite")).unwrap();
    alice.enqueue(id(8), id(5), 500_000, &wire).unwrap();
    let mut bob = Journal::open(&dir.path().join("bob.sqlite")).unwrap();
    let (insert, receipt) = bob.accept_private_authenticated_and_queue_receipt(
        &wire, TrustedRecipient {
            secret: &secret, recipient_id: id(8),
            now: 100_000, registry: &trust,
        }, id(4), &bob_key, 6,
    ).unwrap();
    assert_eq!(insert, Insert::New);
    let validated = receipt_w4::verify(&receipt, &trust).unwrap();
    assert_eq!(validated.packet_digest(), *blake3::hash(&wire).as_bytes());
    assert_eq!(alice.apply_recipient_receipt(&validated).unwrap(),
        Delivery::Recipient);
    assert_eq!(alice.retry_bytes(id(8), id(5), 101).unwrap(), None);
    let (dup, same) = bob.accept_private_authenticated_and_queue_receipt(
        &wire, TrustedRecipient {
            secret: &secret, recipient_id: id(8),
            now: 100_000, registry: &trust,
        }, id(4), &bob_key, 6,
    ).unwrap();
    assert_eq!(dup, Insert::Duplicate);
    assert_eq!(same, receipt);
}
