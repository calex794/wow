//! LABO EXP-018 per-letter event handoff -> real WOW W3/Ed25519 W4.
//! The fixture comes from the public CI artifact of calex794/labo run
//! 39974946737 (12 selected rows, source CSV SHA-256 pinned in spec).
//! Only the *schedule* is replayed. LABO recipient/return timestamps are
//! synthetic observations, NEVER cryptographic authority.
//! No physical radio, Internet, gateway replica, or cross-machine replay.

use akula_wire_lab::crypto_identity_w3::{SignedHeader, TrustedRecipient};
use akula_wire_lab::crypto_w3::new_recipient;
use akula_wire_lab::journal_w4::{Delivery, Insert, Journal};
use akula_wire_lab::private_return_w4::{self, PrivateReturnError, ReturnInvitation};
use akula_wire_lab::private_route_w3;
use akula_wire_lab::receipt_w4::{self, ReceiptError};
use akula_wire_lab::trust_w3::TrustRegistry;
use ed25519_dalek::SigningKey;
use tempfile::tempdir;

const TICK_MS: u64 = 20_000;
const CLAIM: &str = "measured-human-contact-times-with-synthetic-outages-and-w4-markers";
const HEADER: &str = "source,phase,seed,gateway_percent,pickup_hours,scenario,policy,pair_set_sha256,message_ref,message_index,created_tick,ttl_ticks,custody_copies,first_gateway_stored_tick,mailbox_uploaded_tick,recipient_stored_tick,source_confirmed_tick,delivery_channel,claim";
const FIXTURE: &str = include_str!("fixtures/labo_exp018_12_events.csv");

fn id(n: u8) -> [u8; 16] { [n; 16] }
fn key(n: u8) -> SigningKey { SigningKey::from_bytes(&[n; 32]) }
fn trust() -> TrustRegistry {
    let mut t = TrustRegistry::new();
    t.enroll(id(9), 4, key(9).verifying_key()).unwrap(); // test source
    t.enroll(id(8), 6, key(8).verifying_key()).unwrap(); // test recipient
    t.enroll(id(13), 7, key(13).verifying_key()).unwrap(); // not Bob
    t
}
fn maybe_tick(value: &str) -> Option<u64> {
    if value.is_empty() { None } else { Some(value.parse::<u64>().expect("invalid tick")) }
}
fn parse_message_ref(value: &str) -> [u8; 16] {
    assert_eq!(value.len(), 32, "bad synthetic trace ID length");
    let mut out = [0u8; 16];
    for (i, item) in out.iter_mut().enumerate() {
        let digits = value.get(2*i..2*i+2).expect("non-ASCII synthetic ID");
        *item = u8::from_str_radix(digits, 16).expect("not lowercase hex");
    }
    assert_ne!(out, [0u8; 16]);
    out
}
#[derive(Clone, Debug)]
struct ModelLetter {
    message_id: [u8; 16],
    created_tick: u64,
    ttl_ticks: u64,
    // IMPORTANT: number of cumulative deposits, NOT simultaneous copies.
    // The simulator can MOVE a copy repeatedly while its max is K=4.
    deposit_events: usize,
    first_gateway_tick: Option<u64>,
    uploaded_tick: Option<u64>,
    recipient_tick: Option<u64>,
    return_tick: Option<u64>,
    channel: String,
    scenario: String,
    policy: String,
}
impl ModelLetter {
    fn parse(line: &str) -> Self {
        // Restricted LABO v1 export: ASCII identifiers and integral fields,
        // no quoting or embedded commas. Fail closed on schema changes.
        assert!(!line.contains('"'), "CSV quoting requires a real parser");
        let x: Vec<&str> = line.split(',').collect();
        assert_eq!(x.len(), 19, "unexpected LABO event CSV width");
        assert_eq!(x[0], "SFHH-conference-2009");
        assert!(matches!(x[6], "gateway_direct4" | "hybrid_parallel4"));
        assert!(matches!(x[5], "control" | "gateway_disk_reset" |
            "gateway_radio_offline" | "gateway_internet_offline" |
            "return_channel_unavailable"));
        assert_eq!(x[18], CLAIM);
        assert_eq!(x[7].len(), 64); // cohort fingerprint, not real W3 digest
        let event = Self {
            message_id: parse_message_ref(x[8]),
            created_tick: x[10].parse().unwrap(),
            ttl_ticks: x[11].parse().unwrap(),
            deposit_events: x[12].parse().unwrap(),
            first_gateway_tick: maybe_tick(x[13]),
            uploaded_tick: maybe_tick(x[14]),
            recipient_tick: maybe_tick(x[15]),
            return_tick: maybe_tick(x[16]),
            channel: x[17].to_owned(),
            scenario: x[5].to_owned(),
            policy: x[6].to_owned(),
        };
        event.validate();
        event
    }
    fn expiry(&self) -> u64 {
        self.created_tick.checked_add(self.ttl_ticks).unwrap()
    }
    fn validate(&self) {
        assert_eq!(self.ttl_ticks, 720);
        assert!(self.created_tick > 0);
        assert_eq!(self.first_gateway_tick.is_some(), self.deposit_events > 0);
        if let Some(stored) = self.first_gateway_tick {
            assert!(stored >= self.created_tick && stored < self.expiry());
        }
        if let Some(up) = self.uploaded_tick {
            assert!(self.first_gateway_tick.is_some());
            assert!(up >= self.first_gateway_tick.unwrap() && up < self.expiry());
        }
        if let Some(recv) = self.recipient_tick {
            assert!(recv >= self.created_tick && recv < self.expiry());
            assert!(matches!(self.channel.as_str(),
                "synthetic-mailbox-poll" | "observed-contact-synthetic-recipient"));
            if self.channel == "synthetic-mailbox-poll" {
                assert!(self.uploaded_tick.is_some());
                assert!(recv > self.uploaded_tick.unwrap());
            }
        } else {
            assert!(self.channel.is_empty());
        }
        if let Some(receipt) = self.return_tick {
            assert!(receipt > self.recipient_tick.expect("receipt without recipient"));
            assert_ne!(self.scenario, "return_channel_unavailable");
        }
    }
}
fn sample() -> Vec<ModelLetter> {
    let mut lines = FIXTURE.lines();
    assert_eq!(lines.next(), Some(HEADER));
    lines.map(ModelLetter::parse).collect()
}
fn millis(tick: u64) -> u64 {
    tick.checked_mul(TICK_MS).unwrap()
}

#[test]
fn recorded_event_schema_preserves_model_timing_not_copy_authority() {
    let events = sample();
    assert_eq!(events.len(), 12);
    assert_eq!(events.iter().filter(|e| e.recipient_tick.is_some()).count(), 9);
    assert_eq!(events.iter().filter(|e| e.return_tick.is_some()).count(), 7);
    assert!(events.iter().any(|e| e.scenario == "gateway_disk_reset"
        && e.policy == "gateway_direct4" && e.deposit_events >= 2
        && e.recipient_tick.is_some()));
    assert!(events.iter().any(|e| e.scenario == "return_channel_unavailable"
        && e.recipient_tick.is_some() && e.return_tick.is_none()));
    // This actually occurs in LABO: many cumulative transfers/recustodies
    // of the same limited copy. It must NOT become 77 W8 copy-slot credits.
    assert!(events.iter().any(|e| e.deposit_events == 77));
}

#[test]
fn lab_model_schedule_yields_real_w4_only_after_verified_recipient_commit() {
    let events = sample();
    let dir = tempdir().unwrap();
    let registry = trust();
    let mut durable_recipient = 0;
    let mut source_confirmed = 0;

    for (idx, row) in events.iter().enumerate() {
        let (bob_secret, bob_public) = new_recipient();
        let (return_secret, return_public) = new_recipient();
        let expiry_ms = millis(row.expiry());
        let created_ms = millis(row.created_tick);
        let payload = format!("EXPERIMENT ONLY {idx}: source/recipient ids are test-only");
        let encrypted_w3 = private_route_w3::seal_private(
            &key(9), &bob_public, id(4),
            SignedHeader {
                message_id: row.message_id, recipient_id: id(8),
                sender_id: id(9), epoch: 4, expiry: expiry_ms,
            },
            payload.as_bytes(),
        ).unwrap();

        let sender_path = dir.path().join(format!("sender-{idx}.sqlite"));
        let recipient_path = dir.path().join(format!("recipient-{idx}.sqlite"));
        let mut alice = Journal::open(&sender_path).unwrap();
        alice.enqueue(id(8), row.message_id, expiry_ms as i64, &encrypted_w3)
            .unwrap();
        alice.begin_multipath(
            id(8), row.message_id, &encrypted_w3,
            expiry_ms as i64, 4, created_ms as i64,
        ).unwrap();
        assert_eq!(alice.state(id(8), row.message_id).unwrap(), Delivery::Queued);
        assert_eq!(alice.multipath_snapshot(id(8), row.message_id).unwrap().budget, 4);

        let Some(recipient_tick) = row.recipient_tick else {
            // A model "gateway stored" marker can never manufacture recipient W4.
            let bob = Journal::open(&recipient_path).unwrap();
            assert_eq!(bob.queued_recipient_receipt(id(9), row.message_id).unwrap(), None);
            assert_eq!(alice.state(id(8), row.message_id).unwrap(), Delivery::Queued);
            continue;
        };

        // Scheduling a simulated recipient event is NOT a real packet receipt.
        // The recipient must still authenticate the complete W3 and atomically
        // commit the exact ciphertext + Ed25519 W4 into its SQLite.
        let mut bob = Journal::open(&recipient_path).unwrap();
        let (inserted, signed_w4) = bob.accept_private_authenticated_and_queue_receipt(
            &encrypted_w3,
            TrustedRecipient {
                secret: &bob_secret, recipient_id: id(8),
                now: millis(recipient_tick), registry: &registry,
            },
            id(4), &key(8), 6,
        ).unwrap();
        assert_eq!(inserted, Insert::New);
        durable_recipient += 1;
        drop(bob);
        let bob = Journal::open(&recipient_path).unwrap();
        assert_eq!(bob.queued_recipient_receipt(id(9), row.message_id).unwrap(),
                   Some(signed_w4.clone()));
        // Recipient did commit, but sender still knows nothing.
        assert_eq!(alice.state(id(8), row.message_id).unwrap(), Delivery::Queued);
        let opaque = private_return_w4::seal_signed_receipt(
            &signed_w4, &return_public, id(61),
        ).unwrap();
        assert!(!opaque.windows(16).any(|w|
            w == id(8).as_slice() || w == row.message_id.as_slice()));

        let Some(receipt_tick) = row.return_tick else {
            assert_eq!(alice.state(id(8), row.message_id).unwrap(), Delivery::Queued);
            assert!(!alice.multipath_snapshot(id(8), row.message_id).unwrap().stopped);
            continue;
        };

        // A forged W4 signed by a gateway cannot confirm exact recipient ID.
        let forged_w4 = receipt_w4::sign(
            &key(13), id(8), row.message_id,
            *blake3::hash(&encrypted_w3).as_bytes(), 6,
        );
        let bad_envelope = private_return_w4::seal_signed_receipt(
            &forged_w4, &return_public, id(61),
        ).unwrap();
        let now = millis(receipt_tick);
        let invitation = || ReturnInvitation {
            sender_secret: &return_secret,
            expected_tag: id(61),
            expires_at_ms: now + TICK_MS,
            now_ms: now,
            recipient_trust: &registry,
        };
        assert!(matches!(
            private_return_w4::open_verify_and_apply(
                &bad_envelope, invitation(), &mut alice,
            ),
            Err(PrivateReturnError::UntrustedReceipt(ReceiptError::InvalidSignature))
        ));
        assert_eq!(alice.state(id(8), row.message_id).unwrap(), Delivery::Queued);
        drop(alice);
        let mut alice = Journal::open(&sender_path).unwrap();
        assert_eq!(private_return_w4::open_verify_and_apply(
            &opaque, invitation(), &mut alice,
        ).unwrap(), Delivery::Recipient);
        source_confirmed += 1;
        assert!(alice.multipath_snapshot(id(8), row.message_id).unwrap().stopped);
        assert_eq!(alice.retry_bytes(id(8), row.message_id, now as i64).unwrap(), None);
        drop(alice);
        let mut alice = Journal::open(&sender_path).unwrap();
        assert_eq!(private_return_w4::open_verify_and_apply(
            &opaque, invitation(), &mut alice,
        ).unwrap(), Delivery::Recipient);
    }
    assert_eq!(durable_recipient, 9);
    assert_eq!(source_confirmed, 7);
}

#[test]
fn model_return_blackout_does_not_synthesize_signature_or_sender_success() {
    let events = sample();
    let blocked: Vec<_> = events.iter()
        .filter(|e| e.scenario == "return_channel_unavailable"
            && e.recipient_tick.is_some())
        .collect();
    assert_eq!(blocked.len(), 1);
    assert!(blocked.iter().all(|e| e.return_tick.is_none()));
    // More general condition also holds for direct contact with no follow-up:
    assert!(events.iter().any(|e|
        e.channel == "observed-contact-synthetic-recipient"
            && e.return_tick.is_none()));
}
