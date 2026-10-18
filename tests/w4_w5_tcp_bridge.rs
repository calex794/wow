//! One-request TCP loopback bridge between W5 store-and-forward and W4
//! authenticated recipient acceptance. Real kernel TCP is exercised; this
//! does NOT bind untrusted interfaces or assert production network readiness.
use akula_wire_lab::crypto_identity_w3::{seal, SignedHeader, TrustedRecipient};
use akula_wire_lab::crypto_w3::new_recipient;
use akula_wire_lab::ingress_bridge_w5::{
    receive_verified_recipient_ack, serve_one_tcp, BridgeError, IngressOutcome,
    IngressRoute, LabRelayGrant,
};
use akula_wire_lab::journal_w4::{Delivery, Insert, Journal, JournalError};
use akula_wire_lab::mailbox_w5::{Mailbox, MailboxLimits, PutStatus};
use akula_wire_lab::trust_w3::TrustRegistry;
use akula_wire_lab::{stream_frame, WireError, MAX_MESSAGE_BYTES};
use ed25519_dalek::SigningKey;
use std::io::{Cursor, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::time::Duration;
use tempfile::tempdir;

fn id(value: u8) -> [u8;16] { [value;16] }

fn enrolled(sender: &SigningKey, recipient: &SigningKey) -> TrustRegistry {
    let mut trust = TrustRegistry::new();
    trust.enroll(id(1), 3, sender.verifying_key()).unwrap();
    trust.enroll(id(2), 4, recipient.verifying_key()).unwrap();
    trust
}

/// Binds a real localhost listener, sends one W2 frame, routes it on the
/// accepted TCP stream, then reads any response. Does not spawn background
/// threads or open any non-loopback listener.
fn tcp_once(
    route: IngressRoute<'_>,
    framed_packet: &[u8],
) -> (Result<IngressOutcome,BridgeError>, Vec<u8>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    client.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    client.write_all(framed_packet).unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let (server, _) = listener.accept().unwrap();
    server.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let routed = serve_one_tcp(server, route);
    let mut reply = Vec::new();
    client.read_to_end(&mut reply).unwrap();
    (routed, reply)
}

fn send(
    route: IngressRoute<'_>, encrypted_packet: &[u8],
) -> (Result<IngressOutcome,BridgeError>, Vec<u8>) {
    tcp_once(route, &stream_frame(encrypted_packet).unwrap())
}

#[test]
fn mailbox_temporary_storage_never_confirms_recipient_but_final_commit_does() {
    let dir = tempdir().unwrap();
    let sender_path = dir.path().join("sender.sqlite");
    let relay_path = dir.path().join("relay.sqlite");
    let recipient_path = dir.path().join("recipient.sqlite");

    let sender = SigningKey::from_bytes(&[1;32]);
    let recipient = SigningKey::from_bytes(&[2;32]);
    let (secret, public) = new_recipient();
    let trust = enrolled(&sender, &recipient);
    let packet = seal(&sender, &public, SignedHeader {
        message_id: id(7), recipient_id: id(2), expiry: 9000,
        sender_id: id(1), epoch: 3,
    }, b"opaque, E2E authenticated payload").unwrap();

    let mut outbox = Journal::open(&sender_path).unwrap();
    outbox.enqueue(id(2),id(7),9000,&packet).unwrap();
    let mut relay = Mailbox::open_recovery_gated(
        &relay_path, MailboxLimits::default(),
    ).unwrap();
    relay.try_resume_after_maintenance().unwrap();

    let (stored, relay_wire) = send(
        IngressRoute::Mailbox {
            store: &mut relay,
            grant: LabRelayGrant {
                route_token: id(9), message_id: id(7), now: 100, expires_at: 8000,
            },
        },
        &packet,
    );
    assert!(matches!(stored, Ok(IngressOutcome::MailboxStored(PutStatus::Stored))));
    assert!(relay_wire.is_empty(), "mailbox must NOT emit recipient ACK bytes");
    assert_eq!(outbox.state(id(2),id(7)).unwrap(), Delivery::Queued);

    let forwarded = relay.get_page(id(9), 101, None, 1).unwrap().remove(0).bytes;
    assert_eq!(forwarded, packet, "relay must forward exact ciphertext bytes");

    let mut inbox = Journal::open(&recipient_path).unwrap();
    let (accepted, signed_wire) = send(
        IngressRoute::Recipient {
            journal: &mut inbox,
            context: TrustedRecipient {
                secret: &secret, recipient_id: id(2), now: 102, registry: &trust,
            },
            signer: &recipient, signer_epoch: 4,
        },
        &forwarded,
    );
    assert!(matches!(accepted, Ok(IngressOutcome::RecipientAccepted(Insert::New))));
    assert_eq!(outbox.state(id(2),id(7)).unwrap(), Delivery::Queued);
    assert!(!signed_wire.is_empty(), "recipient emits ACK only after DB commit");
    assert_eq!(
        receive_verified_recipient_ack(
            &mut Cursor::new(&signed_wire), &mut outbox, &trust
        ).unwrap(),
        Delivery::Recipient
    );
    assert_eq!(outbox.state(id(2),id(7)).unwrap(), Delivery::Recipient);
    assert!(outbox.retry_bytes(id(2),id(7),103).unwrap().is_none());
}

#[test]
fn recipient_db_error_yields_no_tcp_ack_and_retry_is_exact_after_restart() {
    let dir = tempdir().unwrap();
    let recipient_path = dir.path().join("recipient.sqlite");
    let sender_path = dir.path().join("outbox.sqlite");
    let sender = SigningKey::from_bytes(&[1;32]);
    let recipient = SigningKey::from_bytes(&[2;32]);
    let (secret,public) = new_recipient();
    let trust = enrolled(&sender,&recipient);
    let packet = seal(&sender,&public,SignedHeader {
        message_id:id(8),recipient_id:id(2),expiry:9000,
        sender_id:id(1),epoch:3,
    },b"must not acknowledge before storage COMMIT").unwrap();
    let mut outbox = Journal::open(&sender_path).unwrap();
    outbox.enqueue(id(2),id(8),9000,&packet).unwrap();

    Journal::open(&recipient_path).unwrap();
    let injector = rusqlite::Connection::open(&recipient_path).unwrap();
    injector.execute_batch(
        "CREATE TRIGGER fail_relayed_ack BEFORE INSERT ON receipt_outbox
         BEGIN SELECT RAISE(ABORT, 'injected disk failure'); END;",
    ).unwrap();

    let mut recipient_journal = Journal::open(&recipient_path).unwrap();
    let (failed, none) = send(
        IngressRoute::Recipient {
            journal: &mut recipient_journal,
            context:TrustedRecipient {
                secret:&secret,recipient_id:id(2),now:100,registry:&trust,
            },
            signer:&recipient,signer_epoch:4,
        },
        &packet,
    );
    assert!(matches!(failed,Err(BridgeError::Recipient(JournalError::Db(_)))));
    assert!(none.is_empty(), "do not send a receipt on any SQL error");
    assert_eq!(outbox.state(id(2),id(8)).unwrap(),Delivery::Queued);
    assert!(recipient_journal.queued_recipient_receipt(id(1),id(8)).unwrap().is_none());
    drop(recipient_journal);

    injector.execute_batch("DROP TRIGGER fail_relayed_ack;").unwrap();
    drop(injector);
    let mut reopened = Journal::open(&recipient_path).unwrap();
    let (ok, first_ack) = send(
        IngressRoute::Recipient {
            journal: &mut reopened,
            context:TrustedRecipient {
                secret:&secret,recipient_id:id(2),now:101,registry:&trust,
            },
            signer:&recipient,signer_epoch:4,
        },
        &packet,
    );
    assert!(matches!(ok, Ok(IngressOutcome::RecipientAccepted(Insert::New))));
    let expected = reopened.queued_recipient_receipt(id(1),id(8)).unwrap().unwrap();
    assert_eq!(first_ack, stream_frame(&expected).unwrap());

    let (duplicate, same_ack) = send(
        IngressRoute::Recipient {
            journal: &mut reopened,
            context:TrustedRecipient {
                secret:&secret,recipient_id:id(2),now:102,registry:&trust,
            },
            signer:&recipient,signer_epoch:4,
        },
        &packet,
    );
    assert!(matches!(
        duplicate, Ok(IngressOutcome::RecipientAccepted(Insert::Duplicate))
    ));
    assert_eq!(same_ack, first_ack);
    // Simulate the receiver having committed but the first ACK being lost.
    assert_eq!(outbox.state(id(2),id(8)).unwrap(),Delivery::Queued);
    assert_eq!(
        receive_verified_recipient_ack(
            &mut Cursor::new(same_ack),&mut outbox,&trust,
        ).unwrap(), Delivery::Recipient
    );
}

#[test]
fn forged_mailbox_bytes_are_not_authentic_recipient_messages() {
    let dir=tempdir().unwrap();
    let mut relay=Mailbox::open_recovery_gated(
        &dir.path().join("relay.sqlite"),MailboxLimits::default()
    ).unwrap();
    relay.try_resume_after_maintenance().unwrap();
    let fake=b"not an authenticated W3 packet";
    let (stored, wire)=send(
        IngressRoute::Mailbox {
            store:&mut relay,
            grant:LabRelayGrant{
                route_token:id(9),message_id:id(9),now:100,expires_at:200,
            },
        },fake
    );
    assert!(matches!(stored,Ok(IngressOutcome::MailboxStored(PutStatus::Stored))));
    assert!(wire.is_empty());

    let sender=SigningKey::from_bytes(&[1;32]);
    let recipient=SigningKey::from_bytes(&[2;32]);
    let (secret,_) = new_recipient();
    let trust=enrolled(&sender,&recipient);
    let mut inbox=Journal::open(&dir.path().join("recipient.sqlite")).unwrap();
    let (rejected,no_ack)=send(
        IngressRoute::Recipient{
            journal:&mut inbox,
            context:TrustedRecipient{
                secret:&secret,recipient_id:id(2),now:101,registry:&trust,
            },
            signer:&recipient,signer_epoch:4,
        },fake,
    );
    assert!(matches!(rejected,Err(BridgeError::Recipient(JournalError::Unauthorized))));
    assert!(no_ack.is_empty());
    assert!(inbox.queued_recipient_receipt(id(1),id(9)).unwrap().is_none());
}

#[test]
fn corrupt_or_oversized_stream_frames_cannot_touch_mailbox_or_send_ack() {
    let dir=tempdir().unwrap();
    let mut relay=Mailbox::open_recovery_gated(
        &dir.path().join("relay.sqlite"),MailboxLimits::default()
    ).unwrap();
    relay.try_resume_after_maintenance().unwrap();
    let grant=LabRelayGrant{route_token:id(9),message_id:id(7),now:100,expires_at:200};

    let oversized = u32::try_from(MAX_MESSAGE_BYTES+1).unwrap().to_be_bytes();
    let (rejected,ack)=tcp_once(
        IngressRoute::Mailbox{store:&mut relay,grant},&oversized,
    );
    assert!(matches!(rejected,Err(BridgeError::Wire(WireError::TooLarge))));
    assert!(ack.is_empty());
    assert_eq!(relay.stats().unwrap().messages,0);

    let mut truncated = Vec::from(30u32.to_be_bytes());
    truncated.extend_from_slice(b"short");
    let (rejected,ack)=tcp_once(
        IngressRoute::Mailbox{store:&mut relay,grant},&truncated,
    );
    assert!(matches!(rejected,Err(BridgeError::Io(_))));
    assert!(ack.is_empty());
    assert_eq!(relay.stats().unwrap().messages,0);
}

#[test]
fn forged_or_mismatched_recipient_ack_does_not_advance_sender_journal() {
    let dir=tempdir().unwrap();
    let mut sender_journal=Journal::open(&dir.path().join("sender.sqlite")).unwrap();
    let signer=SigningKey::from_bytes(&[2;32]);
    let fake_signer=SigningKey::from_bytes(&[3;32]);
    let mut trust=TrustRegistry::new();
    trust.enroll(id(2),4,signer.verifying_key()).unwrap();
    let packet=b"encrypted bytes from sender";
    sender_journal.enqueue(id(2),id(7),9000,packet).unwrap();
    let digest=*blake3::hash(packet).as_bytes();
    let forged=akula_wire_lab::receipt_w4::sign(&fake_signer,id(2),id(7),digest,4);
    let rejected=receive_verified_recipient_ack(
        &mut Cursor::new(stream_frame(&forged).unwrap()),
        &mut sender_journal,&trust,
    );
    assert!(matches!(rejected,Err(BridgeError::Receipt(_))));
    assert_eq!(sender_journal.state(id(2),id(7)).unwrap(),Delivery::Queued);

    let wrong_packet_digest=akula_wire_lab::receipt_w4::sign(
        &signer,id(2),id(7),[77u8;32],4
    );
    let wrong=receive_verified_recipient_ack(
        &mut Cursor::new(stream_frame(&wrong_packet_digest).unwrap()),
        &mut sender_journal,&trust,
    );
    assert!(matches!(wrong,Err(BridgeError::Recipient(JournalError::Conflict))));
    assert_eq!(sender_journal.state(id(2),id(7)).unwrap(),Delivery::Queued);

    let correct=akula_wire_lab::receipt_w4::sign(&signer,id(2),id(7),digest,4);
    assert_eq!(
        receive_verified_recipient_ack(
            &mut Cursor::new(stream_frame(&correct).unwrap()),
            &mut sender_journal,&trust,
        ).unwrap(),Delivery::Recipient
    );
}
