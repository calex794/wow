//! Actual kernel TCP pre-auth ingress tests for the W4/W5 Mailbox.
//! Only 127.0.0.1 is used; no external listener, peer identity, or public API.
use akula_wire_lab::guarded_tcp_w5::{
    serve_guarded_loopback_mailbox_tcp, GuardedTcpClock, GuardedTcpError,
};
use akula_wire_lab::ingress_bridge_w5::{BridgeError, IngressOutcome};
use akula_wire_lab::ingress_guard_w5::{AdmissionError, IngressGuard, Lane};
use akula_wire_lab::mailbox_w5::{Mailbox, MailboxLimits, PutStatus};
use akula_wire_lab::route_grant_w5::{
    sign_for_lab, GrantError, RelayGrantClaims, RelayPolicy, SIGNED_GRANT_LEN,
};
use akula_wire_lab::trust_w3::TrustRegistry;
use akula_wire_lab::{stream_frame, WireError, MAX_MESSAGE_BYTES};
use ed25519_dalek::SigningKey;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::Mutex;
use std::time::Duration;
use tempfile::tempdir;

fn id(n: u8) -> [u8;16] { [n;16] }

fn issued_grant(packet: &[u8], expires: i64) -> (TrustRegistry, RelayPolicy, Vec<u8>) {
    let issuer=SigningKey::from_bytes(&[10;32]);
    let mut trust=TrustRegistry::new();
    trust.enroll(id(1),3,issuer.verifying_key()).unwrap();
    let policy=RelayPolicy {
        issuer_id:id(1),relay_id:id(2),namespace:id(3),route_token:id(4)
    };
    let grant=sign_for_lab(&issuer,RelayGrantClaims {
        issuer_id:policy.issuer_id,issuer_epoch:3,
        relay_id:policy.relay_id,namespace:policy.namespace,
        route_token:policy.route_token,message_id:id(5),expires_at:expires,
        ciphertext_len:u32::try_from(packet.len()).unwrap(),
        ciphertext_digest:*blake3::hash(packet).as_bytes(),
    }).unwrap();
    (trust,policy,grant)
}

fn wire(grant: &[u8], packet: &[u8]) -> Vec<u8> {
    [stream_frame(grant).unwrap(),stream_frame(packet).unwrap()].concat()
}

fn clock(tick: u64) -> GuardedTcpClock {
    GuardedTcpClock {
        monotonic_tick:tick, now_seconds:100, read_budget:Duration::from_millis(400),
    }
}

/// For an intentionally bad frame, a close with unread TCP bytes may cause
/// ECONNRESET on the test client. We only inspect any actually received bytes.
fn tcp_once(
    guard:&Mutex<IngressGuard>, cfg:GuardedTcpClock,
    store:&mut Mailbox, policy:&RelayPolicy, trust:&TrustRegistry,
    data:&[u8], finish_writing:bool,
) -> (Result<IngressOutcome,GuardedTcpError>,Vec<u8>) {
    let listener=TcpListener::bind("127.0.0.1:0").unwrap();
    let mut client=TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    client.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    client.write_all(data).unwrap();
    if finish_writing { client.shutdown(Shutdown::Write).unwrap(); }
    let (server,_)=listener.accept().unwrap();
    let result=serve_guarded_loopback_mailbox_tcp(
        server,guard,cfg,store,policy,trust,
    );
    let mut reply=Vec::new();
    let _=client.read_to_end(&mut reply);
    (result,reply)
}

#[test]
fn scoped_grant_relay_store_is_bounded_and_does_not_issue_recipient_ack() {
    let dir=tempdir().unwrap();
    let mut store=Mailbox::open_recovery_gated(
        &dir.path().join("mail.sqlite"),MailboxLimits::default()
    ).unwrap();
    store.try_resume_after_maintenance().unwrap();
    let packet=b"unchanged encrypted W3 bytes";
    let (trust,policy,grant)=issued_grant(packet,200);
    assert_eq!(grant.len(),SIGNED_GRANT_LEN);
    let guard=Mutex::new(IngressGuard::new());
    for expected in [PutStatus::Stored,PutStatus::Duplicate] {
        let (outcome,wire_reply)=tcp_once(
            &guard,clock(0),&mut store,&policy,&trust,&wire(&grant,packet),true
        );
        assert!(matches!(
            outcome,Ok(IngressOutcome::MailboxStored(status)) if status==expected
        ));
        assert!(wire_reply.is_empty(), "relay cannot sign or send recipient ACK");
    }
    let s=guard.lock().unwrap().stats();
    assert_eq!(s.active,0);
    assert_eq!(s.buffered_bytes,0);
    assert_eq!(s.attempts_this_tick,2);
    assert_eq!(s.accepted_bytes_this_tick,2*SIGNED_GRANT_LEN);
    assert_eq!(store.stats().unwrap().messages,1);
    assert_eq!(
        store.get_page(id(4),101,None,1).unwrap()[0].bytes,packet
    );
}

#[test]
fn invalid_grant_and_wrong_ciphertext_never_touch_mailbox() {
    let dir=tempdir().unwrap();
    let mut store=Mailbox::open_recovery_gated(
        &dir.path().join("mail.sqlite"),MailboxLimits::default()
    ).unwrap();
    store.try_resume_after_maintenance().unwrap();
    let packet=b"message requires signed capability";
    let (mut trust,policy,grant)=issued_grant(packet,200);
    let guard=Mutex::new(IngressGuard::new());

    let (wrong,reply)=tcp_once(
        &guard,clock(0),&mut store,&policy,&trust,
        &wire(&grant,b"altered message"),true,
    );
    assert!(matches!(
        wrong,Err(GuardedTcpError::Bridge(BridgeError::Grant(GrantError::PacketMismatch)))
    ));
    assert!(reply.is_empty());

    let mut tampered=grant.clone();
    tampered[140]^=1;
    let (forged,reply)=tcp_once(
        &guard,clock(0),&mut store,&policy,&trust,&wire(&tampered,packet),true,
    );
    assert!(matches!(
        forged,Err(GuardedTcpError::Bridge(BridgeError::Grant(GrantError::InvalidSignature)))
    ));
    assert!(reply.is_empty());

    trust.revoke(id(1)).unwrap();
    let (revoked,reply)=tcp_once(
        &guard,clock(0),&mut store,&policy,&trust,&wire(&grant,packet),true,
    );
    assert!(matches!(
        revoked,Err(GuardedTcpError::Bridge(BridgeError::Grant(GrantError::UntrustedIssuer)))
    ));
    assert!(reply.is_empty());
    assert_eq!(store.stats().unwrap().messages,0);
    assert_eq!(guard.lock().unwrap().stats().active,0);
}

#[test]
fn malformed_or_oversized_frame_rejected_before_payload_allocation_and_storage() {
    let dir=tempdir().unwrap();
    let mut store=Mailbox::open_recovery_gated(
        &dir.path().join("mail.sqlite"),MailboxLimits::default()
    ).unwrap();
    store.try_resume_after_maintenance().unwrap();
    let packet=b"valid grant packet";
    let (trust,policy,grant)=issued_grant(packet,200);
    let guard=Mutex::new(IngressGuard::new());

    // The guard frame must have exactly the fixed signed-grant size.
    let wrong_grant=(SIGNED_GRANT_LEN as u32 - 1).to_be_bytes();
    let (result,reply)=tcp_once(
        &guard,clock(0),&mut store,&policy,&trust,&wrong_grant,true,
    );
    assert!(matches!(result,Err(GuardedTcpError::InvalidGrantFrameLength)));
    assert!(reply.is_empty());

    // Full valid grant, then a declared E2E body larger than MAX_MESSAGE_BYTES.
    let mut oversized=stream_frame(&grant).unwrap();
    oversized.extend_from_slice(
        &u32::try_from(MAX_MESSAGE_BYTES+1).unwrap().to_be_bytes()
    );
    let (result,reply)=tcp_once(
        &guard,clock(0),&mut store,&policy,&trust,&oversized,true,
    );
    assert!(matches!(result,Err(GuardedTcpError::Wire(WireError::TooLarge))));
    assert!(reply.is_empty());
    assert_eq!(store.stats().unwrap().messages,0);
    assert_eq!(guard.lock().unwrap().stats().active,0);
}

#[test]
fn held_lan_tickets_deny_new_tcp_before_reading_and_preserve_storage() {
    let dir=tempdir().unwrap();
    let mut store=Mailbox::open_recovery_gated(
        &dir.path().join("mail.sqlite"),MailboxLimits::default()
    ).unwrap();
    store.try_resume_after_maintenance().unwrap();
    let packet=b"ordinary legitimate packet";
    let (trust,policy,grant)=issued_grant(packet,200);
    let guard=Mutex::new(IngressGuard::new());
    let tickets={
        let mut g=guard.lock().unwrap();
        (0..8).map(|n|g.begin(Lane::LocalNetwork,id(n)).unwrap()).collect::<Vec<_>>()
    };
    let (result,reply)=tcp_once(
        &guard,clock(0),&mut store,&policy,&trust,&wire(&grant,packet),true
    );
    assert!(matches!(result,Err(GuardedTcpError::Admission(AdmissionError::AtCapacity))));
    assert!(reply.is_empty());
    assert_eq!(store.stats().unwrap().messages,0);
    {
        let mut g=guard.lock().unwrap();
        assert_eq!(g.stats().active,8);
        for ticket in tickets {g.cancel(ticket).unwrap();}
        assert_eq!(g.stats().active,0);
    }
    let (result,reply)=tcp_once(
        &guard,clock(0),&mut store,&policy,&trust,&wire(&grant,packet),true
    );
    assert!(matches!(result,Ok(IngressOutcome::MailboxStored(PutStatus::Stored))));
    assert!(reply.is_empty());
}

#[test]
fn repeated_aborted_tcp_attempts_cannot_reset_same_tick_quota() {
    let dir=tempdir().unwrap();
    let mut store=Mailbox::open_recovery_gated(
        &dir.path().join("mail.sqlite"),MailboxLimits::default()
    ).unwrap();
    store.try_resume_after_maintenance().unwrap();
    let packet=b"one fixed message";
    let (trust,policy,grant)=issued_grant(packet,200);
    let guard=Mutex::new(IngressGuard::new());
    for _ in 0..12 {
        let (result,_)=tcp_once(
            &guard,clock(0),&mut store,&policy,&trust,&[0,0,0,0],true
        );
        assert!(matches!(result,Err(GuardedTcpError::Wire(WireError::InvalidEncoding))));
    }
    let (denied,reply)=tcp_once(
        &guard,clock(0),&mut store,&policy,&trust,&wire(&grant,packet),true,
    );
    assert!(matches!(denied,Err(GuardedTcpError::Admission(AdmissionError::RateLimited))));
    assert!(reply.is_empty());
    assert_eq!(store.stats().unwrap().messages,0);
    let (accepted,reply)=tcp_once(
        &guard,clock(1),&mut store,&policy,&trust,&wire(&grant,packet),true,
    );
    assert!(matches!(accepted,Ok(IngressOutcome::MailboxStored(PutStatus::Stored))));
    assert!(reply.is_empty());
    assert_eq!(guard.lock().unwrap().stats().active,0);
}

#[test]
fn dribbling_prefix_hits_absolute_deadline_and_releases_slot() {
    let dir=tempdir().unwrap();
    let mut store=Mailbox::open_recovery_gated(
        &dir.path().join("mail.sqlite"),MailboxLimits::default()
    ).unwrap();
    store.try_resume_after_maintenance().unwrap();
    let packet=b"must not be written";
    let (trust,policy,_)=issued_grant(packet,200);
    let guard=Mutex::new(IngressGuard::new());
    // Keep client write half OPEN but send only 1 of the 4 prefix bytes.
    let (result,reply)=tcp_once(
        &guard,
        GuardedTcpClock {
            monotonic_tick:0,now_seconds:100,
            read_budget:Duration::from_millis(110),
        },
        &mut store,&policy,&trust,&[0],false,
    );
    assert!(matches!(result,Err(GuardedTcpError::DeadlineExceeded)));
    assert!(reply.is_empty());
    assert_eq!(guard.lock().unwrap().stats().active,0);
    assert_eq!(guard.lock().unwrap().stats().buffered_bytes,0);
    assert_eq!(store.stats().unwrap().messages,0);
}
