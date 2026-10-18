//! Kernel-TCP, loopback-only proof-of-possession experiments. Signed grant
//! alone must not permit storage by an unknown/untrusted local process.
//! THIS IS NOT A TLS/Noise session or a public TCP listener.
use akula_wire_lab::guarded_tcp_w5::{
    serve_mutual_peer_proof_loopback_mailbox_tcp_shared,
    GuardedTcpClock, GuardedTcpError,
};
use akula_wire_lab::ingress_bridge_w5::{BridgeError, IngressOutcome};
use akula_wire_lab::ingress_guard_w5::IngressGuard;
use akula_wire_lab::mailbox_w5::{Mailbox, MailboxLimits, PutStatus};
use akula_wire_lab::peer_proof_w5::{
    verify_relay_and_answer, PeerProofError, PeerRouteScope,
    SIGNED_CHALLENGE_LEN,
};
use akula_wire_lab::route_grant_w5::{
    sign_for_lab, GrantError, RelayGrantClaims, RelayPolicy,
};
use akula_wire_lab::trust_w3::TrustRegistry;
use akula_wire_lab::stream_frame;
use ed25519_dalek::SigningKey;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use tempfile::{tempdir, TempDir};

fn id(n: u8) -> [u8;16] { [n;16] }

struct Case {
    _dir: TempDir,
    guard: Arc<Mutex<IngressGuard>>,
    store: Arc<Mutex<Mailbox>>,
    issuer_trust: Arc<TrustRegistry>,
    devices: Arc<TrustRegistry>,
    relay: Arc<SigningKey>,
    peer: SigningKey,
    policy: RelayPolicy,
    scope: PeerRouteScope,
    grant: Vec<u8>,
    packet: Vec<u8>,
}

impl Case {
    fn new() -> Self {
        let dir = tempdir().unwrap();
        let mut mail = Mailbox::open_recovery_gated(
            &dir.path().join("mail.sqlite"), MailboxLimits::default(),
        ).unwrap();
        mail.try_resume_after_maintenance().unwrap();

        let issuer=SigningKey::from_bytes(&[11;32]);
        let relay=Arc::new(SigningKey::from_bytes(&[12;32]));
        let peer=SigningKey::from_bytes(&[13;32]);
        let mut issuers=TrustRegistry::new();
        issuers.enroll(id(1),3,issuer.verifying_key()).unwrap();
        let mut devices=TrustRegistry::new();
        devices.enroll(id(2),7,relay.verifying_key()).unwrap();
        devices.enroll(id(3),9,peer.verifying_key()).unwrap();
        let policy=RelayPolicy {
            issuer_id:id(1),relay_id:id(2),namespace:id(4),route_token:id(5),
        };
        let scope=PeerRouteScope {
            device_id:id(3),device_epoch:9,relay_epoch:7,
        };
        let packet=b"unchanged opaque W3 encrypted bytes".to_vec();
        let grant=sign_for_lab(&issuer,RelayGrantClaims {
            issuer_id:id(1),issuer_epoch:3,relay_id:id(2),
            namespace:id(4),route_token:id(5),message_id:id(6),
            expires_at:200,ciphertext_len:u32::try_from(packet.len()).unwrap(),
            ciphertext_digest:*blake3::hash(&packet).as_bytes(),
        }).unwrap();
        Self {
            _dir:dir, guard:Arc::new(Mutex::new(IngressGuard::new())),
            store:Arc::new(Mutex::new(mail)),
            issuer_trust:Arc::new(issuers),devices:Arc::new(devices),
            relay,peer,policy,scope,grant,packet,
        }
    }

    fn run<F>(&self, grant:&[u8], respond:F)
      -> (Result<IngressOutcome,GuardedTcpError>,Vec<u8>,Option<Vec<u8>>)
    where F: FnOnce(&mut TcpStream,Option<&[u8]>) {
        let listener=TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client=TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        client.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        client.write_all(&stream_frame(grant).unwrap()).unwrap();
        let (socket,_)=listener.accept().unwrap();

        let guard=Arc::clone(&self.guard);
        let store=Arc::clone(&self.store);
        let issuer_trust=Arc::clone(&self.issuer_trust);
        let devices=Arc::clone(&self.devices);
        let relay=Arc::clone(&self.relay);
        let policy=self.policy;
        let scope=self.scope;
        let server=thread::spawn(move || {
            serve_mutual_peer_proof_loopback_mailbox_tcp_shared(
                socket,&guard,GuardedTcpClock {
                    monotonic_tick:0,now_seconds:100,
                    read_budget:Duration::from_millis(700),
                },
                &store,&policy,&issuer_trust,&devices,&relay,scope,
            )
        });
        // Server may reject untrusted peers before issuing a challenge.
        let challenge=read_frame(&mut client).ok();
        respond(&mut client,challenge.as_deref());
        let _=client.shutdown(Shutdown::Write);
        let mut trailing=Vec::new();
        let _=client.read_to_end(&mut trailing);
        (server.join().unwrap(),trailing,challenge)
    }

    fn assert_empty(&self) {
        assert_eq!(self.store.lock().unwrap().stats().unwrap().messages,0);
        assert_eq!(self.guard.lock().unwrap().stats().active,0);
        assert_eq!(self.guard.lock().unwrap().stats().buffered_bytes,0);
    }
}

fn read_frame(stream:&mut TcpStream)->std::io::Result<Vec<u8>> {
    let mut hdr=[0u8;4];
    stream.read_exact(&mut hdr)?;
    let n=u32::from_be_bytes(hdr) as usize;
    if n>1024 {return Err(std::io::Error::from(std::io::ErrorKind::InvalidData));}
    let mut body=vec![0u8;n];
    stream.read_exact(&mut body)?;
    Ok(body)
}

fn answer(
    case:&Case,client:&mut TcpStream,challenge:Option<&[u8]>,
    signer:&SigningKey,packet:&[u8],
) {
    let challenge=challenge.expect("relay must provide signed challenge");
    assert_eq!(challenge.len(),SIGNED_CHALLENGE_LEN);
    let signed=verify_relay_and_answer(
        challenge,&case.grant,&case.policy,case.scope,&case.devices,signer,
    ).unwrap();
    client.write_all(&stream_frame(&signed).unwrap()).unwrap();
    client.write_all(&stream_frame(packet).unwrap()).unwrap();
}

#[test]
fn signed_grant_and_mutual_pinned_peer_proof_store_without_recipient_ack() {
    let case=Case::new();
    let (outcome,reply,challenge)=case.run(&case.grant,|client,challenge|{
        answer(&case,client,challenge,&case.peer,&case.packet);
    });
    assert!(challenge.is_some());
    assert!(matches!(outcome,Ok(IngressOutcome::MailboxStored(PutStatus::Stored))));
    assert!(reply.is_empty(), "relay cannot emit end-recipient receipt");
    assert_eq!(case.store.lock().unwrap().stats().unwrap().messages,1);
    assert_eq!(case.guard.lock().unwrap().stats().active,0);
    assert_eq!(
        case.guard.lock().unwrap().stats().accepted_bytes_this_tick,
        case.grant.len()+89
    );
}

#[test]
fn stolen_signed_grant_without_approved_private_key_cannot_store() {
    let case=Case::new();
    let impostor=SigningKey::from_bytes(&[14;32]);
    let (outcome,reply,_)=case.run(&case.grant,|client,challenge|{
        answer(&case,client,challenge,&impostor,&case.packet);
    });
    assert!(matches!(
        outcome,Err(GuardedTcpError::PeerProof(PeerProofError::InvalidSignature))
    ));
    assert!(reply.is_empty());
    case.assert_empty();
}

#[test]
fn captured_proof_cannot_be_replayed_on_another_connection() {
    let case=Case::new();
    let mut cached_response=Vec::new();
    let (first,_,first_challenge)=case.run(&case.grant,|client,ch|{
        cached_response=verify_relay_and_answer(
            ch.unwrap(),&case.grant,&case.policy,case.scope,
            &case.devices,&case.peer,
        ).unwrap();
        client.write_all(&stream_frame(&cached_response).unwrap()).unwrap();
        client.write_all(&stream_frame(&case.packet).unwrap()).unwrap();
    });
    assert!(matches!(first,Ok(IngressOutcome::MailboxStored(PutStatus::Stored))));
    let (replayed,reply,next_challenge)=case.run(&case.grant,|client,ch|{
        assert!(ch.is_some());
        client.write_all(&stream_frame(&cached_response).unwrap()).unwrap();
        client.write_all(&stream_frame(&case.packet).unwrap()).unwrap();
    });
    assert_ne!(first_challenge,next_challenge,"nonce must be fresh");
    assert!(matches!(
        replayed,Err(GuardedTcpError::PeerProof(PeerProofError::InvalidSignature))
    ));
    assert!(reply.is_empty());
    assert_eq!(case.store.lock().unwrap().stats().unwrap().messages,1);
    assert_eq!(case.guard.lock().unwrap().stats().active,0);
}

#[test]
fn even_authenticated_peer_cannot_use_forged_route_issuer_grant() {
    let case=Case::new();
    let mut forged=case.grant.clone();
    *forged.last_mut().unwrap()^=1;
    let (outcome,reply,_)=case.run(&forged,|client,ch|{
        let response=verify_relay_and_answer(
            ch.unwrap(),&forged,&case.policy,case.scope,
            &case.devices,&case.peer,
        ).unwrap();
        client.write_all(&stream_frame(&response).unwrap()).unwrap();
        client.write_all(&stream_frame(&case.packet).unwrap()).unwrap();
    });
    assert!(matches!(
        outcome,Err(GuardedTcpError::Bridge(
            BridgeError::Grant(GrantError::InvalidSignature)
        ))
    ));
    assert!(reply.is_empty());
    case.assert_empty();
}

#[test]
fn revoked_or_rotated_device_never_receives_an_authorized_challenge() {
    let mut revoked=Case::new();
    Arc::get_mut(&mut revoked.devices).unwrap().revoke(id(3)).unwrap();
    let (outcome,reply,ch)=revoked.run(&revoked.grant,|_,_|{});
    assert!(ch.is_none());
    assert!(reply.is_empty());
    assert!(matches!(
        outcome,Err(GuardedTcpError::PeerProof(PeerProofError::UntrustedPeer))
    ));
    revoked.assert_empty();

    let mut rotated=Case::new();
    let new_key=SigningKey::from_bytes(&[15;32]);
    Arc::get_mut(&mut rotated.devices).unwrap().enroll(
        id(3),10,new_key.verifying_key()
    ).unwrap();
    let (outcome,reply,ch)=rotated.run(&rotated.grant,|_,_|{});
    assert!(ch.is_none());
    assert!(reply.is_empty());
    assert!(matches!(
        outcome,Err(GuardedTcpError::PeerProof(PeerProofError::UntrustedPeer))
    ));
    rotated.assert_empty();
}

#[test]
fn missing_response_times_out_and_releases_pre_auth_ticket() {
    let case=Case::new();
    let (outcome,reply,ch)=case.run(&case.grant,|_client,_challenge|{
        // Keep the write half OPEN: no response, no ciphertext.
    });
    assert!(ch.is_some());
    assert!(reply.is_empty());
    assert!(matches!(outcome,Err(GuardedTcpError::DeadlineExceeded)));
    case.assert_empty();
}
