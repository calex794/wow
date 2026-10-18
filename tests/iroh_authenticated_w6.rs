//! W6: actual QUIC/TLS identity checks against two iroh 1.3 endpoints.
//! The CI harness binds ONLY IPv4 127.0.0.1 and uses presets::Minimal:
//! no external relay, N0 discovery, WAN or user information.
#![cfg(feature = "iroh-transport")]

use akula_wire_lab::crypto_identity_w3::{seal, SignedHeader};
use akula_wire_lab::crypto_w3::new_recipient;
use akula_wire_lab::guarded_tcp_w5::GuardedTcpClock;
use akula_wire_lab::ingress_bridge_w5::{BridgeError, IngressOutcome};
use akula_wire_lab::ingress_guard_w5::IngressGuard;
use akula_wire_lab::iroh_mailbox_w6::{
    receive_authenticated_iroh_mailbox, IrohAuthorizedPeer, IrohIngressError,
    IrohMailboxContext, W6_LAB_ALPN,
};
use akula_wire_lab::mailbox_w5::{Mailbox, MailboxLimits, PutStatus};
use akula_wire_lab::route_grant_w5::{
    sign_for_lab, GrantError, RelayGrantClaims, RelayPolicy,
};
use akula_wire_lab::stream_frame;
use akula_wire_lab::trust_w3::TrustRegistry;
use ed25519_dalek::SigningKey;
use iroh::{Endpoint, endpoint::{Connection, presets}};
use std::sync::Mutex;
use std::time::Duration;
use tempfile::{tempdir, TempDir};

fn id(n: u8) -> [u8; 16] { [n;16] }

async fn bind_lab(alpns: Vec<Vec<u8>>) -> Endpoint {
    Endpoint::builder(presets::Minimal)
        .clear_ip_transports()
        .bind_addr("127.0.0.1:0").unwrap()
        .alpns(alpns)
        .bind().await.unwrap()
}

struct Lab {
    _dir: TempDir,
    server: Endpoint,
    trusted: Endpoint,
    stranger: Endpoint,
    trusted_peer: IrohAuthorizedPeer,
    relay_policy: RelayPolicy,
    issuer_registry: TrustRegistry,
    device_registry: TrustRegistry,
    mailbox: Mutex<Mailbox>,
    guard: Mutex<IngressGuard>,
    signed_grant: Vec<u8>,
    packet: Vec<u8>,
}
impl Lab {
    async fn new() -> Self {
        let dir = tempdir().unwrap();
        let server = bind_lab(vec![W6_LAB_ALPN.to_vec()]).await;
        let trusted = bind_lab(vec![]).await;
        let stranger = bind_lab(vec![]).await;

        let mut mailbox = Mailbox::open_recovery_gated(
            &dir.path().join("mail.sqlite"), MailboxLimits::default(),
        ).unwrap();
        mailbox.try_resume_after_maintenance().unwrap();

        let issuer = SigningKey::from_bytes(&[10;32]);
        let w3_peer = SigningKey::from_bytes(&[11;32]);
        let sender = SigningKey::from_bytes(&[12;32]);
        let (_, recipient_key) = new_recipient();
        let packet = seal(&sender, &recipient_key, SignedHeader {
            message_id:id(5), recipient_id:id(8), expiry:8000,
            sender_id:id(9), epoch:4,
        }, b"actual E2E protected ciphertext").unwrap();

        let mut issuer_registry=TrustRegistry::new();
        issuer_registry.enroll(id(1),3,issuer.verifying_key()).unwrap();
        let mut device_registry=TrustRegistry::new();
        device_registry.enroll(id(7),9,w3_peer.verifying_key()).unwrap();
        let route_policy=RelayPolicy {
            issuer_id:id(1),relay_id:id(2),
            namespace:id(3),route_token:id(4),
        };
        let signed_grant=sign_for_lab(&issuer,RelayGrantClaims {
            issuer_id:route_policy.issuer_id,issuer_epoch:3,
            relay_id:route_policy.relay_id,namespace:route_policy.namespace,
            route_token:route_policy.route_token,message_id:id(5),
            expires_at:200,
            ciphertext_len:u32::try_from(packet.len()).unwrap(),
            ciphertext_digest:*blake3::hash(&packet).as_bytes(),
        }).unwrap();
        let trusted_peer=IrohAuthorizedPeer {
            endpoint_id:trusted.id(),w3_device_id:id(7),w3_epoch:9,
        };
        Self {
            _dir:dir,server,trusted,stranger,trusted_peer,
            relay_policy:route_policy,issuer_registry,device_registry,
            mailbox:Mutex::new(mailbox),guard:Mutex::new(IngressGuard::new()),
            signed_grant,packet,
        }
    }
    fn context<'a>(&'a self, peer: &'a IrohAuthorizedPeer, budget: Duration)
        -> IrohMailboxContext<'a>
    {
        IrohMailboxContext {
            local:&self.server,expected_local_id:self.server.id(),
            peer,devices:&self.device_registry,
            issuer_trust:&self.issuer_registry,
            relay_policy:&self.relay_policy,
            guard:&self.guard,mailbox:&self.mailbox,
            clock:GuardedTcpClock{
                monotonic_tick:0,now_seconds:100,read_budget:budget,
            },
        }
    }
    fn wire(&self)->Vec<u8> {
        [stream_frame(&self.signed_grant).unwrap(),
         stream_frame(&self.packet).unwrap()].concat()
    }
    fn assert_clean_guard(&self) {
        let stats=self.guard.lock().unwrap().stats();
        assert_eq!(stats.active,0);
        assert_eq!(stats.buffered_bytes,0);
    }
    fn assert_message_count(&self,expected:usize) {
        assert_eq!(
            self.mailbox.lock().unwrap().stats().unwrap().messages,expected
        );
    }
}

async fn connect_pair(server:&Endpoint, client:&Endpoint, alpn:&[u8])
    -> (Connection,Connection)
{
    let outgoing=tokio::time::timeout(
        Duration::from_secs(10),client.connect(server.addr(),alpn),
    ).await.unwrap().unwrap();
    let incoming=tokio::time::timeout(
        Duration::from_secs(10),server.accept(),
    ).await.unwrap().expect("server must accept");
    let accepted=tokio::time::timeout(
        Duration::from_secs(10),incoming,
    ).await.unwrap().unwrap();
    (outgoing,accepted)
}
async fn transmit(client:&Connection, bytes:&[u8]) {
    let (mut send,_recv)=client.open_bi().await.unwrap();
    send.write_all(bytes).await.unwrap();
    send.finish().unwrap();
}
async fn receive_with_bytes(
    lab:&Lab, peer:&IrohAuthorizedPeer,
    client:&Connection,server:&Connection, bytes:&[u8],
)->Result<IngressOutcome,IrohIngressError> {
    let ((),response)=tokio::join!(
        transmit(client,bytes),
        receive_authenticated_iroh_mailbox(
            server,lab.context(peer,Duration::from_secs(5)),
        ),
    );
    response
}

#[tokio::test(flavor="multi_thread",worker_threads=2)]
async fn real_quic_tls_identity_accepts_exact_message_once_without_relay_ack() {
    let lab=Lab::new().await;
    let (sender,receiver)=connect_pair(
        &lab.server,&lab.trusted,W6_LAB_ALPN,
    ).await;
    assert_eq!(receiver.remote_id(),lab.trusted.id());
    assert_eq!(sender.remote_id(),lab.server.id());

    let first=receive_with_bytes(
        &lab,&lab.trusted_peer,&sender,&receiver,&lab.wire(),
    ).await;
    assert!(matches!(first,Ok(IngressOutcome::MailboxStored(PutStatus::Stored))));
    lab.assert_clean_guard();
    lab.assert_message_count(1);
    assert_eq!(
        lab.mailbox.lock().unwrap()
            .get_page(id(4),101,None,1).unwrap()[0].bytes,
        lab.packet,
    );

    let next=receive_with_bytes(
        &lab,&lab.trusted_peer,&sender,&receiver,&lab.wire(),
    ).await;
    assert!(matches!(next,Ok(IngressOutcome::MailboxStored(PutStatus::Duplicate))));
    lab.assert_message_count(1);
    lab.assert_clean_guard();
}

#[tokio::test(flavor="multi_thread",worker_threads=2)]
async fn stolen_route_grant_cannot_be_used_from_different_tls_endpoint_id() {
    let lab=Lab::new().await;
    let (_,server)=connect_pair(
        &lab.server,&lab.stranger,W6_LAB_ALPN,
    ).await;
    assert_eq!(server.remote_id(),lab.stranger.id());
    let rejected=receive_authenticated_iroh_mailbox(
        &server,lab.context(&lab.trusted_peer,Duration::from_secs(2)),
    ).await;
    assert!(matches!(rejected,Err(IrohIngressError::WrongRemoteEndpoint)));
    lab.assert_message_count(0);
    lab.assert_clean_guard();
}

#[tokio::test(flavor="multi_thread",worker_threads=2)]
async fn revoked_or_wrong_epoch_device_cannot_submit_on_authenticated_quic() {
    let mut lab=Lab::new().await;
    lab.device_registry.revoke(id(7)).unwrap();
    let (_,receiver)=connect_pair(
        &lab.server,&lab.trusted,W6_LAB_ALPN,
    ).await;
    assert!(matches!(
        receive_authenticated_iroh_mailbox(
            &receiver,lab.context(&lab.trusted_peer,Duration::from_secs(2)),
        ).await,
        Err(IrohIngressError::RevokedOrStaleDevice)
    ));
    lab.assert_message_count(0);
    lab.assert_clean_guard();
}

#[tokio::test(flavor="multi_thread",worker_threads=2)]
async fn authorized_quic_peer_cannot_submit_forged_grant_or_extra_frame() {
    let lab=Lab::new().await;
    let (outgoing,incoming)=connect_pair(
        &lab.server,&lab.trusted,W6_LAB_ALPN,
    ).await;
    let mut forged=lab.signed_grant.clone();
    *forged.last_mut().unwrap() ^= 1;
    let bad=[stream_frame(&forged).unwrap(),
        stream_frame(&lab.packet).unwrap()].concat();
    assert!(matches!(
        receive_with_bytes(
            &lab,&lab.trusted_peer,&outgoing,&incoming,&bad,
        ).await,
        Err(IrohIngressError::Bridge(
            BridgeError::Grant(GrantError::InvalidSignature)
        ))
    ));
    lab.assert_message_count(0);
    lab.assert_clean_guard();

    // A third frame is invalid, even if the grant and ciphertext are genuine.
    let extras=[lab.wire(),stream_frame(b"unexpected").unwrap()].concat();
    assert!(matches!(
        receive_with_bytes(
            &lab,&lab.trusted_peer,&outgoing,&incoming,&extras,
        ).await,
        Err(IrohIngressError::InvalidFrame)
    ));
    lab.assert_message_count(0);
    lab.assert_clean_guard();
}

#[tokio::test(flavor="multi_thread",worker_threads=2)]
async fn incomplete_authenticated_stream_times_out_and_releases_ticket() {
    let lab=Lab::new().await;
    let (_outgoing,incoming)=connect_pair(
        &lab.server,&lab.trusted,W6_LAB_ALPN,
    ).await;
    let start=tokio::time::Instant::now();
    let result=receive_authenticated_iroh_mailbox(
        &incoming,lab.context(&lab.trusted_peer,Duration::from_millis(150)),
    ).await;
    assert!(matches!(result,Err(IrohIngressError::DeadlineExceeded)));
    assert!(start.elapsed() >= Duration::from_millis(100));
    lab.assert_message_count(0);
    lab.assert_clean_guard();
}
