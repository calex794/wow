//! W6: actual QUIC/TLS identity checks against two iroh 1.3 endpoints.
//! The CI harness binds ONLY IPv4 127.0.0.1 and uses presets::Minimal:
//! no external relay, N0 discovery, WAN or user information.
#![cfg(feature = "iroh-transport")]

#[path = "support/w6_memory_anchor.rs"]
mod w6_memory_anchor;
use w6_memory_anchor::MemoryAnchor;

use akula_wire_lab::crypto_identity_w3::{seal, SignedHeader};
use akula_wire_lab::crypto_w3::new_recipient;
use akula_wire_lab::guarded_tcp_w5::GuardedTcpClock;
use akula_wire_lab::ingress_bridge_w5::{BridgeError, IngressOutcome};
use akula_wire_lab::ingress_guard_w5::IngressGuard;
use akula_wire_lab::iroh_mailbox_w6::{
    receive_authenticated_iroh_mailbox, IrohIngressError,
    IrohMailboxContext, W6_LAB_ALPN,
};
use akula_wire_lab::mailbox_w5::{Mailbox, MailboxLimits, PutStatus};
use akula_wire_lab::peer_enrollment_w6::{
    sign_operator_change, EndpointRouteBinding, EnrollmentError,
    OperatorChange, PeerEnrollmentDb, PolicyOperation,
};
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
    enrollment: Mutex<PeerEnrollmentDb>,
    anchor: MemoryAnchor,
    operator: SigningKey,
    trusted_binding: EndpointRouteBinding,
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
        let operator = SigningKey::from_bytes(&[20;32]);
        let trusted_binding = EndpointRouteBinding {
            endpoint_id:trusted.id(),w3_device_id:id(7),w3_epoch:9,
            relay_id:route_policy.relay_id,namespace:route_policy.namespace,
            route_token:route_policy.route_token,issuer_id:route_policy.issuer_id,
        };
        let mut enrollment = PeerEnrollmentDb::open(
            &dir.path().join("peer-policy.sqlite"), operator.verifying_key(),
        ).unwrap();
        let signed = sign_operator_change(&operator, &OperatorChange {
            operation: PolicyOperation::Allow, revision:1,
            binding:trusted_binding,
        }).unwrap();
        enrollment.apply_signed(&signed).unwrap();
        // Test-only independent checkpoint bootstrapped explicitly after
        // offline operator enrollment. Never bootstrap from untrusted DB
        // automatically in a real network service.
        let anchor = MemoryAnchor::new(enrollment.checkpoint().unwrap());
        assert_eq!(anchor.observed().revision,1);
        Self {
            _dir:dir,server,trusted,stranger,
            enrollment:Mutex::new(enrollment),anchor,operator,trusted_binding,
            relay_policy:route_policy,issuer_registry,device_registry,
            mailbox:Mutex::new(mailbox),guard:Mutex::new(IngressGuard::new()),
            signed_grant,packet,
        }
    }
    fn context(&self, budget: Duration) -> IrohMailboxContext<'_>
    {
        IrohMailboxContext {
            local:&self.server,expected_local_id:self.server.id(),
            enrollments:&self.enrollment,policy_anchor:&self.anchor,
            devices:&self.device_registry,
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
    // Both halves of iroh's TLS/QUIC handshake must be polled together.
    // Awaiting connect() before accept() deadlocks until the client times out.
    let (outgoing,incoming)=tokio::join!(
        tokio::time::timeout(
            Duration::from_secs(10), client.connect(server.addr(),alpn),
        ),
        tokio::time::timeout(Duration::from_secs(10),async {
            let incoming=server.accept().await.expect("server must accept");
            incoming.await
        }),
    );
    (outgoing.unwrap().unwrap(), incoming.unwrap().unwrap())
}
async fn transmit(client:&Connection, bytes:&[u8]) {
    let (mut send,_recv)=client.open_bi().await.unwrap();
    send.write_all(bytes).await.unwrap();
    send.finish().unwrap();
}
async fn receive_with_bytes(
    lab:&Lab,
    client:&Connection,server:&Connection, bytes:&[u8],
)->Result<IngressOutcome,IrohIngressError> {
    let ((),response)=tokio::join!(
        transmit(client,bytes),
        receive_authenticated_iroh_mailbox(
            server,lab.context(Duration::from_secs(5)),
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
        &lab,&sender,&receiver,&lab.wire(),
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
        &lab,&sender,&receiver,&lab.wire(),
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
        &server,lab.context(Duration::from_secs(2)),
    ).await;
    assert!(matches!(rejected,Err(IrohIngressError::Enrollment(EnrollmentError::UnknownEndpoint))));
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
            &receiver,lab.context(Duration::from_secs(2)),
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
            &lab,&outgoing,&incoming,&bad,
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
            &lab,&outgoing,&incoming,&extras,
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
        &incoming,lab.context(Duration::from_millis(150)),
    ).await;
    assert!(matches!(result,Err(IrohIngressError::DeadlineExceeded)));
    assert!(start.elapsed() >= Duration::from_millis(100));
    lab.assert_message_count(0);
    lab.assert_clean_guard();
}


#[tokio::test(flavor="multi_thread",worker_threads=2)]
async fn signed_operator_revoke_drops_existing_quic_endpoint_before_ingress() {
    let lab=Lab::new().await;
    let (sender,receiver)=connect_pair(&lab.server,&lab.trusted,W6_LAB_ALPN).await;
    // TLS connection remains alive after operator revokes its route binding.
    let revoke = sign_operator_change(&lab.operator,&OperatorChange {
        operation:PolicyOperation::Revoke,revision:2,binding:lab.trusted_binding,
    }).unwrap();
    lab.enrollment.lock().unwrap().apply_signed_anchored(&revoke,&lab.anchor).unwrap();
    assert!(matches!(
        receive_authenticated_iroh_mailbox(
            &receiver,lab.context(Duration::from_secs(2))
        ).await,
        Err(IrohIngressError::Enrollment(EnrollmentError::Revoked))
    ));
    // Even a still-valid W5 signed-grant capability and encrypted ciphertext
    // cannot restore access after operator revocation.
    assert!(sender.remote_id()==lab.server.id());
    lab.assert_message_count(0);
    lab.assert_clean_guard();
}

#[tokio::test(flavor="multi_thread",worker_threads=2)]
async fn revocation_between_ticket_admission_and_read_fails_at_commit_boundary() {
    let lab=Lab::new().await;
    let (sender,receiver)=connect_pair(&lab.server,&lab.trusted,W6_LAB_ALPN).await;

    let result=receive_authenticated_iroh_mailbox(
        &receiver,lab.context(Duration::from_secs(5)),
    );
    let attack=async {
        // Wait until the receiver has really reserved a shared ingress
        // ticket, meaning it already checked initial enrollment and is
        // awaiting a QUIC application stream.
        let deadline=tokio::time::Instant::now()+Duration::from_secs(2);
        while lab.guard.lock().unwrap().stats().active==0 {
            assert!(tokio::time::Instant::now()<deadline,"no admission ticket");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let signed = sign_operator_change(&lab.operator,&OperatorChange {
            operation:PolicyOperation::Revoke,revision:2,
            binding:lab.trusted_binding,
        }).unwrap();
        lab.enrollment.lock().unwrap().apply_signed_anchored(&signed,&lab.anchor).unwrap();
        transmit(&sender,&lab.wire()).await;
    };
    let (outcome,())=tokio::join!(result,attack);
    assert!(matches!(
        outcome,Err(IrohIngressError::Enrollment(EnrollmentError::Revoked))
    ));
    lab.assert_message_count(0);
    lab.assert_clean_guard();
}

#[tokio::test(flavor="multi_thread",worker_threads=2)]
async fn operator_bound_route_scope_is_checked_beyond_tls_identity() {
    let lab=Lab::new().await;
    let (_,receiver)=connect_pair(&lab.server,&lab.trusted,W6_LAB_ALPN).await;
    let forbidden=RelayPolicy {route_token:id(55),..lab.relay_policy};
    let mut context=lab.context(Duration::from_secs(2));
    context.relay_policy=&forbidden;
    let result=receive_authenticated_iroh_mailbox(&receiver,context).await;
    assert!(matches!(
        result,Err(IrohIngressError::Enrollment(EnrollmentError::WrongScope))
    ));
    lab.assert_message_count(0);
    lab.assert_clean_guard();
}

#[tokio::test(flavor="multi_thread",worker_threads=2)]
async fn operator_signed_epoch_rotation_requires_matching_w3_registry() {
    let mut lab=Lab::new().await;
    let (sender,receiver)=connect_pair(&lab.server,&lab.trusted,W6_LAB_ALPN).await;
    let rotated=EndpointRouteBinding {w3_epoch:10,..lab.trusted_binding};
    let change=sign_operator_change(&lab.operator,&OperatorChange {
        operation:PolicyOperation::Allow,revision:2,binding:rotated,
    }).unwrap();
    lab.enrollment.lock().unwrap().apply_signed_anchored(&change,&lab.anchor).unwrap();
    // Policy now demands epoch 10, but W3 registry still holds epoch 9.
    assert!(matches!(
        receive_authenticated_iroh_mailbox(
            &receiver,lab.context(Duration::from_secs(2)),
        ).await,
        Err(IrohIngressError::RevokedOrStaleDevice)
    ));
    let new_w3_key=SigningKey::from_bytes(&[22;32]);
    lab.device_registry.enroll(id(7),10,new_w3_key.verifying_key()).unwrap();
    assert!(matches!(
        receive_with_bytes(&lab,&sender,&receiver,&lab.wire()).await,
        Ok(IngressOutcome::MailboxStored(PutStatus::Stored))
    ));
    lab.assert_message_count(1);
    lab.assert_clean_guard();
}

#[tokio::test(flavor="multi_thread",worker_threads=2)]
async fn wrong_alpn_rejected_before_ticket_or_storage_even_with_valid_tls_key() {
    let lab=Lab::new().await;
    let bad_alpn=b"akula-wow/other-app/1";
    // Deliberately offer both ALPNs in the server to allow a VALID QUIC/TLS
    // handshake negotiating the wrong protocol, rather than only a failed
    // handshake. This proves handler-level protocol separation.
    let wrong_server=bind_lab(vec![W6_LAB_ALPN.to_vec(),bad_alpn.to_vec()]).await;
    let (_,receiver)=connect_pair(&wrong_server,&lab.trusted,bad_alpn).await;
    let mut context=lab.context(Duration::from_secs(2));
    context.local=&wrong_server;
    context.expected_local_id=wrong_server.id();
    assert!(matches!(
        receive_authenticated_iroh_mailbox(&receiver,context).await,
        Err(IrohIngressError::WrongAlpn)
    ));
    lab.assert_message_count(0);
    lab.assert_clean_guard();
}


#[tokio::test(flavor="multi_thread",worker_threads=2)]
async fn trust_anchor_unavailable_rejects_genuine_roha_tls_before_stream() {
    let lab=Lab::new().await;
    let (_sender,receiver)=connect_pair(
        &lab.server,&lab.trusted,W6_LAB_ALPN,
    ).await;
    assert_eq!(receiver.remote_id(),lab.trusted.id());
    lab.anchor.set_unavailable(true);
    assert!(matches!(
        receive_authenticated_iroh_mailbox(
            &receiver,lab.context(Duration::from_secs(2)),
        ).await,
        Err(IrohIngressError::Enrollment(
            EnrollmentError::Anchor(
                akula_wire_lab::peer_enrollment_w6::AnchorError::Unavailable
            )
        ))
    ));
    lab.assert_message_count(0);
    lab.assert_clean_guard();
}

#[tokio::test(flavor="multi_thread",worker_threads=2)]
async fn unanchored_sql_policy_revoke_cannot_masquerade_as_verified_state() {
    let lab=Lab::new().await;
    let (_sender,receiver)=connect_pair(
        &lab.server,&lab.trusted,W6_LAB_ALPN,
    ).await;
    let forged_local_state=sign_operator_change(&lab.operator,&OperatorChange {
        operation:PolicyOperation::Revoke,revision:2,
        binding:lab.trusted_binding,
    }).unwrap();
    // This simulates a local-only policy mutation bypassing external
    // checkpoint publication. W6 network ingress MUST refuse both the old
    // and new state until an independently trusted checkpoint matches it.
    lab.enrollment.lock().unwrap().apply_signed(&forged_local_state).unwrap();
    assert!(matches!(
        receive_authenticated_iroh_mailbox(
            &receiver,lab.context(Duration::from_secs(2)),
        ).await,
        Err(IrohIngressError::Enrollment(
            EnrollmentError::CheckpointMismatch
        ))
    ));
    lab.assert_message_count(0);
    lab.assert_clean_guard();
}


/// This uses REAL pinned Blue W3 v3 HPKE/Ed25519 and TWO independent
/// Roha/noq TLS endpoints with separate SQLite stores on one CI host.
/// It DOES NOT prove two physical machines or recipient W4 return privacy.
#[tokio::test(flavor="multi_thread",worker_threads=2)]
async fn private_w3_v3_personal_to_public_custodian_over_real_roha_quic() {
    use akula_wire_lab::crypto_identity_w3::{SignedHeader,TrustedRecipient};
    use akula_wire_lab::private_route_w3;
    use akula_wire_lab::custody_receipt_w6::{self,ExpectedCustody};
    use akula_wire_lab::journal_w4::{Delivery,Insert,Journal};
    use akula_wire_lab::receipt_w4;
    use akula_wire_lab::mailbox_w5::Mailbox;
    use akula_wire_lab::mailbox_w5::MailboxLimits;

    let mut personal=Lab::new().await;
    let mut public=Lab::new().await;
    assert_ne!(personal.server.id(),public.server.id());
    assert_ne!(personal._dir.path(),public._dir.path());
    let sender=SigningKey::from_bytes(&[12;32]);
    let bob=SigningKey::from_bytes(&[18;32]);
    let (bob_secret,bob_pub)=new_recipient();
    let message=SignedHeader{
        message_id:id(5),recipient_id:id(8),expiry:500_000,
        sender_id:id(9),epoch:4,
    };
    let packet=private_route_w3::seal_private(
        &sender,&bob_pub,id(4),message,b"end-to-end secret via public custodian"
    ).unwrap();
    // The route hint contains NO persistent sender or recipient identity.
    let hint=private_route_w3::inspect_route(&packet).unwrap();
    assert_eq!(hint.token,id(4));
    assert_eq!(hint.message_id,id(5));
    assert_eq!(packet[0],private_route_w3::VERSION);
    assert!(packet[..private_route_w3::PUBLIC_HEADER_BYTES]
        .windows(16)
        .all(|chunk|chunk!=id(8).as_slice()&&chunk!=id(9).as_slice()));

    // Both operator-authorized route grants bind the exact same W3 ciphertext.
    let issuer=SigningKey::from_bytes(&[10;32]);
    let grant=|sealed:&[u8]| sign_for_lab(&issuer,RelayGrantClaims {
        issuer_id:id(1),issuer_epoch:3,relay_id:id(2),
        namespace:id(3),route_token:id(4),message_id:id(5),
        expires_at:200,
        ciphertext_len:u32::try_from(sealed.len()).unwrap(),
        ciphertext_digest:*blake3::hash(sealed).as_bytes(),
    }).unwrap();
    personal.packet=packet.clone();
    personal.signed_grant=grant(&packet);
    public.packet=packet.clone();
    public.signed_grant=grant(&packet);

    // First TLS hop: Alice -> PERSONAL P. Original bytes enter P SQLite.
    let (a_to_p,p_from_a)=connect_pair(
        &personal.server,&personal.trusted,W6_LAB_ALPN,
    ).await;
    assert!(matches!(
        receive_with_bytes(&personal,&a_to_p,&p_from_a,&personal.wire()).await,
        Ok(IngressOutcome::MailboxStored(PutStatus::Stored))
    ));
    drop(a_to_p);
    drop(p_from_a);
    let from_p=personal.mailbox.lock().unwrap()
        .get_page(id(4),101,None,1).unwrap();
    assert_eq!(from_p.len(),1);
    assert_eq!(from_p[0].bytes,packet);
    let forwarded=from_p[0].bytes.clone();

    // Source sender does not participate any more. Public Y explicitly
    // enrolls P's REAL QUIC EndpointId via an operator-signed policy update.
    let p_as_peer=EndpointRouteBinding {
        endpoint_id:personal.server.id(),w3_device_id:id(17),w3_epoch:9,
        ..public.trusted_binding
    };
    let signed=sign_operator_change(&public.operator,&OperatorChange{
        operation:PolicyOperation::Allow,revision:2,binding:p_as_peer,
    }).unwrap();
    public.enrollment.lock().unwrap()
        .apply_signed_anchored(&signed,&public.anchor).unwrap();
    public.device_registry.enroll(
        id(17),9,SigningKey::from_bytes(&[17;32]).verifying_key(),
    ).unwrap();
    let (p_to_y,y_from_p)=connect_pair(
        &public.server,&personal.server,W6_LAB_ALPN,
    ).await;
    assert_eq!(y_from_p.remote_id(),personal.server.id());
    let wire=[stream_frame(&public.signed_grant).unwrap(),
              stream_frame(&forwarded).unwrap()].concat();
    let ((),response)=tokio::join!(
        transmit(&p_to_y,&wire),
        receive_authenticated_iroh_mailbox(
            &y_from_p,public.context(Duration::from_secs(5)),
        ),
    );
    assert!(matches!(response,
        Ok(IngressOutcome::MailboxStored(PutStatus::Stored))));
    public.assert_message_count(1);
    let after=public.mailbox.lock().unwrap().get_page(id(4),101,None,1).unwrap();
    assert_eq!(after.len(),1);
    assert_eq!(after[0].bytes,forwarded);

    // A new SQLite reader sees the exact bytes after the network writer has
    // committed; the two custodians have distinct DB files and endpoints.
    let reopened=Mailbox::open(
        &public._dir.path().join("mail.sqlite"),MailboxLimits::default(),
    ).unwrap();
    let durable=reopened.get_page(id(4),101,None,1).unwrap();
    assert_eq!(durable[0].bytes,packet);

    // A custodial proof has its own Ed25519 domain and MUST NOT be W4.
    let keeper=SigningKey::from_bytes(&[13;32]);
    let mut proof_trust=TrustRegistry::new();
    proof_trust.enroll(id(13),7,keeper.verifying_key()).unwrap();
    let proof=custody_receipt_w6::sign_after_store(
        &keeper,id(13),id(41),id(5),&durable[0].bytes,7,300_000,
    ).unwrap();
    let valid=custody_receipt_w6::verify(&proof,ExpectedCustody {
        custodian_id:id(13),slot_id:id(41),message_id:id(5),
        ciphertext:&packet,now_ms:100_000,
    },&proof_trust).unwrap();
    assert_eq!(valid.ciphertext_digest(),*blake3::hash(&packet).as_bytes());
    assert!(receipt_w4::verify(&proof,&proof_trust).is_err());

    // Bob, and ONLY Bob, possesses HPKE private key and enrolled sender key.
    let mut recipient_trust=TrustRegistry::new();
    recipient_trust.enroll(id(9),4,sender.verifying_key()).unwrap();
    recipient_trust.enroll(id(8),6,bob.verifying_key()).unwrap();
    let decrypted=private_route_w3::open_authenticated(
        &durable[0].bytes,TrustedRecipient {
            secret:&bob_secret,recipient_id:id(8),now:100_000,
            registry:&recipient_trust,
        },id(4),
    ).unwrap();
    assert_eq!(decrypted.payload(),b"end-to-end secret via public custodian");
    assert_eq!(decrypted.original_packet(),packet.as_slice());

    // On Bob's *separate* SQLite, durable inbox acceptance + true end-user
    // W4 is atomic. W4 RETURN PATH REMAINS UNENCRYPTED in this laboratory.
    let bob_file=public._dir.path().join("bob-inbox.sqlite");
    let mut journal=Journal::open(&bob_file).unwrap();
    let (status,w4)=journal.accept_private_authenticated_and_queue_receipt(
        &packet,TrustedRecipient {
            secret:&bob_secret,recipient_id:id(8),
            now:100_000,registry:&recipient_trust,
        },id(4),&bob,6,
    ).unwrap();
    assert_eq!(status,Insert::New);
    drop(journal);
    let final_receipt=receipt_w4::verify(&w4,&recipient_trust).unwrap();
    assert_eq!(final_receipt.packet_digest(),*blake3::hash(&packet).as_bytes());
    let mut source=Journal::open(&personal._dir.path().join("alice-outbox.sqlite")).unwrap();
    source.enqueue(id(8),id(5),500_000,&packet).unwrap();
    assert_eq!(source.apply_recipient_receipt(&final_receipt).unwrap(),Delivery::Recipient);
    assert_eq!(source.retry_bytes(id(8),id(5),101).unwrap(),None);

    // A changed public W3 route token is authenticated; a stored-only
    // custodian can't impersonate Bob to issue an accepted final receipt.
    let mut bad=packet.clone();
    bad[17]^=1;
    assert!(private_route_w3::open_authenticated(&bad,TrustedRecipient{
        secret:&bob_secret,recipient_id:id(8),now:100_000,
        registry:&recipient_trust,
    },id(4)).is_err());
}
