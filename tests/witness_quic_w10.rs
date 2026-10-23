//! W10: authenticated Roha/noq QUIC to an independent W9 witness PROCESS,
//! followed by *peer-to-peer QUIC gossip* of signed checkpoints.
//! All sockets are loopback on ONE GitHub runner, not two physical hosts.
//! A malicious witness can sign incompatible histories under its real key.
#![cfg(feature="iroh-transport")]

use akula_wire_lab::crypto_identity_w3::SignedHeader;
use akula_wire_lab::crypto_w3::new_recipient;
use akula_wire_lab::custody_transfer_w8::{self,OfferClaims};
use akula_wire_lab::custody_witness_w9::{
    self,ChainRelation,Verdict,WitnessStore,CHECKPOINT_LEN,
};
use akula_wire_lab::private_route_w3;
use akula_wire_lab::witness_pin_w10::{PinError,PinOutcome,WitnessPinStore};
use akula_wire_lab::trust_w3::TrustRegistry;
use ed25519_dalek::SigningKey;
use iroh::{Endpoint,EndpointAddr,EndpointId,endpoint::presets};
use std::io::{BufRead,BufReader};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Child,Command,Stdio};
use std::time::Duration;
use tempfile::{tempdir,TempDir};

const WITNESS_ALPN:&[u8]=b"akula-wow/w10-private-witness-loopback/1";
const GOSSIP_ALPN:&[u8]=b"akula-wow/w10-private-gossip-loopback/1";
fn id(v:u8)->[u8;16]{[v;16]}
fn key(v:u8)->SigningKey{SigningKey::from_bytes(&[v;32])}
fn trust()->TrustRegistry{
    let mut t=TrustRegistry::new();
    t.enroll(id(21),3,key(21).verifying_key()).unwrap();
    t.enroll(id(17),9,key(17).verifying_key()).unwrap();
    t.enroll(id(18),10,key(18).verifying_key()).unwrap();
    t
}
fn offer_for(target:u8,serial:u8,slot:u8)->Vec<u8>{
    // Real Blue W3 v3 HPKE/COSE Ed25519; witness only sees signed W8
    // ciphertext digest and pseudonymous peers, NEVER the plaintext/W3.
    let (_,public)=new_recipient();
    let w3=private_route_w3::seal_private(
        &key(9),&public,id(4),
        SignedHeader {
            message_id:id(5),recipient_id:id(8),expiry:500_000,
            sender_id:id(9),epoch:4,
        },b"hello opaque W10 witness",
    ).unwrap();
    custody_transfer_w8::sign_offer(OfferClaims {
        source_id:id(21),source_epoch:3,
        target_id:id(target),target_epoch:if target==13{7}else{8},
        slot_alias:id(slot),offer_id:id(serial),
        ciphertext_digest:*blake3::hash(&w3).as_bytes(),
        expires_at_ms:500_000,
    },&key(21)).unwrap()
}
async fn peer() ->Endpoint{
    Endpoint::builder(presets::Minimal)
        .clear_ip_transports()
        .bind_addr("127.0.0.1:0").unwrap()
        .alpns(vec![GOSSIP_ALPN.to_vec()])
        .bind().await.unwrap()
}
struct WitnessProcess {
    child:Child,
    addr:EndpointAddr,
    dir:TempDir,
}
impl WitnessProcess {
    fn start(mode:&str,left:EndpointId,right:EndpointId)->Self{
        let dir=tempdir().unwrap();
        let mut child=Command::new(env!("CARGO_BIN_EXE_w10_private_witness"))
            .arg(mode)
            .arg(dir.path())
            .arg(left.to_string())
            .arg(right.to_string())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn().expect("spawn independent W10 private witness process");
        let stdout=child.stdout.take().unwrap();
        let mut line=String::new();
        BufReader::new(stdout).read_line(&mut line).unwrap();
        let fields=line.split_whitespace().collect::<Vec<_>>();
        assert_eq!(fields.len(),3,"invalid W10 READY line: {line}");
        assert_eq!(fields[0],"READY");
        let endpoint:EndpointId=fields[1].parse().unwrap();
        let socket:SocketAddr=fields[2].parse().unwrap();
        assert!(socket.ip().is_loopback());
        Self {
            child,addr:EndpointAddr::new(endpoint).with_ip_addr(socket),dir,
        }
    }
    fn path(&self,name:&str)->PathBuf{self.dir.path().join(name)}
}
impl Drop for WitnessProcess{
    fn drop(&mut self){
        let _=self.child.kill();
        let _=self.child.wait();
    }
}
/// Each authenticated QUIC request is bounded and made to a pre-pinned server.
async fn rpc(client:&Endpoint,server:&WitnessProcess,request:&[u8])->Vec<u8>{
    let conn=tokio::time::timeout(
        Duration::from_secs(10),
        client.connect(server.addr.clone(),WITNESS_ALPN),
    ).await.expect("witness connect timed out").expect("witness handshake failed");
    assert_eq!(conn.remote_id(),server.addr.id);
    let (mut tx,mut rx)=conn.open_bi().await.unwrap();
    tx.write_all(request).await.unwrap();
    tx.finish().unwrap();
    let reply=tokio::time::timeout(
        Duration::from_secs(5),
        rx.read_to_end(1+CHECKPOINT_LEN),
    ).await.expect("witness reply timed out").expect("read W10 reply");
    conn.close(0u32.into(),b"verified witness reply");
    reply
}
async fn submit(client:&Endpoint,server:&WitnessProcess,offer:&[u8])->Vec<u8>{
    let mut request=vec![1];
    request.extend_from_slice(offer);
    rpc(client,server,&request).await
}
fn unpack(reply:&[u8],expected:u8,trust:&TrustRegistry)->Vec<u8>{
    assert_eq!(reply.len(),1+CHECKPOINT_LEN);
    assert_eq!(reply[0],expected);
    custody_witness_w9::verify_checkpoint(&reply[1..],id(17),trust).unwrap();
    reply[1..].to_vec()
}
/// QUIC peer-to-peer checkpoint gossip. Two endpoints independently pin the
/// W9 witness Ed25519 key and TLS identities: neither trusts peer-supplied
/// witness keys nor unauthenticated endpoint names.
async fn gossip(from:&Endpoint,to:&Endpoint,checkpoint:&[u8])->Vec<u8>{
    let (out,inc)=tokio::join!(
        async {
            tokio::time::timeout(
                Duration::from_secs(10),
                from.connect(to.addr(),GOSSIP_ALPN),
            ).await.unwrap().unwrap()
        },
        async {
            tokio::time::timeout(
                Duration::from_secs(10),
                async {to.accept().await.unwrap().await},
            ).await.unwrap().unwrap()
        },
    );
    assert_eq!(out.remote_id(),to.id());
    assert_eq!(inc.remote_id(),from.id());
    let ((),received)=tokio::join!(
        async {
            let (mut tx,mut rx)=out.open_bi().await.unwrap();
            tx.write_all(checkpoint).await.unwrap();
            tx.finish().unwrap();
            let ack=tokio::time::timeout(
                Duration::from_secs(5),rx.read_to_end(4),
            ).await.unwrap().unwrap();
            assert_eq!(ack,vec![1]);
            out.close(0u32.into(),b"gossip complete");
        },
        async {
            let (mut tx,mut rx)=inc.accept_bi().await.unwrap();
            let received=tokio::time::timeout(
                Duration::from_secs(5),rx.read_to_end(CHECKPOINT_LEN),
            ).await.unwrap().unwrap();
            tx.write_all(&[1]).await.unwrap();
            tx.finish().unwrap();
            let _=tokio::time::timeout(Duration::from_secs(2),inc.closed()).await;
            received
        },
    );
    received
}

#[tokio::test(flavor="multi_thread",worker_threads=2)]
async fn honest_witness_over_real_quic_detects_two_signed_issuer_offers() {
    let left=peer().await;let right=peer().await;let stranger=peer().await;
    let witness=WitnessProcess::start("honest",left.id(),right.id());
    let trusted=trust();
    let offer_x=offer_for(13,31,42);
    let offer_y=offer_for(14,32,42);
    // A valid signed offer does not grant an unknown network endpoint access.
    let denied=submit(&stranger,&witness,&offer_x).await;
    assert_eq!(denied,vec![255]);
    let denied=submit(&left,&witness,&offer_y).await;
    assert_eq!(denied,vec![255]);
    let cp_x=unpack(&submit(&left,&witness,&offer_x).await,0x11,&trusted);
    let mut left_pin=WitnessPinStore::open(
        &witness.path("client_left_pin.sqlite"),id(17),9,
    ).unwrap();
    assert_eq!(left_pin.pin(&cp_x,&trusted).unwrap(),PinOutcome::First);
    // A replay after durable SQLite commit returns the IDENTICAL checkpoint.
    assert_eq!(unpack(&submit(&left,&witness,&offer_x).await,0x11,&trusted),cp_x);

    // Malicious issuer produced two valid offers for the *same* slot alias.
    // Independent witness sees Y's fork, returns a conflict checkpoint rather
    // than a new approval. The two signed raw offers stay in PRIVATE SQLite.
    let cp_fork=unpack(&submit(&right,&witness,&offer_y).await,0x12,&trusted);
    let verify=custody_witness_w9::verify_checkpoint(&cp_fork,id(17),&trusted).unwrap();
    assert_eq!(verify.verdict,Verdict::ConflictObserved);
    assert_eq!(verify.sequence,2);
    assert_eq!(custody_witness_w9::compare_checkpoints(
        &cp_x,&cp_fork,id(17),&trusted,
    ).unwrap(),ChainRelation::Adjacent);

    let mut right_pin=WitnessPinStore::open(
        &witness.path("client_right_pin.sqlite"),id(17),9,
    ).unwrap();
    // Fresh pin cannot start with only the second checkpoint.
    assert!(matches!(right_pin.pin(&cp_fork,&trusted),
        Err(PinError::MissingHistory)));
    // The two endpoint IDs exchange first checkpoint on a SEPARATE real
    // authenticated peer-to-peer QUIC TLS connection, not through witness.
    let gossiped=gossip(&left,&right,&cp_x).await;
    assert_eq!(gossiped,cp_x);
    assert_eq!(right_pin.pin(&gossiped,&trusted).unwrap(),PinOutcome::First);
    assert_eq!(right_pin.pin(&cp_fork,&trusted).unwrap(),PinOutcome::Advanced);
    assert_eq!(left_pin.pin(&cp_fork,&trusted).unwrap(),PinOutcome::Advanced);
    assert_eq!(unpack(&rpc(&left,&witness,&[2]).await,0x13,&trusted),cp_fork);

    // Independent read of witness's PRIVATE disk: signed issuer fork exists.
    let local=WitnessStore::open(&witness.path("honest.sqlite"),id(17),9).unwrap();
    let evidence=local.conflicting_evidence(id(21),id(42)).unwrap().unwrap();
    custody_witness_w9::verify_fork(&evidence,id(17),&trusted).unwrap();
    assert_eq!(evidence.first_offer,offer_x);
    assert_eq!(evidence.conflicting_offer,offer_y);
    // This does not issue, nor impersonate, a final recipient W4.
}

#[tokio::test(flavor="multi_thread",worker_threads=2)]
async fn malicious_witness_split_view_is_caught_by_independent_quic_gossip() {
    let left=peer().await;let right=peer().await;
    let witness=WitnessProcess::start("split",left.id(),right.id());
    let trusted=trust();
    let offer_x=offer_for(13,31,42);
    let offer_y=offer_for(14,32,42);
    // Same legitimate witness Ed25519 key, but TWO independent W9 SQLite
    // files are used to tell contradictory FIRST-SEEN stories to X and Y.
    let cp_x=unpack(&submit(&left,&witness,&offer_x).await,0x11,&trusted);
    let cp_y=unpack(&submit(&right,&witness,&offer_y).await,0x11,&trusted);
    let a=custody_witness_w9::verify_checkpoint(&cp_x,id(17),&trusted).unwrap();
    let b=custody_witness_w9::verify_checkpoint(&cp_y,id(17),&trusted).unwrap();
    assert_eq!(a.sequence,1);
    assert_eq!(b.sequence,1);
    assert_ne!(a.head,b.head);
    let local=tempdir().unwrap();
    let left_path=local.path().join("left.sqlite");
    let right_path=local.path().join("right.sqlite");
    let mut left_pin=WitnessPinStore::open(&left_path,id(17),9).unwrap();
    let mut right_pin=WitnessPinStore::open(&right_path,id(17),9).unwrap();
    assert_eq!(left_pin.pin(&cp_x,&trusted).unwrap(),PinOutcome::First);
    assert_eq!(right_pin.pin(&cp_y,&trusted).unwrap(),PinOutcome::First);
    assert!(left_pin.fork().unwrap().is_none());
    assert!(right_pin.fork().unwrap().is_none());

    let exchanged=gossip(&left,&right,&cp_x).await;
    assert!(matches!(right_pin.pin(&exchanged,&trusted),
        Err(PinError::Equivocation)));
    let reverse=gossip(&right,&left,&cp_y).await;
    assert!(matches!(left_pin.pin(&reverse,&trusted),
        Err(PinError::Equivocation)));
    assert!(left_pin.frozen().unwrap());
    assert!(right_pin.frozen().unwrap());
    drop(left_pin);drop(right_pin);
    let left_reopened=WitnessPinStore::open(&left_path,id(17),9).unwrap();
    let right_reopened=WitnessPinStore::open(&right_path,id(17),9).unwrap();
    assert_eq!(left_reopened.fork().unwrap(),Some((cp_x.clone(),cp_y.clone())));
    assert_eq!(right_reopened.fork().unwrap(),Some((cp_y.clone(),cp_x.clone())));
    assert_eq!(left_reopened.current().unwrap(),Some(cp_x));
    assert_eq!(right_reopened.current().unwrap(),Some(cp_y));
    assert!(left_reopened.frozen().unwrap());
    assert!(right_reopened.frozen().unwrap());
}
