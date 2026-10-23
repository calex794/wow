//! W10 TEST-ONLY private witness Roha/noq process. Binds exclusively to
//! 127.0.0.1, uses deterministic laboratory signing keys, and accepts only
//! two pre-provisioned QUIC EndpointIds. Never deploy this as a public service.
//!
//! In `honest` mode both TLS peers share ONE witness SQLite.
//! In `split` mode the witness maliciously signs two different timelines
//! under the SAME W9 signing key from two different SQLite files.
//! No raw offers or peer IDs are returned: clients only receive commitments.
//!
//! Protocol (one QUIC bidi stream):
//! [1 || W8 OFFER_LEN bytes] -> [0x11 || W9 checkpoint] on first,
//!                            [0x12 || W9 conflict checkpoint] on fork.
//! [2]                    -> [0x13 || latest checkpoint], or [0].
//! Bad request/unauthorized TLS EndpointId -> [255].
//! This ALPN is separate from production W6 and has no public network path.
use akula_wire_lab::custody_transfer_w8::{self,OFFER_LEN};
use akula_wire_lab::custody_witness_w9::{WitnessObservation,WitnessStore};
use akula_wire_lab::trust_w3::TrustRegistry;
use ed25519_dalek::SigningKey;
use iroh::{Endpoint,EndpointId,endpoint::{presets,Connection}};
use std::io::{self,Write};
use std::net::SocketAddr;
use std::path::{Path,PathBuf};
use std::str::FromStr;
use std::time::Duration;

const ALPN:&[u8]=b"akula-wow/w10-private-witness-loopback/1";
const MAX_REQUEST:usize=1+OFFER_LEN;
fn id(v:u8)->[u8;16]{[v;16]}
fn key(v:u8)->SigningKey{SigningKey::from_bytes(&[v;32])}
fn lab_error(error:impl std::fmt::Debug)->io::Error {
    io::Error::other(format!("w10 private witness lab: {error:?}"))
}
#[derive(Clone,Copy)]
enum Mode {Honest,Split}
impl FromStr for Mode {
    type Err=&'static str;
    fn from_str(s:&str)->Result<Self,Self::Err>{
        match s {"honest"=>Ok(Self::Honest),"split"=>Ok(Self::Split),
                 _=>Err("expected honest|split")}
    }
}
struct Config {
    mode:Mode,
    directory:PathBuf,
    left:EndpointId,
    right:EndpointId,
}
impl Config {
    fn path(&self,peer:EndpointId)->Option<PathBuf>{
        if peer!=self.left && peer!=self.right{return None;}
        let filename=match self.mode {
            Mode::Honest=>"honest.sqlite",
            Mode::Split if peer==self.left=>"left.sqlite",
            Mode::Split=>"right.sqlite",
        };
        Some(self.directory.join(filename))
    }
}
fn trust()->TrustRegistry {
    let mut registry=TrustRegistry::new();
    registry.enroll(id(21),3,key(21).verifying_key()).unwrap();
    registry.enroll(id(17),9,key(17).verifying_key()).unwrap();
    registry
}
fn respond(
    config:&Config,remote:EndpointId,packet:&[u8],
)->Result<Vec<u8>,io::Error>{
    let Some(path)=config.path(remote) else {return Ok(vec![255]);};
    if packet.is_empty()||packet.len()>MAX_REQUEST{return Ok(vec![255]);}
    let mut witness=WitnessStore::open(Path::new(&path),id(17),9)
        .map_err(lab_error)?;
    if packet==[2] {
        return Ok(if let Some(checkpoint)=witness.checkpoint().map_err(lab_error)?{
            let mut reply=vec![0x13];
            reply.extend_from_slice(&checkpoint);
            reply
        }else{vec![0]});
    }
    if packet.len()!=1+OFFER_LEN||packet[0]!=1{return Ok(vec![255]);}
    let raw_offer=&packet[1..];
    let trusted=trust();
    let Ok(claims)=custody_transfer_w8::verify_offer(raw_offer,&trusted)
        else{return Ok(vec![255]);};
    // The TLS sender must be the independently approved custodian named in
    // the *signed* offer, not a peer proposing some else's slot.
    let expected_target=if remote==config.left{id(13)}else{id(14)};
    if claims.target_id!=expected_target{return Ok(vec![255]);}
    let witnessed=witness.observe(raw_offer,&key(17),&trusted)
        .map_err(lab_error)?;
    let (code,checkpoint)=match witnessed {
        WitnessObservation::FirstSeen(raw)=>(0x11,raw),
        WitnessObservation::Conflict(evidence)=>(0x12,evidence.conflict_checkpoint),
    };
    let mut reply=vec![code];
    reply.extend_from_slice(&checkpoint);
    Ok(reply)
}
async fn handle(
    connection:Connection,config:&Config,
)->Result<(),Box<dyn std::error::Error>>{
    let remote=connection.remote_id();
    let (mut tx,mut rx)=tokio::time::timeout(
        Duration::from_secs(5),connection.accept_bi()
    ).await??;
    let request=tokio::time::timeout(
        Duration::from_secs(5),rx.read_to_end(MAX_REQUEST),
    ).await??;
    let reply=respond(config,remote,&request)?;
    tx.write_all(&reply).await?;
    tx.finish()?;
    // Keep the server-side QUIC connection alive until the client has
    // consumed the entire reply, avoiding the premature-close W7 regression.
    let _=tokio::time::timeout(Duration::from_secs(2),connection.closed()).await;
    Ok(())
}
#[tokio::main(flavor="multi_thread",worker_threads=2)]
async fn main()->Result<(),Box<dyn std::error::Error>>{
    let args=std::env::args().collect::<Vec<_>>();
    if args.len()!=5 {
        return Err("usage: w10_private_witness <honest|split> <dbdir> <left-EndpointId> <right-EndpointId>".into());
    }
    let config=Config {
        mode:args[1].parse()?,
        directory:PathBuf::from(&args[2]),
        left:args[3].parse()?,
        right:args[4].parse()?,
    };
    if config.left==config.right{return Err("two independent peer EndpointIds required".into());}
    let endpoint=Endpoint::builder(presets::Minimal)
        .clear_ip_transports().bind_addr("127.0.0.1:0")?
        .alpns(vec![ALPN.to_vec()])
        .bind().await?;
    let socket:SocketAddr=endpoint.bound_sockets().into_iter()
        .find(|addr|addr.is_ipv4()&&addr.ip().is_loopback())
        .ok_or("missing loopback QUIC address")?;
    println!("READY {} {}",endpoint.id(),socket);
    io::stdout().flush()?;
    while let Some(incoming)=endpoint.accept().await {
        match incoming.await {
            Ok(connection)=>{
                if let Err(error)=handle(connection,&config).await {
                    eprintln!("w10 witness lab connection error: {error}");
                }
            }
            Err(error)=>eprintln!("w10 witness TLS accept error: {error}"),
        }
    }
    Ok(())
}
