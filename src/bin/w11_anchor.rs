//! W11 test-only independent anchor process over authentic Roha/noq QUIC.
//!
//! Binds exclusively to 127.0.0.1. Deterministic LAB keys and a PRIVATE
//! laboratory-only ALPN are NEVER suitable for public deployment. No
//! production API, no physical independence, no authenticated freshness.
//!
//! STORE [1, W9 signed checkpoint] => [0x11, W11 signed receipt] after
//! independent SQLite COMMIT (or no ACK in drop-ack test mode).
//! READ  [2] => [0x21, W9 checkpoint, W11 receipt] (0 if empty).
//! Unauthorized TLS peer => 255. Frozen witness/anchor => 254.
//!
//! "split" simulates a malicious anchor operator: two SQLite databases and
//! ONE genuine Ed25519 anchor key, scoped by independently pinned peer TLS IDs.
use akula_wire_lab::trust_w3::TrustRegistry;
use akula_wire_lab::custody_witness_w9::CHECKPOINT_LEN;
use akula_wire_lab::witness_anchor_w11::{AnchorIdentity,AnchorStore};
use ed25519_dalek::SigningKey;
use iroh::{Endpoint,EndpointId,endpoint::{presets,Connection}};
use std::io::{self,Write};
use std::net::SocketAddr;
use std::path::{Path,PathBuf};
use std::str::FromStr;
use std::time::Duration;

const ALPN:&[u8]=b"akula-wow/w11-independent-anchor-local-only/1";
const MAX_REQUEST:usize=1+CHECKPOINT_LEN;
fn id(n:u8)->[u8;16]{[n;16]}
fn key(n:u8)->SigningKey{SigningKey::from_bytes(&[n;32])}
fn scope()->AnchorIdentity {
    AnchorIdentity {
        anchor_id:id(19),anchor_epoch:11,
        witness_id:id(17),witness_epoch:9,
    }
}
fn trust()->TrustRegistry {
    let mut r=TrustRegistry::new();
    r.enroll(id(17),9,key(17).verifying_key()).unwrap();
    r.enroll(id(19),11,key(19).verifying_key()).unwrap();
    r
}
fn lab_error(error:impl std::fmt::Debug)->io::Error {
    io::Error::other(format!("W11 test anchor failure: {error:?}"))
}
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
enum Mode {Honest,Split,DropAck}
impl FromStr for Mode {
    type Err=&'static str;
    fn from_str(s:&str)->Result<Self,Self::Err>{
        match s{
            "honest"=>Ok(Self::Honest),
            "split"=>Ok(Self::Split),
            "drop-ack"=>Ok(Self::DropAck),
            _=>Err("expected honest, split, or drop-ack"),
        }
    }
}
struct Config {
    mode:Mode,
    directory:PathBuf,
    left:EndpointId,
    right:EndpointId,
}
impl Config {
    fn path(&self,remote:EndpointId)->Option<PathBuf>{
        if remote!=self.left && remote!=self.right {return None;}
        let basename=match self.mode{
            Mode::Honest | Mode::DropAck => "anchor.sqlite",
            Mode::Split if remote==self.left=>"anchor_left.sqlite",
            Mode::Split=>"anchor_right.sqlite",
        };
        Some(self.directory.join(basename))
    }
}
fn respond(config:&Config,remote:EndpointId,packet:&[u8])->Result<Vec<u8>,io::Error>{
    let Some(path)=config.path(remote) else {return Ok(vec![255]);};
    if packet.is_empty()||packet.len()>MAX_REQUEST{return Ok(vec![255]);}
    let mut store=AnchorStore::open(Path::new(&path),scope()).map_err(lab_error)?;
    if packet==[2] {
        return Ok(match store.latest() {
            Ok(Some((cp,receipt)))=>{
                let mut reply=vec![0x21];
                reply.extend_from_slice(&cp);
                reply.extend_from_slice(&receipt);
                reply
            }
            Ok(None)=>vec![0],
            Err(_)=>vec![254],
        });
    }
    if packet.len()!=1+CHECKPOINT_LEN||packet[0]!=1{return Ok(vec![255]);}
    // This lab deliberately gives each approved peer the same anchor service.
    // A real service needs capability rights and per-client quotas.
    match store.observe(&packet[1..],&key(19),&trust()) {
        Ok((_,receipt))=>{
            if config.mode==Mode::DropAck {
                // Persisted and signed but sender sees no response. GET must
                // recover exactly the original committed checkpoint/receipt.
                Ok(Vec::new())
            }else{
                let mut reply=vec![0x11];
                reply.extend_from_slice(&receipt);
                Ok(reply)
            }
        }
        Err(_) if store.frozen().unwrap_or(false)=>Ok(vec![254]),
        Err(_)=>Ok(vec![255]),
    }
}
async fn handle(connection:Connection,config:&Config)->Result<(),Box<dyn std::error::Error>>{
    let remote=connection.remote_id();
    let (mut tx,mut rx)=tokio::time::timeout(
        Duration::from_secs(5),connection.accept_bi(),
    ).await??;
    let request=tokio::time::timeout(
        Duration::from_secs(5),rx.read_to_end(MAX_REQUEST),
    ).await??;
    let response=respond(config,remote,&request)?;
    if !response.is_empty(){tx.write_all(&response).await?;}
    tx.finish()?;
    let _=tokio::time::timeout(Duration::from_secs(2),connection.closed()).await;
    Ok(())
}
#[tokio::main(flavor="multi_thread",worker_threads=2)]
async fn main()->Result<(),Box<dyn std::error::Error>>{
    let args=std::env::args().collect::<Vec<_>>();
    if args.len()!=5 {
        return Err("usage: w11_anchor <honest|split|drop-ack> <dir> <left-id> <right-id>".into());
    }
    let config=Config {
        mode:args[1].parse()?,
        directory:PathBuf::from(&args[2]),
        left:args[3].parse()?,
        right:args[4].parse()?,
    };
    if config.left==config.right{return Err("distinct approved TLS peer IDs required".into());}
    let endpoint=Endpoint::builder(presets::Minimal)
        .clear_ip_transports().bind_addr("127.0.0.1:0")?
        .alpns(vec![ALPN.to_vec()])
        .bind().await?;
    let socket:SocketAddr=endpoint.bound_sockets().into_iter()
        .find(|s|s.is_ipv4()&&s.ip().is_loopback())
        .ok_or("missing loopback socket")?;
    println!("READY {} {}",endpoint.id(),socket);
    io::stdout().flush()?;
    while let Some(incoming)=endpoint.accept().await {
        match incoming.await {
            Ok(connection)=>{
                if let Err(error)=handle(connection,&config).await{
                    eprintln!("w11 anchor test connection error: {error}");
                }
            }
            Err(error)=>eprintln!("w11 anchor test QUIC auth error: {error}"),
        }
    }
    Ok(())
}
