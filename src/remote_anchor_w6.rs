//! W6 externally hosted checkpoint authority over authenticated project-fork
//! Roha/noq QUIC/TLS. The server stores a durable linearizable CAS watermark
//! in its OWN SQLite WAL database; caller must deploy on an independently
//! administered/rollback-isolated host. Tests run on loopback but that is NOT
//! a production anti-rollback trust boundary.
//!
//! The relay is a READ-ONLY TLS identity. A separately pinned admin TLS
//! identity may publish a strictly monotonic CAS. No network bootstrap:
//! provisioning is an explicit local service-owner operation.
//!
//! Protocol v1: exactly one bounded bidirectional QUIC stream per connection,
//! 1-byte GET or 81-byte CAS request. Responses are 41-byte checkpoint
//! (status 0) or 1-byte refusal. No 0-RTT or custom signature handshake.
//! QUIC identity always comes from connection.remote_id(), never a frame.
//!
//! This is a bounded LAB service and synchronous client adapter, not a
//! production accept scheduler, physical HSM, quorum audit log or disk quota.
use crate::peer_enrollment_w6::{AnchorError, PolicyCheckpoint, TrustedPolicyAnchor};
use iroh::{Endpoint, EndpointAddr, EndpointId, SecretKey, endpoint::{Connection, presets}};
use rusqlite::{params, Connection as Sqlite, OpenFlags, TransactionBehavior};
use std::{
    path::Path,
    sync::{Mutex, mpsc::{self, Receiver, SyncSender}},
    thread,
    time::Duration,
};

pub const ANCHOR_ALPN: &[u8] = b"akula-wow/w6-external-anchor-lab/1";
const OP_GET: u8 = 1;
const OP_CAS: u8 = 2;
const STATUS_OK: u8 = 0;
const STATUS_DENIED: u8 = 3;
const STATUS_CONFLICT: u8 = 4;
const STATUS_FAULT: u8 = 5;
const STATUS_MALFORMED: u8 = 6;
const CLIENT_RESPONSE_RECEIVED: u8 = 0x71;
const CHECKPOINT_BYTES: usize = 40;
const GET_BYTES: usize = 1;
const CAS_BYTES: usize = 1 + 2 * CHECKPOINT_BYTES;
const RESPONSE_BYTES: usize = 1 + CHECKPOINT_BYTES;
const IO_BUDGET: Duration = Duration::from_secs(2);

#[derive(Debug)]
pub enum RemoteAnchorError {
    Db(rusqlite::Error),
    AlreadyProvisioned,
    NotProvisioned,
    ConfigurationMismatch,
    UntrustedPeer,
    Conflict,
    CorruptStorage,
    Protocol,
    Transport(String),
    Deadline,
}
impl From<rusqlite::Error> for RemoteAnchorError {
    fn from(e: rusqlite::Error) -> Self { Self::Db(e) }
}

/// These TLS identities MUST originate from local protected operator config,
/// not user-supplied network frames or a database field treated as authority.
#[derive(Clone, Copy, Debug)]
pub struct AnchorServicePolicy {
    pub reader: EndpointId,
    pub administrator: EndpointId,
}
fn to_int(revision:u64) -> Result<i64,RemoteAnchorError> {
    if revision>i64::MAX as u64 {return Err(RemoteAnchorError::Protocol);}
    Ok(revision as i64)
}
fn checkpoint_bytes(p:PolicyCheckpoint)->[u8;CHECKPOINT_BYTES] {
    let mut bytes=[0;CHECKPOINT_BYTES];
    bytes[..8].copy_from_slice(&p.revision.to_be_bytes());
    bytes[8..].copy_from_slice(&p.digest);
    bytes
}
fn decode_checkpoint(bytes:&[u8])->Result<PolicyCheckpoint,RemoteAnchorError> {
    if bytes.len()!=CHECKPOINT_BYTES {return Err(RemoteAnchorError::Protocol);}
    let rev=u64::from_be_bytes(bytes[..8].try_into().map_err(|_|RemoteAnchorError::Protocol)?);
    to_int(rev)?;
    let mut digest=[0u8;32];
    digest.copy_from_slice(&bytes[8..]);
    Ok(PolicyCheckpoint {revision:rev,digest})
}

/// Remote SQLite anchor. An operator must bootstrap it independently.
/// Reopening an empty or missing DB must NOT silently accept a digest
/// obtained from potentially rolled-back W6 policy.sqlite.
struct StoredAnchorRow {
    reader: Vec<u8>,
    administrator: Vec<u8>,
    checkpoint: PolicyCheckpoint,
}

pub struct RemoteAnchorLedger {
    sql: Sqlite,
    policy: AnchorServicePolicy,
}
impl RemoteAnchorLedger {
    pub fn provision(
        path:&Path, policy:AnchorServicePolicy, initial:PolicyCheckpoint,
    )->Result<Self,RemoteAnchorError>{
        let _=to_int(initial.revision)?;
        let mut sql=Sqlite::open(path)?;
        Self::schema(&mut sql)?;
        let tx=sql.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing:i64=tx.query_row(
            "SELECT COUNT(*) FROM w6_external_anchor WHERE id=1",
            [],|row|row.get(0),
        )?;
        if existing!=0 {return Err(RemoteAnchorError::AlreadyProvisioned);}
        tx.execute(
            "INSERT INTO w6_external_anchor
             (id,reader,administrator,revision,digest) VALUES(1,?1,?2,?3,?4)",
            params![
                policy.reader.as_bytes().as_slice(),
                policy.administrator.as_bytes().as_slice(),
                to_int(initial.revision)?, initial.digest.as_slice(),
            ],
        )?;
        tx.commit()?;
        Ok(Self {sql,policy})
    }
    /// Open uses SQLITE_OPEN_READ_WRITE without CREATE. If the independent
    /// remote datastore is lost, the service MUST stop, not reinitialize.
    pub fn open(path:&Path,policy:AnchorServicePolicy)->Result<Self,RemoteAnchorError>{
        let sql=Sqlite::open_with_flags(path,OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        sql.busy_timeout(Duration::from_secs(2))?;
        sql.execute_batch("PRAGMA synchronous=FULL; PRAGMA journal_mode=WAL;")?;
        let found=Self::record(&sql)?;
        let trusted=found.ok_or(RemoteAnchorError::NotProvisioned)?;
        if trusted.reader.as_slice()!=policy.reader.as_bytes()
            || trusted.administrator.as_slice()!=policy.administrator.as_bytes()
        {
            return Err(RemoteAnchorError::ConfigurationMismatch);
        }
        Ok(Self {sql,policy})
    }
    fn schema(sql:&mut Sqlite)->Result<(),RemoteAnchorError>{
        sql.busy_timeout(Duration::from_secs(2))?;
        sql.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=FULL;
             CREATE TABLE IF NOT EXISTS w6_external_anchor (
               id INTEGER PRIMARY KEY CHECK(id=1),
               reader BLOB NOT NULL CHECK(length(reader)=32),
               administrator BLOB NOT NULL CHECK(length(administrator)=32),
               revision INTEGER NOT NULL CHECK(revision>=0),
               digest BLOB NOT NULL CHECK(length(digest)=32)
             );"
        )?;
        Ok(())
    }
    fn record(db:&Sqlite)->Result<Option<StoredAnchorRow>,RemoteAnchorError>{
        use rusqlite::OptionalExtension;
        let rec=db.query_row(
            "SELECT reader,administrator,revision,digest FROM w6_external_anchor WHERE id=1",
            [],|row|Ok((
                row.get::<_,Vec<u8>>(0)?,
                row.get::<_,Vec<u8>>(1)?,
                row.get::<_,i64>(2)?,
                row.get::<_,Vec<u8>>(3)?,
            )),
        ).optional()?;
        let Some((reader,administrator,rev,digest))=rec else {return Ok(None)};
        if reader.len()!=32 || administrator.len()!=32 || digest.len()!=32 || rev<0 {
            return Err(RemoteAnchorError::CorruptStorage);
        }
        let mut d=[0u8;32];d.copy_from_slice(&digest);
        Ok(Some(StoredAnchorRow {
            reader, administrator,
            checkpoint:PolicyCheckpoint {revision:rev as u64,digest:d},
        }))
    }
    /// Only the two pinned QUIC identities may query current state.
    pub fn current_for(
        &self,peer:EndpointId,
    )->Result<PolicyCheckpoint,RemoteAnchorError>{
        if peer!=self.policy.reader && peer!=self.policy.administrator {
            return Err(RemoteAnchorError::UntrustedPeer);
        }
        let record=Self::record(&self.sql)?
            .ok_or(RemoteAnchorError::NotProvisioned)?;
        Ok(record.checkpoint)
    }
    /// Strictly monotonic, FULL-synchronous SQLite BEGIN IMMEDIATE CAS;
    /// only operator TLS key may change the independent trust watermark.
    pub fn advance_for(
        &mut self,peer:EndpointId,expected:PolicyCheckpoint,
        next:PolicyCheckpoint,
    )->Result<PolicyCheckpoint,RemoteAnchorError>{
        if peer!=self.policy.administrator {
            return Err(RemoteAnchorError::UntrustedPeer);
        }
        to_int(next.revision)?;
        if next.revision<=expected.revision {return Err(RemoteAnchorError::Conflict);}
        let tx=self.sql.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let record=Self::record(&tx)?
            .ok_or(RemoteAnchorError::NotProvisioned)?;
        if record.checkpoint!=expected {return Err(RemoteAnchorError::Conflict);}
        tx.execute(
            "UPDATE w6_external_anchor SET revision=?1,digest=?2 WHERE id=1",
            params![to_int(next.revision)?,next.digest.as_slice()],
        )?;
        tx.commit()?;
        Ok(next)
    }
}

/// This response is explicitly distinct from a signed W4 recipient ACK:
/// it is ONLY internal policy audit state in an authenticated TLS channel.
fn encode_reply(out:Result<PolicyCheckpoint,RemoteAnchorError>)->Vec<u8>{
    match out {
        Ok(v)=>{
            let mut r=Vec::with_capacity(RESPONSE_BYTES);
            r.push(STATUS_OK);r.extend_from_slice(&checkpoint_bytes(v));r
        }
        Err(RemoteAnchorError::UntrustedPeer)=>vec![STATUS_DENIED],
        Err(RemoteAnchorError::Conflict)=>vec![STATUS_CONFLICT],
        Err(RemoteAnchorError::Protocol)=>vec![STATUS_MALFORMED],
        Err(_)=>vec![STATUS_FAULT],
    }
}

/// Process ONE completed Roha QUIC/TLS connection. The service owner must
/// bound accepted connections/handshakes and schedule worker resources
/// separately; this function is NOT a public unbounded accept loop.
pub async fn serve_one_anchor_connection(
    conn:&Connection,service:&Mutex<RemoteAnchorLedger>,
)->Result<(),RemoteAnchorError>{
    if conn.alpn()!=ANCHOR_ALPN {return Err(RemoteAnchorError::Protocol);}
    let remote=conn.remote_id();
    let (mut response_send,mut recv)=tokio::time::timeout(IO_BUDGET,conn.accept_bi())
        .await.map_err(|_|RemoteAnchorError::Deadline)?
        .map_err(|e|RemoteAnchorError::Transport(e.to_string()))?;
    let wire=tokio::time::timeout(IO_BUDGET,recv.read_to_end(CAS_BYTES))
        .await.map_err(|_|RemoteAnchorError::Deadline)?
        .map_err(|e|RemoteAnchorError::Transport(e.to_string()))?;
    let response={
        let mut service=service.lock().map_err(|_|RemoteAnchorError::CorruptStorage)?;
        if wire.len()==GET_BYTES && wire[0]==OP_GET {
            encode_reply(service.current_for(remote))
        } else if wire.len()==CAS_BYTES && wire[0]==OP_CAS {
            let first=decode_checkpoint(&wire[1..1+CHECKPOINT_BYTES]);
            let second=decode_checkpoint(&wire[1+CHECKPOINT_BYTES..]);
            match (first,second) {
                (Ok(old),Ok(new))=>
                    encode_reply(service.advance_for(remote,old,new)),
                _=>vec![STATUS_MALFORMED],
            }
        } else {
            vec![STATUS_MALFORMED]
        }
    };
    // One request and one reply share the SAME authenticated bidirectional
    // QUIC stream. No second stream negotiation or response misbinding.
    tokio::time::timeout(IO_BUDGET,async {
        response_send.write_all(&response).await
            .map_err(|e|RemoteAnchorError::Transport(e.to_string()))?;
        response_send.finish().map_err(|e|RemoteAnchorError::Transport(e.to_string()))
    }).await.map_err(|_|RemoteAnchorError::Deadline)??;

    // QUIC Connection drops in this lab immediately after handler return.
    // A response FIN is not evidence that the peer received its bytes.
    // Keep this authenticated connection alive until the client confirms
    // that it read the result. This is a transport-level service receipt,
    // NOT a medical recipient ACK.
    let ack=tokio::time::timeout(IO_BUDGET,async {
        let mut peer_ack=conn.accept_uni().await
            .map_err(|e|RemoteAnchorError::Transport(e.to_string()))?;
        peer_ack.read_to_end(1).await
            .map_err(|e|RemoteAnchorError::Transport(e.to_string()))
    }).await.map_err(|_|RemoteAnchorError::Deadline)??;
    if ack != [CLIENT_RESPONSE_RECEIVED] {
        return Err(RemoteAnchorError::Protocol);
    }
    Ok(())
}

/// Spawn a *separate OS thread and Tokio runtime*. This allows synchronous
/// TrustedPolicyAnchor calls while holding SQLite's transaction lock even
/// when the original caller is running inside a single-thread Tokio reactor.
/// The local QUIC key and pinned remote EndpointAddr are supplied via a
/// trusted provisioning channel, NEVER from W6 packets.
/// Each RPC establishes fresh QUIC/TLS, no 0-RTT, bounded to 2 seconds.
pub struct RemoteAnchorClient {
    tx:SyncSender<ClientRequest>,
}
struct ClientRequest {
    old:Option<PolicyCheckpoint>,
    next:Option<PolicyCheckpoint>,
    reply:mpsc::SyncSender<Result<PolicyCheckpoint,AnchorError>>,
}
impl RemoteAnchorClient {
    pub fn start(
        local:SecretKey,remote:EndpointAddr,
    )->Result<Self,AnchorError>{
        let (tx,requests)=mpsc::sync_channel(8);
        let (ready_sender,ready)=mpsc::sync_channel(1);
        thread::spawn(move || {
            let rt=tokio::runtime::Builder::new_current_thread()
                .enable_all().build();
            let Ok(rt)=rt else {
                let _=ready_sender.send(Err(AnchorError::Unavailable));
                return;
            };
            let endpoint=rt.block_on(async {
                Endpoint::builder(presets::Minimal)
                    .clear_ip_transports()
                    .bind_addr("127.0.0.1:0")
                    .map_err(|_|AnchorError::Unavailable)?
                    .secret_key(local)
                    .bind().await.map_err(|_|AnchorError::Unavailable)
            });
            match endpoint {
                Ok(endpoint)=>{
                    let _=ready_sender.send(Ok(()));
                    Self::worker(&rt,&endpoint,remote,requests);
                }
                Err(e)=>{let _=ready_sender.send(Err(e));}
            }
        });
        ready.recv_timeout(IO_BUDGET).map_err(|_|AnchorError::Unavailable)??;
        Ok(Self {tx})
    }
    fn worker(
        rt:&tokio::runtime::Runtime,local:&Endpoint,remote:EndpointAddr,
        requests:Receiver<ClientRequest>,
    ) {
        for req in requests {
            let output=rt.block_on(Self::invoke(local,remote.clone(),req.old,req.next));
            let _=req.reply.send(output);
        }
    }
    async fn invoke(
        local:&Endpoint,remote:EndpointAddr,
        old:Option<PolicyCheckpoint>,next:Option<PolicyCheckpoint>,
    )->Result<PolicyCheckpoint,AnchorError>{
        let mut request=Vec::with_capacity(CAS_BYTES);
        match (old,next) {
            (None,None)=>request.push(OP_GET),
            (Some(o),Some(n))=>{
                request.push(OP_CAS);
                request.extend_from_slice(&checkpoint_bytes(o));
                request.extend_from_slice(&checkpoint_bytes(n));
            }
            _=>return Err(AnchorError::InvalidAttestation),
        }
        let response=tokio::time::timeout(IO_BUDGET,async {
            let conn=local.connect(remote,ANCHOR_ALPN).await
                .map_err(|e| {
                    eprintln!("W6 LAB anchor TLS connect failed: {e:?}");
                    AnchorError::Unavailable
                })?;
            if conn.alpn()!=ANCHOR_ALPN {return Err(AnchorError::InvalidAttestation);}
            let (mut send,mut response)=conn.open_bi().await
                .map_err(|e| {
                    eprintln!("W6 LAB anchor stream open failed: {e:?}");
                    AnchorError::Unavailable
                })?;
            send.write_all(&request).await.map_err(|e|{
                eprintln!("W6 LAB anchor stream write failed: {e:?}");
                AnchorError::Unavailable
            })?;
            send.finish().map_err(|_|AnchorError::Unavailable)?;
            let result=response.read_to_end(RESPONSE_BYTES).await
                .map_err(|e|{
                    eprintln!("W6 LAB anchor reply read failed: {e:?}");
                    AnchorError::Unavailable
                })?;
            // Do not let the server close the QUIC Connection before
            // the authenticated client has read its authoritative response.
            let mut confirmation=conn.open_uni().await
                .map_err(|_|AnchorError::Unavailable)?;
            confirmation.write_all(&[CLIENT_RESPONSE_RECEIVED]).await
                .map_err(|_|AnchorError::Unavailable)?;
            confirmation.finish().map_err(|_|AnchorError::Unavailable)?;
            Ok(result)
        }).await.map_err(|e| {
            eprintln!("W6 LAB anchor RPC timeout: {e:?}");
            AnchorError::Unavailable
        })??;
        match response.as_slice() {
            [STATUS_OK,rest @ ..] if rest.len()==CHECKPOINT_BYTES=>
                decode_checkpoint(rest).map_err(|_|AnchorError::InvalidAttestation),
            [STATUS_CONFLICT]=>Err(AnchorError::Conflict),
            [STATUS_DENIED]|[STATUS_MALFORMED]=>Err(AnchorError::InvalidAttestation),
            _=>Err(AnchorError::Unavailable),
        }
    }
    fn rpc(
        &self,old:Option<PolicyCheckpoint>,next:Option<PolicyCheckpoint>,
    )->Result<PolicyCheckpoint,AnchorError>{
        let (reply,receiver)=mpsc::sync_channel(1);
        self.tx.try_send(ClientRequest {old,next,reply})
            .map_err(|_|AnchorError::Unavailable)?;
        receiver.recv_timeout(IO_BUDGET+Duration::from_secs(1))
            .map_err(|_|AnchorError::Unavailable)?
    }
}
impl TrustedPolicyAnchor for RemoteAnchorClient {
    fn current(&self)->Result<PolicyCheckpoint,AnchorError>{
        self.rpc(None,None)
    }
    fn advance(
        &self,expected:PolicyCheckpoint,replacement:PolicyCheckpoint,
    )->Result<(),AnchorError>{
        let result=self.rpc(Some(expected),Some(replacement))?;
        if result!=replacement {return Err(AnchorError::InvalidAttestation);}
        Ok(())
    }
}
