//! W6 externally hosted checkpoint authority over authenticated project-fork
//! Roha/noq QUIC/TLS. The server stores a durable linearizable CAS watermark
//! in its OWN SQLite WAL database; caller must deploy on an independently
//! administered/rollback-isolated host. Tests run on loopback but that is NOT
//! a production anti-rollback trust boundary.
//!
//! The relay is a READ-ONLY TLS identity. A separately pinned admin TLS
//! identity may publish a strictly monotonic CAS ONLY when it carries TWO
//! valid offline operator Ed25519 signatures binding the change, original
//! checkpoint and exact replacement digest. Admin TLS key alone CANNOT
//! create or change any checkpoint. No network bootstrap:
//! provisioning is an explicit local service-owner operation.
//!
//! Protocol v3: one bounded bidirectional QUIC stream per connection,
//! GET, offline-signed CAS, and fixed-size WRITE-BEGIN/WRITE-FINISH. Successful
//! responses echo the pinned domain and 40-byte checkpoint. No 0-RTT.
//! A durable writer fence serializes revoke CAS with any Mailbox COMMIT; a
//! crashed writer leaves HOLD, NEVER an automatically expiring lease.
//! QUIC identity always comes from connection.remote_id(), never a frame.
//!
//! This is a bounded LAB service and synchronous client adapter, not a
//! production accept scheduler, physical HSM, quorum audit log or disk quota.
use crate::peer_enrollment_w6::{
    AnchorError, AuthorityDomainId, PolicyCheckpoint, TrustedPolicyAnchor, SIGNED_ENROLLMENT_BYTES,
    SIGNED_TRANSITION_PROOF_BYTES, verify_signed_anchor_transition,
};
use ed25519_dalek::VerifyingKey;
use iroh::{Endpoint, EndpointAddr, EndpointId, SecretKey, endpoint::{Connection, presets}};
use rusqlite::{params, Connection as Sqlite, OpenFlags, TransactionBehavior};
use std::{
    path::Path,
    sync::{Mutex, mpsc::{self, Receiver, SyncSender}},
    thread,
    time::Duration,
};

pub const ANCHOR_ALPN: &[u8] = b"akula-wow/w6-external-anchor-lab/3";
const OP_GET: u8 = 1;
const OP_CAS: u8 = 2;
const OP_WRITE_BEGIN: u8 = 3;
const OP_WRITE_FINISH: u8 = 4;
const STATUS_OK: u8 = 0;
const STATUS_DENIED: u8 = 3;
const STATUS_CONFLICT: u8 = 4;
const STATUS_FAULT: u8 = 5;
const STATUS_MALFORMED: u8 = 6;
const CLIENT_RESPONSE_RECEIVED: u8 = 0x71;
const CHECKPOINT_BYTES: usize = 40;
const GET_BYTES: usize = 1;
const WRITE_FENCE_BYTES: usize = 1 + CHECKPOINT_BYTES + 32;
const CAS_BYTES: usize = 1 + 2 * CHECKPOINT_BYTES
    + SIGNED_ENROLLMENT_BYTES + SIGNED_TRANSITION_PROOF_BYTES;
const RESPONSE_BYTES: usize = 1 + 32 + CHECKPOINT_BYTES;
const IO_BUDGET: Duration = Duration::from_secs(2);

#[derive(Debug)]
pub enum RemoteAnchorError {
    Db(rusqlite::Error),
    AlreadyProvisioned,
    NotProvisioned,
    ConfigurationMismatch,
    UntrustedPeer,
    UntrustedOperatorTransition,
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
    /// Independent pinned ID of the logical authority/cluster, NOT its
    /// QUIC key or an untrusted value supplied by the request.
    pub authority: AuthorityDomainId,
    /// Independently pinned OFFLINE Ed25519 operator signing authority.
    /// The corresponding private key must NEVER run on this anchor server,
    /// W6 relay, or the TLS-administrator client.
    pub operator: VerifyingKey,
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
    operator: Vec<u8>,
    authority: Vec<u8>,
    checkpoint: PolicyCheckpoint,
}
struct WriterFenceRow {
    peer: Vec<u8>,
    nonce: Vec<u8>,
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
             (id,reader,administrator,operator,authority,revision,digest)
             VALUES(1,?1,?2,?3,?4,?5,?6)",
            params![
                policy.reader.as_bytes().as_slice(),
                policy.administrator.as_bytes().as_slice(),
                policy.operator.as_bytes().as_slice(),
                policy.authority.as_bytes().as_slice(),
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
        // A pre-v3 authority without the durable fence table MUST refuse to
        // start. Merely bumping ALPN without this table would re-open the
        // cross-host CAS versus Mailbox COMMIT race.
        let _ = Self::writer_fence(&sql)?;
        if trusted.reader.as_slice()!=policy.reader.as_bytes()
            || trusted.administrator.as_slice()!=policy.administrator.as_bytes()
            || trusted.operator.as_slice()!=policy.operator.as_bytes()
            || trusted.authority.as_slice()!=policy.authority.as_bytes()
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
               operator BLOB NOT NULL CHECK(length(operator)=32),
               authority BLOB NOT NULL CHECK(length(authority)=32),
               revision INTEGER NOT NULL CHECK(revision>=0),
               digest BLOB NOT NULL CHECK(length(digest)=32)
             );
             CREATE TABLE IF NOT EXISTS w6_writer_fence (
               singleton INTEGER PRIMARY KEY CHECK(singleton=1),
               peer BLOB NOT NULL CHECK(length(peer)=32),
               nonce BLOB NOT NULL CHECK(length(nonce)=32),
               revision INTEGER NOT NULL CHECK(revision>=0),
               digest BLOB NOT NULL CHECK(length(digest)=32)
             );"
        )?;
        Ok(())
    }
    fn record(db:&Sqlite)->Result<Option<StoredAnchorRow>,RemoteAnchorError>{
        use rusqlite::OptionalExtension;
        let rec=db.query_row(
            "SELECT reader,administrator,operator,authority,revision,digest
             FROM w6_external_anchor WHERE id=1",
            [],|row|Ok((
                row.get::<_,Vec<u8>>(0)?,
                row.get::<_,Vec<u8>>(1)?,
                row.get::<_,Vec<u8>>(2)?,
                row.get::<_,Vec<u8>>(3)?,
                row.get::<_,i64>(4)?,
                row.get::<_,Vec<u8>>(5)?,
            )),
        ).optional()?;
        let Some((reader,administrator,operator,authority,rev,digest))=rec
        else {return Ok(None)};
        if reader.len()!=32 || administrator.len()!=32
            || operator.len()!=32 || authority.len()!=32
            || authority.iter().all(|&b| b == 0)
            || digest.len()!=32 || rev<0 {
            return Err(RemoteAnchorError::CorruptStorage);
        }
        let mut d=[0u8;32];d.copy_from_slice(&digest);
        Ok(Some(StoredAnchorRow {
            reader, administrator, operator, authority,
            checkpoint:PolicyCheckpoint {revision:rev as u64,digest:d},
        }))
    }
    fn writer_fence(db:&Sqlite)->Result<Option<WriterFenceRow>,RemoteAnchorError>{
        use rusqlite::OptionalExtension;
        let row=db.query_row(
            "SELECT peer,nonce,revision,digest FROM w6_writer_fence WHERE singleton=1",
            [],|r|Ok((
                r.get::<_,Vec<u8>>(0)?,r.get::<_,Vec<u8>>(1)?,
                r.get::<_,i64>(2)?,r.get::<_,Vec<u8>>(3)?,
            )),
        ).optional()?;
        let Some((peer,nonce,revision,digest))=row else {return Ok(None)};
        if peer.len()!=32 || nonce.len()!=32 || nonce.iter().all(|&n|n==0)
            || revision<0 || digest.len()!=32 {
            return Err(RemoteAnchorError::CorruptStorage);
        }
        let mut hash=[0u8;32];hash.copy_from_slice(&digest);
        Ok(Some(WriterFenceRow {
            peer,nonce,checkpoint:PolicyCheckpoint{revision:revision as u64,digest:hash},
        }))
    }

    /// Reserve one global Mailbox-commit slot, linearized against signed CAS
    /// in the SAME authority SQLite IMMEDIATE transaction. A client must
    /// already have a valid local enrollment for the identical checkpoint.
    /// The token is a fresh CSPRNG-generated secret scoped to this operation.
    pub fn begin_write_for(
        &mut self,peer:EndpointId,expected:PolicyCheckpoint,nonce:[u8;32],
    )->Result<PolicyCheckpoint,RemoteAnchorError>{
        if peer!=self.policy.reader {return Err(RemoteAnchorError::UntrustedPeer);}
        if nonce==[0;32] {return Err(RemoteAnchorError::Protocol);}
        let tx=self.sql.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current=Self::record(&tx)?.ok_or(RemoteAnchorError::NotProvisioned)?;
        if current.checkpoint!=expected {return Err(RemoteAnchorError::Conflict);}
        if let Some(held)=Self::writer_fence(&tx)? {
            // Retried acquisition after an ambiguous QUIC response must be
            // idempotent ONLY for the original writer and exact token.
            if held.peer.as_slice()!=peer.as_bytes()
                || held.nonce.as_slice()!=nonce
                || held.checkpoint!=expected
            {
                return Err(RemoteAnchorError::Conflict);
            }
        } else {
            tx.execute(
                "INSERT INTO w6_writer_fence
                 (singleton,peer,nonce,revision,digest) VALUES(1,?1,?2,?3,?4)",
                params![peer.as_bytes().as_slice(),nonce.as_slice(),
                    to_int(expected.revision)?,expected.digest.as_slice()],
            )?;
        }
        tx.commit()?;
        Ok(expected)
    }

    /// Never release a fence based on elapsed time or connection teardown:
    /// the writer may still be committing on another host. The exact reader
    /// credential and nonce must finish AFTER its durable callback outcome.
    pub fn finish_write_for(
        &mut self,peer:EndpointId,expected:PolicyCheckpoint,nonce:[u8;32],
    )->Result<PolicyCheckpoint,RemoteAnchorError>{
        if peer!=self.policy.reader {return Err(RemoteAnchorError::UntrustedPeer);}
        let tx=self.sql.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current=Self::record(&tx)?.ok_or(RemoteAnchorError::NotProvisioned)?;
        if current.checkpoint!=expected {return Err(RemoteAnchorError::Conflict);}
        let held=Self::writer_fence(&tx)?.ok_or(RemoteAnchorError::Conflict)?;
        if held.peer.as_slice()!=peer.as_bytes()
            || held.nonce.as_slice()!=nonce || held.checkpoint!=expected
        {
            return Err(RemoteAnchorError::Conflict);
        }
        tx.execute("DELETE FROM w6_writer_fence WHERE singleton=1",[])?;
        tx.commit()?;
        Ok(expected)
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
    /// Strictly monotonic, FULL-synchronous SQLite BEGIN IMMEDIATE CAS.
    /// BOTH the pinned admin TLS identity and independently OFFLINE-signed
    /// operator change + checkpoint transition MUST validate. The server
    /// verifies these signatures itself, never accepting an arbitrary digest
    /// chosen solely by an online TLS administrator.
    pub fn advance_for(
        &mut self,peer:EndpointId,expected:PolicyCheckpoint,
        next:PolicyCheckpoint,change:&[u8],proof:&[u8],
    )->Result<PolicyCheckpoint,RemoteAnchorError>{
        if peer!=self.policy.administrator {
            return Err(RemoteAnchorError::UntrustedPeer);
        }
        verify_signed_anchor_transition(
            &self.policy.operator,self.policy.authority,change,expected,next,proof,
        ).map_err(|_|RemoteAnchorError::UntrustedOperatorTransition)?;
        to_int(next.revision)?;
        let tx=self.sql.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let record=Self::record(&tx)?
            .ok_or(RemoteAnchorError::NotProvisioned)?;
        if record.checkpoint!=expected {return Err(RemoteAnchorError::Conflict);}
        // IMPORTANT: no signed revoke (or allow) is published while an
        // independent host still has an in-flight Mailbox COMMIT. The
        // durable slot survives authority process SIGKILL/restart.
        if Self::writer_fence(&tx)?.is_some() {
            return Err(RemoteAnchorError::Conflict);
        }
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
fn encode_reply(
    out:Result<PolicyCheckpoint,RemoteAnchorError>,authority:AuthorityDomainId,
)->Vec<u8>{
    match out {
        Ok(v)=>{
            let mut r=Vec::with_capacity(RESPONSE_BYTES);
            r.push(STATUS_OK);
            r.extend_from_slice(authority.as_bytes());
            r.extend_from_slice(&checkpoint_bytes(v));
            r
        }
        Err(RemoteAnchorError::UntrustedPeer
            | RemoteAnchorError::UntrustedOperatorTransition)=>vec![STATUS_DENIED],
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
            encode_reply(service.current_for(remote),service.policy.authority)
        } else if wire.len()==WRITE_FENCE_BYTES
            && (wire[0]==OP_WRITE_BEGIN || wire[0]==OP_WRITE_FINISH)
        {
            let cp=decode_checkpoint(&wire[1..1+CHECKPOINT_BYTES]);
            let nonce:Result<[u8;32],_>=wire[1+CHECKPOINT_BYTES..].try_into();
            match (cp,nonce) {
                (Ok(expected),Ok(nonce))=>{
                    let response=if wire[0]==OP_WRITE_BEGIN {
                        service.begin_write_for(remote,expected,nonce)
                    } else {
                        service.finish_write_for(remote,expected,nonce)
                    };
                    encode_reply(response,service.policy.authority)
                },
                _=>vec![STATUS_MALFORMED],
            }
        } else if wire.len()==CAS_BYTES && wire[0]==OP_CAS {
            let first=decode_checkpoint(&wire[1..1+CHECKPOINT_BYTES]);
            // Signed operator change follows two *exactly 40-byte* checkpoint
            // fields. Decoding the entire remaining packet would include the
            // Ed25519 proofs and reject every legitimate signed CAS.
            let second=decode_checkpoint(
                &wire[1+CHECKPOINT_BYTES..1+2*CHECKPOINT_BYTES],
            );
            let change_start=1+2*CHECKPOINT_BYTES;
            let proof_start=change_start+SIGNED_ENROLLMENT_BYTES;
            let change=&wire[change_start..proof_start];
            let proof=&wire[proof_start..CAS_BYTES];
            match (first,second) {
                (Ok(old),Ok(new))=>
                    encode_reply(
                        service.advance_for(remote,old,new,change,proof),
                        service.policy.authority,
                    ),
                _=>{
                    eprintln!("W6 anchor invalid signed-CAS checkpoint encoding");
                    vec![STATUS_MALFORMED]
                },
            }
        } else {
            // Redacted structural-only telemetry, no keys or patient data.
            eprintln!("W6 anchor unexpected request wire bytes: len={} expected-CAS={}",wire.len(),CAS_BYTES);
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
    authority: AuthorityDomainId,
}
struct ClientRequest {
    wire:Vec<u8>,
    reply:mpsc::SyncSender<Result<PolicyCheckpoint,AnchorError>>,
}
impl RemoteAnchorClient {
    pub fn start(
        local:SecretKey,remote:EndpointAddr,authority:AuthorityDomainId,
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
                    Self::worker(&rt,&endpoint,remote,authority,requests);
                }
                Err(e)=>{let _=ready_sender.send(Err(e));}
            }
        });
        ready.recv_timeout(IO_BUDGET).map_err(|_|AnchorError::Unavailable)??;
        Ok(Self {tx,authority})
    }
    fn worker(
        rt:&tokio::runtime::Runtime,local:&Endpoint,remote:EndpointAddr,
        authority:AuthorityDomainId,requests:Receiver<ClientRequest>,
    ) {
        for req in requests {
            let output=rt.block_on(Self::invoke(
                local,remote.clone(),authority,req.wire,
            ));
            let _=req.reply.send(output);
        }
    }
    async fn invoke(
        local:&Endpoint,remote:EndpointAddr,
        authority:AuthorityDomainId,request:Vec<u8>,
    )->Result<PolicyCheckpoint,AnchorError>{
        if request.len()!=GET_BYTES && request.len()!=CAS_BYTES
            && request.len()!=WRITE_FENCE_BYTES
        {
            return Err(AnchorError::InvalidAttestation);
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
            [STATUS_OK,rest @ ..] if rest.len()==32+CHECKPOINT_BYTES => {
                // A TLS-authenticated server identity is not sufficient if
                // the same EndpointId is configured for multiple domains.
                // The response itself MUST echo our independently pinned ID.
                if &rest[..32] != authority.as_bytes() {
                    return Err(AnchorError::InvalidAttestation);
                }
                decode_checkpoint(&rest[32..])
                    .map_err(|_|AnchorError::InvalidAttestation)
            },
            [STATUS_CONFLICT]=>Err(AnchorError::Conflict),
            [STATUS_DENIED]=>{
                eprintln!("W6 anchor rejected TLS identity or offline operator proof");
                Err(AnchorError::InvalidAttestation)
            }
            [STATUS_MALFORMED]=>{
                eprintln!("W6 anchor rejected malformed signed-CAS wire frame");
                Err(AnchorError::InvalidAttestation)
            }
            _=>Err(AnchorError::Unavailable),
        }
    }
    fn rpc(&self,wire:Vec<u8>)->Result<PolicyCheckpoint,AnchorError>{
        let (reply,receiver)=mpsc::sync_channel(1);
        self.tx.try_send(ClientRequest {wire,reply})
            .map_err(|_|AnchorError::Unavailable)?;
        receiver.recv_timeout(IO_BUDGET+Duration::from_secs(1))
            .map_err(|_|AnchorError::Unavailable)?
    }
}
impl TrustedPolicyAnchor for RemoteAnchorClient {
    fn authority_domain(&self)->Option<AuthorityDomainId> { Some(self.authority) }
    fn current(&self)->Result<PolicyCheckpoint,AnchorError>{
        self.rpc(vec![OP_GET])
    }
    fn advance(
        &self,_expected:PolicyCheckpoint,_replacement:PolicyCheckpoint,
    )->Result<(),AnchorError>{
        // SECURITY: Disable unauthenticated legacy CAS. TLS admin identity
        // alone may NOT choose any new revision or BLAKE3 digest.
        Err(AnchorError::InvalidAttestation)
    }
    fn begin_write_fence(
        &self,checkpoint:PolicyCheckpoint,nonce:[u8;32],
    )->Result<(),AnchorError>{
        let mut wire=Vec::with_capacity(WRITE_FENCE_BYTES);
        wire.push(OP_WRITE_BEGIN);
        wire.extend_from_slice(&checkpoint_bytes(checkpoint));
        wire.extend_from_slice(&nonce);
        if self.rpc(wire)?!=checkpoint {return Err(AnchorError::InvalidAttestation);}
        Ok(())
    }
    fn finish_write_fence(
        &self,checkpoint:PolicyCheckpoint,nonce:[u8;32],
    )->Result<(),AnchorError>{
        let mut wire=Vec::with_capacity(WRITE_FENCE_BYTES);
        wire.push(OP_WRITE_FINISH);
        wire.extend_from_slice(&checkpoint_bytes(checkpoint));
        wire.extend_from_slice(&nonce);
        if self.rpc(wire)?!=checkpoint {return Err(AnchorError::InvalidAttestation);}
        Ok(())
    }
    fn advance_signed(
        &self,expected:PolicyCheckpoint,replacement:PolicyCheckpoint,
        change:&[u8],proof:&[u8],
    )->Result<(),AnchorError>{
        if change.len()!=SIGNED_ENROLLMENT_BYTES
            || proof.len()!=SIGNED_TRANSITION_PROOF_BYTES
        {
            return Err(AnchorError::InvalidAttestation);
        }
        let mut wire=Vec::with_capacity(CAS_BYTES);
        wire.push(OP_CAS);
        wire.extend_from_slice(&checkpoint_bytes(expected));
        wire.extend_from_slice(&checkpoint_bytes(replacement));
        wire.extend_from_slice(change);
        wire.extend_from_slice(proof);
        let result=self.rpc(wire)?;
        if result!=replacement {return Err(AnchorError::InvalidAttestation);}
        Ok(())
    }
}
