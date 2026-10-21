//! W6 externally hosted checkpoint authority over authenticated project-fork
//! Roha/noq QUIC/TLS. The server stores a durable linearizable CAS watermark
//! in its OWN SQLite WAL database; caller must deploy on an independently
//! administered/rollback-isolated host. Tests run on loopback but that is NOT
//! a production anti-rollback trust boundary.
//!
//! The pinned reader TLS identity cannot change policy, but may BEGIN
//! and FINISH an exclusive durable Mailbox write fence. A separate admin TLS
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
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use iroh::{Endpoint, EndpointAddr, EndpointId, SecretKey, endpoint::{Connection, presets}};
use rusqlite::{params, Connection as Sqlite, OpenFlags, TransactionBehavior};
use std::{
    fs::OpenOptions,
    path::Path,
    sync::{Mutex, mpsc::{self, Receiver, SyncSender}},
    thread,
    time::Duration,
};

// v4 breaks the protected reader registry schema; do not negotiate v3.
pub const ANCHOR_ALPN: &[u8] = b"akula-wow/w6-external-anchor-lab/4";
const EXTRA_READER_SLOTS: usize = 4;
const EXTRA_READER_BYTES: usize = EXTRA_READER_SLOTS * 33;
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
// Both MUTATING RPCs carry their independently pinned authority ID INSIDE
// the request. Echo-only response verification is too late: a misrouted
// request may have mutated another same-TLS-key authority already.
const WRITE_FENCE_BYTES: usize = 1 + 32 + CHECKPOINT_BYTES + 32;
const CAS_BYTES: usize = 1 + 2 * CHECKPOINT_BYTES
    + SIGNED_ENROLLMENT_BYTES + SIGNED_TRANSITION_PROOF_BYTES;
const RESPONSE_BYTES: usize = 1 + 32 + CHECKPOINT_BYTES;
const IO_BUDGET: Duration = Duration::from_secs(2);

#[derive(Debug)]
pub enum RemoteAnchorError {
    Db(rusqlite::Error),
    Io(std::io::Error),
    AlreadyProvisioned,
    NotProvisioned,
    ConfigurationMismatch,
    /// Recovery cannot proceed without two role-separated offline signatures.
    UntrustedRecovery,
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
impl From<std::io::Error> for RemoteAnchorError {
    fn from(e: std::io::Error) -> Self { Self::Io(e) }
}

/// These TLS identities MUST originate from local protected operator config,
/// not user-supplied network frames or a database field treated as authority.
#[derive(Clone, Copy, Debug)]
pub struct AnchorServicePolicy {
    /// Primary, externally provisioned writer TLS identity.
    pub reader: EndpointId,
    /// Four additional independently provisioned writer TLS identities.
    /// Every slot (including None) is pinned and compared with authority
    /// SQLite; these values never come from a QUIC peer or local policy DB.
    pub additional_readers: [Option<EndpointId>; EXTRA_READER_SLOTS],
    pub administrator: EndpointId,
    /// Independent pinned ID of the logical authority/cluster, NOT its
    /// QUIC key or an untrusted value supplied by the request.
    pub authority: AuthorityDomainId,
    /// Independently pinned OFFLINE Ed25519 operator signing authority.
    /// The corresponding private key must NEVER run on this anchor server,
    /// W6 relay, or the TLS-administrator client.
    pub operator: VerifyingKey,
    /// Independent protected offline infrastructure-fencing witness.
    /// A signature is an operator-controlled attestation of physical
    /// isolation, NOT proof that the OS has stopped a remote process.
    /// Never store its private key on the authority service.
    pub recovery_witness: VerifyingKey,
}
fn additional_reader_bytes(
    policy:AnchorServicePolicy,
)->[u8;EXTRA_READER_BYTES]{
    let mut bytes=[0u8;EXTRA_READER_BYTES];
    for (i,slot) in policy.additional_readers.iter().enumerate() {
        if let Some(reader)=slot {
            bytes[i*33]=1;
            bytes[i*33+1..(i+1)*33].copy_from_slice(reader.as_bytes());
        }
    }
    bytes
}
fn is_writer(policy:AnchorServicePolicy,peer:EndpointId)->bool{
    peer==policy.reader
        || policy.additional_readers.contains(&Some(peer))
}
fn validate_distinct_trust_roles(
    policy:&AnchorServicePolicy,
)->Result<(),RemoteAnchorError>{
    let operator=policy.operator.as_bytes();
    let witness=policy.recovery_witness.as_bytes();
    let reader=policy.reader.as_bytes();
    let administrator=policy.administrator.as_bytes();
    if operator==witness || operator==reader || operator==administrator
        || witness==reader || witness==administrator
        || reader==administrator
    {
        return Err(RemoteAnchorError::ConfigurationMismatch);
    }
    for (i,entry) in policy.additional_readers.iter().enumerate() {
        if let Some(id)=entry {
            let bytes=id.as_bytes();
            if bytes==reader || bytes==operator || bytes==witness
                || bytes==administrator
                || policy.additional_readers[..i].contains(&Some(*id))
            {
                return Err(RemoteAnchorError::ConfigurationMismatch);
            }
        }
    }
    Ok(())
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
    additional_readers: Vec<u8>,
    administrator: Vec<u8>,
    operator: Vec<u8>,
    authority: Vec<u8>,
    recovery_witness: Vec<u8>,
    checkpoint: PolicyCheckpoint,
}
struct WriterFenceRow {
    peer: Vec<u8>,
    nonce: Vec<u8>,
    checkpoint: PolicyCheckpoint,
}

/// PRIVILEGED LOCAL-ONLY recovery envelope: must never be exposed as an
/// unauthenticated network RPC or logged with its raw nonce.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OrphanFenceRecoveryOrder {
    pub authority: AuthorityDomainId,
    pub previous_reader: EndpointId,
    pub replacement_reader: EndpointId,
    pub checkpoint: PolicyCheckpoint,
    pub nonce: [u8;32],
    pub generation: u64,
}

/// The observed orphan information is read only from the authority's
/// independently trusted SQLite ledger, not from a network-supplied digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OrphanFenceInspection {
    pub authority: AuthorityDomainId,
    pub reader: EndpointId,
    pub checkpoint: PolicyCheckpoint,
    /// Treat as secret. Copy only into an operator-controlled recovery order.
    pub nonce: [u8;32],
    pub next_generation: u64,
}

const OPERATOR_RECOVERY_DOMAIN: &[u8] =
    b"Akula/WOW/W6/orphan-fence/rotate-operator/v1\0";
const WITNESS_RECOVERY_DOMAIN: &[u8] =
    b"Akula/WOW/W6/orphan-fence/physical-isolation-witness/v1\0";

fn recovery_message(domain:&[u8],order:&OrphanFenceRecoveryOrder)->Vec<u8>{
    let mut bytes=Vec::with_capacity(domain.len()+32+32+32+40+32+8);
    bytes.extend_from_slice(domain);
    bytes.extend_from_slice(order.authority.as_bytes());
    bytes.extend_from_slice(order.previous_reader.as_bytes());
    bytes.extend_from_slice(order.replacement_reader.as_bytes());
    bytes.extend_from_slice(&checkpoint_bytes(order.checkpoint));
    bytes.extend_from_slice(&order.nonce);
    bytes.extend_from_slice(&order.generation.to_be_bytes());
    bytes
}
fn verify_recovery_proof(
    signer:&VerifyingKey, domain:&[u8], order:&OrphanFenceRecoveryOrder,
    signature:&[u8],
)->Result<(),RemoteAnchorError>{
    let signature=Signature::from_slice(signature)
        .map_err(|_|RemoteAnchorError::UntrustedRecovery)?;
    signer.verify(&recovery_message(domain,order),&signature)
        .map_err(|_|RemoteAnchorError::UntrustedRecovery)
}
/// Call ONLY in the offline operator's signing environment. The signing
/// key must not be deployed to the authority or the writer.
pub fn sign_orphan_recovery_operator(
    key:&SigningKey,order:&OrphanFenceRecoveryOrder,
)->[u8;64]{
    key.sign(&recovery_message(OPERATOR_RECOVERY_DOMAIN,order)).to_bytes()
}
/// Call ONLY in the separately trusted physical isolation witness, after
/// independently verifying the old writer and authority are fenced/stopped.
pub fn sign_orphan_recovery_witness(
    key:&SigningKey,order:&OrphanFenceRecoveryOrder,
)->[u8;64]{
    key.sign(&recovery_message(WITNESS_RECOVERY_DOMAIN,order)).to_bytes()
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
        validate_distinct_trust_roles(&policy)?;
        // IMPORTANT: never run CREATE TABLE/ALTER on any existing authority
        // file. Earlier logic made an old v2 database look v3-compatible
        // even though reprovision ultimately returned AlreadyProvisioned.
        // create_new is OS-atomic; even an empty/partial former authority
        // requires a separate reviewed operator recovery ceremony.
        let reserved=match OpenOptions::new().write(true).create_new(true).open(path) {
            Ok(file)=>file,
            Err(e) if e.kind()==std::io::ErrorKind::AlreadyExists =>
                return Err(RemoteAnchorError::AlreadyProvisioned),
            Err(e)=>return Err(RemoteAnchorError::Io(e)),
        };
        drop(reserved);
        let mut sql=Sqlite::open_with_flags(path,OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        Self::schema(&mut sql)?;
        let tx=sql.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing:i64=tx.query_row(
            "SELECT COUNT(*) FROM w6_external_anchor WHERE id=1",
            [],|row|row.get(0),
        )?;
        if existing!=0 {return Err(RemoteAnchorError::AlreadyProvisioned);}
        tx.execute(
            "INSERT INTO w6_external_anchor
             (id,reader,additional_readers,administrator,operator,authority,
              recovery_witness,revision,digest)
             VALUES(1,?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                policy.reader.as_bytes().as_slice(),
                additional_reader_bytes(policy).as_slice(),
                policy.administrator.as_bytes().as_slice(),
                policy.operator.as_bytes().as_slice(),
                policy.authority.as_bytes().as_slice(),
                policy.recovery_witness.as_bytes().as_slice(),
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
        validate_distinct_trust_roles(&policy)?;
        let found=Self::record(&sql)?;
        let trusted=found.ok_or(RemoteAnchorError::NotProvisioned)?;
        // The recovery journal is mandatory. No implicit legacy schema
        // repair and no trust-root adoption from an old/rolled-back file.
        let _:i64=sql.query_row(
            "SELECT COUNT(*) FROM w6_writer_recovery",[],|row|row.get(0),
        )?;
        // A pre-v3 authority without the durable fence table MUST refuse to
        // start. Merely bumping ALPN without this table would re-open the
        // cross-host CAS versus Mailbox COMMIT race.
        let _ = Self::writer_fence(&sql)?;
        if trusted.reader.as_slice()!=policy.reader.as_bytes()
            || trusted.additional_readers.as_slice()!=additional_reader_bytes(policy)
            || trusted.administrator.as_slice()!=policy.administrator.as_bytes()
            || trusted.operator.as_slice()!=policy.operator.as_bytes()
            || trusted.authority.as_slice()!=policy.authority.as_bytes()
            || trusted.recovery_witness.as_slice()!=policy.recovery_witness.as_bytes()
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
               additional_readers BLOB NOT NULL
                 CHECK(length(additional_readers)=132),
               administrator BLOB NOT NULL CHECK(length(administrator)=32),
               operator BLOB NOT NULL CHECK(length(operator)=32),
               authority BLOB NOT NULL CHECK(length(authority)=32),
               recovery_witness BLOB NOT NULL CHECK(length(recovery_witness)=32),
               revision INTEGER NOT NULL CHECK(revision>=0),
               digest BLOB NOT NULL CHECK(length(digest)=32)
             );
             CREATE TABLE IF NOT EXISTS w6_writer_fence (
               singleton INTEGER PRIMARY KEY CHECK(singleton=1),
               peer BLOB NOT NULL CHECK(length(peer)=32),
               nonce BLOB NOT NULL CHECK(length(nonce)=32),
               revision INTEGER NOT NULL CHECK(revision>=0),
               digest BLOB NOT NULL CHECK(length(digest)=32)
             );
             CREATE TABLE IF NOT EXISTS w6_writer_recovery (
               generation INTEGER PRIMARY KEY CHECK(generation>0),
               authority BLOB NOT NULL CHECK(length(authority)=32),
               previous_reader BLOB NOT NULL CHECK(length(previous_reader)=32),
               replacement_reader BLOB NOT NULL CHECK(length(replacement_reader)=32),
               nonce_hash BLOB NOT NULL CHECK(length(nonce_hash)=32),
               revision INTEGER NOT NULL CHECK(revision>=0),
               digest BLOB NOT NULL CHECK(length(digest)=32),
               operator_signature BLOB NOT NULL CHECK(length(operator_signature)=64),
               witness_signature BLOB NOT NULL CHECK(length(witness_signature)=64)
             );"
        )?;
        Ok(())
    }
    fn record(db:&Sqlite)->Result<Option<StoredAnchorRow>,RemoteAnchorError>{
        use rusqlite::OptionalExtension;
        let rec=db.query_row(
            "SELECT reader,additional_readers,administrator,operator,authority,
                    recovery_witness,revision,digest
             FROM w6_external_anchor WHERE id=1",
            [],|row|Ok((
                row.get::<_,Vec<u8>>(0)?,
                row.get::<_,Vec<u8>>(1)?,
                row.get::<_,Vec<u8>>(2)?,
                row.get::<_,Vec<u8>>(3)?,
                row.get::<_,Vec<u8>>(4)?,
                row.get::<_,Vec<u8>>(5)?,
                row.get::<_,i64>(6)?,
                row.get::<_,Vec<u8>>(7)?,
            )),
        ).optional()?;
        let Some((reader,additional_readers,administrator,operator,authority,
                  recovery_witness,rev,digest))=rec
        else {return Ok(None)};
        if reader.len()!=32 || additional_readers.len()!=EXTRA_READER_BYTES
            || administrator.len()!=32 || operator.len()!=32 || authority.len()!=32
            || recovery_witness.len()!=32
            || recovery_witness.as_slice()==operator.as_slice()
            || authority.iter().all(|&b| b == 0)
            || digest.len()!=32 || rev<0 {
            return Err(RemoteAnchorError::CorruptStorage);
        }
        let mut d=[0u8;32];d.copy_from_slice(&digest);
        Ok(Some(StoredAnchorRow {
            reader, additional_readers, administrator, operator, authority,
            recovery_witness, checkpoint:PolicyCheckpoint {revision:rev as u64,digest:d},
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

    /// Compare the independently pinned configuration on EVERY access.
    /// An old authority process that still has the old reader key in memory
    /// must never process new writes after a different local maintenance
    /// process rotated that key in shared SQLite.
    fn require_pinned_policy(
        policy:AnchorServicePolicy,stored:&StoredAnchorRow,
    )->Result<(),RemoteAnchorError>{
        if stored.reader.as_slice()!=policy.reader.as_bytes()
            || stored.additional_readers.as_slice()!=additional_reader_bytes(policy)
            || stored.administrator.as_slice()!=policy.administrator.as_bytes()
            || stored.operator.as_slice()!=policy.operator.as_bytes()
            || stored.authority.as_slice()!=policy.authority.as_bytes()
            || stored.recovery_witness.as_slice()!=policy.recovery_witness.as_bytes()
        {
            return Err(RemoteAnchorError::ConfigurationMismatch);
        }
        Ok(())
    }
    fn recovery_generation(db:&Sqlite)->Result<u64,RemoteAnchorError>{
        let latest:i64=db.query_row(
            "SELECT COALESCE(MAX(generation),0) FROM w6_writer_recovery",
            [],|row|row.get(0),
        )?;
        let next=latest.checked_add(1).ok_or(RemoteAnchorError::CorruptStorage)?;
        if next<=0 {return Err(RemoteAnchorError::CorruptStorage);}
        Ok(next as u64)
    }

    /// PRIVILEGED LOCAL ONLY: returns sensitive nonce bytes. Never expose
    /// this method through QUIC, logs, user-visible diagnostics, or untrusted
    /// callers. The operator must obtain independent evidence that the
    /// original writer is PHYSICALLY isolated before signing a recovery.
    pub fn inspect_orphan_fence(
        &self,
    )->Result<Option<OrphanFenceInspection>,RemoteAnchorError>{
        let current=Self::record(&self.sql)?
            .ok_or(RemoteAnchorError::NotProvisioned)?;
        Self::require_pinned_policy(self.policy,&current)?;
        let Some(held)=Self::writer_fence(&self.sql)? else {return Ok(None)};
        if held.checkpoint!=current.checkpoint {
            return Err(RemoteAnchorError::CorruptStorage);
        }
        let reader:[u8;32]=held.peer.try_into()
            .map_err(|_|RemoteAnchorError::CorruptStorage)?;
        let nonce:[u8;32]=held.nonce.try_into()
            .map_err(|_|RemoteAnchorError::CorruptStorage)?;
        let reader=EndpointId::from_bytes(&reader)
            .map_err(|_|RemoteAnchorError::CorruptStorage)?;
        Ok(Some(OrphanFenceInspection {
            authority:self.policy.authority,
            reader,nonce,checkpoint:held.checkpoint,
            next_generation:Self::recovery_generation(&self.sql)?,
        }))
    }

    /// ONLY for a physically fenced old writer, after out-of-band witness
    /// attestation. A cryptographic witness signature is an assertion of
    /// isolation, NOT an OS liveness oracle. If this assertion is false,
    /// a paused old writer could still durably commit after the recovery.
    ///
    /// No online QUIC RPC exposes this operation. Releasing the old fence,
    /// installing a fresh reader TLS identity and writing the audit evidence
    /// is one FULL-synchronous SQLite IMMEDIATE transaction.
    pub fn recover_orphan_after_external_isolation(
        &mut self,order:&OrphanFenceRecoveryOrder,
        operator_signature:&[u8],witness_signature:&[u8],
    )->Result<PolicyCheckpoint,RemoteAnchorError>{
        if order.authority!=self.policy.authority
            || !is_writer(self.policy,order.previous_reader)
            || order.replacement_reader==order.previous_reader
            || is_writer(self.policy,order.replacement_reader)
            || order.replacement_reader==self.policy.administrator
            || order.replacement_reader.as_bytes()==self.policy.operator.as_bytes()
            || order.replacement_reader.as_bytes()==self.policy.recovery_witness.as_bytes()
            || order.nonce==[0;32]
            || order.generation==0
        {
            return Err(RemoteAnchorError::UntrustedRecovery);
        }
        // Each signature has a DIFFERENT domain separator and DIFFERENT
        // independently pinned root; neither the TLS admin nor a single
        // operator key can authorize an orphan release.
        verify_recovery_proof(
            &self.policy.operator,OPERATOR_RECOVERY_DOMAIN,
            order,operator_signature,
        )?;
        verify_recovery_proof(
            &self.policy.recovery_witness,WITNESS_RECOVERY_DOMAIN,
            order,witness_signature,
        )?;
        let tx=self.sql.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current=Self::record(&tx)?.ok_or(RemoteAnchorError::NotProvisioned)?;
        Self::require_pinned_policy(self.policy,&current)?;
        if current.checkpoint!=order.checkpoint
            || Self::recovery_generation(&tx)?!=order.generation
        {
            return Err(RemoteAnchorError::Conflict);
        }
        let held=Self::writer_fence(&tx)?.ok_or(RemoteAnchorError::Conflict)?;
        if held.peer.as_slice()!=order.previous_reader.as_bytes()
            || held.nonce.as_slice()!=order.nonce
            || held.checkpoint!=order.checkpoint
        {
            return Err(RemoteAnchorError::Conflict);
        }
        // The signature binds exact old reader, replacement reader,
        // authority, checkpoint, secret token and monotonic sequence.
        // Record a hash rather than leaking the WRITE-FINISH capability.
        let nonce_hash=blake3::hash(&order.nonce);
        tx.execute(
            "INSERT INTO w6_writer_recovery (
                generation,authority,previous_reader,replacement_reader,
                nonce_hash,revision,digest,operator_signature,witness_signature
             ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![
                to_int(order.generation)?,
                order.authority.as_bytes().as_slice(),
                order.previous_reader.as_bytes().as_slice(),
                order.replacement_reader.as_bytes().as_slice(),
                nonce_hash.as_bytes().as_slice(),
                to_int(order.checkpoint.revision)?,
                order.checkpoint.digest.as_slice(),
                operator_signature,witness_signature,
            ],
        )?;
        // Rotate ONLY the exact credential holding the fence; other
        // independent writers keep their pinned identities unchanged.
        let mut updated=self.policy;
        if order.previous_reader==updated.reader {
            updated.reader=order.replacement_reader;
        } else {
            let Some(slot)=updated.additional_readers.iter_mut()
                .find(|s|**s==Some(order.previous_reader))
            else {return Err(RemoteAnchorError::ConfigurationMismatch)};
            *slot=Some(order.replacement_reader);
        }
        tx.execute(
            "UPDATE w6_external_anchor SET reader=?1,additional_readers=?2
             WHERE id=1",
            params![
                updated.reader.as_bytes().as_slice(),
                additional_reader_bytes(updated).as_slice(),
            ],
        )?;
        tx.execute("DELETE FROM w6_writer_fence WHERE singleton=1",[])?;
        tx.commit()?;
        // In-memory server authorization must switch only after COMMIT.
        // Protected deployment configuration must independently pin the new
        // writer set before restart; other writers remain authorized.
        self.policy=updated;
        Ok(order.checkpoint)
    }

    /// Reserve one global Mailbox-commit slot, linearized against signed CAS
    /// in the SAME authority SQLite IMMEDIATE transaction. A client must
    /// already have a valid local enrollment for the identical checkpoint.
    /// The token is a fresh CSPRNG-generated secret scoped to this operation.
    pub fn begin_write_for(
        &mut self,peer:EndpointId,expected:PolicyCheckpoint,nonce:[u8;32],
    )->Result<PolicyCheckpoint,RemoteAnchorError>{
        if !is_writer(self.policy,peer) {return Err(RemoteAnchorError::UntrustedPeer);}
        if nonce==[0;32] {return Err(RemoteAnchorError::Protocol);}
        let tx=self.sql.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current=Self::record(&tx)?.ok_or(RemoteAnchorError::NotProvisioned)?;
        Self::require_pinned_policy(self.policy,&current)?;
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
        if !is_writer(self.policy,peer) {return Err(RemoteAnchorError::UntrustedPeer);}
        let tx=self.sql.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current=Self::record(&tx)?.ok_or(RemoteAnchorError::NotProvisioned)?;
        Self::require_pinned_policy(self.policy,&current)?;
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
        if !is_writer(self.policy,peer) && peer!=self.policy.administrator {
            return Err(RemoteAnchorError::UntrustedPeer);
        }
        let record=Self::record(&self.sql)?
            .ok_or(RemoteAnchorError::NotProvisioned)?;
        Self::require_pinned_policy(self.policy,&record)?;
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
        Self::require_pinned_policy(self.policy,&record)?;
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
            if &wire[1..33] != service.policy.authority.as_bytes() {
                // Reject BEFORE touching the SQLite permit row. Same TLS
                // EndpointId is allowed to front distinct logical domains.
                vec![STATUS_DENIED]
            } else {
                let cp=decode_checkpoint(&wire[33..33+CHECKPOINT_BYTES]);
                let nonce:Result<[u8;32],_>=
                    wire[33+CHECKPOINT_BYTES..].try_into();
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
        wire.extend_from_slice(self.authority.as_bytes());
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
        wire.extend_from_slice(self.authority.as_bytes());
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
