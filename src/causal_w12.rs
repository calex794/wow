//! W12 lab: bind exact opaque W3 ciphertext and a private causal commitment
//! in ONE SQLite WAL+FULL transaction. A causal commitment is NOT W4.
//!
//! The caller MUST independently authorize the actor and mailbox scope
//! before calling; this method only checks pinned signer identity, byte
//! integrity and v3 framing. It neither decrypts W3 nor proves physical
//! retention by a malicious or compromised custodian.
//!
//! Feature causal-lab-fault enables intentional process aborts in tests.
use crate::journal_w4::Journal;
use crate::trust_w3::TrustRegistry;
use crate::private_route_w3;
use ed25519_dalek::{Signature,Signer,SigningKey,Verifier};
use rusqlite::{params,OptionalExtension,TransactionBehavior};
use std::convert::TryInto;

const DOMAIN: &[u8] = b"Akula/WOW/W12/PrivateCausalStorageClaim/Ed25519/v0\0";
const EMPTY: [u8;32] = [0;32];

#[derive(Debug)]
pub enum CausalError {
    Db(rusqlite::Error),
    Invalid,
    Unauthorized,
    Conflict,
    Corrupt,
}
impl From<rusqlite::Error> for CausalError {
    fn from(v: rusqlite::Error) -> Self { Self::Db(v) }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CausalCommitment {
    pub seq: u64,
    pub digest: [u8;32],
}
#[derive(Debug, Clone, Copy)]
pub struct CausalRequest {
    pub private_scope: [u8;16],
    pub custodian_id: [u8;16],
    pub custodian_epoch: u64,
    pub recipient: [u8;16],
    pub message: [u8;16],
    pub expiry_ms: i64,
}
fn bytes(req: CausalRequest, seq: u64, prev: &[u8;32], packet_hash: &[u8;32]) -> Vec<u8> {
    let mut v=Vec::with_capacity(190);
    v.extend_from_slice(DOMAIN);
    v.extend_from_slice(&req.private_scope);
    v.extend_from_slice(&req.custodian_id);
    v.extend_from_slice(&req.custodian_epoch.to_be_bytes());
    v.extend_from_slice(&seq.to_be_bytes());
    v.extend_from_slice(prev);
    v.extend_from_slice(&req.recipient);
    v.extend_from_slice(&req.message);
    v.extend_from_slice(packet_hash);
    v
}
fn digest_of(body: &[u8], sig: &[u8]) -> [u8;32] {
    let mut h=blake3::Hasher::new();
    h.update(body); h.update(sig);
    *h.finalize().as_bytes()
}
fn fixed32(v: &[u8]) -> Result<[u8;32],CausalError> {
    v.try_into().map_err(|_|CausalError::Corrupt)
}
impl Journal {
    fn ensure_w12_schema(&self) -> Result<(),CausalError> {
        self.db.execute_batch(
            "CREATE TABLE IF NOT EXISTS causal_w12_event(
               private_scope BLOB NOT NULL CHECK(length(private_scope)=16),
               custodian_id BLOB NOT NULL CHECK(length(custodian_id)=16),
               custodian_epoch INTEGER NOT NULL CHECK(custodian_epoch>0),
               seq INTEGER NOT NULL CHECK(seq>0),
               predecessor BLOB NOT NULL CHECK(length(predecessor)=32),
               recipient BLOB NOT NULL CHECK(length(recipient)=16),
               message BLOB NOT NULL CHECK(length(message)=16),
               packet_digest BLOB NOT NULL CHECK(length(packet_digest)=32),
               body BLOB NOT NULL,
               signature BLOB NOT NULL CHECK(length(signature)=64),
               commitment BLOB NOT NULL UNIQUE CHECK(length(commitment)=32),
               PRIMARY KEY(private_scope,custodian_id,seq),
               UNIQUE(recipient,message),
               FOREIGN KEY(recipient,message) REFERENCES outbox(recipient,message)
             );
             CREATE TABLE IF NOT EXISTS causal_w12_head(
               private_scope BLOB NOT NULL CHECK(length(private_scope)=16),
               custodian_id BLOB NOT NULL CHECK(length(custodian_id)=16),
               seq INTEGER NOT NULL CHECK(seq>0),
               commitment BLOB NOT NULL CHECK(length(commitment)=32),
               PRIMARY KEY(private_scope,custodian_id)
             );"
        )?;
        Ok(())
    }

    /// Caller first validates *separate* rights to accept/store under
    /// private_scope. The returned commitment is available only after durable
    /// local SQLite commit, and never impersonates recipient's W4.
    pub fn enqueue_w3_with_causal(
        &mut self, req: CausalRequest, w3: &[u8],
        signer: &SigningKey, trust: &TrustRegistry,
    ) -> Result<CausalCommitment,CausalError> {
        if req.private_scope == [0;16] || req.custodian_id == [0;16]
            || req.custodian_epoch == 0 || req.custodian_epoch > i64::MAX as u64
            || req.recipient == [0;16] || req.message == [0;16]
            || req.expiry_ms <= 0 || w3.is_empty()
            || w3.len() > crate::MAX_MESSAGE_BYTES
        { return Err(CausalError::Invalid); }
        if trust.key_for(req.custodian_id,req.custodian_epoch).ok()
            != Some(&signer.verifying_key())
        { return Err(CausalError::Unauthorized); }
        // Public v3 route header is untrusted, but at minimum reject
        // misidentified / malformed W3 bytes. No W3 sender authority inferred.
        let hint=private_route_w3::inspect_route(w3)
            .map_err(|_|CausalError::Invalid)?;
        if hint.message_id != req.message { return Err(CausalError::Invalid); }
        let packet_hash=*blake3::hash(w3).as_bytes();
        self.ensure_w12_schema()?;
        let tx=self.db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let old:Option<(Vec<u8>,i64)>=tx.query_row(
            "SELECT digest,expiry FROM outbox WHERE recipient=?1 AND message=?2",
            params![req.recipient.as_slice(),req.message.as_slice()],
            |r|Ok((r.get(0)?,r.get(1)?)),
        ).optional()?;
        if let Some((old_hash,old_expiry))=old {
            if old_hash.as_slice()!=packet_hash || old_expiry != req.expiry_ms {
                return Err(CausalError::Conflict);
            }
            type Existing=(Vec<u8>,Vec<u8>,i64,Vec<u8>,Vec<u8>,Vec<u8>);
            let row:Option<Existing>=tx.query_row(
                "SELECT private_scope,custodian_id,seq,body,signature,commitment
                 FROM causal_w12_event WHERE recipient=?1 AND message=?2",
                params![req.recipient.as_slice(),req.message.as_slice()],
                |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?)),
            ).optional()?;
            let Some((scope,actor,seq,body,sig,commitment))=row else {
                // Do NOT manufacture a retroactive signing claim for older
                // noncausal Journal.enqueue records.
                return Err(CausalError::Conflict);
            };
            if scope!=req.private_scope || actor!=req.custodian_id || seq<=0
                || !body.starts_with(DOMAIN) || fixed32(&commitment)!=Ok(digest_of(&body,&sig))
            {return Err(CausalError::Conflict);}
            let sig=Signature::from_slice(&sig).map_err(|_|CausalError::Corrupt)?;
            signer.verifying_key().verify(&body,&sig)
                .map_err(|_|CausalError::Corrupt)?;
            tx.commit()?;
            return Ok(CausalCommitment{seq:seq as u64,digest:fixed32(&commitment)?});
        }

        let head:Option<(i64,Vec<u8>)>=tx.query_row(
            "SELECT seq,commitment FROM causal_w12_head
             WHERE private_scope=?1 AND custodian_id=?2",
            params![req.private_scope.as_slice(),req.custodian_id.as_slice()],
            |r|Ok((r.get(0)?,r.get(1)?)),
        ).optional()?;
        let (seq,prev)=match head {
            Some((n,p)) if n>0 && n<i64::MAX => (n+1,fixed32(&p)?),
            None=>(1,EMPTY),
            _=>return Err(CausalError::Corrupt),
        };
        let body=bytes(req,seq as u64,&prev,&packet_hash);
        let sig=signer.sign(&body).to_bytes();
        let commitment=digest_of(&body,&sig);
        tx.execute(
            "INSERT INTO outbox(recipient,message,digest,packet,expiry,status)
             VALUES(?1,?2,?3,?4,?5,0)",
            params![req.recipient.as_slice(),req.message.as_slice(),
                    packet_hash.as_slice(),w3,req.expiry_ms],
        )?;
        tx.execute(
            "INSERT INTO causal_w12_event
             (private_scope,custodian_id,custodian_epoch,seq,predecessor,
              recipient,message,packet_digest,body,signature,commitment)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            params![req.private_scope.as_slice(),req.custodian_id.as_slice(),
                req.custodian_epoch as i64,seq,prev.as_slice(),
                req.recipient.as_slice(),req.message.as_slice(),
                packet_hash.as_slice(),body,sig.as_slice(),commitment.as_slice()],
        )?;
        tx.execute(
            "INSERT INTO causal_w12_head
             (private_scope,custodian_id,seq,commitment)
             VALUES(?1,?2,?3,?4)
             ON CONFLICT(private_scope,custodian_id)
             DO UPDATE SET seq=excluded.seq,commitment=excluded.commitment",
            params![req.private_scope.as_slice(),req.custodian_id.as_slice(),
                seq,commitment.as_slice()],
        )?;

        // Intentionally crash the ACTUAL production-shaped transaction,
        // not a separate SQL reimplementation; only available to opt-in lab
        // feature and never a product build.
        #[cfg(feature="causal-lab-fault")]
        if std::env::var_os("LABO_W12_ABORT_BEFORE_COMMIT").is_some() {
            std::process::abort();
        }
        tx.commit()?;
        #[cfg(feature="causal-lab-fault")]
        if std::env::var_os("LABO_W12_ABORT_AFTER_COMMIT").is_some() {
            std::process::abort();
        }
        Ok(CausalCommitment{seq:seq as u64,digest:commitment})
    }

    /// Revalidate the local persisted chain and exact W3 ciphertext at read
    /// time. This check only detects errors visible in the local snapshot;
    /// external W10-like pins are still required to detect complete rollback.
    pub fn audit_w12(
        &self, scope: [u8;16], actor: [u8;16],
        trust: &TrustRegistry,
    ) -> Result<Option<CausalCommitment>,CausalError> {
        self.ensure_w12_schema()?;
        let mut stmt=self.db.prepare(
            "SELECT custodian_epoch,seq,predecessor,recipient,message,
                    packet_digest,body,signature,commitment
             FROM causal_w12_event WHERE private_scope=?1 AND custodian_id=?2
             ORDER BY seq ASC",
        )?;
        let mut rows=stmt.query(params![scope.as_slice(),actor.as_slice()])?;
        let mut expected_seq=1i64;
        let mut prev=EMPTY;
        while let Some(row)=rows.next()? {
            let epoch:i64=row.get(0)?;
            let seq:i64=row.get(1)?;
            let old:Vec<u8>=row.get(2)?;
            let recipient:Vec<u8>=row.get(3)?;
            let message:Vec<u8>=row.get(4)?;
            let packet_hash:Vec<u8>=row.get(5)?;
            let signed_body:Vec<u8>=row.get(6)?;
            let signature:Vec<u8>=row.get(7)?;
            let commitment:Vec<u8>=row.get(8)?;
            if epoch<=0||seq!=expected_seq||old!=prev
                ||recipient.len()!=16||message.len()!=16
                ||packet_hash.len()!=32
                ||signature.len()!=64
            {return Err(CausalError::Corrupt);}
            let req=CausalRequest {
                private_scope:scope,custodian_id:actor,
                custodian_epoch:epoch as u64,
                recipient:recipient.as_slice().try_into().map_err(|_|CausalError::Corrupt)?,
                message:message.as_slice().try_into().map_err(|_|CausalError::Corrupt)?,
                expiry_ms:1,
            };
            if bytes(req,seq as u64,&prev,&fixed32(&packet_hash)?)!=signed_body {
                return Err(CausalError::Corrupt);
            }
            let key=trust.key_for(actor,epoch as u64)
                .map_err(|_|CausalError::Unauthorized)?;
            let sig=Signature::from_slice(&signature).map_err(|_|CausalError::Corrupt)?;
            key.verify(&signed_body,&sig).map_err(|_|CausalError::Corrupt)?;
            if fixed32(&commitment)? != digest_of(&signed_body,&signature){
                return Err(CausalError::Corrupt);
            }
            let packet:Option<(Vec<u8>,Vec<u8>)>=self.db.query_row(
                "SELECT packet,digest FROM outbox WHERE recipient=?1 AND message=?2",
                params![recipient.as_slice(),message.as_slice()],
                |r|Ok((r.get(0)?,r.get(1)?)),
            ).optional()?;
            let Some((packet,dbhash))=packet else {return Err(CausalError::Corrupt)};
            if dbhash!=packet_hash || blake3::hash(&packet).as_bytes()!=packet_hash.as_slice() {
                return Err(CausalError::Corrupt);
            }
            prev=fixed32(&commitment)?;
            expected_seq+=1;
        }
        let head:Option<(i64,Vec<u8>)>=self.db.query_row(
            "SELECT seq,commitment FROM causal_w12_head
             WHERE private_scope=?1 AND custodian_id=?2",
            params![scope.as_slice(),actor.as_slice()],
            |r|Ok((r.get(0)?,r.get(1)?)),
        ).optional()?;
        match (head,expected_seq) {
            (None,1)=>Ok(None),
            (Some((seq,hash)),next) if seq==next-1 && hash==prev =>
                Ok(Some(CausalCommitment{seq:seq as u64,digest:prev})),
            _=>Err(CausalError::Corrupt),
        }
    }
}
