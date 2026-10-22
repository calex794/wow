//! W9 experimental *independent* witness for W8 single-slot CustodyOffer.
//!
//! Signed checkpoint chains and two issuer-signed conflicting offers create
//! portable evidence of *observed* equivocation. They do not forbid a
//! malicious issuer, a colluding/rollback witness, or an unobserved fork.
//!
//! W8 offers contain per-link pseudonyms, targets and a W3 ciphertext digest.
//! The witness locally sees and durably stores the full signed offers: NEVER
//! publish that database, raw conflict evidence or the checkpoint stream as
//! a global social graph. Public checkpoint bodies contain only commitments.
//!
//! NOT RFC 9162 Certificate Transparency: this is a linear hash-chain lab,
//! with adjacent-checkpoint comparisons only (no Merkle consistency proofs).
use crate::custody_transfer_w8::{
    self, PeerConsent, PeerCustodyStore, TransferError, OFFER_LEN,
};
use crate::trust_w3::TrustRegistry;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use std::path::Path;

const SLOT_DOMAIN: &[u8] = b"Akula/WOW/W9/slot-commitment/v1\0";
const CHAIN_DOMAIN: &[u8] = b"Akula/WOW/W9/chain-head/v1\0";
const SIGN_DOMAIN: &[u8] = b"Akula/WOW/W9/witness-checkpoint/Ed25519-v1\0";
const VERSION: u8 = 1;
const HEAD_OFFSET: usize = 130;
const BODY_LEN: usize = HEAD_OFFSET + 32;
pub const CHECKPOINT_LEN: usize = BODY_LEN + 64;
const MAX_CHECKPOINTS: u64 = 1024;

#[derive(Debug)]
pub enum WitnessError {
    Db(rusqlite::Error),
    Transfer(TransferError),
    Invalid,
    WrongWitness,
    UntrustedWitness,
    InvalidSignature,
    InvalidHead,
    WrongOffer,
    Forked,
    Limit,
}
impl From<rusqlite::Error> for WitnessError {
    fn from(e:rusqlite::Error)->Self {Self::Db(e)}
}
impl From<TransferError> for WitnessError {
    fn from(e:TransferError)->Self {Self::Transfer(e)}
}

#[derive(Clone,Copy,Debug,Eq,PartialEq)]
#[repr(u8)]
pub enum Verdict { FirstSeen=1, ConflictObserved=2 }
impl Verdict {
    fn decode(v:u8)->Result<Self,WitnessError>{
        match v {
            1=>Ok(Self::FirstSeen),2=>Ok(Self::ConflictObserved),
            _=>Err(WitnessError::Invalid),
        }
    }
}
#[derive(Clone,Copy,Debug,Eq,PartialEq)]
pub struct VerifiedCheckpoint {
    pub witness_id:[u8;16],
    pub witness_epoch:u64,
    pub sequence:u64,
    pub verdict:Verdict,
    pub slot_commitment:[u8;32],
    pub offer_digest:[u8;32],
    pub previous_head:[u8;32],
    pub head:[u8;32],
}
#[derive(Debug,Clone,Copy,Eq,PartialEq)]
pub enum ChainRelation {
    Same,
    Adjacent,
    /// Two signed checkpoints at the same sequence or adjacent incompatible
    /// histories: proof of a witness fork IF both signatures are valid.
    Equivocation,
    /// A newly offered checkpoint is older than a locally pinned value.
    RollbackSuspected,
    /// We lack intermediate receipts; never assume unproven continuity.
    MissingHistory,
}
#[derive(Debug,Clone)]
pub struct ForkEvidence {
    pub first_offer:Vec<u8>,
    pub conflicting_offer:Vec<u8>,
    pub first_checkpoint:Vec<u8>,
    pub conflict_checkpoint:Vec<u8>,
}
#[derive(Debug)]
pub enum WitnessObservation {
    FirstSeen(Vec<u8>),
    Conflict(ForkEvidence),
}
fn arr16(bytes:&[u8])->[u8;16]{bytes.try_into().expect("checked size")}
fn arr32(bytes:&[u8])->[u8;32]{bytes.try_into().expect("checked size")}
fn u64be(bytes:&[u8])->u64{u64::from_be_bytes(bytes.try_into().expect("checked size"))}
fn commit_slot(source_id:[u8;16],slot_alias:[u8;16])->[u8;32]{
    let mut h=blake3::Hasher::new();
    h.update(SLOT_DOMAIN);
    h.update(&source_id);
    h.update(&slot_alias);
    *h.finalize().as_bytes()
}
fn chain_head(prefix:&[u8])->[u8;32]{
    let mut h=blake3::Hasher::new();
    h.update(CHAIN_DOMAIN);
    h.update(prefix);
    *h.finalize().as_bytes()
}
fn signer_is_trusted(
    id:[u8;16],epoch:u64,signer:&SigningKey,trust:&TrustRegistry,
)->Result<(),WitnessError>{
    if id==[0;16]||epoch==0{return Err(WitnessError::Invalid);}
    let enrolled=trust.key_for(id,epoch)
        .map_err(|_|WitnessError::UntrustedWitness)?;
    if enrolled!=&signer.verifying_key(){return Err(WitnessError::UntrustedWitness);}
    Ok(())
}
struct CheckpointClaims {
    id:[u8;16],
    epoch:u64,
    sequence:u64,
    verdict:Verdict,
    slot:[u8;32],
    digest:[u8;32],
    prior:[u8;32],
}
type StoredWitnessRow=(Vec<u8>,Vec<u8>,Option<Vec<u8>>,Option<Vec<u8>>);

fn sign_checkpoint(claims:CheckpointClaims,signer:&SigningKey)->Vec<u8>{
    let CheckpointClaims {
        id,epoch,sequence,verdict,slot,digest,prior,
    }=claims;
    let mut body=Vec::with_capacity(CHECKPOINT_LEN);
    body.push(VERSION);
    body.extend_from_slice(&id);
    body.extend_from_slice(&epoch.to_be_bytes());
    body.extend_from_slice(&sequence.to_be_bytes());
    body.push(verdict as u8);
    body.extend_from_slice(&slot);
    body.extend_from_slice(&digest);
    body.extend_from_slice(&prior);
    debug_assert_eq!(body.len(),HEAD_OFFSET);
    let head=chain_head(&body);
    body.extend_from_slice(&head);
    let mut to_sign=Vec::with_capacity(SIGN_DOMAIN.len()+BODY_LEN);
    to_sign.extend_from_slice(SIGN_DOMAIN);
    to_sign.extend_from_slice(&body);
    body.extend_from_slice(&signer.sign(&to_sign).to_bytes());
    body
}
pub fn verify_checkpoint(
    raw:&[u8],expected_witness:[u8;16],trust:&TrustRegistry,
)->Result<VerifiedCheckpoint,WitnessError>{
    if raw.len()!=CHECKPOINT_LEN||raw[0]!=VERSION{return Err(WitnessError::Invalid);}
    let witness_id=arr16(&raw[1..17]);
    let witness_epoch=u64be(&raw[17..25]);
    let sequence=u64be(&raw[25..33]);
    if witness_id!=expected_witness||witness_id==[0;16]
        ||witness_epoch==0||sequence==0
    {return Err(WitnessError::WrongWitness);}
    let verdict=Verdict::decode(raw[33])?;
    let slot_commitment=arr32(&raw[34..66]);
    let offer_digest=arr32(&raw[66..98]);
    let previous_head=arr32(&raw[98..130]);
    let head=arr32(&raw[130..162]);
    if chain_head(&raw[..HEAD_OFFSET])!=head{
        return Err(WitnessError::InvalidHead);
    }
    let key=trust.key_for(witness_id,witness_epoch)
        .map_err(|_|WitnessError::UntrustedWitness)?;
    let signature=Signature::from_slice(&raw[BODY_LEN..])
        .map_err(|_|WitnessError::InvalidSignature)?;
    let mut signed=Vec::with_capacity(SIGN_DOMAIN.len()+BODY_LEN);
    signed.extend_from_slice(SIGN_DOMAIN);
    signed.extend_from_slice(&raw[..BODY_LEN]);
    key.verify(&signed,&signature).map_err(|_|WitnessError::InvalidSignature)?;
    Ok(VerifiedCheckpoint {
        witness_id,witness_epoch,sequence,verdict,
        slot_commitment,offer_digest,previous_head,head,
    })
}
pub fn compare_checkpoints(
    known:&[u8],received:&[u8],expected_witness:[u8;16],
    trust:&TrustRegistry,
)->Result<ChainRelation,WitnessError>{
    let a=verify_checkpoint(known,expected_witness,trust)?;
    let b=verify_checkpoint(received,expected_witness,trust)?;
    if a.witness_epoch!=b.witness_epoch{return Err(WitnessError::WrongWitness);}
    if a.sequence==b.sequence{
        return Ok(if a.head==b.head {
            ChainRelation::Same
        }else{ChainRelation::Equivocation});
    }
    if b.sequence<a.sequence{return Ok(ChainRelation::RollbackSuspected);}
    if b.sequence!=a.sequence+1{return Ok(ChainRelation::MissingHistory);}
    Ok(if b.previous_head==a.head {
        ChainRelation::Adjacent
    }else{ChainRelation::Equivocation})
}

/// Independently verifiable proof that one issuer signed two distinct W8
/// offers for the same (pseudonymous issuer, one-time slot_alias).
/// Raw evidence MUST stay private: it discloses both target pseudonyms.
pub fn verify_fork(
    evidence:&ForkEvidence,expected_witness:[u8;16],
    trust:&TrustRegistry,
)->Result<(),WitnessError>{
    let a=custody_transfer_w8::verify_offer(&evidence.first_offer,trust)?;
    let b=custody_transfer_w8::verify_offer(&evidence.conflicting_offer,trust)?;
    if a.source_id!=b.source_id||a.slot_alias!=b.slot_alias
        ||evidence.first_offer==evidence.conflicting_offer
    {return Err(WitnessError::WrongOffer);}
    let first=verify_checkpoint(&evidence.first_checkpoint,expected_witness,trust)?;
    let conflict=verify_checkpoint(&evidence.conflict_checkpoint,expected_witness,trust)?;
    let slot=commit_slot(a.source_id,a.slot_alias);
    if first.verdict!=Verdict::FirstSeen||conflict.verdict!=Verdict::ConflictObserved
        ||first.slot_commitment!=slot||conflict.slot_commitment!=slot
        ||first.offer_digest!=*blake3::hash(&evidence.first_offer).as_bytes()
        ||conflict.offer_digest!=*blake3::hash(&evidence.conflicting_offer).as_bytes()
        ||first.sequence>=conflict.sequence
        ||first.witness_epoch!=conflict.witness_epoch
    {return Err(WitnessError::WrongOffer);}
    if conflict.sequence==first.sequence+1
        && conflict.previous_head!=first.head
    {return Err(WitnessError::InvalidHead);}
    Ok(())
}

/// This proves ONLY that a trusted witness signed "first seen" *at that
/// historical time*. It does NOT prove no subsequent fork, current storage,
/// or that a malicious target will honor the witness. Require fresh audit
/// and independent endpoint policy for higher-risk uses.
pub fn verify_first_seen(
    offer:&[u8],checkpoint:&[u8],expected_witness:[u8;16],
    trust:&TrustRegistry,
)->Result<VerifiedCheckpoint,WitnessError>{
    let claims=custody_transfer_w8::verify_offer(offer,trust)?;
    let proof=verify_checkpoint(checkpoint,expected_witness,trust)?;
    if proof.verdict!=Verdict::FirstSeen
        ||proof.slot_commitment!=commit_slot(claims.source_id,claims.slot_alias)
        ||proof.offer_digest!=*blake3::hash(offer).as_bytes()
    {return Err(WitnessError::WrongOffer);}
    Ok(proof)
}

/// Additional optional gate for an HONEST peer. An untrusted custodian can
/// ignore this API; an old signed first-seen checkpoint may become stale.
pub fn accept_witnessed(
    store:&mut PeerCustodyStore,offer:&[u8],packet:&[u8],
    consent:PeerConsent<'_>,checkpoint:&[u8],witness_id:[u8;16],
)->Result<Vec<u8>,WitnessError>{
    verify_first_seen(offer,checkpoint,witness_id,consent.trust)?;
    store.accept(offer,packet,consent).map_err(Into::into)
}

pub struct WitnessStore {
    db:Connection,
    id:[u8;16],
    epoch:u64,
}
impl WitnessStore {
    pub fn open(path:&Path,id:[u8;16],epoch:u64)->Result<Self,WitnessError>{
        if id==[0;16]||epoch==0||epoch>i64::MAX as u64{
            return Err(WitnessError::Invalid);
        }
        let db=Connection::open(path)?;
        db.busy_timeout(std::time::Duration::from_secs(5))?;
        db.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
             CREATE TABLE IF NOT EXISTS witness_state(
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                witness_id BLOB NOT NULL CHECK(length(witness_id)=16),
                epoch INTEGER NOT NULL CHECK(epoch>0),
                latest_seq INTEGER NOT NULL CHECK(latest_seq>=0),
                head BLOB NOT NULL CHECK(length(head)=32)
             );
             CREATE TABLE IF NOT EXISTS witness_slots(
                slot BLOB PRIMARY KEY CHECK(length(slot)=32),
                first_offer BLOB NOT NULL CHECK(length(first_offer)=185),
                first_checkpoint BLOB NOT NULL CHECK(length(first_checkpoint)=226),
                conflicting_offer BLOB CHECK(conflicting_offer IS NULL OR length(conflicting_offer)=185),
                conflicting_checkpoint BLOB CHECK(conflicting_checkpoint IS NULL OR length(conflicting_checkpoint)=226)
             );
             CREATE TABLE IF NOT EXISTS witness_events(
                seq INTEGER PRIMARY KEY CHECK(seq>0),
                slot BLOB NOT NULL CHECK(length(slot)=32),
                digest BLOB NOT NULL CHECK(length(digest)=32),
                verdict INTEGER NOT NULL CHECK(verdict IN (1,2)),
                prior BLOB NOT NULL CHECK(length(prior)=32),
                head BLOB NOT NULL CHECK(length(head)=32),
                signed_checkpoint BLOB NOT NULL CHECK(length(signed_checkpoint)=226)
             );"
        )?;
        db.execute(
            "INSERT OR IGNORE INTO witness_state(singleton,witness_id,epoch,latest_seq,head)
             VALUES(1,?1,?2,0,?3)",
            params![id.as_slice(),epoch as i64,[0u8;32].as_slice()],
        )?;
        let (stored_id,stored_epoch):(Vec<u8>,i64)=db.query_row(
            "SELECT witness_id,epoch FROM witness_state WHERE singleton=1",[],
            |r|Ok((r.get(0)?,r.get(1)?)),
        )?;
        if stored_id.as_slice()!=id||stored_epoch!=epoch as i64{
            return Err(WitnessError::WrongWitness);
        }
        Ok(Self{db,id,epoch})
    }

    fn append(
        tx:&Transaction<'_>,id:[u8;16],epoch:u64,
        slot:[u8;32],offer:&[u8],verdict:Verdict,signer:&SigningKey,
    )->Result<Vec<u8>,WitnessError>{
        let (last,prior):(i64,Vec<u8>)=tx.query_row(
            "SELECT latest_seq,head FROM witness_state WHERE singleton=1",[],
            |r|Ok((r.get(0)?,r.get(1)?)),
        )?;
        if last<0||last>=MAX_CHECKPOINTS as i64{return Err(WitnessError::Limit);}
        let prior=arr32(&prior);
        let seq=(last as u64)+1;
        let digest=*blake3::hash(offer).as_bytes();
        let receipt=sign_checkpoint(CheckpointClaims {
            id,epoch,sequence:seq,verdict,slot,digest,prior,
        },signer);
        let next=arr32(&receipt[HEAD_OFFSET..BODY_LEN]);
        tx.execute(
            "INSERT INTO witness_events(seq,slot,digest,verdict,prior,head,signed_checkpoint)
             VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![seq as i64,slot.as_slice(),digest.as_slice(),verdict as u8,
                    prior.as_slice(),next.as_slice(),&receipt],
        )?;
        tx.execute(
            "UPDATE witness_state SET latest_seq=?1,head=?2 WHERE singleton=1",
            params![seq as i64,next.as_slice()],
        )?;
        Ok(receipt)
    }

    /// Durably append a signed first-seen witness claim or preserve the pair
    /// of issuer-signed conflicting offers. Retried identical requests do not
    /// append new checkpoints. A third fork is bounded: existing evidence is
    /// retained rather than growing an untrusted storage flood.
    pub fn observe(
        &mut self,offer:&[u8],signer:&SigningKey,trust:&TrustRegistry,
    )->Result<WitnessObservation,WitnessError>{
        signer_is_trusted(self.id,self.epoch,signer,trust)?;
        let claims=custody_transfer_w8::verify_offer(offer,trust)?;
        if offer.len()!=OFFER_LEN{return Err(WitnessError::Invalid);}
        let slot=commit_slot(claims.source_id,claims.slot_alias);
        let tx=self.db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing:Option<StoredWitnessRow>=tx.query_row(
            "SELECT first_offer,first_checkpoint,conflicting_offer,conflicting_checkpoint
             FROM witness_slots WHERE slot=?1",
            params![slot.as_slice()],
            |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)),
        ).optional()?;
        if let Some((first,first_checkpoint,second,second_checkpoint))=existing{
            if let (Some(second),Some(second_checkpoint))=(second,second_checkpoint){
                tx.commit()?;
                return Ok(WitnessObservation::Conflict(ForkEvidence {
                    first_offer:first,conflicting_offer:second,
                    first_checkpoint,conflict_checkpoint:second_checkpoint,
                }));
            }
            if first==offer{
                tx.commit()?;
                return Ok(WitnessObservation::FirstSeen(first_checkpoint));
            }
            let conflict=Self::append(
                &tx,self.id,self.epoch,slot,offer,Verdict::ConflictObserved,signer,
            )?;
            tx.execute(
                "UPDATE witness_slots SET conflicting_offer=?2,conflicting_checkpoint=?3
                 WHERE slot=?1",
                params![slot.as_slice(),offer,&conflict],
            )?;
            tx.commit()?;
            return Ok(WitnessObservation::Conflict(ForkEvidence {
                first_offer:first,conflicting_offer:offer.to_vec(),
                first_checkpoint,conflict_checkpoint:conflict,
            }));
        }
        let signed=Self::append(
            &tx,self.id,self.epoch,slot,offer,Verdict::FirstSeen,signer,
        )?;
        tx.execute(
            "INSERT INTO witness_slots(slot,first_offer,first_checkpoint)
             VALUES(?1,?2,?3)",
            params![slot.as_slice(),offer,&signed],
        )?;
        tx.commit()?;
        Ok(WitnessObservation::FirstSeen(signed))
    }

    pub fn checkpoint(&self)->Result<Option<Vec<u8>>,WitnessError>{
        self.db.query_row(
            "SELECT signed_checkpoint FROM witness_events ORDER BY seq DESC LIMIT 1",
            [],|r|r.get(0),
        ).optional().map_err(Into::into)
    }

    /// Raw offers and evidence stay on the local witness device, not public
    /// global consensus. A real service needs authenticated, private egress.
    pub fn conflicting_evidence(
        &self,source_id:[u8;16],slot_alias:[u8;16],
    )->Result<Option<ForkEvidence>,WitnessError>{
        let slot=commit_slot(source_id,slot_alias);
        let row:Option<StoredWitnessRow>=
            self.db.query_row(
                "SELECT first_offer,first_checkpoint,conflicting_offer,conflicting_checkpoint
                 FROM witness_slots WHERE slot=?1",
                params![slot.as_slice()],
                |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)),
            ).optional()?;
        Ok(row.and_then(|(first,first_checkpoint,second,second_checkpoint)|{
            Some(ForkEvidence {
                first_offer:first,
                conflicting_offer:second?,
                first_checkpoint,
                conflict_checkpoint:second_checkpoint?,
            })
        }))
    }
}
