//! W8 research: durable one-slot custody transfer across *separate* SQLite
//! databases with no distributed transaction. An issued slot is never
//! automatically refunded after timeout, unknown ACK or process restart.
//!
//! A signed Offer and signed PeerAccepted are NOT a final recipient W4 and
//! NOT evidence that a malicious custodian actually retained data. Signed
//! source and target identities are per-link pseudonyms; do not broadcast
//! this protocol or the W3 public route hint as a mailbox read capability.
//!
//! This is an honest-ledger lab, not a global Byzantine copy-count guarantee.
//! Physical copying, independently rolled-back issuer snapshots and Sybil
//! operators remain outside the guaranteed invariant.
use crate::journal_w4::Journal;
use crate::private_route_w3;
use crate::trust_w3::TrustRegistry;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use std::path::Path;

const OFFER_DOMAIN: &[u8] = b"Akula/WOW/CustodyOffer/W8/Ed25519-v1\0";
const ACCEPT_DOMAIN: &[u8] = b"Akula/WOW/PeerAccepted/W8/Ed25519-v1\0";
const VERSION: u8 = 1;
const OFFER_BODY: usize = 121;
pub const OFFER_LEN: usize = OFFER_BODY + 64;
const ACCEPT_BODY: usize = 145;
pub const ACCEPT_LEN: usize = ACCEPT_BODY + 64;
pub const MAX_RECEIVER_ROWS: i64 = 256;

#[derive(Debug)]
pub enum TransferError {
    Db(rusqlite::Error),
    Invalid,
    Missing,
    Unauthorized,
    BadSignature,
    Expired,
    Conflict,
    ClockRollback,
    RecipientConfirmed,
}
impl From<rusqlite::Error> for TransferError {
    fn from(err:rusqlite::Error)->Self{Self::Db(err)}
}
#[derive(Debug,Clone,Copy,Eq,PartialEq)]
pub enum TransferPhase { Pending, Ambiguous, PeerClaimed, RecipientConfirmed }
impl TransferPhase {
    fn parse(n:i64)->Result<Self,TransferError>{
        match n {
            1=>Ok(Self::Pending),2=>Ok(Self::Ambiguous),
            3=>Ok(Self::PeerClaimed),4=>Ok(Self::RecipientConfirmed),
            _=>Err(TransferError::Conflict),
        }
    }
}
#[derive(Debug,Clone,Copy,Eq,PartialEq)]
pub struct TransferSnapshot {
    pub phase: TransferPhase,
    pub target: [u8;16],
    pub slot_alias: [u8;16],
    pub offer_id: [u8;16],
}

#[derive(Clone,Copy,Debug)]
pub struct OfferClaims {
    pub source_id:[u8;16],
    pub source_epoch:u64,
    pub target_id:[u8;16],
    pub target_epoch:u64,
    pub slot_alias:[u8;16],
    pub offer_id:[u8;16],
    pub ciphertext_digest:[u8;32],
    pub expires_at_ms:u64,
}
#[derive(Clone,Copy,Debug)]
pub struct Acceptance {
    pub source_id:[u8;16],
    pub target_id:[u8;16],
    pub target_epoch:u64,
    pub slot_alias:[u8;16],
    pub offer_id:[u8;16],
    pub ciphertext_digest:[u8;32],
    pub offer_digest:[u8;32],
    pub expires_at_ms:u64,
}
fn take16(bytes:&[u8])->[u8;16] {bytes.try_into().expect("fixed length checked")}
fn take32(bytes:&[u8])->[u8;32] {bytes.try_into().expect("fixed length checked")}
fn take64(bytes:&[u8])->u64{u64::from_be_bytes(bytes.try_into().expect("length checked"))}
fn is_nonzero(value:[u8;16])->bool{value != [0;16]}
fn sign(domain:&[u8],body:&[u8],key:&SigningKey)->Vec<u8>{
    let mut to_sign=Vec::with_capacity(domain.len()+body.len());
    to_sign.extend_from_slice(domain);
    to_sign.extend_from_slice(body);
    let mut out=body.to_vec();
    out.extend_from_slice(&key.sign(&to_sign).to_bytes());
    out
}
fn verify_signature(
    domain:&[u8],wire:&[u8],body_len:usize,
    signer_id:[u8;16],epoch:u64,trust:&TrustRegistry,
)->Result<(),TransferError>{
    let key=trust.key_for(signer_id,epoch)
        .map_err(|_|TransferError::Unauthorized)?;
    let sig=Signature::from_slice(&wire[body_len..])
        .map_err(|_|TransferError::BadSignature)?;
    let mut to_sign=Vec::with_capacity(domain.len()+body_len);
    to_sign.extend_from_slice(domain);
    to_sign.extend_from_slice(&wire[..body_len]);
    key.verify(&to_sign,&sig).map_err(|_|TransferError::BadSignature)
}
pub fn sign_offer(c:OfferClaims,signer:&SigningKey)->Result<Vec<u8>,TransferError>{
    if !is_nonzero(c.source_id)||!is_nonzero(c.target_id)
        || c.source_id==c.target_id || !is_nonzero(c.slot_alias)
        || !is_nonzero(c.offer_id) || c.source_epoch==0 || c.target_epoch==0
        || c.expires_at_ms==0 || c.expires_at_ms>i64::MAX as u64
    {return Err(TransferError::Invalid);}
    let mut body=Vec::with_capacity(OFFER_BODY);
    body.push(VERSION);
    body.extend_from_slice(&c.source_id);
    body.extend_from_slice(&c.source_epoch.to_be_bytes());
    body.extend_from_slice(&c.target_id);
    body.extend_from_slice(&c.target_epoch.to_be_bytes());
    body.extend_from_slice(&c.slot_alias);
    body.extend_from_slice(&c.offer_id);
    body.extend_from_slice(&c.ciphertext_digest);
    body.extend_from_slice(&c.expires_at_ms.to_be_bytes());
    debug_assert_eq!(body.len(),OFFER_BODY);
    Ok(sign(OFFER_DOMAIN,&body,signer))
}
pub fn verify_offer(wire:&[u8],trust:&TrustRegistry)->Result<OfferClaims,TransferError>{
    if wire.len()!=OFFER_LEN||wire[0]!=VERSION{return Err(TransferError::Invalid);}
    let claims=OfferClaims {
        source_id:take16(&wire[1..17]),
        source_epoch:take64(&wire[17..25]),
        target_id:take16(&wire[25..41]),
        target_epoch:take64(&wire[41..49]),
        slot_alias:take16(&wire[49..65]),
        offer_id:take16(&wire[65..81]),
        ciphertext_digest:take32(&wire[81..113]),
        expires_at_ms:take64(&wire[113..121]),
    };
    if !is_nonzero(claims.source_id)||!is_nonzero(claims.target_id)
        || claims.source_id==claims.target_id||!is_nonzero(claims.slot_alias)
        ||!is_nonzero(claims.offer_id)||claims.source_epoch==0
        ||claims.target_epoch==0||claims.expires_at_ms==0
        ||claims.expires_at_ms>i64::MAX as u64
    {return Err(TransferError::Invalid);}
    verify_signature(
        OFFER_DOMAIN,wire,OFFER_BODY,claims.source_id,claims.source_epoch,trust,
    )?;
    Ok(claims)
}
fn sign_acceptance(c:Acceptance,key:&SigningKey)->Vec<u8>{
    let mut body=Vec::with_capacity(ACCEPT_BODY);
    body.push(VERSION);
    body.extend_from_slice(&c.source_id);
    body.extend_from_slice(&c.target_id);
    body.extend_from_slice(&c.target_epoch.to_be_bytes());
    body.extend_from_slice(&c.slot_alias);
    body.extend_from_slice(&c.offer_id);
    body.extend_from_slice(&c.ciphertext_digest);
    body.extend_from_slice(&c.offer_digest);
    body.extend_from_slice(&c.expires_at_ms.to_be_bytes());
    debug_assert_eq!(body.len(),ACCEPT_BODY);
    sign(ACCEPT_DOMAIN,&body,key)
}
pub fn verify_acceptance(wire:&[u8],trust:&TrustRegistry)->Result<Acceptance,TransferError>{
    if wire.len()!=ACCEPT_LEN||wire[0]!=VERSION{return Err(TransferError::Invalid);}
    let claims=Acceptance {
        source_id:take16(&wire[1..17]),
        target_id:take16(&wire[17..33]),
        target_epoch:take64(&wire[33..41]),
        slot_alias:take16(&wire[41..57]),
        offer_id:take16(&wire[57..73]),
        ciphertext_digest:take32(&wire[73..105]),
        offer_digest:take32(&wire[105..137]),
        expires_at_ms:take64(&wire[137..145]),
    };
    if !is_nonzero(claims.source_id)||!is_nonzero(claims.target_id)
        ||!is_nonzero(claims.slot_alias)||!is_nonzero(claims.offer_id)
        ||claims.target_epoch==0
    {return Err(TransferError::Invalid);}
    verify_signature(
        ACCEPT_DOMAIN,wire,ACCEPT_BODY,claims.target_id,claims.target_epoch,trust,
    )?;
    Ok(claims)
}

// Use the SAME local SQLite file as the sender's multipath plan; the source
// reserve is already spent BEFORE a CustodyOffer can be signed and issued.
impl Journal {
    pub fn issue_custody_offer(
        &mut self, recipient:[u8;16],message:[u8;16],attempt_id:[u8;16],
        offer_id:[u8;16],source_id:[u8;16],source_epoch:u64,
        target_id:[u8;16],target_epoch:u64,now_ms:i64,
        signer:&SigningKey,trust:&TrustRegistry,
    )->Result<Vec<u8>,TransferError>{
        if !is_nonzero(offer_id)||!is_nonzero(attempt_id)||now_ms<0{
            return Err(TransferError::Invalid);
        }
        let key=trust.key_for(source_id,source_epoch)
            .map_err(|_|TransferError::Unauthorized)?;
        if key != &signer.verifying_key(){return Err(TransferError::Unauthorized);}
        let tx=self.db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        type PlanRow=(Vec<u8>,Vec<u8>,Vec<u8>,Vec<u8>,i64,i64,i64,i64);
        let row:Option<PlanRow>=tx.query_row(
            "SELECT a.alias,a.peer,o.packet,o.digest,o.expiry,o.status,p.stopped,p.last_now
             FROM multipath_attempt a
             JOIN multipath_plan p ON p.recipient=a.recipient AND p.message=a.message
             JOIN outbox o ON o.recipient=a.recipient AND o.message=a.message
             WHERE a.recipient=?1 AND a.message=?2 AND a.attempt=?3",
            params![recipient.as_slice(),message.as_slice(),attempt_id.as_slice()],
            |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?)),
        ).optional()?;
        let (alias,peer,packet,digest,expiry,status,stopped,last_now)=row.ok_or(TransferError::Missing)?;
        if stopped!=0||status==4{return Err(TransferError::RecipientConfirmed);}
        if now_ms<last_now{return Err(TransferError::ClockRollback);}
        if now_ms>=expiry{return Err(TransferError::Expired);}
        if peer.as_slice()!=target_id{return Err(TransferError::Conflict);}
        if digest!=blake3::hash(&packet).as_bytes() {return Err(TransferError::Conflict);}
        let hint=private_route_w3::inspect_route(&packet)
            .map_err(|_|TransferError::Invalid)?;
        if hint.message_id != message{return Err(TransferError::Invalid);}
        let alias=take16(&alias);
        let offered=sign_offer(OfferClaims {
            source_id,source_epoch,target_id,target_epoch,
            slot_alias:alias,offer_id,ciphertext_digest:*blake3::hash(&packet).as_bytes(),
            expires_at_ms:expiry as u64,
        },signer)?;
        let previous:Option<(Vec<u8>,Vec<u8>)>=tx.query_row(
            "SELECT offer_id,offer FROM custody_transfer_source
             WHERE recipient=?1 AND message=?2 AND slot_alias=?3",
            params![recipient.as_slice(),message.as_slice(),alias.as_slice()],
            |r|Ok((r.get(0)?,r.get(1)?)),
        ).optional()?;
        if let Some((old_id,old_offer))=previous {
            if old_id!=offer_id || old_offer!=offered{return Err(TransferError::Conflict);}
            tx.execute(
                "UPDATE multipath_plan SET last_now=?3
                 WHERE recipient=?1 AND message=?2",
                params![recipient.as_slice(),message.as_slice(),now_ms],
            )?;
            tx.commit()?;
            return Ok(offered);
        }
        tx.execute(
            "INSERT INTO custody_transfer_source
               (recipient,message,slot_alias,offer_id,target,offer,phase)
             VALUES (?1,?2,?3,?4,?5,?6,1)",
            params![recipient.as_slice(),message.as_slice(),alias.as_slice(),
                    offer_id.as_slice(),target_id.as_slice(),&offered],
        )?;
        tx.execute(
            "UPDATE multipath_plan SET last_now=?3 WHERE recipient=?1 AND message=?2",
            params![recipient.as_slice(),message.as_slice(),now_ms],
        )?;
        tx.commit()?;
        Ok(offered)
    }

    /// A lost ACK means Ambiguous, NEVER "the neighbor did not receive".
    /// This state does not refund the local route slot.
    pub fn mark_custody_ambiguous(
        &mut self,offer_id:[u8;16],
    )->Result<TransferPhase,TransferError>{
        let tx=self.db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let phase:Option<i64>=tx.query_row(
            "SELECT phase FROM custody_transfer_source WHERE offer_id=?1",
            params![offer_id.as_slice()],|r|r.get(0),
        ).optional()?;
        let phase=TransferPhase::parse(phase.ok_or(TransferError::Missing)?)?;
        if phase==TransferPhase::Pending {
            tx.execute("UPDATE custody_transfer_source SET phase=2 WHERE offer_id=?1",
                params![offer_id.as_slice()])?;
        }
        tx.commit()?;
        Ok(if phase==TransferPhase::Pending{TransferPhase::Ambiguous}else{phase})
    }

    /// Accept only a proof from exactly the peer to which this slot was
    /// durably issued. This is a peer's CLAIM of durable write, not recipient W4.
    pub fn accept_peer_custody_claim(
        &mut self,wire:&[u8],trust:&TrustRegistry,
    )->Result<TransferPhase,TransferError>{
        let receipt=verify_acceptance(wire,trust)?;
        let tx=self.db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let saved:Option<(Vec<u8>,Vec<u8>,i64)>=tx.query_row(
            "SELECT offer,target,phase FROM custody_transfer_source WHERE offer_id=?1",
            params![receipt.offer_id.as_slice()],
            |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)),
        ).optional()?;
        let (signed_offer,target,old_phase)=saved.ok_or(TransferError::Missing)?;
        let offered=verify_offer(&signed_offer,trust)?;
        if target.as_slice()!=receipt.target_id
            ||offered.source_id!=receipt.source_id||offered.target_id!=receipt.target_id
            ||offered.target_epoch!=receipt.target_epoch
            ||offered.slot_alias!=receipt.slot_alias
            ||offered.offer_id!=receipt.offer_id
            ||offered.ciphertext_digest!=receipt.ciphertext_digest
            ||offered.expires_at_ms!=receipt.expires_at_ms
            ||*blake3::hash(&signed_offer).as_bytes()!=receipt.offer_digest
        {return Err(TransferError::Conflict);}
        let phase=TransferPhase::parse(old_phase)?;
        if phase==TransferPhase::RecipientConfirmed{return Ok(phase);}
        if phase!=TransferPhase::PeerClaimed {
            tx.execute(
                "UPDATE custody_transfer_source SET phase=3,acceptance=?2
                 WHERE offer_id=?1",
                params![receipt.offer_id.as_slice(),wire],
            )?;
        }
        tx.commit()?;
        Ok(TransferPhase::PeerClaimed)
    }

    pub fn custody_transfer_snapshot(
        &self,offer_id:[u8;16],
    )->Result<TransferSnapshot,TransferError>{
        let row:Option<(Vec<u8>,Vec<u8>,Vec<u8>,i64)>=self.db.query_row(
            "SELECT target,slot_alias,offer_id,phase
             FROM custody_transfer_source WHERE offer_id=?1",
            params![offer_id.as_slice()],
            |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)),
        ).optional()?;
        let (target,slot,offer,phase)=row.ok_or(TransferError::Missing)?;
        Ok(TransferSnapshot {
            target:take16(&target),slot_alias:take16(&slot),
            offer_id:take16(&offer),phase:TransferPhase::parse(phase)?,
        })
    }
}

/// Independent peer custodian: its own SQLite with WAL+FULL and UNIQUE slots.
/// This cannot atomically commit a sender's separate SQLite ledger.
pub struct PeerCustodyStore { db:Connection }
impl PeerCustodyStore {
    pub fn open(path:&Path)->Result<Self,TransferError>{
        let db=Connection::open(path)?;
        db.busy_timeout(std::time::Duration::from_secs(5))?;
        db.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
             CREATE TABLE IF NOT EXISTS custody_inbox(
               offer_id BLOB PRIMARY KEY CHECK(length(offer_id)=16),
               source BLOB NOT NULL CHECK(length(source)=16),
               slot_alias BLOB NOT NULL CHECK(length(slot_alias)=16),
               exact_offer BLOB NOT NULL CHECK(length(exact_offer)=185),
               digest BLOB NOT NULL CHECK(length(digest)=32),
               packet BLOB NOT NULL CHECK(length(packet) BETWEEN 1 AND 16384),
               acceptance BLOB NOT NULL CHECK(length(acceptance)=209),
               UNIQUE(source,slot_alias)
             );
             CREATE TABLE IF NOT EXISTS custody_clock(
               singleton INTEGER PRIMARY KEY CHECK(singleton=1),
               last_now INTEGER NOT NULL CHECK(last_now>=0)
             );
             INSERT OR IGNORE INTO custody_clock(singleton,last_now) VALUES(1,0);"
        )?;
        Ok(Self{db})
    }

    pub fn accept(
        &mut self,wire:&[u8],exact_w3:&[u8],
        expected_source:[u8;16],target_id:[u8;16],target_epoch:u64,
        signer:&SigningKey,trust:&TrustRegistry,now_ms:i64,
    )->Result<Vec<u8>,TransferError>{
        if now_ms<0 || exact_w3.is_empty()||exact_w3.len()>crate::MAX_MESSAGE_BYTES
            ||!is_nonzero(expected_source)||!is_nonzero(target_id)
        {return Err(TransferError::Invalid);}
        let offer=verify_offer(wire,trust)?;
        if offer.source_id!=expected_source || offer.target_id!=target_id
            ||offer.target_epoch!=target_epoch
        {return Err(TransferError::Unauthorized);}
        let own=trust.key_for(target_id,target_epoch)
            .map_err(|_|TransferError::Unauthorized)?;
        if own!=&signer.verifying_key(){return Err(TransferError::Unauthorized);}
        if (now_ms as u64)>=offer.expires_at_ms{return Err(TransferError::Expired);}
        if *blake3::hash(exact_w3).as_bytes()!=offer.ciphertext_digest
        {return Err(TransferError::Conflict);}
        let hint=private_route_w3::inspect_route(exact_w3)
            .map_err(|_|TransferError::Invalid)?;
        if hint.message_id==[0;16]{return Err(TransferError::Invalid);}
        let tx=self.db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let previous_now:i64=tx.query_row(
            "SELECT last_now FROM custody_clock WHERE singleton=1",[],
            |r|r.get(0),
        )?;
        if now_ms<previous_now{return Err(TransferError::ClockRollback);}
        let existing:Option<(Vec<u8>,Vec<u8>,Vec<u8>)>=tx.query_row(
            "SELECT exact_offer,packet,acceptance FROM custody_inbox WHERE offer_id=?1",
            params![offer.offer_id.as_slice()],
            |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)),
        ).optional()?;
        if let Some((old_offer,old_packet,receipt))=existing {
            if old_offer!=wire || old_packet!=exact_w3{return Err(TransferError::Conflict);}
            tx.execute("UPDATE custody_clock SET last_now=?1 WHERE singleton=1",
                params![now_ms])?;
            tx.commit()?;
            return Ok(receipt);
        }
        let used:i64=tx.query_row("SELECT COUNT(*) FROM custody_inbox",[],|r|r.get(0))?;
        if used>=MAX_RECEIVER_ROWS{return Err(TransferError::Invalid);}
        let signed=sign_acceptance(Acceptance {
            source_id:offer.source_id,target_id,target_epoch,
            slot_alias:offer.slot_alias,offer_id:offer.offer_id,
            ciphertext_digest:offer.ciphertext_digest,
            offer_digest:*blake3::hash(wire).as_bytes(),
            expires_at_ms:offer.expires_at_ms,
        },signer);
        tx.execute(
            "INSERT INTO custody_inbox
                (offer_id,source,slot_alias,exact_offer,digest,packet,acceptance)
             VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![offer.offer_id.as_slice(),offer.source_id.as_slice(),
                    offer.slot_alias.as_slice(),wire,offer.ciphertext_digest.as_slice(),
                    exact_w3,&signed],
        )?;
        tx.execute("UPDATE custody_clock SET last_now=?1 WHERE singleton=1",
            params![now_ms])?;
        tx.commit()?;
        Ok(signed)
    }
}
