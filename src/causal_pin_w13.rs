//! W13 independent pin of a W12 causal head. A pin is a private local
//! observation, NOT proof that a malicious custodian ever stored W3 bytes.
//! The database MUST live independently of the custodian SQLite to detect
//! rollback of that database. Never publicize scope or hashes.
use crate::causal_w12::{CausalCommitment, verify_w12_signed_claim};
use crate::trust_w3::TrustRegistry;
use rusqlite::{Connection,OptionalExtension,params,TransactionBehavior};
use std::path::Path;
#[derive(Debug)]
pub enum PinError {Db(rusqlite::Error),Invalid,Rollback,Conflict,Frozen,Missing}
impl From<rusqlite::Error> for PinError{fn from(v:rusqlite::Error)->Self{Self::Db(v)}}
#[derive(Debug,PartialEq,Eq)]
pub enum Check {NoPin,Match,Rollback,Conflict}
pub struct ExternalCausalPin{db:Connection}
impl ExternalCausalPin{
 pub fn open(path:&Path)->Result<Self,PinError>{
  let db=Connection::open(path)?;
  db.busy_timeout(std::time::Duration::from_secs(5))?;
  db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
   CREATE TABLE IF NOT EXISTS causal_pin(
    private_scope BLOB NOT NULL CHECK(length(private_scope)=16),
    custodian BLOB NOT NULL CHECK(length(custodian)=16),
    seq INTEGER NOT NULL CHECK(seq>0),
    digest BLOB NOT NULL CHECK(length(digest)=32),
    frozen INTEGER NOT NULL DEFAULT 0 CHECK(frozen IN (0,1)),
    PRIMARY KEY(private_scope,custodian));")?;
  Ok(Self{db})
 }
 pub fn pin_observed(&mut self,scope:[u8;16],actor:[u8;16],observed:CausalCommitment)->Result<(),PinError>{
  if scope==[0;16]||actor==[0;16]||observed.seq==0||observed.seq>i64::MAX as u64{return Err(PinError::Invalid)}
  let tx=self.db.transaction_with_behavior(TransactionBehavior::Immediate)?;
  let prev:Option<(i64,Vec<u8>,i64)>=tx.query_row(
   "SELECT seq,digest,frozen FROM causal_pin WHERE private_scope=?1 AND custodian=?2",
   params![scope.as_slice(),actor.as_slice()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
  match prev {
   Some((_,_,1))=>return Err(PinError::Frozen),
   Some((seq,_,_)) if observed.seq < seq as u64=>return Err(PinError::Rollback),
   Some((seq,d,_)) if observed.seq==seq as u64 && d.as_slice()!=observed.digest.as_slice()=> {
      tx.execute("UPDATE causal_pin SET frozen=1 WHERE private_scope=?1 AND custodian=?2",params![scope.as_slice(),actor.as_slice()])?;
      tx.commit()?;return Err(PinError::Conflict)
   }
   Some((seq,d,_)) if observed.seq==seq as u64&&d.as_slice()==observed.digest.as_slice()=>return Ok(()),
   _=>{}
  }
  tx.execute("INSERT INTO causal_pin(private_scope,custodian,seq,digest,frozen)
   VALUES(?1,?2,?3,?4,0) ON CONFLICT(private_scope,custodian)
   DO UPDATE SET seq=excluded.seq,digest=excluded.digest",
    params![scope.as_slice(),actor.as_slice(),observed.seq as i64,observed.digest.as_slice()])?;
  tx.commit()?;Ok(())
 }
 pub fn compare(&self,scope:[u8;16],actor:[u8;16],actual:Option<CausalCommitment>)->Result<Check,PinError>{
  let pin:Option<(i64,Vec<u8>,i64)>=self.db.query_row(
   "SELECT seq,digest,frozen FROM causal_pin WHERE private_scope=?1 AND custodian=?2",
   params![scope.as_slice(),actor.as_slice()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
  match pin {
   None=>Ok(Check::NoPin),
   Some((_,_,1))=>Ok(Check::Conflict),
   Some((seq,_,_)) if actual.is_none_or(|v|v.seq<seq as u64)=>Ok(Check::Rollback),
   Some((seq,d,_)) if actual.is_some_and(|v|v.seq==seq as u64&&v.digest.as_slice()!=d)=>Ok(Check::Conflict),
   Some((seq,d,_)) if actual.is_some_and(|v|v.seq==seq as u64&&v.digest.as_slice()==d)=>Ok(Check::Match),
   Some((_seq,_d,_))=>Err(PinError::Missing), // advanced head needs verified continuity
  }
 }
}


impl ExternalCausalPin {
 /// Verified entry-point for a *custodian-signed claim*. Not a genuine W10
 /// witness checkpoint. Authenticate transport, scope and STORE rights
 /// separately before exposing this outside a laboratory.
 pub fn pin_signed_claim(
   &mut self,raw:&[u8],expected_scope:[u8;16],
   expected_actor:[u8;16],trust:&TrustRegistry,
 )->Result<CausalCommitment,PinError>{
   let verified=verify_w12_signed_claim(raw,trust).map_err(|_|PinError::Invalid)?;
   if verified.private_scope!=expected_scope || verified.custodian_id!=expected_actor {
      return Err(PinError::Invalid);
   }
   let prior=self.compare(expected_scope,expected_actor,Some(verified.commitment))?;
   match prior {
     Check::Rollback|Check::Conflict=>return Err(PinError::Conflict),
     _=>{}
   }
   // Fail closed on missing continuity rather than trusting a new higher seq.
   self.pin_observed(expected_scope,expected_actor,verified.commitment)?;
   Ok(verified.commitment)
 }
}
