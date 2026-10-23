//! W10 local checkpoint pin: honest clients independently persist a signed
//! witness history anchor before trusting future custody decisions.
//!
//! First contact is NOT TOFU: the witness signing key, id and epoch MUST be
//! provisioned out-of-band in TrustRegistry. An empty local pin accepts only
//! checkpoint sequence 1, not an arbitrary claimed latest head. Subsequent
//! checkpoints must be adjacent (a verified gap is NOT inferred). A conflicting
//! signed head at the same sequence or incompatible adjacent link is durable
//! evidence of a witness fork and freezes this pin until human recovery.
//!
//! Signed checkpoints alone do not establish W8 issuer global uniqueness:
//! malicious witness can withhold fork observations, a compromised local pin
//! DB can be rolled back, and gossip requires participants to exchange data.
use crate::custody_witness_w9::{
    self, ChainRelation, WitnessError, CHECKPOINT_LEN,
};
use crate::trust_w3::TrustRegistry;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use std::path::Path;

#[derive(Debug)]
pub enum PinError {
    Db(rusqlite::Error),
    Witness(WitnessError),
    WrongScope,
    MissingHistory,
    Stale,
    Equivocation,
    Frozen,
}
impl From<rusqlite::Error> for PinError {
    fn from(e:rusqlite::Error)->Self {Self::Db(e)}
}
impl From<WitnessError> for PinError {
    fn from(e:WitnessError)->Self {Self::Witness(e)}
}
#[derive(Debug,Clone,Copy,Eq,PartialEq)]
pub enum PinOutcome { First, Unchanged, Advanced }

/// Both signed observations of a witness equivocation. Keep private.
pub type ForkPair=(Vec<u8>,Vec<u8>);
type StoredForkPair=(Option<Vec<u8>>,Option<Vec<u8>>);

pub struct WitnessPinStore {
    db:Connection,
    witness_id:[u8;16],
    epoch:u64,
}
impl WitnessPinStore {
    pub fn open(path:&Path,witness_id:[u8;16],epoch:u64)->Result<Self,PinError>{
        if witness_id==[0;16]||epoch==0||epoch>i64::MAX as u64 {
            return Err(PinError::WrongScope);
        }
        let db=Connection::open(path)?;
        db.busy_timeout(std::time::Duration::from_secs(5))?;
        db.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
             CREATE TABLE IF NOT EXISTS pinned_witness (
                singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                witness_id BLOB NOT NULL CHECK(length(witness_id)=16),
                epoch INTEGER NOT NULL CHECK(epoch>0),
                checkpoint BLOB CHECK(checkpoint IS NULL OR length(checkpoint)=226),
                frozen INTEGER NOT NULL CHECK(frozen IN (0,1)),
                fork_a BLOB CHECK(fork_a IS NULL OR length(fork_a)=226),
                fork_b BLOB CHECK(fork_b IS NULL OR length(fork_b)=226)
             );"
        )?;
        db.execute(
            "INSERT OR IGNORE INTO pinned_witness
             (singleton,witness_id,epoch,checkpoint,frozen,fork_a,fork_b)
             VALUES(1,?1,?2,NULL,0,NULL,NULL)",
            params![witness_id.as_slice(),epoch as i64],
        )?;
        let (stored_id,stored_epoch):(Vec<u8>,i64)=db.query_row(
            "SELECT witness_id,epoch FROM pinned_witness WHERE singleton=1",[],
            |r|Ok((r.get(0)?,r.get(1)?)),
        )?;
        if stored_id.as_slice()!=witness_id||stored_epoch!=epoch as i64 {
            return Err(PinError::WrongScope);
        }
        Ok(Self{db,witness_id,epoch})
    }

    /// Persist only a verified, adjacent signed witness checkpoint. A fork
    /// comparison durably freezes the pin and saves both signed statements.
    /// No witness-supplied timestamps or peer-provided keys are trusted.
    pub fn pin(
        &mut self,raw:&[u8],trust:&TrustRegistry,
    )->Result<PinOutcome,PinError>{
        let checkpoint=custody_witness_w9::verify_checkpoint(
            raw,self.witness_id,trust,
        )?;
        if checkpoint.witness_epoch!=self.epoch {
            return Err(PinError::WrongScope);
        }
        let tx=self.db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (known,frozen):(Option<Vec<u8>>,i64)=tx.query_row(
            "SELECT checkpoint,frozen FROM pinned_witness WHERE singleton=1",[],
            |r|Ok((r.get(0)?,r.get(1)?)),
        )?;
        if frozen!=0{return Err(PinError::Frozen);}
        let outcome=if let Some(known)=known {
            match custody_witness_w9::compare_checkpoints(
                &known,raw,self.witness_id,trust,
            )? {
                ChainRelation::Same=>PinOutcome::Unchanged,
                ChainRelation::Adjacent=>{
                    tx.execute(
                        "UPDATE pinned_witness SET checkpoint=?1 WHERE singleton=1",
                        params![raw],
                    )?;
                    PinOutcome::Advanced
                }
                ChainRelation::MissingHistory=>return Err(PinError::MissingHistory),
                ChainRelation::RollbackSuspected=>return Err(PinError::Stale),
                ChainRelation::Equivocation=>{
                    tx.execute(
                        "UPDATE pinned_witness
                         SET frozen=1,fork_a=?1,fork_b=?2 WHERE singleton=1",
                        params![known.as_slice(),raw],
                    )?;
                    tx.commit()?;
                    return Err(PinError::Equivocation);
                }
            }
        } else {
            if checkpoint.sequence!=1||checkpoint.previous_head!=[0;32] {
                return Err(PinError::MissingHistory);
            }
            tx.execute(
                "UPDATE pinned_witness SET checkpoint=?1 WHERE singleton=1",
                params![raw],
            )?;
            PinOutcome::First
        };
        tx.commit()?;
        Ok(outcome)
    }

    pub fn current(&self)->Result<Option<Vec<u8>>,PinError>{
        self.db.query_row(
            "SELECT checkpoint FROM pinned_witness WHERE singleton=1",[],
            |r|r.get(0),
        ).optional()
            .map(|row:Option<Option<Vec<u8>>>|row.flatten())
            .map_err(Into::into)
    }

    pub fn fork(&self)->Result<Option<ForkPair>,PinError>{
        let pair:Option<StoredForkPair>=self.db.query_row(
            "SELECT fork_a,fork_b FROM pinned_witness WHERE singleton=1",[],
            |r|Ok((r.get(0)?,r.get(1)?)),
        ).optional()?;
        Ok(pair.and_then(|(a,b)|Some((a?,b?))))
    }

    pub fn frozen(&self)->Result<bool,PinError>{
        let value:i64=self.db.query_row(
            "SELECT frozen FROM pinned_witness WHERE singleton=1",[],
            |r|r.get(0),
        )?;
        Ok(value!=0)
    }

    pub fn inspect(&self,trust:&TrustRegistry)->Result<Option<u64>,PinError>{
        if self.frozen()? {return Err(PinError::Frozen);}
        if let Some(raw)=self.current()? {
            if raw.len()!=CHECKPOINT_LEN {return Err(PinError::MissingHistory);}
            let checked=custody_witness_w9::verify_checkpoint(
                &raw,self.witness_id,trust,
            )?;
            if checked.witness_epoch!=self.epoch{return Err(PinError::WrongScope);}
            Ok(Some(checked.sequence))
        } else {
            Ok(None)
        }
    }
}
