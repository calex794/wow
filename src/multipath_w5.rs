//! Local-first crash-conservative credits shared by multipath forwarding lanes.
//!
//! A single owner with a shared SQLite file has K TOTAL slots including its
//! original copy. Reservations remain spent after crash or missing neighbour
//! ACK; automatic reclaim could duplicate a copy already accepted remotely.
//! This is NOT global off-device K enforcement, an anonymous routing system,
//! durable peer custody proof, or a public untrusted network API.
use crate::journal_w4::Journal;
use rusqlite::{params, OptionalExtension, TransactionBehavior};

pub const MAX_COPIES: u8 = 8;

#[derive(Debug)]
pub enum RouteError {
    Db(rusqlite::Error), Invalid, Missing, Conflict, Expired,
    ClockRollback, Exhausted, RecipientConfirmed, Entropy,
}
impl From<rusqlite::Error> for RouteError {
    fn from(e: rusqlite::Error) -> Self { Self::Db(e) }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i64)]
pub enum Lane { Forecast=1, Explore=2, Gateway=3 }
impl Lane {
    fn parse(n:i64) -> Result<Self,RouteError> {
        match n { 1=>Ok(Self::Forecast),2=>Ok(Self::Explore),
                  3=>Ok(Self::Gateway),_=>Err(RouteError::Conflict) }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RouteAttempt {
    pub slot:u8, pub lane:Lane, pub peer:[u8;16], pub alias:[u8;16],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RouteSnapshot {
    pub local_hint:[u8;16], pub budget:u8, pub allocated:u8, pub stopped:bool,
}
fn secret16()->Result<[u8;16],RouteError>{
    let mut out=[0u8;16];
    getrandom::fill(&mut out).map_err(|_|RouteError::Entropy)?;
    Ok(out)
}
fn digest(packet:&[u8])->Result<[u8;32],RouteError>{
    if packet.is_empty() || packet.len()>crate::MAX_MESSAGE_BYTES{
        return Err(RouteError::Invalid);
    }
    Ok(*blake3::hash(packet).as_bytes())
}
// Named alias keeps the SQL row contract visible without a deeply nested local type.
type StoredPlanRow=(Vec<u8>,i64,i64,Vec<u8>,i64,i64);

impl Journal {
    /// Private owner-only method; parent MUST be already durably enqueued.
    /// Returned hint is locally generated, NOT derived from recipient identity.
    pub fn begin_multipath(
        &mut self, recipient:[u8;16], message:[u8;16],
        packet:&[u8], expiry:i64, budget:u8, now:i64,
    )->Result<[u8;16],RouteError>{
        if now<0 || expiry<=now || !(1..=MAX_COPIES).contains(&budget){
            return Err(RouteError::Invalid);
        }
        let original=digest(packet)?;
        let tx=self.db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let parent:Option<(Vec<u8>,i64,i64)>=tx.query_row(
            "SELECT digest,expiry,status FROM outbox WHERE recipient=?1 AND message=?2",
            params![recipient.as_slice(),message.as_slice()],
            |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)),
        ).optional()?;
        let (old,ends,status)=parent.ok_or(RouteError::Missing)?;
        if old.as_slice()!=original.as_slice() || ends!=expiry{return Err(RouteError::Conflict);}
        if status==4{return Err(RouteError::RecipientConfirmed);}
        let previous:Option<StoredPlanRow>=tx.query_row(
            "SELECT digest,expiry,budget,local_hint,stopped,last_now
             FROM multipath_plan WHERE recipient=?1 AND message=?2",
            params![recipient.as_slice(),message.as_slice()],
            |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?)),
        ).optional()?;
        if let Some((prev,old_end,k,hint,stopped,last_now))=previous{
            if prev.as_slice()!=original.as_slice() || old_end!=expiry || k!=i64::from(budget){
                return Err(RouteError::Conflict);
            }
            if stopped!=0{return Err(RouteError::RecipientConfirmed);}
            if now<last_now{return Err(RouteError::ClockRollback);}
            tx.execute("UPDATE multipath_plan SET last_now=?3
                        WHERE recipient=?1 AND message=?2",
                       params![recipient.as_slice(),message.as_slice(),now])?;
            tx.commit()?;
            return hint.as_slice().try_into().map_err(|_|RouteError::Conflict);
        }
        let hint=secret16()?;
        tx.execute(
            "INSERT INTO multipath_plan
             (recipient,message,digest,expiry,budget,local_hint,stopped,last_now)
             VALUES(?1,?2,?3,?4,?5,?6,0,?7)",
            params![recipient.as_slice(),message.as_slice(),original.as_slice(),
                    expiry,i64::from(budget),hint.as_slice(),now],
        )?;
        tx.commit()?;
        Ok(hint)
    }
    /// Persist the reservation BEFORE sending the ciphertext. Identical retry
    /// returns the stored route attempt, with no new credit. Slots never refund.
    pub fn reserve_multipath(
        &mut self,identity:([u8;16],[u8;16]),packet:&[u8],
        request:[u8;16],peer:[u8;16],lane:Lane,now:i64,
    )->Result<RouteAttempt,RouteError>{
        let (recipient,message)=identity;
        if now<0 || request==[0;16] || peer==[0;16]{return Err(RouteError::Invalid);}
        let original=digest(packet)?;
        let tx=self.db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let plan:Option<(Vec<u8>,i64,i64,i64,i64,i64)>=tx.query_row(
            "SELECT p.digest,p.expiry,p.budget,p.stopped,p.last_now,o.status
             FROM multipath_plan p JOIN outbox o ON
              p.recipient=o.recipient AND p.message=o.message
             WHERE p.recipient=?1 AND p.message=?2",
            params![recipient.as_slice(),message.as_slice()],
            |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?)),
        ).optional()?;
        let (hash,expiry,budget,stopped,last_now,status)=plan.ok_or(RouteError::Missing)?;
        if hash.as_slice()!=original.as_slice(){return Err(RouteError::Conflict);}
        if stopped!=0 || status==4{return Err(RouteError::RecipientConfirmed);}
        if now<last_now{return Err(RouteError::ClockRollback);}
        if now>=expiry{return Err(RouteError::Expired);}
        let prev:Option<(i64,Vec<u8>,i64,Vec<u8>)>=tx.query_row(
            "SELECT lane,peer,slot,alias FROM multipath_attempt
             WHERE recipient=?1 AND message=?2 AND attempt=?3",
            params![recipient.as_slice(),message.as_slice(),request.as_slice()],
            |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)),
        ).optional()?;
        if let Some((old_lane,old_peer,slot,old_alias))=prev{
            if Lane::parse(old_lane)?!=lane || old_peer.as_slice()!=peer.as_slice(){
                return Err(RouteError::Conflict);
            }
            let alias:[u8;16]=old_alias.as_slice().try_into()
                .map_err(|_|RouteError::Conflict)?;
            tx.execute("UPDATE multipath_plan SET last_now=?3
                        WHERE recipient=?1 AND message=?2",
                       params![recipient.as_slice(),message.as_slice(),now])?;
            tx.commit()?;
            return Ok(RouteAttempt{slot:slot as u8,lane,peer,alias});
        }
        let used:i64=tx.query_row(
            "SELECT COUNT(*) FROM multipath_attempt WHERE recipient=?1 AND message=?2",
            params![recipient.as_slice(),message.as_slice()],|r|r.get(0))?;
        if used>=budget-1{return Err(RouteError::Exhausted);}
        let alias=secret16()?;
        let slot=used+1;
        tx.execute(
            "INSERT INTO multipath_attempt
             (recipient,message,attempt,alias,peer,lane,slot)
             VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![recipient.as_slice(),message.as_slice(),request.as_slice(),
                    alias.as_slice(),peer.as_slice(),lane as i64,slot],
        )?;
        tx.execute("UPDATE multipath_plan SET last_now=?3
                    WHERE recipient=?1 AND message=?2",
                   params![recipient.as_slice(),message.as_slice(),now])?;
        tx.commit()?;
        Ok(RouteAttempt{slot:slot as u8,lane,peer,alias})
    }
    pub fn multipath_snapshot(
        &self,recipient:[u8;16],message:[u8;16],
    )->Result<RouteSnapshot,RouteError>{
        let row:Option<(Vec<u8>,i64,i64,i64)>=self.db.query_row(
            "SELECT p.local_hint,p.budget,p.stopped,
              (SELECT COUNT(*) FROM multipath_attempt a
               WHERE a.recipient=p.recipient AND a.message=p.message)
             FROM multipath_plan p WHERE p.recipient=?1 AND p.message=?2",
            params![recipient.as_slice(),message.as_slice()],
            |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)),
        ).optional()?;
        let (hint,k,stopped,issued)=row.ok_or(RouteError::Missing)?;
        let local_hint:[u8;16]=hint.as_slice().try_into()
            .map_err(|_|RouteError::Conflict)?;
        let allocated=u8::try_from(issued+1).map_err(|_|RouteError::Conflict)?;
        if allocated>k as u8{return Err(RouteError::Conflict);}
        Ok(RouteSnapshot{local_hint,budget:k as u8,allocated,stopped:stopped!=0})
    }
}
