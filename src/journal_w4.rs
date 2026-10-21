//! Experimental SQLite durable inbox/outbox. Not a substitute for authenticated delivery
//! receipts or Akula Sync Core's transaction journal.
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use std::path::Path;

#[derive(Debug)]
pub enum JournalError { Db(rusqlite::Error), Conflict, TooLarge, InvalidState, NotFound }
impl From<rusqlite::Error> for JournalError {
    fn from(e: rusqlite::Error) -> Self { Self::Db(e) }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i64)]
pub enum Delivery { Queued=0, Neighbor=1, Gateway=2, Mailbox=3, Recipient=4 }
impl Delivery {
    fn from_int(x:i64)->Result<Self,JournalError>{ match x {
        0=>Ok(Self::Queued),1=>Ok(Self::Neighbor),2=>Ok(Self::Gateway),
        3=>Ok(Self::Mailbox),4=>Ok(Self::Recipient),_=>Err(JournalError::InvalidState),
    }}
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Insert { New, Duplicate }
pub struct Journal { db: Connection }
impl Journal {
    pub fn open(path:&Path)->Result<Self,JournalError>{
        let db=Connection::open(path)?;
        db.busy_timeout(std::time::Duration::from_secs(5))?;
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS outbox(
                recipient BLOB NOT NULL CHECK(length(recipient)=16),
                message BLOB NOT NULL CHECK(length(message)=16),
                digest BLOB NOT NULL CHECK(length(digest)=32),
                packet BLOB NOT NULL CHECK(length(packet) BETWEEN 1 AND 16384),
                expiry INTEGER NOT NULL,
                status INTEGER NOT NULL CHECK(status BETWEEN 0 AND 4),
                PRIMARY KEY(recipient,message));
            CREATE TABLE IF NOT EXISTS inbox(
                sender BLOB NOT NULL CHECK(length(sender)=16),
                message BLOB NOT NULL CHECK(length(message)=16),
                digest BLOB NOT NULL CHECK(length(digest)=32),
                PRIMARY KEY(sender,message));")?;
        Ok(Self{db})
    }
    pub fn enqueue(&mut self,recipient:[u8;16],message:[u8;16],expiry:i64,packet:&[u8])
        ->Result<Insert,JournalError>{
        if packet.is_empty()||packet.len()>crate::MAX_MESSAGE_BYTES{return Err(JournalError::TooLarge);}
        let digest=blake3::hash(packet);
        let tx=self.db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing:Option<Vec<u8>>=tx.query_row("SELECT digest FROM outbox WHERE recipient=?1 AND message=?2",
            params![recipient.as_slice(),message.as_slice()],|r|r.get(0)).optional()?;
        if let Some(old)=existing {
            if old.as_slice()!=digest.as_bytes(){return Err(JournalError::Conflict);}
            tx.commit()?;return Ok(Insert::Duplicate);
        }
        tx.execute("INSERT INTO outbox(recipient,message,digest,packet,expiry,status) VALUES(?1,?2,?3,?4,?5,0)",
            params![recipient.as_slice(),message.as_slice(),digest.as_bytes().as_slice(),packet,expiry])?;
        tx.commit()?;Ok(Insert::New)
    }
    /// Persist a *verified* receipt level supplied by an authenticated upper layer.
    /// This journal does not verify receipt signatures on its own.
    pub fn record_verified_receipt(&mut self,recipient:[u8;16],message:[u8;16],level:Delivery)
        ->Result<Delivery,JournalError>{
        if level == Delivery::Recipient { return Err(JournalError::InvalidState); }
        let tx=self.db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let old:Option<i64>=tx.query_row("SELECT status FROM outbox WHERE recipient=?1 AND message=?2",
            params![recipient.as_slice(),message.as_slice()],|r|r.get(0)).optional()?;
        let old=Delivery::from_int(old.ok_or(JournalError::NotFound)?)?;
        if (level as i64)>(old as i64){
            tx.execute("UPDATE outbox SET status=?3 WHERE recipient=?1 AND message=?2",
                params![recipient.as_slice(),message.as_slice(),level as i64])?;
        }
        tx.commit()?;Ok(if (old as i64)>(level as i64){old}else{level})
    }
    /// Elevate to recipient-confirmed only with a verified signature AND an
    /// exact ciphertext digest match. No arbitrary relay can advance this state.
    pub fn apply_recipient_receipt(
        &mut self, receipt: &crate::receipt_w4::VerifiedRecipientReceipt,
    ) -> Result<Delivery, JournalError> {
        let tx=self.db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let recipient=receipt.recipient_id();
        let message=receipt.message_id();
        let row:Option<(Vec<u8>,i64)>=tx.query_row(
            "SELECT digest,status FROM outbox WHERE recipient=?1 AND message=?2",
            params![recipient.as_slice(),message.as_slice()],
            |r| Ok((r.get(0)?,r.get(1)?)),
        ).optional()?;
        let (digest,status)=row.ok_or(JournalError::NotFound)?;
        if digest.as_slice()!=receipt.packet_digest() {return Err(JournalError::Conflict);}
        let old=Delivery::from_int(status)?;
        if old != Delivery::Recipient {
            tx.execute("UPDATE outbox SET status=4 WHERE recipient=?1 AND message=?2",
                params![recipient.as_slice(),message.as_slice()])?;
        }
        tx.commit()?;
        Ok(Delivery::Recipient)
    }

    pub fn state(&self,recipient:[u8;16],message:[u8;16])->Result<Delivery,JournalError>{
        let value:i64=self.db.query_row("SELECT status FROM outbox WHERE recipient=?1 AND message=?2",
            params![recipient.as_slice(),message.as_slice()],|r|r.get(0))?;
        Delivery::from_int(value)
    }
    /// Retry exact saved ciphertext. Never encrypt again with the same message ID.
    pub fn retry_bytes(&self,recipient:[u8;16],message:[u8;16],now:i64)->Result<Option<Vec<u8>>,JournalError>{
        let row:Option<(Vec<u8>,Vec<u8>,i64,i64)>=self.db.query_row(
            "SELECT packet,digest,expiry,status FROM outbox WHERE recipient=?1 AND message=?2",
            params![recipient.as_slice(),message.as_slice()],
            |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?;
        match row {
            None=>Err(JournalError::NotFound),
            Some((packet,digest,expiry,status))=>{
                Delivery::from_int(status)?;
                if digest.as_slice()!=blake3::hash(&packet).as_bytes(){return Err(JournalError::Conflict);}
                if expiry<=now||status==4 {Ok(None)} else {Ok(Some(packet))}
            }
        }
    }
    /// Caller MUST validate signature, trusted identity and permissions first.
    /// Marking as received does NOT mean the corresponding Sync Core operation was applied.
    pub fn accept_verified(&mut self,sender:[u8;16],message:[u8;16],packet:&[u8])
        ->Result<Insert,JournalError>{
        if packet.is_empty()||packet.len()>crate::MAX_MESSAGE_BYTES{return Err(JournalError::TooLarge);}
        let digest=blake3::hash(packet);
        let tx=self.db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing:Option<Vec<u8>>=tx.query_row("SELECT digest FROM inbox WHERE sender=?1 AND message=?2",
            params![sender.as_slice(),message.as_slice()],|r|r.get(0)).optional()?;
        if let Some(old)=existing{
            if old.as_slice()!=digest.as_bytes(){return Err(JournalError::Conflict);}
            tx.commit()?;return Ok(Insert::Duplicate);
        }
        tx.execute("INSERT INTO inbox(sender,message,digest) VALUES(?1,?2,?3)",
            params![sender.as_slice(),message.as_slice(),digest.as_bytes().as_slice()])?;
        tx.commit()?;Ok(Insert::New)
    }
}
