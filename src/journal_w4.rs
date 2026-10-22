//! Experimental SQLite durable inbox/outbox. Not a substitute for authenticated delivery
//! receipts or Akula Sync Core's transaction journal.
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use std::path::Path;

#[derive(Debug)]
pub enum JournalError { Db(rusqlite::Error), Conflict, TooLarge, InvalidState, NotFound, Unauthorized }
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
pub struct Journal { pub(crate) db: Connection }
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
                PRIMARY KEY(sender,message));
            CREATE TABLE IF NOT EXISTS receipt_outbox(
                sender BLOB NOT NULL CHECK(length(sender)=16),
                message BLOB NOT NULL CHECK(length(message)=16),
                digest BLOB NOT NULL CHECK(length(digest)=32),
                receipt BLOB NOT NULL CHECK(length(receipt)=137),
                PRIMARY KEY(sender,message));
            CREATE TABLE IF NOT EXISTS multipath_plan(
              recipient BLOB NOT NULL CHECK(length(recipient)=16),
              message BLOB NOT NULL CHECK(length(message)=16),
              digest BLOB NOT NULL CHECK(length(digest)=32),
              expiry INTEGER NOT NULL,
              budget INTEGER NOT NULL CHECK(budget BETWEEN 1 AND 8),
              local_hint BLOB NOT NULL UNIQUE CHECK(length(local_hint)=16),
              stopped INTEGER NOT NULL DEFAULT 0 CHECK(stopped BETWEEN 0 AND 1),
              last_now INTEGER NOT NULL CHECK(last_now>=0),
              PRIMARY KEY(recipient,message),
              FOREIGN KEY(recipient,message) REFERENCES outbox(recipient,message));
            CREATE TABLE IF NOT EXISTS multipath_attempt(
              recipient BLOB NOT NULL CHECK(length(recipient)=16),
              message BLOB NOT NULL CHECK(length(message)=16),
              attempt BLOB NOT NULL CHECK(length(attempt)=16),
              alias BLOB NOT NULL UNIQUE CHECK(length(alias)=16),
              peer BLOB NOT NULL CHECK(length(peer)=16),
              lane INTEGER NOT NULL CHECK(lane BETWEEN 1 AND 3),
              slot INTEGER NOT NULL CHECK(slot BETWEEN 1 AND 7),
              PRIMARY KEY(recipient,message,attempt),
              UNIQUE(recipient,message,slot),
              FOREIGN KEY(recipient,message) REFERENCES multipath_plan(recipient,message));
            CREATE TABLE IF NOT EXISTS custody_transfer_source(
              recipient BLOB NOT NULL CHECK(length(recipient)=16),
              message BLOB NOT NULL CHECK(length(message)=16),
              slot_alias BLOB NOT NULL CHECK(length(slot_alias)=16),
              offer_id BLOB NOT NULL UNIQUE CHECK(length(offer_id)=16),
              target BLOB NOT NULL CHECK(length(target)=16),
              offer BLOB NOT NULL CHECK(length(offer)=185),
              phase INTEGER NOT NULL CHECK(phase BETWEEN 1 AND 4),
              acceptance BLOB CHECK(acceptance IS NULL OR length(acceptance)=209),
              PRIMARY KEY(recipient,message,slot_alias),
              FOREIGN KEY(recipient,message) REFERENCES multipath_plan(recipient,message));
            PRAGMA foreign_keys=ON;")?;
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
        // One transaction: verified W4 sets final status AND fences route
        // credits and all pending/ambiguous peer custody offers in this
        // sender ledger. Peer-custody ACK by itself never ends delivery.
        tx.execute("UPDATE multipath_plan SET stopped=1
                    WHERE recipient=?1 AND message=?2",
                   params![recipient.as_slice(),message.as_slice()])?;
        tx.execute("UPDATE custody_transfer_source SET phase=4
                    WHERE recipient=?1 AND message=?2",
                   params![recipient.as_slice(),message.as_slice()])?;
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
    /// Authenticate the sender, persist inbox dedup AND queue a signed recipient
    /// acknowledgment in ONE transaction. A receipt is returned only after
    /// successful commit; a network sender cannot infer receipt from an attempted
    /// INSERT. The receipt means durable network acceptance, NOT Sync application.
    ///
    /// The recipient's signing key must also be enrolled for this exact epoch;
    /// the sender's identity and epoch come from the signed encrypted header.
    pub fn accept_authenticated_and_queue_receipt(
        &mut self,
        packet: &[u8],
        context: crate::crypto_identity_w3::TrustedRecipient<'_>,
        recipient_signer: &ed25519_dalek::SigningKey,
        recipient_epoch: u64,
    ) -> Result<(Insert, Vec<u8>), JournalError> {
        let expected_key=context.registry
            .key_for(context.recipient_id, recipient_epoch)
            .map_err(|_| JournalError::Unauthorized)?;
        if expected_key != &recipient_signer.verifying_key() {
            return Err(JournalError::Unauthorized);
        }
        let (header, _payload)=crate::crypto_identity_w3::open(packet, context)
            .map_err(|_| JournalError::Unauthorized)?;
        self.commit_authenticated_receipt(packet, header, recipient_signer, recipient_epoch)
    }

    /// Private W3 v3 is decrypted and Ed25519-verified using independent
    /// sender trust and an invitation-scoped route token BEFORE the recipient
    /// atomically commits inbox dedup and its signed final W4 receipt.
    /// No automatic fallback to public-identity W3 v2 is permitted.
    ///
    /// This LAB interface does not encrypt the return path of W4: never
    /// expose the returned receipt to an untrusted relay or public mailbox.
    pub fn accept_private_authenticated_and_queue_receipt(
        &mut self,
        packet: &[u8],
        context: crate::crypto_identity_w3::TrustedRecipient<'_>,
        route_token: [u8;16],
        recipient_signer: &ed25519_dalek::SigningKey,
        recipient_epoch: u64,
    ) -> Result<(Insert, Vec<u8>), JournalError> {
        let enrolled = context.registry.key_for(context.recipient_id, recipient_epoch)
            .map_err(|_| JournalError::Unauthorized)?;
        if enrolled != &recipient_signer.verifying_key() {
            return Err(JournalError::Unauthorized);
        }
        let verified=crate::private_route_w3::open_authenticated(
            packet, context, route_token,
        ).map_err(|_| JournalError::Unauthorized)?;
        self.commit_authenticated_receipt(
            packet, verified.header().into(), recipient_signer, recipient_epoch,
        )
    }

    // Caller performed suite-specific cryptographic sender authentication
    // and verified current recipient signing identity. Do not make public:
    // unauthenticated callers must never fabricate a durable recipient W4.
    fn commit_authenticated_receipt(
        &mut self,
        packet: &[u8],
        header: crate::crypto_identity_w3::SignedHeader,
        recipient_signer: &ed25519_dalek::SigningKey,
        recipient_epoch: u64,
    ) -> Result<(Insert, Vec<u8>), JournalError> {
        let digest=blake3::hash(packet);
        let sender=header.sender_id;
        let message=header.message_id;
        let tx=self.db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing:Option<Vec<u8>>=tx.query_row(
            "SELECT digest FROM inbox WHERE sender=?1 AND message=?2",
            params![sender.as_slice(), message.as_slice()],
            |r|r.get(0),
        ).optional()?;
        let result=if let Some(old)=existing {
            if old.as_slice()!=digest.as_bytes() { return Err(JournalError::Conflict); }
            Insert::Duplicate
        } else {
            tx.execute("INSERT INTO inbox(sender,message,digest) VALUES(?1,?2,?3)",
                params![sender.as_slice(),message.as_slice(),digest.as_bytes().as_slice()])?;
            Insert::New
        };
        let saved:Option<(Vec<u8>,Vec<u8>)>=tx.query_row(
            "SELECT digest,receipt FROM receipt_outbox WHERE sender=?1 AND message=?2",
            params![sender.as_slice(),message.as_slice()],
            |r| Ok((r.get(0)?,r.get(1)?)),
        ).optional()?;
        let receipt=if let Some((old_digest,old_receipt))=saved {
            if old_digest.as_slice()!=digest.as_bytes(){
                return Err(JournalError::Conflict);
            }
            old_receipt
        } else {
            let receipt=crate::receipt_w4::sign(
                recipient_signer,
                header.recipient_id,
                message,
                *digest.as_bytes(),
                recipient_epoch,
            );
            tx.execute(
                "INSERT INTO receipt_outbox(sender,message,digest,receipt) VALUES(?1,?2,?3,?4)",
                params![sender.as_slice(),message.as_slice(),digest.as_bytes().as_slice(),&receipt],
            )?;
            receipt
        };
        tx.commit()?;
        Ok((result,receipt))

    }

    /// Retransmit the original signed receipt after restart/ACK loss.
    /// Caller is responsible for rate limits, current trust and network egress.
    pub fn queued_recipient_receipt(
        &self, sender:[u8;16], message:[u8;16],
    ) -> Result<Option<Vec<u8>>, JournalError> {
        let stored:Option<(Vec<u8>,Vec<u8>,Vec<u8>)>=self.db.query_row(
            "SELECT r.digest,r.receipt,i.digest
             FROM receipt_outbox r JOIN inbox i
               ON i.sender=r.sender AND i.message=r.message
             WHERE r.sender=?1 AND r.message=?2",
            params![sender.as_slice(),message.as_slice()],
            |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)),
        ).optional()?;
        match stored {
            None=>Ok(None),
            Some((a,receipt,b)) if a==b=>Ok(Some(receipt)),
            Some(_)=>Err(JournalError::Conflict),
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
