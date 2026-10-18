//! Experimental, bounded, SQLite-backed store-and-forward mailbox.
//!
//! Opaque packets are NEVER decrypted or treated as authorizing Sync operations.
//! This is a logical-quota prototype, not a production mailbox service:
//! authentication, recipient subscriptions, rate limits, disk/WAL bounds,
//! trusted clock and signed deletion acknowledgments are separate gates.
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use std::path::Path;

pub const HARD_MAX_RECORDS: usize = 256;
pub const HARD_MAX_TOTAL_BYTES: usize = 1024 * 1024;
pub const HARD_MAX_PER_TOKEN_BYTES: usize = 64 * 1024;
pub const HARD_MAX_PAGE: usize = 16;
pub const HARD_MAX_TTL_SECONDS: i64 = 24 * 60 * 60;

#[derive(Clone, Copy, Debug)]
pub struct MailboxLimits {
    pub total_records: usize,
    pub per_token_records: usize,
    pub total_payload_bytes: usize,
    pub per_token_payload_bytes: usize,
    pub max_ttl_seconds: i64,
}

impl Default for MailboxLimits {
    fn default() -> Self {
        Self {
            total_records: 128,
            per_token_records: 16,
            total_payload_bytes: HARD_MAX_TOTAL_BYTES,
            per_token_payload_bytes: HARD_MAX_PER_TOKEN_BYTES,
            max_ttl_seconds: HARD_MAX_TTL_SECONDS,
        }
    }
}
impl MailboxLimits {
    fn validate(self) -> Result<Self, MailError> {
        if self.total_records == 0 || self.total_records > HARD_MAX_RECORDS
            || self.per_token_records == 0 || self.per_token_records > self.total_records
            || self.total_payload_bytes == 0 || self.total_payload_bytes > HARD_MAX_TOTAL_BYTES
            || self.per_token_payload_bytes == 0
            || self.per_token_payload_bytes > HARD_MAX_PER_TOKEN_BYTES
            || self.per_token_payload_bytes > self.total_payload_bytes
            || self.max_ttl_seconds <= 0 || self.max_ttl_seconds > HARD_MAX_TTL_SECONDS
        {
            return Err(MailError::InvalidLimits);
        }
        Ok(self)
    }
}

#[derive(Debug)]
pub enum MailError {
    Db(rusqlite::Error),
    InvalidLimits,
    InvalidTime,
    ClockRollback,
    InvalidPacket,
    TooLongTtl,
    QuotaExceeded,
    Conflict,
    InvalidPage,
    CorruptStorage,
}
impl From<rusqlite::Error> for MailError {
    fn from(value: rusqlite::Error) -> Self { Self::Db(value) }
}
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum PutStatus { Stored, Duplicate }

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct OpaqueMessage {
    pub id: [u8; 16],
    pub expires_at: i64,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct MailboxStats {
    /// Only logically stored ciphertext bytes, excluding SQLite/WAL overhead.
    pub messages: usize,
    pub payload_bytes: usize,
}

pub struct Mailbox {
    db: Connection,
    limits: MailboxLimits,
}
impl Mailbox {
    pub fn open(path: &Path, limits: MailboxLimits) -> Result<Self, MailError> {
        let limits = limits.validate()?;
        let db = Connection::open(path)?;
        db.busy_timeout(std::time::Duration::from_secs(5))?;
        db.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=FULL;
             CREATE TABLE IF NOT EXISTS mailbox_entries (
                 route_token BLOB NOT NULL CHECK(length(route_token)=16),
                 message_id BLOB NOT NULL CHECK(length(message_id)=16),
                 digest BLOB NOT NULL CHECK(length(digest)=32),
                 sealed BLOB NOT NULL CHECK(length(sealed) BETWEEN 1 AND 16384),
                 expires_at INTEGER NOT NULL CHECK(expires_at>0),
                 created_at INTEGER NOT NULL CHECK(created_at>=0),
                 PRIMARY KEY(route_token, message_id)
             );
             CREATE INDEX IF NOT EXISTS mailbox_expiry
                ON mailbox_entries(expires_at);
             CREATE INDEX IF NOT EXISTS mailbox_paging
                ON mailbox_entries(route_token, message_id);
             CREATE TABLE IF NOT EXISTS mailbox_maintenance (
                 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                 last_gc_at INTEGER NOT NULL CHECK(last_gc_at>=0)
             );
             INSERT OR IGNORE INTO mailbox_maintenance (singleton,last_gc_at)
               VALUES (1,0);",
        )?;
        Ok(Self {db, limits})
    }

    /// Enqueue an opaque ciphertext under a recipient-issued routing token.
    ///
    /// Duplicate ID + identical ciphertext AND expiry are idempotent;
    /// a changed expiry cannot extend TTL. The SQLite IMMEDIATE transaction
    /// serializes quota checks and insertion across writers.
    /// Token ownership and sender authorization are NOT implemented here.
    /// An ordinary enqueue never uses caller-provided time to delete other
    /// messages. Expired rows retain their quota until explicit maintenance.
    pub fn put(
        &mut self,
        route_token: [u8; 16],
        message_id: [u8; 16],
        now: i64,
        expires_at: i64,
        sealed: &[u8],
    ) -> Result<PutStatus, MailError> {
        if now < 0 || expires_at <= now {
            return Err(MailError::InvalidTime);
        }
        if expires_at.checked_sub(now).is_none_or(|d| d > self.limits.max_ttl_seconds) {
            return Err(MailError::TooLongTtl);
        }
        if sealed.is_empty() || sealed.len() > crate::MAX_MESSAGE_BYTES {
            return Err(MailError::InvalidPacket);
        }
        let digest = blake3::hash(sealed);
        let tx = self.db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let last_gc_at: i64 = tx.query_row(
            "SELECT last_gc_at FROM mailbox_maintenance WHERE singleton=1",
            [], |r| r.get(0),
        )?;
        if now < last_gc_at { return Err(MailError::ClockRollback); }
        let existing: Option<(Vec<u8>, Vec<u8>, i64)> = tx.query_row(
            "SELECT digest,sealed,expires_at FROM mailbox_entries
             WHERE route_token=?1 AND message_id=?2",
            params![route_token.as_slice(), message_id.as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        ).optional()?;
        if let Some((old_hash, old_sealed, old_expiry)) = existing {
            if old_expiry != expires_at || old_hash.as_slice() != digest.as_bytes()
                || old_sealed != sealed
            {
                return Err(MailError::Conflict);
            }
            tx.commit()?;
            return Ok(PutStatus::Duplicate);
        }
        let (all_n, all_size): (i64, i64) = tx.query_row(
            "SELECT COUNT(*),COALESCE(SUM(length(sealed)),0) FROM mailbox_entries",
            [],
            |r| Ok((r.get(0)?,r.get(1)?)),
        )?;
        let (token_n, token_size): (i64, i64) = tx.query_row(
            "SELECT COUNT(*),COALESCE(SUM(length(sealed)),0)
             FROM mailbox_entries WHERE route_token=?1",
            params![route_token.as_slice()],
            |r| Ok((r.get(0)?,r.get(1)?)),
        )?;
        if all_n >= self.limits.total_records as i64
            || token_n >= self.limits.per_token_records as i64
            || all_size + sealed.len() as i64 > self.limits.total_payload_bytes as i64
            || token_size + sealed.len() as i64 > self.limits.per_token_payload_bytes as i64
        {
            return Err(MailError::QuotaExceeded);
        }
        tx.execute(
            "INSERT INTO mailbox_entries
              (route_token,message_id,digest,sealed,expires_at,created_at)
             VALUES (?1,?2,?3,?4,?5,?6)",
            params![
                route_token.as_slice(), message_id.as_slice(),
                digest.as_bytes().as_slice(), sealed, expires_at, now
            ],
        )?;
        tx.commit()?;
        Ok(PutStatus::Stored)
    }

    /// Non-destructive, paged mailbox listing. A read never acknowledges,
    /// applies, or deletes an object. Cursor is exclusive message ID.
    /// Database-stored bytes are checked against their digest on every read.
    pub fn get_page(
        &self, route_token: [u8; 16], now: i64,
        after: Option<[u8; 16]>, limit: usize,
    ) -> Result<Vec<OpaqueMessage>, MailError> {
        if now < 0 { return Err(MailError::InvalidTime); }
        if limit == 0 || limit > HARD_MAX_PAGE { return Err(MailError::InvalidPage); }
        let last_gc_at: i64 = self.db.query_row(
            "SELECT last_gc_at FROM mailbox_maintenance WHERE singleton=1",
            [], |r| r.get(0),
        )?;
        if now < last_gc_at { return Err(MailError::ClockRollback); }
        let anchor = after.map(|a| a.to_vec());
        let mut stmt = self.db.prepare(
            "SELECT message_id,expires_at,sealed,digest
             FROM mailbox_entries
             WHERE route_token=?1 AND expires_at>?2
               AND (?3 IS NULL OR message_id>?3)
             ORDER BY message_id ASC LIMIT ?4",
        )?;
        let rows = stmt.query_map(
            params![route_token.as_slice(),now,anchor,limit as i64],
            |r| Ok((
                r.get::<_,Vec<u8>>(0)?,
                r.get::<_,i64>(1)?,
                r.get::<_,Vec<u8>>(2)?,
                r.get::<_,Vec<u8>>(3)?,
            )),
        )?;
        let mut result = Vec::with_capacity(limit);
        for row in rows {
            let (id, expires_at, bytes, digest) = row?;
            if id.len() != 16 || bytes.is_empty()
                || bytes.len() > crate::MAX_MESSAGE_BYTES
                || digest.as_slice() != blake3::hash(&bytes).as_bytes()
            {
                return Err(MailError::CorruptStorage);
            }
            let id: [u8;16] = id.try_into().map_err(|_|MailError::CorruptStorage)?;
            result.push(OpaqueMessage { id, expires_at, bytes });
        }
        Ok(result)
    }

    /// Explicit, privileged garbage collection. Call with trusted maintenance
    /// time only; arbitrary put() requests cannot authorize deletion.
    /// A durable high-water mark rejects backward clock movement across restarts.
    /// This cannot detect an incorrect *forward* jump in the trusted clock.
    /// No receipt-driven deletion is allowed without a separate verified
    /// end-recipient deletion protocol.
    pub fn purge_expired(&mut self, now: i64) -> Result<usize, MailError> {
        if now < 0 { return Err(MailError::InvalidTime); }
        let tx=self.db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let last_gc_at: i64 = tx.query_row(
            "SELECT last_gc_at FROM mailbox_maintenance WHERE singleton=1",
            [], |r| r.get(0),
        )?;
        if now < last_gc_at { return Err(MailError::ClockRollback); }
        let deleted=tx.execute(
            "DELETE FROM mailbox_entries WHERE expires_at<=?1",
            params![now],
        )?;
        tx.execute(
            "UPDATE mailbox_maintenance SET last_gc_at=?1 WHERE singleton=1",
            params![now],
        )?;
        tx.commit()?;
        Ok(deleted)
    }

    pub fn stats(&self) -> Result<MailboxStats, MailError> {
        let (n, bytes):(i64,i64)=self.db.query_row(
            "SELECT COUNT(*),COALESCE(SUM(length(sealed)),0) FROM mailbox_entries",
            [],
            |r| Ok((r.get(0)?,r.get(1)?)),
        )?;
        let messages=usize::try_from(n).map_err(|_|MailError::CorruptStorage)?;
        let payload_bytes=usize::try_from(bytes).map_err(|_|MailError::CorruptStorage)?;
        Ok(MailboxStats {messages,payload_bytes})
    }
}
