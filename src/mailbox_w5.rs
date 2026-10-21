//! Experimental, bounded, SQLite-backed store-and-forward mailbox.
//!
//! Opaque packets are NEVER decrypted or treated as authorizing Sync operations.
//! This is a logical-quota prototype, not a production mailbox service:
//! authentication, recipient subscriptions, rate limits, disk/WAL bounds,
//! trusted clock and signed deletion acknowledgments are separate gates.
//! Deleted MessageIds are reserved for a bounded retention window only;
//! this journal cannot guarantee lifetime-unique identifiers.
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use std::path::{Path, PathBuf};

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
    InvalidDiskLimit,
    Io(std::io::Error),
    WalCheckpointBusy,
    InvalidTime,
    ClockRollback,
    ReusedMessageId,
    TombstoneQuotaExceeded,
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
impl From<std::io::Error> for MailError {
    fn from(value: std::io::Error) -> Self { Self::Io(value) }
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
    /// Logical tombstone rows, not SQLite disk/WAL usage.
    pub tombstones: usize,
}

/// Filesystem observation only: not an atomic snapshot and not an enforced
/// byte cap. WAL and SHM are distinct files and can grow independently.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MailboxDiskUsage {
    pub database_bytes: u64,
    pub wal_bytes: u64,
    pub shm_bytes: u64,
    pub total_bytes: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WalCheckpointResult {
    pub log_frames: i64,
    pub checkpointed_frames: i64,
}

pub struct Mailbox {
    db: Connection,
    limits: MailboxLimits,
    path: PathBuf,
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
               VALUES (1,0);
             CREATE TABLE IF NOT EXISTS mailbox_tombstones (
                 route_token BLOB NOT NULL CHECK(length(route_token)=16),
                 message_id BLOB NOT NULL CHECK(length(message_id)=16),
                 digest BLOB NOT NULL CHECK(length(digest)=32),
                 original_expires_at INTEGER NOT NULL CHECK(original_expires_at>0),
                 retained_until INTEGER NOT NULL CHECK(retained_until>original_expires_at),
                 PRIMARY KEY(route_token,message_id)
             );
             CREATE INDEX IF NOT EXISTS mailbox_tombstone_gc
               ON mailbox_tombstones(retained_until);",
        )?;
        Ok(Self {db, limits, path: path.to_path_buf()})
    }

    /// Explicit opt-in: apply a connection-scoped SQLite main-database page
    /// bound on EVERY open (SQLite does not persist max_page_count reliably).
    /// WAL/SHM growth is not controlled by this bound. A too-small bound
    /// causes writes that require new main-database pages to fail safely.
    pub fn open_with_main_page_limit(
        path: &Path, limits: MailboxLimits, max_pages: u32,
    ) -> Result<Self, MailError> {
        let mailbox = Self::open(path, limits)?;
        mailbox.configure_main_page_limit(max_pages)?;
        Ok(mailbox)
    }

    fn configure_main_page_limit(&self, max_pages: u32) -> Result<(), MailError> {
        let used: i64 = self.db.query_row(
            "PRAGMA page_count", [], |row| row.get(0),
        )?;
        if max_pages == 0 || i64::from(max_pages) < used {
            return Err(MailError::InvalidDiskLimit);
        }
        // Numeric input is strongly typed, not user-supplied SQL.
        let pragma = format!("PRAGMA max_page_count={max_pages}");
        let actual: i64 = self.db.query_row(&pragma, [], |row| row.get(0))?;
        if actual != i64::from(max_pages) {
            return Err(MailError::InvalidDiskLimit);
        }
        Ok(())
    }

    /// The current connection's maximum main-DB pages. This limit MUST be
    /// reapplied after a restart; it does not cap WAL, SHM, or OS metadata.
    pub fn main_page_limit(&self) -> Result<u64, MailError> {
        let pages: i64 = self.db.query_row(
            "PRAGMA max_page_count", [], |row| row.get(0),
        )?;
        u64::try_from(pages).map_err(|_| MailError::CorruptStorage)
    }

    /// Non-atomic observation of database, -wal and -shm file lengths.
    /// The normal SQLite WAL lifecycle can create/remove sidecars between
    /// metadata calls. This is telemetry, NOT disk-quota enforcement.
    pub fn disk_usage(&self) -> Result<MailboxDiskUsage, MailError> {
        let database_bytes = file_len_or_zero(&self.path)?;
        let wal_bytes = file_len_or_zero(&sidecar_path(&self.path, "-wal"))?;
        let shm_bytes = file_len_or_zero(&sidecar_path(&self.path, "-shm"))?;
        let total_bytes = database_bytes
            .checked_add(wal_bytes)
            .and_then(|n| n.checked_add(shm_bytes))
            .ok_or(MailError::CorruptStorage)?;
        Ok(MailboxDiskUsage {
            database_bytes, wal_bytes, shm_bytes, total_bytes,
        })
    }

    /// Privileged, on-demand WAL checkpoint with truncation. No mailbox
    /// row or receipt is deleted. A pinned reader may prevent truncation;
    /// failure must not be presented to operators as a successful reclaim.
    /// Checkpointing is not safe as a replacement for filesystem quotas.
    pub fn checkpoint_wal_truncate(&self) -> Result<WalCheckpointResult, MailError> {
        let (busy, log_frames, checkpointed_frames): (i64, i64, i64) =
            self.db.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })?;
        if busy != 0 { return Err(MailError::WalCheckpointBusy); }
        Ok(WalCheckpointResult { log_frames, checkpointed_frames })
    }

    /// Enqueue an opaque ciphertext under a recipient-issued routing token.
    ///
    /// Duplicate ID + identical ciphertext AND expiry are idempotent;
    /// a changed expiry cannot extend TTL. The SQLite IMMEDIATE transaction
    /// serializes quota checks and insertion across writers.
    /// Token ownership and sender authorization are NOT implemented here.
    /// An ordinary enqueue never uses caller-provided time to delete other
    /// messages. Expired rows retain their quota until explicit maintenance.
    /// Deleted IDs remain reserved while a bounded tombstone is retained.
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
        let was_deleted: i64 = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM mailbox_tombstones
              WHERE route_token=?1 AND message_id=?2)",
            params![route_token.as_slice(), message_id.as_slice()],
            |r| r.get(0),
        )?;
        if was_deleted != 0 { return Err(MailError::ReusedMessageId); }
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
    /// Each deleted ID is reserved for max_ttl_seconds after the GC run.
    /// When tombstone limits are reached GC fails atomically instead of
    /// deleting entries without replay protection. This can delay cleanup.
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
        let retained_until = now.checked_add(self.limits.max_ttl_seconds)
            .ok_or(MailError::InvalidTime)?;
        // Clearing aged tombstones, reserving new IDs, deleting data, and
        // advancing the GC high-water mark are one atomic transaction.
        tx.execute(
            "DELETE FROM mailbox_tombstones WHERE retained_until<=?1",
            params![now],
        )?;
        let reserved: i64 = tx.query_row(
            "SELECT COUNT(*) FROM mailbox_tombstones", [], |r| r.get(0),
        )?;
        let expiring: i64 = tx.query_row(
            "SELECT COUNT(*) FROM mailbox_entries WHERE expires_at<=?1",
            params![now], |r| r.get(0),
        )?;
        if reserved.checked_add(expiring)
            .is_none_or(|n| n > self.limits.total_records as i64)
        {
            return Err(MailError::TombstoneQuotaExceeded);
        }
        let token_over_quota: i64 = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM (
               SELECT route_token FROM mailbox_tombstones
               UNION ALL
               SELECT route_token FROM mailbox_entries WHERE expires_at<=?1
             ) GROUP BY route_token HAVING COUNT(*)>?2)",
            params![now, self.limits.per_token_records as i64],
            |r| r.get(0),
        )?;
        if token_over_quota != 0 {
            return Err(MailError::TombstoneQuotaExceeded);
        }
        tx.execute(
            "INSERT INTO mailbox_tombstones
               (route_token,message_id,digest,original_expires_at,retained_until)
             SELECT route_token,message_id,digest,expires_at,?2
               FROM mailbox_entries WHERE expires_at<=?1",
            params![now, retained_until],
        )?;
        let deleted = tx.execute(
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
        let tombstones: i64 = self.db.query_row(
            "SELECT COUNT(*) FROM mailbox_tombstones", [], |r| r.get(0),
        )?;
        let messages=usize::try_from(n).map_err(|_|MailError::CorruptStorage)?;
        let payload_bytes=usize::try_from(bytes).map_err(|_|MailError::CorruptStorage)?;
        let tombstones=usize::try_from(tombstones).map_err(|_|MailError::CorruptStorage)?;
        Ok(MailboxStats {messages,payload_bytes,tombstones})
    }
}

fn sidecar_path(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

fn file_len_or_zero(path: &Path) -> Result<u64, MailError> {
    match std::fs::metadata(path) {
        Ok(metadata) => Ok(metadata.len()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(err) => Err(MailError::Io(err)),
    }
}
