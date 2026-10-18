//! W6 trusted operator-signed enrollment of iroh TLS EndpointIds into W3
//! DeviceIds and a SINGLE authorized relay route, durably in SQLite.
//!
//! These records are NOT submitted by an incoming QUIC peer. Only a trusted
//! control plane may apply changes, and every change needs a signature from
//! an OUT-OF-BAND pinned operator key. The SQLite copy of the operator key
//! detects configuration mismatches but is NEVER itself a trust anchor.
//!
//! Revocation is sticky for an EndpointId. Re-enrollment after compromise
//! must use a new iroh key/EndpointId and a newer operator revision. An active
//! device's W3 key epoch can rotate strictly upward on the same endpoint.
//! The global revision and tombstones survive ordinary process restarts.
//!
//! Bounds: 128 endpoint rows, including revoked tombstones. No automatic
//! deletion. File/WAL quota, multi-process revocation ordering, cross-host
//! propagation, SQLite rollback after restoring an old snapshot, OS disk
//! tampering, and enrollment hardware proof are OUT OF SCOPE here.
//! This is a lab-only trust-policy component, not an HTTP/QUIC admin endpoint.
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use iroh::EndpointId;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use std::path::Path;

const DOMAIN: &[u8] = b"Akula/WOW/W6/endpoint-route-enrollment/lab-v1\0";
const VERSION: u8 = 1;
const BODY_BYTES: usize = 130;
pub const SIGNED_ENROLLMENT_BYTES: usize = BODY_BYTES + 64;
pub const MAX_ENROLLED_ENDPOINTS: i64 = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PolicyOperation { Allow = 1, Revoke = 2 }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EndpointRouteBinding {
    pub endpoint_id: EndpointId,
    pub w3_device_id: [u8; 16],
    pub w3_epoch: u64,
    pub relay_id: [u8; 16],
    pub namespace: [u8; 16],
    pub route_token: [u8; 16],
    pub issuer_id: [u8; 16],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OperatorChange {
    pub operation: PolicyOperation,
    /// Strictly increasing trusted control-plane serial, > 0 and <= i64::MAX.
    pub revision: u64,
    pub binding: EndpointRouteBinding,
}

#[derive(Debug)]
pub enum EnrollmentError {
    Db(rusqlite::Error),
    InvalidEncoding,
    UntrustedOperator,
    InvalidSignature,
    RevisionRollback,
    TooManyPeers,
    UnknownEndpoint,
    Revoked,
    WrongScope,
    EpochRollback,
    BindingConflict,
    CorruptStorage,
}
impl From<rusqlite::Error> for EnrollmentError {
    fn from(value: rusqlite::Error) -> Self { Self::Db(value) }
}

fn bytes16(raw: &[u8], start: usize) -> [u8;16] {
    raw[start..start + 16].try_into().expect("fixed body length checked")
}
fn num64(raw: &[u8], start: usize) -> u64 {
    u64::from_be_bytes(
        raw[start..start + 8].try_into().expect("fixed body length checked")
    )
}
fn valid_numbers(action: &OperatorChange) -> bool {
    action.revision > 0
        && action.revision <= i64::MAX as u64
        && action.binding.w3_epoch <= i64::MAX as u64
}
fn encoded_body(action: &OperatorChange) -> Result<Vec<u8>, EnrollmentError> {
    if !valid_numbers(action) { return Err(EnrollmentError::InvalidEncoding); }
    let b = &action.binding;
    let mut result = Vec::with_capacity(BODY_BYTES);
    result.push(VERSION);
    result.push(action.operation as u8);
    result.extend_from_slice(&action.revision.to_be_bytes());
    result.extend_from_slice(b.endpoint_id.as_bytes());
    result.extend_from_slice(&b.w3_device_id);
    result.extend_from_slice(&b.w3_epoch.to_be_bytes());
    result.extend_from_slice(&b.relay_id);
    result.extend_from_slice(&b.namespace);
    result.extend_from_slice(&b.route_token);
    result.extend_from_slice(&b.issuer_id);
    debug_assert_eq!(result.len(), BODY_BYTES);
    Ok(result)
}
fn signing_input(body: &[u8]) -> Vec<u8> {
    let mut data = Vec::with_capacity(DOMAIN.len() + body.len());
    data.extend_from_slice(DOMAIN);
    data.extend_from_slice(body);
    data
}

/// Offline/control-plane helper. Holding a signing key is privileged; this
/// does not give an unauthenticated client a way to change the relay policy.
pub fn sign_operator_change(
    signer: &SigningKey, action: &OperatorChange,
) -> Result<Vec<u8>, EnrollmentError> {
    let mut data = encoded_body(action)?;
    let signature = signer.sign(&signing_input(&data));
    data.extend_from_slice(&signature.to_bytes());
    Ok(data)
}

fn decode(raw: &[u8]) -> Result<OperatorChange, EnrollmentError> {
    if raw.len() != SIGNED_ENROLLMENT_BYTES || raw[0] != VERSION {
        return Err(EnrollmentError::InvalidEncoding);
    }
    let operation = match raw[1] {
        1 => PolicyOperation::Allow,
        2 => PolicyOperation::Revoke,
        _ => return Err(EnrollmentError::InvalidEncoding),
    };
    let mut endpoint = [0u8;32];
    endpoint.copy_from_slice(&raw[10..42]);
    let endpoint_id = EndpointId::from_bytes(&endpoint)
        .map_err(|_| EnrollmentError::InvalidEncoding)?;
    let action = OperatorChange {
        operation,
        revision: num64(raw, 2),
        binding: EndpointRouteBinding {
            endpoint_id,
            w3_device_id: bytes16(raw, 42),
            w3_epoch: num64(raw, 58),
            relay_id: bytes16(raw, 66),
            namespace: bytes16(raw, 82),
            route_token: bytes16(raw, 98),
            issuer_id: bytes16(raw, 114),
        },
    };
    if !valid_numbers(&action) { return Err(EnrollmentError::InvalidEncoding); }
    Ok(action)
}

struct StoredBinding {
    device: Vec<u8>,
    epoch: i64,
    relay: Vec<u8>,
    namespace: Vec<u8>,
    token: Vec<u8>,
    issuer: Vec<u8>,
    revoked: i64,
}
impl StoredBinding {
    fn read(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            device: row.get(0)?,
            epoch: row.get(1)?,
            relay: row.get(2)?,
            namespace: row.get(3)?,
            token: row.get(4)?,
            issuer: row.get(5)?,
            revoked: row.get(6)?,
        })
    }
    fn valid(&self) -> bool {
        self.device.len() == 16 && self.epoch >= 0
            && self.relay.len() == 16 && self.namespace.len() == 16
            && self.token.len() == 16 && self.issuer.len() == 16
            && (self.revoked == 0 || self.revoked == 1)
    }
    fn scope_matches(&self, b: &EndpointRouteBinding) -> bool {
        self.device.as_slice() == b.w3_device_id
            && self.relay.as_slice() == b.relay_id
            && self.namespace.as_slice() == b.namespace
            && self.token.as_slice() == b.route_token
            && self.issuer.as_slice() == b.issuer_id
    }
}

fn stored_at(
    db: &Connection, endpoint: &EndpointId,
) -> Result<Option<StoredBinding>, EnrollmentError> {
    Ok(db.query_row(
        "SELECT device,epoch,relay,namespace,token,issuer,revoked
         FROM w6_peer_enrollments WHERE endpoint = ?1",
        params![endpoint.as_bytes().as_slice()],
        StoredBinding::read,
    ).optional()?)
}

pub struct PeerEnrollmentDb {
    db: Connection,
    operator: VerifyingKey,
}
impl PeerEnrollmentDb {
    /// Root key is an independently pinned local parameter. Reopening a DB
    /// with a DIFFERENT root fails closed; DB content cannot choose the root.
    pub fn open(path: &Path, operator: VerifyingKey) -> Result<Self, EnrollmentError> {
        let db = Connection::open(path)?;
        db.busy_timeout(std::time::Duration::from_secs(2))?;
        db.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=FULL;
             CREATE TABLE IF NOT EXISTS w6_policy_state (
               singleton INTEGER PRIMARY KEY CHECK(singleton=1),
               operator_key BLOB NOT NULL CHECK(length(operator_key)=32),
               last_revision INTEGER NOT NULL CHECK(last_revision>=0)
             );
             CREATE TABLE IF NOT EXISTS w6_peer_enrollments (
               endpoint BLOB PRIMARY KEY NOT NULL CHECK(length(endpoint)=32),
               device BLOB NOT NULL CHECK(length(device)=16),
               epoch INTEGER NOT NULL CHECK(epoch>=0),
               relay BLOB NOT NULL CHECK(length(relay)=16),
               namespace BLOB NOT NULL CHECK(length(namespace)=16),
               token BLOB NOT NULL CHECK(length(token)=16),
               issuer BLOB NOT NULL CHECK(length(issuer)=16),
               revoked INTEGER NOT NULL CHECK(revoked IN (0,1))
             );"
        )?;
        db.execute(
            "INSERT OR IGNORE INTO w6_policy_state
             (singleton,operator_key,last_revision) VALUES(1,?1,0)",
            params![operator.as_bytes().as_slice()],
        )?;
        let persisted: Vec<u8> = db.query_row(
            "SELECT operator_key FROM w6_policy_state WHERE singleton=1",
            [], |row|row.get(0),
        )?;
        if persisted.as_slice() != operator.as_bytes() {
            return Err(EnrollmentError::UntrustedOperator);
        }
        Ok(Self { db, operator })
    }

    pub fn last_revision(&self) -> Result<u64, EnrollmentError> {
        let value: i64 = self.db.query_row(
            "SELECT last_revision FROM w6_policy_state WHERE singleton=1",
            [], |row|row.get(0),
        )?;
        if value < 0 { return Err(EnrollmentError::CorruptStorage); }
        Ok(value as u64)
    }

    /// Serialized, atomic signed update. No remote W6 handler can call this.
    /// Monotonic revision rejects stale/replayed changes across a restart.
    pub fn apply_signed(&mut self, bytes: &[u8]) -> Result<(), EnrollmentError> {
        let action = decode(bytes)?;
        let sig = Signature::from_slice(&bytes[BODY_BYTES..])
            .map_err(|_| EnrollmentError::InvalidSignature)?;
        self.operator.verify_strict(
            &signing_input(&bytes[..BODY_BYTES]), &sig,
        ).map_err(|_| EnrollmentError::InvalidSignature)?;
        let tx = self.db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let last: i64 = tx.query_row(
            "SELECT last_revision FROM w6_policy_state WHERE singleton=1",
            [], |row|row.get(0),
        )?;
        if last < 0 { return Err(EnrollmentError::CorruptStorage); }
        if action.revision <= last as u64 {
            return Err(EnrollmentError::RevisionRollback);
        }
        let existing = stored_at(&tx, &action.binding.endpoint_id)?;
        match action.operation {
            PolicyOperation::Allow => {
                if let Some(old) = existing {
                    if !old.valid() { return Err(EnrollmentError::CorruptStorage); }
                    if old.revoked == 1 { return Err(EnrollmentError::Revoked); }
                    if !old.scope_matches(&action.binding) {
                        return Err(EnrollmentError::BindingConflict);
                    }
                    if action.binding.w3_epoch <= old.epoch as u64 {
                        return Err(EnrollmentError::EpochRollback);
                    }
                    tx.execute(
                        "UPDATE w6_peer_enrollments SET epoch=?2 WHERE endpoint=?1",
                        params![
                            action.binding.endpoint_id.as_bytes().as_slice(),
                            action.binding.w3_epoch as i64,
                        ],
                    )?;
                } else {
                    let count: i64 = tx.query_row(
                        "SELECT COUNT(*) FROM w6_peer_enrollments",
                        [], |row|row.get(0),
                    )?;
                    if count >= MAX_ENROLLED_ENDPOINTS {
                        return Err(EnrollmentError::TooManyPeers);
                    }
                    let b = action.binding;
                    tx.execute(
                        "INSERT INTO w6_peer_enrollments
                         (endpoint,device,epoch,relay,namespace,token,issuer,revoked)
                         VALUES(?1,?2,?3,?4,?5,?6,?7,0)",
                        params![
                            b.endpoint_id.as_bytes().as_slice(),
                            b.w3_device_id.as_slice(),
                            b.w3_epoch as i64,
                            b.relay_id.as_slice(),
                            b.namespace.as_slice(),
                            b.route_token.as_slice(),
                            b.issuer_id.as_slice(),
                        ],
                    )?;
                }
            }
            PolicyOperation::Revoke => {
                let old = existing.ok_or(EnrollmentError::UnknownEndpoint)?;
                if !old.valid() { return Err(EnrollmentError::CorruptStorage); }
                if old.revoked == 1 { return Err(EnrollmentError::Revoked); }
                if !old.scope_matches(&action.binding)
                    || old.epoch as u64 != action.binding.w3_epoch
                {
                    return Err(EnrollmentError::BindingConflict);
                }
                tx.execute(
                    "UPDATE w6_peer_enrollments SET revoked=1 WHERE endpoint=?1",
                    params![action.binding.endpoint_id.as_bytes().as_slice()],
                )?;
            }
        }
        tx.execute(
            "UPDATE w6_policy_state SET last_revision=?1 WHERE singleton=1",
            params![action.revision as i64],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Authorize a proven QUIC/TLS endpoint for exactly the operator-pinned
    /// route. Returns only a W3 DeviceId/epoch; still require TrustRegistry.
    pub fn authorize(
        &self, remote: &EndpointId, relay: &[u8;16],
        namespace: &[u8;16], token: &[u8;16], issuer: &[u8;16],
    ) -> Result<([u8;16],u64), EnrollmentError> {
        let old = stored_at(&self.db, remote)?
            .ok_or(EnrollmentError::UnknownEndpoint)?;
        if !old.valid() { return Err(EnrollmentError::CorruptStorage); }
        if old.revoked == 1 { return Err(EnrollmentError::Revoked); }
        if old.relay.as_slice() != relay
            || old.namespace.as_slice() != namespace
            || old.token.as_slice() != token
            || old.issuer.as_slice() != issuer
        {
            return Err(EnrollmentError::WrongScope);
        }
        let device: [u8;16] = old.device.try_into()
            .map_err(|_| EnrollmentError::CorruptStorage)?;
        Ok((device,old.epoch as u64))
    }
}
