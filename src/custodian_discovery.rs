//! P0 lab-only recipient-discoverable mailbox read authority.
//! A recipient signs a short-lived private list capability. The signed cursor
//! advances by W12 commit sequence, not by reservation order or message ID.
//! A listing reveals metadata to the enrolled recipient only; it is NOT W4,
//! and a malicious custodian can still omit data or lie about completeness.
use crate::{
    custodian_mailbox::{decode_store, load_policy, AuthError, SavedPolicy},
    journal_w4::Journal,
    private_route_w3,
    trust_w3::TrustRegistry,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use rusqlite::{params, OptionalExtension, TransactionBehavior};

const DOMAIN: &[u8] = b"Akula/WOW/Custodian/RECIPIENT-LIST/lab-v0\0";
const VERSION: u8 = 1;
const BODY_LEN: usize = 1 + 16 * 6 + 8 * 4 + 1;
const SIGNATURE_LEN: usize = 64;
pub const LIST_GRANT_BYTES: usize = BODY_LEN + SIGNATURE_LEN;
pub const MAX_LIST_ITEMS: u8 = 16;
const MAX_LIST_TTL_MS: i64 = 5 * 60 * 1000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ListClaims {
    pub issuer: [u8; 16],
    pub issuer_epoch: u64,
    pub custodian: [u8; 16],
    pub mailbox: [u8; 16],
    pub scope: [u8; 16],
    pub recipient: [u8; 16],
    pub recipient_epoch: u64,
    pub since_seq: u64,
    pub grant_until_ms: i64,
    pub nonce: [u8; 16],
    pub max_items: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ListedEntry {
    pub seq: u64,
    pub message: [u8; 16],
    pub digest: [u8; 32],
    pub expires_at_ms: i64,
}

fn body(claims: ListClaims) -> Vec<u8> {
    let mut out = Vec::with_capacity(BODY_LEN);
    out.push(VERSION);
    out.extend_from_slice(&claims.issuer);
    out.extend_from_slice(&claims.issuer_epoch.to_be_bytes());
    for field in [claims.custodian, claims.mailbox, claims.scope, claims.recipient] {
        out.extend_from_slice(&field);
    }
    out.extend_from_slice(&claims.recipient_epoch.to_be_bytes());
    out.extend_from_slice(&claims.since_seq.to_be_bytes());
    out.extend_from_slice(&claims.grant_until_ms.to_be_bytes());
    out.extend_from_slice(&claims.nonce);
    out.push(claims.max_items);
    debug_assert_eq!(out.len(), BODY_LEN);
    out
}

fn take<const N: usize>(data: &[u8], pos: &mut usize) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(&data[*pos..*pos + N]);
    *pos += N;
    out
}

fn decode(raw: &[u8]) -> Result<(ListClaims, Signature), AuthError> {
    if raw.len() != LIST_GRANT_BYTES || raw[0] != VERSION {
        return Err(AuthError::Invalid);
    }
    let mut offset = 1;
    let claims = ListClaims {
        issuer: take(raw, &mut offset),
        issuer_epoch: u64::from_be_bytes(take(raw, &mut offset)),
        custodian: take(raw, &mut offset),
        mailbox: take(raw, &mut offset),
        scope: take(raw, &mut offset),
        recipient: take(raw, &mut offset),
        recipient_epoch: u64::from_be_bytes(take(raw, &mut offset)),
        since_seq: u64::from_be_bytes(take(raw, &mut offset)),
        grant_until_ms: i64::from_be_bytes(take(raw, &mut offset)),
        nonce: take(raw, &mut offset),
        max_items: raw[offset],
    };
    debug_assert_eq!(offset + 1, BODY_LEN);
    let signature = Signature::from_slice(&raw[BODY_LEN..]).map_err(|_| AuthError::Invalid)?;
    Ok((claims, signature))
}

/// Privileged laboratory issuance. A caller must provision the recipient's
/// verifying key through an authenticated channel, never trust network TOFU.
pub fn sign_list_for_lab(recipient: &SigningKey, claims: ListClaims) -> Vec<u8> {
    let mut bytes = body(claims);
    let mut message = Vec::with_capacity(DOMAIN.len() + bytes.len());
    message.extend_from_slice(DOMAIN);
    message.extend_from_slice(&bytes);
    bytes.extend_from_slice(&recipient.sign(&message).to_bytes());
    bytes
}

fn authorize(
    raw: &[u8],
    policy: SavedPolicy,
    trust: &TrustRegistry,
    now_ms: i64,
) -> Result<ListClaims, AuthError> {
    let (claims, signature) = decode(raw)?;
    let p = policy.policy;
    if policy.fetch_revoked
        || claims.issuer != p.issuer
        || claims.issuer_epoch != p.issuer_epoch
        || claims.custodian != p.custodian
        || claims.mailbox != p.mailbox
        || claims.scope != p.scope
        || claims.recipient != p.recipient
    {
        return Err(AuthError::Unauthorized);
    }
    if claims.recipient_epoch == 0
        || claims.recipient_epoch > i64::MAX as u64
        || claims.since_seq > i64::MAX as u64
        || claims.nonce == [0; 16]
        || claims.max_items == 0
        || claims.max_items > MAX_LIST_ITEMS
        || now_ms < 0
        || claims.grant_until_ms <= now_ms
        || claims.grant_until_ms - now_ms > MAX_LIST_TTL_MS
    {
        return Err(AuthError::Invalid);
    }
    // Both the mailbox owner trust epoch and the recipient trust epoch must
    // still be independently enrolled and nonrevoked.
    trust.key_for(p.issuer, p.issuer_epoch).map_err(|_| AuthError::Unauthorized)?;
    let key = trust.key_for(p.recipient, claims.recipient_epoch)
        .map_err(|_| AuthError::Unauthorized)?;
    let mut message = Vec::with_capacity(DOMAIN.len() + BODY_LEN);
    message.extend_from_slice(DOMAIN);
    message.extend_from_slice(&raw[..BODY_LEN]);
    key.verify(&message, &signature).map_err(|_| AuthError::Unauthorized)?;
    Ok(claims)
}

type StoredRow = (i64, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, i64);

fn check_stored(row: StoredRow, recipient: [u8; 16], now_ms: i64)
    -> Result<ListedEntry, AuthError>
{
    let (seq, stored_grant, message, packet, digest, expiry) = row;
    let (grant, _) = decode_store(&stored_grant).map_err(|_| AuthError::Corrupt)?;
    let digest_array: [u8; 32] = digest.as_slice().try_into().map_err(|_| AuthError::Corrupt)?;
    let message_array: [u8; 16] = message.as_slice().try_into().map_err(|_| AuthError::Corrupt)?;
    let hint = private_route_w3::inspect_route(&packet).map_err(|_| AuthError::Corrupt)?;
    if seq <= 0 || expiry <= now_ms
        || grant.recipient != recipient
        || grant.message != message_array
        || grant.digest != digest_array
        || grant.expires_at != expiry
        || blake3::hash(&packet).as_bytes() != &digest_array
        || hint.message_id != message_array
        || hint.expires_at_ms != expiry as u64
    {
        return Err(AuthError::Corrupt);
    }
    Ok(ListedEntry {
        seq: seq as u64,
        message: message_array,
        digest: digest_array,
        expires_at_ms: expiry,
    })
}

impl Journal {
    /// Recipient-signed, bounded, no-public-enumeration mailbox list. It
    /// advances by W12 commit sequence, so a late-completed offer cannot be
    /// skipped merely because it was reserved earlier.
    pub fn list_custodian_authorized(
        &mut self,
        signed_list: &[u8],
        trust: &TrustRegistry,
        now_ms: i64,
    ) -> Result<Vec<ListedEntry>, AuthError> {
        let (untrusted, _) = decode(signed_list)?;
        self.ensure_custodian_mailbox_schema()?;
        self.ensure_w12_schema()?;
        let tx = self.db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let policy = load_policy(&tx, untrusted.mailbox)?.ok_or(AuthError::Unauthorized)?;
        let claims = authorize(signed_list, policy, trust, now_ms)?;
        let mut results = Vec::with_capacity(usize::from(claims.max_items));
        {
            let mut query = tx.prepare(
                "SELECT e.seq,o.signed_grant,o.message,b.packet,b.digest,b.expiry
                 FROM custodian_mailbox_offer o
                 JOIN outbox b ON b.recipient=o.recipient AND b.message=o.message
                 JOIN causal_w12_event e ON e.recipient=o.recipient AND e.message=o.message
                 WHERE o.mailbox=?1 AND o.recipient=?2 AND o.state=1
                   AND e.private_scope=?3 AND e.custodian_id=?4
                   AND e.seq>?5 AND b.expiry>?6
                 ORDER BY e.seq ASC LIMIT ?7",
            )?;
            let rows = query.query_map(
                params![claims.mailbox.as_slice(), claims.recipient.as_slice(),
                    claims.scope.as_slice(), claims.custodian.as_slice(),
                    claims.since_seq as i64, now_ms, i64::from(claims.max_items)],
                |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?)),
            )?;
            for row in rows {
                let entry = check_stored(row?, claims.recipient, now_ms)?;
                results.push(entry);
            }
        }
        tx.commit()?;
        Ok(results)
    }

    /// FETCH can reuse the recipient's short-lived LIST read proof plus an
    /// exact listed seq/message/digest tuple. The credential is NOT a STORE or
    /// W4 authorization. The current policy and key epoch are checked again.
    pub fn fetch_custodian_listed(
        &mut self,
        signed_list: &[u8],
        wanted: ListedEntry,
        trust: &TrustRegistry,
        now_ms: i64,
    ) -> Result<Option<Vec<u8>>, AuthError> {
        let (untrusted, _) = decode(signed_list)?;
        self.ensure_custodian_mailbox_schema()?;
        self.ensure_w12_schema()?;
        let tx = self.db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let policy = load_policy(&tx, untrusted.mailbox)?.ok_or(AuthError::Unauthorized)?;
        let claims = authorize(signed_list, policy, trust, now_ms)?;
        if wanted.seq <= claims.since_seq || wanted.seq > i64::MAX as u64
            || wanted.message == [0; 16]
        {
            return Err(AuthError::Invalid);
        }
        let row: Option<StoredRow> = tx.query_row(
            "SELECT e.seq,o.signed_grant,o.message,b.packet,b.digest,b.expiry
             FROM custodian_mailbox_offer o
             JOIN outbox b ON b.recipient=o.recipient AND b.message=o.message
             JOIN causal_w12_event e ON e.recipient=o.recipient AND e.message=o.message
             WHERE o.mailbox=?1 AND o.recipient=?2 AND o.message=?3 AND o.state=1
               AND e.private_scope=?4 AND e.custodian_id=?5 AND e.seq=?6 AND b.expiry>?7",
            params![claims.mailbox.as_slice(),claims.recipient.as_slice(),
                wanted.message.as_slice(),claims.scope.as_slice(),
                claims.custodian.as_slice(),wanted.seq as i64,now_ms],
            |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?)),
        ).optional()?;
        let Some(row) = row else {
            tx.commit()?;
            return Ok(None);
        };
        let packet = row.3.clone();
        if check_stored(row, claims.recipient, now_ms)? != wanted {
            return Err(AuthError::Unauthorized);
        }
        tx.commit()?;
        Ok(Some(packet))
    }
}
