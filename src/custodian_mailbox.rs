//! Laboratory-only mailbox STORE/FETCH authorization: distinct from W5 relay
//! admission and W3's public route hint. No network endpoint is exported.
//!
//! A trusted local operator provisions the policy. STORE reservations,
//! revocation flags and the exact W12 ciphertext/causal event live in the SAME
//! SQLite database. Both the offer and read proofs are separately signed.
//! This is NOT a proof of physical custody or an authenticated transport.
use crate::{
    causal_w12::{CausalCommitment, CausalError, CausalRequest},
    journal_w4::Journal,
    private_route_w3,
    trust_w3::TrustRegistry,
    MAX_MESSAGE_BYTES,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};

const STORE_DOMAIN: &[u8] = b"Akula/WOW/Custodian/STORE/lab-v0\0";
const FETCH_DOMAIN: &[u8] = b"Akula/WOW/Custodian/FETCH/lab-v0\0";
const STORED_DOMAIN: &[u8] = b"Akula/WOW/Custodian/STORED-CLAIM/lab-v0\0";
const VERSION: u8 = 1;
const STORE_BODY: usize = 1 + 16 * 8 + 8 * 3 + 4 + 32;
const FETCH_BODY: usize = 1 + 16 * 6 + 8 * 2 + 32;
const SIG_BYTES: usize = 64;
const MAX_OFFERS: u32 = 64;

pub const STORE_GRANT_BYTES: usize = STORE_BODY + SIG_BYTES;
pub const FETCH_GRANT_BYTES: usize = FETCH_BODY + SIG_BYTES;

#[derive(Debug)]
pub enum AuthError {
    Db(rusqlite::Error),
    Causal(CausalError),
    Invalid,
    Unauthorized,
    Expired,
    Conflict,
    Capacity,
    Corrupt,
}
impl From<rusqlite::Error> for AuthError {
    fn from(e: rusqlite::Error) -> Self { Self::Db(e) }
}
impl From<CausalError> for AuthError {
    fn from(e: CausalError) -> Self {
        match e {
            CausalError::Unauthorized => Self::Unauthorized,
            CausalError::Conflict => Self::Conflict,
            CausalError::Invalid => Self::Invalid,
            CausalError::Corrupt => Self::Corrupt,
            other => Self::Causal(other),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MailboxPolicy {
    pub mailbox: [u8; 16],
    pub issuer: [u8; 16],
    pub issuer_epoch: u64,
    pub custodian: [u8; 16],
    pub scope: [u8; 16],
    pub recipient: [u8; 16],
    pub max_message_bytes: u32,
    pub max_offers: u32,
}
#[derive(Clone, Copy)]
struct SavedPolicy {
    policy: MailboxPolicy,
    store_revoked: bool,
    fetch_revoked: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StoreClaims {
    pub issuer: [u8; 16],
    pub issuer_epoch: u64,
    pub custodian: [u8; 16],
    pub mailbox: [u8; 16],
    pub scope: [u8; 16],
    pub recipient: [u8; 16],
    pub message: [u8; 16],
    pub offer: [u8; 16],
    pub slot: [u8; 16],
    pub expires_at: i64,
    pub grant_until: i64,
    pub packet_len: u32,
    pub digest: [u8; 32],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FetchClaims {
    pub issuer: [u8; 16],
    pub issuer_epoch: u64,
    pub custodian: [u8; 16],
    pub mailbox: [u8; 16],
    pub scope: [u8; 16],
    pub recipient: [u8; 16],
    pub message: [u8; 16],
    pub grant_until: i64,
    pub digest: [u8; 32],
}
/// A signer assertion bound to the exact owner STORE grant and W12 head.
/// This does NOT prove continuous physical storage or recipient delivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CustodianStoredClaim {
    pub store: StoreClaims,
    pub custodian_epoch: u64,
    pub causal: CausalCommitment,
    pub signature: [u8; 64],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Reservation { Reserved, AlreadyReserved, AlreadyCommitted }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StoreLocator { pub mailbox: [u8; 16], pub offer: [u8; 16] }

fn nonzero(v: &[u8; 16]) -> bool { *v != [0; 16] }
fn valid_policy(p: &MailboxPolicy) -> bool {
    nonzero(&p.mailbox) && nonzero(&p.issuer) && nonzero(&p.custodian)
        && nonzero(&p.scope) && nonzero(&p.recipient)
        && p.issuer_epoch > 0 && p.issuer_epoch <= i64::MAX as u64
        && p.max_message_bytes > 0 && p.max_message_bytes as usize <= MAX_MESSAGE_BYTES
        && p.max_offers > 0 && p.max_offers <= MAX_OFFERS
}
fn signed(domain: &[u8], body: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(domain.len() + body.len());
    v.extend_from_slice(domain);
    v.extend_from_slice(body);
    v
}
fn take<const N: usize>(raw: &[u8], offset: &mut usize) -> [u8; N] {
    // Only call after checking the exact fixed wire length.
    let mut out = [0; N];
    out.copy_from_slice(&raw[*offset..*offset + N]);
    *offset += N;
    out
}
fn encode_store(c: StoreClaims) -> Vec<u8> {
    let mut b = Vec::with_capacity(STORE_BODY);
    b.push(VERSION);
    b.extend_from_slice(&c.issuer);
    b.extend_from_slice(&c.issuer_epoch.to_be_bytes());
    for value in [c.custodian, c.mailbox, c.scope, c.recipient, c.message, c.offer, c.slot] {
        b.extend_from_slice(&value);
    }
    b.extend_from_slice(&c.expires_at.to_be_bytes());
    b.extend_from_slice(&c.grant_until.to_be_bytes());
    b.extend_from_slice(&c.packet_len.to_be_bytes());
    b.extend_from_slice(&c.digest);
    debug_assert_eq!(b.len(), STORE_BODY);
    b
}
pub(crate) fn decode_store(raw: &[u8]) -> Result<(StoreClaims, Signature), AuthError> {
    if raw.len() != STORE_BODY + SIG_BYTES || raw[0] != VERSION { return Err(AuthError::Invalid); }
    let mut offset = 1;
    let c = StoreClaims {
        issuer: take(raw, &mut offset),
        issuer_epoch: u64::from_be_bytes(take(raw, &mut offset)),
        custodian: take(raw, &mut offset),
        mailbox: take(raw, &mut offset),
        scope: take(raw, &mut offset),
        recipient: take(raw, &mut offset),
        message: take(raw, &mut offset),
        offer: take(raw, &mut offset),
        slot: take(raw, &mut offset),
        expires_at: i64::from_be_bytes(take(raw, &mut offset)),
        grant_until: i64::from_be_bytes(take(raw, &mut offset)),
        packet_len: u32::from_be_bytes(take(raw, &mut offset)),
        digest: take(raw, &mut offset),
    };
    debug_assert_eq!(offset, STORE_BODY);
    let signature = Signature::from_slice(&raw[STORE_BODY..]).map_err(|_|AuthError::Invalid)?;
    Ok((c, signature))
}
fn encode_fetch(c: FetchClaims) -> Vec<u8> {
    let mut b = Vec::with_capacity(FETCH_BODY);
    b.push(VERSION);
    b.extend_from_slice(&c.issuer);
    b.extend_from_slice(&c.issuer_epoch.to_be_bytes());
    for value in [c.custodian, c.mailbox, c.scope, c.recipient, c.message] {
        b.extend_from_slice(&value);
    }
    b.extend_from_slice(&c.grant_until.to_be_bytes());
    b.extend_from_slice(&c.digest);
    debug_assert_eq!(b.len(), FETCH_BODY);
    b
}
fn decode_fetch(raw: &[u8]) -> Result<(FetchClaims, Signature), AuthError> {
    if raw.len() != FETCH_BODY + SIG_BYTES || raw[0] != VERSION { return Err(AuthError::Invalid); }
    let mut offset = 1;
    let c = FetchClaims {
        issuer: take(raw, &mut offset),
        issuer_epoch: u64::from_be_bytes(take(raw, &mut offset)),
        custodian: take(raw, &mut offset),
        mailbox: take(raw, &mut offset),
        scope: take(raw, &mut offset),
        recipient: take(raw, &mut offset),
        message: take(raw, &mut offset),
        grant_until: i64::from_be_bytes(take(raw, &mut offset)),
        digest: take(raw, &mut offset),
    };
    debug_assert_eq!(offset, FETCH_BODY);
    let signature = Signature::from_slice(&raw[FETCH_BODY..]).map_err(|_|AuthError::Invalid)?;
    Ok((c, signature))
}

/// Privileged laboratory issuance helper, NOT authorization by itself.
pub fn sign_store_for_lab(signer: &SigningKey, claims: StoreClaims) -> Vec<u8> {
    let mut body = encode_store(claims);
    let sig = signer.sign(&signed(STORE_DOMAIN, &body));
    body.extend_from_slice(&sig.to_bytes());
    body
}
/// Read capability uses a different signing domain from STORE and relay W5.
pub fn sign_fetch_for_lab(signer: &SigningKey, claims: FetchClaims) -> Vec<u8> {
    let mut body = encode_fetch(claims);
    let sig = signer.sign(&signed(FETCH_DOMAIN, &body));
    body.extend_from_slice(&sig.to_bytes());
    body
}
fn verify_store(
    raw: &[u8], current: SavedPolicy, trust: &TrustRegistry, now: i64,
) -> Result<StoreClaims, AuthError> {
    let (c, signature) = decode_store(raw)?;
    let p = current.policy;
    if current.store_revoked || c.issuer != p.issuer || c.issuer_epoch != p.issuer_epoch
        || c.custodian != p.custodian || c.mailbox != p.mailbox
        || c.scope != p.scope || c.recipient != p.recipient
    { return Err(AuthError::Unauthorized); }
    if !nonzero(&c.message) || !nonzero(&c.offer) || !nonzero(&c.slot)
        || c.packet_len == 0 || c.packet_len > p.max_message_bytes
        || c.expires_at <= 0 || c.grant_until <= 0
    { return Err(AuthError::Invalid); }
    if now < 0 || now >= c.grant_until || now >= c.expires_at {
        return Err(AuthError::Expired);
    }
    let key = trust.key_for(c.issuer, c.issuer_epoch).map_err(|_|AuthError::Unauthorized)?;
    key.verify(&signed(STORE_DOMAIN, &raw[..STORE_BODY]), &signature)
        .map_err(|_|AuthError::Unauthorized)?;
    Ok(c)
}
fn verify_fetch(
    raw: &[u8], current: SavedPolicy, trust: &TrustRegistry, now: i64,
) -> Result<FetchClaims, AuthError> {
    let (c, signature) = decode_fetch(raw)?;
    let p = current.policy;
    if current.fetch_revoked || c.issuer != p.issuer || c.issuer_epoch != p.issuer_epoch
        || c.custodian != p.custodian || c.mailbox != p.mailbox
        || c.scope != p.scope || c.recipient != p.recipient
    { return Err(AuthError::Unauthorized); }
    if !nonzero(&c.message) || c.grant_until <= 0 { return Err(AuthError::Invalid); }
    if now < 0 || now >= c.grant_until { return Err(AuthError::Expired); }
    let key = trust.key_for(c.issuer, c.issuer_epoch).map_err(|_|AuthError::Unauthorized)?;
    key.verify(&signed(FETCH_DOMAIN, &raw[..FETCH_BODY]), &signature)
        .map_err(|_|AuthError::Unauthorized)?;
    Ok(c)
}
fn stored_claim_body(claim: &CustodianStoredClaim) -> Vec<u8> {
    let mut body = signed(STORED_DOMAIN, &encode_store(claim.store));
    body.extend_from_slice(&claim.custodian_epoch.to_be_bytes());
    body.extend_from_slice(&claim.causal.seq.to_be_bytes());
    body.extend_from_slice(&claim.causal.digest);
    body
}

/// Verify a custodian's signed assertion against the *original* owner-signed
/// grant, exact ciphertext and currently enrolled keys. The W12 journal itself
/// requires a separate audit. This is neither recipient W4 nor a remote storage proof.
pub fn verify_custodian_stored_claim(
    claim: &CustodianStoredClaim,
    signed_store: &[u8],
    w3: &[u8],
    trust: &TrustRegistry,
) -> Result<(), AuthError> {
    let (expected, owner_signature) = decode_store(signed_store)?;
    if claim.store != expected
        || claim.custodian_epoch == 0
        || claim.custodian_epoch > i64::MAX as u64
        || claim.causal.seq == 0
        || claim.causal.digest == [0; 32]
        || expected.packet_len as usize != w3.len()
        || blake3::hash(w3).as_bytes() != &expected.digest
        || expected.expires_at <= 0
    {
        return Err(AuthError::Invalid);
    }
    let route = private_route_w3::inspect_route(w3).map_err(|_| AuthError::Invalid)?;
    if route.message_id != expected.message || route.expires_at_ms != expected.expires_at as u64 {
        return Err(AuthError::Invalid);
    }
    let owner = trust.key_for(expected.issuer, expected.issuer_epoch)
        .map_err(|_| AuthError::Unauthorized)?;
    owner.verify(&signed(STORE_DOMAIN, &signed_store[..STORE_BODY]), &owner_signature)
        .map_err(|_| AuthError::Unauthorized)?;
    let custodian = trust.key_for(expected.custodian, claim.custodian_epoch)
        .map_err(|_| AuthError::Unauthorized)?;
    custodian.verify(
        &stored_claim_body(claim),
        &Signature::from_bytes(&claim.signature),
    ).map_err(|_| AuthError::Unauthorized)?;
    Ok(())
}

fn id16(v: Vec<u8>) -> Result<[u8; 16], AuthError> {
    v.try_into().map_err(|_|AuthError::Corrupt)
}
fn load_policy(tx: &Transaction<'_>, mailbox: [u8; 16]) -> Result<Option<SavedPolicy>, AuthError> {
    type Row = (Vec<u8>, i64, Vec<u8>, Vec<u8>, Vec<u8>, i64, i64, i64, i64);
    let row: Option<Row> = tx.query_row(
        "SELECT issuer,issuer_epoch,custodian,scope,recipient,max_bytes,max_offers,store_revoked,fetch_revoked
         FROM custodian_mailbox_policy WHERE mailbox=?1",
        params![mailbox.as_slice()],
        |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,
               r.get(5)?,r.get(6)?,r.get(7)?,r.get(8)?)),
    ).optional()?;
    let Some((issuer,epoch,custodian,scope,recipient,bytes,offers,s,f)) = row else {
        return Ok(None);
    };
    let p = MailboxPolicy {
        mailbox,
        issuer: id16(issuer)?,
        issuer_epoch: u64::try_from(epoch).map_err(|_|AuthError::Corrupt)?,
        custodian: id16(custodian)?,
        scope: id16(scope)?,
        recipient: id16(recipient)?,
        max_message_bytes: u32::try_from(bytes).map_err(|_|AuthError::Corrupt)?,
        max_offers: u32::try_from(offers).map_err(|_|AuthError::Corrupt)?,
    };
    if !valid_policy(&p) || (s != 0 && s != 1) || (f != 0 && f != 1) {
        return Err(AuthError::Corrupt);
    }
    Ok(Some(SavedPolicy { policy: p, store_revoked: s == 1, fetch_revoked: f == 1 }))
}

impl Journal {
    fn ensure_custodian_mailbox_schema(&self) -> Result<(), AuthError> {
        self.db.execute_batch(
            "CREATE TABLE IF NOT EXISTS custodian_mailbox_policy(
               mailbox BLOB PRIMARY KEY CHECK(length(mailbox)=16),
               issuer BLOB NOT NULL CHECK(length(issuer)=16),
               issuer_epoch INTEGER NOT NULL CHECK(issuer_epoch>0),
               custodian BLOB NOT NULL CHECK(length(custodian)=16),
               scope BLOB NOT NULL CHECK(length(scope)=16),
               recipient BLOB NOT NULL CHECK(length(recipient)=16),
               max_bytes INTEGER NOT NULL CHECK(max_bytes BETWEEN 1 AND 16384),
               max_offers INTEGER NOT NULL CHECK(max_offers BETWEEN 1 AND 64),
               store_revoked INTEGER NOT NULL DEFAULT 0 CHECK(store_revoked IN (0,1)),
               fetch_revoked INTEGER NOT NULL DEFAULT 0 CHECK(fetch_revoked IN (0,1))
             );
             CREATE TABLE IF NOT EXISTS custodian_mailbox_offer(
               offer BLOB PRIMARY KEY CHECK(length(offer)=16),
               slot BLOB NOT NULL UNIQUE CHECK(length(slot)=16),
               mailbox BLOB NOT NULL CHECK(length(mailbox)=16),
               recipient BLOB NOT NULL CHECK(length(recipient)=16),
               message BLOB NOT NULL CHECK(length(message)=16),
               signed_grant BLOB NOT NULL CHECK(length(signed_grant)=253),
               state INTEGER NOT NULL CHECK(state IN (0,1)),
               UNIQUE(mailbox,recipient,message),
               FOREIGN KEY(mailbox) REFERENCES custodian_mailbox_policy(mailbox)
             );",
        )?;
        Ok(())
    }

    /// Trusted local operator only; never wire this directly to network input.
    /// New epoch is required for any policy change, including unrevocation.
    pub fn operator_provision_mailbox(
        &mut self, policy: MailboxPolicy, trust: &TrustRegistry,
    ) -> Result<(), AuthError> {
        if !valid_policy(&policy) { return Err(AuthError::Invalid); }
        trust.key_for(policy.issuer, policy.issuer_epoch)
            .map_err(|_|AuthError::Unauthorized)?;
        self.ensure_custodian_mailbox_schema()?;
        let tx = self.db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(old) = load_policy(&tx, policy.mailbox)? {
            if old.policy == policy {
                tx.commit()?;
                return Ok(());
            }
            if policy.issuer_epoch <= old.policy.issuer_epoch
                || policy.issuer != old.policy.issuer
                || policy.custodian != old.policy.custodian
                || policy.scope != old.policy.scope
                || policy.recipient != old.policy.recipient
            { return Err(AuthError::Conflict); }
            tx.execute(
                "UPDATE custodian_mailbox_policy SET issuer_epoch=?1,max_bytes=?2,
                 max_offers=?3,store_revoked=0,fetch_revoked=0 WHERE mailbox=?4",
                params![policy.issuer_epoch as i64,policy.max_message_bytes as i64,
                        policy.max_offers as i64,policy.mailbox.as_slice()],
            )?;
        } else {
            tx.execute(
                "INSERT INTO custodian_mailbox_policy
                 (mailbox,issuer,issuer_epoch,custodian,scope,recipient,max_bytes,max_offers)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
                params![policy.mailbox.as_slice(),policy.issuer.as_slice(),
                    policy.issuer_epoch as i64,policy.custodian.as_slice(),
                    policy.scope.as_slice(),policy.recipient.as_slice(),
                    policy.max_message_bytes as i64,policy.max_offers as i64],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// STORE revocation never deletes existing ciphertext or revokes FETCH.
    pub fn operator_revoke_store(&mut self, mailbox: [u8; 16]) -> Result<(), AuthError> {
        self.revoke_mailbox_action(mailbox, "store_revoked")
    }
    /// FETCH revocation is separate; old data remains stored and owned.
    pub fn operator_revoke_fetch(&mut self, mailbox: [u8; 16]) -> Result<(), AuthError> {
        self.revoke_mailbox_action(mailbox, "fetch_revoked")
    }
    fn revoke_mailbox_action(&mut self, mailbox: [u8; 16], column: &str)
        -> Result<(), AuthError>
    {
        self.ensure_custodian_mailbox_schema()?;
        let tx = self.db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        // Only internal constant column names from the two methods above.
        let query = format!("UPDATE custodian_mailbox_policy SET {column}=1 WHERE mailbox=?1");
        if tx.execute(&query, params![mailbox.as_slice()])? != 1 {
            return Err(AuthError::Unauthorized);
        }
        tx.commit()?;
        Ok(())
    }

    /// RequestStore: cheap bounded signed authorization and durable reservation.
    /// Repeated signed offers return the original state; never free a K slot
    /// merely because an ACK is missing.
    pub fn request_custodian_store(
        &mut self, signed_store: &[u8], trust: &TrustRegistry, now: i64,
    ) -> Result<Reservation, AuthError> {
        let (claims, _) = decode_store(signed_store)?;
        self.ensure_custodian_mailbox_schema()?;
        let tx = self.db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let policy = load_policy(&tx, claims.mailbox)?.ok_or(AuthError::Unauthorized)?;
        let claims = verify_store(signed_store, policy, trust, now)?;
        let old: Option<(Vec<u8>, i64)> = tx.query_row(
            "SELECT signed_grant,state FROM custodian_mailbox_offer WHERE offer=?1",
            params![claims.offer.as_slice()],
            |r| Ok((r.get(0)?,r.get(1)?)),
        ).optional()?;
        if let Some((saved,state)) = old {
            if saved != signed_store { return Err(AuthError::Conflict); }
            tx.commit()?;
            return match state {
                0 => Ok(Reservation::AlreadyReserved),
                1 => Ok(Reservation::AlreadyCommitted),
                _ => Err(AuthError::Corrupt),
            };
        }
        let used: i64 = tx.query_row(
            "SELECT count(*) FROM custodian_mailbox_offer WHERE mailbox=?1",
            params![claims.mailbox.as_slice()], |r| r.get(0),
        )?;
        if used >= i64::from(policy.policy.max_offers) { return Err(AuthError::Capacity); }
        let slot_occupied: i64 = tx.query_row(
            "SELECT count(*) FROM custodian_mailbox_offer WHERE slot=?1
             OR (mailbox=?2 AND recipient=?3 AND message=?4)",
            params![claims.slot.as_slice(),claims.mailbox.as_slice(),
                    claims.recipient.as_slice(),claims.message.as_slice()],
            |r| r.get(0),
        )?;
        if slot_occupied != 0 { return Err(AuthError::Conflict); }
        tx.execute(
            "INSERT INTO custodian_mailbox_offer
             (offer,slot,mailbox,recipient,message,signed_grant,state)
             VALUES(?1,?2,?3,?4,?5,?6,0)",
            params![claims.offer.as_slice(),claims.slot.as_slice(),
                    claims.mailbox.as_slice(),claims.recipient.as_slice(),
                    claims.message.as_slice(),signed_store],
        )?;
        tx.commit()?;
        Ok(Reservation::Reserved)
    }

    /// CommitStore: check current local policy and signed STORE grant under
    /// the SAME SQLite IMMEDIATE transaction as W12/W3 and reservation state.
    /// The signer is the separately enrolled custodian, never the mailbox owner.
    fn commit_custodian_store_verified(
        &mut self, locator: StoreLocator, w3: &[u8],
        custodian_signer: &SigningKey, custodian_epoch: u64,
        trust: &TrustRegistry, now: i64,
    ) -> Result<(CausalCommitment, StoreClaims), AuthError> {
        let StoreLocator { mailbox, offer } = locator;
        if w3.is_empty() || w3.len() > MAX_MESSAGE_BYTES { return Err(AuthError::Invalid); }
        self.ensure_custodian_mailbox_schema()?;
        self.ensure_w12_schema()?;
        let tx = self.db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let policy = load_policy(&tx, mailbox)?.ok_or(AuthError::Unauthorized)?;
        let row: Option<(Vec<u8>, i64)> = tx.query_row(
            "SELECT signed_grant,state FROM custodian_mailbox_offer
             WHERE mailbox=?1 AND offer=?2",
            params![mailbox.as_slice(),offer.as_slice()],
            |r| Ok((r.get(0)?,r.get(1)?)),
        ).optional()?;
        let (signed_store,state) = row.ok_or(AuthError::Unauthorized)?;
        if state != 0 && state != 1 { return Err(AuthError::Corrupt); }
        let claims = verify_store(&signed_store, policy, trust, now)?;
        if claims.offer != offer || claims.mailbox != mailbox
            || claims.packet_len as usize != w3.len()
            || blake3::hash(w3).as_bytes() != &claims.digest
        { return Err(AuthError::Conflict); }
        let req = CausalRequest {
            private_scope: claims.scope,
            custodian_id: claims.custodian,
            custodian_epoch,
            recipient: claims.recipient,
            message: claims.message,
            expiry_ms: claims.expires_at,
        };
        // Custodian identity and epoch are separate from owner STORE authority.
        trust.verify(claims.custodian, custodian_epoch, &custodian_signer.verifying_key())
            .map_err(|_|AuthError::Unauthorized)?;
        let result = Self::enqueue_w3_with_causal_tx(
            &tx, req, w3, custodian_signer, trust,
        )?;
        tx.execute(
            "UPDATE custodian_mailbox_offer SET state=1 WHERE mailbox=?1 AND offer=?2",
            params![mailbox.as_slice(),offer.as_slice()],
        )?;
        tx.commit()?;
        Ok((result, claims))
    }

    /// Safe ordering for a one-message network adapter: reject wrong or
    /// malformed ciphertext BEFORE reserving a one-use custody slot.
    /// The independently signed STORE grant and policy are still verified
    /// under SQLite IMMEDIATE at RequestStore and again at CommitStore.
    pub fn accept_custodian_store_and_claim(
        &mut self,
        signed_store: &[u8],
        w3: &[u8],
        custodian_signer: &SigningKey,
        custodian_epoch: u64,
        trust: &TrustRegistry,
        now: i64,
    ) -> Result<CustodianStoredClaim, AuthError> {
        let (claims, _) = decode_store(signed_store)?;
        if w3.is_empty()
            || w3.len() > MAX_MESSAGE_BYTES
            || claims.packet_len as usize != w3.len()
            || blake3::hash(w3).as_bytes() != &claims.digest
        {
            return Err(AuthError::Invalid);
        }
        let route = private_route_w3::inspect_route(w3).map_err(|_| AuthError::Invalid)?;
        if route.message_id != claims.message || route.expires_at_ms != claims.expires_at as u64 {
            return Err(AuthError::Invalid);
        }
        self.request_custodian_store(signed_store, trust, now)?;
        self.commit_custodian_store_with_claim(
            StoreLocator {
                mailbox: claims.mailbox,
                offer: claims.offer,
            },
            w3,
            custodian_signer,
            custodian_epoch,
            trust,
            now,
        )
    }

    /// Existing low-level lab entrypoint remains compatible with its original
    /// causal return value. It does NOT return a signed custodian receipt.
    pub fn commit_custodian_store(
        &mut self, locator: StoreLocator, w3: &[u8],
        custodian_signer: &SigningKey, custodian_epoch: u64,
        trust: &TrustRegistry, now: i64,
    ) -> Result<CausalCommitment, AuthError> {
        self.commit_custodian_store_verified(
            locator, w3, custodian_signer, custodian_epoch, trust, now,
        ).map(|(causal, _)| causal)
    }

    /// Sign only AFTER the same-DB STORE reservation, exact W3, and W12
    /// have committed. After lost ACK, replay signs the same immutable claim.
    /// A CustodianStoredClaim is a bounded custodian assertion, not recipient W4
    /// and not proof that a malicious server retained the bytes.
    pub fn commit_custodian_store_with_claim(
        &mut self, locator: StoreLocator, w3: &[u8],
        custodian_signer: &SigningKey, custodian_epoch: u64,
        trust: &TrustRegistry, now: i64,
    ) -> Result<CustodianStoredClaim, AuthError> {
        let (causal, store) = self.commit_custodian_store_verified(
            locator, w3, custodian_signer, custodian_epoch, trust, now,
        )?;
        let mut claim = CustodianStoredClaim {
            store,
            custodian_epoch,
            causal,
            signature: [0; 64],
        };
        claim.signature = custodian_signer.sign(&stored_claim_body(&claim)).to_bytes();
        Ok(claim)
    }

    /// FETCH is a separate signed capability. A public W3 route tag,
    /// valid STORE grant or CustodianStored claim cannot authorize this read.
    /// Unauthorized requests must not reveal mailbox existence or count.
    pub fn fetch_custodian_authorized(
        &mut self, signed_fetch: &[u8], trust: &TrustRegistry, now: i64,
    ) -> Result<Option<Vec<u8>>, AuthError> {
        let (claims, _) = decode_fetch(signed_fetch)?;
        self.ensure_custodian_mailbox_schema()?;
        let tx = self.db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let policy = load_policy(&tx, claims.mailbox)?.ok_or(AuthError::Unauthorized)?;
        let claims = verify_fetch(signed_fetch, policy, trust, now)?;
        type Row = (Vec<u8>, Vec<u8>, Vec<u8>, i64);
        let row: Option<Row> = tx.query_row(
            "SELECT o.signed_grant,b.packet,b.digest,b.expiry
             FROM custodian_mailbox_offer o
             JOIN outbox b ON b.recipient=o.recipient AND b.message=o.message
             WHERE o.mailbox=?1 AND o.recipient=?2 AND o.message=?3 AND o.state=1",
            params![claims.mailbox.as_slice(),claims.recipient.as_slice(),
                    claims.message.as_slice()],
            |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)),
        ).optional()?;
        let Some((original_grant,packet,dbhash,expiry)) = row else {
            tx.commit()?;
            return Ok(None);
        };
        let (original, _) = decode_store(&original_grant).map_err(|_|AuthError::Corrupt)?;
        if original.digest != claims.digest || dbhash.as_slice() != claims.digest.as_slice()
            || blake3::hash(&packet).as_bytes() != &claims.digest
            || expiry != original.expires_at
        { return Err(AuthError::Corrupt); }
        let hint = private_route_w3::inspect_route(&packet).map_err(|_|AuthError::Corrupt)?;
        if hint.message_id != claims.message
            || hint.expires_at_ms != expiry as u64
        { return Err(AuthError::Corrupt); }
        if now >= expiry { return Err(AuthError::Expired); }
        tx.commit()?;
        Ok(Some(packet))
    }
}

