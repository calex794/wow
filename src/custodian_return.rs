//! Laboratory-only private W4 return mailbox for the EXISTING custodian W3.
//! Recipient stores a fixed-size HPKE envelope containing its durable, signed
//! final W4. The custodian can authenticate deposit authority but CANNOT read
//! W4, forge recipient delivery, or update the sender's delivery ledger.
//!
//! A separately enrolled sender registers one opaque tag after W3 STORE.
//! Recipient deposits encrypted W4 with its own domain-separated signature.
//! The sender polls through an independently signed short-lived read proof.
//! Local SQLite and loopback tests only: NOT a public transport or VPS daemon.
use crate::{
    custodian_invitation::verify_invitation_for_sender,
    custodian_mailbox::{decode_store, load_policy, AuthError, SavedPolicy},
    journal_w4::Journal,
    private_return_w4::{self, ENVELOPE_LEN},
    private_route_w3,
    trust_w3::TrustRegistry,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use rusqlite::{params, OptionalExtension, TransactionBehavior};

const ROUTE_DOMAIN: &[u8] = b"Akula/WOW/Custodian/W4-RETURN-ROUTE/lab-v0\0";
const DEPOSIT_DOMAIN: &[u8] = b"Akula/WOW/Custodian/W4-RETURN-DEPOSIT/lab-v0\0";
const READ_DOMAIN: &[u8] = b"Akula/WOW/Custodian/W4-RETURN-READ/lab-v0\0";
const VERSION: u8 = 1;
const ROUTE_BODY: usize = 1 + 16 * 6 + 8 * 3 + 32;
const DEPOSIT_BODY: usize = 1 + 16 * 5 + 8 * 2 + 32 * 2;
const READ_BODY: usize = 1 + 16 * 5 + 8 * 2;
const SIGNATURE_BYTES: usize = 64;
pub const ROUTE_BYTES: usize = ROUTE_BODY + SIGNATURE_BYTES;
pub const DEPOSIT_BYTES: usize = DEPOSIT_BODY + SIGNATURE_BYTES;
pub const READ_BYTES: usize = READ_BODY + SIGNATURE_BYTES;
const MAX_READ_TTL_MS: i64 = 5 * 60 * 1000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReturnRoute {
    pub sender: [u8;16],
    pub sender_epoch: u64,
    pub custodian: [u8;16],
    pub mailbox: [u8;16],
    pub recipient: [u8;16],
    pub message: [u8;16],
    pub digest: [u8;32],
    pub expires_at_ms: i64,
    pub tag: [u8;16],
    pub grant_until_ms: i64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReturnDeposit {
    pub recipient: [u8;16],
    pub recipient_epoch: u64,
    pub custodian: [u8;16],
    pub mailbox: [u8;16],
    pub message: [u8;16],
    pub digest: [u8;32],
    pub tag: [u8;16],
    pub envelope_digest: [u8;32],
    pub grant_until_ms: i64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReturnRead {
    pub sender: [u8;16],
    pub sender_epoch: u64,
    pub custodian: [u8;16],
    pub mailbox: [u8;16],
    pub tag: [u8;16],
    pub nonce: [u8;16],
    pub grant_until_ms: i64,
}
fn take<const N: usize>(b: &[u8], at: &mut usize) -> [u8;N] {
    let mut out=[0u8;N];
    out.copy_from_slice(&b[*at..*at+N]);
    *at+=N;
    out
}
fn sign(domain: &[u8], body: &[u8], signer: &SigningKey) -> Vec<u8> {
    let mut message=Vec::with_capacity(domain.len()+body.len());
    message.extend_from_slice(domain);
    message.extend_from_slice(body);
    let mut result=body.to_vec();
    result.extend_from_slice(&signer.sign(&message).to_bytes());
    result
}
fn verify_sig(raw: &[u8], body_len: usize, domain: &[u8],
              key: &ed25519_dalek::VerifyingKey) -> Result<(),AuthError> {
    let signature=Signature::from_slice(&raw[body_len..])
        .map_err(|_|AuthError::Invalid)?;
    let mut message=Vec::with_capacity(domain.len()+body_len);
    message.extend_from_slice(domain);
    message.extend_from_slice(&raw[..body_len]);
    key.verify(&message,&signature).map_err(|_|AuthError::Unauthorized)
}
fn route_body(c: ReturnRoute) -> Vec<u8> {
    let mut v=Vec::with_capacity(ROUTE_BODY);
    v.push(VERSION);
    v.extend_from_slice(&c.sender);
    v.extend_from_slice(&c.sender_epoch.to_be_bytes());
    for f in [c.custodian,c.mailbox,c.recipient,c.message] {
        v.extend_from_slice(&f);
    }
    v.extend_from_slice(&c.digest);
    v.extend_from_slice(&c.expires_at_ms.to_be_bytes());
    v.extend_from_slice(&c.tag);
    v.extend_from_slice(&c.grant_until_ms.to_be_bytes());
    debug_assert_eq!(v.len(),ROUTE_BODY);
    v
}
fn decode_route(raw: &[u8]) -> Result<ReturnRoute,AuthError> {
    if raw.len()!=ROUTE_BYTES || raw[0]!=VERSION {return Err(AuthError::Invalid);}
    let mut pos=1;
    let c=ReturnRoute {
        sender:take(raw,&mut pos),
        sender_epoch:u64::from_be_bytes(take(raw,&mut pos)),
        custodian:take(raw,&mut pos),
        mailbox:take(raw,&mut pos),
        recipient:take(raw,&mut pos),
        message:take(raw,&mut pos),
        digest:take(raw,&mut pos),
        expires_at_ms:i64::from_be_bytes(take(raw,&mut pos)),
        tag:take(raw,&mut pos),
        grant_until_ms:i64::from_be_bytes(take(raw,&mut pos)),
    };
    debug_assert_eq!(pos,ROUTE_BODY);
    Ok(c)
}
fn deposit_body(c:ReturnDeposit)->Vec<u8>{
    let mut v=Vec::with_capacity(DEPOSIT_BODY);
    v.push(VERSION);
    v.extend_from_slice(&c.recipient);
    v.extend_from_slice(&c.recipient_epoch.to_be_bytes());
    for f in [c.custodian,c.mailbox,c.message] {v.extend_from_slice(&f);}
    v.extend_from_slice(&c.digest);
    v.extend_from_slice(&c.tag);
    v.extend_from_slice(&c.envelope_digest);
    v.extend_from_slice(&c.grant_until_ms.to_be_bytes());
    debug_assert_eq!(v.len(),DEPOSIT_BODY);
    v
}
fn decode_deposit(raw:&[u8])->Result<ReturnDeposit,AuthError>{
    if raw.len()!=DEPOSIT_BYTES || raw[0]!=VERSION {return Err(AuthError::Invalid);}
    let mut pos=1;
    let c=ReturnDeposit{
        recipient:take(raw,&mut pos),
        recipient_epoch:u64::from_be_bytes(take(raw,&mut pos)),
        custodian:take(raw,&mut pos),
        mailbox:take(raw,&mut pos),
        message:take(raw,&mut pos),
        digest:take(raw,&mut pos),
        tag:take(raw,&mut pos),
        envelope_digest:take(raw,&mut pos),
        grant_until_ms:i64::from_be_bytes(take(raw,&mut pos)),
    };
    debug_assert_eq!(pos,DEPOSIT_BODY);
    Ok(c)
}
fn read_body(c:ReturnRead)->Vec<u8>{
    let mut v=Vec::with_capacity(READ_BODY);
    v.push(VERSION);
    v.extend_from_slice(&c.sender);
    v.extend_from_slice(&c.sender_epoch.to_be_bytes());
    for f in [c.custodian,c.mailbox,c.tag,c.nonce]{v.extend_from_slice(&f);}
    v.extend_from_slice(&c.grant_until_ms.to_be_bytes());
    debug_assert_eq!(v.len(),READ_BODY);
    v
}
fn decode_read(raw:&[u8])->Result<ReturnRead,AuthError>{
    if raw.len()!=READ_BYTES || raw[0]!=VERSION{return Err(AuthError::Invalid);}
    let mut pos=1;
    let c=ReturnRead{
        sender:take(raw,&mut pos),
        sender_epoch:u64::from_be_bytes(take(raw,&mut pos)),
        custodian:take(raw,&mut pos),
        mailbox:take(raw,&mut pos),
        tag:take(raw,&mut pos),
        nonce:take(raw,&mut pos),
        grant_until_ms:i64::from_be_bytes(take(raw,&mut pos)),
    };
    debug_assert_eq!(pos,READ_BODY);
    Ok(c)
}

/// Only local lab issuance; caller pins sender/recipient identities outside C.
pub fn sign_return_route_for_lab(signer:&SigningKey,claims:ReturnRoute)->Vec<u8>{
    sign(ROUTE_DOMAIN,&route_body(claims),signer)
}
pub fn sign_return_deposit_for_lab(signer:&SigningKey,claims:ReturnDeposit)->Vec<u8>{
    sign(DEPOSIT_DOMAIN,&deposit_body(claims),signer)
}
pub fn sign_return_read_for_lab(signer:&SigningKey,claims:ReturnRead)->Vec<u8>{
    sign(READ_DOMAIN,&read_body(claims),signer)
}
fn authorize_route(raw:&[u8], policy:SavedPolicy,trust:&TrustRegistry,now:i64)
    ->Result<ReturnRoute,AuthError> {
    let c=decode_route(raw)?;
    let p=policy.policy;
    if policy.store_revoked || c.custodian!=p.custodian
        || c.mailbox!=p.mailbox || c.recipient!=p.recipient {
        return Err(AuthError::Unauthorized);
    }
    if c.sender==[0;16] || c.sender_epoch==0 || c.sender_epoch>i64::MAX as u64
        || c.message==[0;16] || c.digest==[0;32] || c.tag==[0;16]
        || c.expires_at_ms<=0 || c.grant_until_ms<=0
        || c.grant_until_ms>c.expires_at_ms
        || now<0 || now>=c.grant_until_ms || now>=c.expires_at_ms {
        return Err(AuthError::Expired);
    }
    let key=trust.key_for(c.sender,c.sender_epoch).map_err(|_|AuthError::Unauthorized)?;
    verify_sig(raw,ROUTE_BODY,ROUTE_DOMAIN,key)?;
    Ok(c)
}
fn authorize_deposit(raw:&[u8], policy:SavedPolicy, route:ReturnRoute,
                     envelope:&[u8],trust:&TrustRegistry,now:i64)
    ->Result<ReturnDeposit,AuthError>{
    let c=decode_deposit(raw)?;
    if policy.store_revoked || c.recipient!=route.recipient
        || c.custodian!=route.custodian || c.mailbox!=route.mailbox
        || c.message!=route.message || c.digest!=route.digest || c.tag!=route.tag {
        return Err(AuthError::Unauthorized);
    }
    if c.recipient_epoch==0 || c.recipient_epoch>i64::MAX as u64
        || now<0 || c.grant_until_ms<=now || now>=route.expires_at_ms
        || c.grant_until_ms>route.expires_at_ms
        || envelope.len()!=ENVELOPE_LEN
        || blake3::hash(envelope).as_bytes()!=&c.envelope_digest {
        return Err(AuthError::Invalid);
    }
    if private_return_w4::inspect_route(envelope).map_err(|_|AuthError::Invalid)?!=c.tag {
        return Err(AuthError::Unauthorized);
    }
    let key=trust.key_for(c.recipient,c.recipient_epoch).map_err(|_|AuthError::Unauthorized)?;
    verify_sig(raw,DEPOSIT_BODY,DEPOSIT_DOMAIN,key)?;
    Ok(c)
}
fn authorize_read(raw:&[u8], policy:SavedPolicy,route:ReturnRoute,
                  trust:&TrustRegistry,now:i64)->Result<ReturnRead,AuthError>{
    let c=decode_read(raw)?;
    if policy.fetch_revoked || c.sender!=route.sender
        || c.sender_epoch!=route.sender_epoch
        || c.custodian!=route.custodian
        || c.mailbox!=route.mailbox || c.tag!=route.tag {
        return Err(AuthError::Unauthorized);
    }
    if now<0 || now>=route.expires_at_ms || c.nonce==[0;16]
        || c.grant_until_ms<=now
        || c.grant_until_ms>route.expires_at_ms
        || c.grant_until_ms-now>MAX_READ_TTL_MS {
        return Err(AuthError::Expired);
    }
    let key=trust.key_for(c.sender,c.sender_epoch).map_err(|_|AuthError::Unauthorized)?;
    verify_sig(raw,READ_BODY,READ_DOMAIN,key)?;
    Ok(c)
}

impl Journal {
    fn ensure_custodian_return_schema(&self)->Result<(),AuthError>{
        self.ensure_custodian_mailbox_schema()?;
        self.db.execute_batch(
            "CREATE TABLE IF NOT EXISTS custodian_private_w4_return(
                tag BLOB PRIMARY KEY CHECK(length(tag)=16),
                mailbox BLOB NOT NULL CHECK(length(mailbox)=16),
                sender BLOB NOT NULL CHECK(length(sender)=16),
                recipient BLOB NOT NULL CHECK(length(recipient)=16),
                message BLOB NOT NULL CHECK(length(message)=16),
                signed_route BLOB NOT NULL CHECK(length(signed_route)=217),
                envelope BLOB CHECK(envelope IS NULL OR length(envelope)=202),
                envelope_digest BLOB CHECK(envelope_digest IS NULL OR length(envelope_digest)=32),
                CHECK ((envelope IS NULL) = (envelope_digest IS NULL)),
                UNIQUE(mailbox,recipient,message)
            );"
        )?;
        Ok(())
    }

    /// Sender registers an opaque return location only after the exact
    /// delegated W3 STORE is committed. Never mint a return slot from a
    /// public route token or unsigned network parameters.
    pub fn register_private_w4_return(
        &mut self,signed_route:&[u8],trust:&TrustRegistry,now_ms:i64,
    )->Result<bool,AuthError>{
        let hint=decode_route(signed_route)?;
        self.ensure_custodian_return_schema()?;
        let tx=self.db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let policy=load_policy(&tx, hint.mailbox, self.mail_role_gate)?.ok_or(AuthError::Unauthorized)?;
        let route=authorize_route(signed_route,policy,trust,now_ms)?;
        type Entry=(Vec<u8>,Vec<u8>,Vec<u8>,Vec<u8>,i64,Vec<u8>);
        let stored:Option<Entry>=tx.query_row(
            "SELECT o.signed_grant,d.signed_invitation,b.packet,b.digest,b.expiry,o.message
             FROM custodian_mailbox_offer o
             JOIN custodian_mailbox_delegated_offer d ON d.offer=o.offer
             JOIN outbox b ON b.recipient=o.recipient AND b.message=o.message
             WHERE o.mailbox=?1 AND o.recipient=?2 AND o.message=?3 AND o.state=1",
            params![route.mailbox.as_slice(),route.recipient.as_slice(),route.message.as_slice()],
            |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?)),
        ).optional()?;
        let (signed_store,invitation,packet,digest,expiry,message)=stored.ok_or(AuthError::Unauthorized)?;
        let (store, _)=decode_store(&signed_store)?;
        let invite=verify_invitation_for_sender(
            &invitation,policy.policy.issuer,route.custodian,route.sender,trust,now_ms,
        )?;
        let hint=private_route_w3::inspect_route(&packet).map_err(|_|AuthError::Corrupt)?;
        if invite.sender_epoch!=route.sender_epoch || invite.mailbox!=route.mailbox
            || invite.recipient!=route.recipient || invite.scope!=store.scope
            || hint.token!=invite.route_token
            || store.message!=route.message || store.digest!=route.digest
            || store.expires_at!=route.expires_at_ms
            || digest.as_slice()!=route.digest.as_slice()
            || blake3::hash(&packet).as_bytes()!=&route.digest
            || expiry!=route.expires_at_ms || message.as_slice()!=route.message.as_slice() {
            return Err(AuthError::Unauthorized);
        }
        let existing:Option<Vec<u8>>=tx.query_row(
            "SELECT signed_route FROM custodian_private_w4_return WHERE tag=?1",
            params![route.tag.as_slice()],|r|r.get(0),
        ).optional()?;
        if let Some(old)=existing {
            if old!=signed_route {return Err(AuthError::Conflict);}
            tx.commit()?;
            return Ok(false);
        }
        let taken:Option<i64>=tx.query_row(
            "SELECT 1 FROM custodian_private_w4_return
             WHERE mailbox=?1 AND recipient=?2 AND message=?3",
            params![route.mailbox.as_slice(),route.recipient.as_slice(),route.message.as_slice()],
            |r|r.get(0),
        ).optional()?;
        if taken.is_some(){return Err(AuthError::Conflict);}
        tx.execute(
            "INSERT INTO custodian_private_w4_return
             (tag,mailbox,sender,recipient,message,signed_route)
             VALUES(?1,?2,?3,?4,?5,?6)",
            params![route.tag.as_slice(),route.mailbox.as_slice(),route.sender.as_slice(),
                route.recipient.as_slice(),route.message.as_slice(),signed_route],
        )?;
        tx.commit()?;
        Ok(true)
    }

    /// A recipient-specific signed deposit only stores opaque ciphertext.
    /// It does NOT advance sender delivery status or constitute validated W4.
    /// Ambiguous ACK must be replayed with the SAME envelope/signature bytes.
    pub fn deposit_private_w4_return(
        &mut self,signed_deposit:&[u8],envelope:&[u8],
        trust:&TrustRegistry,now_ms:i64,
    )->Result<bool,AuthError>{
        let claims=decode_deposit(signed_deposit)?;
        self.ensure_custodian_return_schema()?;
        let tx=self.db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        type Entry=(Vec<u8>,Option<Vec<u8>>,Option<Vec<u8>>);
        let row:Option<Entry>=tx.query_row(
            "SELECT signed_route,envelope,envelope_digest
             FROM custodian_private_w4_return WHERE tag=?1",
            params![claims.tag.as_slice()],
            |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)),
        ).optional()?;
        let (signed_route,stored,stored_hash)=row.ok_or(AuthError::Unauthorized)?;
        let route_hint=decode_route(&signed_route)?;
        let policy=load_policy(&tx, route_hint.mailbox, self.mail_role_gate)?.ok_or(AuthError::Unauthorized)?;
        let route=authorize_route(&signed_route,policy,trust,now_ms)?;
        authorize_deposit(signed_deposit,policy,route,envelope,trust,now_ms)?;
        if let Some(old)=stored {
            if old!=envelope || stored_hash.as_deref()!=Some(claims.envelope_digest.as_slice()) {
                return Err(AuthError::Conflict);
            }
            tx.commit()?;
            return Ok(false);
        }
        tx.execute(
            "UPDATE custodian_private_w4_return SET envelope=?2,envelope_digest=?3
             WHERE tag=?1 AND envelope IS NULL",
            params![claims.tag.as_slice(),envelope,claims.envelope_digest.as_slice()],
        )?;
        tx.commit()?;
        Ok(true)
    }

    /// The sender's independent short-lived signing proof gates readback.
    /// C returns identical opaque bytes after any restart or lost read reply;
    /// only the sender can decrypt and apply a real recipient-signed W4.
    pub fn fetch_private_w4_return(
        &mut self,signed_read:&[u8],trust:&TrustRegistry,now_ms:i64,
    )->Result<Option<Vec<u8>>,AuthError>{
        let claims=decode_read(signed_read)?;
        self.ensure_custodian_return_schema()?;
        let tx=self.db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        type Entry=(Vec<u8>,Option<Vec<u8>>,Option<Vec<u8>>);
        let row:Option<Entry>=tx.query_row(
            "SELECT signed_route,envelope,envelope_digest
             FROM custodian_private_w4_return WHERE tag=?1",
            params![claims.tag.as_slice()],
            |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)),
        ).optional()?;
        let (signed_route,stored,stored_hash)=row.ok_or(AuthError::Unauthorized)?;
        let route_hint=decode_route(&signed_route)?;
        let policy=load_policy(&tx, route_hint.mailbox, self.mail_role_gate)?.ok_or(AuthError::Unauthorized)?;
        // A revoked STORE grant does not erase already deposited returns, so
        // use explicit sender read proof and current FETCH revocation here.
        let route=decode_route(&signed_route)?;
        let sender=trust.key_for(route.sender,route.sender_epoch)
            .map_err(|_|AuthError::Unauthorized)?;
        verify_sig(&signed_route,ROUTE_BODY,ROUTE_DOMAIN,sender)?;
        authorize_read(signed_read,policy,route,trust,now_ms)?;
        let result=match stored {
            None=>None,
            Some(bytes)=>{
                if stored_hash.as_deref()!=Some(blake3::hash(&bytes).as_bytes().as_slice())
                    || private_return_w4::inspect_route(&bytes)
                       .map_err(|_|AuthError::Corrupt)? != route.tag {
                    return Err(AuthError::Corrupt);
                }
                Some(bytes)
            }
        };
        tx.commit()?;
        Ok(result)
    }
}
