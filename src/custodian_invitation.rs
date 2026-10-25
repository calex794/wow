//! Lab-only one-off mailbox invitation for a sender who will create W3
//! after the recipient has gone offline. Owner signs a SINGLE offer/slot,
//! sender signs the actual W3 digest under that offer, C checks both.
//! This is NOT recipient identity/W3 decryption, not public enrollment,
//! not a production trust/clock service, and never authorizes FETCH or W4.
use crate::{
    custodian_mailbox::{
        decode_store, load_policy, stored_claim_body, AuthError, CustodianStoredClaim,
        MailboxPolicy, Reservation, SavedPolicy, StoreClaims, StoreLocator, STORE_BODY,
        STORE_DOMAIN,
    },
    journal_w4::Journal,
    crypto_w3::RecipientPublic,
    private_route_w3,
    trust_w3::TrustRegistry,
    MAX_MESSAGE_BYTES,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use hpke::Deserializable;
use rusqlite::{params, OptionalExtension, TransactionBehavior};

const DOMAIN: &[u8] = b"Akula/WOW/Custodian/ONE-SLOT-INVITE/lab-v0\0";
const VERSION: u8 = 1;
const BODY_LEN: usize = 1 + 8 * 16 + 8 * 3 + 4 + 32 + 16;
pub const INVITATION_BYTES: usize = BODY_LEN + 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MailboxInvitation {
    pub issuer: [u8; 16],
    pub issuer_epoch: u64,
    pub custodian: [u8; 16],
    pub mailbox: [u8; 16],
    pub scope: [u8; 16],
    pub recipient: [u8; 16],
    pub sender: [u8; 16],
    pub sender_epoch: u64,
    pub offer: [u8; 16],
    pub slot: [u8; 16],
    pub max_packet_bytes: u32,
    pub valid_until_ms: i64,
    /// Owner-authenticated W3 encryption public key and private-route token.
    pub recipient_hpke_public: [u8; 32],
    pub route_token: [u8; 16],
}

fn encode(c: MailboxInvitation) -> Vec<u8> {
    let mut out = Vec::with_capacity(BODY_LEN);
    out.push(VERSION);
    out.extend_from_slice(&c.issuer);
    out.extend_from_slice(&c.issuer_epoch.to_be_bytes());
    for value in [c.custodian, c.mailbox, c.scope, c.recipient, c.sender] {
        out.extend_from_slice(&value);
    }
    out.extend_from_slice(&c.sender_epoch.to_be_bytes());
    out.extend_from_slice(&c.offer);
    out.extend_from_slice(&c.slot);
    out.extend_from_slice(&c.max_packet_bytes.to_be_bytes());
    out.extend_from_slice(&c.valid_until_ms.to_be_bytes());
    out.extend_from_slice(&c.recipient_hpke_public);
    out.extend_from_slice(&c.route_token);
    debug_assert_eq!(out.len(), BODY_LEN);
    out
}

fn take<const N: usize>(raw: &[u8], pos: &mut usize) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(&raw[*pos..*pos + N]);
    *pos += N;
    out
}

fn decode(raw: &[u8]) -> Result<(MailboxInvitation, Signature), AuthError> {
    if raw.len() != INVITATION_BYTES || raw[0] != VERSION {
        return Err(AuthError::Invalid);
    }
    let mut pos = 1;
    let invite = MailboxInvitation {
        issuer: take(raw, &mut pos),
        issuer_epoch: u64::from_be_bytes(take(raw, &mut pos)),
        custodian: take(raw, &mut pos),
        mailbox: take(raw, &mut pos),
        scope: take(raw, &mut pos),
        recipient: take(raw, &mut pos),
        sender: take(raw, &mut pos),
        sender_epoch: u64::from_be_bytes(take(raw, &mut pos)),
        offer: take(raw, &mut pos),
        slot: take(raw, &mut pos),
        max_packet_bytes: u32::from_be_bytes(take(raw, &mut pos)),
        valid_until_ms: i64::from_be_bytes(take(raw, &mut pos)),
        recipient_hpke_public: take(raw, &mut pos),
        route_token: take(raw, &mut pos),
    };
    debug_assert_eq!(pos, BODY_LEN);
    let signature = Signature::from_slice(&raw[BODY_LEN..]).map_err(|_| AuthError::Invalid)?;
    Ok((invite, signature))
}

/// Privileged test helper: one invitation authorizes only its own offer/slot.
pub fn sign_invitation_for_lab(owner: &SigningKey, invite: MailboxInvitation) -> Vec<u8> {
    let mut bytes = encode(invite);
    let mut signed = Vec::with_capacity(DOMAIN.len() + BODY_LEN);
    signed.extend_from_slice(DOMAIN);
    signed.extend_from_slice(&bytes);
    bytes.extend_from_slice(&owner.sign(&signed).to_bytes());
    bytes
}

fn verify_invitation(
    raw: &[u8],
    policy: SavedPolicy,
    trust: &TrustRegistry,
    now_ms: i64,
) -> Result<MailboxInvitation, AuthError> {
    let (invite, sig) = decode(raw)?;
    let p = policy.policy;
    if policy.store_revoked
        || invite.issuer != p.issuer
        || invite.issuer_epoch != p.issuer_epoch
        || invite.custodian != p.custodian
        || invite.mailbox != p.mailbox
        || invite.scope != p.scope
        || invite.recipient != p.recipient
    {
        return Err(AuthError::Unauthorized);
    }
    if invite.sender == [0; 16] || invite.sender_epoch == 0
        || invite.sender_epoch > i64::MAX as u64
        || invite.offer == [0; 16] || invite.slot == [0; 16]
        || invite.max_packet_bytes == 0
        || invite.max_packet_bytes > p.max_message_bytes
        || invite.valid_until_ms <= 0
        || invite.route_token == [0; 16]
        || invite.recipient_hpke_public == [0; 32]
        || now_ms < 0 || now_ms >= invite.valid_until_ms
    {
        return Err(AuthError::Invalid);
    }
    RecipientPublic::from_bytes(&invite.recipient_hpke_public)
        .map_err(|_| AuthError::Invalid)?;
    let owner = trust.key_for(p.issuer, p.issuer_epoch)
        .map_err(|_| AuthError::Unauthorized)?;
    let mut signed = Vec::with_capacity(DOMAIN.len() + BODY_LEN);
    signed.extend_from_slice(DOMAIN);
    signed.extend_from_slice(&raw[..BODY_LEN]);
    owner.verify(&signed, &sig).map_err(|_| AuthError::Unauthorized)?;
    // The sender identity and epoch must be independently enrolled by the
    // operator; the signed invitation cannot enroll a network key by itself.
    trust.key_for(invite.sender, invite.sender_epoch)
        .map_err(|_| AuthError::Unauthorized)?;
    Ok(invite)
}

/// Sender-side verification of the original invitation before generating W3.
/// The caller pins the expected owner/custodian IDs and authenticates the owner
/// enrollment independently; no public network key is automatically trusted.
pub fn verify_invitation_for_sender(
    signed_invitation: &[u8],
    expected_owner: [u8; 16],
    expected_custodian: [u8; 16],
    expected_sender: [u8; 16],
    trust: &TrustRegistry,
    now_ms: i64,
) -> Result<MailboxInvitation, AuthError> {
    let (invite, sig) = decode(signed_invitation)?;
    if invite.issuer != expected_owner
        || invite.custodian != expected_custodian
        || invite.sender != expected_sender
        || invite.mailbox == [0; 16]
        || invite.scope == [0; 16]
        || invite.recipient == [0; 16]
        || invite.issuer_epoch == 0
        || invite.sender_epoch == 0
        || invite.offer == [0; 16]
        || invite.slot == [0; 16]
        || invite.max_packet_bytes == 0
        || invite.max_packet_bytes as usize > MAX_MESSAGE_BYTES
        || invite.route_token == [0; 16]
        || invite.recipient_hpke_public == [0; 32]
        || now_ms < 0
        || now_ms >= invite.valid_until_ms
    {
        return Err(AuthError::Invalid);
    }
    RecipientPublic::from_bytes(&invite.recipient_hpke_public)
        .map_err(|_| AuthError::Invalid)?;
    let owner = trust.key_for(invite.issuer, invite.issuer_epoch)
        .map_err(|_| AuthError::Unauthorized)?;
    let mut signed = Vec::with_capacity(DOMAIN.len() + BODY_LEN);
    signed.extend_from_slice(DOMAIN);
    signed.extend_from_slice(&signed_invitation[..BODY_LEN]);
    owner.verify(&signed, &sig).map_err(|_| AuthError::Unauthorized)?;
    trust.key_for(invite.sender, invite.sender_epoch)
        .map_err(|_| AuthError::Unauthorized)?;
    Ok(invite)
}

impl MailboxInvitation {
    /// Only use after verifying the signed invitation with a pinned owner.
    pub fn recipient_public(&self) -> Result<RecipientPublic, AuthError> {
        RecipientPublic::from_bytes(&self.recipient_hpke_public).map_err(|_| AuthError::Invalid)
    }
}

/// Current policy, owner invitation, sender proof and exact W3 object fields
/// must ALL agree. Caller must invoke under the same SQLite IMMEDIATE write
/// transaction that reserves/commits, rather than verifying then trusting it.
pub(crate) fn verify_delegated_store(
    signed_store: &[u8],
    signed_invitation: &[u8],
    policy: SavedPolicy,
    trust: &TrustRegistry,
    now_ms: i64,
) -> Result<StoreClaims, AuthError> {
    let invite = verify_invitation(signed_invitation, policy, trust, now_ms)?;
    let (claims, sender_sig) = decode_store(signed_store)?;
    if claims.issuer != invite.issuer
        || claims.issuer_epoch != invite.issuer_epoch
        || claims.custodian != invite.custodian
        || claims.mailbox != invite.mailbox
        || claims.scope != invite.scope
        || claims.recipient != invite.recipient
        || claims.offer != invite.offer
        || claims.slot != invite.slot
        || claims.message == [0; 16]
        || claims.packet_len == 0
        || claims.packet_len > invite.max_packet_bytes
        || claims.expires_at <= now_ms
        || claims.expires_at > invite.valid_until_ms
        || claims.grant_until <= now_ms
        || claims.grant_until > invite.valid_until_ms
    {
        return Err(AuthError::Unauthorized);
    }
    let sender = trust.key_for(invite.sender, invite.sender_epoch)
        .map_err(|_| AuthError::Unauthorized)?;
    let mut signed = Vec::with_capacity(STORE_DOMAIN.len() + STORE_BODY);
    signed.extend_from_slice(STORE_DOMAIN);
    signed.extend_from_slice(&signed_store[..STORE_BODY]);
    sender.verify(&signed, &sender_sig).map_err(|_| AuthError::Unauthorized)?;
    Ok(claims)
}

/// Historical cryptographic signature check. This does not evaluate the
/// current revocation state or prove continuous physical storage. Retain the
/// original invitation alongside the signed offer when validating old claims.
pub fn verify_delegated_stored_claim(
    claim: &CustodianStoredClaim,
    signed_store: &[u8],
    signed_invitation: &[u8],
    w3: &[u8],
    trust: &TrustRegistry,
) -> Result<(), AuthError> {
    let (invite, _) = decode(signed_invitation)?;
    let policy = MailboxPolicy {
        mailbox: invite.mailbox,
        issuer: invite.issuer,
        issuer_epoch: invite.issuer_epoch,
        custodian: invite.custodian,
        scope: invite.scope,
        recipient: invite.recipient,
        max_message_bytes: invite.max_packet_bytes,
        max_offers: 1,
    };
    let claims = verify_delegated_store(
        signed_store, signed_invitation,
        SavedPolicy { policy, store_revoked: false, fetch_revoked: false },
        trust, 0,
    )?;
    if claim.store != claims
        || claim.custodian_epoch == 0
        || claim.custodian_epoch > i64::MAX as u64
        || claim.causal.seq == 0
        || claim.causal.digest == [0; 32]
        || claims.packet_len as usize != w3.len()
        || blake3::hash(w3).as_bytes() != &claims.digest
    {
        return Err(AuthError::Invalid);
    }
    let route = private_route_w3::inspect_route(w3).map_err(|_| AuthError::Invalid)?;
    if route.message_id != claims.message || route.expires_at_ms != claims.expires_at as u64 {
        return Err(AuthError::Invalid);
    }
    let custodian = trust.key_for(invite.custodian, claim.custodian_epoch)
        .map_err(|_| AuthError::Unauthorized)?;
    custodian.verify(
        &stored_claim_body(claim),
        &Signature::from_bytes(&claim.signature),
    ).map_err(|_| AuthError::Unauthorized)
}

impl Journal {
    /// One-time delegated offer. Fail closed on ambiguous ACK; the same offer
    /// can only be retried with exactly the same signed bytes and invitation.
    pub fn request_delegated_custodian_store(
        &mut self,
        signed_invitation: &[u8],
        signed_store: &[u8],
        trust: &TrustRegistry,
        now_ms: i64,
    ) -> Result<Reservation, AuthError> {
        let (untrusted, _) = decode(signed_invitation)?;
        self.ensure_custodian_mailbox_schema()?;
        let tx = self.db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let policy = load_policy(&tx, untrusted.mailbox)?.ok_or(AuthError::Unauthorized)?;
        let claims = verify_delegated_store(
            signed_store, signed_invitation, policy, trust, now_ms,
        )?;
        let previous: Option<(Vec<u8>, i64, Option<Vec<u8>>)> = tx.query_row(
            "SELECT o.signed_grant,o.state,d.signed_invitation
             FROM custodian_mailbox_offer o
             LEFT JOIN custodian_mailbox_delegated_offer d ON d.offer=o.offer
             WHERE o.offer=?1",
            params![claims.offer.as_slice()],
            |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?)),
        ).optional()?;
        if let Some((old, state, invitation)) = previous {
            if old != signed_store || invitation.as_deref() != Some(signed_invitation) {
                return Err(AuthError::Conflict);
            }
            tx.commit()?;
            return match state {
                0 => Ok(Reservation::AlreadyReserved),
                1 => Ok(Reservation::AlreadyCommitted),
                _ => Err(AuthError::Corrupt),
            };
        }
        let occupied: i64 = tx.query_row(
            "SELECT COUNT(*) FROM custodian_mailbox_offer WHERE mailbox=?1",
            params![claims.mailbox.as_slice()],
            |r| r.get(0),
        )?;
        if occupied >= i64::from(policy.policy.max_offers) {
            return Err(AuthError::Capacity);
        }
        let collision: i64 = tx.query_row(
            "SELECT COUNT(*) FROM custodian_mailbox_offer
             WHERE slot=?1 OR (mailbox=?2 AND recipient=?3 AND message=?4)",
            params![claims.slot.as_slice(),claims.mailbox.as_slice(),
                claims.recipient.as_slice(),claims.message.as_slice()],
            |r| r.get(0),
        )?;
        if collision != 0 {
            return Err(AuthError::Conflict);
        }
        tx.execute(
            "INSERT INTO custodian_mailbox_offer
             (offer,slot,mailbox,recipient,message,signed_grant,state)
             VALUES(?1,?2,?3,?4,?5,?6,0)",
            params![claims.offer.as_slice(),claims.slot.as_slice(),
                claims.mailbox.as_slice(),claims.recipient.as_slice(),
                claims.message.as_slice(),signed_store],
        )?;
        tx.execute(
            "INSERT INTO custodian_mailbox_delegated_offer
             (offer,signed_invitation) VALUES(?1,?2)",
            params![claims.offer.as_slice(),signed_invitation],
        )?;
        tx.commit()?;
        Ok(Reservation::Reserved)
    }

    /// The sender can create exact W3 *after* receiving the invitation.
    /// Validate bytes before reserving, then both STORE authorities are checked
    /// again with the current policy inside the W12 SQLite COMMIT.
    pub fn accept_delegated_custodian_store_and_claim(
        &mut self,
        signed_invitation: &[u8],
        signed_store: &[u8],
        w3: &[u8],
        signer: &SigningKey,
        signer_epoch: u64,
        trust: &TrustRegistry,
        now_ms: i64,
    ) -> Result<CustodianStoredClaim, AuthError> {
        let (claims, _) = decode_store(signed_store)?;
        if w3.is_empty() || w3.len() > MAX_MESSAGE_BYTES
            || claims.packet_len as usize != w3.len()
            || blake3::hash(w3).as_bytes() != &claims.digest
        {
            return Err(AuthError::Invalid);
        }
        let route = private_route_w3::inspect_route(w3).map_err(|_| AuthError::Invalid)?;
        let (invite, _) = decode(signed_invitation)?;
        if route.token != invite.route_token
            || route.message_id != claims.message
            || route.expires_at_ms != claims.expires_at as u64
        {
            return Err(AuthError::Invalid);
        }
        self.request_delegated_custodian_store(
            signed_invitation, signed_store, trust, now_ms,
        )?;
        self.commit_custodian_store_with_claim(
            StoreLocator { mailbox: claims.mailbox, offer: claims.offer },
            w3, signer, signer_epoch, trust, now_ms,
        )
    }
}
