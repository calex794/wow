//! P0 custodian mailbox lab: STORE and FETCH require independent signed
//! capabilities, reservation and W12 commit share one SQLite write boundary.
use akula_wire_lab::{
    crypto_identity_w3::SignedHeader,
    crypto_w3,
    custodian_mailbox::{
        sign_fetch_for_lab, sign_store_for_lab, AuthError, FetchClaims,
        MailboxPolicy, Reservation, StoreClaims, StoreLocator,
    },
    journal_w4::Journal,
    private_route_w3,
    trust_w3::TrustRegistry,
};
use ed25519_dalek::SigningKey;
use rusqlite::{params, Connection};
use std::path::Path;

const ISSUER: [u8; 16] = [1; 16];
const CUSTODIAN: [u8; 16] = [8; 16];
const SCOPE: [u8; 16] = [5; 16];
const RECIPIENT: [u8; 16] = [3; 16];
const MAILBOX: [u8; 16] = [11; 16];
const MESSAGE: [u8; 16] = [4; 16];
const EXPIRY: i64 = 10_000_000;

struct Fixture {
    owner: SigningKey,
    custodian: SigningKey,
    trust: TrustRegistry,
    packet: Vec<u8>,
    policy: MailboxPolicy,
    claims: StoreClaims,
}
impl Fixture {
    fn new(max_offers: u32) -> Self {
        let owner = SigningKey::from_bytes(&[1; 32]);
        let custodian = SigningKey::from_bytes(&[8; 32]);
        let sender = SigningKey::from_bytes(&[7; 32]);
        let mut trust = TrustRegistry::new();
        trust.enroll(ISSUER, 1, owner.verifying_key()).unwrap();
        trust.enroll(CUSTODIAN, 1, custodian.verifying_key()).unwrap();
        let (_, recipient_public) = crypto_w3::new_recipient();
        let packet = private_route_w3::seal_private(
            &sender,
            &recipient_public,
            [9; 16],
            SignedHeader {
                sender_id: [7; 16],
                recipient_id: RECIPIENT,
                message_id: MESSAGE,
                expiry: EXPIRY as u64,
                epoch: 1,
            },
            b"independent signed mailbox STORE authorization",
        ).unwrap();
        let policy = MailboxPolicy {
            mailbox: MAILBOX,
            issuer: ISSUER,
            issuer_epoch: 1,
            custodian: CUSTODIAN,
            scope: SCOPE,
            recipient: RECIPIENT,
            max_message_bytes: 1024,
            max_offers,
        };
        let claims = StoreClaims {
            issuer: ISSUER,
            issuer_epoch: 1,
            custodian: CUSTODIAN,
            mailbox: MAILBOX,
            scope: SCOPE,
            recipient: RECIPIENT,
            message: MESSAGE,
            offer: [12; 16],
            slot: [13; 16],
            expires_at: EXPIRY,
            grant_until: EXPIRY - 1,
            packet_len: packet.len() as u32,
            digest: *blake3::hash(&packet).as_bytes(),
        };
        Self { owner, custodian, trust, packet, policy, claims }
    }
    fn provision(&self, path: &Path) -> Journal {
        let mut journal = Journal::open(path).unwrap();
        journal.operator_provision_mailbox(self.policy, &self.trust).unwrap();
        journal
    }
    fn store(&self) -> Vec<u8> { sign_store_for_lab(&self.owner, self.claims) }
    fn read(&self) -> Vec<u8> {
        sign_fetch_for_lab(&self.owner, FetchClaims {
            issuer: ISSUER,
            issuer_epoch: 1,
            custodian: CUSTODIAN,
            mailbox: MAILBOX,
            scope: SCOPE,
            recipient: RECIPIENT,
            message: MESSAGE,
            grant_until: EXPIRY - 1,
            digest: self.claims.digest,
        })
    }
}
fn count(path: &Path, table: &str) -> i64 {
    let db = Connection::open(path).unwrap();
    db.query_row(&format!("SELECT count(*) FROM {table}"),[],|r|r.get(0)).unwrap()
}
fn state(path: &Path) -> i64 {
    let db=Connection::open(path).unwrap();
    db.query_row(
        "SELECT state FROM custodian_mailbox_offer WHERE offer=?1",
        params![[12u8;16].as_slice()], |r|r.get(0),
    ).unwrap()
}

#[test]
fn authorized_store_is_atomic_idempotent_and_read_is_separately_signed() {
    let t=tempfile::tempdir().unwrap();
    let path=t.path().join("mailbox.sqlite");
    let f=Fixture::new(2);
    let mut j=f.provision(&path);
    let store=f.store();
    assert_eq!(j.request_custodian_store(&store,&f.trust,1).unwrap(),Reservation::Reserved);
    assert_eq!(j.request_custodian_store(&store,&f.trust,1).unwrap(),Reservation::AlreadyReserved);
    let first=j.commit_custodian_store(
        StoreLocator { mailbox: MAILBOX, offer: f.claims.offer },&f.packet,&f.custodian,1,&f.trust,2,
    ).unwrap();
    assert_eq!(first.seq,1);
    assert_eq!(j.request_custodian_store(&store,&f.trust,2).unwrap(),Reservation::AlreadyCommitted);
    assert_eq!(j.commit_custodian_store(
        StoreLocator { mailbox: MAILBOX, offer: f.claims.offer },&f.packet,&f.custodian,1,&f.trust,2,
    ).unwrap(),first);
    assert_eq!(count(&path,"outbox"),1);
    assert_eq!(count(&path,"causal_w12_event"),1);
    assert_eq!(count(&path,"receipt_outbox"),0,"C must not forge recipient W4");
    assert!(matches!(
        j.fetch_custodian_authorized(&store,&f.trust,2),
        Err(AuthError::Invalid)
    ),"STORE cannot authorize FETCH");
    let read=f.read();
    assert_eq!(j.fetch_custodian_authorized(&read,&f.trust,2).unwrap(),Some(f.packet.clone()));
    drop(j);
    let mut reopened=Journal::open(&path).unwrap();
    assert_eq!(reopened.audit_w12(SCOPE,CUSTODIAN,&f.trust).unwrap(),Some(first));
    assert_eq!(reopened.fetch_custodian_authorized(&read,&f.trust,2).unwrap(),Some(f.packet));
    assert_eq!(state(&path),1);
}

#[test]
fn invalid_grants_or_foreign_mailboxes_cannot_reserve_or_commit() {
    let t=tempfile::tempdir().unwrap();
    let path=t.path().join("deny.sqlite");
    let f=Fixture::new(2);
    let mut j=f.provision(&path);
    let valid=f.store();
    let mut damaged=valid.clone(); *damaged.last_mut().unwrap()^=1;
    assert!(matches!(j.request_custodian_store(&damaged,&f.trust,1),Err(AuthError::Unauthorized)));
    let mut wrong=f.claims; wrong.mailbox=[99;16];
    let alien=sign_store_for_lab(&f.owner,wrong);
    assert!(matches!(j.request_custodian_store(&alien,&f.trust,1),Err(AuthError::Unauthorized)));
    wrong=f.claims;wrong.digest=[10;32];
    let another=sign_store_for_lab(&f.owner,wrong);
    // The grant is genuinely owner-signed, so reserving it is valid; its
    // digest is checked against exact W3 bytes at CommitStore.
    assert_eq!(j.request_custodian_store(&another,&f.trust,1).unwrap(),Reservation::Reserved);
    assert!(matches!(
        j.commit_custodian_store(StoreLocator { mailbox: MAILBOX, offer: wrong.offer },&f.packet,&f.custodian,1,&f.trust,2),
        Err(AuthError::Conflict)
    ));
    assert_eq!(count(&path,"outbox"),0);
    assert_eq!(count(&path,"receipt_outbox"),0);
}

#[test]
fn wrong_ciphertext_and_revoked_store_reject_before_w12_commit() {
    let t=tempfile::tempdir().unwrap();
    let path=t.path().join("revoke.sqlite");
    let f=Fixture::new(2);
    let mut j=f.provision(&path);
    j.request_custodian_store(&f.store(),&f.trust,1).unwrap();
    let mut wrong=f.packet.clone();*wrong.last_mut().unwrap()^=1;
    assert!(matches!(j.commit_custodian_store(
        StoreLocator { mailbox: MAILBOX, offer: f.claims.offer },&wrong,&f.custodian,1,&f.trust,2
    ),Err(AuthError::Conflict)));
    assert_eq!(count(&path,"outbox"),0);
    assert_eq!(count(&path,"causal_w12_event"),0);
    assert_eq!(state(&path),0);
    j.operator_revoke_store(MAILBOX).unwrap();
    assert!(matches!(j.commit_custodian_store(
        StoreLocator { mailbox: MAILBOX, offer: f.claims.offer },&f.packet,&f.custodian,1,&f.trust,2
    ),Err(AuthError::Unauthorized)));
    assert_eq!(count(&path,"outbox"),0);
    assert_eq!(count(&path,"causal_w12_event"),0);
    assert_eq!(state(&path),0);
}

#[test]
fn read_revocation_is_separate_from_store_revocation() {
    let t=tempfile::tempdir().unwrap();
    let path=t.path().join("read.sqlite");
    let f=Fixture::new(1);
    let mut j=f.provision(&path);
    j.request_custodian_store(&f.store(),&f.trust,1).unwrap();
    j.commit_custodian_store(
        StoreLocator { mailbox: MAILBOX, offer: f.claims.offer },&f.packet,&f.custodian,1,&f.trust,2
    ).unwrap();
    let read=f.read();
    let mut changed=read.clone();*changed.last_mut().unwrap()^=1;
    assert!(matches!(j.fetch_custodian_authorized(&changed,&f.trust,2),Err(AuthError::Unauthorized)));
    j.operator_revoke_store(MAILBOX).unwrap();
    assert_eq!(j.fetch_custodian_authorized(&read,&f.trust,2).unwrap(),Some(f.packet));
    j.operator_revoke_fetch(MAILBOX).unwrap();
    assert!(matches!(j.fetch_custodian_authorized(&read,&f.trust,2),Err(AuthError::Unauthorized)));
}

#[test]
fn quota_offer_slots_stay_reserved_after_lost_ack_and_restart() {
    let t=tempfile::tempdir().unwrap();
    let path=t.path().join("quota.sqlite");
    let f=Fixture::new(1);
    let signed=f.store();
    {
        let mut j=f.provision(&path);
        assert_eq!(j.request_custodian_store(&signed,&f.trust,1).unwrap(),Reservation::Reserved);
    }
    let mut j=Journal::open(&path).unwrap();
    assert_eq!(j.request_custodian_store(&signed,&f.trust,1).unwrap(),Reservation::AlreadyReserved);
    let mut alternate=f.claims;
    alternate.offer=[14;16];alternate.slot=[15;16];alternate.message=[16;16];
    assert!(matches!(
        j.request_custodian_store(&sign_store_for_lab(&f.owner,alternate),&f.trust,1),
        Err(AuthError::Capacity)
    ));
    assert_eq!(count(&path,"custodian_mailbox_offer"),1);
    let sig=f.store();
    assert!(matches!(j.request_custodian_store(&sig,&f.trust,EXPIRY),Err(AuthError::Expired)));
}
