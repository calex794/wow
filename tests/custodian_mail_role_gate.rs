//! Owner mailbox authorization is checked INSIDE the same IMMEDIATE SQLite
//! transaction as custody reservation, W3/W12 durable commit and recipient
//! discovery. This guard is pinned by an external Akula root operator verifier.
//! No physical VPS, production root secrets or public network listener.
use akula_wire_lab::{
    crypto_identity_w3::SignedHeader,
    crypto_w3,
    custodian_discovery::{sign_list_for_lab, ListClaims},
    custodian_mailbox::{
        MailRoleGate, MailboxPolicy, StoreClaims, StoreLocator, sign_store_for_lab,
    },
    journal_w4::Journal,
    private_route_w3,
    trust_w3::TrustRegistry,
};
use ed25519_dalek::SigningKey;
use rusqlite::Connection;
use std::path::Path;

const OWNER: [u8; 16] = [1; 16];
const CUSTODIAN: [u8; 16] = [8; 16];
const RECIPIENT: [u8; 16] = [3; 16];
const SENDER: [u8; 16] = [7; 16];
const MAILBOX: [u8; 16] = [11; 16];
const SCOPE: [u8; 16] = [5; 16];
const MESSAGE: [u8; 16] = [4; 16];
const OFFER: [u8; 16] = [12; 16];
const EXPIRY: i64 = 10_000_000;

struct Fixture {
    owner: SigningKey,
    custodian: SigningKey,
    recipient: SigningKey,
    trust: TrustRegistry,
    packet: Vec<u8>,
    policy: MailboxPolicy,
    store: Vec<u8>,
}
impl Fixture {
    fn new() -> Self {
        let owner = SigningKey::from_bytes(&[1; 32]);
        let custodian = SigningKey::from_bytes(&[8; 32]);
        let recipient = SigningKey::from_bytes(&[3; 32]);
        let sender = SigningKey::from_bytes(&[7; 32]);
        let mut trust = TrustRegistry::new();
        for (id, key) in [
            (OWNER, &owner), (CUSTODIAN, &custodian),
            (RECIPIENT, &recipient), (SENDER, &sender),
        ] { trust.enroll(id, 1, key.verifying_key()).unwrap(); }
        let (_, pubkey) = crypto_w3::new_recipient();
        let packet = private_route_w3::seal_private(
            &sender, &pubkey, [9;16],
            SignedHeader {
                sender_id: SENDER,
                recipient_id: RECIPIENT,
                message_id: MESSAGE,
                expiry: EXPIRY as u64,
                epoch: 1,
            },
            b"transaction-bound independently pinned mail role",
        ).unwrap();
        let policy = MailboxPolicy {
            mailbox: MAILBOX,
            issuer: OWNER,
            issuer_epoch: 1,
            custodian: CUSTODIAN,
            scope: SCOPE,
            recipient: RECIPIENT,
            max_message_bytes: 1024,
            max_offers: 2,
        };
        let store = sign_store_for_lab(&owner, StoreClaims {
            issuer: OWNER,
            issuer_epoch: 1,
            custodian: CUSTODIAN,
            mailbox: MAILBOX,
            scope: SCOPE,
            recipient: RECIPIENT,
            message: MESSAGE,
            offer: OFFER,
            slot: [13;16],
            expires_at: EXPIRY,
            grant_until: EXPIRY - 1,
            packet_len: packet.len() as u32,
            digest: *blake3::hash(&packet).as_bytes(),
        });
        Self {owner,custodian,recipient,trust,packet,policy,store}
    }
    fn gate(&self, epoch: u64) -> MailRoleGate {
        MailRoleGate {
            mailbox_policy: self.policy,
            policy_epoch: epoch,
            signed_policy_digest: *blake3::hash(
                format!("owner-root-pinned-mail-policy-epoch-{epoch}").as_bytes(),
            ).as_bytes(),
        }
    }
    fn provision(&self, db: &Path) {
        let mut j=Journal::open(db).unwrap();
        j.operator_provision_mailbox(self.policy, &self.trust).unwrap();
        j.operator_provision_mail_role_gate(self.gate(1)).unwrap();
    }
    fn bound(&self, db: &Path) -> Journal {
        let mut j=Journal::open(db).unwrap();
        j.bind_mail_role_gate(self.gate(1)).unwrap();
        j
    }
    fn list(&self) -> Vec<u8> {
        sign_list_for_lab(&self.recipient, ListClaims {
            issuer: OWNER,
            issuer_epoch: 1,
            custodian: CUSTODIAN,
            mailbox: MAILBOX,
            scope: SCOPE,
            recipient: RECIPIENT,
            recipient_epoch: 1,
            since_seq: 0,
            grant_until_ms: 100_000,
            nonce: [77;16],
            max_items: 2,
        })
    }
}
fn count(db: &Path, table: &str) -> i64 {
    let conn=Connection::open(db).unwrap();
    conn.query_row(&format!("SELECT count(*) FROM {table}"), [], |r|r.get(0)).unwrap()
}
fn locator() -> StoreLocator { StoreLocator {mailbox: MAILBOX, offer: OFFER} }

#[test]
fn without_exact_root_pinned_epoch_and_digest_mailbox_cannot_bind() {
    let f=Fixture::new();
    let temp=tempfile::tempdir().unwrap();
    let db=temp.path().join("gate.sqlite");
    let mut j=Journal::open(&db).unwrap();
    j.operator_provision_mailbox(f.policy, &f.trust).unwrap();
    assert!(j.bind_mail_role_gate(f.gate(1)).is_err(), "missing owner witness denies");
    j.operator_provision_mail_role_gate(f.gate(1)).unwrap();
    let mut forged=f.gate(1);
    forged.signed_policy_digest=[55;32];
    assert!(j.bind_mail_role_gate(forged).is_err());
    let mut wrong_mailbox=f.gate(1);
    wrong_mailbox.mailbox_policy.mailbox=[99;16];
    assert!(j.bind_mail_role_gate(wrong_mailbox).is_err());
    assert!(j.bind_mail_role_gate(f.gate(1)).is_ok());
    assert!(j.bind_mail_role_gate(f.gate(1)).is_err(), "no silent rebinding");
}

#[test]
fn revocation_between_reservation_and_commit_denies_w3_w12_atomically() {
    let f=Fixture::new();
    let temp=tempfile::tempdir().unwrap();
    let db=temp.path().join("revocation.sqlite");
    f.provision(&db);
    let mut held=f.bound(&db);
    held.request_custodian_store(&f.store,&f.trust,1).unwrap();
    assert_eq!(count(&db,"custodian_mailbox_offer"),1);

    // Independent operator changes the same database after a reservation.
    let mut operator=Journal::open(&db).unwrap();
    operator.operator_revoke_mail_role_gate(MAILBOX).unwrap();
    assert!(held.commit_custodian_store_with_claim(
        locator(), &f.packet, &f.custodian, 1, &f.trust, 2,
    ).is_err(), "previously authorized reservation cannot survive revocation");
    assert_eq!(count(&db,"outbox"),0);
    assert_eq!(count(&db,"causal_w12_event"),0);
    assert!(held.request_custodian_store(&f.store,&f.trust,2).is_err());
    assert!(held.list_custodian_authorized(&f.list(), &f.trust, 2).is_err());
    assert!(held.require_mail_role_gate_current().is_err());
    assert!(Journal::open(&db).unwrap().bind_mail_role_gate(f.gate(1)).is_err());
}

#[test]
fn newer_operator_epoch_is_explicit_and_existing_live_role_stays_fenced() {
    let f=Fixture::new();
    let temp=tempfile::tempdir().unwrap();
    let db=temp.path().join("epoch.sqlite");
    f.provision(&db);
    let mut held=f.bound(&db);
    let mut operator=Journal::open(&db).unwrap();
    operator.operator_revoke_mail_role_gate(MAILBOX).unwrap();
    assert!(operator.operator_provision_mail_role_gate(f.gate(1)).is_err());
    operator.operator_provision_mail_role_gate(f.gate(2)).unwrap();
    assert!(held.require_mail_role_gate_current().is_err(), "old role cannot inherit new epoch");
    let mut new=Journal::open(&db).unwrap();
    assert!(new.bind_mail_role_gate(f.gate(1)).is_err());
    new.bind_mail_role_gate(f.gate(2)).unwrap();
    assert!(new.require_mail_role_gate_current().is_ok());
    new.request_custodian_store(&f.store,&f.trust,2).unwrap();
    let receipt=new.commit_custodian_store_with_claim(
        locator(), &f.packet, &f.custodian, 1, &f.trust, 2,
    ).unwrap();
    assert!(receipt.causal.seq > 0);
    assert_eq!(new.list_custodian_authorized(&f.list(), &f.trust, 2).unwrap().len(),1);
    operator.operator_revoke_mail_role_gate(MAILBOX).unwrap();
    assert!(new.list_custodian_authorized(&f.list(), &f.trust, 2).is_err());
    assert_eq!(count(&db,"outbox"),1,"revocation retains encrypted historical bytes");
}
