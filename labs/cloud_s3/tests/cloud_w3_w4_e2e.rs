//! CLOUD-03 opt-in: real localhost MinIO -> authenticated private W3 ->
//! receiver SQLite durable W4 -> encrypted private return -> sender SQLite.
//! Not a production invitation, IAM, or two-host connectivity test.
use akula_wire_lab::{
    crypto_identity_w3::{SignedHeader, TrustedRecipient},
    crypto_w3::new_recipient,
    private_route_w3,
    private_return_w4::{self, ReturnInvitation},
    journal_w4::{Delivery, Insert, Journal},
    trust_w3::TrustRegistry,
};
use ed25519_dalek::SigningKey;
use tempfile::tempdir;
use wow_cloud_s3_lab::S3Lab;

fn id(n: u8) -> [u8;16] {[n;16]}
fn signer(n:u8)->SigningKey {SigningKey::from_bytes(&[n;32])}
fn env(name:&str)->String {std::env::var(name).expect("isolated MinIO required")}
fn client()->S3Lab {
    assert_eq!(env("WOW_MINIO_ENDPOINT"),"http://127.0.0.1:9000");
    S3Lab::new(&env("WOW_MINIO_ENDPOINT"),"us-east-1",&env("WOW_MINIO_BUCKET"),
               &env("WOW_MINIO_ACCESS"),&env("WOW_MINIO_SECRET"))
}

#[test]
#[ignore = "requires disposable versioned localhost MinIO"]
fn cloud_w3_then_recipient_commit_then_private_w4_and_sender_stop() {
    let rt=tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let dir=tempdir().unwrap();
        let (bob_secret,bob_public)=new_recipient();
        let (alice_return_secret,alice_return_public)=new_recipient();
        let mut trust=TrustRegistry::new();
        trust.enroll(id(9),4,signer(9).verifying_key()).unwrap();
        trust.enroll(id(8),6,signer(8).verifying_key()).unwrap();
        let route=id(31);
        let w3=private_route_w3::seal_private(
            &signer(9),&bob_public,route,
            SignedHeader{
                message_id:id(5),recipient_id:id(8),sender_id:id(9),
                epoch:4,expiry:500_000,
            },
            b"private encrypted cloud mailbox end-to-end",
        ).unwrap();
        let digest=*blake3::hash(&w3).as_bytes();
        let alice_path=dir.path().join("alice.sqlite");
        let bob_path=dir.path().join("bob.sqlite");
        {
            let mut alice=Journal::open(&alice_path).unwrap();
            alice.enqueue(id(8),id(5),500_000,&w3).unwrap();
        }
        let key=akula_wire_lab::cloud_mail_store::CloudKey {
            namespace:id(21),object:id(22),
        };
        let signed_url={
            let custodian=client();
            let revision=custodian.put_once(key,&w3).await.unwrap();
            custodian.presign_read(key,&revision,30).await.unwrap()
        };
        // Sender/custodian S3 client was dropped; fetch using plain HTTP.
        let download=std::process::Command::new("curl")
            .args(["--silent","--show-error","--fail","--max-time","10"])
            .arg(&signed_url).output().unwrap();
        assert!(download.status.success());
        assert_eq!(*blake3::hash(&download.stdout).as_bytes(),digest);
        let (first,receipt)={
            let mut bob=Journal::open(&bob_path).unwrap();
            bob.accept_private_authenticated_and_queue_receipt(
                &download.stdout,
                TrustedRecipient {
                    secret:&bob_secret,recipient_id:id(8),now:100_000,registry:&trust,
                },
                route,&signer(8),6,
            ).unwrap()
        };
        assert_eq!(first,Insert::New);
        // W4 survived the receiver process restart.
        let (replayed,saved)={
            let mut bob=Journal::open(&bob_path).unwrap();
            let prior=bob.queued_recipient_receipt(id(9),id(5)).unwrap().unwrap();
            let (state,w4)=bob.accept_private_authenticated_and_queue_receipt(
                &download.stdout,
                TrustedRecipient {
                    secret:&bob_secret,recipient_id:id(8),now:100_001,registry:&trust,
                },
                route,&signer(8),6,
            ).unwrap();
            (state,(prior,w4))
        };
        assert_eq!(replayed,Insert::Duplicate);
        assert_eq!(saved.0,receipt);
        assert_eq!(saved.1,receipt);
        let return_tag=id(41);
        let envelope=private_return_w4::seal_signed_receipt(
            &receipt,&alice_return_public,return_tag,
        ).unwrap();
        let invite=||ReturnInvitation {
            sender_secret:&alice_return_secret,expected_tag:return_tag,
            expires_at_ms:250_000,now_ms:100_010,recipient_trust:&trust,
        };
        {
            let mut alice=Journal::open(&alice_path).unwrap();
            assert_eq!(alice.state(id(8),id(5)).unwrap(),Delivery::Queued);
            assert_eq!(private_return_w4::open_verify_and_apply(
                &envelope,invite(),&mut alice,
            ).unwrap(),Delivery::Recipient);
            assert_eq!(alice.retry_bytes(id(8),id(5),100_010).unwrap(),None);
        }
        // Re-open sender: replay cannot re-enable a completed route.
        let mut alice=Journal::open(&alice_path).unwrap();
        assert_eq!(private_return_w4::open_verify_and_apply(
            &envelope,invite(),&mut alice,
        ).unwrap(),Delivery::Recipient);
        assert_eq!(alice.state(id(8),id(5)).unwrap(),Delivery::Recipient);
    });
}
