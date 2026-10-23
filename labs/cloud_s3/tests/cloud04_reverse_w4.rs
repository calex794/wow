//! CLOUD-04: reverse W4 via independent MinIO object, with lost ACK,
//! exact version recovery, replay, and SQLite restart. Localhost-only lab.
use akula_wire_lab::{
 cloud_mail_store::{CloudKey,CloudRevision,CloudError},
 crypto_identity_w3::{SignedHeader,TrustedRecipient},
 crypto_w3::new_recipient, private_route_w3,
 private_return_w4::{self,ReturnInvitation},
 journal_w4::{Journal,Delivery,Insert},
 trust_w3::TrustRegistry,
};
use ed25519_dalek::SigningKey;
use tempfile::tempdir;
use wow_cloud_s3_lab::S3Lab;
fn id(b:u8)->[u8;16]{[b;16]}
fn signing(b:u8)->SigningKey{SigningKey::from_bytes(&[b;32])}
fn env(k:&str)->String{std::env::var(k).unwrap()}
fn client()->S3Lab{
 assert_eq!(env("WOW_MINIO_ENDPOINT"),"http://127.0.0.1:9000");
 S3Lab::new(&env("WOW_MINIO_ENDPOINT"),"us-east-1",&env("WOW_MINIO_BUCKET"),&env("WOW_MINIO_ACCESS"),&env("WOW_MINIO_SECRET"))
}
#[test]
#[ignore="disposable versioned localhost MinIO only"]
fn reverse_mail_w4_survives_unknown_ack_and_restart(){
 let rt=tokio::runtime::Runtime::new().unwrap();
 rt.block_on(async{
  let dir=tempdir().unwrap();
  let alice_db=dir.path().join("a.sqlite");
  let bob_db=dir.path().join("b.sqlite");
  let mut trust=TrustRegistry::new();
  trust.enroll(id(9),4,signing(9).verifying_key()).unwrap();
  trust.enroll(id(8),6,signing(8).verifying_key()).unwrap();
  let (bob_secret,bob_pub)=new_recipient();
  let (alice_secret,alice_pub)=new_recipient();
  let w3=private_route_w3::seal_private(&signing(9),&bob_pub,id(31),
    SignedHeader{message_id:id(5),recipient_id:id(8),sender_id:id(9),
    epoch:4,expiry:500_000},b"reverse mailbox durable W4").unwrap();
  {let mut a=Journal::open(&alice_db).unwrap();a.enqueue(id(8),id(5),500_000,&w3).unwrap();}
  let receipt={
    let mut b=Journal::open(&bob_db).unwrap();
    let (state,receipt)=b.accept_private_authenticated_and_queue_receipt(
      &w3,TrustedRecipient{secret:&bob_secret,recipient_id:id(8),now:100_000,registry:&trust},
      id(31),&signing(8),6).unwrap();
    assert_eq!(state,Insert::New);
    receipt
  };
  let opaque=private_return_w4::seal_signed_receipt(&receipt,&alice_pub,id(41)).unwrap();
  let reply_key=CloudKey{namespace:id(61),object:id(62)};
  // Bob uploads the encrypted receipt, but the response disappears.
  {let bob_uploader=client();bob_uploader.put_once(reply_key,&opaque).await.unwrap();}
  let alice_storage=client();
  let recovered=alice_storage.reconcile_unknown_put(reply_key,&opaque).await.unwrap();
  // A blind second PUT cannot alter the same key.
  assert!(alice_storage.put_once(reply_key,&opaque).await.is_err());
  let wrong=CloudRevision::S3VersionId("not-the-pinned-version".into());
  assert!(alice_storage.read_exact(reply_key,&wrong,2048,*blake3::hash(&opaque).as_bytes()).await.is_err());
  // Simulate an unavailable object by using a different namespace.
  let missing=CloudKey{namespace:id(64),object:id(62)};
  assert!(matches!(alice_storage.reconcile_unknown_put(missing,&opaque).await,Err(CloudError::Ambiguous)));
  let exact=alice_storage.read_exact(reply_key,&recovered,2048,*blake3::hash(&opaque).as_bytes()).await.unwrap();
  assert_eq!(exact,opaque);
  let invitation=||ReturnInvitation{
    sender_secret:&alice_secret,expected_tag:id(41),
    expires_at_ms:250_000,now_ms:100_010,recipient_trust:&trust,
  };
  // A local write is not marked as Recipient before W4 signature validation.
  {let a=Journal::open(&alice_db).unwrap();assert_eq!(a.state(id(8),id(5)).unwrap(),Delivery::Queued);}
  {
   let mut a=Journal::open(&alice_db).unwrap();
   assert_eq!(private_return_w4::open_verify_and_apply(&exact,invitation(),&mut a).unwrap(),Delivery::Recipient);
  }
  let mut a=Journal::open(&alice_db).unwrap();
  assert_eq!(private_return_w4::open_verify_and_apply(&exact,invitation(),&mut a).unwrap(),Delivery::Recipient);
  assert_eq!(a.retry_bytes(id(8),id(5),100_010).unwrap(),None);
  // A corrupted cloud W4 MUST NOT confirm the sender.
  let mut damaged=exact.clone();damaged[damaged.len()-1]^=1;
  assert!(private_return_w4::open_verify_and_apply(&damaged,invitation(),&mut a).is_err());
 });
}
