//! Disposable S3 test: the signed control pin is encrypted, stored as a
//! bounded S3 object and independently opened by a recipient with a pinned
//! signing key. No runner copy of pin metadata.
use akula_wire_lab::{cloud_mail_store::CloudKey,crypto_w3::new_recipient};
use ed25519_dalek::SigningKey;
use wow_cloud_s3_lab::{S3Lab,sealed_control,signed_pin::{self,Direction,PinScope}};
fn env(n:&str)->String{std::env::var(n).unwrap()}
fn s3()->S3Lab{
 assert_eq!(env("WOW_MINIO_ENDPOINT"),"http://127.0.0.1:9000");
 S3Lab::new(&env("WOW_MINIO_ENDPOINT"),"us-east-1",&env("WOW_MINIO_BUCKET"),
            &env("WOW_MINIO_ACCESS"),&env("WOW_MINIO_SECRET"))
}
#[test]
#[ignore="localhost versioned disposable MinIO"]
fn sealed_signed_control_survives_minio_and_rejects_tampering(){
 let rt=tokio::runtime::Runtime::new().unwrap();
 rt.block_on(async {
  let sign=SigningKey::from_bytes(&[84;32]);
  let (sk,pk)=new_recipient();
  let control=CloudKey{namespace:[116;16],object:[117;16]};
  let content=CloudKey{namespace:[118;16],object:[119;16]};
  let bytes=b"encrypted opaque W3 test data";
  let store=s3();
  let data_version=store.put_once(content,bytes).await.unwrap();
  let scope=PinScope{direction:Direction::ForwardW3,key:content,
       recipient:[8;16],message:[5;16],expires_at_ms:500_000};
  let signature=signed_pin::issue(&sign,scope,&data_version,bytes).unwrap();
  let encrypted=sealed_control::seal(&pk,control,&signature).unwrap();
  assert_eq!(encrypted.len(),sealed_control::ENVELOPE_LEN);
  store.put_once(control,&encrypted).await.unwrap();
  let (revision,remote)=s3().discover_control(control,sealed_control::ENVELOPE_LEN).await.unwrap();
  assert!(matches!(revision,akula_wire_lab::cloud_mail_store::CloudRevision::S3VersionId(_)));
  assert_eq!(remote,encrypted);
  let opened=sealed_control::open(&sk,control,&remote).unwrap();
  let verified=signed_pin::verify(&opened,&sign.verifying_key(),scope,100_000).unwrap();
  assert_eq!(s3().read_exact(content,&verified.revision,verified.length,verified.digest).await.unwrap(),bytes);
  let mut forged=remote;
  forged[80]^=1;
  assert!(sealed_control::open(&sk,control,&forged).is_err());
 });
}
