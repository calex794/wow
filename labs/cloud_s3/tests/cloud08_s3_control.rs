//! A signed locator can travel as a bounded, versioned S3 control object.
//! The reader uses a pre-known control key and independently pinned Ed25519
//! verifying key. MinIO object metadata is NOT itself authority.
use akula_wire_lab::cloud_mail_store::{CloudKey,CloudRevision};
use ed25519_dalek::SigningKey;
use wow_cloud_s3_lab::{S3Lab,signed_pin::{self,Direction,PinScope}};
fn env(k:&str)->String{std::env::var(k).unwrap()}
fn client()->S3Lab{
 assert_eq!(env("WOW_MINIO_ENDPOINT"),"http://127.0.0.1:9000");
 S3Lab::new(&env("WOW_MINIO_ENDPOINT"),"us-east-1",
   &env("WOW_MINIO_BUCKET"),&env("WOW_MINIO_ACCESS"),&env("WOW_MINIO_SECRET"))
}
#[test]
#[ignore="isolated disposable MinIO only"]
fn signed_control_object_discovered_without_runner_copy(){
 let rt=tokio::runtime::Runtime::new().unwrap();
 rt.block_on(async{
  let s=client();
  let author=SigningKey::from_bytes(&[33;32]);
  let data=b"private opaque message, not a delivery receipt";
  let object=CloudKey{namespace:[111;16],object:[112;16]};
  let ctrl=CloudKey{namespace:[113;16],object:[114;16]};
  let version=s.put_once(object,data).await.unwrap();
  let scope=PinScope{
     direction:Direction::ForwardW3,key:object,recipient:[19;16],
     message:[18;16],expires_at_ms:500_000,
  };
  let signed=signed_pin::issue(&author,scope,&version,data).unwrap();
  let ctrl_version=s.put_once(ctrl,&signed).await.unwrap();
  let reader=client(); // independent SDK client; no runner copy of pin bytes.
  let (got_ctrl_version,got_signed)=reader.discover_control(ctrl,512).await.unwrap();
  assert_eq!(got_ctrl_version,ctrl_version);
  assert_eq!(got_signed,signed);
  let verified=signed_pin::verify(
     &got_signed,&author.verifying_key(),scope,100_000).unwrap();
  let received=reader.read_exact(object,&verified.revision,
      verified.length,verified.digest).await.unwrap();
  assert_eq!(received,data);
  // Untrusted storage can return a signed pin for a different message: reject.
  let mut different=scope;
  different.message=[99;16];
  assert!(signed_pin::verify(
     &got_signed,&author.verifying_key(),different,100_000).is_err());
  // S3 exposes a version string, but it is not an Ed25519 authorization.
  assert!(matches!(got_ctrl_version,CloudRevision::S3VersionId(_)));
  assert!(reader.discover_control(ctrl,8).await.is_err());
 });
}
