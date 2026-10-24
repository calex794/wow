//! Two real MinIO accounts with reciprocal, prefix-limited access.
//! Only disposable localhost credentials; never tests customer IAM.
use akula_wire_lab::cloud_mail_store::{CloudError,CloudKey,CloudRevision};
use wow_cloud_s3_lab::S3Lab;
fn env(k:&str)->String{std::env::var(k).expect("CI-only credential")}
fn make(access:&str,secret:&str)->S3Lab{
 assert_eq!(env("WOW_MINIO_ENDPOINT"),"http://127.0.0.1:9000");
 S3Lab::new(&env("WOW_MINIO_ENDPOINT"),"us-east-1",&env("WOW_MINIO_BUCKET"),
            &env(access),&env(secret))
}
fn key(n:u8,o:u8)->CloudKey{CloudKey{namespace:[n;16],object:[o;16]}}
#[test]
#[ignore="isolated versioned localhost MinIO with Alice and Bob IAM policies"]
fn alice_and_bob_have_separate_mailbox_permissions(){
 let rt=tokio::runtime::Runtime::new().unwrap();
 rt.block_on(async {
  let alice=make("WOW_ALICE_ACCESS","WOW_ALICE_SECRET");
  let bob=make("WOW_BOB_ACCESS","WOW_BOB_SECRET");
  let forward=key(21,71);let reverse=key(61,72);
  let forward_bytes=b"opaque Alice to Bob encrypted W3";
  let back_bytes=b"opaque Bob to Alice encrypted W4";
  let av=alice.put_once(forward,forward_bytes).await.unwrap();
  let bv=bob.put_once(reverse,back_bytes).await.unwrap();
  assert_eq!(bob.read_exact(forward,&av,1024,*blake3::hash(forward_bytes).as_bytes()).await.unwrap(),forward_bytes);
  assert_eq!(alice.read_exact(reverse,&bv,1024,*blake3::hash(back_bytes).as_bytes()).await.unwrap(),back_bytes);
  // A cross-namespace PUT must always fail.
  assert!(alice.put_once(key(61,73),b"forbidden").await.is_err());
  assert!(bob.put_once(key(21,74),b"forbidden").await.is_err());
  // Reading outside either granted direction must fail.
  assert!(matches!(alice.read_exact(forward,&av,1024,*blake3::hash(forward_bytes).as_bytes()).await,Err(CloudError::Unavailable)));
  assert!(matches!(bob.read_exact(reverse,&bv,1024,*blake3::hash(back_bytes).as_bytes()).await,Err(CloudError::Unavailable)));
  assert!(alice.put_once(forward,forward_bytes).await.is_err());
  assert!(bob.put_once(reverse,back_bytes).await.is_err());
  assert!(matches!(alice.read_exact(reverse,&CloudRevision::S3VersionId("forged".into()),1024,*blake3::hash(back_bytes).as_bytes()).await,Err(CloudError::Unavailable)));
 });
}
