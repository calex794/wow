//! Real localhost MinIO commit followed by network loss of HTTP PUT reply.
//! S3Lab::put_once must report Ambiguous, then reconcile without rewriting.
use akula_wire_lab::cloud_mail_store::{CloudError,CloudKey};
use wow_cloud_s3_lab::S3Lab;
fn env(n:&str)->String{std::env::var(n).unwrap()}
fn client(endpoint:&str)->S3Lab{
 S3Lab::new(endpoint,"us-east-1",&env("WOW_MINIO_BUCKET"),
            &env("WOW_MINIO_ACCESS"),&env("WOW_MINIO_SECRET"))
}
#[test]
#[ignore="localhost MinIO and one-shot lost-ACK proxy required"]
fn commit_succeeds_even_when_successful_put_ack_is_lost(){
 assert_eq!(env("WOW_MINIO_ENDPOINT"),"http://127.0.0.1:9000");
 let rt=tokio::runtime::Runtime::new().unwrap();
 rt.block_on(async{
  let key=CloudKey{namespace:[93;16],object:[94;16]};
  let packet=b"opaque W4 reverse bytes with a lost network acknowledgement";
  // Proxy forwards the PUT in full, observes upstream success, then closes
  // client transport before forwarding the successful response.
  let proxied=client("http://127.0.0.1:9001");
  assert_eq!(proxied.put_once(key,packet).await,Err(CloudError::Ambiguous));
  let direct=client("http://127.0.0.1:9000");
  let version=direct.reconcile_unknown_put(key,packet).await.unwrap();
  let actual=direct.read_exact(key,&version,1024,*blake3::hash(packet).as_bytes()).await.unwrap();
  assert_eq!(actual,packet);
  assert!(direct.put_once(key,packet).await.is_err());
 });
}
