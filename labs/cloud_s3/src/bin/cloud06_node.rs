//! CLOUD-06: independent OS process probe against disposable MinIO.
//! Not a production messenger; W3/W4 authentication is covered by separate
//! CLOUD-03/04 integration tests. No secret credentials in argument list.
use akula_wire_lab::cloud_mail_store::{CloudKey,CloudRevision};
use std::{env,fs};
use wow_cloud_s3_lab::S3Lab;
fn need(n:&str)->String{env::var(n).expect("missing CI-only environment variable")}
fn account(who:&str)->S3Lab{
 assert_eq!(need("WOW_MINIO_ENDPOINT"),"http://127.0.0.1:9000");
 S3Lab::new(&need("WOW_MINIO_ENDPOINT"),"us-east-1",&need("WOW_MINIO_BUCKET"),
   &need(&format!("WOW_{}_ACCESS",who)),&need(&format!("WOW_{}_SECRET",who)))
}
fn key(n:u8,o:u8)->CloudKey{CloudKey{namespace:[n;16],object:[o;16]}}
fn main(){
 let args:Vec<String>=env::args().collect();
 assert_eq!(args.len(),5,"usage: cloud06_node ROLE put|read|reconcile INPUT OUTPUT");
 if args[1]=="HASH"{
   let data=fs::read(&args[3]).unwrap();
   fs::write(&args[4],blake3::hash(&data).to_hex().as_bytes()).unwrap();
   return;
 }
 let who=&args[1];assert!(who=="ALICE"||who=="BOB");
 let mode=&args[2];
 let rt=tokio::runtime::Runtime::new().unwrap();
 rt.block_on(async {
    let store=account(who);
    let namespace=if (who=="ALICE"&&mode=="put") || (who=="BOB"&&mode=="read"){21}else{61};
    let k=key(namespace,99);
    match mode.as_str(){
       "put"=>{
          let bytes=fs::read(&args[3]).unwrap();
          let revision=store.put_once(k,&bytes).await.unwrap();
          let CloudRevision::S3VersionId(version)=revision else {panic!("no version")};
          fs::write(&args[4],version).unwrap();
       }
       "read"=>{
          let rev=CloudRevision::S3VersionId(fs::read_to_string(&args[3]).unwrap());
          let digest_raw=env::var("WOW_EXPECTED_BLAKE3").expect("expected ciphertext hash");
          assert_eq!(digest_raw.len(),64);
          let mut hash=[0u8;32];
          for (i,b) in hash.iter_mut().enumerate(){
            *b=u8::from_str_radix(&digest_raw[i*2..i*2+2],16).unwrap();
          }
          let bytes=store.read_exact(k,&rev,16384,hash).await.unwrap();
          fs::write(&args[4],bytes).unwrap();
       }
       "reconcile"=>{
          // Deliberately lacks read permission for own outbound scope.
          // This must fail rather than claiming the upload is missing.
          let bytes=fs::read(&args[3]).unwrap();
          assert!(store.reconcile_unknown_put(k,&bytes).await.is_err());
          fs::write(&args[4],b"RECONCILIATION_NEEDS_READ_CAPABILITY").unwrap();
       }
       _=>panic!("unsupported test mode"),
    }
 });
}
