//! Run ONLY against an isolated, versioning-enabled disposable test bucket.
//! Example: WOW_MINIO_ENDPOINT=http://127.0.0.1:9000 WOW_MINIO_BUCKET=wow-mail-lab
//! WOW_MINIO_ACCESS=minioadmin WOW_MINIO_SECRET=... cargo test --manifest-path
//! labs/cloud_s3/Cargo.toml --test minio_offline -- --ignored
use wow_cloud_s3_lab::S3Lab;
use akula_wire_lab::cloud_mail_store::{CloudError,CloudKey,CloudRevision};
fn env(name:&str)->String {std::env::var(name).expect("isolated MinIO test environment required")}
fn client()->S3Lab {
    S3Lab::new(&env("WOW_MINIO_ENDPOINT"),"us-east-1",&env("WOW_MINIO_BUCKET"),
               &env("WOW_MINIO_ACCESS"),&env("WOW_MINIO_SECRET"))
}
fn object()->CloudKey {
    let mut bytes=[0u8;16];
    getrandom::fill(&mut bytes).unwrap();
    CloudKey{namespace:[9;16],object:bytes}
}
#[test]
#[ignore = "requires real versioning-enabled MinIO, explicit disposable credentials"]
fn separate_client_reads_after_sender_is_dropped() {
    let rt=tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let key=object();
        let data=b"opaque pre-encrypted WOW/W3 test bytes, not a signed W4";
        let original=*blake3::hash(data).as_bytes();
        let rev={
            let sender=client();
            sender.put_once(key,data).await.expect("create-only upload")
        }; // the sender/custodian object is dropped here
        let receiver=client(); // separate client after sender disappears; same test credentials
        let recovered=receiver.read_exact(key,&rev,16384,original).await.unwrap();
        assert_eq!(recovered,data);
        // It cannot switch to a missing or forged version.
        assert!(matches!(
            receiver.read_exact(key,&CloudRevision::S3VersionId("missing".into()),16384,original).await,
            Err(CloudError::Unavailable)
        ));
        // A wrong ciphertext commitment is rejected by the recipient.
        assert_eq!(
            receiver.read_exact(key,&rev,16384,[42;32]).await,
            Err(CloudError::Corrupt)
        );
        // Exact key cannot be overwritten using a second upload.
        assert!(receiver.put_once(key,b"new bytes").await.is_err());
        assert_eq!(receiver.read_exact(key,&rev,16384,original).await.unwrap(),data);
    });
}


#[test]
#[ignore = "requires isolated localhost MinIO with versioning"]
fn signed_versioned_get_to_plain_http_reader() {
    let rt=tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        assert_eq!(env("WOW_MINIO_ENDPOINT"), "http://127.0.0.1:9000");
        let key=object();
        let data=b"opaque encrypted mail for independent HTTP read";
        let url={
            let issuer=client();
            let rev=issuer.put_once(key,data).await.unwrap();
            issuer.presign_read(key,&rev,30).await.unwrap()
        };
        // Receiver needs only this temporary URL, not an S3 client.
        let response=std::process::Command::new("curl")
            .args(["--fail","--silent","--show-error","--max-time","10"])
            .arg(&url).output().unwrap();
        assert!(response.status.success());
        assert_eq!(response.stdout,data);
        assert_eq!(*blake3::hash(&response.stdout).as_bytes(),
                   *blake3::hash(data).as_bytes());
    });
}
