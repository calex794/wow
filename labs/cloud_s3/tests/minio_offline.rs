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


/// Extract only HTTP status; do not print signed URLs or response payloads.
fn curl_status(url: &str, method: &str) -> String {
    let r=std::process::Command::new("curl")
        .args(["--silent","--show-error","--output","/dev/null",
               "--write-out","%{http_code}","--max-time","12",
               "--noproxy","*","--request",method])
        .arg(url).output().expect("curl present in CI");
    assert!(r.status.success(), "curl itself failed");
    String::from_utf8(r.stdout).unwrap()
}

#[test]
#[ignore = "requires isolated localhost MinIO with versioning"]
fn presigned_grant_rejects_wrong_object_version_method_and_expiry() {
    let rt=tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        assert_eq!(env("WOW_MINIO_ENDPOINT"),"http://127.0.0.1:9000");
        let key=object();
        let payload=b"private test-only encrypted mail";
        let issuer=client();
        let version=issuer.put_once(key,payload).await.unwrap();
        let url=issuer.presign_read(key,&version,30).await.unwrap();

        // First establish the expected positive control.
        assert_eq!(curl_status(&url,"GET"),"200");
        let wrong=object();
        let hex=|id: &[u8;16]| -> String {
            id.iter().map(|b|format!("{b:02x}")).collect()
        };
        let forged=url.replacen(&hex(&key.object),&hex(&wrong.object),1);
        assert_ne!(forged,url);
        assert_ne!(curl_status(&forged,"GET"),"200",
                   "signed GET must not authorize another object");

        // Signing includes the exact VersionId; changing this query value
        // must not silently fall back to the latest version.
        let prefix="versionId=";
        let q=url.split(prefix).nth(1).expect("versionId signed in URL");
        let encoded=q.split('&').next().unwrap();
        let altered=url.replacen(
            &format!("{prefix}{encoded}"),
            "versionId=forged-version",1);
        assert_ne!(altered,url);
        assert_ne!(curl_status(&altered,"GET"),"200",
                   "signed GET must not authorize another version");

        assert_ne!(curl_status(&url,"PUT"),"200",
                   "GET-only capability must not allow upload");
        let list=format!("{}/{}?list-type=2",
                         env("WOW_MINIO_ENDPOINT"),env("WOW_MINIO_BUCKET"));
        assert_ne!(curl_status(&list,"GET"),"200",
                   "unsigned LIST must not be public");

        assert!(matches!(
            issuer.presign_read(key,&version,0).await,
            Err(CloudError::InvalidGrant)));
        assert!(matches!(
            issuer.presign_read(key,&version,61).await,
            Err(CloudError::InvalidGrant)));

        let fleeting=issuer.presign_read(key,&version,1).await.unwrap();
        assert_eq!(curl_status(&fleeting,"GET"),"200");
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        assert_ne!(curl_status(&fleeting,"GET"),"200",
                   "expired signed URL must stop working");
    });
}
