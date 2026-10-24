//! CLOUD-07 test-only object-version audit after the isolated MinIO E2E.
//! Uses the disposable CI bucket administrator solely to count one exact key.
//! Alice and Bob workers never get ListBucketVersions or administrator access.
use aws_sdk_s3::{
    Client,
    config::{Builder, Credentials, Region},
};

#[test]
#[ignore = "requires completed cloud07_crash_recovery.sh on disposable localhost MinIO"]
fn reverse_w4_has_one_version_and_both_parties_pin_the_same_revision() {
    assert_eq!(
        std::env::var("WOW_MINIO_ENDPOINT").unwrap(),
        "http://127.0.0.1:9000",
    );
    let dir = std::path::Path::new(&std::env::var("RUNNER_TEMP").unwrap())
        .join("wow-cloud07");
    let alice = std::fs::read_to_string(dir.join("alice/return.meta")).unwrap();
    let bob = std::fs::read_to_string(dir.join("bob/return.meta")).unwrap();
    assert_eq!(alice, bob, "authenticated participants must receive the same version pin");
    let expected_version = alice.lines().next().unwrap().to_owned();
    assert!(!expected_version.is_empty() && expected_version != "null");

    let key = format!("wow-mail/{}/{}", "3d".repeat(16), "6c".repeat(16));
    let conf = Builder::new()
        .behavior_version(aws_sdk_s3::config::BehaviorVersion::latest())
        .region(Region::new("us-east-1"))
        .credentials_provider(Credentials::new(
            std::env::var("WOW_MINIO_ACCESS").unwrap(),
            std::env::var("WOW_MINIO_SECRET").unwrap(),
            None, None, "temporary-cloud07-test-audit",
        ))
        .endpoint_url("http://127.0.0.1:9000")
        .force_path_style(true)
        .build();
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let s3 = Client::from_conf(conf);
        let result = s3.list_object_versions()
            .bucket(std::env::var("WOW_MINIO_BUCKET").unwrap())
            .prefix(&key)
            .send().await.unwrap();
        let versions: Vec<_> = result.versions().iter()
            .filter(|v| v.key() == Some(key.as_str()))
            .collect();
        assert_eq!(
            versions.len(), 1,
            "lost W4 PUT response must not create multiple remote object revisions",
        );
        assert_eq!(versions[0].version_id(), Some(expected_version.as_str()));
        assert_eq!(
            result.delete_markers().iter()
                .filter(|m| m.key() == Some(key.as_str())).count(),
            0,
            "mailbox reply must not be masked by a delete marker",
        );
    });
}
