//! CLOUD-02: S3-compatible laboratory adapter. Not production credentials,
//! signed grants, W4, custody transfer, or a version-independent data store.
//! The bucket must have S3 VERSIONING ENABLED before test execution.
//! Offline custodian read is tested with an independently instantiated client.
use akula_wire_lab::cloud_mail_store::{CloudKey, CloudRevision, CloudError, MAX_CLOUD_MAIL_BYTES};
use aws_sdk_s3::{Client, config::{retry::RetryConfig, Builder as S3ConfigBuilder, Credentials, Region}, primitives::ByteStream};

pub struct S3Lab {
    client: Client,
    bucket: String,
}
fn object_key(k: CloudKey) -> String {
    fn hex(bytes: &[u8]) -> String {
        const X: &[u8;16] = b"0123456789abcdef";
        let mut s=String::with_capacity(bytes.len()*2);
        for b in bytes {
            s.push(X[usize::from(b >> 4)] as char);
            s.push(X[usize::from(b & 15)] as char);
        }
        s
    }
    format!("wow-mail/{}/{}", hex(&k.namespace), hex(&k.object))
}
impl S3Lab {
    /// The endpoint and credentials belong to the trusted local test launcher;
    /// caller must allowlist endpoints in production. Never copy these keys to
    /// any sender or recipient.
    pub fn new(endpoint: &str, region: &str, bucket: &str, access: &str, secret: &str) -> Self {
        let conf = S3ConfigBuilder::new()
            .behavior_version(aws_sdk_s3::config::BehaviorVersion::latest())
            .region(Region::new(region.to_owned()))
            .credentials_provider(Credentials::new(access, secret, None, None, "wow-cloud-lab"))
            .endpoint_url(endpoint)
            .force_path_style(true)
            // Lost ACK must NOT trigger SDK-level blind repeated PUT attempts.
            .retry_config(RetryConfig::standard().with_max_attempts(1))
            .build();
        Self { client: Client::from_conf(conf), bucket: bucket.to_owned() }
    }
    /// Explicitly versioned create-only, with SDK retries disabled.
    /// Errors are ambiguous until separately reconciled; no W4 implied.
    pub async fn put_once(
        &self, key: CloudKey, encrypted: &[u8],
    ) -> Result<CloudRevision, CloudError> {
        if encrypted.is_empty() || encrypted.len() > MAX_CLOUD_MAIL_BYTES {
            return Err(CloudError::TooLarge);
        }
        let r = self.client.put_object()
            .bucket(&self.bucket).key(object_key(key))
            .if_none_match("*")
            .body(ByteStream::from(encrypted.to_vec()))
            .send().await.map_err(|_|CloudError::Ambiguous)?;
        let version = r.version_id().ok_or(CloudError::InvalidRevision)?;
        if version.is_empty() || version == "null" || version.len()>128 {
            return Err(CloudError::InvalidRevision);
        }
        Ok(CloudRevision::S3VersionId(version.to_owned()))
    }
    /// Laboratory capability: permit an exact-version read for at most one minute.
    /// The caller authenticates the recipient and transports this privately.
    pub async fn presign_read(
        &self, key: CloudKey, version: &CloudRevision, ttl_seconds: u64,
    ) -> Result<String, CloudError> {
        use aws_sdk_s3::presigning::PresigningConfig;
        use std::time::Duration;
        let CloudRevision::S3VersionId(v) = version else {
            return Err(CloudError::InvalidRevision);
        };
        if v.is_empty() || v == "null" || v.len() > 128 || ttl_seconds == 0 || ttl_seconds > 60 {
            return Err(CloudError::InvalidGrant);
        }
        let config=PresigningConfig::expires_in(Duration::from_secs(ttl_seconds))
            .map_err(|_| CloudError::InvalidGrant)?;
        let grant=self.client.get_object()
            .bucket(&self.bucket).key(object_key(key)).version_id(v)
            .presigned(config).await.map_err(|_| CloudError::Unavailable)?;
        Ok(grant.uri().to_owned())
    }
    /// A pinned version is necessary; NEVER silently fetch latest.
    /// A HEAD size bound is followed by a per-chunk bounded stream. This still
    /// does NOT authorize the caller or pin a trusted remote endpoint.
    pub async fn read_exact(
        &self, key: CloudKey, rev: &CloudRevision, max_bytes: usize,
        expected_blake3: [u8;32],
    ) -> Result<Vec<u8>, CloudError> {
        let CloudRevision::S3VersionId(version) = rev else {
            return Err(CloudError::InvalidRevision);
        };
        if version.is_empty() || version == "null" || version.len()>128 ||
           max_bytes == 0 || max_bytes > MAX_CLOUD_MAIL_BYTES {
            return Err(CloudError::InvalidRevision);
        }
        let path = object_key(key);
        let meta=self.client.head_object().bucket(&self.bucket).key(&path)
            .version_id(version).send().await.map_err(|_|CloudError::Unavailable)?;
        let len=meta.content_length().unwrap_or(-1);
        if len <= 0 || len > max_bytes as i64 {
            return Err(CloudError::TooLarge);
        }
        let get=self.client.get_object().bucket(&self.bucket).key(&path)
            .version_id(version).send().await.map_err(|_|CloudError::Unavailable)?;
        if get.content_length().unwrap_or(-1)!=len {
            return Err(CloudError::Corrupt);
        }
        // HEAD cannot be trusted as a true bound for an adversarial server.
        // Count actual streamed bytes before appending each chunk. Never call
        // ByteStream::collect() on an untrusted response.
        let mut stream=get.body;
        let mut bytes=Vec::with_capacity(len as usize);
        while let Some(next)=stream.next().await {
            let chunk=next.map_err(|_|CloudError::Unavailable)?;
            let total=bytes.len().checked_add(chunk.len()).ok_or(CloudError::TooLarge)?;
            if total>max_bytes || total>len as usize {
                return Err(CloudError::TooLarge);
            }
            bytes.extend_from_slice(&chunk);
        }
        if bytes.len()!=len as usize ||
            *blake3::hash(&bytes).as_bytes()!=expected_blake3 {
            return Err(CloudError::Corrupt);
        }
        Ok(bytes)
    }
}
