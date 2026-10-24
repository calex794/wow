//! Isolated WOW cloud-mail laboratory contract (M0/M1).
//!
//! A cloud provider is UNTRUSTED: HTTP success, a provider revision, and
//! a matching provider checksum do not prove future availability or recipient
//! delivery. This module is a bounded ciphertext transport verifier only.
//! UploadGrant / ReadPermit MUST be authenticated and authorized externally;
//! constructing these structs does not confer real access to S3 or Dropbox.
//! This module neither issues custody slot credits nor creates/accepts W4.
//! A successful readback is NOT a durability, anti-rollback or delivery proof.
//!
//! Backends must enforce bounded reads BEFORE allocation; a Vec returned by a
//! malicious backend cannot undo an already incurred network/resource cost.

use crate::MAX_MESSAGE_BYTES;

pub const MAX_CLOUD_MAIL_BYTES: usize = MAX_MESSAGE_BYTES;
pub const MAX_REVISION_LABEL_BYTES: usize = 128;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CloudKey {
    /// Private account/bucket namespace, never a public recipient ID.
    pub namespace: [u8; 16],
    /// Unlinkable random object identifier from an authenticated invitation.
    pub object: [u8; 16],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CloudProvider {
    Fake,
    S3,
    Dropbox,
}

/// A provider revision is a locator, NOT a signature or ciphertext digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CloudRevision {
    Fake(u64),
    S3VersionId(String),
    DropboxRev(String),
}
impl CloudRevision {
    fn valid_for(&self, provider: CloudProvider) -> bool {
        match (provider, self) {
            (CloudProvider::Fake, Self::Fake(n)) => *n != 0,
            (CloudProvider::S3, Self::S3VersionId(s))
            | (CloudProvider::Dropbox, Self::DropboxRev(s)) =>
                !s.is_empty() && s.len() <= MAX_REVISION_LABEL_BYTES,
            _ => false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectHint {
    /// Untrusted metadata, cross-checked against exact downloaded bytes.
    pub revision: CloudRevision,
    pub reported_len: usize,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum CloudError {
    InvalidGrant,
    WrongScope,
    Expired,
    TooLarge,
    Conflict,
    Missing,
    Unavailable,
    Ambiguous,
    Corrupt,
    InvalidRevision,
}

/// Locally validated bounds; cryptographic authorization remains external.
#[derive(Clone, Copy)]
pub struct UploadGrant {
    pub key: CloudKey,
    pub expected_blake3: [u8; 32],
    pub exact_len: usize,
    pub max_bytes: usize,
    pub expires_at_ms: u64,
}

/// A distinct read scope, expected to come from a receiver-authenticated
/// private invitation. This value is NOT a bearer credential by itself.
#[derive(Clone, Copy)]
pub struct ReadPermit {
    pub key: CloudKey,
    pub max_bytes: usize,
    pub expires_at_ms: u64,
}

/// Verified at one instant by downloading a specific revision. No W4 implied.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadbackPin {
    pub key: CloudKey,
    pub provider: CloudProvider,
    pub revision: CloudRevision,
    pub exact_len: usize,
    pub expected_blake3: [u8; 32],
}

pub trait CloudMailStore {
    fn provider(&self) -> CloudProvider;

    /// Provider must create a NEW object, not replace an existing key.
    /// A lost response may mean that the write was applied: return Ambiguous.
    fn put_if_absent(&mut self, key: CloudKey, ciphertext: &[u8])
        -> Result<(), CloudError>;

    /// Untrusted hint used to discover a candidate exact remote revision.
    fn describe(&self, key: CloudKey) -> Result<ObjectHint, CloudError>;

    /// Exact-version read bounded by max_bytes *before* allocation or transfer.
    /// No silent fallback to "latest" if the requested revision is missing.
    fn get_exact(
        &self, key: CloudKey, revision: &CloudRevision, max_bytes: usize,
    ) -> Result<Vec<u8>, CloudError>;
}

fn valid_key(key: CloudKey) -> bool {
    key.namespace != [0; 16] && key.object != [0; 16]
}
fn valid_limit(max_bytes: usize) -> bool {
    (1..=MAX_CLOUD_MAIL_BYTES).contains(&max_bytes)
}
fn verify_bytes(bytes: &[u8], expected_len: usize, expected_digest: [u8; 32])
    -> Result<(), CloudError>
{
    if bytes.len() != expected_len ||
        *blake3::hash(bytes).as_bytes() != expected_digest
    {
        return Err(CloudError::Corrupt);
    }
    Ok(())
}

/// Fail closed on invalid permissions/bytes BEFORE interacting with a provider.
/// A lost upload ACK is reconciled by exact-version readback, never by a blind
/// second PUT. An absent object after a lost ACK remains ambiguous.
pub fn upload_and_pin<S: CloudMailStore>(
    store: &mut S, grant: UploadGrant, ciphertext: &[u8], now_ms: u64,
) -> Result<ReadbackPin, CloudError> {
    if !valid_key(grant.key) || !valid_limit(grant.max_bytes) ||
        grant.exact_len == 0 || grant.exact_len > grant.max_bytes ||
        grant.exact_len != ciphertext.len()
    {
        return Err(CloudError::InvalidGrant);
    }
    if now_ms >= grant.expires_at_ms {
        return Err(CloudError::Expired);
    }
    verify_bytes(ciphertext, grant.exact_len, grant.expected_blake3)?;

    match store.put_if_absent(grant.key, ciphertext) {
        Ok(()) | Err(CloudError::Ambiguous) => {}
        Err(other) => return Err(other),
    }
    let hint = match store.describe(grant.key) {
        Ok(hint) => hint,
        Err(CloudError::Missing) | Err(CloudError::Unavailable) =>
            return Err(CloudError::Ambiguous),
        Err(other) => return Err(other),
    };
    if !hint.revision.valid_for(store.provider()) {
        return Err(CloudError::InvalidRevision);
    }
    // Provider metadata alone is not evidence, even if its length matches.
    if hint.reported_len != grant.exact_len {
        return Err(CloudError::Corrupt);
    }
    let observed = match store.get_exact(grant.key, &hint.revision, grant.max_bytes) {
        Ok(value) => value,
        Err(CloudError::Missing) | Err(CloudError::Unavailable) =>
            return Err(CloudError::Ambiguous),
        Err(other) => return Err(other),
    };
    if observed.len() > grant.max_bytes {
        return Err(CloudError::TooLarge);
    }
    verify_bytes(&observed, grant.exact_len, grant.expected_blake3)?;
    Ok(ReadbackPin {
        key: grant.key, provider: store.provider(),
        revision: hint.revision, exact_len: grant.exact_len,
        expected_blake3: grant.expected_blake3,
    })
}

/// An independently provisioned receiver can retrieve the exact bytes even
/// when the issuing custodian is offline, *if* the provider grants the receiver
/// the necessary read capability. No assertion of cryptographic W3 acceptance.
pub fn read_pinned<S: CloudMailStore>(
    store: &S, pin: &ReadbackPin, permit: ReadPermit, now_ms: u64,
) -> Result<Vec<u8>, CloudError> {
    if !valid_key(pin.key) || permit.key != pin.key ||
        store.provider() != pin.provider
    {
        return Err(CloudError::WrongScope);
    }
    if now_ms >= permit.expires_at_ms {
        return Err(CloudError::Expired);
    }
    if !valid_limit(permit.max_bytes) || pin.exact_len == 0 ||
        pin.exact_len > permit.max_bytes || !pin.revision.valid_for(pin.provider)
    {
        return Err(CloudError::InvalidGrant);
    }
    let observed = store.get_exact(pin.key, &pin.revision, permit.max_bytes)?;
    if observed.len() > permit.max_bytes {
        return Err(CloudError::TooLarge);
    }
    verify_bytes(&observed, pin.exact_len, pin.expected_blake3)?;
    Ok(observed)
}
