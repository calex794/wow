//! Signed exact-version locator for the CLOUD laboratory.
//!
//! A pin authenticates a ciphertext location, exact version and digest to a
//! *previously pinned* peer Ed25519 public key. It is not an S3 capability,
//! a trust bootstrap, a custody receipt or the final recipient W4.
//! The transport of keys and pins is still test-only in CLOUD-07.
use akula_wire_lab::cloud_mail_store::{
    CloudError, CloudKey, CloudRevision, MAX_CLOUD_MAIL_BYTES,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

const DOMAIN: &[u8] = b"WOW-CLOUD-S3-PIN-v1\0";
const SIGNATURE_LEN: usize = 64;
const MAX_REVISION_LEN: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Direction {
    ForwardW3 = 1,
    ReturnW4 = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PinScope {
    pub direction: Direction,
    pub key: CloudKey,
    pub recipient: [u8; 16],
    pub message: [u8; 16],
    pub expires_at_ms: u64,
}

#[derive(Debug, Eq, PartialEq)]
pub struct VerifiedPin {
    pub revision: CloudRevision,
    pub length: usize,
    pub digest: [u8; 32],
}

fn validate_revision(revision: &CloudRevision) -> Result<&str, CloudError> {
    let CloudRevision::S3VersionId(value) = revision else {
        return Err(CloudError::InvalidRevision);
    };
    if value.is_empty() || value == "null" ||
        value.len() > MAX_REVISION_LEN ||
        !value.bytes().all(|b| (0x21..=0x7e).contains(&b))
    {
        return Err(CloudError::InvalidRevision);
    }
    Ok(value)
}

/// Produce canonical signed bytes; the public key must be authenticated
/// independently, not taken from the same unsigned invitation.
pub fn issue(
    signer: &SigningKey, scope: PinScope, revision: &CloudRevision,
    opaque_ciphertext: &[u8],
) -> Result<Vec<u8>, CloudError> {
    if scope.expires_at_ms == 0 || opaque_ciphertext.is_empty() ||
        opaque_ciphertext.len() > MAX_CLOUD_MAIL_BYTES
    {
        return Err(CloudError::InvalidGrant);
    }
    let rev = validate_revision(revision)?;
    let mut body = Vec::with_capacity(256 + rev.len());
    body.extend_from_slice(DOMAIN);
    body.push(scope.direction as u8);
    body.extend_from_slice(&scope.key.namespace);
    body.extend_from_slice(&scope.key.object);
    body.extend_from_slice(&scope.recipient);
    body.extend_from_slice(&scope.message);
    body.extend_from_slice(&scope.expires_at_ms.to_be_bytes());
    body.extend_from_slice(&(opaque_ciphertext.len() as u32).to_be_bytes());
    body.extend_from_slice(&(rev.len() as u16).to_be_bytes());
    body.extend_from_slice(rev.as_bytes());
    body.extend_from_slice(blake3::hash(opaque_ciphertext).as_bytes());
    let signature = signer.sign(&body).to_bytes();
    body.extend_from_slice(&signature);
    Ok(body)
}
fn take<'a>(input: &'a [u8], index: &mut usize, n: usize)
    -> Result<&'a [u8], CloudError>
{
    let end = index.checked_add(n).ok_or(CloudError::InvalidGrant)?;
    let value = input.get(*index..end).ok_or(CloudError::InvalidGrant)?;
    *index = end;
    Ok(value)
}

/// Fail closed on the pinned peer identity, scope, expiry and exact byte
/// envelope. The caller MUST also read the pinned S3 VersionId and verify
/// the downloaded ciphertext against VerifiedPin.digest.
pub fn verify(
    input: &[u8], pinned_signer: &VerifyingKey, expected: PinScope,
    now_ms: u64,
) -> Result<VerifiedPin, CloudError> {
    if input.len() > 512 || input.len() < DOMAIN.len() + 1 + 16 * 4 + 8 + 4 +
        2 + 1 + 32 + SIGNATURE_LEN
    {
        return Err(CloudError::InvalidGrant);
    }
    let signed_len = input.len() - SIGNATURE_LEN;
    let signed = &input[..signed_len];
    let signature_bytes: [u8; SIGNATURE_LEN] = input[signed_len..]
        .try_into().map_err(|_| CloudError::InvalidGrant)?;
    let signature = Signature::from_bytes(&signature_bytes);
    pinned_signer.verify_strict(signed, &signature)
        .map_err(|_| CloudError::Corrupt)?;

    let mut index = 0;
    if take(signed, &mut index, DOMAIN.len())? != DOMAIN {
        return Err(CloudError::InvalidGrant);
    }
    let direction = take(signed, &mut index, 1)?[0];
    let namespace: [u8; 16] = take(signed, &mut index, 16)?
        .try_into().map_err(|_| CloudError::InvalidGrant)?;
    let object: [u8; 16] = take(signed, &mut index, 16)?
        .try_into().map_err(|_| CloudError::InvalidGrant)?;
    let recipient: [u8; 16] = take(signed, &mut index, 16)?
        .try_into().map_err(|_| CloudError::InvalidGrant)?;
    let message: [u8; 16] = take(signed, &mut index, 16)?
        .try_into().map_err(|_| CloudError::InvalidGrant)?;
    let expiry = u64::from_be_bytes(
        take(signed, &mut index, 8)?.try_into()
            .map_err(|_| CloudError::InvalidGrant)?,
    );
    let length = u32::from_be_bytes(
        take(signed, &mut index, 4)?.try_into()
            .map_err(|_| CloudError::InvalidGrant)?,
    ) as usize;
    let rev_len = u16::from_be_bytes(
        take(signed, &mut index, 2)?.try_into()
            .map_err(|_| CloudError::InvalidGrant)?,
    ) as usize;
    if rev_len == 0 || rev_len > MAX_REVISION_LEN {
        return Err(CloudError::InvalidRevision);
    }
    let version = std::str::from_utf8(take(signed, &mut index, rev_len)?)
        .map_err(|_| CloudError::InvalidRevision)?.to_owned();
    validate_revision(&CloudRevision::S3VersionId(version.clone()))?;
    let digest: [u8; 32] = take(signed, &mut index, 32)?
        .try_into().map_err(|_| CloudError::InvalidGrant)?;
    if index != signed.len() || length == 0 || length > MAX_CLOUD_MAIL_BYTES {
        return Err(CloudError::InvalidGrant);
    }
    if direction != expected.direction as u8 ||
        namespace != expected.key.namespace || object != expected.key.object ||
        recipient != expected.recipient || message != expected.message ||
        expiry != expected.expires_at_ms
    {
        return Err(CloudError::WrongScope);
    }
    if now_ms >= expiry {
        return Err(CloudError::Expired);
    }
    Ok(VerifiedPin {
        revision: CloudRevision::S3VersionId(version),
        length,
        digest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn scope() -> PinScope {
        PinScope {
            direction: Direction::ForwardW3,
            key: CloudKey { namespace: [11; 16], object: [12; 16] },
            recipient: [13; 16], message: [14; 16], expires_at_ms: 10_000,
        }
    }
    #[test]
    fn signature_scope_and_expiry_are_mandatory() {
        let signer = SigningKey::from_bytes(&[9; 32]);
        let payload = b"opaque W3 test ciphertext";
        let encoded = issue(
            &signer, scope(), &CloudRevision::S3VersionId("rev-1".into()),
            payload,
        ).unwrap();
        let pin = verify(&encoded, &signer.verifying_key(), scope(), 100).unwrap();
        assert_eq!(pin.length, payload.len());
        assert_eq!(pin.digest, *blake3::hash(payload).as_bytes());
        assert_eq!(pin.revision, CloudRevision::S3VersionId("rev-1".into()));

        let wrong_signer = SigningKey::from_bytes(&[7; 32]);
        assert_eq!(
            verify(&encoded, &wrong_signer.verifying_key(), scope(), 100),
            Err(CloudError::Corrupt),
        );
        let mut damaged = encoded.clone();
        let middle = damaged.len() / 2;
        damaged[middle] ^= 1;
        assert_eq!(
            verify(&damaged, &signer.verifying_key(), scope(), 100),
            Err(CloudError::Corrupt),
        );
        let mut wrong = scope();
        wrong.key.object = [44; 16];
        assert_eq!(
            verify(&encoded, &signer.verifying_key(), wrong, 100),
            Err(CloudError::WrongScope),
        );
        wrong = scope();
        wrong.direction = Direction::ReturnW4;
        assert_eq!(
            verify(&encoded, &signer.verifying_key(), wrong, 100),
            Err(CloudError::WrongScope),
        );
        wrong = scope();
        wrong.message = [55; 16];
        assert_eq!(
            verify(&encoded, &signer.verifying_key(), wrong, 100),
            Err(CloudError::WrongScope),
        );
        assert_eq!(
            verify(&encoded, &signer.verifying_key(), scope(), 10_000),
            Err(CloudError::Expired),
        );
        assert_eq!(
            verify(&encoded[..encoded.len() - 1], &signer.verifying_key(), scope(), 100),
            Err(CloudError::InvalidGrant),
        );
    }
}
