//! Experimental W4 **file committed** extension, not the legacy 137-byte
//! W4 *encrypted-message accepted* receipt. These domains and formats MUST
//! remain disjoint: receiving a W3 notification is not proof of file bytes.
//!
//! Receiver signs a statement binding exactly one authenticated W3 ciphertext
//! digest, stable message ID, selected BLAKE3 content root, 64-bit object
//! size, and the receiver's private Inbox transfer UUID. The signature alone
//! does not independently prove disk persistence; Akula's cold-verified Inbox
//! publisher must gate calling `sign_file_committed`.
//!
//! This crypto-only library has no SQLite, files, transport or authority to
//! persist, deduplicate or import any object into an Akula Vault.
use crate::trust_w3::TrustRegistry;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};

const VERSION: u8 = 1;
const DOMAIN: &[u8] = b"Akula/WOW/W4/file-committed/v1\0";
const SIGNED_BYTES: usize = 1 + 16 + 16 + 32 + 32 + 8 + 16 + 8;
pub const FILE_RECEIPT_BYTES: usize = SIGNED_BYTES + 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileReceiptError {
    InvalidLength,
    UnsupportedVersion,
    WrongBinding,
    InvalidSignature,
    UntrustedRecipient,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileCommitStatement {
    pub recipient_id: [u8; 16],
    pub message_id: [u8; 16],
    pub w3_packet_digest: [u8; 32],
    pub file_blake3: [u8; 32],
    pub file_size: u64,
    pub inbox_transfer_id: [u8; 16],
    pub recipient_epoch: u64,
}

impl FileCommitStatement {
    fn valid(self) -> bool {
        self.recipient_id != [0; 16]
            && self.message_id != [0; 16]
            && self.w3_packet_digest != [0; 32]
            && self.file_blake3 != [0; 32]
            && self.file_size > 0
            && self.file_size <= 8 * 1024 * 1024
            && self.inbox_transfer_id != [0; 16]
            && self.recipient_epoch != 0
    }

    fn encode(self) -> [u8; SIGNED_BYTES] {
        let mut body = [0u8; SIGNED_BYTES];
        let mut at = 0usize;
        fn copy(out: &mut [u8; SIGNED_BYTES], at: &mut usize, field: &[u8]) {
            out[*at..*at + field.len()].copy_from_slice(field);
            *at += field.len();
        }
        copy(&mut body, &mut at, &[VERSION]);
        copy(&mut body, &mut at, &self.recipient_id);
        copy(&mut body, &mut at, &self.message_id);
        copy(&mut body, &mut at, &self.w3_packet_digest);
        copy(&mut body, &mut at, &self.file_blake3);
        copy(&mut body, &mut at, &self.file_size.to_be_bytes());
        copy(&mut body, &mut at, &self.inbox_transfer_id);
        copy(&mut body, &mut at, &self.recipient_epoch.to_be_bytes());
        debug_assert_eq!(at, SIGNED_BYTES);
        body
    }
}

/// Crypto primitive only: application MUST first verify private on-disk
/// Inbox and independently provision matching current recipient signer.
pub fn sign_file_committed(
    recipient_signer: &SigningKey,
    statement: FileCommitStatement,
) -> Result<[u8; FILE_RECEIPT_BYTES], FileReceiptError> {
    if !statement.valid() {
        return Err(FileReceiptError::WrongBinding);
    }
    let mut result = [0u8; FILE_RECEIPT_BYTES];
    result[..SIGNED_BYTES].copy_from_slice(&statement.encode());
    let mut message = Vec::with_capacity(DOMAIN.len() + SIGNED_BYTES);
    message.extend_from_slice(DOMAIN);
    message.extend_from_slice(&result[..SIGNED_BYTES]);
    result[SIGNED_BYTES..].copy_from_slice(
        &recipient_signer.sign(&message).to_bytes()
    );
    Ok(result)
}

/// Verify independently enrolled recipient key and epoch. The caller MUST
/// compare all returned fields with its original authenticated W3 packet and
/// selected Akula object (including size/root and receiver Inbox UUID).
pub fn verify_file_committed(
    packet: &[u8],
    recipient_registry: &TrustRegistry,
) -> Result<FileCommitStatement, FileReceiptError> {
    if packet.len() != FILE_RECEIPT_BYTES {
        return Err(FileReceiptError::InvalidLength);
    }
    if packet[0] != VERSION {
        return Err(FileReceiptError::UnsupportedVersion);
    }
    let u64_field = |at: usize| -> u64 {
        u64::from_be_bytes(packet[at..at + 8].try_into().expect("checked length"))
    };
    let statement = FileCommitStatement {
        recipient_id: packet[1..17].try_into().unwrap(),
        message_id: packet[17..33].try_into().unwrap(),
        w3_packet_digest: packet[33..65].try_into().unwrap(),
        file_blake3: packet[65..97].try_into().unwrap(),
        file_size: u64_field(97),
        inbox_transfer_id: packet[105..121].try_into().unwrap(),
        recipient_epoch: u64_field(121),
    };
    if !statement.valid() {
        return Err(FileReceiptError::WrongBinding);
    }
    let key = recipient_registry
        .key_for(statement.recipient_id, statement.recipient_epoch)
        .map_err(|_| FileReceiptError::UntrustedRecipient)?;
    let signature = Signature::from_slice(&packet[SIGNED_BYTES..])
        .map_err(|_| FileReceiptError::InvalidSignature)?;
    let mut message = Vec::with_capacity(DOMAIN.len() + SIGNED_BYTES);
    message.extend_from_slice(DOMAIN);
    message.extend_from_slice(&packet[..SIGNED_BYTES]);
    key.verify(&message, &signature)
        .map_err(|_| FileReceiptError::InvalidSignature)?;
    Ok(statement)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn statement() -> FileCommitStatement {
        FileCommitStatement {
            recipient_id: [1; 16],
            message_id: [2; 16],
            w3_packet_digest: [3; 32],
            file_blake3: [4; 32],
            file_size: 5 * 1024 * 1024,
            inbox_transfer_id: [5; 16],
            recipient_epoch: 7,
        }
    }
    #[test]
    fn signed_file_ack_binds_full_content_and_refuses_old_w4() {
        let key = SigningKey::from_bytes(&[8; 32]);
        let mut trusted = TrustRegistry::new();
        trusted.enroll([1; 16], 7, key.verifying_key()).unwrap();
        let signed = sign_file_committed(&key, statement()).unwrap();
        assert_eq!(signed.len(), FILE_RECEIPT_BYTES);
        assert_eq!(verify_file_committed(&signed, &trusted), Ok(statement()));
        let again = sign_file_committed(&key, statement()).unwrap();
        assert_eq!(signed, again, "same committed item can be reissued after lost ACK");
        for i in [0, 1, 16, 17, 33, 64, 65, 96, 97, 104, 105, 120, 121, 128, 129, 192] {
            let mut damaged = signed;
            damaged[i] ^= 1;
            assert!(verify_file_committed(&damaged, &trusted).is_err(), "altered byte {i}");
        }
        assert!(verify_file_committed(&signed[..signed.len() - 1], &trusted).is_err());
        assert!(verify_file_committed(&[0u8; 137], &trusted).is_err(),
            "ordinary 137-byte W4 may not claim file-committed semantics");
        trusted.revoke([1; 16]).unwrap();
        assert_eq!(verify_file_committed(&signed, &trusted), Err(FileReceiptError::UntrustedRecipient));
    }
}
