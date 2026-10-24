//! Independent *client-side* availability observation for untrusted WOW
//! mail custodians. A valid Ed25519 CustodianStored claim is not storage proof.
//!
//! This checker consumes a ciphertext reference obtained from the trusted
//! sender/recipient, NOT a hash supplied by the custodian being audited.
//! A successful observation proves only that exact bytes were returned at
//! the caller-supplied time. It does NOT prove disk residency, independent
//! operators, continuous retention, future availability or recipient W4.
//! Authentication and authorization of the Fetch response are performed by
//! the caller; the route token alone MUST NOT be a read capability.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditError {
    InvalidReference,
    InvalidTime,
    Unavailable,
    WrongLength,
    WrongCiphertext,
}

/// The trusted sender/recipient established this exact ciphertext reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditReference {
    length: usize,
    digest: [u8; 32],
}

impl AuditReference {
    pub fn from_trusted_ciphertext(packet: &[u8]) -> Result<Self, AuditError> {
        if packet.is_empty() || packet.len() > crate::MAX_MESSAGE_BYTES {
            return Err(AuditError::InvalidReference);
        }
        Ok(Self {
            length: packet.len(),
            digest: *blake3::hash(packet).as_bytes(),
        })
    }

    pub fn ciphertext_digest(&self) -> [u8; 32] {
        self.digest
    }

    /// Trusted exact ciphertext length, for grant scope checks.
    pub fn ciphertext_len(&self) -> usize {
        self.length
    }

    /// Treat missing, refused or timed-out reads as *unavailable*, not fraud.
    /// The trusted observer supplies its own local time; nothing in the
    /// custodian's reply proves what time it was or where it was stored.
    pub fn observe(
        &self,
        returned: Option<&[u8]>,
        observed_at_ms: u64,
    ) -> Result<AvailabilityObservation, AuditError> {
        if observed_at_ms == 0 {
            return Err(AuditError::InvalidTime);
        }
        let bytes = returned.ok_or(AuditError::Unavailable)?;
        if bytes.len() != self.length {
            return Err(AuditError::WrongLength);
        }
        if *blake3::hash(bytes).as_bytes() != self.digest {
            return Err(AuditError::WrongCiphertext);
        }
        Ok(AvailabilityObservation {
            observed_at_ms,
            ciphertext_digest: self.digest,
        })
    }
}

/// May only be produced by an independent exact-byte check. No method can
/// convert this into VerifiedRecipientReceipt; B must accept W3 and sign W4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AvailabilityObservation {
    observed_at_ms: u64,
    ciphertext_digest: [u8; 32],
}
impl AvailabilityObservation {
    pub fn observed_at_ms(&self) -> u64 {
        self.observed_at_ms
    }

    pub fn ciphertext_digest(&self) -> [u8; 32] {
        self.ciphertext_digest
    }
}
