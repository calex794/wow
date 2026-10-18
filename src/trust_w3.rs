//! Experimental in-memory trust registry, not a persistent key authority.
//! Trust must be provisioned by a separately authenticated enrollment flow.
use ed25519_dalek::VerifyingKey;
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrustError { Untrusted, Revoked, WrongEpoch, WrongKey, EpochRollback, EpochConflict }

#[derive(Clone)]
struct Entry { epoch: u64, key: VerifyingKey, revoked: bool }

#[derive(Default)]
pub struct TrustRegistry { devices: BTreeMap<[u8;16], Entry> }

impl TrustRegistry {
    pub fn new() -> Self { Self::default() }

    /// Explicitly provision a trust root or replace an existing one with a
    /// strictly newer epoch. Calling this method is itself a privileged action.
    pub fn enroll(&mut self, device: [u8;16], epoch: u64, key: VerifyingKey)
        -> Result<(), TrustError>
    {
        match self.devices.get(&device) {
            Some(old) if epoch < old.epoch => Err(TrustError::EpochRollback),
            Some(old) if epoch == old.epoch && old.revoked => Err(TrustError::Revoked),
            Some(old) if epoch == old.epoch && old.key != key => Err(TrustError::EpochConflict),
            Some(old) if epoch == old.epoch => Ok(()),
            _ => {
                self.devices.insert(device, Entry { epoch, key, revoked: false });
                Ok(())
            }
        }
    }

    /// Revocation is sticky for a given epoch; enrollment of a newer epoch
    /// requires an independent authenticated re-enrollment decision.
    pub fn revoke(&mut self, device: [u8;16]) -> Result<(), TrustError> {
        let entry=self.devices.get_mut(&device).ok_or(TrustError::Untrusted)?;
        entry.revoked=true;
        Ok(())
    }

    /// Return the registry-owned key for an exact nonrevoked epoch.
    pub fn key_for(&self, device: [u8;16], epoch: u64)
        -> Result<&VerifyingKey, TrustError>
    {
        let entry=self.devices.get(&device).ok_or(TrustError::Untrusted)?;
        if entry.revoked { return Err(TrustError::Revoked); }
        if entry.epoch != epoch { return Err(TrustError::WrongEpoch); }
        Ok(&entry.key)
    }

    pub fn verify(&self, device: [u8;16], epoch: u64, key: &VerifyingKey)
        -> Result<(), TrustError>
    {
        let entry=self.devices.get(&device).ok_or(TrustError::Untrusted)?;
        if entry.revoked { return Err(TrustError::Revoked); }
        if epoch != entry.epoch { return Err(TrustError::WrongEpoch); }
        if &entry.key != key { return Err(TrustError::WrongKey); }
        Ok(())
    }
}
