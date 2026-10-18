//! TEST-ONLY stand-in for an independently trusted, durable, linearizable
//! control-plane checkpoint. In-memory Mutex state DOES NOT protect against
//! rollback after a real OS power loss or compromised host and MUST NEVER be
//! used as a production anchor implementation.
use akula_wire_lab::peer_enrollment_w6::{
    AnchorError, PolicyCheckpoint, TrustedPolicyAnchor,
};
use std::sync::Mutex;

#[derive(Debug)]
struct State {
    checkpoint: PolicyCheckpoint,
    unavailable: bool,
}

/// Explicit bootstrap from already-provisioned test data. Production systems
/// must bootstrap out-of-band from an independently authenticated operator
/// checkpoint; copying local SQLite's digest is not a trust ceremony.
#[derive(Debug)]
pub struct MemoryAnchor {
    state: Mutex<State>,
}
impl MemoryAnchor {
    pub fn new(checkpoint: PolicyCheckpoint) -> Self {
        Self { state: Mutex::new(State {checkpoint,unavailable:false}) }
    }
    pub fn set_unavailable(&self, unavailable: bool) {
        self.state.lock().unwrap().unavailable = unavailable;
    }
    pub fn observed(&self) -> PolicyCheckpoint {
        self.state.lock().unwrap().checkpoint
    }
}
impl TrustedPolicyAnchor for MemoryAnchor {
    fn current(&self) -> Result<PolicyCheckpoint, AnchorError> {
        let guard=self.state.lock().map_err(|_| AnchorError::Unavailable)?;
        if guard.unavailable {return Err(AnchorError::Unavailable);}
        Ok(guard.checkpoint)
    }
    fn advance(
        &self, expected: PolicyCheckpoint, replacement: PolicyCheckpoint,
    ) -> Result<(), AnchorError> {
        let mut guard=self.state.lock().map_err(|_| AnchorError::Unavailable)?;
        if guard.unavailable {return Err(AnchorError::Unavailable);}
        if guard.checkpoint!=expected || replacement.revision<=expected.revision {
            return Err(AnchorError::Conflict);
        }
        guard.checkpoint=replacement;
        Ok(())
    }
}
