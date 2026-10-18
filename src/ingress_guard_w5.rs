//! W5/W6 boundary experiment: bounded PRE-AUTH connection admission.
//!
//! Does not authenticate devices, identify real people, defeat a botnet,
//! solve Sybil attacks, provide transport endpoints, or authorize file access.
//! The lane comes from a trusted transport adapter, NEVER from remote bytes.
//! Caller must advance the clock from a local monotonic source. Remote packet
//! timestamps and claimed DeviceIds are explicitly ignored for admission.
use std::collections::BTreeMap;

const GLOBAL_ACTIVE: usize = 24;
const PER_LANE_ATTEMPTS_PER_TICK: u32 = 12;
const GLOBAL_ATTEMPTS_PER_TICK: u32 = 32;
const MAX_HANDSHAKE_BYTES: usize = 1024;
const MAX_BUFFERED_BYTES: usize = 16 * 1024;
const MAX_BYTES_RECEIVED_PER_TICK: usize = 8 * 1024;
const MAX_HANDSHAKE_FRAGMENTS: u8 = 16;
const HANDSHAKE_TTL_TICKS: u64 = 10;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Lane { Bluetooth, LocalNetwork, Iroh, Gateway }

impl Lane {
    const fn index(self) -> usize {
        match self {
            Self::Bluetooth => 0,
            Self::LocalNetwork => 1,
            Self::Iroh => 2,
            Self::Gateway => 3,
        }
    }
    const fn active_limit(self) -> usize {
        match self {
            Self::Bluetooth => 4,
            Self::LocalNetwork | Self::Iroh | Self::Gateway => 8,
        }
    }
}

/// Issued locally. Its numeric value is never accepted from network data.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Ticket(u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmissionError {
    RateLimited, AtCapacity, InvalidTicket, TooLarge, EmptyFragment,
    TooManyFragments, ClockRollback, ClockExhausted,
}

struct Pending {
    lane: Lane,
    expires: u64,
    parts: u8,
    bytes: Vec<u8>,
}

/// Bytes are NOT a trusted identity or an authenticated Akula message.
/// The next layer must independently validate keys, capabilities, and data.
pub struct UntrustedHandshake {
    bytes: Vec<u8>,
}
impl UntrustedHandshake {
    pub fn as_bytes(&self) -> &[u8] { &self.bytes }
    pub fn into_bytes(self) -> Vec<u8> { self.bytes }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdmissionStats {
    pub active: usize,
    pub buffered_bytes: usize,
    pub attempts_this_tick: u32,
    pub accepted_bytes_this_tick: usize,
}

/// No heap allocation keyed by user-controlled DeviceId. At most 24 live
/// tickets, a fixed four-entry lane array, and 16 KiB of retained bytes.
pub struct IngressGuard {
    now: u64,
    next_ticket: u64,
    sessions: BTreeMap<Ticket, Pending>,
    active_by_lane: [usize; 4],
    attempts_by_lane: [u32; 4],
    attempts_this_tick: u32,
    bytes_this_tick: usize,
    buffered_bytes: usize,
}

impl IngressGuard {
    pub fn new() -> Self {
        Self {
            now: 0,
            next_ticket: 1,
            sessions: BTreeMap::new(),
            active_by_lane: [0; 4],
            attempts_by_lane: [0; 4],
            attempts_this_tick: 0,
            bytes_this_tick: 0,
            buffered_bytes: 0,
        }
    }

    pub fn stats(&self) -> AdmissionStats {
        AdmissionStats {
            active: self.sessions.len(),
            buffered_bytes: self.buffered_bytes,
            attempts_this_tick: self.attempts_this_tick,
            accepted_bytes_this_tick: self.bytes_this_tick,
        }
    }

    pub fn active_on(&self, lane: Lane) -> usize { self.active_by_lane[lane.index()] }

    /// Invoke ONLY with a trusted local monotonic tick. Equal ticks do NOT
    /// replenish quotas; stale ticks cannot move this guard backwards.
    pub fn advance_tick(&mut self, now: u64) -> Result<(), AdmissionError> {
        if now < self.now { return Err(AdmissionError::ClockRollback); }
        if now == self.now { return Ok(()); }
        self.now = now;
        self.attempts_this_tick = 0;
        self.attempts_by_lane = [0; 4];
        self.bytes_this_tick = 0;
        let expired: Vec<_> = self.sessions.iter()
            .filter_map(|(&ticket, pending)| (pending.expires <= now).then_some(ticket))
            .collect();
        for ticket in expired {
            self.remove(ticket);
        }
        Ok(())
    }

    /// A remote-claimed 128-bit device ID is deliberately not used as a
    /// quota bucket or an authority. Every connection costs a real slot.
    pub fn begin(&mut self, lane: Lane, _claimed_device_id: [u8; 16])
        -> Result<Ticket, AdmissionError>
    {
        let idx = lane.index();
        if self.attempts_this_tick >= GLOBAL_ATTEMPTS_PER_TICK
            || self.attempts_by_lane[idx] >= PER_LANE_ATTEMPTS_PER_TICK
        { return Err(AdmissionError::RateLimited); }

        // Charge even an attempt denied by a full connection pool.
        self.attempts_this_tick += 1;
        self.attempts_by_lane[idx] += 1;

        if self.sessions.len() >= GLOBAL_ACTIVE
            || self.active_by_lane[idx] >= lane.active_limit()
        { return Err(AdmissionError::AtCapacity); }

        let expires = self.now.checked_add(HANDSHAKE_TTL_TICKS)
            .ok_or(AdmissionError::ClockExhausted)?;
        let next = self.next_ticket.checked_add(1)
            .ok_or(AdmissionError::ClockExhausted)?;
        let ticket = Ticket(self.next_ticket);
        self.next_ticket = next;
        self.sessions.insert(ticket, Pending {
            lane, expires, parts: 0, bytes: Vec::new(),
        });
        self.active_by_lane[idx] += 1;
        Ok(ticket)
    }

    /// Validate sizes before reserving more memory or copying a fragment.
    /// Repeating a self-claimed ID cannot reset per-ticket or global limits.
    pub fn offer_fragment(&mut self, ticket: Ticket, fragment: &[u8])
        -> Result<(), AdmissionError>
    {
        let pending = self.sessions.get(&ticket).ok_or(AdmissionError::InvalidTicket)?;
        if self.now >= pending.expires { return Err(AdmissionError::InvalidTicket); }
        if fragment.is_empty() { return Err(AdmissionError::EmptyFragment); }
        if pending.parts >= MAX_HANDSHAKE_FRAGMENTS {
            return Err(AdmissionError::TooManyFragments);
        }
        if pending.bytes.len().saturating_add(fragment.len()) > MAX_HANDSHAKE_BYTES
            || self.buffered_bytes.saturating_add(fragment.len()) > MAX_BUFFERED_BYTES
            || self.bytes_this_tick.saturating_add(fragment.len()) > MAX_BYTES_RECEIVED_PER_TICK
        { return Err(AdmissionError::TooLarge); }

        let pending = self.sessions.get_mut(&ticket).ok_or(AdmissionError::InvalidTicket)?;
        pending.bytes.extend_from_slice(fragment);
        pending.parts += 1;
        self.buffered_bytes += fragment.len();
        self.bytes_this_tick += fragment.len();
        Ok(())
    }

    /// Does not mark the peer authenticated; returns only untrusted bytes.
    pub fn take_untrusted(&mut self, ticket: Ticket)
        -> Result<UntrustedHandshake, AdmissionError>
    {
        let pending = self.remove(ticket).ok_or(AdmissionError::InvalidTicket)?;
        Ok(UntrustedHandshake { bytes: pending.bytes })
    }

    /// Explicit cancellation releases memory and a concurrent slot, but not
    /// the per-tick attempt/byte charges (prevents fast reconnect evasion).
    pub fn cancel(&mut self, ticket: Ticket) -> Result<(), AdmissionError> {
        self.remove(ticket).map(|_| ()).ok_or(AdmissionError::InvalidTicket)
    }

    fn remove(&mut self, ticket: Ticket) -> Option<Pending> {
        let pending = self.sessions.remove(&ticket)?;
        self.active_by_lane[pending.lane.index()] -= 1;
        self.buffered_bytes -= pending.bytes.len();
        Some(pending)
    }
}
impl Default for IngressGuard {
    fn default() -> Self { Self::new() }
}
