//! Bounded, deterministic transport framing laboratory (W2).
//! Neither TCP/QUIC nor BLE drivers are included.
//! Parsed bytes are NOT authenticated; callers must perform E2E verification.

use crate::{WireError, BLE_HEADER_BYTES, MAX_MESSAGE_BYTES};
use std::collections::BTreeMap;

/// A stream decoder stores no more than one 16-KiB packet at a time.
/// Every push consumes at most one complete length-prefixed frame.
#[derive(Debug, Default)]
pub struct StreamDecoder {
    prefix: [u8; 4],
    prefix_len: usize,
    expected: Option<usize>,
    body: Vec<u8>,
}

impl StreamDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns (bytes_consumed, optional_raw_message).
    /// The caller must call again with unconsumed bytes for coalesced frames.
    /// An invalid length discards the current partial frame.
    pub fn push(&mut self, input: &[u8]) -> Result<(usize, Option<Vec<u8>>), WireError> {
        let mut used = 0;
        if self.expected.is_none() {
            let take = (4 - self.prefix_len).min(input.len());
            self.prefix[self.prefix_len..self.prefix_len + take]
                .copy_from_slice(&input[..take]);
            self.prefix_len += take;
            used += take;
            if self.prefix_len < 4 {
                return Ok((used, None));
            }
            let length = u32::from_be_bytes(self.prefix) as usize;
            if length == 0 {
                self.reset();
                return Err(WireError::InvalidEncoding);
            }
            if length > MAX_MESSAGE_BYTES {
                self.reset();
                return Err(WireError::TooLarge);
            }
            self.expected = Some(length);
        }
        let need = self.expected.expect("set above") - self.body.len();
        let take = need.min(input.len() - used);
        self.body.extend_from_slice(&input[used..used + take]);
        used += take;
        if self.body.len() == self.expected.expect("set above") {
            let message = std::mem::take(&mut self.body);
            self.reset();
            return Ok((used, Some(message)));
        }
        Ok((used, None))
    }

    pub fn buffered_bytes(&self) -> usize {
        self.prefix_len + self.body.len()
    }

    pub fn reset(&mut self) {
        self.prefix_len = 0;
        self.expected = None;
        self.body.clear();
    }
}

/// Caller-supplied link-local peer identity, bound by the radio/IP connection.
/// This is not a cryptographic author identity and conveys no file permissions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PeerKey(pub [u8; 16]);

/// Hard ceilings even when a caller provides a permissive configuration.
pub const HARD_MAX_TRANSFERS: usize = 32;
pub const HARD_MAX_RESERVED_PARTS: usize = 4096;
pub const HARD_MAX_PARTS_PER_TRANSFER: usize = 1536;
pub const HARD_MAX_FRAGMENT_PAYLOAD: usize = 512;
pub const HARD_MAX_BUFFERED_PAYLOAD: usize = 128 * 1024;

/// Resource policy is applied before making any allocation based on a frame.
#[derive(Debug, Clone, Copy)]
pub struct FragmentLimits {
    pub max_transfers: usize,
    pub max_transfers_per_peer: usize,
    pub max_parts_per_transfer: usize,
    pub max_reserved_parts: usize,
    pub max_fragment_payload: usize,
    pub max_total_bytes: usize,
    pub max_peer_bytes: usize,
    pub idle_timeout_ms: u64,
    pub absolute_timeout_ms: u64,
}

impl Default for FragmentLimits {
    fn default() -> Self {
        Self {
            max_transfers: 16,
            max_transfers_per_peer: 2,
            max_parts_per_transfer: HARD_MAX_PARTS_PER_TRANSFER,
            max_reserved_parts: HARD_MAX_RESERVED_PARTS,
            max_fragment_payload: HARD_MAX_FRAGMENT_PAYLOAD,
            max_total_bytes: 64 * 1024,
            max_peer_bytes: 32 * 1024,
            idle_timeout_ms: 30_000,
            absolute_timeout_ms: 120_000,
        }
    }
}

impl FragmentLimits {
    pub fn validate(self) -> Result<Self, WireError> {
        if self.max_transfers == 0
            || self.max_transfers > HARD_MAX_TRANSFERS
            || self.max_transfers_per_peer == 0
            || self.max_transfers_per_peer > self.max_transfers
            || self.max_parts_per_transfer == 0
            || self.max_parts_per_transfer > HARD_MAX_PARTS_PER_TRANSFER
            || self.max_reserved_parts == 0
            || self.max_reserved_parts > HARD_MAX_RESERVED_PARTS
            || self.max_parts_per_transfer > self.max_reserved_parts
            || self.max_fragment_payload == 0
            || self.max_fragment_payload > HARD_MAX_FRAGMENT_PAYLOAD
            || self.max_total_bytes == 0
            || self.max_total_bytes > HARD_MAX_BUFFERED_PAYLOAD
            || self.max_peer_bytes == 0
            || self.max_peer_bytes > self.max_total_bytes
            || self.idle_timeout_ms == 0
            || self.absolute_timeout_ms == 0
        {
            return Err(WireError::ResourceLimit);
        }
        Ok(self)
    }
}

struct Transfer {
    parts: Vec<Option<Vec<u8>>>,
    received: usize,
    payload_bytes: usize,
    first_ms: u64,
    last_ms: u64,
}

/// Counters include received payload bytes and reserved fragment slots.
/// Slot accounting matters: an attacker can request many empty slots cheaply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FragmentStats {
    pub transfers: usize,
    pub reserved_parts: usize,
    pub buffered_bytes: usize,
}

/// Multi-peer bounded receiver. All timestamps are caller-supplied MONOTONIC
/// milliseconds. No wall-clock or device time is used for expiry.
/// This service is in-memory, not a durable DTN store.
pub struct FragmentPool {
    limits: FragmentLimits,
    transfers: BTreeMap<(PeerKey, u32), Transfer>,
    last_time_ms: Option<u64>,
}

impl FragmentPool {
    pub fn new(limits: FragmentLimits) -> Result<Self, WireError> {
        Ok(Self {
            limits: limits.validate()?,
            transfers: BTreeMap::new(),
            last_time_ms: None,
        })
    }

    pub fn stats(&self) -> FragmentStats {
        FragmentStats {
            transfers: self.transfers.len(),
            reserved_parts: self.transfers.values().map(|x| x.parts.len()).sum(),
            buffered_bytes: self.transfers.values().map(|x| x.payload_bytes).sum(),
        }
    }

    pub fn reset(&mut self) {
        self.transfers.clear();
        self.last_time_ms = None;
    }

    /// Drop expired partial transfers. A backward clock step is rejected.
    /// Expiration also runs automatically before accepting every fragment.
    pub fn expire(&mut self, now_ms: u64) -> Result<usize, WireError> {
        if self.last_time_ms.is_some_and(|last| now_ms < last) {
            return Err(WireError::NonMonotonicTime);
        }
        self.last_time_ms = Some(now_ms);
        let before = self.transfers.len();
        self.transfers.retain(|_, transfer| {
            now_ms.saturating_sub(transfer.first_ms) < self.limits.absolute_timeout_ms
                && now_ms.saturating_sub(transfer.last_ms) < self.limits.idle_timeout_ms
        });
        Ok(before - self.transfers.len())
    }

    /// Returns a raw reassembled message when ALL pieces are present.
    /// Does not claim confidentiality, integrity, sender authority or delivery.
    pub fn accept(
        &mut self,
        peer: PeerKey,
        now_ms: u64,
        frame: &[u8],
    ) -> Result<Option<Vec<u8>>, WireError> {
        self.expire(now_ms)?;
        if frame.len() <= BLE_HEADER_BYTES {
            return Err(WireError::Truncated);
        }
        if frame.len() - BLE_HEADER_BYTES > self.limits.max_fragment_payload {
            return Err(WireError::TooLarge);
        }
        let transfer_id = u32::from_be_bytes(frame[0..4].try_into().expect("checked length"));
        let index = u16::from_be_bytes(frame[4..6].try_into().expect("checked length")) as usize;
        let count = u16::from_be_bytes(frame[6..8].try_into().expect("checked length")) as usize;
        let payload = &frame[BLE_HEADER_BYTES..];
        if count == 0 || count > self.limits.max_parts_per_transfer {
            return Err(WireError::FragmentCount);
        }
        if index >= count {
            return Err(WireError::FragmentMismatch);
        }

        let key = (peer, transfer_id);
        if let Some(existing) = self.transfers.get(&key) {
            if existing.parts.len() != count {
                return Err(WireError::FragmentMismatch);
            }
            if let Some(old) = &existing.parts[index] {
                if old == payload {
                    return Ok(None);
                }
                // Ambiguous transfer state must never be returned as complete.
                self.transfers.remove(&key);
                return Err(WireError::ConflictingDuplicate);
            }
            let global = self.stats();
            let peer_bytes: usize = self.transfers.iter()
                .filter(|((p, _), _)| *p == peer)
                .map(|(_, t)| t.payload_bytes)
                .sum();
            if global.buffered_bytes + payload.len() > self.limits.max_total_bytes
                || peer_bytes + payload.len() > self.limits.max_peer_bytes
                || existing.payload_bytes + payload.len() > MAX_MESSAGE_BYTES
            {
                return Err(WireError::ResourceLimit);
            }
            let state = self.transfers.get_mut(&key).expect("found above");
            state.parts[index] = Some(payload.to_vec());
            state.received += 1;
            state.payload_bytes += payload.len();
            state.last_ms = now_ms;

            if state.received == count {
                let state = self.transfers.remove(&key).expect("found above");
                let mut complete = Vec::with_capacity(state.payload_bytes);
                for piece in state.parts {
                    complete.extend_from_slice(&piece.expect("received count matched"));
                }
                return Ok(Some(complete));
            }
            return Ok(None);
        }

        if payload.len() > self.limits.max_total_bytes
            || payload.len() > self.limits.max_peer_bytes
            || payload.len() > MAX_MESSAGE_BYTES
        {
            return Err(WireError::ResourceLimit);
        }
        // A single-fragment message is complete without reserving state.
        if count == 1 {
            return Ok(Some(payload.to_vec()));
        }

        let stats = self.stats();
        let mut peer_transfers = 0;
        let mut peer_bytes = 0;
        for ((p, _), transfer) in &self.transfers {
            if *p == peer {
                peer_transfers += 1;
                peer_bytes += transfer.payload_bytes;
            }
        }
        if stats.transfers >= self.limits.max_transfers
            || peer_transfers >= self.limits.max_transfers_per_peer
            || stats.reserved_parts + count > self.limits.max_reserved_parts
            || stats.buffered_bytes + payload.len() > self.limits.max_total_bytes
            || peer_bytes + payload.len() > self.limits.max_peer_bytes
        {
            return Err(WireError::ResourceLimit);
        }
        let mut parts = vec![None; count];
        parts[index] = Some(payload.to_vec());
        self.transfers.insert(
            key,
            Transfer {
                parts,
                received: 1,
                payload_bytes: payload.len(),
                first_ms: now_ms,
                last_ms: now_ms,
            },
        );
        Ok(None)
    }
}
