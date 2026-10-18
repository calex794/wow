//! W5 deterministic, transport-free store-and-forward laboratory.
//!
//! Routes are deliberately fixed for A -> B -> gateway -> mailbox -> G,
//! then G -> mailbox -> gateway -> B -> A for an opaque signed receipt.
//! This is NOT a discovery protocol, production router or trusted delivery
//! authority. In particular, presence at G does not mean an authenticated
//! receipt or an accepted Sync Core operation.
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt::Write;
use crate::crypto_identity_w3::{open, TrustedRecipient};
use crate::crypto_w3::CryptoError;

pub type MessageId = [u8; 16];
const MAX_TICKS: u64 = 1024;
const MAX_MESSAGES: usize = 16;
const MAX_TRACE: usize = 4096;
const MAX_ALTERNATES_PER_KEY: usize = 2;
const MAX_REJECTED_PER_KEY: usize = 4;
const MAX_CACHE_BYTES: usize = 1024 * 1024;
const MAX_PENDING_FLIGHTS: usize = 256;
const MAX_FAULT_INJECTIONS: usize = 64;
const MAX_UNTRUSTED_OFFERS_PER_TICK: usize = 32;
const MAX_UNTRUSTED_OFFERS_PER_KEY_PER_TICK: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Node { A, B, V, W, Mailbox, G }
impl Node {
    fn name(self) -> &'static str {
        match self {
            Self::A => "A", Self::B => "B", Self::V => "V",
            Self::W => "W", Self::Mailbox => "Mailbox", Self::G => "G",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Flow { Data, Receipt }
impl Flow {
    fn name(self) -> &'static str {
        match self { Self::Data => "data", Self::Receipt => "receipt" }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Fault { Drop, Duplicate, Corrupt, Delay(u64) }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SimError { InvalidOrigin, InvalidPayload, Expired, Conflict, ResourceLimit }

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Trace {
    pub tick: u64,
    pub from: Node,
    pub to: Node,
    pub flow: Flow,
    pub message_id: MessageId,
    pub event: &'static str,
}

#[derive(Clone)]
struct Stored {
    bytes: Vec<u8>,
    expires: u64,
}

#[derive(Clone)]
struct Transit {
    from: Node,
    to: Node,
    flow: Flow,
    id: MessageId,
    stored: Stored,
    due: u64,
}

#[derive(Clone, Copy)]
struct InjectedFault {
    from: Node,
    to: Node,
    flow: Flow,
    fault: Fault,
}

/// No clock, OS, network or user-data side effects. Every step is repeatable
/// for the same seed, link schedule, input bytes and ordered fault injections.
pub struct Simulation {
    tick: u64,
    rng: u64,
    alive: BTreeSet<Node>,
    opted_in: BTreeSet<Node>,
    links: BTreeSet<(Node, Node)>,
    copies: BTreeMap<(Node, Flow, MessageId), Stored>,
    // Different bytes with the same ID are UNTRUSTED candidates, not overwrites.
    // Limit alternate candidates so an attacker cannot grow unbounded memory.
    alternates: BTreeMap<(Node, Flow, MessageId), Vec<Stored>>,
    // Only G (using its own crypto keys) can mark invalid data variants here.
    rejected: BTreeMap<(Node, Flow, MessageId), VecDeque<[u8; 32]>>,
    known: BTreeSet<MessageId>,
    pending: Vec<Transit>,
    faults: Vec<InjectedFault>,
    trace: VecDeque<Trace>,
    dropped_trace_events: u64,
    untrusted_this_tick: usize,
    untrusted_by_key: BTreeMap<(Node, Flow, MessageId), usize>,
}

impl Simulation {
    pub fn new(seed: u64) -> Self {
        Self {
            tick: 0,
            rng: if seed == 0 { 0x9e3779b97f4a7c15 } else { seed },
            alive: [Node::A, Node::B, Node::V, Node::W, Node::Mailbox, Node::G]
                .into_iter().collect(),
            opted_in: BTreeSet::new(),
            links: BTreeSet::new(),
            copies: BTreeMap::new(),
            alternates: BTreeMap::new(),
            rejected: BTreeMap::new(),
            known: BTreeSet::new(),
            pending: Vec::new(),
            faults: Vec::new(),
            trace: VecDeque::new(),
            dropped_trace_events: 0,
            untrusted_this_tick: 0,
            untrusted_by_key: BTreeMap::new(),
        }
    }

    pub fn tick(&self) -> u64 { self.tick }
    pub fn events(&self) -> &VecDeque<Trace> { &self.trace }
    pub fn dropped_trace_events(&self) -> u64 { self.dropped_trace_events }
    pub fn copies(&self) -> usize { self.copies.len() }
    pub fn cached_bytes(&self) -> usize {
        self.copies.values().map(|v| v.bytes.len()).sum::<usize>()
            + self.alternates.values().flatten().map(|v| v.bytes.len()).sum::<usize>()
    }
    pub fn buffered_bytes(&self) -> usize {
        self.cached_bytes() + self.pending.iter().map(|v|v.stored.bytes.len()).sum::<usize>()
    }
    pub fn rejected_fingerprints(&self) -> usize {
        self.rejected.values().map(VecDeque::len).sum::<usize>()
    }

    pub fn connect(&mut self, a: Node, b: Node, enabled: bool) {
        if a == b { return; }
        let pair = ordered_pair(a, b);
        if enabled { self.links.insert(pair); } else { self.links.remove(&pair); }
    }

    /// Relay participation must be opted in, never implied by network access.
    pub fn relay_opt_in(&mut self, node: Node, enabled: bool) {
        if !matches!(node, Node::B | Node::V | Node::W) { return; }
        if enabled { self.opted_in.insert(node); } else { self.opted_in.remove(&node); }
    }

    /// An offline intermediary loses its volatile forwarding copies.
    /// The modeled Mailbox retains previously accepted bytes across restarts;
    /// its durable behavior is only an abstraction, not a tested disk store.
    /// The real sender's W4 journal is independent from this simulator.
    pub fn set_alive(&mut self, node: Node, enabled: bool) {
        if enabled {
            self.alive.insert(node);
        } else {
            self.alive.remove(&node);
            if node != Node::Mailbox {
                self.copies.retain(|(n, _, _), _| *n != node);
                self.alternates.retain(|(n, _, _), _| *n != node);
                self.rejected.retain(|(n, _, _), _| *n != node);
            }
        }
    }

    /// Fault queue is bounded even if a caller tries to insert thousands.
    /// Returns false when full; existing fault injections remain unchanged.
    pub fn inject_once(&mut self, from: Node, to: Node, flow: Flow, fault: Fault) -> bool {
        if self.faults.len() >= MAX_FAULT_INJECTIONS { return false; }
        self.faults.push(InjectedFault { from, to, flow, fault });
        true
    }

    pub fn fault_queue_len(&self) -> usize { self.faults.len() }

    /// Test-only network-edge model: an UNTRUSTED mailbox can offer bytes
    /// claiming to be a known message. This is not peer authentication or
    /// network discovery. Only G's local crypto verification grants trust.
    /// Enforces per-tick admission limits before copying malicious payloads.
    pub fn offer_untrusted_mailbox_frame(&mut self, id: MessageId, expires: u64, bytes: &[u8])
        -> Result<(), SimError>
    {
        let from = Node::Mailbox;
        let to = Node::G;
        let flow = Flow::Data;
        let key = (to, flow, id);
        if !self.available(from, to) { return Err(SimError::InvalidOrigin); }
        let Some(source) = self.copies.get(&(Node::A, flow, id)) else {
            return Err(SimError::InvalidOrigin);
        };
        if source.expires != expires { return Err(SimError::Conflict); }
        if bytes.is_empty() || bytes.len() > crate::MAX_MESSAGE_BYTES {
            return Err(SimError::InvalidPayload);
        }
        if expires <= self.tick { return Err(SimError::Expired); }
        if self.untrusted_this_tick >= MAX_UNTRUSTED_OFFERS_PER_TICK
            || self.untrusted_by_key.get(&key).copied().unwrap_or(0)
               >= MAX_UNTRUSTED_OFFERS_PER_KEY_PER_TICK
        { return Err(SimError::ResourceLimit); }
        self.untrusted_this_tick += 1;
        *self.untrusted_by_key.entry(key).or_default() += 1;
        self.arrive(Transit {
            from, to, flow, id,
            stored: Stored { bytes: bytes.to_vec(), expires }, due: self.tick,
        })
    }

    pub fn submit_data(&mut self, id: MessageId, expires: u64, opaque: &[u8])
        -> Result<(), SimError>
    {
        self.submit(Node::A, Flow::Data, id, expires, opaque)
    }

    /// A simulated G can offer a *claimed* receipt; only the sender's
    /// receipt_w4::verify + Journal::apply_recipient_receipt may trust it.
    pub fn submit_receipt(&mut self, id: MessageId, expires: u64, claimed: &[u8])
        -> Result<(), SimError>
    {
        self.submit(Node::G, Flow::Receipt, id, expires, claimed)
    }

    fn submit(&mut self, node: Node, flow: Flow, id: MessageId, expires: u64, bytes: &[u8])
        -> Result<(), SimError>
    {
        if !self.alive.contains(&node) { return Err(SimError::InvalidOrigin); }
        if bytes.is_empty() || bytes.len() > crate::MAX_MESSAGE_BYTES {
            return Err(SimError::InvalidPayload);
        }
        if expires <= self.tick { return Err(SimError::Expired); }
        if !self.known.contains(&id) && self.known.len() >= MAX_MESSAGES {
            return Err(SimError::ResourceLimit);
        }
        let key = (node, flow, id);
        if let Some(old) = self.copies.get(&key) {
            return if old.bytes == bytes { Ok(()) } else { Err(SimError::Conflict) };
        }
        if self.buffered_bytes().saturating_add(bytes.len()) > MAX_CACHE_BYTES {
            return Err(SimError::ResourceLimit);
        }
        self.known.insert(id);
        self.copies.insert(key, Stored { bytes: bytes.to_vec(), expires });
        self.emit(node, node, flow, id, "queued")?;
        Ok(())
    }

    pub fn packet(&self, node: Node, flow: Flow, id: MessageId) -> Option<&[u8]> {
        self.copies.get(&(node, flow, id)).map(|s| s.bytes.as_slice())
    }

    fn has_copy(&self, key: (Node, Flow, MessageId), bytes: &[u8]) -> bool {
        self.copies.get(&key).is_some_and(|s| s.bytes == bytes)
            || self.alternates.get(&key).is_some_and(|v| v.iter().any(|s| s.bytes == bytes))
    }

    fn rejected_here(&self, key: (Node, Flow, MessageId), bytes: &[u8]) -> bool {
        self.rejected.get(&key).is_some_and(|seen| seen.contains(blake3::hash(bytes).as_bytes()))
    }

    /// Endpoint-only cryptographic check for the W3 v2 *research* envelope.
    /// Bad AEAD/signature bytes are quarantined LOCALLY at G. No relay or
    /// remote rejection request can delete somebody else's stored copy.
    /// Missing/expired trust alone is not proof of corrupted bytes.
    /// Successful verification returns a payload, NOT Sync Core permission.
    pub fn verify_data_at_g(&mut self, id: MessageId, recipient: TrustedRecipient<'_>)
        -> Result<Option<Vec<u8>>, CryptoError>
    {
        let Some(raw) = self.packet(Node::G, Flow::Data, id).map(<[u8]>::to_vec)
            else { return Ok(None); };
        match open(&raw, recipient) {
            Ok((header, body)) if header.message_id == id => Ok(Some(body)),
            Ok(_) => {
                self.quarantine_bad_at_g(id, &raw);
                Err(CryptoError::InvalidPacket)
            }
            Err(err @ (CryptoError::DecryptFailed | CryptoError::InvalidSignature
                | CryptoError::InvalidPacket | CryptoError::UnknownSuite
                | CryptoError::Oversized)) => {
                self.quarantine_bad_at_g(id, &raw);
                Err(err)
            }
            Err(err) => Err(err),
        }
    }

    fn quarantine_bad_at_g(&mut self, id: MessageId, observed: &[u8]) {
        let key = (Node::G, Flow::Data, id);
        // Exact local compare prevents a stale report from deleting a new copy.
        if self.packet(Node::G, Flow::Data, id) != Some(observed) { return; }
        let digest = *blake3::hash(observed).as_bytes();
        let rejected = self.rejected.entry(key).or_default();
        if !rejected.contains(&digest) {
            if rejected.len() >= MAX_REJECTED_PER_KEY {
                rejected.pop_front(); // bounded recent negatives; crypto always rechecked
            }
            rejected.push_back(digest);
        }
        self.copies.remove(&key);
        // Promote a staged DIFFERENT candidate only as unverified data.
        // It must pass verify_data_at_g separately before an app may use it.
        let replacement = self.alternates.get_mut(&key).and_then(|candidates| {
            let index = candidates.iter().position(|s|
                !rejected.contains(blake3::hash(&s.bytes).as_bytes()))?;
            Some(candidates.remove(index))
        });
        if self.alternates.get(&key).is_some_and(Vec::is_empty) {
            self.alternates.remove(&key);
        }
        if let Some(next) = replacement { self.copies.insert(key, next); }
        let _ = self.emit(Node::G, Node::G, Flow::Data, id, "quarantined");
    }

    pub fn run(&mut self, ticks: u64) -> Result<(), SimError> {
        for _ in 0..ticks { self.step()?; }
        Ok(())
    }

    pub fn step(&mut self) -> Result<(), SimError> {
        if self.tick >= MAX_TICKS { return Err(SimError::ResourceLimit); }
        self.tick += 1;
        self.untrusted_this_tick = 0;
        self.untrusted_by_key.clear();

        // Complete flights scheduled on prior ticks before offering new ones.
        let flights = std::mem::take(&mut self.pending);
        for flight in flights {
            if flight.due <= self.tick {
                self.arrive(flight)?;
            } else {
                self.pending.push(flight);
            }
        }

        // Snapshot before transfers: at most one hop per tick. Caches may
        // stage bounded conflicting variants but they never overwrite silently.
        let mut candidates = Vec::new();
        for (&(from, flow, id), primary) in &self.copies {
            if !self.alive.contains(&from) || !self.may_forward(from) { continue; }
            let sources = std::iter::once(primary)
                .chain(self.alternates.get(&(from, flow, id)).into_iter().flatten());
            for stored in sources {
                if self.tick >= stored.expires { continue; }
                for &to in destinations(from, flow) {
                    if !self.available(from, to) { continue; }
                    let target = (to, flow, id);
                    if self.has_copy(target, &stored.bytes)
                        || self.rejected_here(target, &stored.bytes) { continue; }
                    if self.pending.iter().any(|p| p.from == from && p.to == to
                        && p.flow == flow && p.id == id && p.stored.bytes == stored.bytes)
                    { continue; }
                    candidates.push(Transit {
                        from, to, flow, id, stored: stored.clone(), due: self.tick,
                    });
                }
            }
        }

        // Seed-dependent order, deterministic for a given scenario.
        for i in (1..candidates.len()).rev() {
            let j = (self.random() as usize) % (i + 1);
            candidates.swap(i, j);
        }
        for mut flight in candidates {
            let where_fault = self.faults.iter().position(|f|
                f.from == flight.from && f.to == flight.to && f.flow == flight.flow);
            let fault = where_fault.map(|i| self.faults.remove(i).fault);
            match fault {
                Some(Fault::Drop) => {
                    self.emit(flight.from, flight.to, flight.flow, flight.id, "dropped")?;
                }
                Some(Fault::Duplicate) => {
                    let second = flight.clone();
                    self.arrive(flight)?;
                    self.arrive(second)?;
                }
                Some(Fault::Corrupt) => {
                    if let Some(byte) = flight.stored.bytes.last_mut() { *byte ^= 0x01; }
                    self.emit(flight.from, flight.to, flight.flow, flight.id, "corrupted")?;
                    self.arrive(flight)?;
                }
                Some(Fault::Delay(delta)) => {
                    if self.pending.len() >= MAX_PENDING_FLIGHTS
                        || self.buffered_bytes().saturating_add(flight.stored.bytes.len()) > MAX_CACHE_BYTES
                    {
                        self.emit(flight.from, flight.to, flight.flow, flight.id, "pending_limit")?;
                        continue;
                    }
                    flight.due = self.tick.saturating_add(delta.max(1));
                    self.emit(flight.from, flight.to, flight.flow, flight.id, "delayed")?;
                    self.pending.push(flight);
                }
                None => self.arrive(flight)?,
            }
        }
        Ok(())
    }

    fn arrive(&mut self, f: Transit) -> Result<(), SimError> {
        if self.tick >= f.stored.expires {
            return self.emit(f.from, f.to, f.flow, f.id, "expired");
        }
        if !self.available(f.from, f.to) {
            return self.emit(f.from, f.to, f.flow, f.id, "unreachable");
        }
        let key = (f.to, f.flow, f.id);
        if self.rejected_here(key, &f.stored.bytes) {
            return self.emit(f.from, f.to, f.flow, f.id, "quarantined_repeat");
        }
        if self.has_copy(key, &f.stored.bytes) {
            return self.emit(f.from, f.to, f.flow, f.id, "duplicate");
        }
        if self.copies.contains_key(&key) {
            if self.alternates.get(&key).is_some_and(|v| v.len() >= MAX_ALTERNATES_PER_KEY) {
                return self.emit(f.from, f.to, f.flow, f.id, "variant_limit");
            }
            if self.buffered_bytes().saturating_add(f.stored.bytes.len()) > MAX_CACHE_BYTES {
                return self.emit(f.from, f.to, f.flow, f.id, "cache_limit");
            }
            self.alternates.entry(key).or_default().push(f.stored);
            return self.emit(f.from, f.to, f.flow, f.id, "variant_staged");
        }
        if self.copies.len() >= MAX_MESSAGES * 6 * 2
            || self.buffered_bytes().saturating_add(f.stored.bytes.len()) > MAX_CACHE_BYTES
        {
            return self.emit(f.from, f.to, f.flow, f.id, "cache_limit");
        }
        self.copies.insert(key, f.stored);
        self.emit(f.from, f.to, f.flow, f.id, "copied")
    }

    fn may_forward(&self, from: Node) -> bool {
        matches!(from, Node::A | Node::G | Node::Mailbox)
            || self.opted_in.contains(&from)
    }
    fn available(&self, from: Node, to: Node) -> bool {
        self.alive.contains(&from) && self.alive.contains(&to)
            && self.links.contains(&ordered_pair(from, to))
    }
    fn emit(&mut self, from: Node, to: Node, flow: Flow, id: MessageId, event: &'static str)
        -> Result<(), SimError>
    {
        if self.trace.len() >= MAX_TRACE {
            self.trace.pop_front();
            self.dropped_trace_events = self.dropped_trace_events.saturating_add(1);
        }
        self.trace.push_back(Trace { tick: self.tick, from, to, flow, message_id: id, event });
        Ok(())
    }
    fn random(&mut self) -> u64 {
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 7;
        self.rng ^= self.rng << 17;
        self.rng
    }

    /// Machine-readable record without plaintext, ciphertext or secret keys.
    pub fn trace_jsonl(&self) -> String {
        let mut out = String::new();
        for event in &self.trace {
            let mut id = String::with_capacity(32);
            for byte in event.message_id {
                write!(&mut id, "{byte:02x}").expect("write to String");
            }
            writeln!(&mut out,
                "{{\"tick\":{},\"from\":\"{}\",\"to\":\"{}\",\"flow\":\"{}\",\"message_id\":\"{}\",\"event\":\"{}\"}}",
                event.tick, event.from.name(), event.to.name(), event.flow.name(), id, event.event
            ).expect("write to String");
        }
        out
    }
}

fn ordered_pair(a: Node, b: Node) -> (Node, Node) {
    if a < b { (a, b) } else { (b, a) }
}

fn destinations(node: Node, flow: Flow) -> &'static [Node] {
    use Node::*;
    match (flow, node) {
        (Flow::Data, A) => &[B],
        (Flow::Data, B) => &[V, W],
        (Flow::Data, V | W) => &[Mailbox],
        (Flow::Data, Mailbox) => &[G],
        (Flow::Receipt, G) => &[Mailbox],
        (Flow::Receipt, Mailbox) => &[V, W],
        (Flow::Receipt, V | W) => &[B],
        (Flow::Receipt, B) => &[A],
        _ => &[],
    }
}
