//! W5 deterministic, transport-free store-and-forward laboratory.
//!
//! Routes are deliberately fixed for A -> B -> gateway -> mailbox -> G,
//! then G -> mailbox -> gateway -> B -> A for an opaque signed receipt.
//! This is NOT a discovery protocol, production router or trusted delivery
//! authority. In particular, presence at G does not mean an authenticated
//! receipt or an accepted Sync Core operation.
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;

pub type MessageId = [u8; 16];
const MAX_TICKS: u64 = 1024;
const MAX_MESSAGES: usize = 16;
const MAX_TRACE: usize = 4096;
/// Laboratory safety bound against infinitely repeating poisoned packets.
/// This is not a production retransmission schedule.
const MAX_TERMINAL_REJECTIONS: u8 = 3;

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
pub enum SimError { InvalidOrigin, InvalidPayload, Expired, Conflict, ResourceLimit,
    InvalidTerminal, MissingPacket }

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
    known: BTreeSet<MessageId>,
    pending: Vec<Transit>,
    faults: Vec<InjectedFault>,
    /// Bounded by the simulator's maximum 16 distinct message IDs and 2 sinks.
    terminal_rejections: BTreeMap<(Node, Flow, MessageId), u8>,
    trace: Vec<Trace>,
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
            known: BTreeSet::new(),
            pending: Vec::new(),
            faults: Vec::new(),
            terminal_rejections: BTreeMap::new(),
            trace: Vec::new(),
        }
    }

    pub fn tick(&self) -> u64 { self.tick }
    pub fn events(&self) -> &[Trace] { &self.trace }
    pub fn copies(&self) -> usize { self.copies.len() }

    pub fn connect(&mut self, a: Node, b: Node, enabled: bool) {
        if a == b { return; }
        let pair = ordered_pair(a, b);
        if enabled { self.links.insert(pair); } else { self.links.remove(&pair); }
    }

    /// Relay participation must be opted in, never implied by network access.
    pub fn relay_opt_in(&mut self, node: Node, enabled: bool) {
        if !matches!(node, Node::B | Node::V | Node::W) { return; }
        if enabled {
            self.opted_in.insert(node);
        } else {
            self.opted_in.remove(&node);
            // Revoking voluntary participation also discards unsent and stored
            // relay copies. Disconnecting is not a license to send queued data.
            self.copies.retain(|(owner, _, _), _| *owner != node);
            self.pending.retain(|flight| flight.from != node && flight.to != node);
        }
    }

    /// A crashed intermediary loses only its volatile simulated copies.
    /// Sender's real W4 journal and mailbox's separate persistence are NOT
    /// modified here. A restart does not manufacture any recipient receipts.
    pub fn set_alive(&mut self, node: Node, enabled: bool) {
        if enabled {
            self.alive.insert(node);
        } else {
            self.alive.remove(&node);
            // A mailbox is modeled as a durable node: downtime prevents
            // delivery, but does not erase previously stored envelopes.
            // Other nodes only have volatile local transport copies.
            if node != Node::Mailbox {
                self.copies.retain(|(n, _, _), _| *n != node);
            }
            self.pending.retain(|flight| flight.from != node && flight.to != node);
        }
    }

    /// One deterministic fault on the next attempted crossing of this link.
    pub fn inject_once(&mut self, from: Node, to: Node, flow: Flow, fault: Fault) {
        self.faults.push(InjectedFault { from, to, flow, fault });
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
        self.known.insert(id);
        self.copies.insert(key, Stored { bytes: bytes.to_vec(), expires });
        self.emit(node, node, flow, id, "queued")?;
        Ok(())
    }

    pub fn packet(&self, node: Node, flow: Flow, id: MessageId) -> Option<&[u8]> {
        self.copies.get(&(node, flow, id)).map(|s| s.bytes.as_slice())
    }

    /// Only a terminal endpoint can locally evict its rejected copy AFTER
    /// independently checking a cryptographic failure (COSE/HPKE or signed ACK).
    ///
    /// This action does not authenticate data or allow a relay to modify other
    /// nodes. A valid upstream copy may be resent unchanged next tick. Three
    /// rejections quarantine this terminal message ID to bound hostile retries.
    pub fn reject_terminal_copy(
        &mut self, terminal: Node, flow: Flow, id: MessageId,
    ) -> Result<(), SimError> {
        if !matches!((terminal, flow),
            (Node::G, Flow::Data) | (Node::A, Flow::Receipt)) {
            return Err(SimError::InvalidTerminal);
        }
        let key=(terminal,flow,id);
        if self.copies.remove(&key).is_none() {
            return Err(SimError::MissingPacket);
        }
        let attempts=self.terminal_rejections.entry(key).or_insert(0);
        if *attempts < MAX_TERMINAL_REJECTIONS { *attempts += 1; }
        let quarantined=*attempts >= MAX_TERMINAL_REJECTIONS;
        self.emit(terminal,terminal,flow,id,"rejected")?;
        if quarantined { self.emit(terminal,terminal,flow,id,"quarantined")?; }
        Ok(())
    }

    pub fn is_terminal_quarantined(&self, terminal: Node, flow: Flow, id: MessageId) -> bool {
        self.terminal_rejections.get(&(terminal,flow,id)).copied().unwrap_or(0)
            >= MAX_TERMINAL_REJECTIONS
    }

    pub fn run(&mut self, ticks: u64) -> Result<(), SimError> {
        for _ in 0..ticks { self.step()?; }
        Ok(())
    }

    pub fn step(&mut self) -> Result<(), SimError> {
        if self.tick >= MAX_TICKS { return Err(SimError::ResourceLimit); }
        self.tick += 1;

        // Complete flights scheduled on prior ticks before offering new ones.
        let flights = std::mem::take(&mut self.pending);
        for flight in flights {
            if flight.due <= self.tick {
                self.arrive(flight)?;
            } else {
                self.pending.push(flight);
            }
        }

        // Snapshot before transfers: at most one hop per tick. No copy may
        // turn into an instantaneous multi-hop delivery.
        let mut candidates = Vec::new();
        for (&(from, flow, id), stored) in &self.copies {
            if !self.alive.contains(&from) || self.tick >= stored.expires
                || !self.may_forward(from) { continue; }
            for &to in destinations(from, flow) {
                if !self.available(from, to) { continue; }
                if self.is_terminal_quarantined(to, flow, id) { continue; }
                if self.copies.contains_key(&(to, flow, id)) { continue; }
                if self.pending.iter().any(|p|
                    p.from == from && p.to == to && p.flow == flow && p.id == id) { continue; }
                candidates.push(Transit {
                    from, to, flow, id, stored: stored.clone(), due: self.tick,
                });
            }
        }

        // Seed-dependent order, deterministic for a given scenario.
        for i in (1..candidates.len()).rev() {
            let j = (self.random() as usize) % (i + 1);
            candidates.swap(i, j);
        }
        for mut flight in candidates {
            if self.copies.contains_key(&(flight.to, flight.flow, flight.id)) {
                continue;
            }
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
        if let Some(existing) = self.copies.get(&key) {
            if existing.bytes != f.stored.bytes {
                return self.emit(f.from, f.to, f.flow, f.id, "conflict");
            }
            return self.emit(f.from, f.to, f.flow, f.id, "duplicate");
        }
        if self.copies.len() >= MAX_MESSAGES * 6 * 2 {
            return Err(SimError::ResourceLimit);
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
            // A connection never implies consent to receive or relay foreign
            // packets. Check opt-in again for delayed flights upon arrival.
            && (!matches!(from, Node::B | Node::V | Node::W)
                || self.opted_in.contains(&from))
            && (!matches!(to, Node::B | Node::V | Node::W)
                || self.opted_in.contains(&to))
    }
    fn emit(&mut self, from: Node, to: Node, flow: Flow, id: MessageId, event: &'static str)
        -> Result<(), SimError>
    {
        if self.trace.len() >= MAX_TRACE { return Err(SimError::ResourceLimit); }
        self.trace.push(Trace { tick: self.tick, from, to, flow, message_id: id, event });
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
