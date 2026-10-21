//! Small, transport-independent, *unsigned and unencrypted* CBOR wire experiment.
//! The production AkulaNetEnvelopeV0 with COSE/HPKE is NOT implemented here.
//! This crate must not be used to send personal or confidential information.

/// Hard cap applied before allocation or decoding.
pub const MAX_MESSAGE_BYTES: usize = 16 * 1024;
pub const MAX_FRAME_BYTES: usize = MAX_MESSAGE_BYTES + 4;
/// Fixed header (transfer id, 16-bit index, 16-bit count).
pub const BLE_HEADER_BYTES: usize = 8;

pub mod transport;
pub mod crypto_w3;
pub mod trust_w3;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Envelope {
    pub message_id: [u8; 16],
    pub route_token: [u8; 16],
    pub expires_at: u64,
    pub priority: u8,
    /// In a future version, this must be authenticated ciphertext, not plaintext.
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WireError {
    TooLarge, Truncated, InvalidEncoding, UnsupportedVersion,
    InvalidPriority, LengthMismatch, FragmentMismatch, FragmentCount,
    ConflictingDuplicate, Incomplete, UnsupportedCriticalExtension,
    TooManyExtensions, ResourceLimit, NonMonotonicTime, ReplaySuppressed,
}

/// Minimal deterministic CBOR encoding subset: unsigned integers,
/// definite byte strings, definite maps with ascending integer keys.
fn cbor_uint(out: &mut Vec<u8>, major: u8, n: u64) {
    let tag = major << 5;
    match n {
        0..=23 => out.push(tag | n as u8),
        24..=255 => { out.push(tag | 24); out.push(n as u8); }
        256..=65535 => { out.push(tag | 25); out.extend_from_slice(&(n as u16).to_be_bytes()); }
        65536..=4294967295 => { out.push(tag | 26); out.extend_from_slice(&(n as u32).to_be_bytes()); }
        _ => { out.push(tag | 27); out.extend_from_slice(&n.to_be_bytes()); }
    }
}
fn cbor_bytes(out: &mut Vec<u8>, b: &[u8]) {
    cbor_uint(out, 2, b.len() as u64);
    out.extend_from_slice(b);
}

/// Experimental map:
/// {0:0, 1:message_id(bstr16), 2:route_token(bstr16),
///  3:expires_at(uint), 4:priority(uint 0..2), 5:payload(bstr)}.
/// NOT the planned encrypted v0 schema in Notion.
pub fn encode(e: &Envelope) -> Result<Vec<u8>, WireError> {
    if e.priority > 2 { return Err(WireError::InvalidPriority); }
    if e.payload.len() > MAX_MESSAGE_BYTES { return Err(WireError::TooLarge); }
    let mut out = Vec::with_capacity(52 + e.payload.len());
    cbor_uint(&mut out, 5, 6);
    cbor_uint(&mut out, 0, 0); cbor_uint(&mut out, 0, 0);
    cbor_uint(&mut out, 0, 1); cbor_bytes(&mut out, &e.message_id);
    cbor_uint(&mut out, 0, 2); cbor_bytes(&mut out, &e.route_token);
    cbor_uint(&mut out, 0, 3); cbor_uint(&mut out, 0, e.expires_at);
    cbor_uint(&mut out, 0, 4); cbor_uint(&mut out, 0, e.priority as u64);
    cbor_uint(&mut out, 0, 5); cbor_bytes(&mut out, &e.payload);
    if out.len() > MAX_MESSAGE_BYTES { return Err(WireError::TooLarge); }
    Ok(out)
}

struct Decoder<'a> { bytes: &'a [u8], offset: usize }
impl<'a> Decoder<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], WireError> {
        let end = self.offset.checked_add(count).ok_or(WireError::TooLarge)?;
        let slice = self.bytes.get(self.offset..end).ok_or(WireError::Truncated)?;
        self.offset = end;
        Ok(slice)
    }
    fn head(&mut self, major: u8) -> Result<u64, WireError> {
        let head = self.take(1)?[0];
        if head >> 5 != major { return Err(WireError::InvalidEncoding); }
        let n = match head & 31 {
            0..=23 => (head & 31) as u64,
            24 => { let n = self.take(1)?[0] as u64; if n < 24 { return Err(WireError::InvalidEncoding); } n },
            25 => { let n = u16::from_be_bytes(self.take(2)?.try_into().unwrap()) as u64;
                if n <= 255 { return Err(WireError::InvalidEncoding); } n },
            26 => { let n = u32::from_be_bytes(self.take(4)?.try_into().unwrap()) as u64;
                if n <= 65535 { return Err(WireError::InvalidEncoding); } n },
            27 => { let n = u64::from_be_bytes(self.take(8)?.try_into().unwrap());
                if n <= u32::MAX as u64 { return Err(WireError::InvalidEncoding); } n },
            _ => return Err(WireError::InvalidEncoding),
        };
        Ok(n)
    }
    fn bytes(&mut self) -> Result<&'a [u8], WireError> {
        let len = self.head(2)?;
        if len > MAX_MESSAGE_BYTES as u64 { return Err(WireError::TooLarge); }
        self.take(len as usize)
    }
    fn fixed16(&mut self) -> Result<[u8; 16], WireError> {
        self.bytes()?.try_into().map_err(|_| WireError::InvalidEncoding)
    }
}
pub fn decode(input: &[u8]) -> Result<Envelope, WireError> {
    if input.len() > MAX_MESSAGE_BYTES { return Err(WireError::TooLarge); }
    decode_inner(input)
}
fn decode_inner(input: &[u8]) -> Result<Envelope, WireError> {
    let mut d = Decoder { bytes: input, offset: 0 };
    if d.head(5)? != 6 || d.head(0)? != 0 { return Err(WireError::InvalidEncoding); }
    if d.head(0)? != 0 { return Err(WireError::UnsupportedVersion); }
    if d.head(0)? != 1 { return Err(WireError::InvalidEncoding); }
    let message_id = d.fixed16()?;
    if d.head(0)? != 2 { return Err(WireError::InvalidEncoding); }
    let route_token = d.fixed16()?;
    if d.head(0)? != 3 { return Err(WireError::InvalidEncoding); }
    let expires_at = d.head(0)?;
    if d.head(0)? != 4 { return Err(WireError::InvalidEncoding); }
    let priority = d.head(0)?;
    if priority > 2 { return Err(WireError::InvalidPriority); }
    if d.head(0)? != 5 { return Err(WireError::InvalidEncoding); }
    let payload = d.bytes()?.to_vec();
    if d.offset != input.len() { return Err(WireError::LengthMismatch); }
    Ok(Envelope { message_id, route_token, expires_at, priority: priority as u8, payload })
}

/// A bounded, experimental version-evolution profile.
/// Key 6 is an optional map of extension IDs to opaque byte strings.
/// The lowest bit of an ID is the critical flag (odd = critical).
/// IDs are assigned append-only: old clients know no critical extensions.
/// This is NOT an authenticated Akula network envelope.
pub const MAX_EXTENSIONS: usize = 16;
pub const MAX_EXTENSION_BYTES: usize = 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Extension {
    /// Stable numeric registry identifier. Even IDs are ancillary.
    pub id: u16,
    /// Opaque bytes, not a recursively decoded CBOR item.
    pub value: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExtendedEnvelope {
    pub envelope: Envelope,
    pub extensions: Vec<Extension>,
}

fn validate_extensions(extensions: &[Extension]) -> Result<(), WireError> {
    if extensions.len() > MAX_EXTENSIONS {
        return Err(WireError::TooManyExtensions);
    }
    let mut previous = 0;
    for extension in extensions {
        if extension.id <= previous {
            return Err(WireError::InvalidEncoding);
        }
        // Unknown critical fields are not interpretable by this reader/writer.
        if extension.id & 1 == 1 {
            return Err(WireError::UnsupportedCriticalExtension);
        }
        if extension.value.len() > MAX_EXTENSION_BYTES {
            return Err(WireError::TooLarge);
        }
        previous = extension.id;
    }
    Ok(())
}

/// Writes only an *experimental*, unsigned format, never an existing signed event.
/// Do not use to rewrite an opaque message from another producer.
pub fn encode_extended(e: &ExtendedEnvelope) -> Result<Vec<u8>, WireError> {
    validate_extensions(&e.extensions)?;
    let mut out = encode(&e.envelope)?;
    if e.extensions.is_empty() {
        return Ok(out);
    }
    // The base lab envelope is a definite map of exactly six pairs.
    out[0] = 0xa7;
    cbor_uint(&mut out, 0, 6);
    cbor_uint(&mut out, 5, e.extensions.len() as u64);
    for extension in &e.extensions {
        cbor_uint(&mut out, 0, extension.id as u64);
        cbor_bytes(&mut out, &extension.value);
    }
    if out.len() > MAX_MESSAGE_BYTES {
        return Err(WireError::TooLarge);
    }
    Ok(out)
}

/// Parses a v0 lab message with optional ancillary extensions.
/// Unknown critical extensions fail closed. Unknown ancillary byte strings
/// remain opaque and are preserved exactly by this experimental model.
/// Real relays must forward the ORIGINAL authenticated bytes, not re-encode.
pub fn decode_extended(input: &[u8]) -> Result<ExtendedEnvelope, WireError> {
    if input.len() > MAX_MESSAGE_BYTES {
        return Err(WireError::TooLarge);
    }
    let mut d = Decoder { bytes: input, offset: 0 };
    let count = d.head(5)?;
    if count != 6 && count != 7 {
        return Err(WireError::InvalidEncoding);
    }
    if d.head(0)? != 0 {
        return Err(WireError::InvalidEncoding);
    }
    if d.head(0)? != 0 {
        return Err(WireError::UnsupportedVersion);
    }
    if d.head(0)? != 1 {
        return Err(WireError::InvalidEncoding);
    }
    let message_id = d.fixed16()?;
    if d.head(0)? != 2 {
        return Err(WireError::InvalidEncoding);
    }
    let route_token = d.fixed16()?;
    if d.head(0)? != 3 {
        return Err(WireError::InvalidEncoding);
    }
    let expires_at = d.head(0)?;
    if d.head(0)? != 4 {
        return Err(WireError::InvalidEncoding);
    }
    let priority = d.head(0)?;
    if priority > 2 {
        return Err(WireError::InvalidPriority);
    }
    if d.head(0)? != 5 {
        return Err(WireError::InvalidEncoding);
    }
    let payload = d.bytes()?.to_vec();
    let mut extensions = Vec::new();
    if count == 7 {
        if d.head(0)? != 6 {
            return Err(WireError::InvalidEncoding);
        }
        let n = d.head(5)?;
        if n == 0 {
            // An empty extension map must use the six-field representation.
            return Err(WireError::InvalidEncoding);
        }
        if n > MAX_EXTENSIONS as u64 {
            return Err(WireError::TooManyExtensions);
        }
        let mut previous = 0;
        for _ in 0..n {
            let id = d.head(0)?;
            if id > u16::MAX as u64 || id <= previous {
                return Err(WireError::InvalidEncoding);
            }
            // No critical extensions are implemented by this lab profile.
            if id & 1 == 1 {
                return Err(WireError::UnsupportedCriticalExtension);
            }
            let value = d.bytes()?;
            if value.len() > MAX_EXTENSION_BYTES {
                return Err(WireError::TooLarge);
            }
            extensions.push(Extension { id: id as u16, value: value.to_vec() });
            previous = id;
        }
    }
    if d.offset != input.len() {
        return Err(WireError::LengthMismatch);
    }
    Ok(ExtendedEnvelope {
        envelope: Envelope { message_id, route_token, expires_at, priority: priority as u8, payload },
        extensions,
    })
}

/// Four-byte big-endian length prefix for byte streams (TCP / QUIC).
pub fn stream_frame(encoded: &[u8]) -> Result<Vec<u8>, WireError> {
    if encoded.len() > MAX_MESSAGE_BYTES { return Err(WireError::TooLarge); }
    let mut out = Vec::with_capacity(4 + encoded.len());
    out.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
    out.extend_from_slice(encoded);
    Ok(out)
}
pub fn unframe(input: &[u8]) -> Result<&[u8], WireError> {
    let prefix: [u8; 4] = input.get(..4).ok_or(WireError::Truncated)?.try_into().unwrap();
    let len = u32::from_be_bytes(prefix) as usize;
    if len > MAX_MESSAGE_BYTES { return Err(WireError::TooLarge); }
    if input.len() != len + 4 { return Err(WireError::LengthMismatch); }
    Ok(&input[4..])
}

/// Fragment *encoded* message bytes for an experimental 8-byte BLE header.
/// Not a Bluetooth transport driver. Caller supplies effective payload MTU.
pub fn fragment(encoded: &[u8], transfer_id: u32, mtu: usize) -> Result<Vec<Vec<u8>>, WireError> {
    if encoded.is_empty() || encoded.len() > MAX_MESSAGE_BYTES { return Err(WireError::TooLarge); }
    if mtu <= BLE_HEADER_BYTES { return Err(WireError::FragmentCount); }
    let chunk = mtu - BLE_HEADER_BYTES;
    let count = encoded.len().div_ceil(chunk);
    if count > transport::HARD_MAX_PARTS_PER_TRANSFER { return Err(WireError::FragmentCount); }
    let mut out = Vec::with_capacity(count);
    for (index, bytes) in encoded.chunks(chunk).enumerate() {
        let mut f = Vec::with_capacity(BLE_HEADER_BYTES + bytes.len());
        f.extend_from_slice(&transfer_id.to_be_bytes());
        f.extend_from_slice(&(index as u16).to_be_bytes());
        f.extend_from_slice(&(count as u16).to_be_bytes());
        f.extend_from_slice(bytes);
        out.push(f);
    }
    Ok(out)
}

/// Receiver holds at most one bounded transfer. Do not share this over many peers.
pub struct Reassembler {
    transfer_id: u32,
    parts: Vec<Option<Vec<u8>>>,
    len: usize,
}
impl Reassembler {
    pub fn new(transfer_id: u32, count: u16) -> Result<Self, WireError> {
        if count == 0 || count as usize > transport::HARD_MAX_PARTS_PER_TRANSFER {
            return Err(WireError::FragmentCount);
        }
        Ok(Self { transfer_id, parts: vec![None; count as usize], len: 0 })
    }
    pub fn accept(&mut self, frame: &[u8]) -> Result<(), WireError> {
        if frame.len() <= BLE_HEADER_BYTES { return Err(WireError::Truncated); }
        let id = u32::from_be_bytes(frame[0..4].try_into().unwrap());
        let index = u16::from_be_bytes(frame[4..6].try_into().unwrap()) as usize;
        let count = u16::from_be_bytes(frame[6..8].try_into().unwrap()) as usize;
        if id != self.transfer_id || count != self.parts.len() || index >= count {
            return Err(WireError::FragmentMismatch);
        }
        let bytes = &frame[8..];
        if let Some(existing) = &self.parts[index] {
            if existing != bytes { return Err(WireError::ConflictingDuplicate); }
            return Ok(());
        }
        let len = self.len.checked_add(bytes.len()).ok_or(WireError::TooLarge)?;
        if len > MAX_MESSAGE_BYTES { return Err(WireError::TooLarge); }
        self.len = len;
        self.parts[index] = Some(bytes.to_vec());
        Ok(())
    }
    pub fn finish(self) -> Result<Vec<u8>, WireError> {
        if self.parts.iter().any(Option::is_none) { return Err(WireError::Incomplete); }
        Ok(self.parts.into_iter().flatten().flatten().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn sample() -> Envelope {
        Envelope { message_id: [3; 16], route_token: [5; 16], expires_at: 1792368000, priority: 1, payload: vec![0, 255, 13, 10] }
    }
    #[test] fn round_trip_is_byte_identical() {
        let e = sample();
        let bytes = encode(&e).unwrap();
        assert_eq!(decode(&bytes).unwrap(), e);
        assert_eq!(encode(&decode(&bytes).unwrap()).unwrap(), bytes);
    }
    #[test] fn rejects_noncanonical_and_duplicate_keys() {
        let mut bytes = encode(&sample()).unwrap();
        bytes[1] = 0x18; bytes.insert(2, 0);
        assert_eq!(decode(&bytes), Err(WireError::InvalidEncoding));
        let mut bytes = encode(&sample()).unwrap();
        bytes[38] = 1; // intentionally corrupt; decoder must reject or change decoded data
        assert_ne!(decode(&bytes).ok(), Some(sample()));
    }
    #[test] fn wrong_version_rejected() {
        let mut bytes = encode(&sample()).unwrap();
        bytes[2] = 1;
        assert_eq!(decode(&bytes), Err(WireError::UnsupportedVersion));
    }
    #[test] fn stream_round_trip_and_length_guard() {
        let bytes = encode(&sample()).unwrap();
        let frame = stream_frame(&bytes).unwrap();
        assert_eq!(unframe(&frame).unwrap(), bytes);
        assert_eq!(unframe(&[255,255,255,255]), Err(WireError::TooLarge));
        assert_eq!(unframe(&frame[..3]), Err(WireError::Truncated));
    }
    #[test] fn ble_out_of_order_duplicate_and_corrupt() {
        let bytes = encode(&sample()).unwrap();
        let chunks = fragment(&bytes, 0x01020304, 20).unwrap();
        let mut r = Reassembler::new(0x01020304, chunks.len() as u16).unwrap();
        for chunk in chunks.iter().rev() { r.accept(chunk).unwrap(); r.accept(chunk).unwrap(); }
        assert_eq!(r.finish().unwrap(), bytes);
        let mut r = Reassembler::new(0x01020304, chunks.len() as u16).unwrap();
        let mut corrupt = chunks[0].clone();
        *corrupt.last_mut().unwrap() ^= 1;
        r.accept(&chunks[0]).unwrap();
        assert_eq!(r.accept(&corrupt), Err(WireError::ConflictingDuplicate));
    }
    #[test] fn oversized_decode_and_missing_fragment() {
        assert_eq!(decode(&vec![0; MAX_MESSAGE_BYTES + 1]), Err(WireError::TooLarge));
        let bytes = encode(&sample()).unwrap();
        let chunks = fragment(&bytes, 7, 20).unwrap();
        let mut r = Reassembler::new(7, chunks.len() as u16).unwrap();
        r.accept(&chunks[0]).unwrap();
        assert_eq!(r.finish(), Err(WireError::Incomplete));
    }
}
