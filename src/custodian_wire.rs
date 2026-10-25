//! Lab-only one-shot loopback TCP adapter for the signed custodian mailbox.
//! This is NOT a production listener, public QUIC service or VPS installer.
//! Bind ONLY 127.0.0.1. Remote use requires a separately authenticated,
//! pinned transport such as the existing SSH acceptance tunnel.
//! No sender/recipient Vault rights or W4 are exposed by this adapter.
use crate::custodian_mailbox::{
    decode_store, verify_custodian_stored_claim, AuthError, CustodianStoredClaim,
    FETCH_GRANT_BYTES, STORE_GRANT_BYTES,
};
use crate::journal_w4::Journal;
use crate::trust_w3::TrustRegistry;
use crate::MAX_MESSAGE_BYTES;
use ed25519_dalek::SigningKey;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream};
use std::time::Duration;

const VERSION: u8 = 1;
const STORE: u8 = 1;
const FETCH: u8 = 2;
const STORED: u8 = 17;
const FETCHED: u8 = 18;
const MISSING: u8 = 19;
const FAILED: u8 = 254;
const DENIED: u8 = 255;
const FRAME_LIMIT: usize = MAX_MESSAGE_BYTES + 512;

#[derive(Debug)]
pub enum WireError {
    Io(io::Error),
    Invalid,
    Denied,
    Unavailable,
}
impl From<io::Error> for WireError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Caller controls where the listener is bound: accept only literal IPv4
/// localhost, even when passed a preexisting listener by mistake.
fn local_only(listener: &TcpListener) -> Result<(), WireError> {
    if listener.local_addr()?.ip() == IpAddr::V4(Ipv4Addr::LOCALHOST) {
        Ok(())
    } else {
        Err(WireError::Denied)
    }
}

pub fn bind_test_loopback() -> io::Result<TcpListener> {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
}

fn write_frame(stream: &mut TcpStream, bytes: &[u8]) -> Result<(), WireError> {
    if bytes.is_empty() || bytes.len() > FRAME_LIMIT {
        return Err(WireError::Invalid);
    }
    stream.write_all(&(bytes.len() as u32).to_be_bytes())?;
    stream.write_all(bytes)?;
    stream.flush()?;
    Ok(())
}

fn read_frame(stream: &mut TcpStream) -> Result<Vec<u8>, WireError> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header)?;
    let n = u32::from_be_bytes(header) as usize;
    if n == 0 || n > FRAME_LIMIT {
        return Err(WireError::Invalid);
    }
    let mut body = vec![0u8; n];
    stream.read_exact(&mut body)?;
    Ok(body)
}

fn handle_request(
    request: &[u8],
    journal: &mut Journal,
    signer: &SigningKey,
    signer_epoch: u64,
    trust: &TrustRegistry,
    now_ms: i64,
) -> Result<Vec<u8>, AuthError> {
    if request.len() < 2 || request[0] != VERSION || now_ms <= 0 {
        return Err(AuthError::Invalid);
    }
    match request[1] {
        STORE => {
            let prefix = 2 + STORE_GRANT_BYTES;
            if request.len() < prefix + 2 {
                return Err(AuthError::Invalid);
            }
            let mut len = [0u8; 2];
            len.copy_from_slice(&request[prefix..prefix + 2]);
            let expected = usize::from(u16::from_be_bytes(len));
            let packet = &request[prefix + 2..];
            if expected == 0 || expected > MAX_MESSAGE_BYTES || expected != packet.len() {
                return Err(AuthError::Invalid);
            }
            let claim = journal.accept_custodian_store_and_claim(
                &request[2..prefix],
                packet,
                signer,
                signer_epoch,
                trust,
                now_ms,
            )?;
            let mut reply = Vec::with_capacity(114);
            reply.extend_from_slice(&[VERSION, STORED]);
            reply.extend_from_slice(&claim.custodian_epoch.to_be_bytes());
            reply.extend_from_slice(&claim.causal.seq.to_be_bytes());
            reply.extend_from_slice(&claim.causal.digest);
            reply.extend_from_slice(&claim.signature);
            Ok(reply)
        }
        FETCH if request.len() == 2 + FETCH_GRANT_BYTES => {
            let packet = journal.fetch_custodian_authorized(&request[2..], trust, now_ms)?;
            match packet {
                Some(packet) => {
                    let mut reply = Vec::with_capacity(packet.len() + 2);
                    reply.extend_from_slice(&[VERSION, FETCHED]);
                    reply.extend_from_slice(&packet);
                    Ok(reply)
                }
                None => Ok(vec![VERSION, MISSING]),
            }
        }
        _ => Err(AuthError::Invalid),
    }
}

/// One request per connection, fixed memory bound, no automatic retry or
/// acceptance of external bind addresses. No W4 or privilege escalation.
/// External adapters must NOT use this as an unauthenticated Internet API.
pub fn serve_one_loopback(
    listener: &TcpListener,
    journal: &mut Journal,
    signer: &SigningKey,
    signer_epoch: u64,
    trust: &TrustRegistry,
    now_ms: i64,
) -> Result<(), WireError> {
    local_only(listener)?;
    if now_ms <= 0 {
        return Err(WireError::Invalid);
    }
    let (mut stream, peer) = listener.accept()?;
    if peer.ip() != IpAddr::V4(Ipv4Addr::LOCALHOST) {
        return Err(WireError::Denied);
    }
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let request = read_frame(&mut stream)?;
    let reply = match handle_request(&request, journal, signer, signer_epoch, trust, now_ms) {
        Ok(reply) => reply,
        Err(AuthError::Db(_) | AuthError::Causal(_) | AuthError::Corrupt) => {
            vec![VERSION, FAILED]
        }
        Err(_) => vec![VERSION, DENIED],
    };
    write_frame(&mut stream, &reply)
}

fn parse_reply(reply: &[u8], expected: u8) -> Result<&[u8], WireError> {
    if reply.len() < 2 || reply[0] != VERSION {
        return Err(WireError::Invalid);
    }
    match reply[1] {
        DENIED => Err(WireError::Denied),
        FAILED => Err(WireError::Unavailable),
        tag if tag == expected => Ok(&reply[2..]),
        _ => Err(WireError::Invalid),
    }
}

/// Client refuses a claim until its independently enrolled issuer and
/// custodian signatures, exact W3 bytes, expiry and message match.
pub fn client_store(
    stream: &mut TcpStream,
    signed_store: &[u8],
    w3: &[u8],
    trust: &TrustRegistry,
) -> Result<CustodianStoredClaim, WireError> {
    if signed_store.len() != STORE_GRANT_BYTES || w3.is_empty() || w3.len() > MAX_MESSAGE_BYTES {
        return Err(WireError::Invalid);
    }
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let mut request = Vec::with_capacity(2 + STORE_GRANT_BYTES + 2 + w3.len());
    request.extend_from_slice(&[VERSION, STORE]);
    request.extend_from_slice(signed_store);
    request.extend_from_slice(&(w3.len() as u16).to_be_bytes());
    request.extend_from_slice(w3);
    write_frame(stream, &request)?;
    let reply = read_frame(stream)?;
    let result = parse_reply(&reply, STORED)?;
    if result.len() != 8 + 8 + 32 + 64 {
        return Err(WireError::Invalid);
    }
    let (claims, _) = decode_store(signed_store).map_err(|_| WireError::Invalid)?;
    let mut cursor = 0usize;
    let epoch = u64::from_be_bytes(result[cursor..cursor + 8].try_into().unwrap());
    cursor += 8;
    let seq = u64::from_be_bytes(result[cursor..cursor + 8].try_into().unwrap());
    cursor += 8;
    let digest: [u8; 32] = result[cursor..cursor + 32].try_into().unwrap();
    cursor += 32;
    let signature: [u8; 64] = result[cursor..cursor + 64].try_into().unwrap();
    let claim = CustodianStoredClaim {
        store: claims,
        custodian_epoch: epoch,
        causal: crate::causal_w12::CausalCommitment { seq, digest },
        signature,
    };
    verify_custodian_stored_claim(&claim, signed_store, w3, trust)
        .map_err(|_| WireError::Denied)?;
    Ok(claim)
}

/// Client verifies the returned ciphertext digest; encrypted W3 still requires
/// recipient-side authenticated decryption before any recipient W4 is issued.
pub fn client_fetch(
    stream: &mut TcpStream,
    signed_fetch: &[u8],
    expected_digest: [u8; 32],
) -> Result<Option<Vec<u8>>, WireError> {
    if signed_fetch.len() != FETCH_GRANT_BYTES {
        return Err(WireError::Invalid);
    }
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let mut request = Vec::with_capacity(2 + FETCH_GRANT_BYTES);
    request.extend_from_slice(&[VERSION, FETCH]);
    request.extend_from_slice(signed_fetch);
    write_frame(stream, &request)?;
    let reply = read_frame(stream)?;
    if reply.as_slice() == [VERSION, MISSING] {
        return Ok(None);
    }
    let packet = parse_reply(&reply, FETCHED)?;
    if packet.is_empty()
        || packet.len() > MAX_MESSAGE_BYTES
        || blake3::hash(packet).as_bytes() != &expected_digest
    {
        return Err(WireError::Invalid);
    }
    Ok(Some(packet.to_vec()))
}
