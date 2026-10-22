//! DELIBERATELY MALICIOUS custodial endpoint for W7 integration tests.
//!
//! This is not a service for deployment. Binds only 127.0.0.1, uses lab
//! deterministic keys, fixed route/IDs and a deliberately tiny test protocol.
//! The executable intentionally violates its own claimed storage contract.
//! Client tests must treat its signature as a claim and independently check
//! exact W3 bytes before accepting any recipient-signed W4.
//!
//! Protocol over one mutually authenticated Roha/noq QUIC/TLS bidi stream:
//! STORE [1,route16,message16,W3...] => [1,Ed25519 custody proof] or no ACK
//! AUDIT [2,audit_cap16]            => [2,W3...] or [0] or [255]
//! FETCH [3,recipient_cap16]       => [2,W3...] or [0] or [255]
//! FORGED_W4 [4]                   => [3,forged W4 bytes] or [255]
//! Frames are test-only; no invitation, real RelayGrant or W4 return privacy.
use akula_wire_lab::custody_receipt_w6;
use akula_wire_lab::mailbox_w5::{Mailbox, MailboxLimits};
use akula_wire_lab::private_route_w3;
use akula_wire_lab::receipt_w4;
use akula_wire_lab::MAX_MESSAGE_BYTES;
use ed25519_dalek::SigningKey;
use iroh::{Endpoint, EndpointId, endpoint::presets, endpoint::Connection};
use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;

const ALPN: &[u8] = b"akula-wow/w7-hostile-custodian-local-only/1";
const AUDIT_CAP: [u8; 16] = [22; 16];
const RECIPIENT_CAP: [u8; 16] = [23; 16];
const MAX_REQUEST: usize = MAX_MESSAGE_BYTES + 64;
fn id(n: u8) -> [u8; 16] { [n; 16] }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode { Fake, Delete, Censor, Honest, Corrupt, DropAck }
impl FromStr for Mode {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "fake" => Ok(Self::Fake),
            "delete" => Ok(Self::Delete),
            "censor" => Ok(Self::Censor),
            "honest" => Ok(Self::Honest),
            "corrupt" => Ok(Self::Corrupt),
            "drop-ack" => Ok(Self::DropAck),
            _ => Err("invalid laboratory mode"),
        }
    }
}

struct Config {
    mode: Mode,
    db: PathBuf,
    sender: EndpointId,
    auditor: EndpointId,
    recipient: EndpointId,
}

fn read_stored(db: &Path) -> Option<Vec<u8>> {
    let mailbox = Mailbox::open(db, MailboxLimits::default()).ok()?;
    mailbox.get_page(id(4), 101, None, 1).ok()?.into_iter()
        .find(|msg| msg.id == id(5))
        .map(|msg| msg.bytes)
}

fn remove_stored(db: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let connection = rusqlite::Connection::open(db)?;
    connection.execute(
        "DELETE FROM mailbox_entries WHERE route_token=?1 AND message_id=?2",
        rusqlite::params![id(4).as_slice(), id(5).as_slice()],
    )?;
    Ok(())
}

fn store(
    config: &Config,
    sender: &SigningKey,
    payload: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if payload.len() < 34 || payload.len() > MAX_REQUEST {
        return Ok(vec![255]);
    }
    if payload[1..17] != id(4) || payload[17..33] != id(5) {
        return Ok(vec![255]);
    }
    let wire = &payload[33..];
    // Inspecting the public route is NOT authentication of the sender and
    // does not authorize mailbox writes. The custom laboratory STORE is
    // constrained to the pinned TLS client but bypasses W6 RelayGrant.
    let Ok(hint) = private_route_w3::inspect_route(wire) else {
        return Ok(vec![255]);
    };
    if hint.token != id(4) || hint.message_id != id(5) {
        return Ok(vec![255]);
    }

    if config.mode != Mode::Fake {
        {
            let mut mailbox = Mailbox::open(&config.db, MailboxLimits::default())?;
            mailbox.put(id(4), id(5), 100, 200, wire)?;
        }
        if config.mode == Mode::Delete {
            // A modified program can bypass Mailbox API and delete the row.
            remove_stored(&config.db)?;
        }
    }
    // Critical: possession of C's legitimate key is enough to sign this
    // claim even if no bytes were ever durably stored.
    let proof = custody_receipt_w6::sign_after_store(
        sender, id(13), id(41), id(5), wire, 7, 300_000,
    ).map_err(|_| "custody signer rejected claims")?;
    if config.mode == Mode::DropAck {
        // Store succeeded but response is intentionally dropped; a timeout
        // or absent ACK cannot safely be interpreted as "never stored".
        return Ok(Vec::new());
    }
    let mut reply = vec![1];
    reply.extend_from_slice(&proof);
    Ok(reply)
}

fn respond(
    config: &Config,
    remote: EndpointId,
    packet: &[u8],
    signer: &SigningKey,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if packet.is_empty() { return Ok(vec![255]); }
    match packet[0] {
        1 if remote == config.sender => store(config, signer, packet),
        2 if remote == config.auditor && packet.get(1..) == Some(AUDIT_CAP.as_slice()) => {
            if let Some(mut bytes) = read_stored(&config.db) {
                if config.mode == Mode::Corrupt {
                    if let Some(last) = bytes.last_mut() { *last ^= 1; }
                }
                let mut result = vec![2];
                result.extend_from_slice(&bytes);
                Ok(result)
            } else { Ok(vec![0]) }
        }
        3 if remote == config.recipient && packet.get(1..) == Some(RECIPIENT_CAP.as_slice()) => {
            if config.mode == Mode::Censor {
                // Selective denial despite successful third-party audit.
                return Ok(vec![0]);
            }
            if let Some(mut bytes) = read_stored(&config.db) {
                if config.mode == Mode::Corrupt {
                    if let Some(last) = bytes.last_mut() { *last ^= 1; }
                }
                let mut result = vec![2];
                result.extend_from_slice(&bytes);
                Ok(result)
            } else { Ok(vec![0]) }
        }
        4 if remote == config.sender && packet.len() == 1 => {
            let forged = receipt_w4::sign(
                signer, id(8), id(5), [0; 32], 6,
            );
            let mut result = vec![3];
            result.extend_from_slice(&forged);
            Ok(result)
        }
        _ => Ok(vec![255]),
    }
}

async fn serve_connection(
    connection: Connection,
    config: &Config,
    signer: &SigningKey,
) -> Result<(), Box<dyn std::error::Error>> {
    let remote = connection.remote_id();
    let (mut send, mut recv) = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        connection.accept_bi(),
    ).await??;
    let packet = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        recv.read_to_end(MAX_REQUEST),
    ).await??;
    let response = respond(config, remote, &packet, signer)?;
    if !response.is_empty() {
        send.write_all(&response).await?;
    }
    send.finish()?;
    Ok(())
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args().collect::<Vec<_>>();
    if args.len() != 6 {
        return Err("expected mode db sender_endpoint auditor_endpoint recipient_endpoint".into());
    }
    let config = Config {
        mode: args[1].parse()?,
        db: PathBuf::from(&args[2]),
        sender: args[3].parse()?,
        auditor: args[4].parse()?,
        recipient: args[5].parse()?,
    };
    let signer = SigningKey::from_bytes(&[13; 32]); // Test-only, fixed.
    let endpoint = Endpoint::builder(presets::Minimal)
        .clear_ip_transports()
        .bind_addr("127.0.0.1:0")?
        .alpns(vec![ALPN.to_vec()])
        .bind().await?;
    let socket: SocketAddr = endpoint.bound_sockets().into_iter()
        .find(|addr| addr.is_ipv4() && addr.ip().is_loopback())
        .ok_or("missing loopback socket")?;
    println!("READY {} {}", endpoint.id(), socket);
    io::stdout().flush()?;
    while let Some(incoming) = endpoint.accept().await {
        match incoming.await {
            Ok(connection) => {
                if let Err(error) = serve_connection(connection, &config, &signer).await {
                    eprintln!("w7 rogue test connection error: {error}");
                }
            }
            Err(error) => eprintln!("w7 rogue test handshake error: {error}"),
        }
    }
    Ok(())
}
