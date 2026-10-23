//! EXPERIMENT ONLY: one-message W3 v3 / private Ed25519 W4 over a localhost
//! TCP connection, intended to be forwarded by independently authenticated
//! SSH between TWO PHYSICAL HOSTS. No public listener or unsigned receipt.
//!
//! This is NOT a production service, transport replacement for Roha/noq,
//! Sync-Core API, global K verifier, or device enrollment product.
//! Unix-only for fail-closed permissions on raw laboratory key files.
use akula_wire_lab::crypto_identity_w3::{SignedHeader, TrustedRecipient};
use akula_wire_lab::crypto_w3::{new_recipient, RecipientPublic, RecipientSecret};
use akula_wire_lab::journal_w4::{Delivery, Insert, Journal};
use akula_wire_lab::private_return_w4::{self, ReturnInvitation, ENVELOPE_LEN};
use akula_wire_lab::private_route_w3;
use akula_wire_lab::trust_w3::TrustRegistry;
use akula_wire_lab::MAX_MESSAGE_BYTES;
use ed25519_dalek::{SigningKey, VerifyingKey};
use hpke::{Deserializable, Serializable};
use std::env;
use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const EPOCH: u64 = 1;
const FORWARD_TTL_MS: u64 = 15 * 60 * 1000;
const RETURN_GRACE_MS: u64 = 60 * 60 * 1000;
const RETURN_METADATA_LEN: usize = 16 + 32;
const SENDER_SECRET_BYTES: usize = 32 + 32 + 32;
const RECIPIENT_SECRET_BYTES: usize = 32 + 32 + 16;
const INVITE_BYTES: usize = 32 + 32 + 16;
const IO_BUDGET: Duration = Duration::from_secs(15);

fn error(value: impl std::fmt::Debug) -> io::Error {
    io::Error::other(format!("W4 tunnel experiment: {value:?}"))
}
fn bad(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
fn now_ms() -> Result<u64, io::Error> {
    let ms = SystemTime::now().duration_since(UNIX_EPOCH)
        .map_err(error)?.as_millis();
    u64::try_from(ms).map_err(error)
}
fn random<const N: usize>() -> Result<[u8; N], io::Error> {
    let mut out = [0u8; N];
    getrandom::fill(&mut out).map_err(error)?;
    Ok(out)
}
fn hex(data: &[u8]) -> String {
    let mut result = String::with_capacity(data.len() * 2);
    for byte in data { result.push_str(&format!("{byte:02x}")); }
    result
}
fn decode<const N: usize>(value: &str) -> Result<[u8; N], io::Error> {
    if value.len() != N * 2 || !value.is_ascii() {
        return Err(bad("invalid hex length/encoding"));
    }
    let mut out = [0u8; N];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[2*i..2*i+2], 16).map_err(error)?;
    }
    Ok(out)
}
fn device_id(public: &[u8; 32]) -> [u8; 16] {
    let hash = blake3::hash(public);
    let mut id = [0u8;16];
    id.copy_from_slice(&hash.as_bytes()[..16]);
    id
}
fn usable_address(value: &str) -> Result<SocketAddr, io::Error> {
    let address: SocketAddr = value.parse().map_err(error)?;
    if !address.ip().is_loopback() { return Err(bad("only 127.0.0.1 or ::1 is allowed")); }
    Ok(address)
}

// Private key files are exclusive and owner-only; no symlinks or broad modes.
// This lab intentionally does not support Windows until an equivalent
// Windows-DACL-backed secret store is implemented.
#[cfg(unix)]
fn save_secret(path: &Path, bytes: &[u8]) -> Result<(), io::Error> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = OpenOptions::new().create_new(true).write(true)
        .mode(0o600).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}
#[cfg(not(unix))]
fn save_secret(_path: &Path, _bytes: &[u8]) -> Result<(), io::Error> {
    Err(bad("this secret-file lab is Unix-only"))
}
fn load_secret<const N: usize>(path: &Path) -> Result<[u8; N], io::Error> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_file() || meta.file_type().is_symlink() {
        return Err(bad("secret must be a regular, non-symlink file"));
    }
    #[cfg(unix)] {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(bad("insecure key file permissions; chmod 600"));
        }
    }
    #[cfg(not(unix))]
    return Err(bad("this secret-file lab is Unix-only"));
    #[cfg(unix)] {
        let raw = fs::read(path)?;
        raw.try_into().map_err(|_| bad("wrong secret file length"))
    }
}
struct SenderKeys {
    signing: SigningKey,
    return_secret: RecipientSecret,
    tag_key: [u8;32],
}
struct RecipientKeys {
    signing: SigningKey,
    secret: RecipientSecret,
    route_token: [u8;16],
}
impl SenderKeys {
    fn open(path: &Path) -> Result<Self, io::Error> {
        let raw = load_secret::<SENDER_SECRET_BYTES>(path)?;
        let signing = SigningKey::from_bytes(&raw[..32].try_into().unwrap());
        let return_secret = RecipientSecret::from_bytes(&raw[32..64]).map_err(error)?;
        let tag_key = raw[64..96].try_into().unwrap();
        Ok(Self { signing, return_secret, tag_key })
    }
    fn return_tag(&self, message_id: [u8;16]) -> [u8;16] {
        let mut h = blake3::Hasher::new_keyed(&self.tag_key);
        h.update(b"Akula/WOW/tunnel-return-tag/v1");
        h.update(&message_id);
        let mut tag = [0u8;16];
        tag.copy_from_slice(&h.finalize().as_bytes()[..16]);
        tag
    }
}
impl RecipientKeys {
    fn open(path: &Path) -> Result<Self, io::Error> {
        let raw = load_secret::<RECIPIENT_SECRET_BYTES>(path)?;
        Ok(Self {
            signing: SigningKey::from_bytes(&raw[..32].try_into().unwrap()),
            secret: RecipientSecret::from_bytes(&raw[32..64]).map_err(error)?,
            route_token: raw[64..80].try_into().unwrap(),
        })
    }
}

fn init_sender(path: &Path) -> Result<(), io::Error> {
    let signing = SigningKey::from_bytes(&random::<32>()?);
    let (secret, _) = new_recipient();
    let mut out = [0u8;SENDER_SECRET_BYTES];
    out[..32].copy_from_slice(&signing.to_bytes());
    out[32..64].copy_from_slice(&secret.to_bytes());
    out[64..96].copy_from_slice(&random::<32>()?);
    save_secret(path, &out)?;
    println!("SENDER_VERIFY={}", hex(signing.verifying_key().as_bytes()));
    println!("SENDER_ID={}", hex(&device_id(signing.verifying_key().as_bytes())));
    Ok(())
}
fn init_recipient(path: &Path) -> Result<(), io::Error> {
    let signing = SigningKey::from_bytes(&random::<32>()?);
    let (secret, public) = new_recipient();
    let token = random::<16>()?;
    if token == [0;16] { return Err(bad("empty route token")); }
    let mut private = [0u8;RECIPIENT_SECRET_BYTES];
    private[..32].copy_from_slice(&signing.to_bytes());
    private[32..64].copy_from_slice(&secret.to_bytes());
    private[64..80].copy_from_slice(&token);
    save_secret(path, &private)?;
    let mut invite = [0u8;INVITE_BYTES];
    invite[..32].copy_from_slice(signing.verifying_key().as_bytes());
    invite[32..64].copy_from_slice(&public.to_bytes());
    invite[64..80].copy_from_slice(&token);
    println!("RECIPIENT_INVITE={}", hex(&invite));
    println!("RECIPIENT_ID={}", hex(&device_id(signing.verifying_key().as_bytes())));
    Ok(())
}
struct Invitation {
    signing: VerifyingKey,
    secret_public: RecipientPublic,
    recipient_id: [u8;16],
    route_token: [u8;16],
}
fn parse_invite(value: &str) -> Result<Invitation, io::Error> {
    let raw = decode::<INVITE_BYTES>(value)?;
    let pub_signing: [u8;32] = raw[..32].try_into().unwrap();
    let signing = VerifyingKey::from_bytes(&pub_signing).map_err(error)?;
    let secret_public = RecipientPublic::from_bytes(&raw[32..64]).map_err(error)?;
    let token = raw[64..80].try_into().unwrap();
    if token == [0;16] { return Err(bad("empty route token")); }
    Ok(Invitation { signing, secret_public,
        recipient_id: device_id(&pub_signing), route_token: token })
}
fn exhausted() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "absolute 15-second I/O budget exceeded")
}
fn read_before(socket: &mut TcpStream, mut bytes: &mut [u8],
               deadline: Instant) -> Result<(), io::Error> {
    while !bytes.is_empty() {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() { return Err(exhausted()); }
        socket.set_read_timeout(Some(left))?;
        match socket.read(bytes) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(count) => {
                let (_, rest) = bytes.split_at_mut(count);
                bytes = rest;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    if Instant::now() >= deadline { return Err(exhausted()); }
    Ok(())
}
fn write_before(socket: &mut TcpStream, mut bytes: &[u8],
                deadline: Instant) -> Result<(), io::Error> {
    while !bytes.is_empty() {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() { return Err(exhausted()); }
        socket.set_write_timeout(Some(left))?;
        match socket.write(bytes) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(count) => bytes = &bytes[count..],
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    if Instant::now() >= deadline { return Err(exhausted()); }
    Ok(())
}
fn send_frame(socket: &mut TcpStream, bytes: &[u8],
              deadline: Instant) -> Result<(), io::Error> {
    if bytes.is_empty() || bytes.len() > MAX_MESSAGE_BYTES {
        return Err(bad("framed payload outside limit"));
    }
    write_before(socket, &(bytes.len() as u32).to_be_bytes(), deadline)?;
    write_before(socket, bytes, deadline)?;
    socket.flush()?;
    if Instant::now() >= deadline { return Err(exhausted()); }
    Ok(())
}
fn recv_frame(socket: &mut TcpStream, cap: usize,
              deadline: Instant) -> Result<Vec<u8>, io::Error> {
    let mut len = [0u8;4];
    read_before(socket, &mut len, deadline)?;
    let size = u32::from_be_bytes(len) as usize;
    if size == 0 || size > cap { return Err(bad("invalid inbound frame size")); }
    let mut data = vec![0u8;size];
    read_before(socket, &mut data, deadline)?;
    Ok(data)
}
fn server_once(keys: &Path, db: &Path, verify: &str,
               bind: SocketAddr, lose_ack: bool) -> Result<(), io::Error> {
    let recipient = RecipientKeys::open(keys)?;
    let verify = decode::<32>(verify)?;
    let sender_verify = VerifyingKey::from_bytes(&verify).map_err(error)?;
    let sender = device_id(&verify);
    let recipient_id = device_id(recipient.signing.verifying_key().as_bytes());
    let mut trust = TrustRegistry::new();
    trust.enroll(sender, EPOCH, sender_verify).map_err(error)?;
    trust.enroll(recipient_id, EPOCH, recipient.signing.verifying_key()).map_err(error)?;
    let listener = TcpListener::bind(bind)?;
    println!("READY {}", listener.local_addr()?);
    io::stdout().flush()?;
    let (mut socket, from) = listener.accept()?;
    if !from.ip().is_loopback() { return Err(bad("non-loopback connection")); }
    let io_deadline = Instant::now() + IO_BUDGET;
    let packet = recv_frame(&mut socket, MAX_MESSAGE_BYTES, io_deadline)?;
    let hint = private_route_w3::inspect_route(&packet).map_err(error)?;
    if hint.token != recipient.route_token { return Err(bad("wrong invitation token")); }
    let now = now_ms()?;
    // Authenticate private W3 BEFORE accepting any return key or metadata.
    let verified = private_route_w3::open_authenticated(
        &packet, TrustedRecipient {
            secret: &recipient.secret, recipient_id,
            now, registry: &trust,
        }, recipient.route_token,
    ).map_err(error)?;
    let body = verified.payload();
    if body.len() < RETURN_METADATA_LEN { return Err(bad("signed return metadata missing")); }
    let mut return_tag = [0u8;16];
    return_tag.copy_from_slice(&body[..16]);
    if return_tag == [0;16] { return Err(bad("invalid signed return tag")); }
    let return_public = RecipientPublic::from_bytes(&body[16..48]).map_err(error)?;
    let mut journal = Journal::open(db).map_err(error)?;
    let (insert, signed) = journal.accept_private_authenticated_and_queue_receipt(
        &packet, TrustedRecipient {
            secret: &recipient.secret, recipient_id,
            now, registry: &trust,
        }, recipient.route_token, &recipient.signing, EPOCH,
    ).map_err(error)?;
    let from_disk = journal.queued_recipient_receipt(sender, hint.message_id)
        .map_err(error)?;
    if from_disk.as_deref() != Some(signed.as_slice()) {
        return Err(bad("W4 not durable after commit"));
    }
    let status = if insert == Insert::New { "new" } else { "duplicate" };
    println!("RECIPIENT_COMMITTED {} {}", hex(&hint.message_id), status);
    io::stdout().flush()?;
    if lose_ack {
        println!("INJECTED_W4_DROP (recipient remains durable)");
        return Ok(());
    }
    let encrypted = private_return_w4::seal_signed_receipt(
        &signed, &return_public, return_tag,
    ).map_err(error)?;
    if encrypted.len() != ENVELOPE_LEN { return Err(bad("invalid encrypted W4 size")); }
    send_frame(&mut socket, &encrypted, io_deadline)?;
    println!("W4_SENT {}", hex(&hint.message_id));
    Ok(())
}
fn deliver(keys: &Path, db: &Path, invitation: &Invitation,
           addr: SocketAddr, message: [u8;16]) -> Result<(), io::Error> {
    let sender = SenderKeys::open(keys)?;
    let mut journal = Journal::open(db).map_err(error)?;
    let now = now_ms()?;
    let Some(packet) = journal.retry_bytes(invitation.recipient_id, message, now as i64)
        .map_err(error)? else {
            return Err(bad("message already confirmed or forward TTL expired"));
        };
    let hint = private_route_w3::inspect_route(&packet).map_err(error)?;
    if hint.message_id != message || hint.token != invitation.route_token {
        return Err(bad("stored W3 does not match recipient invitation"));
    }
    let mut socket = TcpStream::connect_timeout(&addr, IO_BUDGET)?;
    let io_deadline = Instant::now() + IO_BUDGET;
    send_frame(&mut socket, &packet, io_deadline)?;
    let encrypted = recv_frame(&mut socket, ENVELOPE_LEN, io_deadline)?;
    if encrypted.len() != ENVELOPE_LEN { return Err(bad("return length mismatch")); }
    let mut trust = TrustRegistry::new();
    trust.enroll(invitation.recipient_id, EPOCH, invitation.signing).map_err(error)?;
    let deadline = hint.expires_at_ms.checked_add(RETURN_GRACE_MS)
        .ok_or(bad("return invitation expiry overflow"))?;
    let result = private_return_w4::open_verify_and_apply(
        &encrypted,
        ReturnInvitation {
            sender_secret: &sender.return_secret,
            expected_tag: sender.return_tag(message),
            expires_at_ms: deadline,
            now_ms: now_ms()?,
            recipient_trust: &trust,
        },
        &mut journal,
    ).map_err(error)?;
    if result != Delivery::Recipient { return Err(bad("not an end-recipient receipt")); }
    if journal.retry_bytes(invitation.recipient_id, message, now_ms()? as i64)
        .map_err(error)?.is_some()
    {
        return Err(bad("verified recipient W4 did not close the outbox"));
    }
    println!("RECIPIENT_CONFIRMED {}", hex(&message));
    Ok(())
}
fn new_message(keys: &Path, db: &Path, invite: &Invitation,
               addr: SocketAddr, payload: &str) -> Result<(), io::Error> {
    let sender = SenderKeys::open(keys)?;
    let now = now_ms()?;
    let expiry = now.checked_add(FORWARD_TTL_MS).ok_or(bad("clock overflow"))?;
    let message = random::<16>()?;
    if message == [0;16] { return Err(bad("empty message id")); }
    let mut encoded = Vec::with_capacity(RETURN_METADATA_LEN + payload.len());
    let (_, pub_return) = {
        // Derive the public key corresponding to the saved return secret.
        // X25519 public_key() is a deterministic KEM operation.
        type Kem = hpke::kem::X25519HkdfSha256;
        ((), <Kem as hpke::Kem>::sk_to_pk(&sender.return_secret))
    };
    encoded.extend_from_slice(&sender.return_tag(message));
    encoded.extend_from_slice(&pub_return.to_bytes());
    encoded.extend_from_slice(payload.as_bytes());
    let packet = private_route_w3::seal_private(
        &sender.signing, &invite.secret_public, invite.route_token,
        SignedHeader {
            message_id: message, recipient_id: invite.recipient_id,
            sender_id: device_id(sender.signing.verifying_key().as_bytes()),
            epoch: EPOCH, expiry,
        },
        &encoded,
    ).map_err(error)?;
    let mut journal = Journal::open(db).map_err(error)?;
    journal.enqueue(invite.recipient_id, message, expiry as i64, &packet)
        .map_err(error)?;
    journal.begin_multipath(
        invite.recipient_id, message, &packet, expiry as i64,
        1, now as i64,
    ).map_err(error)?;
    println!("MESSAGE_ID={}", hex(&message));
    io::stdout().flush()?; // User needs the ID if the W4 response is lost.
    deliver(keys, db, invite, addr, message)
}
fn usage() -> io::Error {
    bad("usage: w4_tunnel_lab init-sender <file> | init-recipient <file> | \
        serve-once|serve-drop-ack <recipient.keys> <recipient.sqlite> \
        <sender-verify-hex> <127.0.0.1:port> | \
        send-new <sender.keys> <sender.sqlite> <recipient-invite-hex> \
        <127.0.0.1:port> <test-text> | \
        resend <sender.keys> <sender.sqlite> <recipient-invite-hex> \
        <127.0.0.1:port> <message-id-hex>")
}
fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("init-sender") if args.len() == 3 => init_sender(Path::new(&args[2]))?,
        Some("init-recipient") if args.len() == 3 => init_recipient(Path::new(&args[2]))?,
        Some("serve-once" | "serve-drop-ack") if args.len() == 6 => server_once(
            Path::new(&args[2]), Path::new(&args[3]), &args[4],
            usable_address(&args[5])?, args[1] == "serve-drop-ack",
        )?,
        Some("send-new") if args.len() == 7 => {
            let invite = parse_invite(&args[4])?;
            new_message(Path::new(&args[2]), Path::new(&args[3]),
                &invite, usable_address(&args[5])?, &args[6])?;
        }
        Some("resend") if args.len() == 7 => {
            let invite = parse_invite(&args[4])?;
            deliver(Path::new(&args[2]), Path::new(&args[3]), &invite,
                    usable_address(&args[5])?, decode::<16>(&args[6])?)?;
        }
        _ => return Err(usage().into()),
    }
    Ok(())
}


#[cfg(test)]
mod frame_budget_tests {
    use super::*;
    #[test]
    fn expired_absolute_deadline_rejects_before_allocating_any_frame() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let _client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut server, _) = listener.accept().unwrap();
        let expired = Instant::now() - Duration::from_millis(1);
        let err = recv_frame(&mut server, MAX_MESSAGE_BYTES, expired).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }
    #[test]
    fn oversized_frame_prefix_is_refused_without_reading_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut server, _) = listener.accept().unwrap();
        client.write_all(&u32::MAX.to_be_bytes()).unwrap();
        let err = recv_frame(
            &mut server, MAX_MESSAGE_BYTES, Instant::now() + Duration::from_secs(2),
        ).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }
}
