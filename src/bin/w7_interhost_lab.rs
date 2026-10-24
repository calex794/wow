//! W7 P0-7 PRIVATE OVERLAY ONLY: separate lab audit host/prober.
//!
//! No W3 STORE, no FETCH, no real mailbox/Vault, no public interface, no W4.
//! This binary is a lab appliance for SYNTHETIC W3 and separately pinned keys.
//! NEVER deploy on the public internet; restrict to local/VPN firewalled peers.
//! All seed files are raw 32 bytes, owner-only on Unix and never printed.
//! Physical independence of operators is NOT inferred from a successful run.
use akula_wire_lab::custodian_audit_grant_w7::{sign_for_lab, AuditGrantClaims, AuditGrantExpectation};
use akula_wire_lab::custodian_evidence_bridge::{LocalEvidenceContext, ServiceIdentity};
use akula_wire_lab::custodian_observation::{LocalObservationStore, ServiceRole};
use akula_wire_lab::custodian_p07_overlay::{
    check_and_respond, local_wall_clock_ms, validate_bind_address,
    validate_synthetic_fixture, HostAuditPolicy, ProbeFault, P07_ALPN,
};
use akula_wire_lab::custodian_w7_quic_lab::{
    audit_and_record_private_overlay, endpoint_binding_message,
    GrantedLabAuditRequest, LabAuditError, LabAuditOutcome, SignedEndpointBinding,
};
use akula_wire_lab::custody_audit_w7::AuditReference;
use akula_wire_lab::trust_w3::TrustRegistry;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use iroh::{endpoint::presets, Endpoint, EndpointAddr, EndpointId, SecretKey};
use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::Path;
use std::time::{Duration, Instant};

type LabResult<T> = Result<T, Box<dyn Error>>;
const NETWORK_OPT_IN: &str = "--private-overlay-opt-in";
const LOOPBACK_ONLY: &str = "--loopback-only";

fn fail(message: &str) -> Box<dyn Error> { message.to_owned().into() }
fn byte_array<const N: usize>(value: &str) -> LabResult<[u8; N]> {
    if value.len() != N * 2 || !value.is_ascii() {
        return Err(fail("invalid fixed-length hexadecimal identifier"));
    }
    let mut raw = [0u8; N];
    for (i, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        raw[i] = u8::from_str_radix(std::str::from_utf8(pair)?, 16)?;
    }
    Ok(raw)
}
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes { let _ = write!(out, "{b:02x}"); }
    out
}
fn seed(path: &str) -> LabResult<[u8; 32]> {
    let metadata = fs::metadata(path)?;
    if !metadata.is_file() || metadata.len() != 32 {
        return Err(fail("key file must contain exactly 32 raw secret bytes"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(fail("key file is readable by group/others; chmod 600"));
        }
    }
    let data = fs::read(path)?;
    Ok(data.as_slice().try_into().expect("exact key length checked"))
}
fn create_private(path: &str, contents: &[u8]) -> LabResult<()> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(contents)?;
    file.sync_all()?;
    Ok(())
}
fn trust_key(trust: &mut TrustRegistry, id: [u8; 16],
    epoch: u64, value: &str) -> LabResult<()> {
    let key = VerifyingKey::from_bytes(&byte_array::<32>(value)?)?;
    trust.enroll(id, epoch, key).map_err(|e| format!("invalid pinned service/issuer: {e:?}"))?;
    Ok(())
}
fn parse_overlay(flag: &str) -> LabResult<bool> {
    match flag {
        NETWORK_OPT_IN => Ok(true),
        LOOPBACK_ONLY => Ok(false),
        _ => Err(fail("expected --loopback-only or --private-overlay-opt-in")),
    }
}
fn parse_socket(text: &str, allow_overlay: bool) -> LabResult<SocketAddr> {
    let addr: SocketAddr = text.parse()?;
    validate_bind_address(addr, allow_overlay)
        .map_err(|e| format!("unsafe network address: {e:?}"))?;
    Ok(addr)
}
fn fixture(path: &str) -> LabResult<Vec<u8>> {
    let metadata = fs::metadata(path)?;
    if !metadata.is_file() || metadata.len() == 0
        || metadata.len() > akula_wire_lab::MAX_MESSAGE_BYTES as u64
    {
        return Err(fail("fixture must be a bounded synthetic W3 file"));
    }
    let bytes = fs::read(path)?;
    validate_synthetic_fixture(&bytes).map_err(|e| format!("{e:?}"))?;
    Ok(bytes)
}
fn parse_epoch(text: &str) -> LabResult<u64> {
    let epoch: u64 = text.parse()?;
    if epoch == 0 || epoch > i64::MAX as u64 { return Err(fail("invalid epoch")); }
    Ok(epoch)
}
fn make_bind_label(id: EndpointId, socket: SocketAddr, signature: &[u8; 64]) {
    println!("READY {} {} {}", id, socket, hex(signature));
}
fn public(args: &[String]) -> LabResult<()> {
    if args.len() != 2 { return Err(fail("public KEYFILE")); }
    let secret = seed(&args[1])?;
    let key = SigningKey::from_bytes(&secret);
    println!("ED25519 {}", hex(&key.verifying_key().to_bytes()));
    println!("QUIC {}", SecretKey::from_bytes(&secret).public());
    Ok(())
}
fn generate(args: &[String]) -> LabResult<()> {
    if args.len() != 2 { return Err(fail("generate KEYFILE")); }
    let mut secret = [0u8; 32];
    getrandom::fill(&mut secret)?;
    create_private(&args[1], &secret)?;
    println!("CREATED private-key-file (secret never printed)");
    Ok(())
}
fn issue(args: &[String]) -> LabResult<()> {
    if args.len() != 13 {
        return Err(fail("issue ISSUER_KEY ISSUER_ID ISSUER_EPOCH SERVICE_ID SERVICE_EPOCH SERVICE_TLS_ID AUDITOR_TLS_ID ROUTE MESSAGE W3_FIXTURE EXPIRES_MS NONCE_HEX GRANT_OUT"));
    }
    let sender = SigningKey::from_bytes(&seed(&args[1])?);
    let issued = local_wall_clock_ms().map_err(|e| format!("clock: {e:?}"))?;
    let expires_at_ms: u64 = args[11].parse()?;
    // Very short lab-only capability. Replayed by same TLS client until expiry.
    if expires_at_ms <= issued || expires_at_ms - issued > 120_000 {
        return Err(fail("signed audit grant TTL must be in (0,120s]"));
    }
    let w3 = fixture(&args[10])?;
    let claim = AuditGrantClaims {
        issuer_id: byte_array(&args[2])?, issuer_epoch: parse_epoch(&args[3])?,
        service_id: byte_array(&args[4])?, service_epoch: parse_epoch(&args[5])?,
        service_endpoint: args[6].parse()?, auditor_endpoint: args[7].parse()?,
        route_token: byte_array(&args[8])?, message_id: byte_array(&args[9])?,
        ciphertext_len: w3.len() as u32,
        ciphertext_digest: *blake3::hash(&w3).as_bytes(),
        expires_at_ms,
        nonce: byte_array(&args[12])?,
    };
    // The issuer must be an independently authorized local operator. This
    // command does not assert that it has the product's STORE/FETCH authority.
    let signed = sign_for_lab(&sender, claim).map_err(|e| format!("grant: {e:?}"))?;
    let destination = args.get(13).ok_or_else(|| fail("missing GRANT_OUT"))?;
    create_private(destination, &signed)?;
    println!("SIGNED lab-only W7 AUDIT grant; grant bytes not printed");
    Ok(())
}

struct HostConfig {
    bind: SocketAddr,
    service_id: [u8; 16],
    epoch: u64,
    service_signer: SigningKey,
    tls_secret: SecretKey,
    trust: TrustRegistry,
    issuer_id: [u8; 16],
    auditor: EndpointId,
    route: [u8; 16],
    message: [u8; 16],
    fixture: Vec<u8>,
    fault: ProbeFault,
}
fn host_config(args: &[String]) -> LabResult<HostConfig> {
    if args.len() != 15 {
        return Err(fail("serve BIND SERVICE_ID EPOCH SERVICE_KEY TLS_KEY ISSUER_ID ISSUER_EPOCH ISSUER_PUB AUDITOR_TLS_ID ROUTE MESSAGE W3_FIXTURE FAULT --loopback-only|--private-overlay-opt-in"));
    }
    let allow = parse_overlay(&args[14])?;
    let bind = parse_socket(&args[1], allow)?;
    let issuer_id = byte_array(&args[6])?;
    let issuer_epoch = parse_epoch(&args[7])?;
    let mut trust = TrustRegistry::new();
    trust_key(&mut trust, issuer_id, issuer_epoch, &args[8])?;
    let service_signer = SigningKey::from_bytes(&seed(&args[4])?);
    let tls_secret = SecretKey::from_bytes(&seed(&args[5])?);
    if service_signer.verifying_key().to_bytes() == tls_secret.public().as_bytes()[..] {
        return Err(fail("reuse of service signing key as TLS key forbidden"));
    }
    Ok(HostConfig {
        bind, service_id: byte_array(&args[2])?, epoch: parse_epoch(&args[3])?,
        service_signer, tls_secret, trust, issuer_id,
        auditor: args[9].parse()?, route: byte_array(&args[10])?,
        message: byte_array(&args[11])?, fixture: fixture(&args[12])?,
        fault: args[13].parse()?,
    })
}
async fn handle_one(
    conn: iroh::endpoint::Connection, policy: &HostAuditPolicy<'_>,
    trust: &TrustRegistry, fault: ProbeFault,
) -> LabResult<()> {
    let remote = conn.remote_id();
    let (mut tx, mut rx) = tokio::time::timeout(
        Duration::from_secs(5), conn.accept_bi(),
    ).await??;
    let frame = tokio::time::timeout(
        Duration::from_secs(5),
        rx.read_to_end(akula_wire_lab::custodian_audit_grant_w7::SIGNED_AUDIT_GRANT_LEN + 1),
    ).await??;
    let now = local_wall_clock_ms().map_err(|e| format!("clock: {e:?}"))?;
    let (decision, response) = check_and_respond(policy, remote, &frame, trust, now);
    if fault == ProbeFault::Delay && decision != akula_wire_lab::custodian_p07_overlay::Decision::Denied {
        tokio::time::sleep(Duration::from_secs(7)).await;
    }
    tx.write_all(&response).await?;
    tx.finish()?;
    let _ = tokio::time::timeout(Duration::from_millis(350), conn.closed()).await;
    Ok(())
}
async fn serve(args: &[String]) -> LabResult<()> {
    let cfg = host_config(args)?;
    let endpoint = Endpoint::builder(presets::Minimal)
        .clear_ip_transports()
        .secret_key(cfg.tls_secret)
        .bind_addr(cfg.bind)?
        .alpns(vec![P07_ALPN.to_vec()])
        .bind().await?;
    let socket = endpoint.bound_sockets().into_iter()
        .find(|a| a.ip() == cfg.bind.ip())
        .ok_or_else(|| fail("no socket bound on requested interface"))?;
    let signed = cfg.service_signer.sign(&endpoint_binding_message(
        cfg.service_id, cfg.epoch, &endpoint.id(),
    )).to_bytes();
    make_bind_label(endpoint.id(), socket, &signed);
    io::stdout().flush()?;
    let digest = *blake3::hash(&cfg.fixture).as_bytes();
    let expected = AuditGrantExpectation {
        issuer_id: cfg.issuer_id,
        service_id: cfg.service_id, service_epoch: cfg.epoch,
        service_endpoint: endpoint.id(), auditor_endpoint: cfg.auditor,
        route_token: cfg.route, message_id: cfg.message,
        ciphertext_len: cfg.fixture.len() as u32, ciphertext_digest: digest,
    };
    let policy = HostAuditPolicy {
        expected, actual_service_endpoint: endpoint.id(),
        synthetic_w3: Some(&cfg.fixture), fault: cfg.fault,
    };
    // Deliberately serial, bounded sessions for a tiny private lab.
    // No public listener, no user Mailbox, no replay-to-rank feedback.
    while let Some(incoming) = endpoint.accept().await {
        match tokio::time::timeout(Duration::from_secs(5), incoming).await {
            Ok(Ok(connection)) => {
                if let Err(e) = handle_one(connection, &policy, &cfg.trust, cfg.fault).await {
                    eprintln!("P07 unknown transport failure: {e}");
                }
            }
            _ => eprintln!("P07 unknown TLS handshake failure"),
        }
    }
    Ok(())
}
async fn probe(args: &[String]) -> LabResult<()> {
    if args.len() != 18 {
        return Err(fail("probe LOCAL_BIND AUDITOR_TLS_KEY REMOTE_ADDR REMOTE_TLS_ID SERVICE_BINDING_SIG SERVICE_ID SERVICE_EPOCH SERVICE_PUB ISSUER_ID ISSUER_EPOCH ISSUER_PUB ROUTE MESSAGE GRANT_FILE W3_FIXTURE OBS_DB --loopback-only|--private-overlay-opt-in"));
    }
    let allow = parse_overlay(&args[17])?;
    let local_bind = parse_socket(&args[1], allow)?;
    let remote_socket = parse_socket(&args[3], allow)?;
    let remote_id: EndpointId = args[4].parse()?;
    let issuer_id = byte_array(&args[9])?;
    let issuer_epoch = parse_epoch(&args[10])?;
    let service_id = byte_array(&args[6])?;
    let epoch = parse_epoch(&args[7])?;
    let mut trust = TrustRegistry::new();
    trust_key(&mut trust, service_id, epoch, &args[8])?;
    trust_key(&mut trust, issuer_id, issuer_epoch, &args[11])?;
    let signed_grant = fs::read(&args[14])?;
    let w3 = fixture(&args[15])?;
    let reference = AuditReference::from_trusted_ciphertext(&w3)
        .map_err(|e| format!("reference: {e:?}"))?;
    let endpoint = Endpoint::builder(presets::Minimal)
        .clear_ip_transports()
        .secret_key(SecretKey::from_bytes(&seed(&args[2])?))
        .bind_addr(local_bind)?
        .bind().await?;
    let bound = SignedEndpointBinding {
        service_id, service_epoch: epoch, endpoint_id: remote_id,
        signature: byte_array(&args[5])?,
    };
    let mut observer_key = [0u8; 32];
    getrandom::fill(&mut observer_key)?;
    let observer = SigningKey::from_bytes(&observer_key);
    let started_ms = local_wall_clock_ms().map_err(|e| format!("clock: {e:?}"))?;
    let context = LocalEvidenceContext::bind(
        ServiceIdentity { id: service_id, epoch, role: ServiceRole::Public },
        &observer, 1, [91; 16], started_ms, &trust,
    ).map_err(|e| format!("context: {e:?}"))?;
    let mut store = LocalObservationStore::open(Path::new(&args[16]))
        .map_err(|e| format!("observer journal: {e:?}"))?;
    let started = Instant::now();
    let result = audit_and_record_private_overlay(
        &mut store, &context, &trust,
        GrantedLabAuditRequest {
            client: &endpoint,
            address: EndpointAddr::new(remote_id).with_ip_addr(remote_socket),
            expected_pinned_endpoint: remote_id,
            signed_binding: &bound,
            signed_grant: &signed_grant,
            trusted_issuer_id: issuer_id,
            route_token: byte_array(&args[12])?,
            message_id: byte_array(&args[13])?,
            trusted_reference: &reference,
            now_ms: started_ms,
        },
    ).await;
    let elapsed_ms = started.elapsed().as_millis();
    let outcome = match result {
        Ok(LabAuditOutcome::ExactBytes(_)) => "EXACT_W3_LOCAL_E1",
        Ok(LabAuditOutcome::Unavailable) => "UNKNOWN_UNAVAILABLE",
        Ok(LabAuditOutcome::Rejected) => "DENIED",
        Ok(LabAuditOutcome::UnattributedMismatch) => "UNATTRIBUTED_MISMATCH",
        Err(LabAuditError::Grant(_) | LabAuditError::InvalidBinding
            | LabAuditError::UntrustedService | LabAuditError::WrongEndpoint) => "DENIED",
        Err(_) => "UNKNOWN_TRANSPORT",
    };
    let report = store.verified_report(context.scope(), started_ms)
        .map_err(|e| format!("observer report: {e:?}"))?;
    println!("RESULT status={} rtt_ms={} request_payload_bytes={} exact_w3_count={} domain_independence=UNVERIFIED auto_sanction=false",
        outcome, elapsed_ms, signed_grant.len() + 1, report.last_24h.storage.successes);
    Ok(())
}
#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> LabResult<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let Some(action) = args.first().map(|s| s.as_str()) else {
        return Err(fail("actions: generate | public | issue | serve | probe"));
    };
    match action {
        "generate" => generate(&args),
        "public" => public(&args),
        "issue" => issue(&args),
        "serve" => serve(&args).await,
        "probe" => probe(&args).await,
        _ => Err(fail("unknown P07 lab action")),
    }
}
