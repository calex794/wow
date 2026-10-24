//! P07 real QUIC/TLS tests: TWO independently spawned OS host processes.
//! They run on the SAME CI runner and are NOT independent physical machines.
#![cfg(feature = "iroh-transport")]
use akula_wire_lab::crypto_identity_w3::SignedHeader;
use akula_wire_lab::crypto_w3::new_recipient;
use akula_wire_lab::private_route_w3::seal_private;
use ed25519_dalek::SigningKey;
use iroh::{EndpointId, SecretKey};
use std::fs;
use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};
use tempfile::{tempdir, TempDir};
const BIN: &str = env!("CARGO_BIN_EXE_w7_interhost_lab");

fn id(n: u8) -> [u8; 16] { [n; 16] }
fn signing(n: u8) -> SigningKey { SigningKey::from_bytes(&[n; 32]) }
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len()*2);
    for b in bytes { let _=write!(&mut out, "{b:02x}"); }
    out
}
fn secret_file(dir: &Path, name: &str, byte: u8) -> PathBuf {
    let path = dir.join(name);
    fs::write(&path, [byte; 32]).unwrap();
    #[cfg(unix)] {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    path
}
fn run(args: &[String]) -> String {
    let output = Command::new(BIN).args(args).output().unwrap();
    assert!(output.status.success(), "P07 command failed {:?}: {}", args.first(),
        String::from_utf8_lossy(&output.stderr));
    String::from_utf8(output.stdout).unwrap()
}
fn w3_fixture(dir: &Path) -> PathBuf {
    let (_secret, public) = new_recipient();
    let bytes = seal_private(
        &signing(9), &public, id(4),
        SignedHeader {
            message_id: id(5), recipient_id: id(8),
            expiry: 900_000, sender_id: id(9), epoch: 4,
        }, b"synthetic P07-only signed and encrypted W3",
    ).unwrap();
    let path = dir.join("synthetic-w3.bin");
    fs::write(&path, bytes).unwrap();
    path
}
fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

struct Host {
    process: Child,
    id: EndpointId,
    addr: SocketAddr,
    binding: String,
    service: u8,
    epoch: u64,
}
impl Host {
    fn start(
        root: &Path, service: u8, epoch: u64, tls_seed: u8,
        auditor: EndpointId, fixture: &Path, fault: &str,
    ) -> Self {
        let svc_key=secret_file(root,&format!("service-{service}.seed"),service);
        let tls_key=secret_file(root,&format!("quic-{service}.seed"),tls_seed);
        let args=vec![
            "serve".into(), "127.0.0.1:0".into(), hex(&id(service)),
            epoch.to_string(), svc_key.display().to_string(), tls_key.display().to_string(),
            hex(&id(9)), "4".into(), hex(&signing(9).verifying_key().to_bytes()),
            auditor.to_string(), hex(&id(4)), hex(&id(5)),
            fixture.display().to_string(), fault.into(), "--loopback-only".into(),
        ];
        let mut process=Command::new(BIN).args(&args)
            .stdout(Stdio::piped()).stderr(Stdio::inherit()).spawn().unwrap();
        let stream=process.stdout.take().unwrap();
        let mut line=String::new();
        BufReader::new(stream).read_line(&mut line).unwrap();
        let fields=line.split_whitespace().collect::<Vec<_>>();
        assert_eq!(fields.len(),4,"unexpected server startup output {line:?}");
        assert_eq!(fields[0],"READY");
        let id=fields[1].parse().unwrap();
        let addr: SocketAddr = fields[2].parse().unwrap();
        assert!(addr.ip().is_loopback());
        Self {process,id,addr,binding:fields[3].into(),service,epoch}
    }
    fn issue(&self, issuer_seed: &Path, fixture:&Path, auditor:EndpointId,
        grant_file:&Path, nonce:u8)
    {
        let args=vec![
            "issue".into(), issuer_seed.display().to_string(),
            hex(&id(9)), "4".into(), hex(&id(self.service)), self.epoch.to_string(),
            self.id.to_string(), auditor.to_string(), hex(&id(4)), hex(&id(5)),
            fixture.display().to_string(), (now_ms()+90_000).to_string(),
            hex(&id(nonce)), grant_file.display().to_string(),
        ];
        let output=run(&args);
        assert!(output.contains("SIGNED lab-only"));
        assert!(!output.contains("genuine encrypted private"));
    }
    fn probe(&self, root:&Path, aud_key:&Path, fixture:&Path,
        grant_file:&Path, observer_db:&Path, binding:&str) -> String
    {
        let args=vec![
            "probe".into(), "127.0.0.1:0".into(), aud_key.display().to_string(),
            self.addr.to_string(), self.id.to_string(), binding.into(),
            hex(&id(self.service)), self.epoch.to_string(),
            hex(&signing(self.service).verifying_key().to_bytes()),
            hex(&id(9)), "4".into(), hex(&signing(9).verifying_key().to_bytes()),
            hex(&id(4)), hex(&id(5)), grant_file.display().to_string(),
            fixture.display().to_string(), observer_db.display().to_string(),
            "--loopback-only".into(),
        ];
        let _=root; // lab root is owned by the fixture and key file lifetimes
        run(&args)
    }
}
impl Drop for Host {
    fn drop(&mut self) {
        let _=self.process.kill();
        let _=self.process.wait();
    }
}

#[test]
fn two_real_quic_processes_have_independent_pins_and_authorized_exact_w3() {
    let temp: TempDir=tempdir().unwrap();
    let root=temp.path();
    let issuer=secret_file(root,"issuer.seed",9);
    let auditor_seed=secret_file(root,"auditor.seed",50);
    let auditor=SecretKey::from_bytes(&[50;32]).public();
    let fixture=w3_fixture(root);
    let first=Host::start(root,13,7,53,auditor,&fixture,"honest");
    let second=Host::start(root,14,8,54,auditor,&fixture,"honest");
    assert_ne!(first.id,second.id);
    assert_ne!(first.addr,second.addr);
    assert_ne!(first.binding,second.binding);
    let a_grant=root.join("grant-a.bin");
    let b_grant=root.join("grant-b.bin");
    first.issue(&issuer,&fixture,auditor,&a_grant,91);
    second.issue(&issuer,&fixture,auditor,&b_grant,92);

    let db=root.join("private-audit.sqlite");
    let first_result=first.probe(root,&auditor_seed,&fixture,&a_grant,&db,&first.binding);
    assert!(first_result.contains("status=EXACT_W3_LOCAL_E1"),"{first_result}");
    assert!(first_result.contains("domain_independence=UNVERIFIED"));
    let second_result=second.probe(root,&auditor_seed,&fixture,&b_grant,&db,&second.binding);
    assert!(second_result.contains("status=EXACT_W3_LOCAL_E1"),"{second_result}");
    assert!(second_result.contains("domain_independence=UNVERIFIED"));

    // Wrong TLS-bound grant and tampered Ed25519 binding must never count.
    let stolen=secret_file(root,"stolen-auditor.seed",60);
    let stolen_result=first.probe(root,&stolen,&fixture,&a_grant,&db,&first.binding);
    assert!(stolen_result.contains("status=DENIED"),"{stolen_result}");
    let mut changed_sig=first.binding.clone().into_bytes();
    changed_sig[0]=if changed_sig[0]==b'0'{b'1'}else{b'0'};
    let changed_sig=String::from_utf8(changed_sig).unwrap();
    let bad_sig=first.probe(root,&auditor_seed,&fixture,&a_grant,&db,&changed_sig);
    assert!(bad_sig.contains("status=DENIED"),"{bad_sig}");

    // A signed W5/WRITE permission is not accepted by this client path.
    // P07 never creates a recipient W4 or a K3 slot.
}

#[test]
fn true_network_corruption_and_missing_w3_have_no_negative_sanctions() {
    let temp=tempdir().unwrap();
    let root=temp.path();
    let issuer=secret_file(root,"issuer.seed",9);
    let auditor_seed=secret_file(root,"auditor.seed",50);
    let auditor=SecretKey::from_bytes(&[50;32]).public();
    let fixture=w3_fixture(root);
    let corrupted=Host::start(root,13,7,53,auditor,&fixture,"corrupt");
    let missing=Host::start(root,14,8,54,auditor,&fixture,"missing");
    let a_grant=root.join("a.grant");let b_grant=root.join("b.grant");
    corrupted.issue(&issuer,&fixture,auditor,&a_grant,91);
    missing.issue(&issuer,&fixture,auditor,&b_grant,92);
    let db=root.join("observations.sqlite");
    let a=corrupted.probe(root,&auditor_seed,&fixture,&a_grant,&db,&corrupted.binding);
    assert!(a.contains("status=UNATTRIBUTED_MISMATCH"),"{a}");
    assert!(a.contains("exact_w3_count=0"),"{a}");
    let b=missing.probe(root,&auditor_seed,&fixture,&b_grant,&db,&missing.binding);
    assert!(b.contains("status=UNKNOWN_UNAVAILABLE"),"{b}");
    assert!(b.contains("exact_w3_count=0"),"{b}");
    // The client does not expose a global failure rating or auto-ban flag.
    assert!(a.contains("auto_sanction=false"));
    assert!(b.contains("auto_sanction=false"));
}
