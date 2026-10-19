//! W6/F12: independent child processes exercise the manually pinned Roha/noq
//! QUIC probe. This is a same-host 127.0.0.1 regression, NOT two physical
//! computers, NAT traversal, WOW Mailbox or an end-recipient delivery receipt.
#![cfg(all(unix, feature = "iroh-transport"))]

use std::{
    fs::{self, File, Permissions},
    net::SocketAddr,
    os::unix::fs::{symlink, PermissionsExt},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};
use tempfile::tempdir;

const BIN: &str = env!("CARGO_BIN_EXE_wow_two_host_probe");
const DEADLINE: Duration = Duration::from_secs(15);

struct Process {
    child: Child,
    stdout: PathBuf,
    stderr: PathBuf,
}
impl Process {
    fn launch(root: &Path, name: &str, args: &[&str]) -> Self {
        let stdout = root.join(format!("{name}.stdout"));
        let stderr = root.join(format!("{name}.stderr"));
        let child = Command::new(BIN)
            .args(args)
            .stdout(Stdio::from(File::create(&stdout).unwrap()))
            .stderr(Stdio::from(File::create(&stderr).unwrap()))
            .spawn()
            .expect("spawn independent two-host diagnostic process");
        Self {
            child,
            stdout,
            stderr,
        }
    }

    fn stdout(&self) -> String {
        fs::read_to_string(&self.stdout).unwrap_or_default()
    }
    fn stderr(&self) -> String {
        fs::read_to_string(&self.stderr).unwrap_or_default()
    }

    fn wait(&mut self) -> ExitStatus {
        let end = Instant::now() + DEADLINE;
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status;
            }
            assert!(
                Instant::now() < end,
                "probe child exceeded deadline: stdout={} stderr={}",
                self.stdout(),
                self.stderr()
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn ready_address(&mut self) -> SocketAddr {
        let end = Instant::now() + DEADLINE;
        loop {
            if let Some(line) = self.stdout().lines().find(|line| line.starts_with("READY ")) {
                let value = line
                    .split_whitespace()
                    .find_map(|field| field.strip_prefix("address="))
                    .expect("READY must contain address=");
                let addr: SocketAddr = value.parse().expect("valid bound address");
                assert!(addr.ip().is_loopback(), "must be IPv4 loopback only");
                assert_ne!(addr.port(), 0, "the server must publish an actual port");
                return addr;
            }
            assert!(
                self.child.try_wait().unwrap().is_none(),
                "server exited before READY: stdout={} stderr={}",
                self.stdout(),
                self.stderr()
            );
            assert!(Instant::now() < end, "no READY marker: {}", self.stderr());
            thread::sleep(Duration::from_millis(10));
        }
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn run(root: &Path, name: &str, args: &[&str]) -> (bool, String, String) {
    let mut child = Process::launch(root, name, args);
    let ok = child.wait().success();
    (ok, child.stdout(), child.stderr())
}

fn generate(root: &Path, name: &str) -> (PathBuf, String) {
    let key = root.join(format!("{name}.key"));
    let key_str = key.to_str().unwrap();
    let (ok, stdout, stderr) = run(root, &format!("keygen-{name}"), &["keygen", key_str]);
    assert!(ok, "keygen failed: {stdout} {stderr}");
    assert_eq!(fs::metadata(&key).unwrap().permissions().mode() & 0o777, 0o600);
    let (ok, stdout, stderr) = run(root, &format!("id-{name}"), &["id", key_str]);
    assert!(ok, "read ID failed: {stdout} {stderr}");
    let endpoint_id = stdout.trim()
        .strip_prefix("endpoint_id=")
        .expect("CLI must return a public EndpointId")
        .to_owned();
    assert!(!endpoint_id.is_empty());
    (key, endpoint_id)
}

#[test]
fn two_real_os_processes_exchange_authenticated_loopback_challenge() {
    let dir = tempdir().unwrap();
    let root = dir.path();
    let (receiver, receiver_id) = generate(root, "receiver");
    let (sender, sender_id) = generate(root, "sender");
    assert_ne!(receiver_id, sender_id, "independent keys must give distinct IDs");
    let mut server = Process::launch(
        root, "receiver-child",
        &["listen", receiver.to_str().unwrap(), "127.0.0.1:0", &sender_id],
    );
    let addr = server.ready_address();
    let (sender_ok, sender_out, sender_err) = run(
        root, "sender-child",
        &["send", sender.to_str().unwrap(), &addr.to_string(), &receiver_id],
    );
    let server_ok = server.wait().success();
    assert!(sender_ok, "sender failed: {sender_out} {sender_err}");
    assert!(server_ok, "receiver failed: {} {}", server.stdout(), server.stderr());
    assert!(sender_out.contains("PASS_TRANSPORT"), "no sender proof: {sender_out}");
    assert!(server.stdout().contains("PASS_TRANSPORT"), "no receiver proof");
    assert!(sender_out.contains(&receiver_id), "sender accepted unpinned identity");
    assert!(server.stdout().contains(&sender_id), "receiver accepted unallowlisted identity");
}

#[test]
fn independent_wrong_peer_is_denied_after_tls_without_a_success_receipt() {
    let dir = tempdir().unwrap();
    let root = dir.path();
    let (receiver, receiver_id) = generate(root, "receiver");
    let (_, allowed_id) = generate(root, "allowed");
    let (intruder, _) = generate(root, "intruder");
    let mut server = Process::launch(
        root, "denial-server",
        &["listen", receiver.to_str().unwrap(), "127.0.0.1:0", &allowed_id],
    );
    let addr = server.ready_address();
    let (client_ok, client_out, _) = run(
        root, "intruder-child",
        &["send", intruder.to_str().unwrap(), &addr.to_string(), &receiver_id],
    );
    let server_ok = server.wait().success();
    assert!(!client_ok, "unauthorized client must not receive PASS");
    assert!(!server_ok, "denying server must return nonzero");
    assert!(!client_out.contains("PASS_TRANSPORT"), "client forged PASS");
    assert!(
        server.stderr().contains("DENIED"),
        "server did not identify disallowed authenticated peer: {}",
        server.stderr()
    );
    assert!(!server.stdout().contains("PASS_TRANSPORT"));
}

#[test]
fn private_keys_and_external_network_scope_fail_closed() {
    let dir = tempdir().unwrap();
    let root = dir.path();
    let (key, id) = generate(root, "probe");
    let key_str = key.to_str().unwrap();

    // Explicitly refuse group/world-readable private keys.
    fs::set_permissions(&key, Permissions::from_mode(0o644)).unwrap();
    let (ok, _, err) = run(root, "world-readable", &["id", key_str]);
    assert!(!ok && err.contains("chmod 600"), "unsafe permissions accepted: {err}");
    fs::set_permissions(&key, Permissions::from_mode(0o600)).unwrap();

    // Symlinks and partial binary keys must not be silently accepted.
    let alias = root.join("alias.key");
    symlink(&key, &alias).unwrap();
    let (ok, _, _) = run(root, "symlink", &["id", alias.to_str().unwrap()]);
    assert!(!ok, "symlink unexpectedly accepted");
    let short = root.join("short.key");
    fs::write(&short, [1u8; 31]).unwrap();
    fs::set_permissions(&short, Permissions::from_mode(0o600)).unwrap();
    let (ok, _, _) = run(root, "short", &["id", short.to_str().unwrap()]);
    assert!(!ok, "truncated secret unexpectedly accepted");

    // The probe must not silently listen on or dial a non-loopback address.
    let (ok, _, _) = run(root, "unexpected-listen",
        &["listen", key_str, "192.0.2.11:38541", &id]);
    assert!(!ok, "LAN/WAN listener was allowed without explicit opt-in");
    let (ok, _, _) = run(root, "unexpected-dial",
        &["send", key_str, "192.0.2.11:38541", &id]);
    assert!(!ok, "LAN/WAN dial was allowed without explicit opt-in");
    let (ok, _, _) = run(root, "wildcard",
        &["listen", key_str, "0.0.0.0:38541", &id, "--allow-nonloopback"]);
    assert!(!ok, "wildcard listener unexpectedly accepted");
}
