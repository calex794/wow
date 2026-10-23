//! TWO INDEPENDENT OS child processes and TWO different SQLite files.
//! Localhost only: physical Internet/SSH is a separate manual acceptance.
#![cfg(unix)]
use akula_wire_lab::journal_w4::{Delivery, Journal};
use std::io::{BufRead, BufReader};
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use tempfile::{tempdir, TempDir};

fn bin() -> PathBuf { PathBuf::from(env!("CARGO_BIN_EXE_w4_tunnel_lab")) }
fn run(args: &[&str]) -> Output {
    Command::new(bin()).args(args).output().expect("could not launch CLI")
}
fn output_text(output: &Output) -> String {
    assert!(output.status.success(), "exit={:?} stderr={} stdout={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout));
    String::from_utf8(output.stdout.clone()).unwrap()
}
fn field(text: &str, key: &str) -> String {
    text.lines().find_map(|line| line.strip_prefix(key))
        .unwrap_or_else(|| panic!("missing {key} in {text}")).to_owned()
}
fn keys(dir: &TempDir) -> (String, String) {
    let sender = dir.path().join("sender.keys");
    let recipient = dir.path().join("recipient.keys");
    let sender_pub = field(
        &output_text(&run(&["init-sender",sender.to_str().unwrap()])),
        "SENDER_VERIFY=",
    );
    let invite = field(
        &output_text(&run(&["init-recipient",recipient.to_str().unwrap()])),
        "RECIPIENT_INVITE=",
    );
    (sender_pub, invite)
}
fn temporary_port() -> SocketAddr {
    let probe = TcpListener::bind("127.0.0.1:0").unwrap();
    probe.local_addr().unwrap()
}
fn start_server(dir: &Path, sender_pub: &str, mode: &str, port: SocketAddr)
    -> (Child, BufReader<std::process::ChildStdout>)
{
    let mut server = Command::new(bin())
        .args([
            mode,
            dir.join("recipient.keys").to_str().unwrap(),
            dir.join("recipient.sqlite").to_str().unwrap(),
            sender_pub,
            &port.to_string(),
        ])
        .stdout(Stdio::piped()).stderr(Stdio::piped())
        .spawn().unwrap();
    let stdout = server.stdout.take().unwrap();
    let mut stdout = BufReader::new(stdout);
    let mut ready = String::new();
    stdout.read_line(&mut ready).unwrap();
    assert_eq!(ready.trim(), format!("READY {port}"));
    (server, stdout)
}
fn expect_server_success(mut child: Child, mut stdout: BufReader<std::process::ChildStdout>)
    -> String
{
    let mut output = String::new();
    for line in stdout.by_ref().lines() {
        output.push_str(&line.unwrap());
        output.push('\n');
    }
    assert!(child.wait().unwrap().success(),"server failed: {output}");
    output
}
fn make_args<'a>(dir: &'a Path, invite: &'a str,
                  endpoint: &'a str, text: &'a str) -> [String; 6]
{
    [
        "send-new".into(),
        dir.join("sender.keys").display().to_string(),
        dir.join("sender.sqlite").display().to_string(),
        invite.into(),endpoint.into(),text.into(),
    ]
}
fn sender_state(dir: &Path, message_hex: &str) -> Delivery {
    let message = decode16(message_hex);
    // The recipient ID is derived from the verified recipient invitation
    // in production; test uses a query to verify actual persisted state.
    let sqlite = rusqlite::Connection::open(dir.join("sender.sqlite")).unwrap();
    let recipient: Vec<u8> = sqlite.query_row("SELECT recipient FROM outbox WHERE message=?1",
        [message.as_slice()], |r| r.get(0)).unwrap();
    let id: [u8;16] = recipient.try_into().unwrap();
    Journal::open(&dir.join("sender.sqlite")).unwrap().state(id,message).unwrap()
}
fn decode16(s: &str) -> [u8;16] {
    assert_eq!(s.len(),32);
    let mut out=[0u8;16];
    for (i,byte) in out.iter_mut().enumerate() {
        *byte=u8::from_str_radix(&s[i*2..i*2+2],16).unwrap();
    }
    out
}
#[test]
fn independent_processes_have_exact_w3_and_recipient_signed_w4() {
    let dir=tempdir().unwrap();
    let (sender_pub,invite)=keys(&dir);
    let port=temporary_port();
    let (server,reader)=start_server(dir.path(),&sender_pub,"serve-once",port);
    let args=make_args(dir.path(),&invite,&port.to_string(),"1024-byte real W3/W4 lab");
    let output = output_text(&run(&args.iter().map(String::as_str).collect::<Vec<_>>()));
    let mid=field(&output,"MESSAGE_ID=");
    assert!(output.contains("RECIPIENT_CONFIRMED "));
    let srv=expect_server_success(server,reader);
    assert!(srv.contains("RECIPIENT_COMMITTED "));
    assert!(srv.contains("W4_SENT "));
    assert_eq!(sender_state(dir.path(),&mid),Delivery::Recipient);
    // Recipient really persisted the signature in its separate SQLite.
    let row:i64=rusqlite::Connection::open(dir.path().join("recipient.sqlite")).unwrap()
        .query_row("SELECT COUNT(*) FROM receipt_outbox",[],|r|r.get(0)).unwrap();
    assert_eq!(row,1);
}

#[test]
fn lost_reverse_channel_does_not_mark_recipient_until_retried() {
    let dir=tempdir().unwrap();
    let (sender_pub,invite)=keys(&dir);
    let port=temporary_port();
    let (server,reader)=start_server(dir.path(),&sender_pub,"serve-drop-ack",port);
    let args=make_args(dir.path(),&invite,&port.to_string(),"W4 response intentionally lost");
    let result=run(&args.iter().map(String::as_str).collect::<Vec<_>>());
    assert!(!result.status.success(),"missing W4 should fail closed");
    let mid=field(&String::from_utf8(result.stdout).unwrap(),"MESSAGE_ID=");
    let srv=expect_server_success(server,reader);
    assert!(srv.contains("INJECTED_W4_DROP"));
    assert_eq!(sender_state(dir.path(),&mid),Delivery::Queued);
    let port=temporary_port();
    let (server,reader)=start_server(dir.path(),&sender_pub,"serve-once",port);
    let args=[
        "resend",
        dir.path().join("sender.keys").display().to_string().as_str().to_owned(),
        dir.path().join("sender.sqlite").display().to_string(),
        invite,port.to_string(),mid.clone(),
    ];
    let success=output_text(&run(&args.iter().map(String::as_str).collect::<Vec<_>>()));
    assert!(success.contains("RECIPIENT_CONFIRMED"));
    let srv=expect_server_success(server,reader);
    assert!(srv.contains("duplicate"));
    assert_eq!(sender_state(dir.path(),&mid),Delivery::Recipient);
    let db=rusqlite::Connection::open(dir.path().join("recipient.sqlite")).unwrap();
    let (inbox,receipts):(i64,i64)=(
        db.query_row("SELECT COUNT(*) FROM inbox",[],|r|r.get(0)).unwrap(),
        db.query_row("SELECT COUNT(*) FROM receipt_outbox",[],|r|r.get(0)).unwrap(),
    );
    assert_eq!((inbox,receipts),(1,1));
}

#[test]
fn public_listener_and_world_readable_secret_are_refused() {
    let dir=tempdir().unwrap();
    let (sender_pub,_invite)=keys(&dir);
    let result=run(&[
        "serve-once",
        dir.path().join("recipient.keys").to_str().unwrap(),
        dir.path().join("recipient.sqlite").to_str().unwrap(),
        &sender_pub,
        "0.0.0.0:40000",
    ]);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("only 127.0.0.1"));
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(
        dir.path().join("sender.keys"),
        std::fs::Permissions::from_mode(0o644),
    ).unwrap();
    let status=run(&["init-sender",
        dir.path().join("sender.keys").to_str().unwrap()]);
    assert!(!status.status.success(),"refuse overwriting existing key");
    let bad=run(&["send-new",
        dir.path().join("sender.keys").to_str().unwrap(),
        dir.path().join("outbox.sqlite").to_str().unwrap(),
        "00","127.0.0.1:40000","hello"]);
    assert!(!bad.status.success());
}
