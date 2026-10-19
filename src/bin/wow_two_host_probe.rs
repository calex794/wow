//! W6 experimental diagnostic for two manually configured computers.
//!
//! A real, manually pinned Roha/noq QUIC/TLS identity and one synthetic
//! 32-byte challenge. This IS NOT the WOW Mailbox protocol, relay routing,
//! message-delivery receipt, anti-rollback policy anchor, or file sync.
//! Non-loopback operation requires an explicit operator opt-in.
//! Unix first: key files must be private; no Windows keyfile claims.
#[cfg(not(unix))]
fn main() {
    eprintln!("W6 diagnostic only supports Unix private key files currently.");
    std::process::exit(2);
}

#[cfg(unix)]
mod probe {
    use iroh::{
        endpoint::{presets, ServerIncomingLimits},
        Endpoint, EndpointAddr, EndpointId, SecretKey,
    };
    use std::{
        env,
        error::Error,
        fs::{self, OpenOptions},
        io::{self, Read, Write},
        net::SocketAddr,
        os::unix::fs::{OpenOptionsExt, PermissionsExt},
        path::Path,
        time::{Duration, Instant},
    };

    type Result<T> = std::result::Result<T, Box<dyn Error + Send + Sync>>;
    const ALPN: &[u8] = b"wow/w6/two-host-probe-v1";
    const ACCEPT_TIMEOUT: Duration = Duration::from_secs(20);
    const IO_TIMEOUT: Duration = Duration::from_secs(8);

    fn invalid(msg: &str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidInput, msg)
    }

    fn read_key(path: &Path) -> Result<SecretKey> {
        // No symlink/key export; keep the read on one file descriptor to
        // avoid re-opening a different file after checking its metadata.
        if fs::symlink_metadata(path)?.file_type().is_symlink() {
            return Err(invalid("key file cannot be a symbolic link").into());
        }
        let mut file = fs::File::open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
            return Err(invalid("key file must be regular and private (chmod 600)").into());
        }
        let mut raw = [0u8; 32];
        file.read_exact(&mut raw)?;
        let mut extra = [0u8; 1];
        if file.read(&mut extra)? != 0 {
            return Err(invalid("key file is longer than 32 bytes").into());
        }
        Ok(SecretKey::from_bytes(&raw))
    }

    fn keygen(path: &Path) -> Result<()> {
        let secret = SecretKey::generate();
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(&secret.to_bytes())?;
        file.sync_all()?;
        println!("KEY_CREATED endpoint_id={} path={}", secret.public(), path.display());
        Ok(())
    }

    fn socket(value: &str, flag: Option<&str>, listen: bool) -> Result<SocketAddr> {
        let addr: SocketAddr = value.parse()?;
        if flag.is_some() && flag != Some("--allow-nonloopback") {
            return Err(invalid("only --allow-nonloopback is accepted").into());
        }
        if (addr.ip().is_unspecified() && listen) || addr.ip().is_multicast() {
            return Err(invalid("select one real interface address, not wildcard/multicast").into());
        }
        if !listen && (addr.ip().is_unspecified() || addr.port() == 0) {
            return Err(invalid("destination needs a unicast IP and nonzero UDP port").into());
        }
        if !addr.ip().is_loopback() && flag != Some("--allow-nonloopback") {
            return Err(invalid("non-loopback requires --allow-nonloopback").into());
        }
        if listen && !addr.ip().is_loopback() && addr.port() == 0 {
            return Err(invalid("physical-network listener needs a fixed UDP port").into());
        }
        Ok(addr)
    }

    fn peer_id(input: &str) -> Result<EndpointId> {
        Ok(input.parse::<EndpointId>()?)
    }

    pub async fn run() -> Result<()> {
        let args: Vec<String> = env::args().skip(1).collect();
        match args.as_slice() {
            [cmd, path] if cmd == "keygen" => keygen(Path::new(path)),
            [cmd, path] if cmd == "id" => {
                println!("endpoint_id={}", read_key(Path::new(path))?.public());
                Ok(())
            }
            [cmd, key, addr, remote] if cmd == "listen" =>
                listen(key, addr, remote, None).await,
            [cmd, key, addr, remote, flag] if cmd == "listen" =>
                listen(key, addr, remote, Some(flag)).await,
            [cmd, key, addr, remote] if cmd == "send" =>
                send(key, addr, remote, None).await,
            [cmd, key, addr, remote, flag] if cmd == "send" =>
                send(key, addr, remote, Some(flag)).await,
            _ => Err(invalid(
                "Usage:\n\
                 wow_two_host_probe keygen <private-file>\n\
                 wow_two_host_probe id <private-file>\n\
                 wow_two_host_probe listen <private-file> <local-IP:UDP-port> <allowed-peer-ID> [--allow-nonloopback]\n\
                 wow_two_host_probe send <private-file> <remote-IP:UDP-port> <pinned-server-ID> [--allow-nonloopback]"
            ).into()),
        }
    }

    async fn listen(key_file: &str, bind: &str, peer: &str, flag: Option<&str>) -> Result<()> {
        let key = read_key(Path::new(key_file))?;
        let addr = socket(bind, flag, true)?;
        let allowed = peer_id(peer)?;
        if allowed == key.public() {
            return Err(invalid("allowed peer and local endpoint must differ").into());
        }

        let server = Endpoint::builder(presets::Minimal)
            .clear_ip_transports()
            .bind_addr(addr)?
            .secret_key(key)
            .alpns(vec![ALPN.to_vec()])
            .server_incoming_limits(ServerIncomingLimits::new(1, 4096, 4096)?)
            .bind()
            .await?;
        let actual = *server.bound_sockets().iter()
            .find(|bound| bound.is_ipv4() == addr.is_ipv4())
            .ok_or_else(|| invalid("bound UDP socket unavailable"))?;
        println!("READY endpoint_id={} address={} allowed_peer={}", server.id(), actual, allowed);
        io::stdout().flush()?;

        let started = Instant::now();
        let incoming = tokio::time::timeout(ACCEPT_TIMEOUT, server.accept())
            .await?
            .ok_or_else(|| invalid("server endpoint closed during accept"))?;
        let conn = tokio::time::timeout(IO_TIMEOUT, incoming).await??;
        // QUIC/TLS authenticates identity, but operator allowlisting is
        // a separate mandatory decision.
        if conn.remote_id() != allowed {
            eprintln!("DENIED authenticated peer is not on the explicit allowlist");
            server.close().await;
            return Err(invalid("unapproved TLS peer").into());
        }

        let (mut send, mut recv) = tokio::time::timeout(IO_TIMEOUT, conn.accept_bi()).await??;
        let mut challenge = [0u8; 32];
        tokio::time::timeout(IO_TIMEOUT, recv.read_exact(&mut challenge)).await??;
        let expected = blake3::hash(&challenge);
        tokio::time::timeout(IO_TIMEOUT, send.write_all(expected.as_bytes())).await??;
        send.finish()?;
        let confirmation = tokio::time::timeout(IO_TIMEOUT, recv.read_to_end(3)).await??;
        if confirmation != b"ACK" {
            return Err(invalid("transport test ACK not received").into());
        }
        println!(
            "PASS_TRANSPORT peer={} challenge_digest={} elapsed_ms={} scope=transport_only",
            allowed, expected.to_hex(), started.elapsed().as_millis()
        );
        server.close().await;
        Ok(())
    }

    async fn send(key_file: &str, target: &str, server_id: &str, flag: Option<&str>) -> Result<()> {
        let key = read_key(Path::new(key_file))?;
        let remote = socket(target, flag, false)?;
        let expected = peer_id(server_id)?;
        if expected == key.public() {
            return Err(invalid("pinned server and local endpoint must differ").into());
        }

        // For local self-test use loopback. For two hosts use a normal
        // ephemeral outgoing UDP socket; never open an application listener.
        let bind = match (remote.is_ipv4(), remote.ip().is_loopback()) {
            (true, true) => "127.0.0.1:0",
            (false, true) => "[::1]:0",
            (true, false) => "0.0.0.0:0",
            (false, false) => "[::]:0",
        };
        let client = Endpoint::builder(presets::Minimal)
            .clear_ip_transports()
            .bind_addr(bind)?
            .secret_key(key)
            .bind()
            .await?;
        let addr = EndpointAddr::new(expected).with_ip_addr(remote);
        let started = Instant::now();
        let conn = tokio::time::timeout(IO_TIMEOUT, client.connect(addr, ALPN))
            .await??;
        if conn.remote_id() != expected {
            return Err(invalid("QUIC peer does not match pinned server identity").into());
        }
        let (mut send, mut recv) = tokio::time::timeout(IO_TIMEOUT, conn.open_bi()).await??;
        let mut challenge = [0u8; 32];
        getrandom::fill(&mut challenge)?;
        tokio::time::timeout(IO_TIMEOUT, send.write_all(&challenge)).await??;
        let reply = tokio::time::timeout(IO_TIMEOUT, recv.read_to_end(32)).await??;
        let expected_hash = blake3::hash(&challenge);
        if reply != expected_hash.as_bytes() {
            return Err(invalid("server response does not match the challenge").into());
        }
        tokio::time::timeout(IO_TIMEOUT, send.write_all(b"ACK")).await??;
        send.finish()?;
        println!(
            "PASS_TRANSPORT peer={} challenge_digest={} elapsed_ms={} scope=transport_only",
            expected, expected_hash.to_hex(), started.elapsed().as_millis()
        );
        // Allow the independent process to consume its final transport ACK.
        let _ = tokio::time::timeout(Duration::from_secs(3), conn.closed()).await;
        client.close().await;
        Ok(())
    }
}

#[cfg(unix)]
#[tokio::main(flavor = "multi_thread")]
async fn main() {
    if let Err(err) = probe::run().await {
        eprintln!("ERROR: {err}");
        std::process::exit(1);
    }
}
