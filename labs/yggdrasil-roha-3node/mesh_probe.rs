//! Three-namespace test of real Roha/noq QUIC over Yggdrasil IPv6.
//! Static keys are for an isolated test only; never copy into production.
use std::{net::{IpAddr, Ipv6Addr, SocketAddr}, str::FromStr, time::Duration};
use iroh::{Endpoint, EndpointAddr, RelayMode, SecretKey, TransportAddr, endpoint::presets};
use n0_error::{Result, StdResultExt};

const ALPN: &[u8] = b"akula/staya/yggdrasil-multihop-lab/1";
const SERVER_KEY: [u8; 32] = [0x11; 32];
const CLIENT_KEY: [u8; 32] = [0x22; 32];
const SIZE: usize = 65536;

fn socket(ip: &str, port: u16) -> Result<SocketAddr> {
    let ip = Ipv6Addr::from_str(ip).anyerr()?;
    Ok(SocketAddr::new(IpAddr::V6(ip), port))
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    assert!(args.len() == 4 || args.len() == 5,
        "usage: mesh_probe server OWN_IPV6 PORT | client OWN_IPV6 SERVER_IPV6 PORT");
    let server = args[1] == "server";
    let own_port = if server { args[3].parse().anyerr()? } else { 51002 };
    let own_addr = socket(&args[2], own_port)?;
    let endpoint = Endpoint::builder(presets::Minimal)
        .clear_ip_transports()
        .bind_addr(own_addr)?
        .relay_mode(RelayMode::Disabled)
        .secret_key(SecretKey::from(if server { SERVER_KEY } else { CLIENT_KEY }))
        .alpns(vec![ALPN.to_vec()])
        .bind()
        .await?;
    println!("BOUND role={} endpoint={} listen={own_addr} relay=disabled discovery=none",
        args[1], endpoint.id());

    if server {
        let incoming = tokio::time::timeout(Duration::from_secs(90), endpoint.accept())
            .await.anyerr()?.expect("incoming Roha request");
        let conn = incoming.await.anyerr()?;
        let (mut send, mut recv) = conn.accept_bi().await.anyerr()?;
        let bytes = recv.read_to_end(SIZE + 1).await.anyerr()?;
        assert_eq!(bytes, vec![0xA5; SIZE], "received wrong payload");
        send.write_all(&bytes).await.anyerr()?;
        send.finish().anyerr()?;
        println!("SERVER_ECHO_OK size={}", bytes.len());
        let _ = tokio::time::timeout(Duration::from_secs(5), conn.closed()).await;
    } else {
        let remote = socket(&args[3], args[4].parse().anyerr()?)?;
        let addr = EndpointAddr::from_parts(
            SecretKey::from(SERVER_KEY).public(), [TransportAddr::Ip(remote)]);
        let conn = tokio::time::timeout(Duration::from_secs(90), endpoint.connect(addr, ALPN))
            .await.anyerr()?.anyerr()?;
        let (mut send, mut recv) = conn.open_bi().await.anyerr()?;
        let payload = vec![0xA5; SIZE];
        send.write_all(&payload).await.anyerr()?;
        send.finish().anyerr()?;
        let echo = recv.read_to_end(SIZE + 1).await.anyerr()?;
        assert_eq!(echo, payload, "Roha QUIC echo mismatch");
        let selected = conn.paths().into_iter().find(|p| p.is_selected())
            .expect("selected QUIC path").remote_addr();
        assert!(matches!(selected, TransportAddr::Ip(ip) if *ip == remote),
            "expected Yggdrasil IPv6 IP path, got {selected:?}");
        println!("CLIENT_ROHA_QUIC_OK size={} selected={selected:?} relay=disabled",
            echo.len());
        conn.close(0u32.into(), b"done");
    }
    endpoint.close().await;
    Ok(())
}
