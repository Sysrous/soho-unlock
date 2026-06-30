use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, warn};

use crate::state::AppState;

// Minimal SOCKS5 inbound (CONNECT, no-auth). The whole point: KimiR's socks outbound
// hands us the real「目标 IP : 端口」in the SOCKS5 request — which is exactly the info a
// bare-IP / non-standard-port media connection LOSES through DNS or a dest-rewrite. With
// it the 母节点 can dial the real site and egress from its own (Korean) IP. Two locks keep
// it from being an open proxy: the source-IP firewall (WHO can connect = landing nodes
// only) + the unlock-CIDR gate below (WHERE they can reach = configured ranges only).
pub async fn run_socks5(state: Arc<AppState>) -> anyhow::Result<()> {
    let addr_str = &state.config.server.socks_listen;
    if addr_str.is_empty() {
        return Ok(());
    }
    let addr: SocketAddr = addr_str.parse()?;
    let listener = TcpListener::bind(addr).await?;
    tracing::info!("SOCKS5 proxy listening on {}", addr);

    loop {
        let (stream, src) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                warn!("socks5 accept error: {e}");
                continue;
            }
        };
        if !state.is_source_allowed(&src.ip()) {
            debug!("socks5 blocked source {}", src.ip());
            drop(stream);
            continue;
        }
        let st = state.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_socks5(st, stream).await {
                debug!("socks5 connection error: {e}");
            }
        });
    }
}

async fn handle_socks5(state: Arc<AppState>, mut inbound: TcpStream) -> anyhow::Result<()> {
    // --- greeting: VER NMETHODS METHODS... ---
    let mut hdr = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(5), inbound.read_exact(&mut hdr)).await??;
    if hdr[0] != 0x05 {
        return Ok(()); // not SOCKS5
    }
    let nmethods = hdr[1] as usize;
    let mut methods = vec![0u8; nmethods];
    inbound.read_exact(&mut methods).await?;
    // reply: choose no-auth (0x00)
    inbound.write_all(&[0x05, 0x00]).await?;

    // --- request: VER CMD RSV ATYP DST.ADDR DST.PORT ---
    let mut req = [0u8; 4];
    inbound.read_exact(&mut req).await?;
    if req[0] != 0x05 {
        return Ok(());
    }
    let cmd = req[1];
    let atyp = req[3];

    let dest_ip: IpAddr = match atyp {
        0x01 => {
            let mut a = [0u8; 4];
            inbound.read_exact(&mut a).await?;
            IpAddr::V4(Ipv4Addr::new(a[0], a[1], a[2], a[3]))
        }
        0x04 => {
            let mut a = [0u8; 16];
            inbound.read_exact(&mut a).await?;
            IpAddr::V6(Ipv6Addr::from(a))
        }
        0x03 => {
            // domain — media is normally a bare IP, but resolve just in case
            let mut l = [0u8; 1];
            inbound.read_exact(&mut l).await?;
            let mut d = vec![0u8; l[0] as usize];
            inbound.read_exact(&mut d).await?;
            let host = String::from_utf8_lossy(&d).to_string();
            match crate::sni::resolve_via_upstream(&state, &host).await {
                Ok(ip) => ip,
                Err(_) => {
                    reply(&mut inbound, 0x04).await?; // host unreachable
                    return Ok(());
                }
            }
        }
        _ => {
            reply(&mut inbound, 0x08).await?; // address type not supported
            return Ok(());
        }
    };
    let mut port_b = [0u8; 2];
    inbound.read_exact(&mut port_b).await?;
    let dest_port = u16::from_be_bytes(port_b);

    if cmd != 0x01 {
        reply(&mut inbound, 0x07).await?; // command not supported (only CONNECT)
        return Ok(());
    }

    // Gate: only forward to configured unlock CIDRs — never an open proxy. The firewall
    // already restricts WHO connects; this restricts WHERE they can reach.
    let rules = state.rules.load();
    if !rules.match_ip(&dest_ip) {
        debug!("socks5 dest not in unlock cidr: {dest_ip}:{dest_port}");
        reply(&mut inbound, 0x02).await?; // connection not allowed by ruleset
        return Ok(());
    }

    let dest = SocketAddr::new(dest_ip, dest_port);
    let outbound = match tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(dest)).await
    {
        Ok(Ok(s)) => s,
        _ => {
            reply(&mut inbound, 0x05).await?; // connection refused
            return Ok(());
        }
    };

    state.stats.sni_relayed.fetch_add(1, Ordering::Relaxed);
    debug!("socks5 relay -> {dest}");

    // success: VER REP=0 RSV ATYP=IPv4 BND.ADDR=0.0.0.0 BND.PORT=0
    inbound
        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;

    crate::sni::relay(inbound, outbound).await;
    Ok(())
}

// SOCKS5 reply with the given REP code and a dummy IPv4 BND address.
async fn reply(inbound: &mut TcpStream, rep: u8) -> anyhow::Result<()> {
    inbound
        .write_all(&[0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    Ok(())
}
