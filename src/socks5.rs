use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
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

    // Method selection. If creds are configured, REQUIRE username/password (RFC 1929) so
    // the relay is never an open proxy even if the source-IP firewall is ever bypassed.
    // No creds → no-auth (firewall is then the only lock).
    let want_user = &state.config.server.socks_user;
    // Prefer no-auth when the client offers it. The source-IP firewall + is_source_allowed
    // (both fail-CLOSED on an empty whitelist) are the real WHO locks, so the RFC1929 round-trip
    // is pure added latency on every short-lived P2P media connection. Fall back to user/pass
    // only if the client doesn't offer no-auth AND creds are configured.
    if methods.contains(&0x00) {
        inbound.write_all(&[0x05, 0x00]).await?; // no-auth
    } else if !want_user.is_empty() && methods.contains(&0x02) {
        inbound.write_all(&[0x05, 0x02]).await?;
        // sub-negotiation: VER(0x01) ULEN UNAME PLEN PASSWD
        let mut v = [0u8; 1];
        inbound.read_exact(&mut v).await?;
        if v[0] != 0x01 {
            return Ok(());
        }
        let mut ulen = [0u8; 1];
        inbound.read_exact(&mut ulen).await?;
        let mut uname = vec![0u8; ulen[0] as usize];
        inbound.read_exact(&mut uname).await?;
        let mut plen = [0u8; 1];
        inbound.read_exact(&mut plen).await?;
        let mut passwd = vec![0u8; plen[0] as usize];
        inbound.read_exact(&mut passwd).await?;
        let ok = uname.as_slice() == want_user.as_bytes()
            && passwd.as_slice() == state.config.server.socks_pass.as_bytes();
        if !ok {
            inbound.write_all(&[0x01, 0x01]).await?; // auth failure
            debug!("socks5 auth failed");
            return Ok(());
        }
        inbound.write_all(&[0x01, 0x00]).await?; // auth success
    } else {
        inbound.write_all(&[0x05, 0xFF]).await?; // no acceptable method
        return Ok(());
    }

    // --- request: VER CMD RSV ATYP DST.ADDR DST.PORT ---
    let mut req = [0u8; 4];
    inbound.read_exact(&mut req).await?;
    if req[0] != 0x05 {
        return Ok(());
    }
    let cmd = req[1];
    let atyp = req[3];

    // For a domain CONNECT, whether the destination domain is itself a configured unlock
    // target (e.g. a *.sooplive.com / *.edge4k.com subdomain). SOOP's media + API subdomains
    // round-robin across many Korean IPs that can't all live in a CIDR list, so the relay
    // must gate such a request on the DOMAIN ruleset, not the resolved IP — otherwise a legit
    // unlock subdomain whose current IP is outside the configured CIDRs gets refused (REP 02).
    let mut domain_unlock = false;

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
            // domain — KimiR routes unlock domains here by name (their IP round-robins).
            let mut l = [0u8; 1];
            inbound.read_exact(&mut l).await?;
            let mut d = vec![0u8; l[0] as usize];
            inbound.read_exact(&mut d).await?;
            let host = String::from_utf8_lossy(&d).to_string();
            domain_unlock = state.rules.load().match_domain(&host);
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

    if cmd == 0x03 {
        // UDP ASSOCIATE — the DST.ADDR/PORT above is the client's expected source (ignored).
        // We bind a relay socket and shuttle datagrams ↔ real dests. SOOP's P2P livestream
        // grid egresses over UDP, which a CONNECT-only relay silently dropped.
        return handle_udp_associate(state, inbound).await;
    }
    if cmd != 0x01 {
        reply(&mut inbound, 0x07).await?; // command not supported
        return Ok(());
    }

    // Gate: forward if the dest IP is in an unlock CIDR, OR the dest domain is itself an
    // unlock target (domain CONNECT), OR the dest is a high media port (SOOP-style P2P) —
    // never an open proxy. The firewall already restricts WHO connects (landing nodes only);
    // this restricts WHERE they can reach.
    //
    // media-port gate: SOOP live delivers video over a P2P grid of bare Korean residential
    // IPs on high ports (10000-29999) that churn every minute — unboundable by CIDR (a 60s
    // capture yields ~17 fresh /24s). The cheap landing datacenter can't even reach those
    // residential peers (1/6 in testing), but this AWS node can (6/6) — better peering. The
    // landing routes such traffic to us by PORT (route.json usk-port rule); accept it here on
    // the same port signature so the gate isn't a losing whack-a-mole CIDR chase. Still gated
    // to trusted landings by the firewall + is_source_allowed, so this is not an open relay.
    let media_port = (10000..=29999).contains(&dest_port);
    let rules = state.rules.load();
    if !domain_unlock && !media_port && !rules.match_ip(&dest_ip) {
        debug!("socks5 dest not in unlock cidr/domain/mediaport: {dest_ip}:{dest_port}");
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

// SOCKS5 UDP ASSOCIATE relay. KimiR sends UDP over this for unlock destinations reached by
// UDP (e.g. SOOP's P2P livestream grid). We bind a relay socket, hand its port back, then
// shuttle datagrams ↔ the real dests, gating each on the unlock ruleset (IP CIDR or unlock
// domain). The TCP control connection staying open keeps the association alive; its close
// (EOF) tears the relay down.
async fn handle_udp_associate(state: Arc<AppState>, mut inbound: TcpStream) -> anyhow::Result<()> {
    let relay = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(_) => {
            reply(&mut inbound, 0x01).await?;
            return Ok(());
        }
    };
    let port = relay.local_addr()?.port();
    let pb = port.to_be_bytes();
    // BND.ADDR=0.0.0.0 → KimiR sends UDP to the SOCKS5 server's own IP (this TCP conn's peer).
    inbound
        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, pb[0], pb[1]])
        .await?;

    let upstream = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(_) => return Ok(()),
    };
    state.stats.sni_relayed.fetch_add(1, Ordering::Relaxed);
    debug!("socks5 udp associate on :{port}");

    let mut down = vec![0u8; 65535]; // client (KimiR) → us
    let mut up = vec![0u8; 65535]; // real dest → us
    let mut client: Option<SocketAddr> = None;
    let mut ctrl = [0u8; 256];

    loop {
        tokio::select! {
            // client (KimiR) → real dest
            r = relay.recv_from(&mut down) => {
                let (n, src) = match r { Ok(v) => v, Err(_) => break };
                client = Some(src);
                // SOCKS5 UDP request: RSV(2) FRAG(1) ATYP(1) DST.ADDR DST.PORT DATA
                if n < 4 || down[2] != 0 { continue; } // FRAG != 0 (fragmentation) unsupported
                let (dest_ip, data_off): (IpAddr, usize) = match down[3] {
                    0x01 => {
                        if n < 10 { continue; }
                        (IpAddr::V4(Ipv4Addr::new(down[4], down[5], down[6], down[7])), 10)
                    }
                    0x04 => {
                        if n < 22 { continue; }
                        let mut a = [0u8; 16];
                        a.copy_from_slice(&down[4..20]);
                        (IpAddr::V6(Ipv6Addr::from(a)), 22)
                    }
                    0x03 => {
                        let l = down[4] as usize;
                        if n < 5 + l + 2 { continue; }
                        let host = String::from_utf8_lossy(&down[5..5 + l]).to_string();
                        let allow_dom = state.rules.load().match_domain(&host);
                        if let Ok(ip) = crate::sni::resolve_via_upstream(&state, &host).await {
                            if allow_dom || state.rules.load().match_ip(&ip) {
                                let p = u16::from_be_bytes([down[5 + l], down[5 + l + 1]]);
                                let _ = upstream.send_to(&down[5 + l + 2..n], SocketAddr::new(ip, p)).await;
                            }
                        }
                        continue;
                    }
                    _ => continue,
                };
                let dest_port = u16::from_be_bytes([down[data_off - 2], down[data_off - 1]]);
                if !state.rules.load().match_ip(&dest_ip) { continue; }
                let _ = upstream.send_to(&down[data_off..n], SocketAddr::new(dest_ip, dest_port)).await;
            }
            // real dest → client (KimiR), re-encapsulated
            r = upstream.recv_from(&mut up) => {
                let (n, src) = match r { Ok(v) => v, Err(_) => break };
                let Some(c) = client else { continue };
                let mut out = Vec::with_capacity(n + 22);
                out.extend_from_slice(&[0, 0, 0]); // RSV RSV FRAG
                match src.ip() {
                    IpAddr::V4(v4) => {
                        out.push(0x01);
                        out.extend_from_slice(&v4.octets());
                    }
                    IpAddr::V6(v6) => {
                        out.push(0x04);
                        out.extend_from_slice(&v6.octets());
                    }
                }
                out.extend_from_slice(&src.port().to_be_bytes());
                out.extend_from_slice(&up[..n]);
                let _ = relay.send_to(&out, c).await;
            }
            // TCP control connection closed → association ends
            r = inbound.read(&mut ctrl) => {
                if matches!(r, Ok(0) | Err(_)) { break; }
            }
        }
    }
    debug!("socks5 udp associate closed");
    Ok(())
}

// SOCKS5 reply with the given REP code and a dummy IPv4 BND address.
async fn reply(inbound: &mut TcpStream, rep: u8) -> anyhow::Result<()> {
    inbound
        .write_all(&[0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    Ok(())
}

// ── auto-generated SOCKS5 credentials ──

#[derive(serde::Serialize, serde::Deserialize)]
pub struct SocksCreds {
    pub port: u16,
    pub user: String,
    pub pass: String,
}

const CRED_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

fn urandom(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        let _ = f.read_exact(&mut buf);
    }
    buf
}

fn rand_str(len: usize) -> String {
    urandom(len)
        .iter()
        .map(|b| CRED_CHARS[(*b as usize) % CRED_CHARS.len()] as char)
        .collect()
}

impl SocksCreds {
    fn generate() -> Self {
        let r = urandom(2);
        // random high port 20000..=59999 (firewall-locked + creds, so the value is just
        // there to dodge casual scanners, not relied on for security)
        let port = 20000 + ((u16::from(r[0]) << 8 | u16::from(r[1])) % 40000);
        SocksCreds {
            port,
            user: rand_str(14),
            pass: rand_str(24),
        }
    }
}

/// Make sure the 母节点's SOCKS5 has a port + creds WITHOUT the operator editing anything,
/// so a plain `upgrade` just works. Priority: explicit config.toml creds win; else reuse
/// persisted socks.creds (stable across restarts/upgrades); else generate fresh random ones
/// and persist (0600). The result lands back in `cfg.server` so the firewall and run_socks5
/// just use the normal config fields. Proxy-only landing nodes skip this (no SOCKS5 there).
pub fn ensure_creds(cfg: &mut crate::config::Config, data_dir: &Path) {
    if cfg.panel.is_proxy_only() {
        return;
    }
    if !cfg.server.socks_user.is_empty() {
        return; // operator set creds by hand
    }
    let path = data_dir.join("socks.creds");
    if let Ok(text) = std::fs::read_to_string(&path) {
        if let Ok(c) = serde_json::from_str::<SocksCreds>(&text) {
            cfg.server.socks_listen = format!("0.0.0.0:{}", c.port);
            cfg.server.socks_user = c.user;
            cfg.server.socks_pass = c.pass;
            tracing::info!("SOCKS5 creds: loaded from {}", path.display());
            return;
        }
    }
    let c = SocksCreds::generate();
    cfg.server.socks_listen = format!("0.0.0.0:{}", c.port);
    cfg.server.socks_user = c.user.clone();
    cfg.server.socks_pass = c.pass.clone();
    if let Ok(json) = serde_json::to_string_pretty(&c) {
        if std::fs::write(&path, json).is_ok() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
            }
        }
    }
    tracing::info!(
        "SOCKS5 creds: generated random port {} + user/pass, saved to {} (cat it to configure KimiR's socks outbound)",
        c.port,
        path.display()
    );
}
