use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tracing::{debug, warn};

use crate::state::AppState;

const MAX_DNS_PACKET: usize = 512;

pub async fn run_dns_server(state: Arc<AppState>) -> anyhow::Result<()> {
    let addr: SocketAddr = state.config.server.dns_listen.parse()?;
    // Bind with retry + a LOUD warning: if another resolver (dnsmasq / sniproxy /
    // smartdns) already holds port 53, a silent bind failure means soho-unlock's
    // DNS never serves and every unlock query falls through to the squatter. Keep
    // retrying so we self-heal the moment the port is freed.
    let sock = loop {
        match UdpSocket::bind(addr).await {
            Ok(s) => break s,
            Err(e) => {
                warn!(
                    "DNS server cannot bind {addr}: {e}. Another resolver \
                     (dnsmasq/sniproxy/smartdns) is probably holding port 53 — \
                     stop it. Retrying in 10s..."
                );
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        }
    };
    tracing::info!("DNS server listening on {}", addr);

    let sock = Arc::new(sock);
    let mut buf = [0u8; MAX_DNS_PACKET];
    loop {
        let (len, src) = match sock.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => { warn!("dns recv error: {e}"); continue; }
        };
        state.stats.dns_queries.fetch_add(1, Ordering::Relaxed);

        if !state.is_source_allowed(&src.ip()) {
            state.stats.dns_blocked.fetch_add(1, Ordering::Relaxed);
            debug!("dns blocked source {}", src.ip());
            continue;
        }

        let packet = buf[..len].to_vec();
        let sock_clone = sock.clone();
        let state_clone = state.clone();
        tokio::spawn(async move {
            if let Some(response) = handle_query(&state_clone, &packet).await {
                let _ = sock_clone.send_to(&response, src).await;
            }
        });
    }
}

/// DNS over TCP on the same address. Needed because some networks block UDP/53,
/// and `options use-vc` in resolv.conf makes the stub resolver query us over TCP.
pub async fn run_dns_server_tcp(state: Arc<AppState>) -> anyhow::Result<()> {
    let addr: SocketAddr = state.config.server.dns_listen.parse()?;
    let listener = loop {
        match TcpListener::bind(addr).await {
            Ok(l) => break l,
            Err(e) => {
                warn!(
                    "DNS-over-TCP cannot bind {addr}: {e}. Another resolver \
                     (dnsmasq/sniproxy/smartdns) is probably holding port 53 — \
                     stop it. Retrying in 10s..."
                );
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        }
    };
    tracing::info!("DNS server (TCP) listening on {}", addr);

    loop {
        let (mut stream, src) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => { warn!("dns-tcp accept error: {e}"); continue; }
        };
        if !state.is_source_allowed(&src.ip()) {
            state.stats.dns_blocked.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        let st = state.clone();
        tokio::spawn(async move {
            let _ = tokio::time::timeout(Duration::from_secs(10), handle_tcp_query(&st, &mut stream)).await;
        });
    }
}

/// One TCP DNS exchange: 2-byte big-endian length prefix + DNS message, both ways.
async fn handle_tcp_query(state: &AppState, stream: &mut TcpStream) -> anyhow::Result<()> {
    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await?;
    let len = u16::from_be_bytes(len_buf) as usize;
    if len == 0 || len > 4096 {
        return Ok(());
    }
    let mut msg = vec![0u8; len];
    stream.read_exact(&mut msg).await?;
    state.stats.dns_queries.fetch_add(1, Ordering::Relaxed);

    if let Some(resp) = handle_query(state, &msg).await {
        let rlen = (resp.len() as u16).to_be_bytes();
        stream.write_all(&rlen).await?;
        stream.write_all(&resp).await?;
    }
    Ok(())
}

async fn handle_query(state: &AppState, packet: &[u8]) -> Option<Vec<u8>> {
    let query = parse_query(packet)?;

    if query.qtype == QTYPE_A || query.qtype == QTYPE_AAAA {
        let rules = state.rules.load();
        if rules.match_domain(&query.qname) {
            let fwd_map = state.dns_forward_map.load();

            // Mapped domain → answer with its unlock server IP (A), and suppress
            // AAAA so the client takes the unlocked v4 path instead of leaking v6.
            if let Some(unlock_ip) = fwd_map.lookup(&query.qname) {
                state.stats.dns_matched.fetch_add(1, Ordering::Relaxed);
                if query.qtype == QTYPE_A {
                    debug!("dns match: {} -> {}", query.qname, unlock_ip);
                    return Some(build_a_response(packet, &query, unlock_ip, state.config.unlock.ttl));
                }
                return Some(build_empty_response(packet, &query));
            }

            // Matched but not in the forward map. On an unlock server this means
            // "terminate the SNI relay here" → return our own IP. A transit node
            // must NEVER return its own IP: the client would hairpin back to the
            // transit box, and clouds usually don't hairpin → the connection just
            // fails. So on transit nodes fall through and resolve normally.
            if state.config.panel.node_type == "unlock" {
                state.stats.dns_matched.fetch_add(1, Ordering::Relaxed);
                debug!("dns match: {} -> unlock (self)", query.qname);
                if query.qtype == QTYPE_A {
                    if let Some(ip) = state.unlock_ip.load().ipv4 {
                        return Some(build_a_response(packet, &query, ip, state.config.unlock.ttl));
                    }
                }
                return Some(build_empty_response(packet, &query));
            }
        }
    }

    state.stats.dns_forwarded.fetch_add(1, Ordering::Relaxed);
    forward_to_upstream(state, packet).await
}

async fn forward_to_upstream(state: &AppState, packet: &[u8]) -> Option<Vec<u8>> {
    let timeout = Duration::from_millis(state.config.upstream.timeout_ms);
    for server in &state.config.upstream.dns {
        let addr: SocketAddr = if server.contains(':') {
            server.parse().ok()?
        } else {
            format!("{server}:53").parse().ok()?
        };
        match forward_udp(packet, addr, timeout).await {
            Ok(resp) => return Some(resp),
            Err(e) => {
                // Some networks (notably some HK hosts) block outbound UDP/53.
                // Fall back to TCP before giving up on this upstream.
                debug!("upstream UDP {addr} failed: {e}, trying TCP");
                match forward_tcp(packet, addr, timeout).await {
                    Ok(resp) => return Some(resp),
                    Err(e2) => { debug!("upstream TCP {addr} failed: {e2}"); continue; }
                }
            }
        }
    }
    warn!("all upstream DNS servers failed (udp+tcp)");
    None
}

async fn forward_udp(packet: &[u8], upstream: SocketAddr, timeout: Duration) -> anyhow::Result<Vec<u8>> {
    let sock = UdpSocket::bind("0.0.0.0:0").await?;
    sock.send_to(packet, upstream).await?;
    let mut buf = [0u8; 4096];
    let len = tokio::time::timeout(timeout, sock.recv(&mut buf)).await??;
    Ok(buf[..len].to_vec())
}

async fn forward_tcp(packet: &[u8], upstream: SocketAddr, timeout: Duration) -> anyhow::Result<Vec<u8>> {
    let fut = async {
        let mut stream = TcpStream::connect(upstream).await?;
        let len = (packet.len() as u16).to_be_bytes();
        stream.write_all(&len).await?;
        stream.write_all(packet).await?;
        let mut lbuf = [0u8; 2];
        stream.read_exact(&mut lbuf).await?;
        let rlen = u16::from_be_bytes(lbuf) as usize;
        let mut buf = vec![0u8; rlen];
        stream.read_exact(&mut buf).await?;
        Ok::<Vec<u8>, anyhow::Error>(buf)
    };
    tokio::time::timeout(timeout, fut).await?
}

// --- DNS packet constants ---
const QTYPE_A: u16 = 1;
const QTYPE_AAAA: u16 = 28;

struct DnsQuery {
    qname: String,
    qtype: u16,
    qname_end: usize,
}

fn parse_query(buf: &[u8]) -> Option<DnsQuery> {
    if buf.len() < 12 { return None; }
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
    if qdcount == 0 { return None; }

    let mut pos = 12;
    let mut labels = Vec::new();
    loop {
        if pos >= buf.len() { return None; }
        let len = buf[pos] as usize;
        pos += 1;
        if len == 0 { break; }
        if len >= 0xC0 { return None; } // compressed pointer in query = unusual
        if pos + len > buf.len() { return None; }
        labels.push(std::str::from_utf8(&buf[pos..pos + len]).ok()?.to_string());
        pos += len;
    }
    if pos + 4 > buf.len() { return None; }
    let qtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
    let qname = labels.join(".");
    Some(DnsQuery { qname, qtype, qname_end: pos + 4 })
}

fn build_a_response(query_pkt: &[u8], query: &DnsQuery, ip: Ipv4Addr, ttl: u32) -> Vec<u8> {
    let mut resp = Vec::with_capacity(query.qname_end + 16);
    // Copy header
    resp.extend_from_slice(&query_pkt[..2]); // ID
    resp.extend_from_slice(&[0x81, 0x80]); // flags: response, recursion available
    resp.extend_from_slice(&query_pkt[4..6]); // QDCOUNT
    resp.extend_from_slice(&[0, 1]); // ANCOUNT = 1
    resp.extend_from_slice(&[0, 0, 0, 0]); // NSCOUNT, ARCOUNT
    // Copy question
    resp.extend_from_slice(&query_pkt[12..query.qname_end]);
    // Answer: pointer to qname at offset 12
    resp.extend_from_slice(&[0xC0, 0x0C]);
    resp.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
    resp.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
    resp.extend_from_slice(&ttl.to_be_bytes());
    resp.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
    resp.extend_from_slice(&ip.octets());
    resp
}

fn build_empty_response(query_pkt: &[u8], query: &DnsQuery) -> Vec<u8> {
    let mut resp = Vec::with_capacity(query.qname_end);
    resp.extend_from_slice(&query_pkt[..2]);
    resp.extend_from_slice(&[0x81, 0x80]);
    resp.extend_from_slice(&query_pkt[4..6]);
    resp.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // AN=0, NS=0, AR=0
    resp.extend_from_slice(&query_pkt[12..query.qname_end]);
    resp
}
