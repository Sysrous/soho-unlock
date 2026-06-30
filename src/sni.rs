use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, warn};

use crate::state::AppState;

pub async fn run_sni_proxy(state: Arc<AppState>) -> anyhow::Result<()> {
    let addr: SocketAddr = state.config.server.sni_listen.parse()?;
    let listener = TcpListener::bind(addr).await?;
    tracing::info!("SNI proxy listening on {}", addr);

    loop {
        let (stream, src) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => { warn!("sni accept error: {e}"); continue; }
        };
        state.stats.sni_connections.fetch_add(1, Ordering::Relaxed);

        if !state.is_source_allowed(&src.ip()) {
            state.stats.sni_blocked.fetch_add(1, Ordering::Relaxed);
            debug!("sni blocked source {}", src.ip());
            drop(stream);
            continue;
        }

        let st = state.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_sni_connection(st, stream).await {
                debug!("sni connection error: {e}");
            }
        });
    }
}

async fn handle_sni_connection(state: Arc<AppState>, mut inbound: TcpStream) -> anyhow::Result<()> {
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(Duration::from_secs(5), inbound.read(&mut buf)).await??;
    if n == 0 { return Ok(()); }
    let initial = &buf[..n];

    let sni = match extract_sni(initial) {
        Some(s) => s,
        None => {
            debug!("no SNI found, dropping");
            return Ok(());
        }
    };

    let rules = state.rules.load();
    // 媒体走裸 IP 时 KimiR 已把它重定向到本机,SNI 就是那个 IP、没有域名可解析。
    // 命中解锁 CIDR 就直接连它;否则按域名走原解析路径。
    let real_ip: std::net::IpAddr = if let Ok(ip) = sni.parse::<std::net::IpAddr>() {
        if !rules.match_ip(&ip) {
            debug!("sni ip not in unlock cidr: {sni}");
            return Ok(());
        }
        ip
    } else {
        if !rules.match_domain(&sni) {
            debug!("sni domain not matched: {sni}");
            return Ok(());
        }
        resolve_via_upstream(&state, &sni).await?
    };
    let upstream_addr = format!("{real_ip}:443");

    debug!("sni relay: {sni} -> {upstream_addr}");
    state.stats.sni_relayed.fetch_add(1, Ordering::Relaxed);

    let mut outbound = tokio::time::timeout(
        Duration::from_secs(10),
        TcpStream::connect(&upstream_addr),
    ).await??;

    outbound.write_all(initial).await?;
    relay(inbound, outbound).await;
    Ok(())
}

async fn resolve_via_upstream(state: &AppState, domain: &str) -> anyhow::Result<std::net::IpAddr> {
    let query_pkt = build_dns_query(domain, 1); // A record
    let timeout = Duration::from_millis(state.config.upstream.timeout_ms);

    for server in &state.config.upstream.dns {
        let addr: SocketAddr = if server.contains(':') {
            match server.parse() { Ok(a) => a, Err(_) => continue }
        } else {
            match format!("{server}:53").parse() { Ok(a) => a, Err(_) => continue }
        };

        let sock = match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => s, Err(_) => continue,
        };
        if sock.send_to(&query_pkt, addr).await.is_err() { continue; }

        let mut resp_buf = [0u8; 2048];
        match tokio::time::timeout(timeout, sock.recv(&mut resp_buf)).await {
            Ok(Ok(len)) => {
                if let Some(ip) = parse_a_response(&resp_buf[..len]) {
                    return Ok(std::net::IpAddr::V4(ip));
                }
            }
            _ => continue,
        }
    }
    anyhow::bail!("failed to resolve {domain}")
}

fn build_dns_query(domain: &str, qtype: u16) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(64);
    pkt.extend_from_slice(&[0xAB, 0xCD]); // ID
    pkt.extend_from_slice(&[0x01, 0x00]); // flags: standard query, RD
    pkt.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]); // QD=1
    for label in domain.split('.') {
        pkt.push(label.len() as u8);
        pkt.extend_from_slice(label.as_bytes());
    }
    pkt.push(0);
    pkt.extend_from_slice(&qtype.to_be_bytes());
    pkt.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
    pkt
}

fn parse_a_response(buf: &[u8]) -> Option<std::net::Ipv4Addr> {
    if buf.len() < 12 { return None; }
    // ANCOUNT is at offset 6..8; offset 4..6 is QDCOUNT. Reading QDCOUNT here meant a
    // CNAME+A reply (2 answers) was walked only once — stopping on the CNAME, never
    // reaching the A record — so every CNAME-fronted domain failed to resolve.
    let ancount = u16::from_be_bytes([buf[6], buf[7]]);
    if ancount == 0 { return None; }

    // Skip header + question section
    let mut pos = 12;
    // Skip QNAME
    loop {
        if pos >= buf.len() { return None; }
        let len = buf[pos] as usize;
        if len == 0 { pos += 1; break; }
        if len >= 0xC0 { pos += 2; break; }
        pos += 1 + len;
    }
    pos += 4; // QTYPE + QCLASS

    // Parse answers
    for _ in 0..ancount {
        if pos + 12 > buf.len() { return None; }
        // NAME (may be pointer)
        if buf[pos] >= 0xC0 {
            pos += 2;
        } else {
            loop {
                if pos >= buf.len() { return None; }
                let len = buf[pos] as usize;
                if len == 0 { pos += 1; break; }
                // A compression pointer (top two bits set) terminates the name. The
                // old code treated 0xC0 as a label length and ran off the end — which
                // is exactly what a CNAME-chained answer like sooplive's hit.
                if len >= 0xC0 { pos += 2; break; }
                pos += 1 + len;
            }
        }
        if pos + 10 > buf.len() { return None; }
        let rtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let rdlen = u16::from_be_bytes([buf[pos + 8], buf[pos + 9]]) as usize;
        pos += 10;
        if rtype == 1 && rdlen == 4 && pos + 4 <= buf.len() {
            return Some(std::net::Ipv4Addr::new(buf[pos], buf[pos+1], buf[pos+2], buf[pos+3]));
        }
        pos += rdlen;
    }
    None
}

async fn relay(mut a: TcpStream, mut b: TcpStream) {
    let _ = tokio::io::copy_bidirectional(&mut a, &mut b).await;
}

fn extract_sni(buf: &[u8]) -> Option<String> {
    // TLS record header
    if buf.len() < 5 { return None; }
    if buf[0] != 0x16 { return None; } // content type: handshake
    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    if buf.len() < 5 + record_len { return None; }
    let hs = &buf[5..];

    // Handshake header
    if hs.is_empty() || hs[0] != 0x01 { return None; } // ClientHello
    if hs.len() < 4 { return None; }
    let hs_len = ((hs[1] as usize) << 16) | ((hs[2] as usize) << 8) | (hs[3] as usize);
    if hs.len() < 4 + hs_len { return None; }
    let ch = &hs[4..];

    // ClientHello body
    if ch.len() < 34 { return None; } // version(2) + random(32)
    let mut pos = 34;

    // Session ID
    if pos >= ch.len() { return None; }
    let sid_len = ch[pos] as usize;
    pos += 1 + sid_len;

    // Cipher Suites
    if pos + 2 > ch.len() { return None; }
    let cs_len = u16::from_be_bytes([ch[pos], ch[pos + 1]]) as usize;
    pos += 2 + cs_len;

    // Compression Methods
    if pos >= ch.len() { return None; }
    let cm_len = ch[pos] as usize;
    pos += 1 + cm_len;

    // Extensions length
    if pos + 2 > ch.len() { return None; }
    let ext_len = u16::from_be_bytes([ch[pos], ch[pos + 1]]) as usize;
    pos += 2;
    let ext_end = pos + ext_len;

    while pos + 4 <= ext_end && pos + 4 <= ch.len() {
        let ext_type = u16::from_be_bytes([ch[pos], ch[pos + 1]]);
        let ext_data_len = u16::from_be_bytes([ch[pos + 2], ch[pos + 3]]) as usize;
        pos += 4;

        if ext_type == 0x0000 { // SNI
            if pos + 2 > ch.len() { return None; }
            let _sni_list_len = u16::from_be_bytes([ch[pos], ch[pos + 1]]);
            pos += 2;
            if pos >= ch.len() { return None; }
            let name_type = ch[pos];
            pos += 1;
            if name_type != 0 { return None; } // host_name
            if pos + 2 > ch.len() { return None; }
            let name_len = u16::from_be_bytes([ch[pos], ch[pos + 1]]) as usize;
            pos += 2;
            if pos + name_len > ch.len() { return None; }
            return std::str::from_utf8(&ch[pos..pos + name_len]).ok().map(|s| s.to_string());
        }
        pos += ext_data_len;
    }
    None
}

// HTTP Host proxy (port 80)
pub async fn run_http_proxy(state: Arc<AppState>) -> anyhow::Result<()> {
    // :80 HTTP relay is opt-in (http_listen unset = off). When enabled on an unlock
    // node it's locked to the landing whitelist by firewall_active(), never exposed.
    let addr_str = &state.config.server.http_listen;
    if addr_str.is_empty() { return Ok(()); }
    let addr: SocketAddr = addr_str.parse()?;
    let listener = TcpListener::bind(addr).await?;
    tracing::info!("HTTP proxy listening on {}", addr);

    loop {
        let (stream, src) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => { warn!("http accept error: {e}"); continue; }
        };
        if !state.is_source_allowed(&src.ip()) {
            drop(stream);
            continue;
        }
        let st = state.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_http_connection(st, stream).await {
                debug!("http error: {e}");
            }
        });
    }
}

async fn handle_http_connection(state: Arc<AppState>, mut inbound: TcpStream) -> anyhow::Result<()> {
    let mut buf = vec![0u8; 8192];
    let n = tokio::time::timeout(Duration::from_secs(5), inbound.read(&mut buf)).await??;
    if n == 0 { return Ok(()); }
    let initial = &buf[..n];

    let host = match extract_host_header(initial) {
        Some(h) => h,
        None => return Ok(()),
    };

    let rules = state.rules.load();
    // 同 SNI:Host 是解锁 CIDR 内的裸 IP 就直连,否则按域名解析。
    let real_ip: std::net::IpAddr = if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        if !rules.match_ip(&ip) { return Ok(()); }
        ip
    } else {
        if !rules.match_domain(&host) { return Ok(()); }
        resolve_via_upstream(&state, &host).await?
    };
    let mut outbound = tokio::time::timeout(
        Duration::from_secs(10),
        TcpStream::connect(format!("{real_ip}:80")),
    ).await??;

    outbound.write_all(initial).await?;
    relay(inbound, outbound).await;
    Ok(())
}

fn extract_host_header(buf: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(buf).ok()?;
    for line in text.split("\r\n") {
        if let Some(val) = line.strip_prefix("Host:").or_else(|| line.strip_prefix("host:")) {
            let host = val.trim().split(':').next().unwrap_or("").to_string();
            if !host.is_empty() { return Some(host); }
        }
    }
    None
}
