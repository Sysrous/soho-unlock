use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Channel, ClientTlsConfig};
use tracing::{info, warn};

use crate::state::{AppState, SourceEntry, SourceList};
use pb::CommandResult;

pub mod pb {
    tonic::include_proto!("agent");
}

use pb::agent_service_client::AgentServiceClient;
use pb::{agent_message, server_message};
use pb::{
    AgentAuth, AgentHeartbeat, AgentIpReport, AgentMessage, RegisterRequest, ReportIPsRequest,
};

pub async fn run_grpc_client(state: Arc<AppState>) {
    let panel = &state.config.panel;
    if panel.grpc_addr.is_empty() {
        info!("grpc: no grpc_addr configured, skipping");
        return;
    }

    info!("grpc: target {}", panel.grpc_addr);
    let mut backoff = 5u64;

    loop {
        match connect_and_stream(&state).await {
            Ok(()) => {
                info!("grpc: stream ended, reconnecting...");
                backoff = 5;
            }
            Err(e) => {
                warn!("grpc: {e:#}");
            }
        }
        info!("grpc: retry in {backoff}s");
        tokio::time::sleep(Duration::from_secs(backoff)).await;
        backoff = (backoff * 2).min(60);
    }
}

async fn connect_and_stream(state: &Arc<AppState>) -> anyhow::Result<()> {
    let panel = &state.config.panel;
    let addr = &panel.grpc_addr;

    let (url, use_tls) = if addr.starts_with("https://") {
        (addr.clone(), true)
    } else if addr.starts_with("http://") {
        (addr.clone(), false)
    } else {
        (format!("https://{}", addr), true)
    };

    let mut ep = Channel::from_shared(url)?
        .connect_timeout(Duration::from_secs(10));
    if use_tls {
        let mut tls = ClientTlsConfig::new();
        for path in &[
            "/etc/ssl/certs/ca-certificates.crt",
            "/etc/pki/tls/certs/ca-bundle.crt",
        ] {
            if let Ok(pem) = std::fs::read(path) {
                if !pem.is_empty() {
                    tls = tls.ca_certificate(tonic::transport::Certificate::from_pem(pem));
                    break;
                }
            }
        }
        ep = ep.tls_config(tls)?;
    }
    let channel = ep.connect().await?;

    let mut client = AgentServiceClient::new(channel);
    info!("grpc: connected");

    // 1. Register
    let reg = client
        .register(RegisterRequest {
            node_id: panel.node_id as u32,
            token: panel.token.clone(),
            node_type: panel.node_type.clone(),
            hostname: get_hostname(),
            version: env!("CARGO_PKG_VERSION").into(),
        })
        .await?
        .into_inner();

    if !reg.ok {
        anyhow::bail!("register rejected: {}", reg.message);
    }
    let group_id = reg.group_id;
    info!("grpc: registered (group={})", group_id);

    // 2. Report IPs
    let target = state.unlock_ip.load();
    if let Some(ipv4) = target.ipv4 {
        let _ = client
            .report_i_ps(ReportIPsRequest {
                node_id: panel.node_id as u32,
                token: panel.token.clone(),
                ipv4: ipv4.to_string(),
                ipv6: String::new(),
            })
            .await;
    }

    // 3. Bidirectional stream
    let (tx, rx) = mpsc::channel::<AgentMessage>(32);

    tx.send(AgentMessage {
        payload: Some(agent_message::Payload::Auth(AgentAuth {
            node_id: panel.node_id as u32,
            token: panel.token.clone(),
            node_type: panel.node_type.clone(),
            group_id,
        })),
    })
    .await?;

    let response = client.connect(ReceiverStream::new(rx)).await?;
    let mut inbound = response.into_inner();

    // Wait for auth ack
    match inbound.message().await? {
        Some(msg) => match msg.payload {
            Some(server_message::Payload::Ack(ack)) => {
                if !ack.ok {
                    anyhow::bail!("stream auth rejected: {}", ack.message);
                }
                info!("grpc: stream authenticated");
            }
            _ => anyhow::bail!("expected ack after auth"),
        },
        None => anyhow::bail!("stream closed before ack"),
    }

    // Heartbeat sender
    let hb_state = state.clone();
    let cmd_tx = tx.clone();
    let hb_tx = tx;
    let interval = Duration::from_secs(panel.heartbeat_secs.max(10));

    let hb_handle = tokio::spawn(async move {
        loop {
            tokio::time::sleep(interval).await;

            let snap = hb_state.stats.snapshot();
            let msg = AgentMessage {
                payload: Some(agent_message::Payload::Heartbeat(AgentHeartbeat {
                    dns_queries: snap.dns_queries,
                    dns_matched: snap.dns_matched,
                    sni_connections: snap.sni_connections,
                    uptime_secs: snap.uptime_secs,
                    config_hash: String::new(),
                })),
            };
            if hb_tx.send(msg).await.is_err() {
                break;
            }

            let target = hb_state.unlock_ip.load();
            if let Some(ipv4) = target.ipv4 {
                let ip_msg = AgentMessage {
                    payload: Some(agent_message::Payload::IpReport(AgentIpReport {
                        ipv4: ipv4.to_string(),
                        ipv6: String::new(),
                    })),
                };
                if hb_tx.send(ip_msg).await.is_err() {
                    break;
                }
            }
        }
    });

    // Receive loop
    while let Some(msg) = inbound.message().await? {
        match msg.payload {
            Some(server_message::Payload::Config(cfg)) => {
                apply_config_push(state, &cfg);
            }
            Some(server_message::Payload::Command(cmd)) => {
                handle_command(state, &cmd, cmd_tx.clone());
            }
            Some(server_message::Payload::Ack(_)) => {}
            None => {}
        }
    }

    hb_handle.abort();
    Ok(())
}

fn apply_config_push(state: &Arc<AppState>, cfg: &pb::ConfigPush) {
    info!(
        "grpc: config push (sources={} blacklist={})",
        cfg.sources.len(),
        cfg.blacklist.len()
    );

    if !cfg.sources.is_empty() {
        let entries: Vec<SourceEntry> = cfg
            .sources
            .iter()
            .map(|addr| SourceEntry {
                addr: addr.clone(),
                note: String::new(),
                is_domain: addr.parse::<std::net::IpAddr>().is_err(),
                resolved: Vec::new(),
            })
            .collect();

        let mut list = SourceList {
            entries,
            ip_set: Default::default(),
        };
        list.rebuild_set();
        let _ = list.save(&state.config.sources_path());
        state.sources.store(Arc::new(list));
    }

    if !cfg.dns_json.is_empty() {
        let entries = parse_dns_json_to_rules(&cfg.dns_json);
        if !entries.is_empty() {
            let count = entries.len();
            let mut set = crate::rules::RuleSet::from_entries(entries);
            set.rebuild();
            state.rules.store(Arc::new(set));
            info!("grpc: rules updated ({count} entries)");
        }

        // Only transit nodes use the forward map; unlock servers return their own IP
        if state.config.panel.node_type != "unlock" {
            let fwd_map = crate::state::DnsForwardMap::from_dns_json(&cfg.dns_json);
            if !fwd_map.is_empty() {
                info!("grpc: dns forward map loaded ({} domains)", fwd_map.entry_count());
                state.dns_forward_map.store(Arc::new(fwd_map));
            }
        }

        let dir = &state.config.data.dns_json_dir;
        let _ = std::fs::create_dir_all(dir);
        let path = dir.join("dns.json");
        if let Err(e) = std::fs::write(&path, &cfg.dns_json) {
            warn!("grpc: failed to write {}: {e}", path.display());
        } else {
            info!("grpc: wrote {}", path.display());
        }

        if state.config.panel.node_type != "unlock" {
            let local_ip = state.config.local_dns_ip();
            crate::sysdns::apply(&[&local_ip]);
        }
    }
}

fn handle_command(state: &Arc<AppState>, cmd: &pb::ServerCommand, tx: mpsc::Sender<AgentMessage>) {
    info!("grpc: command '{}'", cmd.action);
    match cmd.action.as_str() {
        "reload" => {
            crate::reload_rules(state);
        }
        "restart" => {
            warn!("grpc: restart — exiting");
            std::process::exit(0);
        }
        "run_ut" => {
            let flags = cmd.data.clone();
            tokio::spawn(async move {
                info!("grpc: running ut {}", flags);
                let output = run_ut(&flags).await;
                let ok = !output.contains("Failed to run ut");
                let msg = AgentMessage {
                    payload: Some(agent_message::Payload::Result(CommandResult {
                        action: "run_ut".into(),
                        output,
                        ok,
                    })),
                };
                let _ = tx.send(msg).await;
            });
        }
        "set_dns" => {
            if state.config.panel.node_type == "unlock" {
                warn!("grpc: ignoring set_dns on unlock server");
            } else {
                let servers: Vec<&str> = cmd.data.split_whitespace().collect();
                if servers.is_empty() {
                    warn!("grpc: set_dns with no servers");
                } else {
                    crate::sysdns::apply(&servers);
                    let data = cmd.data.clone();
                    let tx = tx.clone();
                    tokio::spawn(async move {
                        let msg = AgentMessage {
                            payload: Some(agent_message::Payload::Result(CommandResult {
                                action: "set_dns".into(),
                                output: format!("system DNS set to: {data}"),
                                ok: true,
                            })),
                        };
                        let _ = tx.send(msg).await;
                    });
                }
            }
        }
        _ => warn!("grpc: unknown command '{}'", cmd.action),
    }
}

fn find_ut() -> String {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let local = dir.join("ut");
            if local.exists() { return local.to_string_lossy().into_owned(); }
        }
    }
    "ut".into()
}

async fn run_ut(flags: &str) -> String {
    use tokio::process::Command;

    let ut_bin = find_ut();
    let cmd_str = format!("{} {}", ut_bin, flags);
    match Command::new("sh")
        .args(["-c", &cmd_str])
        .env("NO_COLOR", "1")
        .env("TERM", "dumb")
        .output()
        .await
    {
        Ok(o) => {
            let mut out = String::from_utf8_lossy(&o.stdout).to_string();
            let stderr = String::from_utf8_lossy(&o.stderr);
            if !stderr.is_empty() {
                out.push('\n');
                out.push_str(&stderr);
            }
            strip_ansi(&out)
        }
        Err(e) => format!("Failed to run ut: {}", e),
    }
}

fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            if chars.peek() == Some(&'[') {
                chars.next();
                while let Some(&ch) = chars.peek() {
                    chars.next();
                    if ch.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn get_hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "unknown".into())
}

/// Parse dns_json string into RuleEntry list.
/// Supports both nfdns format ({"servers":[...],"tag":"dns_inbound"})
/// and legacy agent-rules format ([{"rule_type":"...","value":"..."}]).
pub fn parse_dns_json_to_rules(raw: &str) -> Vec<crate::rules::RuleEntry> {
    // Try nfdns format first
    if let Ok(obj) = serde_json::from_str::<serde_json::Value>(raw) {
        if let Some(servers) = obj.get("servers").and_then(|v| v.as_array()) {
            let mut entries = Vec::new();
            for srv in servers {
                let domains = match srv.get("domains").and_then(|v| v.as_array()) {
                    Some(d) => d,
                    None => continue, // plain string like "1.1.1.1", skip
                };
                for d in domains {
                    let domain = match d.as_str() {
                        Some(s) => s,
                        None => continue,
                    };
                    if domain.starts_with("geosite:") {
                        continue; // agent has no geosite db
                    }
                    entries.push(crate::rules::RuleEntry {
                        rule_type: "DOMAIN-SUFFIX".into(),
                        value: domain.into(),
                        tag: String::new(),
                    });
                }
            }
            if !entries.is_empty() {
                return entries;
            }
        }
        // Try legacy array format
        if obj.is_array() {
            if let Ok(legacy) = serde_json::from_str::<Vec<crate::rules::RuleEntry>>(raw) {
                return legacy;
            }
        }
    }
    Vec::new()
}

#[allow(dead_code)]
pub fn extract_unlock_ips(raw: &str) -> Vec<String> {
    let mut ips = Vec::new();
    if let Ok(obj) = serde_json::from_str::<serde_json::Value>(raw) {
        if let Some(servers) = obj.get("servers").and_then(|v| v.as_array()) {
            for srv in servers {
                // Only server objects with domains (not plain upstream strings like "1.1.1.1")
                if let Some(addr) = srv.get("address").and_then(|v| v.as_str()) {
                    if srv.get("domains").and_then(|v| v.as_array()).map(|a| !a.is_empty()).unwrap_or(false) {
                        if !ips.contains(&addr.to_string()) {
                            ips.push(addr.to_string());
                        }
                    }
                }
            }
        }
    }
    ips
}
