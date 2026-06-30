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
    AgentAuth, AgentHeartbeat, AgentIpReport, AgentMessage, PullRequest, RegisterRequest,
    ReportIPsRequest,
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

    // 2.5 Pull config over a plain unary RPC. The bidirectional Connect stream below
    // can't traverse some HTTP/2 reverse proxies — nginx grpc_pass silently drops the
    // bidi stream on certain setups (the agent connects + registers, then the stream
    // dies with an h2 protocol error ~60s later and never delivers a push), while unary
    // calls go through fine. So fetch the current config up-front over unary and apply
    // it — that always gets through. The stream below still handles live pushes when it
    // works, and on a bidi-broken proxy the periodic reconnect re-pulls every cycle.
    match client
        .pull_config(PullRequest {
            node_id: panel.node_id as u32,
            token: panel.token.clone(),
            node_type: panel.node_type.clone(),
        })
        .await
    {
        Ok(resp) => {
            let cfg = resp.into_inner();
            info!("grpc: pulled config via unary (dns_json {} bytes)", cfg.dns_json.len());
            apply_config_push(state, &cfg);
        }
        Err(e) => warn!("grpc: pull_config failed: {e}"),
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

        // Re-apply the packet firewall whenever the allow-list actually changes.
        // main() only applies it once at startup, and apply_rules() skips an empty
        // list — which it always is on first boot, before the panel pushes the bound
        // landing IPs. Without re-applying here the relay ports (53/443/80) would stay
        // open to the whole internet until the next restart: exactly the scanner
        // exposure we must avoid. Compare against the live set so the 60s reconnect
        // re-pull doesn't needlessly flush nft rules when nothing actually moved.
        let changed = state.sources.load().ip_set != list.ip_set;
        let _ = list.save(&state.config.sources_path());
        state.sources.store(Arc::new(list));
        if changed {
            reapply_firewall(state);
        }
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

        // Write dns.json where it's actually read: kimir -> /etc/KimiR, xrayr ->
        // /etc/XrayR (for those daemons); unlock母节点 + dns53 -> soho-unlock's own data
        // dir (its self-hosted DNS reads that). dns_json_path() centralizes this so the
        // write path always matches what load_all_rules() reads back.
        let path = state.config.dns_json_path();
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        // Only write + restart the consumer when the dns.json content actually changed.
        // apply_config_push runs on every 60s reconnect re-pull, so writing and
        // restarting unconditionally would bounce KimiR/XrayR every minute and drop all
        // user connections. unwrap_or(true): if the file can't be read (first run),
        // treat it as changed so we always write the initial copy.
        let dns_changed = std::fs::read_to_string(&path)
            .map(|cur| cur != cfg.dns_json)
            .unwrap_or(true);
        if dns_changed {
            if let Err(e) = std::fs::write(&path, &cfg.dns_json) {
                warn!("grpc: failed to write {}: {e}", path.display());
            } else {
                info!("grpc: wrote {}", path.display());
                // KimiR/XrayR only read their dns.json at startup, so freshly-added
                // unlock domains don't take effect until the daemon is restarted.
                // (dns53/母节点 use soho-unlock's own in-process DNS, hot-reloaded above
                // via state.rules.store — no external restart needed there.)
                restart_unlock_consumer(state);
            }
        }

        // No system-DNS repointing anywhere: landing nodes are all kimir/xrayr
        // proxy-only (KimiR/XrayR own DNS), and the 母节点 keeps the host resolver. The
        // old dns53 path that rewrote resolv.conf is gone.
    }
}

/// Re-lock the relay ports to the current whitelist after a config push changes it.
/// On the unlock 母节点 this is mandatory (firewall_active() forces it) — it's what
/// keeps the DNS port (dns_port → 10053), :443 and :80 reachable only by the bound
/// landing nodes and invisible to scanners. MUST use the same dns_port() as main()'s
/// startup apply, or a config push re-locks the wrong port and leaves :10053 (an
/// open-resolver-capable DNS) exposed. Empty whitelist → fail-open by apply_rules().
fn reapply_firewall(state: &Arc<AppState>) {
    if !state.config.firewall_active() {
        return;
    }
    let backend = crate::firewall::detect_backend(&state.config.firewall.backend);
    if backend == crate::firewall::FwBackend::None {
        return;
    }
    let ports = state.config.firewall_ports();
    crate::firewall::apply_rules(state, backend, &ports);
    info!(
        "grpc: firewall re-applied after whitelist change ({} allowed IPs, ports {:?})",
        state.sources.load().ip_set.len(),
        ports
    );
}

/// Restart the unlock consumer daemon after its dns.json changed, so it reloads the new
/// unlock domains. KimiR/XrayR only read dns.json at startup. Only fires on proxy-only
/// (kimir/xrayr) nodes — the unlock母节点 and dns53 nodes run soho-unlock's own DNS,
/// which hot-reloads rules in-process. Runs detached so it never blocks the gRPC loop.
fn restart_unlock_consumer(state: &Arc<AppState>) {
    if !state.config.panel.is_proxy_only() {
        return;
    }
    let svc = match state.config.panel.deploy_mode.as_str() {
        "kimir" => "kimir",
        "xrayr" => "xrayr",
        _ => return,
    }
    .to_string();
    std::thread::spawn(move || {
        match std::process::Command::new(&svc).arg("restart").output() {
            Ok(o) if o.status.success() => {
                info!("grpc: restarted {svc} to apply new dns.json")
            }
            Ok(o) => warn!(
                "grpc: '{svc} restart' exited {:?}: {}",
                o.status.code(),
                String::from_utf8_lossy(&o.stderr).trim()
            ),
            Err(e) => warn!("grpc: failed to run '{svc} restart' (is it in PATH?): {e}"),
        }
    });
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
            if state.config.panel.node_type == "unlock" || state.config.panel.is_proxy_only() {
                warn!("grpc: ignoring set_dns on unlock / proxy-only (kimir/xrayr) node");
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
        "upgrade" => {
            let version = if cmd.data.trim().is_empty() { "latest".to_string() } else { cmd.data.trim().to_string() };
            info!("grpc: self-upgrade to {} requested", version);
            // Drop in a public resolver before the download: we point resolv.conf
            // at our own 127.0.0.1 DNS, which goes down while we restart, and some
            // hosts block outbound UDP/53. The new binary re-applies DNS on start.
            let script = format!(
                "chattr -i /etc/resolv.conf 2>/dev/null || true; \
                 getent hosts raw.githubusercontent.com >/dev/null 2>&1 || \
                 printf 'nameserver 1.1.1.1\\nnameserver 8.8.8.8\\noptions use-vc\\n' > /etc/resolv.conf; \
                 curl -fsSL https://raw.githubusercontent.com/Sysrous/soho-unlock/master/install.sh | bash -s -- upgrade {}",
                version
            );
            let tx = tx.clone();
            tokio::spawn(async move {
                // Run detached in its own cgroup (systemd-run) so the upgrade's
                // 'systemctl stop soho-unlock' doesn't kill the upgrader with us;
                // fall back to setsid where systemd-run is unavailable.
                let started = std::process::Command::new("systemd-run")
                    .args(["--collect", "--unit", "soho-self-upgrade", "sh", "-c"])
                    .arg(script.as_str())
                    .spawn()
                    .or_else(|_| {
                        std::process::Command::new("setsid")
                            .args(["sh", "-c"])
                            .arg(script.as_str())
                            .spawn()
                    })
                    .is_ok();
                let msg = AgentMessage {
                    payload: Some(agent_message::Payload::Result(CommandResult {
                        action: "upgrade".into(),
                        output: if started {
                            format!("upgrade to {version} started")
                        } else {
                            "failed to launch upgrader".into()
                        },
                        ok: started,
                    })),
                };
                let _ = tx.send(msg).await;
            });
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
                // expectedIPs → IP-CIDR/IP-CIDR6 规则:媒体走裸 IP、无域名时,母节点中继靠这些段
                // 放行并直连(配合 KimiR 把命中段的裸 IP 重定向过来)。geoip:* 需 geo 库,跳过。
                if let Some(eips) = srv.get("expectedIPs").and_then(|v| v.as_array()) {
                    for ip in eips {
                        let Some(s) = ip.as_str() else { continue };
                        let s = s.trim();
                        if s.is_empty() || s.starts_with("geoip:") {
                            continue;
                        }
                        let cidr = if s.contains('/') {
                            s.to_string()
                        } else if s.contains(':') {
                            format!("{s}/128")
                        } else {
                            format!("{s}/32")
                        };
                        let rtype = if cidr.contains(':') { "IP-CIDR6" } else { "IP-CIDR" };
                        entries.push(crate::rules::RuleEntry {
                            rule_type: rtype.into(),
                            value: cidr,
                            tag: String::new(),
                        });
                    }
                }
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
