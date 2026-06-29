mod config;
mod dns;
mod export;
mod firewall;
mod grpc_client;
mod panel;
mod rules;
mod service;
mod sni;
mod state;
mod sysdns;
use clap::Parser;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::info;

#[derive(Parser)]
#[command(name = "soho-unlock", version, about = "DNS unlock agent with SNI proxy")]
struct Cli {
    #[arg(short, long, default_value = "/etc/soho-unlock/config.toml")]
    config: PathBuf,
    #[arg(long)]
    install: bool,
}

#[tokio::main(worker_threads = 2)]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "soho_unlock=info".parse().unwrap()),
        )
        .compact()
        .init();

    let cli = Cli::parse();

    if cli.install {
        return install_service();
    }

    let cfg = config::Config::load(&cli.config)?;
    info!("loaded config from {}", cli.config.display());

    std::fs::create_dir_all(&cfg.data.dir)?;
    std::fs::create_dir_all(cfg.rules_dir())?;
    std::fs::create_dir_all(cfg.export_dir())?;

    let state = state::AppState::new(cfg);

    // kimir / xrayr 落地机：agent 退成纯 dns.json 下发代理（见 PanelConfig::is_proxy_only）。
    let proxy_only = state.config.panel.is_proxy_only();

    // Load rules + dns forward map from persisted dns.json + rules/ directory
    load_all_rules(&state);
    load_dns_forward_map(&state);

    // Fetch IP detect URLs from panel, then resolve unlock target
    let ip_urls = fetch_ip_detect_urls(&state).await;
    resolve_target(&state, &ip_urls).await;

    // Firewall — lock the relay ports to whitelisted source IPs. Mandatory on the
    // unlock 母节点 (firewall_active() forces it there); proxy-only kimir/xrayr nodes
    // don't bind 53/443, so they never firewall them. NOTE: at first boot the whitelist
    // is usually empty, so apply_rules() skips (fail-open) — the gRPC config push then
    // re-applies it the moment the bound landing IPs arrive (see
    // grpc_client::apply_config_push), which is what actually locks the ports down.
    // :80 is only firewalled when explicitly enabled (http_listen set) — off by default.
    let fw_backend = if state.config.firewall_active() {
        let backend = firewall::detect_backend(&state.config.firewall.backend);
        info!("firewall backend: {backend:?}");
        let mut ports = vec![state.config.dns_port(), 443];
        if !state.config.server.http_listen.is_empty() {
            ports.push(80);
        }
        firewall::apply_rules(&state, backend, &ports);
        Some(backend)
    } else {
        None
    };

    info!(
        "unlock target: {} -> {:?}",
        state.config.unlock.target,
        state.unlock_ip.load().ipv4
    );
    info!("rules loaded: {}", state.rules.load().rule_count());
    info!("sources: {}", state.sources.load().entries.len());

    // The local management panel and gRPC control stream run in EVERY mode — a
    // proxy-only transit node still receives dns.json pushes and reports heartbeats.
    {
        let s = state.clone();
        tokio::spawn(async move { panel::run_panel(s).await });
    }
    {
        let s = state.clone();
        tokio::spawn(async move { grpc_client::run_grpc_client(s).await });
    }

    if proxy_only {
        // kimir / xrayr: KimiR/XrayR owns DNS:53 and SNI:443. Don't start our own
        // listeners (they'd fight for the ports) and don't repoint system DNS.
        info!(
            "deploy_mode='{}' → proxy-only agent: not starting DNS/SNI/HTTP listeners, leaving system DNS untouched",
            state.config.panel.deploy_mode
        );
        // Self-heal: an older agent (which didn't know about deploy_mode) may have
        // repointed this host's system DNS on a previous run. Undo that here so the OS
        // / KimiR owns DNS again. cleanup() only removes soho-tagged entries, so it's a
        // harmless no-op on hosts that were never touched.
        sysdns::cleanup();
    } else {
        // Only the 母节点 (node_type=="unlock", the only non-proxy-only node) reaches
        // here: it serves the unlock DNS (UDP + TCP, on dns_port → 10053) and the SNI/
        // HTTP relays. It never repoints the host resolver — the dns53 "own DNS + change
        // system DNS" landing mode is gone; all landing nodes are kimir/xrayr proxy-only.
        let s1 = state.clone();
        let s1t = state.clone();
        let s2 = state.clone();
        let s4 = state.clone();
        tokio::spawn(async move { dns::run_dns_server(s1).await });
        tokio::spawn(async move { dns::run_dns_server_tcp(s1t).await });
        tokio::spawn(async move { sni::run_sni_proxy(s2).await });
        tokio::spawn(async move { sni::run_http_proxy(s4).await });
    }

    // Periodic target re-resolve (for domain targets / IP refresh)
    let s5 = state.clone();
    tokio::spawn(async move {
        let interval = s5.config.unlock.resolve_interval_secs;
        if interval == 0 { return; }
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
            let urls = s5.ip_detect_urls.load();
            resolve_target(&s5, &urls).await;
        }
    });

    // Periodic source domain re-resolve
    let s6 = state.clone();
    tokio::spawn(async move {
        let interval = s6.config.unlock.resolve_interval_secs;
        if interval == 0 { return; }
        // Initial resolve for any domain sources loaded from disk
        state::resolve_all_domains(&s6).await;
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
            state::resolve_all_domains(&s6).await;
        }
    });

    info!("soho-unlock started");

    tokio::signal::ctrl_c().await?;
    info!("shutting down");

    if let Some(backend) = fw_backend {
        firewall::cleanup(backend);
    }
    // Don't cleanup sysdns on stop — DNS settings should persist across restarts

    Ok(())
}

pub fn reload_rules(state: &Arc<state::AppState>) {
    load_all_rules(state);
}

fn load_all_rules(state: &Arc<state::AppState>) {
    let mut all_entries = Vec::new();

    // Load from dns_json_dir/dns.json (persisted from gRPC push)
    let kimir_path = state.config.dns_json_path();
    if kimir_path.exists() {
        if let Ok(text) = std::fs::read_to_string(&kimir_path) {
            let entries = grpc_client::parse_dns_json_to_rules(&text);
            if !entries.is_empty() {
                info!("loaded {} rules from {}", entries.len(), kimir_path.display());
                all_entries.extend(entries);
            }
        }
    }

    // Load from custom_rules.json
    let custom_path = state.config.custom_rules_path();
    if custom_path.exists() {
        if let Ok(text) = std::fs::read_to_string(&custom_path) {
            if let Ok(entries) = serde_json::from_str::<Vec<rules::RuleEntry>>(&text) {
                info!("loaded {} custom rules", entries.len());
                all_entries.extend(entries);
            }
        }
    }

    // Load from rules/ directory
    let rules_dir = state.config.rules_dir();
    if let Ok(dir) = std::fs::read_dir(&rules_dir) {
        for entry in dir.flatten() {
            let path = entry.path();
            if path.extension().map_or(false, |e| {
                e == "list" || e == "txt" || e == "conf" || e == "yaml"
            }) {
                match rules::load_rules_from_file(&path) {
                    Ok(entries) => {
                        info!("loaded {} rules from {}", entries.len(), path.display());
                        all_entries.extend(entries);
                    }
                    Err(e) => tracing::warn!("failed to load {}: {e}", path.display()),
                }
            }
        }
    }

    let mut set = rules::RuleSet::from_entries(all_entries);
    set.rebuild();
    state.rules.store(Arc::new(set));
}

fn load_dns_forward_map(state: &Arc<state::AppState>) {
    // Only transit nodes use the forward map; unlock servers return their own IP
    if state.config.panel.node_type == "unlock" {
        return;
    }
    let path = state.config.dns_json_path();
    if let Ok(text) = std::fs::read_to_string(&path) {
        let fwd_map = state::DnsForwardMap::from_dns_json(&text);
        if !fwd_map.is_empty() {
            info!("dns forward map: {} domains from {}", fwd_map.entry_count(), path.display());
            state.dns_forward_map.store(Arc::new(fwd_map));
        }
    }
}

async fn fetch_ip_detect_urls(state: &Arc<state::AppState>) -> Vec<String> {
    let panel = &state.config.panel;
    if panel.url.is_empty() || panel.node_id == 0 || panel.token.is_empty() {
        return Vec::new();
    }
    let url = format!(
        "{}/api/agent/config?node_id={}&token={}",
        panel.url.trim_end_matches('/'),
        panel.node_id,
        panel.token
    );
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap_or_default();
    match client.get(&url).send().await {
        Ok(resp) if resp.status().is_success() => {
            if let Ok(data) = resp.json::<serde_json::Value>().await {
                if let Some(arr) = data.get("ip_detect_urls").and_then(|v| v.as_array()) {
                    let urls: Vec<String> = arr
                        .iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect();
                    if !urls.is_empty() {
                        info!("panel: got {} IP detect URLs", urls.len());
                        state.ip_detect_urls.store(Arc::new(urls.clone()));
                        return urls;
                    }
                }
            }
        }
        Ok(resp) => tracing::warn!("panel config HTTP {}", resp.status()),
        Err(e) => tracing::warn!("panel config fetch error: {e}"),
    }
    Vec::new()
}

async fn resolve_target(state: &Arc<state::AppState>, panel_urls: &[String]) {
    let raw = &state.config.unlock.target;

    if raw.is_empty() || raw == "0.0.0.0" {
        if let Some(ip) = detect_public_ip(panel_urls).await {
            info!("auto-detected public IP: {ip}");
            state.unlock_ip.store(Arc::new(state::ResolvedTarget {
                ipv4: Some(ip),
                raw: ip.to_string(),
            }));
            return;
        }
        tracing::warn!("failed to auto-detect public IP, keeping {raw}");
        return;
    }

    if let Ok(ip) = raw.parse::<Ipv4Addr>() {
        state.unlock_ip.store(Arc::new(state::ResolvedTarget {
            ipv4: Some(ip),
            raw: raw.clone(),
        }));
        return;
    }
    match tokio::net::lookup_host(format!("{raw}:0")).await {
        Ok(mut addrs) => {
            if let Some(addr) = addrs.find(|a| a.is_ipv4()) {
                if let std::net::IpAddr::V4(v4) = addr.ip() {
                    info!("resolved unlock target {raw} -> {v4}");
                    state.unlock_ip.store(Arc::new(state::ResolvedTarget {
                        ipv4: Some(v4),
                        raw: raw.clone(),
                    }));
                    return;
                }
            }
            tracing::warn!("no IPv4 for unlock target {raw}");
        }
        Err(e) => tracing::warn!("failed to resolve unlock target {raw}: {e}"),
    }
}

async fn detect_public_ip(panel_urls: &[String]) -> Option<Ipv4Addr> {
    let builtins = [
        "https://api.ipify.org",
        "https://ifconfig.me/ip",
        "https://icanhazip.com",
    ];
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .ok()?;
    // Panel-configured URLs first, then built-in fallbacks
    for url in panel_urls.iter().map(|s| s.as_str()).chain(builtins.iter().copied()) {
        if let Ok(resp) = client.get(url).send().await {
            if let Ok(text) = resp.text().await {
                if let Ok(ip) = text.trim().parse::<Ipv4Addr>() {
                    return Some(ip);
                }
            }
        }
    }
    None
}

fn install_service() -> anyhow::Result<()> {
    // Detect init system and install appropriate service file
    if PathBuf::from("/run/systemd/system").exists() {
        install_systemd()?;
    } else if PathBuf::from("/sbin/openrc").exists() || PathBuf::from("/sbin/rc-service").exists() {
        install_openrc()?;
    } else {
        println!("Unknown init system. Manual installation required.");
        println!("Binary: copy soho-unlock to /usr/local/bin/");
        println!("Config: /etc/soho-unlock/config.toml");
    }
    Ok(())
}

fn install_systemd() -> anyhow::Result<()> {
    let unit = r#"[Unit]
Description=Soho Unlock - DNS unlock agent
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/soho-unlock -c /etc/soho-unlock/config.toml
Restart=on-failure
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
"#;
    let path = "/etc/systemd/system/soho-unlock.service";
    std::fs::write(path, unit)?;
    println!("Installed systemd service: {path}");
    println!("  systemctl daemon-reload");
    println!("  systemctl enable --now soho-unlock");
    Ok(())
}

fn install_openrc() -> anyhow::Result<()> {
    let script = r#"#!/sbin/openrc-run
name="soho-unlock"
description="Soho Unlock - DNS unlock agent"
command="/usr/local/bin/soho-unlock"
command_args="-c /etc/soho-unlock/config.toml"
command_background=true
pidfile="/run/${RC_SVCNAME}.pid"
start_stop_daemon_args="--stdout /var/log/soho-unlock.log --stderr /var/log/soho-unlock.log"

depend() {
    need net
    after firewall
}
"#;
    let path = "/etc/init.d/soho-unlock";
    std::fs::write(path, script)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))?;
    }
    println!("Installed OpenRC service: {path}");
    println!("  rc-update add soho-unlock default");
    println!("  rc-service soho-unlock start");
    Ok(())
}
