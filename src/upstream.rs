use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use tracing::{info, warn};

use crate::state::{AppState, SourceEntry, SourceList};

pub async fn run_upstream(state: Arc<AppState>) {
    let panel = &state.config.panel;
    if panel.url.is_empty() || panel.node_id == 0 || panel.token.is_empty() {
        info!("upstream: panel not configured, skipping");
        return;
    }

    info!(
        "upstream: connecting to panel {} as node {}",
        panel.url, panel.node_id
    );

    if let Err(e) = register(&state).await {
        warn!("upstream: initial register failed: {e}");
    }

    let hb_state = state.clone();
    tokio::spawn(async move {
        heartbeat_loop(&hb_state).await;
    });

    // Source-sync loop (unlock servers don't consume dns.json — they produce it;
    // the panel manages topology. But source lists are shared.)
    source_sync_loop(&state).await;
}

async fn register(state: &Arc<AppState>) -> anyhow::Result<()> {
    let panel = &state.config.panel;
    let url = format!("{}/api/agent/register", panel.url.trim_end_matches('/'));
    let hostname = std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_default();

    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .json(&serde_json::json!({
            "node_id": panel.node_id,
            "token": panel.token,
            "type": panel.node_type,
            "hostname": hostname,
        }))
        .send()
        .await?;

    if !resp.status().is_success() {
        anyhow::bail!("register HTTP {}", resp.status());
    }
    info!("upstream: registered with panel");
    Ok(())
}

async fn heartbeat_loop(state: &Arc<AppState>) {
    let panel = &state.config.panel;
    let url = format!("{}/api/agent/heartbeat", panel.url.trim_end_matches('/'));
    let ip_url = format!("{}/api/agent/report-ips", panel.url.trim_end_matches('/'));
    let client = reqwest::Client::new();
    let interval = Duration::from_secs(panel.heartbeat_secs.max(10));

    loop {
        tokio::time::sleep(interval).await;

        let snap = state.stats.snapshot();

        let body = serde_json::json!({
            "node_id": panel.node_id,
            "token": panel.token,
            "type": panel.node_type,
            "dns_queries": snap.dns_queries,
            "dns_matched": snap.dns_matched,
            "sni_connections": snap.sni_connections,
            "uptime_secs": snap.uptime_secs,
        });

        match client.post(&url).json(&body).send().await {
            Ok(resp) if resp.status().is_success() => {}
            Ok(resp) => warn!("upstream: heartbeat HTTP {}", resp.status()),
            Err(e) => warn!("upstream: heartbeat error: {e}"),
        }

        let target = state.unlock_ip.load();
        if let Some(ipv4) = target.ipv4 {
            let _ = client
                .post(&ip_url)
                .json(&serde_json::json!({
                    "node_id": panel.node_id,
                    "token": panel.token,
                    "ipv4": ipv4.to_string(),
                }))
                .send()
                .await;
        }
    }
}

async fn source_sync_loop(state: &Arc<AppState>) {
    let panel = &state.config.panel;
    let sources_url = format!(
        "{}/api/agent/sources?node_id={}&token={}",
        panel.url.trim_end_matches('/'),
        panel.node_id,
        panel.token
    );
    let client = reqwest::Client::new();
    let interval = Duration::from_secs(panel.heartbeat_secs.max(10) * 2);

    loop {
        tokio::time::sleep(interval).await;

        match client.get(&sources_url).send().await {
            Ok(resp) if resp.status().is_success() => {
                if let Ok(sources) = resp.json::<Vec<PanelSource>>().await {
                    apply_sources(state, &sources);
                }
            }
            Ok(resp) => warn!("upstream: sources HTTP {}", resp.status()),
            Err(e) => warn!("upstream: sources fetch error: {e}"),
        }
    }
}

#[derive(Deserialize)]
struct PanelSource {
    addr: String,
    #[serde(default)]
    note: String,
    #[serde(default)]
    is_domain: bool,
}

fn apply_sources(state: &Arc<AppState>, panel_sources: &[PanelSource]) {
    let current = state.sources.load();
    let current_addrs: std::collections::HashSet<&str> =
        current.entries.iter().map(|e| e.addr.as_str()).collect();
    let panel_addrs: std::collections::HashSet<&str> =
        panel_sources.iter().map(|s| s.addr.as_str()).collect();

    if current_addrs == panel_addrs {
        return;
    }

    info!(
        "upstream: source list changed ({} -> {})",
        current.entries.len(),
        panel_sources.len()
    );

    let entries: Vec<SourceEntry> = panel_sources
        .iter()
        .map(|s| SourceEntry {
            addr: s.addr.clone(),
            note: s.note.clone(),
            is_domain: s.is_domain,
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
