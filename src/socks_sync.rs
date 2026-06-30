use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};

use crate::state::AppState;

// ── 母节点 side: report auto-generated SOCKS5 creds to the panel ──
// The panel relays them to the landing nodes bound to this 母节点 so their KimiR socks
// outbound can reach it. Runs on startup + every 5 min (panel may restart; the very first
// try can race node creation).
pub async fn report_socks_creds(state: Arc<AppState>) {
    let panel = &state.config.panel;
    if panel.url.is_empty() || panel.node_id == 0 || panel.token.is_empty() {
        return;
    }
    let port = state.config.socks_port();
    let user = state.config.server.socks_user.clone();
    let pass = state.config.server.socks_pass.clone();
    if port == 0 || user.is_empty() {
        return;
    }
    let url = format!("{}/api/agent/report-socks", panel.url.trim_end_matches('/'));
    let body = json!({
        "node_id": panel.node_id,
        "token": panel.token,
        "port": port,
        "user": user,
        "pass": pass,
    });
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap_or_default();
    loop {
        match client.post(&url).json(&body).send().await {
            Ok(r) if r.status().is_success() => info!("reported SOCKS5 creds to panel (port {port})"),
            Ok(r) => warn!("report socks: HTTP {}", r.status()),
            Err(e) => warn!("report socks: {e}"),
        }
        tokio::time::sleep(Duration::from_secs(300)).await;
    }
}

// ── landing side: pull /api/agent/config and write KimiR's socks outbound + route ──
// The panel returns a "socks" array (one entry per 母节点 this landing is bound to). We
// merge them into KimiR's custom_outbound.json + route.json and restart KimiR — only when
// something actually changed, so it's not a restart loop.
pub async fn sync_kimir_socks(state: Arc<AppState>) {
    let panel = &state.config.panel;
    if panel.url.is_empty() || panel.node_id == 0 || panel.token.is_empty() {
        return;
    }
    if state.config.panel.deploy_mode != "kimir" {
        return; // only kimir landings own /etc/KimiR
    }
    // KimiR config dir = the dir we already write dns.json into (/etc/KimiR for kimir mode).
    let kimir_dir = state
        .config
        .dns_json_path()
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("/etc/KimiR"));

    let url = format!(
        "{}/api/agent/config?node_id={}&token={}",
        panel.url.trim_end_matches('/'),
        panel.node_id,
        panel.token
    );
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap_or_default();
    loop {
        if let Ok(resp) = client.get(&url).send().await {
            if let Ok(v) = resp.json::<Value>().await {
                let empty = Vec::new();
                let socks = v.get("socks").and_then(|s| s.as_array()).unwrap_or(&empty);
                if let Err(e) = apply_kimir_socks(&kimir_dir, socks) {
                    debug!("apply kimir socks: {e}");
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(60)).await;
    }
}

// Merge the agent-managed socks outbounds + ip-route rules into KimiR's config, idempotently.
// Agent-managed entries are tagged "usk-*"; we drop the old ones and add the current set, so
// removing a binding cleans up too. Writes + restarts KimiR only on an actual change.
fn apply_kimir_socks(dir: &std::path::Path, socks: &[Value]) -> anyhow::Result<()> {
    let out_path = dir.join("custom_outbound.json");
    let route_path = dir.join("route.json");

    let old_out: Value = std::fs::read_to_string(&out_path)
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_else(|| Value::Array(vec![]));
    let old_route: Value = std::fs::read_to_string(&route_path)
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_else(|| json!({ "rules": [] }));

    // outbounds: keep everything that isn't agent-managed, then add the current usk- set.
    let mut outbounds: Vec<Value> = old_out.as_array().cloned().unwrap_or_default();
    outbounds.retain(|o| !is_usk(o.get("tag")));

    // route rules: same, then insert the new usk- rules before the IPv4_out catch-all.
    let mut route = old_route.clone();
    let mut rules: Vec<Value> = route
        .get("rules")
        .and_then(|r| r.as_array())
        .cloned()
        .unwrap_or_default();
    rules.retain(|r| !is_usk(r.get("outboundTag")));

    let mut new_rules: Vec<Value> = Vec::new();
    for e in socks {
        let host = e.get("host").and_then(|v| v.as_str()).unwrap_or("");
        let port = e.get("port").and_then(|v| v.as_u64()).unwrap_or(0);
        let user = e.get("user").and_then(|v| v.as_str()).unwrap_or("");
        let pass = e.get("pass").and_then(|v| v.as_str()).unwrap_or("");
        let cidrs = e
            .get("cidrs")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        if host.is_empty() || port == 0 || user.is_empty() || cidrs.is_empty() {
            continue;
        }
        let tag = format!("usk-{}", host.replace('.', "_").replace(':', "_"));
        outbounds.push(json!({
            "tag": tag,
            "protocol": "socks",
            "settings": { "servers": [{
                "address": host,
                "port": port,
                "users": [{ "user": user, "pass": pass }]
            }]}
        }));
        new_rules.push(json!({ "type": "field", "outboundTag": tag, "ip": cidrs }));
    }

    let insert_at = rules
        .iter()
        .position(|r| r.get("outboundTag").and_then(|t| t.as_str()) == Some("IPv4_out"))
        .unwrap_or(rules.len());
    for (i, r) in new_rules.into_iter().enumerate() {
        rules.insert(insert_at + i, r);
    }
    route["rules"] = Value::Array(rules);
    let new_out = Value::Array(outbounds);

    // No-op if nothing changed (semantic compare — ignores formatting), so no restart loop.
    if old_out == new_out && old_route == route {
        return Ok(());
    }

    std::fs::write(&out_path, serde_json::to_string_pretty(&new_out)?)?;
    std::fs::write(&route_path, serde_json::to_string_pretty(&route)?)?;
    let _ = std::process::Command::new("kimir").arg("restart").output();
    info!("applied {} SOCKS5 relay(s) to KimiR + restarted", socks.len());
    Ok(())
}

fn is_usk(tag: Option<&Value>) -> bool {
    tag.and_then(|t| t.as_str())
        .map_or(false, |t| t.starts_with("usk-"))
}
