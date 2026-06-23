use std::sync::Arc;

use crate::rules::{classify_pattern, to_plain_domain, to_xray_domain, RuleEntry};
use crate::state::AppState;

pub struct ExportResult {
    pub dns_json: String,
    pub route_json: String,
    pub dns_hash: String,
    pub route_hash: String,
}

pub fn generate(state: &Arc<AppState>) -> ExportResult {
    let services = state.services.load();
    let unlock_ip = state.unlock_ip.load();
    let target_ip = unlock_ip
        .ipv4
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| unlock_ip.raw.clone());

    let mut domain_entries: Vec<RuleEntry> = Vec::new();
    let mut cidr_entries: Vec<RuleEntry> = Vec::new();
    let mut geosite_tags: Vec<String> = Vec::new();
    let mut geoip_tags: Vec<String> = Vec::new();

    for svc in services.services.iter().filter(|s| s.enabled) {
        for d in &svc.domains {
            if let Some(entry) = classify_pattern(d) {
                domain_entries.push(entry);
            }
        }
        for c in &svc.cidrs {
            if let Some(entry) = classify_pattern(c) {
                cidr_entries.push(entry);
            }
        }
        if !svc.geosite.is_empty() {
            let tag = format!("geosite:{}", svc.geosite);
            if !geosite_tags.contains(&tag) {
                geosite_tags.push(tag);
            }
        }
        if !svc.geoip.is_empty() {
            let tag = format!("geoip:{}", svc.geoip);
            if !geoip_tags.contains(&tag) {
                geoip_tags.push(tag);
            }
        }
    }

    // ── dns.json (nfdns plain-domain format) ──
    let plain_domains: Vec<String> = domain_entries.iter().map(to_plain_domain).collect();

    let dns_json = if plain_domains.is_empty() && geosite_tags.is_empty() {
        serde_json::json!({
            "servers": ["1.1.1.1", "8.8.8.8"],
            "tag": "dns_inbound"
        })
    } else {
        let mut unlock_domains: Vec<serde_json::Value> = Vec::new();
        for g in &geosite_tags {
            unlock_domains.push(serde_json::Value::String(g.clone()));
        }
        for d in &plain_domains {
            unlock_domains.push(serde_json::Value::String(d.clone()));
        }

        serde_json::json!({
            "servers": [
                {
                    "address": target_ip,
                    "port": 53,
                    "domains": unlock_domains
                },
                "1.1.1.1",
                "8.8.8.8"
            ],
            "tag": "dns_inbound"
        })
    };

    // ── route.json (Xray format) ──
    let xray_domains: Vec<String> = domain_entries.iter().map(to_xray_domain).collect();
    let mut route_rules: Vec<serde_json::Value> = Vec::new();

    // Unlock domain rule
    let mut unlock_route_domains: Vec<String> = xray_domains.clone();
    for g in &geosite_tags {
        unlock_route_domains.push(g.clone());
    }
    if !unlock_route_domains.is_empty() {
        route_rules.push(serde_json::json!({
            "type": "field",
            "outboundTag": "unlock",
            "domain": unlock_route_domains
        }));
    }

    // Unlock IP rule
    let mut unlock_route_ips: Vec<String> = Vec::new();
    for entry in &cidr_entries {
        unlock_route_ips.push(entry.value.clone());
    }
    for g in &geoip_tags {
        unlock_route_ips.push(g.clone());
    }
    if !unlock_route_ips.is_empty() {
        route_rules.push(serde_json::json!({
            "type": "field",
            "outboundTag": "unlock",
            "ip": unlock_route_ips
        }));
    }

    // Default outbound
    route_rules.push(serde_json::json!({
        "type": "field",
        "outboundTag": "IPv4_out",
        "network": "tcp,udp"
    }));

    let route_json = serde_json::json!({
        "domainStrategy": "IPIfNonMatch",
        "rules": route_rules
    });

    let dns_str = serde_json::to_string_pretty(&dns_json).unwrap_or_default();
    let route_str = serde_json::to_string_pretty(&route_json).unwrap_or_default();

    let dns_hash = simple_hash(&dns_str);
    let route_hash = simple_hash(&route_str);

    ExportResult {
        dns_json: dns_str,
        route_json: route_str,
        dns_hash,
        route_hash,
    }
}

fn simple_hash(s: &str) -> String {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("{h:016x}")
}
