use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::config::Config;
use crate::rules::RuleSet;
use crate::service::ServiceList;

pub struct AppState {
    pub config: Config,
    pub rules: ArcSwap<RuleSet>,
    pub sources: ArcSwap<SourceList>,
    pub services: ArcSwap<ServiceList>,
    pub unlock_ip: ArcSwap<ResolvedTarget>,
    pub ip_detect_urls: ArcSwap<Vec<String>>,
    pub dns_forward_map: ArcSwap<DnsForwardMap>,
    pub stats: Stats,
}

pub struct DnsForwardMap {
    entries: Vec<ForwardEntry>,
}

struct ForwardEntry {
    domains: Vec<String>,
    addr: SocketAddr,
}

impl Default for DnsForwardMap {
    fn default() -> Self { Self { entries: Vec::new() } }
}

impl DnsForwardMap {
    pub fn from_dns_json(raw: &str) -> Self {
        let mut entries = Vec::new();
        if let Ok(obj) = serde_json::from_str::<serde_json::Value>(raw) {
            if let Some(servers) = obj.get("servers").and_then(|v| v.as_array()) {
                for srv in servers {
                    let addr_str = match srv.get("address").and_then(|v| v.as_str()) {
                        Some(a) => a,
                        None => continue,
                    };
                    let port = srv.get("port").and_then(|v| v.as_u64()).unwrap_or(53) as u16;
                    let domains = match srv.get("domains").and_then(|v| v.as_array()) {
                        Some(d) if !d.is_empty() => d,
                        _ => continue,
                    };
                    let domain_list: Vec<String> = domains
                        .iter()
                        .filter_map(|v| v.as_str())
                        .filter(|s| !s.starts_with("geosite:"))
                        .map(|s| s.to_lowercase())
                        .collect();
                    if domain_list.is_empty() { continue; }
                    if let Ok(addr) = format!("{}:{}", addr_str, port).parse::<SocketAddr>() {
                        entries.push(ForwardEntry { domains: domain_list, addr });
                    }
                }
            }
        }
        Self { entries }
    }

    pub fn lookup(&self, domain: &str) -> Option<SocketAddr> {
        let domain = domain.to_lowercase();
        for entry in &self.entries {
            for d in &entry.domains {
                if domain == *d || domain.ends_with(&format!(".{}", d)) {
                    return Some(entry.addr);
                }
            }
        }
        None
    }

    pub fn is_empty(&self) -> bool { self.entries.is_empty() }
    pub fn entry_count(&self) -> usize { self.entries.len() }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceEntry {
    pub addr: String,
    #[serde(default)]
    pub note: String,
    #[serde(default)]
    pub is_domain: bool,
    #[serde(default)]
    pub resolved: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SourceList {
    pub entries: Vec<SourceEntry>,
    #[serde(skip)]
    pub ip_set: HashSet<IpAddr>,
}

impl SourceList {
    pub fn rebuild_set(&mut self) {
        self.ip_set.clear();
        for entry in &self.entries {
            if entry.is_domain {
                for ip_str in &entry.resolved {
                    if let Ok(ip) = ip_str.parse::<IpAddr>() {
                        self.ip_set.insert(ip);
                    }
                }
            } else if let Ok(ip) = entry.addr.parse::<IpAddr>() {
                self.ip_set.insert(ip);
            }
        }
    }

    pub fn contains(&self, ip: &IpAddr) -> bool {
        self.ip_set.contains(ip)
    }

    pub fn load(path: &Path) -> Self {
        let mut list: SourceList = std::fs::read_to_string(path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        list.rebuild_set();
        list
    }

    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(&self.entries)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    pub fn has_domains(&self) -> bool {
        self.entries.iter().any(|e| e.is_domain)
    }
}

pub fn parse_source_line(line: &str) -> Option<SourceEntry> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let (addr, note) = match line.split_once(|c: char| c == ' ' || c == '\t' || c == ',') {
        Some((a, n)) => (a.trim(), n.trim().to_string()),
        None => (line, String::new()),
    };
    if addr.is_empty() {
        return None;
    }
    let is_domain = addr.parse::<IpAddr>().is_err();
    Some(SourceEntry {
        addr: addr.to_string(),
        note,
        is_domain,
        resolved: Vec::new(),
    })
}

pub async fn resolve_source_entry(entry: &mut SourceEntry) {
    if !entry.is_domain {
        return;
    }
    match tokio::net::lookup_host(format!("{}:0", entry.addr)).await {
        Ok(addrs) => {
            let ips: Vec<String> = addrs
                .filter(|a| a.is_ipv4())
                .map(|a| a.ip().to_string())
                .collect();
            if !ips.is_empty() {
                entry.resolved = ips;
            }
        }
        Err(e) => {
            tracing::warn!("source resolve failed {}: {e}", entry.addr);
        }
    }
}

pub async fn resolve_all_domains(state: &Arc<AppState>) {
    let guard = state.sources.load();
    let mut list = SourceList::clone(&**guard);
    drop(guard);

    if !list.has_domains() {
        return;
    }

    let mut changed = false;
    for entry in &mut list.entries {
        if !entry.is_domain {
            continue;
        }
        let old = entry.resolved.clone();
        resolve_source_entry(entry).await;
        if entry.resolved != old {
            changed = true;
            tracing::info!(
                "source re-resolved {} -> {:?}",
                entry.addr,
                entry.resolved
            );
        }
    }

    if changed {
        list.rebuild_set();
        let _ = list.save(&state.config.sources_path());
        state.sources.store(Arc::new(list));
    }
}

#[derive(Debug)]
pub struct ResolvedTarget {
    pub ipv4: Option<Ipv4Addr>,
    pub raw: String,
}

pub struct Stats {
    pub dns_queries: AtomicU64,
    pub dns_matched: AtomicU64,
    pub dns_forwarded: AtomicU64,
    pub dns_blocked: AtomicU64,
    pub sni_connections: AtomicU64,
    pub sni_relayed: AtomicU64,
    pub sni_blocked: AtomicU64,
    pub started_at: std::time::Instant,
}

impl Stats {
    pub fn new() -> Self {
        Self {
            dns_queries: AtomicU64::new(0),
            dns_matched: AtomicU64::new(0),
            dns_forwarded: AtomicU64::new(0),
            dns_blocked: AtomicU64::new(0),
            sni_connections: AtomicU64::new(0),
            sni_relayed: AtomicU64::new(0),
            sni_blocked: AtomicU64::new(0),
            started_at: std::time::Instant::now(),
        }
    }

    pub fn snapshot(&self) -> StatsSnapshot {
        StatsSnapshot {
            dns_queries: self.dns_queries.load(Ordering::Relaxed),
            dns_matched: self.dns_matched.load(Ordering::Relaxed),
            dns_forwarded: self.dns_forwarded.load(Ordering::Relaxed),
            dns_blocked: self.dns_blocked.load(Ordering::Relaxed),
            sni_connections: self.sni_connections.load(Ordering::Relaxed),
            sni_relayed: self.sni_relayed.load(Ordering::Relaxed),
            sni_blocked: self.sni_blocked.load(Ordering::Relaxed),
            uptime_secs: self.started_at.elapsed().as_secs(),
        }
    }
}

#[derive(Serialize)]
pub struct StatsSnapshot {
    pub dns_queries: u64,
    pub dns_matched: u64,
    pub dns_forwarded: u64,
    pub dns_blocked: u64,
    pub sni_connections: u64,
    pub sni_relayed: u64,
    pub sni_blocked: u64,
    pub uptime_secs: u64,
}

impl AppState {
    pub fn new(config: Config) -> Arc<Self> {
        let sources = SourceList::load(&config.sources_path());
        let services = ServiceList::load(&config.services_path());
        let target = ResolvedTarget {
            ipv4: config.unlock.target.parse().ok(),
            raw: config.unlock.target.clone(),
        };
        Arc::new(Self {
            config,
            rules: ArcSwap::from_pointee(RuleSet::default()),
            sources: ArcSwap::from_pointee(sources),
            services: ArcSwap::from_pointee(services),
            unlock_ip: ArcSwap::from_pointee(target),
            ip_detect_urls: ArcSwap::from_pointee(Vec::new()),
            dns_forward_map: ArcSwap::from_pointee(DnsForwardMap::default()),
            stats: Stats::new(),
        })
    }

    pub fn is_source_allowed(&self, ip: &IpAddr) -> bool {
        let sources = self.sources.load();
        if sources.entries.is_empty() {
            return true;
        }
        sources.contains(ip) || ip.is_loopback()
    }
}
