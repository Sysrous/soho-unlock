use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub upstream: UpstreamConfig,
    pub unlock: UnlockConfig,
    #[serde(default)]
    pub firewall: FirewallConfig,
    #[serde(default)]
    pub data: DataConfig,
    #[serde(default)]
    pub panel: PanelConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PanelConfig {
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub grpc_addr: String,
    #[serde(default)]
    pub node_id: u64,
    #[serde(default)]
    pub token: String,
    #[serde(default = "default_node_type")]
    pub node_type: String,
    #[serde(default = "default_deploy_mode")]
    pub deploy_mode: String,
    #[serde(default = "default_panel_interval")]
    pub heartbeat_secs: u64,
}

impl PanelConfig {
    /// kimir / xrayr 落地机由 KimiR / XrayR 自己监听 :53/:443 做 DNS 解锁，
    /// 此时 agent 只当 dns.json 下发代理：不启动自研 DNS/SNI/HTTP 监听、不改系统 DNS
    /// （否则会和 KimiR/XrayR 抢端口、并把宿主机系统 DNS 改坏）。
    /// 母节点（node_type=="unlock"）与 dns53 本地DNS 落地机仍正常提供解析。
    pub fn is_proxy_only(&self) -> bool {
        self.node_type != "unlock"
            && (self.deploy_mode == "kimir" || self.deploy_mode == "xrayr")
    }
}

impl Default for PanelConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            grpc_addr: String::new(),
            node_id: 0,
            token: String::new(),
            node_type: default_node_type(),
            deploy_mode: default_deploy_mode(),
            heartbeat_secs: default_panel_interval(),
        }
    }
}

fn default_node_type() -> String { "transit".into() }

// 落地机部署模式：dns53=用自研本地DNS（要起DNS server+改系统DNS）；
// kimir/xrayr=交给 KimiR/XrayR 管DNS，agent 只当下发代理。默认 dns53 兼容历史行为。
fn default_deploy_mode() -> String { "dns53".into() }

fn default_panel_interval() -> u64 { 30 }

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    #[serde(default = "default_dns_listen")]
    pub dns_listen: String,
    #[serde(default = "default_sni_listen")]
    pub sni_listen: String,
    #[serde(default)]
    pub http_listen: String,
    #[serde(default = "default_panel_listen")]
    pub panel_listen: String,
    #[serde(default = "default_workers")]
    pub workers: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthConfig {
    #[serde(default = "default_token")]
    pub token: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UpstreamConfig {
    #[serde(default = "default_dns_servers")]
    pub dns: Vec<String>,
    #[serde(default = "default_dns_timeout")]
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UnlockConfig {
    pub target: String,
    #[serde(default = "default_ttl")]
    pub ttl: u32,
    #[serde(default = "default_resolve_interval")]
    pub resolve_interval_secs: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FirewallConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_fw_backend")]
    pub backend: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DataConfig {
    #[serde(default = "default_data_dir")]
    pub dir: PathBuf,
    #[serde(default = "default_dns_json_dir")]
    pub dns_json_dir: PathBuf,
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    }

    pub fn sources_path(&self) -> PathBuf {
        self.data.dir.join("sources.json")
    }

    pub fn rules_dir(&self) -> PathBuf {
        self.data.dir.join("rules")
    }

    pub fn custom_rules_path(&self) -> PathBuf {
        self.data.dir.join("custom_rules.json")
    }

    pub fn services_path(&self) -> PathBuf {
        self.data.dir.join("services.json")
    }

    pub fn export_dir(&self) -> PathBuf {
        self.data.dir.join("export")
    }

    pub fn dns_json_path(&self) -> PathBuf {
        self.data.dns_json_dir.join("dns.json")
    }

    pub fn local_dns_ip(&self) -> String {
        let addr = &self.server.dns_listen;
        if let Some(colon) = addr.rfind(':') {
            let host = &addr[..colon];
            if !host.is_empty() && host != "0.0.0.0" && host != "::" && host != "[::]" {
                return host.trim_matches('[').trim_matches(']').to_string();
            }
        }
        "127.0.0.1".to_string()
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            dns_listen: default_dns_listen(),
            sni_listen: default_sni_listen(),
            http_listen: String::new(),
            panel_listen: default_panel_listen(),
            workers: default_workers(),
        }
    }
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self { token: default_token() }
    }
}

impl Default for UpstreamConfig {
    fn default() -> Self {
        Self {
            dns: default_dns_servers(),
            timeout_ms: default_dns_timeout(),
        }
    }
}

impl Default for FirewallConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            backend: default_fw_backend(),
        }
    }
}

impl Default for DataConfig {
    fn default() -> Self {
        Self { dir: default_data_dir(), dns_json_dir: default_dns_json_dir() }
    }
}

fn default_dns_listen() -> String { "0.0.0.0:53".into() }
fn default_sni_listen() -> String { "0.0.0.0:443".into() }
fn default_panel_listen() -> String { "0.0.0.0:9190".into() }
fn default_workers() -> usize { 2 }
fn default_token() -> String { "change-me".into() }
fn default_dns_servers() -> Vec<String> { vec!["1.1.1.1".into(), "8.8.8.8".into()] }
fn default_dns_timeout() -> u64 { 3000 }
fn default_ttl() -> u32 { 300 }
fn default_resolve_interval() -> u64 { 60 }
fn default_fw_backend() -> String { "auto".into() }
fn default_data_dir() -> PathBuf { PathBuf::from("/etc/soho-unlock") }
fn default_dns_json_dir() -> PathBuf { PathBuf::from("/etc/KimiR") }
