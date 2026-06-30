// 按需检测:抓 KimiR 经过的域名 + IP,聚合成可直接加规则的 域名(后缀)/ IP-CIDR / 端口。
//
// 两种用法:
//   ① CLI 手动:  soho-unlock --detect 60   →  抓 60s 打印结果
//   ② 面板触发:  面板给某服务点「检测」→ 排个任务 → 落地机 run_capture_loop 每 10s 轮询
//                到任务 → 抓 N 秒 → POST 结果给面板 → 面板弹窗给用户勾选加进服务。
//
// 抓取只在「有任务/手动开」时跑,不常驻。数据源:`ss`(KimiR 出站 IP,可靠)+ KimiR
// access log(域名,KimiR 重载后会停写,所以是尽力而为)。已走 SOCKS5(母节点:44190)的
// 不算 —— 抓到的正是「还在直连、需要加规则」的那些段。

use crate::state::AppState;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{info, warn};

const ACCESS_LOG: &str = "/var/log/KimiR/xray-access.log";

#[derive(Serialize, Default)]
pub struct CaptureResult {
    pub domains: Vec<String>,    // 主域(后缀匹配,建议加这些)
    pub subdomains: Vec<String>, // 全部子域(参考)
    pub cidrs: Vec<CidrCount>,   // /24 段 + 命中次数
    pub ports: Vec<PortCount>,   // 非标端口分布
    pub uniq_ips: usize,
}

#[derive(Serialize)]
pub struct CidrCount {
    pub cidr: String,
    pub hits: u32,
}

#[derive(Serialize)]
pub struct PortCount {
    pub port: u16,
    pub hits: u32,
}

/// 抓 `dur` 秒:每秒轮询 `ss` 收 KimiR 出站目的 IP,结束后读 access log 收域名,聚合。
pub async fn capture(dur: Duration) -> CaptureResult {
    let base = std::fs::read_to_string(ACCESS_LOG)
        .map(|s| s.lines().count())
        .unwrap_or(0);

    let mut cidr: HashMap<String, u32> = HashMap::new();
    let mut port: HashMap<u16, u32> = HashMap::new();
    let mut uniq: HashSet<String> = HashSet::new();

    let end = Instant::now() + dur;
    while Instant::now() < end {
        for args in [&["-tnp"][..], &["-unp"][..]] {
            for peer in ss_peers(args) {
                if let Some((ip, p)) = split_ipport(&peer) {
                    if skip_ip(&ip) || p == 44190 {
                        continue; // 跳过基础设施 + 已走母节点 SOCKS5 的
                    }
                    uniq.insert(ip.clone());
                    if let Some(c) = slash24(&ip) {
                        *cidr.entry(c).or_insert(0) += 1;
                    }
                    if p != 443 && p != 80 {
                        *port.entry(p).or_insert(0) += 1;
                    }
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    let mut subs: HashSet<String> = HashSet::new();
    if let Ok(s) = std::fs::read_to_string(ACCESS_LOG) {
        for line in s.lines().skip(base) {
            if let Some(h) = parse_accepted_host(line) {
                subs.insert(h);
            }
        }
    }
    let mut domset: HashSet<String> = HashSet::new();
    for d in &subs {
        domset.insert(base_domain(d));
    }

    let mut cidrs: Vec<CidrCount> = cidr
        .into_iter()
        .map(|(c, h)| CidrCount { cidr: c, hits: h })
        .collect();
    cidrs.sort_by(|a, b| b.hits.cmp(&a.hits));
    let mut ports: Vec<PortCount> = port
        .into_iter()
        .map(|(p, h)| PortCount { port: p, hits: h })
        .collect();
    ports.sort_by(|a, b| b.hits.cmp(&a.hits));
    let mut subdomains: Vec<String> = subs.into_iter().collect();
    subdomains.sort();
    let mut domains: Vec<String> = domset.into_iter().collect();
    domains.sort();

    CaptureResult {
        uniq_ips: uniq.len(),
        domains,
        subdomains,
        cidrs,
        ports,
    }
}

// `ss -tnp/-unp` 的每行第 5 列是 Peer(对端=目的)。过滤 KimiR 行,排除入站(:10083)与 SSH。
fn ss_peers(args: &[&str]) -> Vec<String> {
    let out = match Command::new("ss").args(args).output() {
        Ok(o) => o,
        Err(_) => return vec![],
    };
    let s = String::from_utf8_lossy(&out.stdout);
    let mut v = vec![];
    for line in s.lines() {
        if !line.contains("KimiR") {
            continue;
        }
        if line.contains(":10083") || line.contains(":2233") || line.contains(":22 ") {
            continue;
        }
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() >= 5 {
            v.push(f[4].to_string());
        }
    }
    v
}

fn split_ipport(peer: &str) -> Option<(String, u16)> {
    let p = peer
        .replace("[::ffff:", "")
        .replace('[', "")
        .replace(']', "");
    let i = p.rfind(':')?;
    let ip = p[..i].to_string();
    let port: u16 = p[i + 1..].parse().ok()?;
    if ip.parse::<std::net::Ipv4Addr>().is_ok() {
        Some((ip, port))
    } else {
        None
    }
}

fn slash24(ip: &str) -> Option<String> {
    let o: Vec<&str> = ip.split('.').collect();
    if o.len() == 4 {
        Some(format!("{}.{}.{}.0/24", o[0], o[1], o[2]))
    } else {
        None
    }
}

fn skip_ip(ip: &str) -> bool {
    ip.starts_with("127.")
        || ip.starts_with("169.254.")
        || ip == "0.0.0.0"
        || ip == "1.1.1.1"
        || ip == "8.8.8.8"
}

fn parse_accepted_host(line: &str) -> Option<String> {
    let pos = line.find("accepted ")?;
    let rest = &line[pos + 9..];
    let host: String = rest.chars().take_while(|c| *c != ':' && *c != ' ').collect();
    let host = host.to_ascii_lowercase();
    if host.contains('.') && host.chars().any(|c| c.is_ascii_alphabetic()) {
        Some(host)
    } else {
        None
    }
}

// 取主域(后缀):一般最后 2 段;.co.kr / .ne.kr / .com.cn 这类二级后缀取 3 段。
fn base_domain(d: &str) -> String {
    let p: Vec<&str> = d.trim_end_matches('.').split('.').collect();
    let n = p.len();
    if n >= 3
        && p[n - 1].len() == 2
        && matches!(p[n - 2], "co" | "ne" | "or" | "com" | "go" | "ac" | "pe")
    {
        format!("{}.{}.{}", p[n - 3], p[n - 2], p[n - 1])
    } else if n >= 2 {
        format!("{}.{}", p[n - 2], p[n - 1])
    } else {
        d.to_string()
    }
}

pub fn print_result(r: &CaptureResult) {
    println!("═══════════════════ 检测结果 ═══════════════════");
    println!("【1 域名 -> 加到服务 Domains(后缀匹配)】");
    for d in &r.domains {
        println!("    {d}");
    }
    if !r.subdomains.is_empty() {
        println!("  └ 全部子域({}):", r.subdomains.len());
        for s in r.subdomains.iter().take(30) {
            println!("     {s}");
        }
    }
    println!("【2 IP 段 -> 加到服务 CIDRs(/24,按次数降序)】");
    for c in r.cidrs.iter().take(40) {
        println!("    {:<18} ({}次)", c.cidr, c.hits);
    }
    if !r.ports.is_empty() {
        println!("  端口分布:");
        for p in r.ports.iter().take(10) {
            println!("    端口 {:<6} {}次", p.port, p.hits);
        }
    }
    println!("  唯一媒体IP: {}", r.uniq_ips);
    println!("════════════════════════════════════════════════");
}

/// 落地机循环:每 10s 问面板有没有检测任务;有就抓 N 秒并上报。面板没装这功能时拿不到
/// 任务(404/无 session)就静默继续,无副作用。
pub async fn run_capture_loop(state: Arc<AppState>) {
    let base = state.config.panel.url.trim_end_matches('/').to_string();
    let node_id = state.config.panel.node_id;
    let token = state.config.panel.token.clone();
    if base.is_empty() || node_id == 0 || token.is_empty() {
        return;
    }
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .unwrap_or_default();
    loop {
        tokio::time::sleep(Duration::from_secs(10)).await;
        let url = format!(
            "{}/api/agent/capture?node_id={}&token={}",
            base, node_id, token
        );
        let resp = match client.get(&url).send().await {
            Ok(r) if r.status().is_success() => r,
            _ => continue,
        };
        let v: serde_json::Value = match resp.json().await {
            Ok(v) => v,
            Err(_) => continue,
        };
        let dur = v.get("duration").and_then(|d| d.as_u64()).unwrap_or(0);
        let sid = v.get("session_id").and_then(|s| s.as_u64()).unwrap_or(0);
        if dur == 0 || sid == 0 {
            continue;
        }
        let dur = dur.clamp(10, 180);
        info!("capture: 收到检测任务 session={sid} {dur}s");
        let result = capture(Duration::from_secs(dur)).await;
        let body = serde_json::json!({
            "node_id": node_id,
            "token": token,
            "session_id": sid,
            "domains": result.domains,
            "subdomains": result.subdomains,
            "cidrs": result.cidrs,
            "ports": result.ports,
            "uniq_ips": result.uniq_ips,
        });
        match client
            .post(format!("{}/api/agent/capture-result", base))
            .json(&body)
            .send()
            .await
        {
            Ok(r) => info!("capture: 上报 session={sid} -> HTTP {}", r.status()),
            Err(e) => warn!("capture: 上报失败 {e}"),
        }
    }
}
