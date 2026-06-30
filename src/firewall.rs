use std::process::Command;
use std::sync::Arc;
use tracing::{info, warn};

use crate::state::AppState;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FwBackend {
    Iptables,
    Nftables,
    None,
}

const CHAIN: &str = "SOHO_UNLOCK";
const NFT_TABLE: &str = "soho_unlock";

pub fn detect_backend(hint: &str) -> FwBackend {
    match hint {
        "iptables" => return FwBackend::Iptables,
        "nftables" => return FwBackend::Nftables,
        "none" => return FwBackend::None,
        _ => {}
    }
    // auto-detect: try nft first, then iptables
    if cmd_ok("nft", &["list", "ruleset"]) {
        // Check if iptables is nft-backed or legacy
        let out = cmd_output("iptables", &["-V"]);
        if out.contains("nf_tables") {
            return FwBackend::Nftables;
        }
        // Has nft but iptables is legacy — check which has existing rules
        if cmd_ok("iptables", &["-L", "-n"]) {
            return FwBackend::Iptables;
        }
        return FwBackend::Nftables;
    }
    if cmd_ok("iptables", &["-L", "-n"]) {
        return FwBackend::Iptables;
    }
    FwBackend::None
}

pub fn apply_rules(state: &Arc<AppState>, backend: FwBackend, ports: &[u16]) {
    if backend == FwBackend::None { return; }
    let sources = state.sources.load();
    let ips: Vec<String> = sources.ip_set.iter().map(|ip| ip.to_string()).collect();
    if ips.is_empty() {
        // Fail-CLOSED: no whitelist yet → DON'T bail (that left the relay ports wide open).
        // Fall through and apply with an empty allow-set, so only loopback passes and every
        // remote is DROPped on the relay ports. The outbound gRPC config push (not firewalled)
        // re-applies with the real landing whitelist moments later. Was `return` = fail-open,
        // an open-relay window the (now removed) SOCKS5 auth used to backstop.
        info!("firewall: empty whitelist → deny-all lockdown on relay ports");
    }

    let ip_refs: Vec<&str> = ips.iter().map(|s| s.as_str()).collect();
    // DNS also needs UDP open; it lives on dns_port() (10053), not the old hardcoded 53.
    let udp_port = state.config.dns_port();
    match backend {
        FwBackend::Iptables => apply_iptables(&ip_refs, ports, udp_port),
        FwBackend::Nftables => apply_nftables(&ip_refs, ports, udp_port),
        FwBackend::None => {}
    }
}

pub fn cleanup(backend: FwBackend) {
    match backend {
        FwBackend::Iptables => cleanup_iptables(),
        FwBackend::Nftables => cleanup_nftables(),
        FwBackend::None => {}
    }
}

fn apply_iptables(ips: &[&str], ports: &[u16], udp_port: u16) {
    // Flush or create our chain
    let _ = run("iptables", &["-N", CHAIN]);
    let _ = run("iptables", &["-F", CHAIN]);

    // Allow loopback
    let _ = run("iptables", &["-A", CHAIN, "-s", "127.0.0.0/8", "-j", "ACCEPT"]);

    // Allow each source IP
    for ip in ips {
        let _ = run("iptables", &["-A", CHAIN, "-s", ip, "-j", "ACCEPT"]);
    }

    // Drop everything else
    let _ = run("iptables", &["-A", CHAIN, "-j", "DROP"]);

    // Insert jump to our chain for each port (if not already present)
    for port in ports {
        let port_str = port.to_string();
        let check = run("iptables", &[
            "-C", "INPUT", "-p", "tcp", "--dport", &port_str, "-j", CHAIN
        ]);
        if !check {
            let _ = run("iptables", &[
                "-I", "INPUT", "1", "-p", "tcp", "--dport", &port_str, "-j", CHAIN
            ]);
        }
        // UDP for DNS (on the configured dns_port, e.g. 10053)
        if *port == udp_port {
            let udp_str = udp_port.to_string();
            let check_udp = run("iptables", &[
                "-C", "INPUT", "-p", "udp", "--dport", &udp_str, "-j", CHAIN
            ]);
            if !check_udp {
                let _ = run("iptables", &[
                    "-I", "INPUT", "1", "-p", "udp", "--dport", &udp_str, "-j", CHAIN
                ]);
            }
        }
    }
    info!("firewall(iptables): applied {} source IPs on ports {:?}", ips.len(), ports);
}

fn cleanup_iptables() {
    // Remove all references to our chain from INPUT
    loop {
        if !run("iptables", &["-D", "INPUT", "-j", CHAIN]) {
            break;
        }
    }
    let _ = run("iptables", &["-F", CHAIN]);
    let _ = run("iptables", &["-X", CHAIN]);
    info!("firewall(iptables): cleaned up");
}

fn apply_nftables(ips: &[&str], ports: &[u16], udp_port: u16) {
    // Create table + chain
    let _ = run("nft", &["add", "table", "inet", NFT_TABLE]);
    let _ = run("nft", &[
        "add", "chain", "inet", NFT_TABLE, "input",
        "{ type filter hook input priority -1; policy accept; }"
    ]);

    // Create set for source IPs
    let _ = run("nft", &["add", "set", "inet", NFT_TABLE, "allowed_sources", "{ type ipv4_addr; }"]);
    let _ = run("nft", &["flush", "set", "inet", NFT_TABLE, "allowed_sources"]);

    // Add IPs to set
    if !ips.is_empty() {
        let ip_list = ips.join(", ");
        let _ = run("nft", &[
            "add", "element", "inet", NFT_TABLE, "allowed_sources",
            &format!("{{ {ip_list} }}")
        ]);
    }

    // Flush chain and add rules
    let _ = run("nft", &["flush", "chain", "inet", NFT_TABLE, "input"]);

    let port_list = ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", ");
    // Allow loopback
    let _ = run("nft", &[
        "add", "rule", "inet", NFT_TABLE, "input",
        "iif", "lo", "accept"
    ]);
    // Allow sources
    let _ = run("nft", &[
        "add", "rule", "inet", NFT_TABLE, "input",
        &format!("tcp dport {{ {port_list} }} ip saddr @allowed_sources accept")
    ]);
    let _ = run("nft", &[
        "add", "rule", "inet", NFT_TABLE, "input",
        &format!("udp dport {udp_port} ip saddr @allowed_sources accept")
    ]);
    // Drop rest on those ports
    let _ = run("nft", &[
        "add", "rule", "inet", NFT_TABLE, "input",
        &format!("tcp dport {{ {port_list} }} drop")
    ]);
    let _ = run("nft", &[
        "add", "rule", "inet", NFT_TABLE, "input",
        &format!("udp dport {udp_port} drop")
    ]);

    info!("firewall(nftables): applied {} source IPs on ports {:?}", ips.len(), ports);
}

fn cleanup_nftables() {
    let _ = run("nft", &["delete", "table", "inet", NFT_TABLE]);
    info!("firewall(nftables): cleaned up");
}

fn run(cmd: &str, args: &[&str]) -> bool {
    match Command::new(cmd).args(args).output() {
        Ok(out) => out.status.success(),
        Err(e) => {
            warn!("{cmd} failed: {e}");
            false
        }
    }
}

fn cmd_ok(cmd: &str, args: &[&str]) -> bool {
    Command::new(cmd).args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn cmd_output(cmd: &str, args: &[&str]) -> String {
    Command::new(cmd).args(args)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default()
}
