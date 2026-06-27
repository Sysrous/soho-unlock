use std::path::Path;
use std::process::Command;
use tracing::{info, warn};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DnsManager {
    SystemdResolved,
    NetworkManager,
    Networkd,
    Raw,
}

const SOHO_TAG: &str = "# managed by soho-unlock";

pub fn detect() -> DnsManager {
    if Path::new("/run/systemd/resolve/stub-resolv.conf").exists()
        && service_active("systemd-resolved")
    {
        return DnsManager::SystemdResolved;
    }
    if service_active("NetworkManager") {
        return DnsManager::NetworkManager;
    }
    if service_active("systemd-networkd") {
        if has_networkd_configs() {
            return DnsManager::Networkd;
        }
    }
    DnsManager::Raw
}

pub fn apply(dns_servers: &[&str]) {
    if dns_servers.is_empty() {
        warn!("sysdns: no DNS servers to set");
        return;
    }
    let mgr = detect();
    info!("sysdns: detected manager = {:?}", mgr);
    match mgr {
        DnsManager::SystemdResolved => apply_resolved(dns_servers),
        DnsManager::NetworkManager => apply_nm(dns_servers),
        DnsManager::Networkd => apply_networkd(dns_servers),
        DnsManager::Raw => apply_raw(dns_servers),
    }
}

#[allow(dead_code)]
pub fn cleanup() {
    let mgr = detect();
    match mgr {
        DnsManager::SystemdResolved => cleanup_resolved(),
        DnsManager::NetworkManager => cleanup_nm(),
        DnsManager::Networkd => cleanup_networkd(),
        DnsManager::Raw => cleanup_raw(),
    }
}

// ── systemd-resolved: drop-in with highest priority (00-) ──

fn apply_resolved(servers: &[&str]) {
    let dir = Path::new("/etc/systemd/resolved.conf.d");
    let _ = std::fs::create_dir_all(dir);
    let path = dir.join("00-soho.conf");

    let dns_line = servers.join(" ");
    let content = format!(
        "{SOHO_TAG}\n[Resolve]\nDNS={dns_line}\nDomains=~.\n"
    );

    if write_if_changed(&path, &content) {
        let _ = run("systemctl", &["restart", "systemd-resolved"]);
        info!("sysdns(resolved): wrote {} and restarted", path.display());
    }
}

fn cleanup_resolved() {
    let path = Path::new("/etc/systemd/resolved.conf.d/00-soho.conf");
    if path.exists() {
        let _ = std::fs::remove_file(path);
        let _ = run("systemctl", &["restart", "systemd-resolved"]);
        info!("sysdns(resolved): removed drop-in");
    }
}

// ── NetworkManager: dispatcher + unmanaged DNS ──

fn apply_nm(servers: &[&str]) {
    // Tell NM not to touch resolv.conf
    let conf_dir = Path::new("/etc/NetworkManager/conf.d");
    let _ = std::fs::create_dir_all(conf_dir);
    let nm_conf = conf_dir.join("00-soho-dns.conf");
    let nm_content = format!("{SOHO_TAG}\n[main]\ndns=none\n");
    let nm_changed = write_if_changed(&nm_conf, &nm_content);

    // Write resolv.conf directly
    let rc_changed = write_resolv_conf(servers);

    if nm_changed {
        let _ = run("systemctl", &["reload", "NetworkManager"]);
        info!("sysdns(nm): set dns=none + wrote resolv.conf");
    } else if rc_changed {
        info!("sysdns(nm): updated resolv.conf");
    }
}

fn cleanup_nm() {
    let conf = Path::new("/etc/NetworkManager/conf.d/00-soho-dns.conf");
    if conf.exists() {
        let _ = std::fs::remove_file(conf);
        let _ = run("systemctl", &["reload", "NetworkManager"]);
        info!("sysdns(nm): removed dns=none, NM will manage DNS again");
    }
    cleanup_raw();
}

// ── systemd-networkd: drop-in per .network file ──

fn apply_networkd(servers: &[&str]) {
    let dns_line = servers.join(" ");
    let net_dir = Path::new("/etc/systemd/network");
    let mut applied = 0;

    if let Ok(entries) = std::fs::read_dir(net_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("network") {
                continue;
            }
            let stem = path.file_stem().unwrap().to_string_lossy().to_string();
            let dropin_dir = net_dir.join(format!("{stem}.network.d"));
            let _ = std::fs::create_dir_all(&dropin_dir);
            let dropin = dropin_dir.join("00-soho-dns.conf");
            let content = format!(
                "{SOHO_TAG}\n[Network]\nDNS={dns_line}\n[DHCP]\nUseDNS=false\n"
            );
            if write_if_changed(&dropin, &content) {
                applied += 1;
            }
        }
    }

    if applied > 0 {
        let _ = run("networkctl", &["reload"]);
        info!("sysdns(networkd): wrote {applied} drop-in(s) and reloaded");
    }

    // Also write resolv.conf as fallback (networkd may not update it immediately)
    write_resolv_conf(servers);
}

fn cleanup_networkd() {
    let net_dir = Path::new("/etc/systemd/network");
    if let Ok(entries) = std::fs::read_dir(net_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() && path.to_string_lossy().ends_with(".network.d") {
                let dropin = path.join("00-soho-dns.conf");
                if dropin.exists() {
                    let _ = std::fs::remove_file(&dropin);
                }
            }
        }
    }
    let _ = run("networkctl", &["reload"]);
    cleanup_raw();
    info!("sysdns(networkd): cleaned up drop-ins");
}

// ── Raw resolv.conf: write + chattr +i to prevent DHCP overwrite ──

fn apply_raw(servers: &[&str]) {
    // Back up the host's original resolv.conf once (before we ever overwrite it) so
    // cleanup() can restore it verbatim instead of guessing.
    let bak = Path::new("/etc/resolv.conf.soho-orig");
    if !bak.exists() {
        if let Ok(cur) = std::fs::read_to_string("/etc/resolv.conf") {
            if !cur.contains(SOHO_TAG) {
                let _ = std::fs::write(bak, cur);
            }
        }
    }
    // Remove immutable flag first (may fail if not set, that's fine)
    let _ = run("chattr", &["-i", "/etc/resolv.conf"]);

    if write_resolv_conf(servers) {
        // Lock it against DHCP overwrites
        let _ = run("chattr", &["+i", "/etc/resolv.conf"]);
        info!("sysdns(raw): wrote resolv.conf + chattr +i");
    }
}

fn cleanup_raw() {
    let path = Path::new("/etc/resolv.conf");
    let content = std::fs::read_to_string(path).unwrap_or_default();
    if !content.contains(SOHO_TAG) {
        return; // not managed by us — leave it alone
    }
    let _ = run("chattr", &["-i", "/etc/resolv.conf"]);

    let bak = Path::new("/etc/resolv.conf.soho-orig");
    if let Ok(orig) = std::fs::read_to_string(bak) {
        // Restore the host's original resolver exactly as it was before we took over.
        let _ = std::fs::write(path, orig);
        let _ = std::fs::remove_file(bak);
        info!("sysdns(raw): restored original resolv.conf from backup");
        return;
    }
    // No backup (an older agent overwrote resolv.conf wholesale). The ENTIRE block is
    // ours — the SOHO_TAG comment plus the `nameserver <self>` / `options use-vc` lines
    // we wrote — but those data lines don't literally contain "soho-unlock", which is
    // why the old filter left `nameserver 127.0.0.1` behind. Drop the whole thing and
    // fall back to public resolvers so the host can still resolve names.
    let _ = std::fs::write(path, "nameserver 1.1.1.1\nnameserver 8.8.8.8\n");
    info!("sysdns(raw): no backup; restored public resolvers");
}

// ── helpers ──

fn write_resolv_conf(servers: &[&str]) -> bool {
    let path = Path::new("/etc/resolv.conf");

    let mut result = vec![SOHO_TAG.to_string()];
    for s in servers {
        result.push(format!("nameserver {s}"));
    }
    // Force the stub resolver to query us over TCP. Some hosts (e.g. certain HK
    // VPS) can't do UDP/53 reliably; our DNS server listens on TCP too.
    result.push("options use-vc".to_string());

    let new_content = result.join("\n") + "\n";
    write_if_changed(path, &new_content)
}

fn write_if_changed(path: &Path, content: &str) -> bool {
    if let Ok(existing) = std::fs::read_to_string(path) {
        if existing == content {
            return false;
        }
    }
    match std::fs::write(path, content) {
        Ok(()) => true,
        Err(e) => {
            warn!("sysdns: failed to write {}: {e}", path.display());
            false
        }
    }
}

fn has_networkd_configs() -> bool {
    Path::new("/etc/systemd/network")
        .read_dir()
        .map(|mut d| d.any(|e| {
            e.ok()
                .and_then(|e| e.path().extension().map(|ext| ext == "network"))
                .unwrap_or(false)
        }))
        .unwrap_or(false)
}

fn service_active(name: &str) -> bool {
    Command::new("systemctl")
        .args(["is-active", "--quiet", name])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn run(cmd: &str, args: &[&str]) -> bool {
    match Command::new(cmd).args(args).output() {
        Ok(out) => out.status.success(),
        Err(e) => {
            warn!("sysdns: {cmd} failed: {e}");
            false
        }
    }
}
