use aho_corasick::AhoCorasick;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleEntry {
    pub rule_type: String,
    pub value: String,
    #[serde(default)]
    pub tag: String,
}

// ── CIDR prefix-length bucket matcher ──
// O(33) for IPv4, O(129) for IPv6, regardless of rule count.

struct CidrMatcher {
    v4: [HashSet<u32>; 33],
    v6: [HashSet<u128>; 129],
}

impl Default for CidrMatcher {
    fn default() -> Self {
        Self {
            v4: std::array::from_fn(|_| HashSet::new()),
            v6: std::array::from_fn(|_| HashSet::new()),
        }
    }
}

impl CidrMatcher {
    fn clear(&mut self) {
        for s in &mut self.v4 {
            s.clear();
        }
        for s in &mut self.v6 {
            s.clear();
        }
    }

    fn insert(&mut self, cidr: &str) {
        let Ok(net) = cidr.parse::<ipnet::IpNet>() else {
            return;
        };
        let prefix = net.prefix_len();
        match net.addr() {
            IpAddr::V4(ip) => {
                let bits = u32::from(ip);
                let masked = if prefix == 0 { 0 } else { bits >> (32 - prefix) };
                self.v4[prefix as usize].insert(masked);
            }
            IpAddr::V6(ip) => {
                let bits = u128::from(ip);
                let masked = if prefix == 0 { 0 } else { bits >> (128 - prefix) };
                self.v6[prefix as usize].insert(masked);
            }
        }
    }

    fn contains(&self, ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => {
                let bits = u32::from(*v4);
                for prefix in 0..=32u8 {
                    if self.v4[prefix as usize].is_empty() {
                        continue;
                    }
                    let masked = if prefix == 0 { 0 } else { bits >> (32 - prefix) };
                    if self.v4[prefix as usize].contains(&masked) {
                        return true;
                    }
                }
                false
            }
            IpAddr::V6(v6) => {
                let bits = u128::from(*v6);
                for prefix in 0..=128u8 {
                    if self.v6[prefix as usize].is_empty() {
                        continue;
                    }
                    let masked = if prefix == 0 { 0 } else { bits >> (128 - prefix) };
                    if self.v6[prefix as usize].contains(&masked) {
                        return true;
                    }
                }
                false
            }
        }
    }
}

// ── Domain trie with wildcard support ──
// Reversed-label trie: "netflix.com" stored as root → com → netflix.
// Wildcard label * creates a wildcard edge that matches 1+ labels.
// is_match=true at a node means suffix match (any deeper subdomain also matches).

#[derive(Default)]
struct DomainTrie {
    children: HashMap<String, DomainTrie>,
    wildcard: Option<Box<DomainTrie>>,
    is_match: bool,
}

impl DomainTrie {
    fn new() -> Self {
        Self::default()
    }

    fn insert(&mut self, pattern: &str) {
        let mut node = self;
        for label in pattern.trim_end_matches('.').split('.').rev() {
            if label == "*" {
                node = node
                    .wildcard
                    .get_or_insert_with(|| Box::new(DomainTrie::default()));
            } else {
                node = node.children.entry(label.to_string()).or_default();
            }
        }
        node.is_match = true;
    }

    fn matches(&self, domain: &str) -> bool {
        let labels: Vec<&str> = domain.trim_end_matches('.').split('.').rev().collect();
        self.match_labels(&labels)
    }

    fn match_labels(&self, labels: &[&str]) -> bool {
        if self.is_match {
            return true;
        }
        if labels.is_empty() {
            return false;
        }

        if let Some(child) = self.children.get(labels[0]) {
            if child.match_labels(&labels[1..]) {
                return true;
            }
        }

        if let Some(ref wild) = self.wildcard {
            for skip in 1..=labels.len() {
                if wild.match_labels(&labels[skip..]) {
                    return true;
                }
            }
        }

        false
    }
}

// ── RuleSet ──

#[derive(Default)]
pub struct RuleSet {
    trie: DomainTrie,
    exact: HashSet<String>,
    keywords: Vec<String>,
    keyword_ac: Option<AhoCorasick>,
    cidrs: CidrMatcher,
    pub entries: Vec<RuleEntry>,
}

impl RuleSet {
    pub fn from_entries(entries: Vec<RuleEntry>) -> Self {
        let mut set = Self {
            entries,
            ..Default::default()
        };
        set.rebuild();
        set
    }

    pub fn rebuild(&mut self) {
        self.trie = DomainTrie::new();
        self.exact.clear();
        self.keywords.clear();
        self.cidrs.clear();

        for entry in &self.entries {
            let val = entry.value.to_ascii_lowercase();
            match entry.rule_type.as_str() {
                "DOMAIN" => {
                    self.exact.insert(val);
                }
                "DOMAIN-SUFFIX" => {
                    self.trie.insert(&val);
                }
                "DOMAIN-WILDCARD" => {
                    self.trie.insert(&val);
                }
                "DOMAIN-KEYWORD" => {
                    self.keywords.push(val);
                }
                "IP-CIDR" | "IP-CIDR6" => {
                    self.cidrs.insert(&val);
                }
                _ => {}
            }
        }

        self.keyword_ac = if self.keywords.is_empty() {
            None
        } else {
            AhoCorasick::builder()
                .ascii_case_insensitive(true)
                .build(&self.keywords)
                .ok()
        };
    }

    pub fn match_domain(&self, domain: &str) -> bool {
        let lower = domain.to_ascii_lowercase();
        let clean = lower.trim_end_matches('.');
        if self.exact.contains(clean) {
            return true;
        }
        if self.trie.matches(clean) {
            return true;
        }
        if let Some(ref ac) = self.keyword_ac {
            if ac.is_match(clean) {
                return true;
            }
        }
        false
    }

    pub fn match_ip(&self, ip: &IpAddr) -> bool {
        self.cidrs.contains(ip)
    }

    pub fn rule_count(&self) -> usize {
        self.entries.len()
    }
}

// ── Pattern classification ──
// Auto-detect rule type from raw user input (with * wildcards).

pub fn classify_pattern(pattern: &str) -> Option<RuleEntry> {
    let pattern = pattern.trim();
    if pattern.is_empty() || pattern.starts_with('#') || pattern.starts_with("//") {
        return None;
    }

    // Already has Clash-style type prefix
    if let Some((rtype, rest)) = pattern.split_once(',') {
        let rtype = rtype.trim().to_uppercase();
        let value = rest.split(',').next().unwrap_or("").trim().to_string();
        if matches!(
            rtype.as_str(),
            "DOMAIN" | "DOMAIN-SUFFIX" | "DOMAIN-KEYWORD" | "IP-CIDR" | "IP-CIDR6"
        ) {
            return Some(RuleEntry {
                rule_type: rtype,
                value,
                tag: String::new(),
            });
        }
    }

    // CIDR (no wildcard)
    if pattern.contains('/') && !pattern.contains('*') {
        if pattern.parse::<ipnet::IpNet>().is_ok() {
            let rtype = if pattern.contains(':') {
                "IP-CIDR6"
            } else {
                "IP-CIDR"
            };
            return Some(RuleEntry {
                rule_type: rtype.into(),
                value: pattern.to_string(),
                tag: String::new(),
            });
        }
    }

    // Wildcard patterns
    if pattern.contains('*') {
        // *.suffix or +.suffix → DOMAIN-SUFFIX
        let trimmed = pattern
            .trim_start_matches("*.")
            .trim_start_matches("+.");
        if trimmed != pattern && !trimmed.contains('*') {
            return Some(RuleEntry {
                rule_type: "DOMAIN-SUFFIX".into(),
                value: trimmed.to_string(),
                tag: String::new(),
            });
        }
        // *keyword* (no dots, just a bare keyword) → DOMAIN-KEYWORD
        let stripped = pattern.trim_matches('*');
        if !stripped.is_empty() && !stripped.contains('*') && !stripped.contains('.') {
            return Some(RuleEntry {
                rule_type: "DOMAIN-KEYWORD".into(),
                value: stripped.to_string(),
                tag: String::new(),
            });
        }
        // Everything else with * → DOMAIN-WILDCARD (trie with wildcard nodes)
        return Some(RuleEntry {
            rule_type: "DOMAIN-WILDCARD".into(),
            value: pattern.to_string(),
            tag: String::new(),
        });
    }

    // Plain domain → suffix
    if pattern.contains('.') {
        return Some(RuleEntry {
            rule_type: "DOMAIN-SUFFIX".into(),
            value: pattern.to_string(),
            tag: String::new(),
        });
    }

    None
}

// ── Xray export ──
// Convert a RuleEntry to Xray DNS/route domain format string.

pub fn to_xray_domain(entry: &RuleEntry) -> String {
    match entry.rule_type.as_str() {
        "DOMAIN" => format!("full:{}", entry.value),
        "DOMAIN-SUFFIX" => format!("domain:{}", entry.value),
        "DOMAIN-KEYWORD" => format!("keyword:{}", entry.value),
        "DOMAIN-WILDCARD" => {
            let re = entry
                .value
                .replace('.', r"\.")
                .replace('*', ".+");
            format!("regexp:^{re}$")
        }
        _ => entry.value.clone(),
    }
}

// ── nfdns export ──
// Plain domain (no prefix) for nfdns dns.json format.

pub fn to_plain_domain(entry: &RuleEntry) -> String {
    let v = entry.value.trim();
    let v = v.strip_prefix("*.").or_else(|| v.strip_prefix("+.")).unwrap_or(v);
    v.to_string()
}

// ── Parsing (backward-compatible) ──

pub fn parse_rule_line(line: &str) -> Option<RuleEntry> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
        return None;
    }

    // Clash format: DOMAIN-SUFFIX,netflix.com
    if let Some((rtype, rest)) = line.split_once(',') {
        let rtype = rtype.trim().to_uppercase();
        let value = rest.split(',').next().unwrap_or("").trim().to_string();
        match rtype.as_str() {
            "DOMAIN" | "DOMAIN-SUFFIX" | "DOMAIN-KEYWORD" | "IP-CIDR" | "IP-CIDR6" | "IP-ASN" => {
                return Some(RuleEntry {
                    rule_type: rtype,
                    value,
                    tag: String::new(),
                });
            }
            _ => {}
        }
    }

    // dnsmasq: address=/domain/ip  or  server=/domain/ip
    if line.starts_with("address=/") || line.starts_with("server=/") {
        let parts: Vec<&str> = line.splitn(3, '/').collect();
        if parts.len() >= 2 && !parts[1].is_empty() {
            return Some(RuleEntry {
                rule_type: "DOMAIN-SUFFIX".into(),
                value: parts[1].to_string(),
                tag: String::new(),
            });
        }
    }

    // Plain CIDR
    if !line.contains(',') && line.contains('/') && !line.contains('*') {
        if line.parse::<ipnet::IpNet>().is_ok() {
            let rtype = if line.contains(':') {
                "IP-CIDR6"
            } else {
                "IP-CIDR"
            };
            return Some(RuleEntry {
                rule_type: rtype.into(),
                value: line.to_string(),
                tag: String::new(),
            });
        }
    }

    // Wildcard pattern
    if line.contains('*') {
        return classify_pattern(line);
    }

    // Plain domain → suffix
    if !line.contains(' ') && !line.contains(',') && line.contains('.') {
        let domain = line.trim_start_matches("+.");
        return Some(RuleEntry {
            rule_type: "DOMAIN-SUFFIX".into(),
            value: domain.to_string(),
            tag: String::new(),
        });
    }

    None
}

pub fn load_rules_from_text(text: &str) -> Vec<RuleEntry> {
    text.lines().filter_map(parse_rule_line).collect()
}

pub fn load_rules_from_file(path: &std::path::Path) -> anyhow::Result<Vec<RuleEntry>> {
    let text = std::fs::read_to_string(path)?;
    Ok(load_rules_from_text(&text))
}
