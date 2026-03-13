use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::DiscoverySource;

#[derive(Debug, Clone)]
pub struct SeenRecord {
    pub ip: Ipv4Addr,
    pub first_seen_unix_s: u64,
    pub last_seen_unix_s: u64,
    pub hostname: Option<String>,
    pub hostname_source: Option<DiscoverySource>,
    pub open_ports: Vec<u16>,
    pub mac: Option<String>,
}

pub fn load_seen_cache(path: &str) -> Result<HashMap<Ipv4Addr, SeenRecord>, String> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(HashMap::new()),
        Err(e) => return Err(format!("Read failed: {e}")),
    };

    let mut records = HashMap::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let parts: Vec<&str> = trimmed.split('\t').collect();
        if parts.len() < 6 {
            continue;
        }

        let ip: Option<Ipv4Addr> = parts[0].parse().ok();
        let first_seen: Option<u64> = parts[1].parse().ok();
        let last_seen: Option<u64> = parts[2].parse().ok();

        let (Some(ip), Some(first_seen), Some(last_seen)) = (ip, first_seen, last_seen) else {
            continue;
        };

        let hostname = if parts[3] == "-" || parts[3].is_empty() {
            None
        } else {
            Some(parts[3].to_string())
        };

        let hostname_source = if parts[4] == "-" || parts[4].is_empty() {
            None
        } else {
            str_to_source(parts[4])
        };

        let open_ports: Vec<u16> = if parts[5].is_empty() || parts[5] == "-" {
            Vec::new()
        } else {
            parts[5]
                .split(',')
                .filter_map(|p| p.trim().parse().ok())
                .collect()
        };

        let mac = if parts.len() >= 7 && !parts[6].is_empty() && parts[6] != "-" {
            Some(parts[6].to_string())
        } else {
            None
        };

        records.insert(
            ip,
            SeenRecord {
                ip,
                first_seen_unix_s: first_seen,
                last_seen_unix_s: last_seen,
                hostname,
                hostname_source,
                open_ports,
                mac,
            },
        );
    }
    Ok(records)
}

pub fn save_seen_cache(path: &str, records: &[SeenRecord]) -> Result<(), String> {
    let lines: Vec<String> = records
        .iter()
        .map(|r| {
            let hostname = r.hostname.clone().unwrap_or_else(|| "-".to_string());
            let source = r.hostname_source.as_ref().map(source_to_tag).unwrap_or("-");
            let ports = if r.open_ports.is_empty() {
                "-".to_string()
            } else {
                r.open_ports
                    .iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            };
            let mac = r.mac.clone().unwrap_or_else(|| "-".to_string());
            format!(
                "{}\t{}\t{}\t{}\t{}\t{}\t{}",
                r.ip, r.first_seen_unix_s, r.last_seen_unix_s, hostname, source, ports, mac
            )
        })
        .collect();

    std::fs::write(path, lines.join("\n")).map_err(|e| format!("Write failed: {e}"))
}

pub fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn source_to_tag(source: &DiscoverySource) -> &'static str {
    match source {
        DiscoverySource::Ping => "ping",
        DiscoverySource::Neighbor => "neighbor",
        DiscoverySource::TcpConnect => "tcp_connect",
        DiscoverySource::Mdns => "mdns",
        DiscoverySource::Netbios => "netbios",
        DiscoverySource::ReverseDns => "reverse_dns",
        DiscoverySource::Aggregated => "aggregated",
    }
}

fn str_to_source(s: &str) -> Option<DiscoverySource> {
    match s {
        "ping" => Some(DiscoverySource::Ping),
        "neighbor" => Some(DiscoverySource::Neighbor),
        "tcp_connect" => Some(DiscoverySource::TcpConnect),
        "mdns" => Some(DiscoverySource::Mdns),
        "netbios" => Some(DiscoverySource::Netbios),
        "reverse_dns" => Some(DiscoverySource::ReverseDns),
        "aggregated" => Some(DiscoverySource::Aggregated),
        _ => None,
    }
}
