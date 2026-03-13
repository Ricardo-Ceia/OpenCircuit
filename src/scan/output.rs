use crate::{DeviceRecord, DiscoverySource, DiscoveryStatus};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Presence {
    Online,
    RecentlySeen,
    Offline,
}

impl Presence {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Online => "online",
            Self::RecentlySeen => "recently_seen",
            Self::Offline => "offline",
        }
    }
}

pub struct OutputRecord {
    pub ip: Ipv4Addr,
    pub status: &'static str,
    pub presence: &'static str,
    pub connectivity_source: &'static str,
    pub hostname: String,
    pub hostname_source: String,
    pub hostname_confidence: u8,
    pub mac: String,
    pub open_ports: String,
}

impl OutputRecord {
    pub fn from_record(
        record: &DeviceRecord,
        presence: Presence,
        connectivity_source: &'static str,
        mac: Option<String>,
    ) -> Self {
        let status = match record.status {
            DiscoveryStatus::Up => "up",
            DiscoveryStatus::Down => "down",
            DiscoveryStatus::Unknown => "unknown",
        };

        let hostname = record.hostname.clone().unwrap_or_else(|| "-".to_string());
        let hostname_source = record
            .hostname_source
            .as_ref()
            .map(source_to_str)
            .unwrap_or("-")
            .to_string();
        let hostname_confidence = hostname_confidence(record.hostname_source.as_ref());
        let mac = mac.unwrap_or_else(|| "-".to_string());
        let open_ports = if record.open_ports.is_empty() {
            "-".to_string()
        } else {
            record
                .open_ports
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(",")
        };

        Self {
            ip: record.ip,
            status,
            presence: presence.as_str(),
            connectivity_source,
            hostname,
            hostname_source,
            hostname_confidence,
            mac,
            open_ports,
        }
    }

    pub fn format(&self) -> String {
        format!(
            "ip={} status={} presence={} connectivity_source={} hostname={} hostname_source={} hostname_confidence={} mac={} open_ports={}",
            self.ip,
            self.status,
            self.presence,
            self.connectivity_source,
            self.hostname,
            self.hostname_source,
            self.hostname_confidence,
            self.mac,
            self.open_ports
        )
    }
}

pub struct Header {
    pub scanned_hosts: usize,
    pub shown: usize,
    pub elapsed_ms: u128,
    pub recent_minutes: u64,
    pub gateway_ip: String,
    pub gateway_iface: String,
    pub gateway_neighbors: usize,
    pub dhcp_leases: usize,
}

impl Header {
    pub fn format(&self) -> String {
        format!(
            "scanned_hosts={} records={} shown={} elapsed_ms={} recent_minutes={} gateway_ip={} gateway_iface={} gateway_neighbors={} dhcp_leases={}",
            self.scanned_hosts,
            self.scanned_hosts,
            self.shown,
            self.elapsed_ms,
            self.recent_minutes,
            self.gateway_ip,
            self.gateway_iface,
            self.gateway_neighbors,
            self.dhcp_leases
        )
    }
}

fn source_to_str(source: &DiscoverySource) -> &'static str {
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

fn hostname_confidence(source: Option<&DiscoverySource>) -> u8 {
    match source {
        Some(DiscoverySource::Mdns) => 95,
        Some(DiscoverySource::Netbios) => 92,
        Some(DiscoverySource::ReverseDns) => 90,
        _ => 0,
    }
}

use std::net::Ipv4Addr;
