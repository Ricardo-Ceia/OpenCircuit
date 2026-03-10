use std::fmt;
use std::net::Ipv4Addr;
use std::time::{Duration, SystemTime};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoveryStatus {
    Up,
    Down,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoverySource {
    TcpConnect,
    ReverseDns,
    Aggregated,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryConfig {
    pub cidr: String,
    pub ports: Vec<u16>,
    pub timeout: Duration,
    pub concurrency: usize,
    pub retries: u8,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            cidr: String::from("192.168.1.0/24"),
            ports: vec![22, 80, 443],
            timeout: Duration::from_millis(500),
            concurrency: 64,
            retries: 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeResult {
    pub ip: Ipv4Addr,
    pub status: DiscoveryStatus,
    pub source: DiscoverySource,
    pub hostname: Option<String>,
    pub latency_ms: Option<u32>,
    pub open_ports: Vec<u16>,
    pub observed_at: SystemTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRecord {
    pub ip: Ipv4Addr,
    pub status: DiscoveryStatus,
    pub hostname: Option<String>,
    pub latency_ms: Option<u32>,
    pub open_ports: Vec<u16>,
    pub sources: Vec<DiscoverySource>,
    pub first_seen_at: SystemTime,
    pub last_seen_at: SystemTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoveryConfigError {
    EmptyCidr,
    EmptyPorts,
    ZeroConcurrency,
    ZeroTimeout,
}

impl fmt::Display for DiscoveryConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyCidr => write!(f, "discovery config requires a CIDR target"),
            Self::EmptyPorts => write!(f, "discovery config requires at least one probe port"),
            Self::ZeroConcurrency => {
                write!(f, "discovery config concurrency must be greater than zero")
            }
            Self::ZeroTimeout => write!(f, "discovery config timeout must be greater than zero"),
        }
    }
}

pub fn validate_config(config: &DiscoveryConfig) -> Result<(), DiscoveryConfigError> {
    if config.cidr.trim().is_empty() {
        return Err(DiscoveryConfigError::EmptyCidr);
    }

    if config.ports.is_empty() {
        return Err(DiscoveryConfigError::EmptyPorts);
    }

    if config.concurrency == 0 {
        return Err(DiscoveryConfigError::ZeroConcurrency);
    }

    if config.timeout.is_zero() {
        return Err(DiscoveryConfigError::ZeroTimeout);
    }

    Ok(())
}
