use std::fmt;
use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::time::{Duration, SystemTime};

use crate::{first_usable_host, last_usable_host, parse_cidr, usable_host_count, CidrParseError};

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
    Cidr(CidrParseError),
    TooManyHosts { limit: u64, actual: u64 },
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
            Self::Cidr(err) => write!(f, "invalid CIDR: {err}"),
            Self::TooManyHosts { limit, actual } => {
                write!(
                    f,
                    "target host count {actual} exceeds allowed limit {limit}"
                )
            }
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

pub fn expand_target_hosts(
    config: &DiscoveryConfig,
    host_limit: u64,
) -> Result<Vec<Ipv4Addr>, DiscoveryConfigError> {
    let (ip, prefix) = parse_cidr(&config.cidr).map_err(DiscoveryConfigError::Cidr)?;
    let actual = usable_host_count(prefix).map_err(DiscoveryConfigError::Cidr)?;

    if actual > host_limit {
        return Err(DiscoveryConfigError::TooManyHosts {
            limit: host_limit,
            actual,
        });
    }

    if actual == 0 {
        return Ok(Vec::new());
    }

    let first = first_usable_host(ip, prefix).map_err(DiscoveryConfigError::Cidr)?;
    let last = last_usable_host(ip, prefix).map_err(DiscoveryConfigError::Cidr)?;
    let mut hosts = Vec::with_capacity(actual as usize);
    let mut current = u32::from(first);
    let end = u32::from(last);

    while current <= end {
        hosts.push(Ipv4Addr::from(current));
        current = current.saturating_add(1);
    }

    Ok(hosts)
}

pub trait Probe {
    fn name(&self) -> &'static str;
    fn probe_host(&self, ip: Ipv4Addr) -> ProbeResult;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpConnectProbe {
    ports: Vec<u16>,
    timeout: Duration,
}

impl TcpConnectProbe {
    pub fn new(ports: Vec<u16>, timeout: Duration) -> Self {
        Self { ports, timeout }
    }
}

impl Probe for TcpConnectProbe {
    fn name(&self) -> &'static str {
        "tcp_connect"
    }

    fn probe_host(&self, ip: Ipv4Addr) -> ProbeResult {
        let mut open_ports = Vec::new();
        let mut best_latency_ms: Option<u32> = None;

        for port in &self.ports {
            let addr = SocketAddr::V4(SocketAddrV4::new(ip, *port));
            let started = std::time::Instant::now();

            match TcpStream::connect_timeout(&addr, self.timeout) {
                Ok(stream) => {
                    let _ = stream.shutdown(std::net::Shutdown::Both);
                    let elapsed_ms = started.elapsed().as_millis() as u32;
                    open_ports.push(*port);
                    best_latency_ms = match best_latency_ms {
                        Some(current) if current <= elapsed_ms => Some(current),
                        _ => Some(elapsed_ms),
                    };
                }
                Err(err)
                    if matches!(
                        err.kind(),
                        ErrorKind::ConnectionRefused
                            | ErrorKind::TimedOut
                            | ErrorKind::ConnectionAborted
                            | ErrorKind::ConnectionReset
                            | ErrorKind::NotConnected
                            | ErrorKind::AddrNotAvailable
                            | ErrorKind::NetworkUnreachable
                            | ErrorKind::HostUnreachable
                    ) => {}
                Err(_) => {}
            }
        }

        ProbeResult {
            ip,
            status: if open_ports.is_empty() {
                DiscoveryStatus::Down
            } else {
                DiscoveryStatus::Up
            },
            source: DiscoverySource::TcpConnect,
            hostname: None,
            latency_ms: best_latency_ms,
            open_ports,
            observed_at: SystemTime::now(),
        }
    }
}
