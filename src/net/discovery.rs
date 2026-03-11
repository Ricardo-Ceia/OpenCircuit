use std::collections::BTreeMap;
use std::fmt;
use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::process::Command;
use std::process::Stdio;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, SystemTime};

use dns_lookup::lookup_addr;

use crate::{first_usable_host, last_usable_host, parse_cidr, usable_host_count, CidrParseError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoveryStatus {
    Up,
    Down,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoverySource {
    Ping,
    TcpConnect,
    Mdns,
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
    pub hostname_source: Option<DiscoverySource>,
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

pub trait Probe: Sync {
    fn name(&self) -> &'static str;
    fn probe_host(&self, ip: Ipv4Addr) -> ProbeResult;
}

pub fn run_discovery(
    config: &DiscoveryConfig,
    host_limit: u64,
) -> Result<Vec<DeviceRecord>, DiscoveryConfigError> {
    let ping_probe = PingProbe::new(config.timeout);
    let tcp_probe = TcpConnectProbe::new(config.ports.clone(), config.timeout);
    let mdns_probe = MdnsProbe::new();
    let dns_probe = ReverseDnsProbe::new();
    run_discovery_with_probes(
        config,
        host_limit,
        &[&ping_probe, &tcp_probe, &mdns_probe, &dns_probe],
    )
}

pub fn run_discovery_with_progress<F>(
    config: &DiscoveryConfig,
    host_limit: u64,
    mut on_progress: F,
) -> Result<Vec<DeviceRecord>, DiscoveryConfigError>
where
    F: FnMut(usize, usize, Ipv4Addr),
{
    let ping_probe = PingProbe::new(config.timeout);
    let tcp_probe = TcpConnectProbe::new(config.ports.clone(), config.timeout);
    let mdns_probe = MdnsProbe::new();
    let dns_probe = ReverseDnsProbe::new();
    run_discovery_with_probes_and_progress(
        config,
        host_limit,
        &[&ping_probe, &tcp_probe, &mdns_probe, &dns_probe],
        &mut on_progress,
    )
}

pub fn run_discovery_with_probes(
    config: &DiscoveryConfig,
    host_limit: u64,
    probes: &[&dyn Probe],
) -> Result<Vec<DeviceRecord>, DiscoveryConfigError> {
    run_discovery_with_probes_and_progress(config, host_limit, probes, &mut |_, _, _| {})
}

pub fn run_discovery_with_probes_and_progress<F>(
    config: &DiscoveryConfig,
    host_limit: u64,
    probes: &[&dyn Probe],
    on_progress: &mut F,
) -> Result<Vec<DeviceRecord>, DiscoveryConfigError>
where
    F: FnMut(usize, usize, Ipv4Addr),
{
    validate_config(config)?;
    let hosts = expand_target_hosts(config, host_limit)?;
    let total_hosts = hosts.len();

    if total_hosts == 0 {
        return Ok(Vec::new());
    }

    let worker_count = config.concurrency.clamp(1, total_hosts);
    let mut probe_results: Vec<ProbeResult> = Vec::new();

    if worker_count == 1 {
        for (index, ip) in hosts.into_iter().enumerate() {
            for probe in probes {
                probe_results.push(probe.probe_host(ip));
            }
            on_progress(index + 1, total_hosts, ip);
        }
        return Ok(aggregate_probe_results(&probe_results));
    }

    thread::scope(|scope| {
        let (tx, rx) = mpsc::channel::<(Ipv4Addr, Vec<ProbeResult>)>();
        let mut handles = Vec::with_capacity(worker_count);

        for worker_index in 0..worker_count {
            let worker_hosts: Vec<Ipv4Addr> = hosts
                .iter()
                .copied()
                .skip(worker_index)
                .step_by(worker_count)
                .collect();
            let tx = tx.clone();

            handles.push(scope.spawn(move || {
                for ip in worker_hosts {
                    let mut per_host_results: Vec<ProbeResult> = Vec::new();
                    for probe in probes {
                        per_host_results.push(probe.probe_host(ip));
                    }
                    let _ = tx.send((ip, per_host_results));
                }
            }));
        }

        drop(tx);

        let mut completed = 0usize;
        while completed < total_hosts {
            if let Ok((ip, mut host_results)) = rx.recv() {
                completed += 1;
                on_progress(completed, total_hosts, ip);
                probe_results.append(&mut host_results);
            } else {
                break;
            }
        }

        for handle in handles {
            let _ = handle.join();
        }
    });

    Ok(aggregate_probe_results(&probe_results))
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

pub trait PingExecutor {
    fn ping(&self, ip: Ipv4Addr, timeout: Duration) -> bool;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SystemPingExecutor;

impl PingExecutor for SystemPingExecutor {
    fn ping(&self, ip: Ipv4Addr, timeout: Duration) -> bool {
        let timeout_secs = timeout.as_secs().max(1).to_string();
        let status = Command::new("ping")
            .args(["-c", "1", "-W", &timeout_secs, &ip.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();

        match status {
            Ok(exit) => exit.success(),
            Err(_) => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PingProbe<E: PingExecutor = SystemPingExecutor> {
    timeout: Duration,
    executor: E,
}

impl PingProbe<SystemPingExecutor> {
    pub fn new(timeout: Duration) -> Self {
        Self {
            timeout,
            executor: SystemPingExecutor,
        }
    }
}

impl<E: PingExecutor> PingProbe<E> {
    pub fn with_executor(timeout: Duration, executor: E) -> Self {
        Self { timeout, executor }
    }
}

impl<E: PingExecutor + Sync> Probe for PingProbe<E> {
    fn name(&self) -> &'static str {
        "ping"
    }

    fn probe_host(&self, ip: Ipv4Addr) -> ProbeResult {
        let reachable = self.executor.ping(ip, self.timeout);

        ProbeResult {
            ip,
            status: if reachable {
                DiscoveryStatus::Up
            } else {
                DiscoveryStatus::Unknown
            },
            source: DiscoverySource::Ping,
            hostname: None,
            latency_ms: None,
            open_ports: Vec::new(),
            observed_at: SystemTime::now(),
        }
    }
}

pub trait MdnsLookup {
    fn lookup(&self, ip: Ipv4Addr) -> Option<String>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SystemMdnsLookup;

impl MdnsLookup for SystemMdnsLookup {
    fn lookup(&self, ip: Ipv4Addr) -> Option<String> {
        let output = Command::new("avahi-resolve-address")
            .args(["-4", &ip.to_string()])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output()
            .ok()?;

        if !output.status.success() {
            return None;
        }

        let text = String::from_utf8(output.stdout).ok()?;
        let line = text.lines().next()?.trim();
        let (_addr, hostname) = line.split_once('\t')?;
        let name = hostname.trim().trim_end_matches('.').to_string();

        if name.is_empty() {
            None
        } else {
            Some(name)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MdnsProbe<L: MdnsLookup = SystemMdnsLookup> {
    resolver: L,
}

impl MdnsProbe<SystemMdnsLookup> {
    pub fn new() -> Self {
        Self {
            resolver: SystemMdnsLookup,
        }
    }
}

impl<L: MdnsLookup> MdnsProbe<L> {
    pub fn with_resolver(resolver: L) -> Self {
        Self { resolver }
    }
}

impl<L: MdnsLookup + Sync> Probe for MdnsProbe<L> {
    fn name(&self) -> &'static str {
        "mdns"
    }

    fn probe_host(&self, ip: Ipv4Addr) -> ProbeResult {
        let hostname = self.resolver.lookup(ip);

        ProbeResult {
            ip,
            status: if hostname.is_some() {
                DiscoveryStatus::Up
            } else {
                DiscoveryStatus::Unknown
            },
            source: DiscoverySource::Mdns,
            hostname,
            latency_ms: None,
            open_ports: Vec::new(),
            observed_at: SystemTime::now(),
        }
    }
}

pub trait ReverseLookup {
    fn lookup(&self, ip: Ipv4Addr) -> Option<String>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SystemReverseLookup;

impl ReverseLookup for SystemReverseLookup {
    fn lookup(&self, ip: Ipv4Addr) -> Option<String> {
        let addr = std::net::IpAddr::V4(ip);
        lookup_addr(&addr)
            .ok()
            .filter(|name| !name.trim().is_empty())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReverseDnsProbe<L: ReverseLookup = SystemReverseLookup> {
    resolver: L,
}

impl ReverseDnsProbe<SystemReverseLookup> {
    pub fn new() -> Self {
        Self {
            resolver: SystemReverseLookup,
        }
    }
}

impl<L: ReverseLookup> ReverseDnsProbe<L> {
    pub fn with_resolver(resolver: L) -> Self {
        Self { resolver }
    }
}

impl<L: ReverseLookup + Sync> Probe for ReverseDnsProbe<L> {
    fn name(&self) -> &'static str {
        "reverse_dns"
    }

    fn probe_host(&self, ip: Ipv4Addr) -> ProbeResult {
        let hostname = self.resolver.lookup(ip);

        ProbeResult {
            ip,
            status: if hostname.is_some() {
                DiscoveryStatus::Up
            } else {
                DiscoveryStatus::Unknown
            },
            source: DiscoverySource::ReverseDns,
            hostname,
            latency_ms: None,
            open_ports: Vec::new(),
            observed_at: SystemTime::now(),
        }
    }
}

pub fn aggregate_probe_results(results: &[ProbeResult]) -> Vec<DeviceRecord> {
    let mut grouped: BTreeMap<Ipv4Addr, Vec<&ProbeResult>> = BTreeMap::new();
    for result in results {
        grouped.entry(result.ip).or_default().push(result);
    }

    let mut records = Vec::with_capacity(grouped.len());

    for (ip, group) in grouped {
        let mut status = DiscoveryStatus::Down;
        let mut hostname: Option<String> = None;
        let mut hostname_source: Option<DiscoverySource> = None;
        let mut hostname_rank = u8::MAX;
        let mut latency_ms: Option<u32> = None;
        let mut open_ports: Vec<u16> = Vec::new();
        let mut sources: Vec<DiscoverySource> = Vec::new();
        let mut first_seen_at = group[0].observed_at;
        let mut last_seen_at = group[0].observed_at;

        for result in group {
            status = merge_status(&status, &result.status);

            if let Some(name) = result.hostname.as_ref().filter(|n| !n.trim().is_empty()) {
                let rank = hostname_source_rank(&result.source);
                if hostname.is_none() || rank < hostname_rank {
                    hostname = Some(name.clone());
                    hostname_source = Some(result.source.clone());
                    hostname_rank = rank;
                }
            }

            if let Some(ms) = result.latency_ms {
                latency_ms = Some(match latency_ms {
                    Some(current) => current.min(ms),
                    None => ms,
                });
            }

            open_ports.extend(&result.open_ports);

            if !sources.contains(&result.source) {
                sources.push(result.source.clone());
            }

            if result.observed_at < first_seen_at {
                first_seen_at = result.observed_at;
            }
            if result.observed_at > last_seen_at {
                last_seen_at = result.observed_at;
            }
        }

        open_ports.sort_unstable();
        open_ports.dedup();
        sources.sort_by_key(source_rank);

        records.push(DeviceRecord {
            ip,
            status,
            hostname,
            hostname_source,
            latency_ms,
            open_ports,
            sources,
            first_seen_at,
            last_seen_at,
        });
    }

    records
}

fn merge_status(current: &DiscoveryStatus, next: &DiscoveryStatus) -> DiscoveryStatus {
    use DiscoveryStatus::{Down, Unknown, Up};
    match (current, next) {
        (Up, _) | (_, Up) => Up,
        (Unknown, _) | (_, Unknown) => Unknown,
        _ => Down,
    }
}

fn source_rank(source: &DiscoverySource) -> u8 {
    match source {
        DiscoverySource::Ping => 0,
        DiscoverySource::TcpConnect => 1,
        DiscoverySource::Mdns => 2,
        DiscoverySource::ReverseDns => 3,
        DiscoverySource::Aggregated => 4,
    }
}

fn hostname_source_rank(source: &DiscoverySource) -> u8 {
    match source {
        DiscoverySource::Mdns => 0,
        DiscoverySource::ReverseDns => 1,
        DiscoverySource::TcpConnect => 2,
        DiscoverySource::Ping => 3,
        DiscoverySource::Aggregated => 4,
    }
}
