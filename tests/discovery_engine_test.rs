use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::Duration;

use opencircuit::{
    run_discovery_with_probes, run_discovery_with_probes_and_progress, DiscoveryConfig,
    DiscoveryConfigError, DiscoverySource, DiscoveryStatus, Probe,
};

#[derive(Debug, Clone)]
struct FakeTcpProbe {
    up_hosts: Vec<Ipv4Addr>,
}

impl Probe for FakeTcpProbe {
    fn name(&self) -> &'static str {
        "fake_tcp"
    }

    fn probe_host(&self, ip: Ipv4Addr) -> opencircuit::ProbeResult {
        let is_up = self.up_hosts.contains(&ip);
        opencircuit::ProbeResult {
            ip,
            status: if is_up {
                DiscoveryStatus::Up
            } else {
                DiscoveryStatus::Down
            },
            source: DiscoverySource::TcpConnect,
            hostname: None,
            latency_ms: if is_up { Some(10) } else { None },
            open_ports: if is_up { vec![80] } else { Vec::new() },
            observed_at: std::time::SystemTime::UNIX_EPOCH,
        }
    }
}

#[derive(Debug, Clone)]
struct FakeDnsProbe {
    hostnames: HashMap<Ipv4Addr, String>,
}

impl Probe for FakeDnsProbe {
    fn name(&self) -> &'static str {
        "fake_dns"
    }

    fn probe_host(&self, ip: Ipv4Addr) -> opencircuit::ProbeResult {
        let hostname = self.hostnames.get(&ip).cloned();
        opencircuit::ProbeResult {
            ip,
            status: if hostname.is_some() {
                DiscoveryStatus::Unknown
            } else {
                DiscoveryStatus::Down
            },
            source: DiscoverySource::ReverseDns,
            hostname,
            latency_ms: None,
            open_ports: Vec::new(),
            observed_at: std::time::SystemTime::UNIX_EPOCH,
        }
    }
}

#[test]
fn run_discovery_with_probes_aggregates_results_per_host() {
    let config = DiscoveryConfig {
        cidr: String::from("192.168.1.0/30"),
        ports: vec![80],
        timeout: Duration::from_millis(50),
        concurrency: 2,
        retries: 0,
    };

    let tcp = FakeTcpProbe {
        up_hosts: vec![Ipv4Addr::new(192, 168, 1, 1)],
    };
    let mut hostnames = HashMap::new();
    hostnames.insert(Ipv4Addr::new(192, 168, 1, 2), String::from("sensor.local"));
    let dns = FakeDnsProbe { hostnames };

    let records = run_discovery_with_probes(&config, 10, &[&tcp, &dns])
        .expect("discovery with fake probes should succeed");

    assert_eq!(records.len(), 2);
    assert_eq!(records[0].ip, Ipv4Addr::new(192, 168, 1, 1));
    assert_eq!(records[0].status, DiscoveryStatus::Up);
    assert_eq!(records[0].open_ports, vec![80]);

    assert_eq!(records[1].ip, Ipv4Addr::new(192, 168, 1, 2));
    assert_eq!(records[1].hostname.as_deref(), Some("sensor.local"));
    assert_eq!(records[1].status, DiscoveryStatus::Unknown);
}

#[test]
fn run_discovery_with_probes_fails_for_invalid_config() {
    let config = DiscoveryConfig {
        cidr: String::new(),
        ..DiscoveryConfig::default()
    };
    let tcp = FakeTcpProbe {
        up_hosts: Vec::new(),
    };

    let result = run_discovery_with_probes(&config, 10, &[&tcp]);
    assert_eq!(result, Err(DiscoveryConfigError::EmptyCidr));
}

#[test]
fn run_discovery_with_probes_enforces_host_limit() {
    let config = DiscoveryConfig {
        cidr: String::from("192.168.1.0/24"),
        ..DiscoveryConfig::default()
    };
    let tcp = FakeTcpProbe {
        up_hosts: Vec::new(),
    };

    let result = run_discovery_with_probes(&config, 50, &[&tcp]);
    assert_eq!(
        result,
        Err(DiscoveryConfigError::TooManyHosts {
            limit: 50,
            actual: 254
        })
    );
}

#[test]
fn run_discovery_with_progress_reports_each_host_once() {
    let config = DiscoveryConfig {
        cidr: String::from("192.168.1.0/30"),
        ports: vec![80],
        timeout: Duration::from_millis(50),
        concurrency: 2,
        retries: 0,
    };
    let tcp = FakeTcpProbe {
        up_hosts: vec![Ipv4Addr::new(192, 168, 1, 1)],
    };

    let mut progress_events: Vec<(usize, usize, Ipv4Addr)> = Vec::new();
    let mut callback = |current: usize, total: usize, ip: Ipv4Addr| {
        progress_events.push((current, total, ip));
    };

    let records = run_discovery_with_probes_and_progress(&config, 10, &[&tcp], &mut callback)
        .expect("discovery should succeed");

    assert_eq!(records.len(), 2);
    assert_eq!(
        progress_events,
        vec![
            (1, 2, Ipv4Addr::new(192, 168, 1, 1)),
            (2, 2, Ipv4Addr::new(192, 168, 1, 2))
        ]
    );
}
