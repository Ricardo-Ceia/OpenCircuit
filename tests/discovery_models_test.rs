use std::net::Ipv4Addr;
use std::time::{Duration, SystemTime};

use opencircuit::{
    validate_config, DeviceRecord, DiscoveryConfig, DiscoveryConfigError, DiscoverySource,
    DiscoveryStatus, ProbeResult,
};

#[test]
fn default_discovery_config_is_valid() {
    let config = DiscoveryConfig::default();
    assert_eq!(validate_config(&config), Ok(()));
}

#[test]
fn rejects_empty_cidr_in_discovery_config() {
    let config = DiscoveryConfig {
        cidr: String::new(),
        ..DiscoveryConfig::default()
    };

    assert_eq!(
        validate_config(&config),
        Err(DiscoveryConfigError::EmptyCidr)
    );
}

#[test]
fn rejects_empty_ports_in_discovery_config() {
    let config = DiscoveryConfig {
        ports: Vec::new(),
        ..DiscoveryConfig::default()
    };

    assert_eq!(
        validate_config(&config),
        Err(DiscoveryConfigError::EmptyPorts)
    );
}

#[test]
fn rejects_zero_concurrency_in_discovery_config() {
    let config = DiscoveryConfig {
        concurrency: 0,
        ..DiscoveryConfig::default()
    };

    assert_eq!(
        validate_config(&config),
        Err(DiscoveryConfigError::ZeroConcurrency)
    );
}

#[test]
fn rejects_zero_timeout_in_discovery_config() {
    let config = DiscoveryConfig {
        timeout: Duration::ZERO,
        ..DiscoveryConfig::default()
    };

    assert_eq!(
        validate_config(&config),
        Err(DiscoveryConfigError::ZeroTimeout)
    );
}

#[test]
fn probe_result_model_holds_expected_fields() {
    let observed_at = SystemTime::now();
    let result = ProbeResult {
        ip: Ipv4Addr::new(192, 168, 1, 10),
        status: DiscoveryStatus::Up,
        source: DiscoverySource::TcpConnect,
        hostname: Some(String::from("printer.local")),
        latency_ms: Some(18),
        open_ports: vec![80, 443],
        observed_at,
    };

    assert_eq!(result.ip, Ipv4Addr::new(192, 168, 1, 10));
    assert_eq!(result.status, DiscoveryStatus::Up);
    assert_eq!(result.source, DiscoverySource::TcpConnect);
    assert_eq!(result.hostname.as_deref(), Some("printer.local"));
    assert_eq!(result.latency_ms, Some(18));
    assert_eq!(result.open_ports, vec![80, 443]);
    assert_eq!(result.observed_at, observed_at);
}

#[test]
fn device_record_model_holds_expected_fields() {
    let now = SystemTime::now();
    let record = DeviceRecord {
        ip: Ipv4Addr::new(192, 168, 1, 20),
        status: DiscoveryStatus::Unknown,
        hostname: None,
        latency_ms: None,
        open_ports: vec![22],
        sources: vec![DiscoverySource::Aggregated, DiscoverySource::ReverseDns],
        first_seen_at: now,
        last_seen_at: now,
    };

    assert_eq!(record.ip, Ipv4Addr::new(192, 168, 1, 20));
    assert_eq!(record.status, DiscoveryStatus::Unknown);
    assert_eq!(record.hostname, None);
    assert_eq!(record.latency_ms, None);
    assert_eq!(record.open_ports, vec![22]);
    assert_eq!(
        record.sources,
        vec![DiscoverySource::Aggregated, DiscoverySource::ReverseDns]
    );
    assert_eq!(record.first_seen_at, now);
    assert_eq!(record.last_seen_at, now);
}
