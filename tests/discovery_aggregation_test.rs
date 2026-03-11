use std::net::Ipv4Addr;
use std::time::{Duration, SystemTime};

use opencircuit::{aggregate_probe_results, DiscoverySource, DiscoveryStatus, ProbeResult};

#[test]
fn aggregates_tcp_and_reverse_dns_results_for_same_host() {
    let t0 = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
    let t1 = SystemTime::UNIX_EPOCH + Duration::from_secs(110);
    let ip = Ipv4Addr::new(192, 168, 1, 10);

    let tcp = ProbeResult {
        ip,
        status: DiscoveryStatus::Up,
        source: DiscoverySource::TcpConnect,
        hostname: None,
        latency_ms: Some(12),
        open_ports: vec![443, 22, 443],
        observed_at: t1,
    };
    let dns = ProbeResult {
        ip,
        status: DiscoveryStatus::Unknown,
        source: DiscoverySource::ReverseDns,
        hostname: Some(String::from("nas.local")),
        latency_ms: None,
        open_ports: vec![],
        observed_at: t0,
    };

    let records = aggregate_probe_results(&[tcp, dns]);
    assert_eq!(records.len(), 1);

    let record = &records[0];
    assert_eq!(record.ip, ip);
    assert_eq!(record.status, DiscoveryStatus::Up);
    assert_eq!(record.hostname.as_deref(), Some("nas.local"));
    assert_eq!(record.hostname_source, Some(DiscoverySource::ReverseDns));
    assert_eq!(record.latency_ms, Some(12));
    assert_eq!(record.open_ports, vec![22, 443]);
    assert_eq!(
        record.sources,
        vec![DiscoverySource::TcpConnect, DiscoverySource::ReverseDns]
    );
    assert_eq!(record.first_seen_at, t0);
    assert_eq!(record.last_seen_at, t1);
}

#[test]
fn keeps_records_for_distinct_ips_sorted_by_address() {
    let t = SystemTime::UNIX_EPOCH + Duration::from_secs(200);
    let results = vec![
        ProbeResult {
            ip: Ipv4Addr::new(192, 168, 1, 20),
            status: DiscoveryStatus::Down,
            source: DiscoverySource::TcpConnect,
            hostname: None,
            latency_ms: None,
            open_ports: vec![],
            observed_at: t,
        },
        ProbeResult {
            ip: Ipv4Addr::new(192, 168, 1, 5),
            status: DiscoveryStatus::Unknown,
            source: DiscoverySource::ReverseDns,
            hostname: Some(String::from("sensor.local")),
            latency_ms: None,
            open_ports: vec![],
            observed_at: t,
        },
    ];

    let records = aggregate_probe_results(&results);
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].ip, Ipv4Addr::new(192, 168, 1, 5));
    assert_eq!(records[1].ip, Ipv4Addr::new(192, 168, 1, 20));
}

#[test]
fn status_latency_and_sources_follow_precedence_and_dedup_rules() {
    let t = SystemTime::UNIX_EPOCH + Duration::from_secs(300);
    let ip = Ipv4Addr::new(10, 0, 0, 8);

    let results = vec![
        ProbeResult {
            ip,
            status: DiscoveryStatus::Unknown,
            source: DiscoverySource::Ping,
            hostname: None,
            latency_ms: None,
            open_ports: vec![],
            observed_at: t,
        },
        ProbeResult {
            ip,
            status: DiscoveryStatus::Down,
            source: DiscoverySource::TcpConnect,
            hostname: None,
            latency_ms: Some(50),
            open_ports: vec![8080],
            observed_at: t,
        },
        ProbeResult {
            ip,
            status: DiscoveryStatus::Unknown,
            source: DiscoverySource::Aggregated,
            hostname: None,
            latency_ms: Some(40),
            open_ports: vec![8080, 22],
            observed_at: t,
        },
        ProbeResult {
            ip,
            status: DiscoveryStatus::Unknown,
            source: DiscoverySource::Mdns,
            hostname: None,
            latency_ms: None,
            open_ports: vec![],
            observed_at: t,
        },
        ProbeResult {
            ip,
            status: DiscoveryStatus::Unknown,
            source: DiscoverySource::Netbios,
            hostname: None,
            latency_ms: None,
            open_ports: vec![],
            observed_at: t,
        },
        ProbeResult {
            ip,
            status: DiscoveryStatus::Up,
            source: DiscoverySource::ReverseDns,
            hostname: Some(String::from("core.local")),
            latency_ms: Some(45),
            open_ports: vec![22],
            observed_at: t,
        },
    ];

    let records = aggregate_probe_results(&results);
    assert_eq!(records.len(), 1);
    let record = &records[0];

    assert_eq!(record.status, DiscoveryStatus::Up);
    assert_eq!(record.hostname_source, Some(DiscoverySource::ReverseDns));
    assert_eq!(record.latency_ms, Some(40));
    assert_eq!(record.open_ports, vec![22, 8080]);
    assert_eq!(
        record.sources,
        vec![
            DiscoverySource::Ping,
            DiscoverySource::TcpConnect,
            DiscoverySource::Mdns,
            DiscoverySource::Netbios,
            DiscoverySource::ReverseDns,
            DiscoverySource::Aggregated
        ]
    );
}

#[test]
fn prefers_mdns_hostname_over_reverse_dns_when_both_exist() {
    let t = SystemTime::UNIX_EPOCH + Duration::from_secs(400);
    let ip = Ipv4Addr::new(192, 168, 1, 13);

    let records = aggregate_probe_results(&[
        ProbeResult {
            ip,
            status: DiscoveryStatus::Up,
            source: DiscoverySource::ReverseDns,
            hostname: Some(String::from("reverse-name.home")),
            latency_ms: None,
            open_ports: vec![],
            observed_at: t,
        },
        ProbeResult {
            ip,
            status: DiscoveryStatus::Up,
            source: DiscoverySource::Mdns,
            hostname: Some(String::from("phone.local")),
            latency_ms: None,
            open_ports: vec![],
            observed_at: t,
        },
    ]);

    assert_eq!(records.len(), 1);
    let record = &records[0];
    assert_eq!(record.hostname.as_deref(), Some("phone.local"));
    assert_eq!(record.hostname_source, Some(DiscoverySource::Mdns));
}

#[test]
fn prefers_netbios_hostname_over_reverse_dns_when_mdns_absent() {
    let t = SystemTime::UNIX_EPOCH + Duration::from_secs(450);
    let ip = Ipv4Addr::new(192, 168, 1, 55);

    let records = aggregate_probe_results(&[
        ProbeResult {
            ip,
            status: DiscoveryStatus::Up,
            source: DiscoverySource::ReverseDns,
            hostname: Some(String::from("reverse-name.home")),
            latency_ms: None,
            open_ports: vec![],
            observed_at: t,
        },
        ProbeResult {
            ip,
            status: DiscoveryStatus::Up,
            source: DiscoverySource::Netbios,
            hostname: Some(String::from("DESKTOP-ABC123")),
            latency_ms: None,
            open_ports: vec![],
            observed_at: t,
        },
    ]);

    assert_eq!(records.len(), 1);
    let record = &records[0];
    assert_eq!(record.hostname.as_deref(), Some("DESKTOP-ABC123"));
    assert_eq!(record.hostname_source, Some(DiscoverySource::Netbios));
}
