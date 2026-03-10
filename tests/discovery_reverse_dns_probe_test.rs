use std::collections::HashMap;
use std::net::Ipv4Addr;

use opencircuit::{DiscoverySource, DiscoveryStatus, Probe, ReverseDnsProbe, ReverseLookup};

#[derive(Debug, Clone, Default)]
struct FakeReverseLookup {
    table: HashMap<Ipv4Addr, String>,
}

impl ReverseLookup for FakeReverseLookup {
    fn lookup(&self, ip: Ipv4Addr) -> Option<String> {
        self.table.get(&ip).cloned()
    }
}

#[test]
fn reverse_dns_probe_sets_hostname_when_lookup_succeeds() {
    let mut table = HashMap::new();
    table.insert(Ipv4Addr::new(192, 168, 1, 30), String::from("nas.local"));
    let lookup = FakeReverseLookup { table };
    let probe = ReverseDnsProbe::with_resolver(lookup);

    assert_eq!(probe.name(), "reverse_dns");
    let result = probe.probe_host(Ipv4Addr::new(192, 168, 1, 30));

    assert_eq!(result.ip, Ipv4Addr::new(192, 168, 1, 30));
    assert_eq!(result.source, DiscoverySource::ReverseDns);
    assert_eq!(result.status, DiscoveryStatus::Up);
    assert_eq!(result.hostname.as_deref(), Some("nas.local"));
    assert_eq!(result.latency_ms, None);
    assert!(result.open_ports.is_empty());
}

#[test]
fn reverse_dns_probe_returns_unknown_when_lookup_fails() {
    let probe = ReverseDnsProbe::with_resolver(FakeReverseLookup::default());
    let result = probe.probe_host(Ipv4Addr::new(192, 168, 1, 99));

    assert_eq!(result.source, DiscoverySource::ReverseDns);
    assert_eq!(result.status, DiscoveryStatus::Unknown);
    assert_eq!(result.hostname, None);
    assert_eq!(result.latency_ms, None);
    assert!(result.open_ports.is_empty());
}
