use std::collections::HashMap;
use std::net::Ipv4Addr;

use opencircuit::{DiscoverySource, DiscoveryStatus, MdnsLookup, MdnsProbe, Probe};

#[derive(Debug, Clone, Default)]
struct FakeMdnsLookup {
    table: HashMap<Ipv4Addr, String>,
}

impl MdnsLookup for FakeMdnsLookup {
    fn lookup(&self, ip: Ipv4Addr) -> Option<String> {
        self.table.get(&ip).cloned()
    }
}

#[test]
fn mdns_probe_sets_hostname_when_lookup_succeeds() {
    let mut table = HashMap::new();
    table.insert(
        Ipv4Addr::new(192, 168, 1, 13),
        String::from("pixel-9.local"),
    );
    let probe = MdnsProbe::with_resolver(FakeMdnsLookup { table });

    assert_eq!(probe.name(), "mdns");
    let result = probe.probe_host(Ipv4Addr::new(192, 168, 1, 13));

    assert_eq!(result.source, DiscoverySource::Mdns);
    assert_eq!(result.status, DiscoveryStatus::Up);
    assert_eq!(result.hostname.as_deref(), Some("pixel-9.local"));
}

#[test]
fn mdns_probe_returns_unknown_when_lookup_fails() {
    let probe = MdnsProbe::with_resolver(FakeMdnsLookup::default());
    let result = probe.probe_host(Ipv4Addr::new(192, 168, 1, 200));

    assert_eq!(result.source, DiscoverySource::Mdns);
    assert_eq!(result.status, DiscoveryStatus::Unknown);
    assert_eq!(result.hostname, None);
}
