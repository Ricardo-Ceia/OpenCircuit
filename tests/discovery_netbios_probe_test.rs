use std::collections::HashMap;
use std::net::Ipv4Addr;

use opencircuit::{DiscoverySource, DiscoveryStatus, NetbiosLookup, NetbiosProbe, Probe};

#[derive(Debug, Clone, Default)]
struct FakeNetbiosLookup {
    table: HashMap<Ipv4Addr, String>,
}

impl NetbiosLookup for FakeNetbiosLookup {
    fn lookup(&self, ip: Ipv4Addr) -> Option<String> {
        self.table.get(&ip).cloned()
    }
}

#[test]
fn netbios_probe_sets_hostname_when_lookup_succeeds() {
    let mut table = HashMap::new();
    table.insert(
        Ipv4Addr::new(192, 168, 1, 55),
        String::from("DESKTOP-ABC123"),
    );
    let probe = NetbiosProbe::with_resolver(FakeNetbiosLookup { table });

    assert_eq!(probe.name(), "netbios");
    let result = probe.probe_host(Ipv4Addr::new(192, 168, 1, 55));

    assert_eq!(result.source, DiscoverySource::Netbios);
    assert_eq!(result.status, DiscoveryStatus::Up);
    assert_eq!(result.hostname.as_deref(), Some("DESKTOP-ABC123"));
}

#[test]
fn netbios_probe_returns_unknown_when_lookup_fails() {
    let probe = NetbiosProbe::with_resolver(FakeNetbiosLookup::default());
    let result = probe.probe_host(Ipv4Addr::new(192, 168, 1, 250));

    assert_eq!(result.source, DiscoverySource::Netbios);
    assert_eq!(result.status, DiscoveryStatus::Unknown);
    assert_eq!(result.hostname, None);
}
