use std::collections::HashSet;
use std::net::Ipv4Addr;

use opencircuit::{DiscoverySource, DiscoveryStatus, NeighborLookup, NeighborProbe, Probe};

#[derive(Debug, Clone)]
struct FakeNeighborLookup {
    entries: HashSet<Ipv4Addr>,
}

impl NeighborLookup for FakeNeighborLookup {
    fn neighbors(&self) -> HashSet<Ipv4Addr> {
        self.entries.clone()
    }
}

#[test]
fn neighbor_probe_marks_known_neighbor_as_up() {
    let lookup = FakeNeighborLookup {
        entries: HashSet::from([Ipv4Addr::new(192, 168, 1, 13)]),
    };
    let probe = NeighborProbe::with_lookup(lookup);

    assert_eq!(probe.name(), "neighbor");
    let result = probe.probe_host(Ipv4Addr::new(192, 168, 1, 13));

    assert_eq!(result.source, DiscoverySource::Neighbor);
    assert_eq!(result.status, DiscoveryStatus::Up);
}

#[test]
fn neighbor_probe_marks_unknown_ip_as_unknown() {
    let lookup = FakeNeighborLookup {
        entries: HashSet::new(),
    };
    let probe = NeighborProbe::with_lookup(lookup);
    let result = probe.probe_host(Ipv4Addr::new(192, 168, 1, 250));

    assert_eq!(result.source, DiscoverySource::Neighbor);
    assert_eq!(result.status, DiscoveryStatus::Unknown);
}
