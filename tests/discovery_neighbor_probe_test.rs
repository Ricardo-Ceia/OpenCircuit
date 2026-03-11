use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

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

#[derive(Debug, Clone)]
struct RotatingNeighborLookup {
    calls: Arc<AtomicUsize>,
    target: Ipv4Addr,
}

impl NeighborLookup for RotatingNeighborLookup {
    fn neighbors(&self) -> HashSet<Ipv4Addr> {
        let call_index = self.calls.fetch_add(1, Ordering::SeqCst);
        if call_index == 0 {
            HashSet::new()
        } else {
            HashSet::from([self.target])
        }
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

#[test]
fn neighbor_probe_refreshes_lookup_after_interval() {
    let target = Ipv4Addr::new(192, 168, 1, 13);
    let lookup = RotatingNeighborLookup {
        calls: Arc::new(AtomicUsize::new(0)),
        target,
    };
    let probe = NeighborProbe::with_lookup_and_refresh_interval(lookup, Duration::from_millis(1));

    let initial = probe.probe_host(target);
    assert_eq!(initial.source, DiscoverySource::Neighbor);
    assert_eq!(initial.status, DiscoveryStatus::Unknown);

    thread::sleep(Duration::from_millis(5));

    let refreshed = probe.probe_host(target);
    assert_eq!(refreshed.source, DiscoverySource::Neighbor);
    assert_eq!(refreshed.status, DiscoveryStatus::Up);
}
