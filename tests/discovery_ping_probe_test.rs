use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use opencircuit::{DiscoverySource, DiscoveryStatus, PingExecutor, PingProbe, Probe};

#[derive(Debug, Clone)]
struct FakePingExecutor {
    up_hosts: HashSet<Ipv4Addr>,
    calls: Arc<Mutex<Vec<Ipv4Addr>>>,
}

impl PingExecutor for FakePingExecutor {
    fn ping(&self, ip: Ipv4Addr, _timeout: Duration) -> bool {
        self.calls.lock().expect("lock calls").push(ip);
        self.up_hosts.contains(&ip)
    }
}

#[test]
fn ping_probe_marks_host_up_when_ping_succeeds() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let executor = FakePingExecutor {
        up_hosts: HashSet::from([Ipv4Addr::new(192, 168, 1, 5)]),
        calls: Arc::clone(&calls),
    };
    let probe = PingProbe::with_executor(Duration::from_millis(200), executor);

    assert_eq!(probe.name(), "ping");
    let result = probe.probe_host(Ipv4Addr::new(192, 168, 1, 5));

    assert_eq!(result.status, DiscoveryStatus::Up);
    assert_eq!(result.source, DiscoverySource::Ping);
    assert_eq!(result.hostname, None);
    assert!(result.open_ports.is_empty());
    assert_eq!(result.latency_ms, None);
    assert_eq!(
        *calls.lock().expect("lock calls"),
        vec![Ipv4Addr::new(192, 168, 1, 5)]
    );
}

#[test]
fn ping_probe_marks_host_unknown_when_ping_fails() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let executor = FakePingExecutor {
        up_hosts: HashSet::new(),
        calls: Arc::clone(&calls),
    };
    let probe = PingProbe::with_executor(Duration::from_millis(200), executor);

    let result = probe.probe_host(Ipv4Addr::new(192, 168, 1, 55));
    assert_eq!(result.status, DiscoveryStatus::Unknown);
    assert_eq!(result.source, DiscoverySource::Ping);
    assert_eq!(
        *calls.lock().expect("lock calls"),
        vec![Ipv4Addr::new(192, 168, 1, 55)]
    );
}
