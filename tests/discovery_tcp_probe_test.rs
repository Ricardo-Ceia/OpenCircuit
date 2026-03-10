use std::io::{Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, SocketAddrV4, TcpListener};
use std::thread;
use std::time::Duration;

use opencircuit::{DiscoverySource, DiscoveryStatus, Probe, TcpConnectProbe};

#[test]
fn tcp_connect_probe_marks_host_up_when_port_is_open() {
    let listener = TcpListener::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
        .expect("bind listener");
    let port = listener.local_addr().expect("listener addr").port();

    let server = thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 1];
            let _ = stream.read(&mut buf);
            let _ = stream.write_all(&[1u8]);
            let _ = stream.flush();
            let _ = stream.shutdown(Shutdown::Both);
        }
    });

    let probe = TcpConnectProbe::new(vec![port], Duration::from_millis(300));
    assert_eq!(probe.name(), "tcp_connect");

    let result = probe.probe_host(Ipv4Addr::LOCALHOST);
    assert_eq!(result.ip, Ipv4Addr::LOCALHOST);
    assert_eq!(result.status, DiscoveryStatus::Up);
    assert_eq!(result.source, DiscoverySource::TcpConnect);
    assert_eq!(result.open_ports, vec![port]);
    assert!(result.latency_ms.is_some());

    server.join().expect("join server thread");
}

#[test]
fn tcp_connect_probe_marks_host_down_when_ports_are_closed() {
    let temporary = TcpListener::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
        .expect("bind temp listener");
    let closed_port = temporary.local_addr().expect("temp listener addr").port();
    drop(temporary);

    let probe = TcpConnectProbe::new(vec![closed_port], Duration::from_millis(100));
    let result = probe.probe_host(Ipv4Addr::LOCALHOST);

    assert_eq!(result.status, DiscoveryStatus::Down);
    assert_eq!(result.source, DiscoverySource::TcpConnect);
    assert!(result.open_ports.is_empty());
    assert_eq!(result.latency_ms, None);
}
