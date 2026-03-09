use std::net::Ipv4Addr;

use opencircuit::{
    is_link_local_ipv4, is_loopback_ipv4, is_multicast_ipv4, is_private_ipv4, next_ipv4, prev_ipv4,
};

#[test]
fn computes_next_ipv4_for_regular_address() {
    assert_eq!(
        next_ipv4(Ipv4Addr::new(192, 168, 1, 42)),
        Some(Ipv4Addr::new(192, 168, 1, 43))
    );
}

#[test]
fn computes_next_ipv4_with_octet_carry() {
    assert_eq!(
        next_ipv4(Ipv4Addr::new(10, 0, 0, 255)),
        Some(Ipv4Addr::new(10, 0, 1, 0))
    );
}

#[test]
fn returns_none_for_max_ipv4() {
    assert_eq!(next_ipv4(Ipv4Addr::new(255, 255, 255, 255)), None);
}

#[test]
fn computes_prev_ipv4_for_regular_address() {
    assert_eq!(
        prev_ipv4(Ipv4Addr::new(192, 168, 1, 42)),
        Some(Ipv4Addr::new(192, 168, 1, 41))
    );
}

#[test]
fn computes_prev_ipv4_with_octet_borrow() {
    assert_eq!(
        prev_ipv4(Ipv4Addr::new(10, 0, 1, 0)),
        Some(Ipv4Addr::new(10, 0, 0, 255))
    );
}

#[test]
fn returns_none_for_min_ipv4() {
    assert_eq!(prev_ipv4(Ipv4Addr::new(0, 0, 0, 0)), None);
}

#[test]
fn detects_private_ipv4_ranges() {
    assert!(is_private_ipv4(Ipv4Addr::new(10, 1, 2, 3)));
    assert!(is_private_ipv4(Ipv4Addr::new(172, 16, 0, 1)));
    assert!(is_private_ipv4(Ipv4Addr::new(172, 31, 255, 254)));
    assert!(is_private_ipv4(Ipv4Addr::new(192, 168, 1, 1)));
}

#[test]
fn rejects_public_and_adjacent_non_private_ranges() {
    assert!(!is_private_ipv4(Ipv4Addr::new(8, 8, 8, 8)));
    assert!(!is_private_ipv4(Ipv4Addr::new(172, 15, 0, 1)));
    assert!(!is_private_ipv4(Ipv4Addr::new(172, 32, 0, 1)));
    assert!(!is_private_ipv4(Ipv4Addr::new(192, 167, 1, 1)));
    assert!(!is_private_ipv4(Ipv4Addr::new(192, 169, 1, 1)));
}

#[test]
fn detects_link_local_ipv4_range() {
    assert!(is_link_local_ipv4(Ipv4Addr::new(169, 254, 1, 1)));
    assert!(is_link_local_ipv4(Ipv4Addr::new(169, 254, 255, 255)));
}

#[test]
fn rejects_non_link_local_ipv4_addresses() {
    assert!(!is_link_local_ipv4(Ipv4Addr::new(169, 253, 255, 255)));
    assert!(!is_link_local_ipv4(Ipv4Addr::new(169, 255, 0, 1)));
    assert!(!is_link_local_ipv4(Ipv4Addr::new(10, 0, 0, 1)));
}

#[test]
fn detects_loopback_ipv4_range() {
    assert!(is_loopback_ipv4(Ipv4Addr::new(127, 0, 0, 1)));
    assert!(is_loopback_ipv4(Ipv4Addr::new(127, 255, 255, 255)));
}

#[test]
fn rejects_non_loopback_ipv4_addresses() {
    assert!(!is_loopback_ipv4(Ipv4Addr::new(126, 255, 255, 255)));
    assert!(!is_loopback_ipv4(Ipv4Addr::new(128, 0, 0, 0)));
    assert!(!is_loopback_ipv4(Ipv4Addr::new(10, 0, 0, 1)));
}

#[test]
fn detects_multicast_ipv4_range() {
    assert!(is_multicast_ipv4(Ipv4Addr::new(224, 0, 0, 1)));
    assert!(is_multicast_ipv4(Ipv4Addr::new(239, 255, 255, 255)));
}

#[test]
fn rejects_non_multicast_ipv4_addresses() {
    assert!(!is_multicast_ipv4(Ipv4Addr::new(223, 255, 255, 255)));
    assert!(!is_multicast_ipv4(Ipv4Addr::new(240, 0, 0, 0)));
    assert!(!is_multicast_ipv4(Ipv4Addr::new(10, 0, 0, 1)));
}
