use std::net::Ipv4Addr;

use opencircuit::{
    first_usable_host, is_broadcast_address, is_network_address, is_usable_host, last_usable_host,
    usable_host_count, usable_host_range, CidrParseError,
};

#[test]
fn computes_usable_host_count_for_common_subnet() {
    assert_eq!(usable_host_count(24), Ok(254));
}

#[test]
fn computes_usable_host_count_for_point_to_point_subnet() {
    assert_eq!(usable_host_count(31), Ok(2));
}

#[test]
fn computes_usable_host_count_for_single_host_subnet() {
    assert_eq!(usable_host_count(32), Ok(1));
}

#[test]
fn rejects_invalid_prefix_for_usable_host_count() {
    assert_eq!(usable_host_count(40), Err(CidrParseError::InvalidPrefix));
}

#[test]
fn detects_network_address_when_candidate_matches_network() {
    let result = is_network_address(
        Ipv4Addr::new(192, 168, 1, 42),
        24,
        Ipv4Addr::new(192, 168, 1, 0),
    );
    assert_eq!(result, Ok(true));
}

#[test]
fn rejects_non_network_candidate() {
    let result = is_network_address(
        Ipv4Addr::new(192, 168, 1, 42),
        24,
        Ipv4Addr::new(192, 168, 1, 1),
    );
    assert_eq!(result, Ok(false));
}

#[test]
fn rejects_invalid_prefix_for_is_network_address() {
    let result = is_network_address(
        Ipv4Addr::new(192, 168, 1, 42),
        33,
        Ipv4Addr::new(192, 168, 1, 0),
    );
    assert_eq!(result, Err(CidrParseError::InvalidPrefix));
}

#[test]
fn detects_broadcast_address_when_candidate_matches_broadcast() {
    let result = is_broadcast_address(
        Ipv4Addr::new(192, 168, 1, 42),
        24,
        Ipv4Addr::new(192, 168, 1, 255),
    );
    assert_eq!(result, Ok(true));
}

#[test]
fn rejects_non_broadcast_candidate() {
    let result = is_broadcast_address(
        Ipv4Addr::new(192, 168, 1, 42),
        24,
        Ipv4Addr::new(192, 168, 1, 254),
    );
    assert_eq!(result, Ok(false));
}

#[test]
fn rejects_invalid_prefix_for_is_broadcast_address() {
    let result = is_broadcast_address(
        Ipv4Addr::new(192, 168, 1, 42),
        33,
        Ipv4Addr::new(192, 168, 1, 255),
    );
    assert_eq!(result, Err(CidrParseError::InvalidPrefix));
}

#[test]
fn computes_first_usable_host_for_common_subnet() {
    let first = first_usable_host(Ipv4Addr::new(192, 168, 1, 42), 24);
    assert_eq!(first, Ok(Ipv4Addr::new(192, 168, 1, 1)));
}

#[test]
fn computes_first_usable_host_for_point_to_point_subnet() {
    let first = first_usable_host(Ipv4Addr::new(10, 0, 0, 1), 31);
    assert_eq!(first, Ok(Ipv4Addr::new(10, 0, 0, 0)));
}

#[test]
fn computes_first_usable_host_for_single_host_subnet() {
    let first = first_usable_host(Ipv4Addr::new(10, 0, 0, 7), 32);
    assert_eq!(first, Ok(Ipv4Addr::new(10, 0, 0, 7)));
}

#[test]
fn rejects_invalid_prefix_for_first_usable_host() {
    let first = first_usable_host(Ipv4Addr::new(192, 168, 1, 42), 40);
    assert_eq!(first, Err(CidrParseError::InvalidPrefix));
}

#[test]
fn computes_last_usable_host_for_common_subnet() {
    let last = last_usable_host(Ipv4Addr::new(192, 168, 1, 42), 24);
    assert_eq!(last, Ok(Ipv4Addr::new(192, 168, 1, 254)));
}

#[test]
fn computes_last_usable_host_for_point_to_point_subnet() {
    let last = last_usable_host(Ipv4Addr::new(10, 0, 0, 1), 31);
    assert_eq!(last, Ok(Ipv4Addr::new(10, 0, 0, 1)));
}

#[test]
fn computes_last_usable_host_for_single_host_subnet() {
    let last = last_usable_host(Ipv4Addr::new(10, 0, 0, 7), 32);
    assert_eq!(last, Ok(Ipv4Addr::new(10, 0, 0, 7)));
}

#[test]
fn rejects_invalid_prefix_for_last_usable_host() {
    let last = last_usable_host(Ipv4Addr::new(192, 168, 1, 42), 40);
    assert_eq!(last, Err(CidrParseError::InvalidPrefix));
}

#[test]
fn treats_host_inside_common_subnet_as_usable() {
    let usable = is_usable_host(
        Ipv4Addr::new(192, 168, 1, 42),
        24,
        Ipv4Addr::new(192, 168, 1, 10),
    );
    assert_eq!(usable, Ok(true));
}

#[test]
fn rejects_network_and_broadcast_in_common_subnet() {
    let network = is_usable_host(
        Ipv4Addr::new(192, 168, 1, 42),
        24,
        Ipv4Addr::new(192, 168, 1, 0),
    );
    let broadcast = is_usable_host(
        Ipv4Addr::new(192, 168, 1, 42),
        24,
        Ipv4Addr::new(192, 168, 1, 255),
    );
    assert_eq!(network, Ok(false));
    assert_eq!(broadcast, Ok(false));
}

#[test]
fn rejects_candidate_outside_subnet_for_usable_host() {
    let usable = is_usable_host(
        Ipv4Addr::new(192, 168, 1, 42),
        24,
        Ipv4Addr::new(192, 168, 2, 10),
    );
    assert_eq!(usable, Ok(false));
}

#[test]
fn treats_all_addresses_as_usable_for_31() {
    let first = is_usable_host(Ipv4Addr::new(10, 0, 0, 1), 31, Ipv4Addr::new(10, 0, 0, 0));
    let second = is_usable_host(Ipv4Addr::new(10, 0, 0, 1), 31, Ipv4Addr::new(10, 0, 0, 1));
    assert_eq!(first, Ok(true));
    assert_eq!(second, Ok(true));
}

#[test]
fn rejects_invalid_prefix_for_is_usable_host() {
    let usable = is_usable_host(
        Ipv4Addr::new(192, 168, 1, 42),
        40,
        Ipv4Addr::new(192, 168, 1, 10),
    );
    assert_eq!(usable, Err(CidrParseError::InvalidPrefix));
}

#[test]
fn computes_usable_host_range_for_common_subnet() {
    assert_eq!(
        usable_host_range(Ipv4Addr::new(192, 168, 1, 42), 24),
        Ok((
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(192, 168, 1, 254)
        ))
    );
}

#[test]
fn computes_usable_host_range_for_point_to_point_subnet() {
    assert_eq!(
        usable_host_range(Ipv4Addr::new(10, 0, 0, 1), 31),
        Ok((Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(10, 0, 0, 1)))
    );
}

#[test]
fn rejects_invalid_prefix_for_usable_host_range() {
    assert_eq!(
        usable_host_range(Ipv4Addr::new(192, 168, 1, 42), 40),
        Err(CidrParseError::InvalidPrefix)
    );
}
