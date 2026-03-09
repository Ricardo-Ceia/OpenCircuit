use std::net::Ipv4Addr;

use opencircuit::{
    cidr_contains, network_bounds, prefix_from_subnet_mask, subnet_mask, total_address_count,
    wildcard_mask, CidrParseError,
};

#[test]
fn computes_bounds_for_class_c_subnet() {
    let bounds = network_bounds(Ipv4Addr::new(192, 168, 1, 42), 24);
    assert_eq!(
        bounds,
        Ok((
            Ipv4Addr::new(192, 168, 1, 0),
            Ipv4Addr::new(192, 168, 1, 255)
        ))
    );
}

#[test]
fn computes_bounds_for_single_host_subnet() {
    let bounds = network_bounds(Ipv4Addr::new(10, 0, 0, 7), 32);
    assert_eq!(
        bounds,
        Ok((Ipv4Addr::new(10, 0, 0, 7), Ipv4Addr::new(10, 0, 0, 7)))
    );
}

#[test]
fn computes_bounds_for_entire_ipv4_space() {
    let bounds = network_bounds(Ipv4Addr::new(203, 0, 113, 55), 0);
    assert_eq!(
        bounds,
        Ok((Ipv4Addr::new(0, 0, 0, 0), Ipv4Addr::new(255, 255, 255, 255)))
    );
}

#[test]
fn rejects_invalid_prefix_for_bounds() {
    let bounds = network_bounds(Ipv4Addr::new(192, 168, 1, 1), 33);
    assert_eq!(bounds, Err(CidrParseError::InvalidPrefix));
}

#[test]
fn contains_address_inside_subnet() {
    let contains = cidr_contains(
        Ipv4Addr::new(192, 168, 1, 0),
        24,
        Ipv4Addr::new(192, 168, 1, 42),
    );
    assert_eq!(contains, Ok(true));
}

#[test]
fn excludes_address_outside_subnet() {
    let contains = cidr_contains(
        Ipv4Addr::new(192, 168, 1, 0),
        24,
        Ipv4Addr::new(192, 168, 2, 1),
    );
    assert_eq!(contains, Ok(false));
}

#[test]
fn rejects_invalid_prefix_for_contains() {
    let contains = cidr_contains(
        Ipv4Addr::new(192, 168, 1, 0),
        40,
        Ipv4Addr::new(192, 168, 1, 5),
    );
    assert_eq!(contains, Err(CidrParseError::InvalidPrefix));
}

#[test]
fn computes_total_address_count_for_common_subnet() {
    assert_eq!(total_address_count(24), Ok(256));
}

#[test]
fn computes_total_address_count_for_single_host() {
    assert_eq!(total_address_count(32), Ok(1));
}

#[test]
fn computes_total_address_count_for_entire_ipv4_space() {
    assert_eq!(total_address_count(0), Ok(4_294_967_296));
}

#[test]
fn rejects_invalid_prefix_for_total_address_count() {
    assert_eq!(total_address_count(33), Err(CidrParseError::InvalidPrefix));
}

#[test]
fn computes_subnet_mask_for_common_prefix() {
    assert_eq!(subnet_mask(24), Ok(Ipv4Addr::new(255, 255, 255, 0)));
}

#[test]
fn computes_subnet_mask_for_edge_prefixes() {
    assert_eq!(subnet_mask(0), Ok(Ipv4Addr::new(0, 0, 0, 0)));
    assert_eq!(subnet_mask(32), Ok(Ipv4Addr::new(255, 255, 255, 255)));
}

#[test]
fn rejects_invalid_prefix_for_subnet_mask() {
    assert_eq!(subnet_mask(33), Err(CidrParseError::InvalidPrefix));
}

#[test]
fn computes_wildcard_mask_for_common_prefix() {
    assert_eq!(wildcard_mask(24), Ok(Ipv4Addr::new(0, 0, 0, 255)));
}

#[test]
fn computes_wildcard_mask_for_edge_prefixes() {
    assert_eq!(wildcard_mask(0), Ok(Ipv4Addr::new(255, 255, 255, 255)));
    assert_eq!(wildcard_mask(32), Ok(Ipv4Addr::new(0, 0, 0, 0)));
}

#[test]
fn rejects_invalid_prefix_for_wildcard_mask() {
    assert_eq!(wildcard_mask(33), Err(CidrParseError::InvalidPrefix));
}

#[test]
fn derives_prefix_from_valid_subnet_masks() {
    assert_eq!(
        prefix_from_subnet_mask(Ipv4Addr::new(255, 255, 255, 0)),
        Ok(24)
    );
    assert_eq!(prefix_from_subnet_mask(Ipv4Addr::new(0, 0, 0, 0)), Ok(0));
    assert_eq!(
        prefix_from_subnet_mask(Ipv4Addr::new(255, 255, 255, 255)),
        Ok(32)
    );
}

#[test]
fn rejects_non_contiguous_subnet_masks() {
    assert_eq!(
        prefix_from_subnet_mask(Ipv4Addr::new(255, 0, 255, 0)),
        Err(CidrParseError::InvalidSubnetMask)
    );
    assert_eq!(
        prefix_from_subnet_mask(Ipv4Addr::new(255, 255, 254, 255)),
        Err(CidrParseError::InvalidSubnetMask)
    );
}
