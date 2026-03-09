use std::net::Ipv4Addr;

use opencircuit::{
    format_cidr, normalize_cidr, parse_and_normalize_cidr, parse_cidr, CidrParseError,
};

#[test]
fn parses_valid_cidr() {
    let parsed = parse_cidr("192.168.1.0/24");
    assert_eq!(parsed, Ok((Ipv4Addr::new(192, 168, 1, 0), 24)));
}

#[test]
fn parses_edge_prefix_values() {
    assert_eq!(
        parse_cidr("10.0.0.1/0"),
        Ok((Ipv4Addr::new(10, 0, 0, 1), 0))
    );
    assert_eq!(
        parse_cidr("10.0.0.1/32"),
        Ok((Ipv4Addr::new(10, 0, 0, 1), 32))
    );
}

#[test]
fn fails_without_separator() {
    assert_eq!(parse_cidr("192.168.1.0"), Err(CidrParseError::MissingSlash));
}

#[test]
fn fails_with_invalid_ipv4() {
    assert_eq!(parse_cidr("999.1.1.1/24"), Err(CidrParseError::InvalidIp));
}

#[test]
fn fails_with_non_numeric_prefix() {
    assert_eq!(
        parse_cidr("192.168.1.0/x"),
        Err(CidrParseError::InvalidPrefix)
    );
}

#[test]
fn fails_with_out_of_range_prefix() {
    assert_eq!(
        parse_cidr("192.168.1.0/33"),
        Err(CidrParseError::InvalidPrefix)
    );
}

#[test]
fn formats_valid_cidr_string() {
    assert_eq!(
        format_cidr(Ipv4Addr::new(192, 168, 1, 0), 24),
        Ok(String::from("192.168.1.0/24"))
    );
}

#[test]
fn rejects_invalid_prefix_for_format_cidr() {
    assert_eq!(
        format_cidr(Ipv4Addr::new(192, 168, 1, 0), 33),
        Err(CidrParseError::InvalidPrefix)
    );
}

#[test]
fn normalizes_host_cidr_to_network_cidr() {
    assert_eq!(
        normalize_cidr(Ipv4Addr::new(192, 168, 1, 42), 24),
        Ok(String::from("192.168.1.0/24"))
    );
}

#[test]
fn keeps_already_normalized_cidr_unchanged() {
    assert_eq!(
        normalize_cidr(Ipv4Addr::new(10, 0, 0, 0), 8),
        Ok(String::from("10.0.0.0/8"))
    );
}

#[test]
fn rejects_invalid_prefix_for_normalize_cidr() {
    assert_eq!(
        normalize_cidr(Ipv4Addr::new(192, 168, 1, 42), 40),
        Err(CidrParseError::InvalidPrefix)
    );
}

#[test]
fn parses_and_normalizes_valid_cidr_input() {
    assert_eq!(
        parse_and_normalize_cidr("192.168.1.42/24"),
        Ok(String::from("192.168.1.0/24"))
    );
}

#[test]
fn parse_and_normalize_rejects_invalid_cidr_input() {
    assert_eq!(
        parse_and_normalize_cidr("not-an-ip/24"),
        Err(CidrParseError::InvalidIp)
    );
}
