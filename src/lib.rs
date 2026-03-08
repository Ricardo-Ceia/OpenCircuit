use std::fmt;
use std::net::Ipv4Addr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CidrParseError {
    MissingSlash,
    InvalidIp,
    InvalidPrefix,
}

impl fmt::Display for CidrParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingSlash => write!(f, "CIDR must include '/' separator"),
            Self::InvalidIp => write!(f, "CIDR contains an invalid IPv4 address"),
            Self::InvalidPrefix => write!(f, "CIDR prefix must be an integer between 0 and 32"),
        }
    }
}

pub fn parse_cidr(input: &str) -> Result<(Ipv4Addr, u8), CidrParseError> {
    let (ip_part, prefix_part) = input.split_once('/').ok_or(CidrParseError::MissingSlash)?;

    let ip = ip_part
        .parse::<Ipv4Addr>()
        .map_err(|_| CidrParseError::InvalidIp)?;

    let prefix = prefix_part
        .parse::<u8>()
        .map_err(|_| CidrParseError::InvalidPrefix)?;

    if prefix > 32 {
        return Err(CidrParseError::InvalidPrefix);
    }

    Ok((ip, prefix))
}

pub fn network_bounds(ip: Ipv4Addr, prefix: u8) -> Result<(Ipv4Addr, Ipv4Addr), CidrParseError> {
    if prefix > 32 {
        return Err(CidrParseError::InvalidPrefix);
    }

    let ip_u32 = u32::from(ip);
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    };

    let network = ip_u32 & mask;
    let broadcast = network | !mask;

    Ok((Ipv4Addr::from(network), Ipv4Addr::from(broadcast)))
}

pub fn cidr_contains(
    network_ip: Ipv4Addr,
    prefix: u8,
    candidate: Ipv4Addr,
) -> Result<bool, CidrParseError> {
    let (network, broadcast) = network_bounds(network_ip, prefix)?;
    let candidate_u32 = u32::from(candidate);

    Ok(candidate_u32 >= u32::from(network) && candidate_u32 <= u32::from(broadcast))
}

pub fn total_address_count(prefix: u8) -> Result<u64, CidrParseError> {
    if prefix > 32 {
        return Err(CidrParseError::InvalidPrefix);
    }

    Ok(1u64 << (32 - u32::from(prefix)))
}

pub fn usable_host_count(prefix: u8) -> Result<u64, CidrParseError> {
    let total = total_address_count(prefix)?;

    if prefix >= 31 {
        return Ok(total);
    }

    Ok(total - 2)
}

#[cfg(test)]
mod tests {
    use super::{
        cidr_contains, network_bounds, parse_cidr, total_address_count, usable_host_count,
        CidrParseError,
    };
    use std::net::Ipv4Addr;

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
}
