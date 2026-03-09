use std::fmt;
use std::net::Ipv4Addr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CidrParseError {
    MissingSlash,
    InvalidIp,
    InvalidPrefix,
    InvalidSubnetMask,
}

impl fmt::Display for CidrParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingSlash => write!(f, "CIDR must include '/' separator"),
            Self::InvalidIp => write!(f, "CIDR contains an invalid IPv4 address"),
            Self::InvalidPrefix => write!(f, "CIDR prefix must be an integer between 0 and 32"),
            Self::InvalidSubnetMask => {
                write!(f, "Subnet mask must contain contiguous leading 1 bits")
            }
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

pub fn next_ipv4(ip: Ipv4Addr) -> Option<Ipv4Addr> {
    let value = u32::from(ip);
    if value == u32::MAX {
        return None;
    }

    Some(Ipv4Addr::from(value + 1))
}

pub fn prev_ipv4(ip: Ipv4Addr) -> Option<Ipv4Addr> {
    let value = u32::from(ip);
    if value == 0 {
        return None;
    }

    Some(Ipv4Addr::from(value - 1))
}

pub fn is_private_ipv4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();

    if octets[0] == 10 {
        return true;
    }

    if octets[0] == 172 && (16..=31).contains(&octets[1]) {
        return true;
    }

    octets[0] == 192 && octets[1] == 168
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

pub fn is_network_address(
    network_ip: Ipv4Addr,
    prefix: u8,
    candidate: Ipv4Addr,
) -> Result<bool, CidrParseError> {
    let (network, _) = network_bounds(network_ip, prefix)?;
    Ok(candidate == network)
}

pub fn is_broadcast_address(
    network_ip: Ipv4Addr,
    prefix: u8,
    candidate: Ipv4Addr,
) -> Result<bool, CidrParseError> {
    let (_, broadcast) = network_bounds(network_ip, prefix)?;
    Ok(candidate == broadcast)
}

pub fn first_usable_host(network_ip: Ipv4Addr, prefix: u8) -> Result<Ipv4Addr, CidrParseError> {
    let (network, _) = network_bounds(network_ip, prefix)?;

    if prefix >= 31 {
        return Ok(network);
    }

    Ok(Ipv4Addr::from(u32::from(network) + 1))
}

pub fn last_usable_host(network_ip: Ipv4Addr, prefix: u8) -> Result<Ipv4Addr, CidrParseError> {
    let (_, broadcast) = network_bounds(network_ip, prefix)?;

    if prefix >= 31 {
        return Ok(broadcast);
    }

    Ok(Ipv4Addr::from(u32::from(broadcast) - 1))
}

pub fn is_usable_host(
    network_ip: Ipv4Addr,
    prefix: u8,
    candidate: Ipv4Addr,
) -> Result<bool, CidrParseError> {
    if !cidr_contains(network_ip, prefix, candidate)? {
        return Ok(false);
    }

    if prefix >= 31 {
        return Ok(true);
    }

    if is_network_address(network_ip, prefix, candidate)? {
        return Ok(false);
    }

    if is_broadcast_address(network_ip, prefix, candidate)? {
        return Ok(false);
    }

    Ok(true)
}

pub fn subnet_mask(prefix: u8) -> Result<Ipv4Addr, CidrParseError> {
    if prefix > 32 {
        return Err(CidrParseError::InvalidPrefix);
    }

    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    };

    Ok(Ipv4Addr::from(mask))
}

pub fn wildcard_mask(prefix: u8) -> Result<Ipv4Addr, CidrParseError> {
    let subnet = subnet_mask(prefix)?;
    Ok(Ipv4Addr::from(!u32::from(subnet)))
}

pub fn prefix_from_subnet_mask(mask: Ipv4Addr) -> Result<u8, CidrParseError> {
    let mask_u32 = u32::from(mask);
    let prefix = mask_u32.leading_ones() as u8;
    let canonical_mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    };

    if mask_u32 != canonical_mask {
        return Err(CidrParseError::InvalidSubnetMask);
    }

    Ok(prefix)
}

pub fn format_cidr(ip: Ipv4Addr, prefix: u8) -> Result<String, CidrParseError> {
    if prefix > 32 {
        return Err(CidrParseError::InvalidPrefix);
    }

    Ok(format!("{ip}/{prefix}"))
}

pub fn normalize_cidr(ip: Ipv4Addr, prefix: u8) -> Result<String, CidrParseError> {
    let (network, _) = network_bounds(ip, prefix)?;
    format_cidr(network, prefix)
}

pub fn parse_and_normalize_cidr(input: &str) -> Result<String, CidrParseError> {
    let (ip, prefix) = parse_cidr(input)?;
    normalize_cidr(ip, prefix)
}

pub fn usable_host_range(
    network_ip: Ipv4Addr,
    prefix: u8,
) -> Result<(Ipv4Addr, Ipv4Addr), CidrParseError> {
    let first = first_usable_host(network_ip, prefix)?;
    let last = last_usable_host(network_ip, prefix)?;
    Ok((first, last))
}

#[cfg(test)]
mod tests {
    use super::{
        cidr_contains, first_usable_host, format_cidr, is_broadcast_address, is_network_address,
        is_private_ipv4, is_usable_host, last_usable_host, network_bounds, next_ipv4,
        normalize_cidr, parse_and_normalize_cidr, parse_cidr, prefix_from_subnet_mask, prev_ipv4,
        subnet_mask, total_address_count, usable_host_count, usable_host_range, wildcard_mask,
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
}
