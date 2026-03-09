use std::fmt;

pub mod net;
pub use net::address::{
    is_link_local_ipv4, is_loopback_ipv4, is_multicast_ipv4, is_private_ipv4, next_ipv4, prev_ipv4,
};
pub use net::cidr::{format_cidr, normalize_cidr, parse_and_normalize_cidr, parse_cidr};
pub use net::hosts::{
    first_usable_host, is_broadcast_address, is_network_address, is_usable_host, last_usable_host,
    usable_host_count, usable_host_range,
};
pub use net::math::{
    cidr_contains, network_bounds, prefix_from_subnet_mask, subnet_mask, total_address_count,
    wildcard_mask,
};

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

#[cfg(test)]
mod tests {
    use super::{
        cidr_contains, first_usable_host, is_broadcast_address, is_network_address, is_usable_host,
        last_usable_host, network_bounds, prefix_from_subnet_mask, subnet_mask,
        total_address_count, usable_host_count, usable_host_range, wildcard_mask, CidrParseError,
    };
    use std::net::Ipv4Addr;

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
}
