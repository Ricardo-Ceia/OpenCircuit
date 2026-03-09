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
