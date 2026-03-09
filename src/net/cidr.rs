use std::net::Ipv4Addr;

use crate::{network_bounds, CidrParseError};

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
