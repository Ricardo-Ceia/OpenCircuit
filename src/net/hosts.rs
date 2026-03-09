use std::net::Ipv4Addr;

use crate::CidrParseError;

use super::math::{cidr_contains, network_bounds, total_address_count};

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

pub fn usable_host_range(
    network_ip: Ipv4Addr,
    prefix: u8,
) -> Result<(Ipv4Addr, Ipv4Addr), CidrParseError> {
    let first = first_usable_host(network_ip, prefix)?;
    let last = last_usable_host(network_ip, prefix)?;
    Ok((first, last))
}
