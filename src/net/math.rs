use std::net::Ipv4Addr;

use crate::CidrParseError;

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
