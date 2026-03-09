use std::net::Ipv4Addr;

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

pub fn is_link_local_ipv4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 169 && octets[1] == 254
}

pub fn is_loopback_ipv4(ip: Ipv4Addr) -> bool {
    ip.octets()[0] == 127
}

pub fn is_multicast_ipv4(ip: Ipv4Addr) -> bool {
    (224..=239).contains(&ip.octets()[0])
}
