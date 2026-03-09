use std::env;
use std::net::Ipv4Addr;

use opencircuit::{
    cidr_contains, is_link_local_ipv4, is_loopback_ipv4, is_multicast_ipv4, is_private_ipv4,
    network_bounds, parse_and_normalize_cidr, parse_cidr, subnet_mask, total_address_count,
    usable_host_count, usable_host_range, wildcard_mask,
};

const USAGE: &str = "Usage:\n  opencircuit normalize <ipv4-cidr>\n  opencircuit info <ipv4-cidr>\n  opencircuit contains <ipv4-cidr> <ipv4-address>\n  opencircuit classify <ipv4-address>\n  opencircuit summary <ipv4-cidr>\n  opencircuit masks <ipv4-cidr>\n  opencircuit range <ipv4-cidr>\n  opencircuit overlap <ipv4-cidr-a> <ipv4-cidr-b>\n  opencircuit relation <ipv4-cidr-a> <ipv4-cidr-b>";

fn run(args: &[String]) -> Result<String, String> {
    if args.len() < 2 {
        return Err(String::from(USAGE));
    }

    match args[1].as_str() {
        "normalize" => {
            if args.len() != 3 {
                return Err(String::from(USAGE));
            }
            parse_and_normalize_cidr(&args[2]).map_err(|err| format!("Invalid CIDR: {err}"))
        }
        "info" => {
            if args.len() != 3 {
                return Err(String::from(USAGE));
            }
            let (ip, prefix) =
                parse_cidr(&args[2]).map_err(|err| format!("Invalid CIDR: {err}"))?;
            let normalized =
                parse_and_normalize_cidr(&args[2]).map_err(|err| format!("Invalid CIDR: {err}"))?;
            let (network, broadcast) =
                network_bounds(ip, prefix).map_err(|err| format!("Invalid CIDR: {err}"))?;
            let (first_usable, last_usable) =
                usable_host_range(ip, prefix).map_err(|err| format!("Invalid CIDR: {err}"))?;

            Ok(format!(
                "cidr={normalized}\nnetwork={network}\nbroadcast={broadcast}\nfirst_usable={first_usable}\nlast_usable={last_usable}"
            ))
        }
        "contains" => {
            if args.len() != 4 {
                return Err(String::from(USAGE));
            }

            let (ip, prefix) =
                parse_cidr(&args[2]).map_err(|err| format!("Invalid CIDR: {err}"))?;
            let candidate = args[3]
                .parse::<Ipv4Addr>()
                .map_err(|_| String::from("Invalid IPv4 address"))?;
            let contains = cidr_contains(ip, prefix, candidate)
                .map_err(|err| format!("Invalid CIDR: {err}"))?;

            Ok(contains.to_string())
        }
        "classify" => {
            if args.len() != 3 {
                return Err(String::from(USAGE));
            }

            let ip = args[2]
                .parse::<Ipv4Addr>()
                .map_err(|_| String::from("Invalid IPv4 address"))?;

            Ok(format!(
                "ip={ip}\nprivate={}\nlink_local={}\nloopback={}\nmulticast={}",
                is_private_ipv4(ip),
                is_link_local_ipv4(ip),
                is_loopback_ipv4(ip),
                is_multicast_ipv4(ip)
            ))
        }
        "summary" => {
            if args.len() != 3 {
                return Err(String::from(USAGE));
            }

            let (_, prefix) = parse_cidr(&args[2]).map_err(|err| format!("Invalid CIDR: {err}"))?;
            let normalized =
                parse_and_normalize_cidr(&args[2]).map_err(|err| format!("Invalid CIDR: {err}"))?;
            let total =
                total_address_count(prefix).map_err(|err| format!("Invalid CIDR: {err}"))?;
            let usable = usable_host_count(prefix).map_err(|err| format!("Invalid CIDR: {err}"))?;

            Ok(format!("cidr={normalized} total={total} usable={usable}"))
        }
        "masks" => {
            if args.len() != 3 {
                return Err(String::from(USAGE));
            }

            let (_, prefix) = parse_cidr(&args[2]).map_err(|err| format!("Invalid CIDR: {err}"))?;
            let normalized =
                parse_and_normalize_cidr(&args[2]).map_err(|err| format!("Invalid CIDR: {err}"))?;
            let subnet = subnet_mask(prefix).map_err(|err| format!("Invalid CIDR: {err}"))?;
            let wildcard = wildcard_mask(prefix).map_err(|err| format!("Invalid CIDR: {err}"))?;

            Ok(format!(
                "cidr={normalized}\nprefix={prefix}\nsubnet_mask={subnet}\nwildcard_mask={wildcard}"
            ))
        }
        "range" => {
            if args.len() != 3 {
                return Err(String::from(USAGE));
            }

            let (ip, prefix) =
                parse_cidr(&args[2]).map_err(|err| format!("Invalid CIDR: {err}"))?;
            let normalized =
                parse_and_normalize_cidr(&args[2]).map_err(|err| format!("Invalid CIDR: {err}"))?;
            let (first, last) =
                usable_host_range(ip, prefix).map_err(|err| format!("Invalid CIDR: {err}"))?;
            let usable = usable_host_count(prefix).map_err(|err| format!("Invalid CIDR: {err}"))?;

            Ok(format!(
                "cidr={normalized}\nfirst={first}\nlast={last}\nusable={usable}"
            ))
        }
        "overlap" => {
            if args.len() != 4 {
                return Err(String::from(USAGE));
            }

            let (ip_a, prefix_a) =
                parse_cidr(&args[2]).map_err(|err| format!("Invalid CIDR: {err}"))?;
            let (ip_b, prefix_b) =
                parse_cidr(&args[3]).map_err(|err| format!("Invalid CIDR: {err}"))?;

            let (start_a, end_a) =
                network_bounds(ip_a, prefix_a).map_err(|err| format!("Invalid CIDR: {err}"))?;
            let (start_b, end_b) =
                network_bounds(ip_b, prefix_b).map_err(|err| format!("Invalid CIDR: {err}"))?;

            let overlaps =
                u32::from(start_a) <= u32::from(end_b) && u32::from(start_b) <= u32::from(end_a);

            Ok(overlaps.to_string())
        }
        "relation" => {
            if args.len() != 4 {
                return Err(String::from(USAGE));
            }

            let (ip_a, prefix_a) =
                parse_cidr(&args[2]).map_err(|err| format!("Invalid CIDR: {err}"))?;
            let (ip_b, prefix_b) =
                parse_cidr(&args[3]).map_err(|err| format!("Invalid CIDR: {err}"))?;

            let (start_a, end_a) =
                network_bounds(ip_a, prefix_a).map_err(|err| format!("Invalid CIDR: {err}"))?;
            let (start_b, end_b) =
                network_bounds(ip_b, prefix_b).map_err(|err| format!("Invalid CIDR: {err}"))?;

            let start_a_u32 = u32::from(start_a);
            let end_a_u32 = u32::from(end_a);
            let start_b_u32 = u32::from(start_b);
            let end_b_u32 = u32::from(end_b);

            let relation = if start_a_u32 == start_b_u32 && end_a_u32 == end_b_u32 {
                "equal"
            } else if start_a_u32 <= start_b_u32 && end_a_u32 >= end_b_u32 {
                "a_contains_b"
            } else if start_b_u32 <= start_a_u32 && end_b_u32 >= end_a_u32 {
                "b_contains_a"
            } else if start_a_u32 <= end_b_u32 && start_b_u32 <= end_a_u32 {
                "overlap"
            } else {
                "disjoint"
            };

            Ok(String::from(relation))
        }
        _ => Err(String::from(USAGE)),
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();

    match run(&args) {
        Ok(normalized) => {
            println!("{normalized}");
        }
        Err(message) => {
            eprintln!("{message}");
            std::process::exit(1);
        }
    }
}
