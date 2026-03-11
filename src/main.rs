use std::env;
use std::net::Ipv4Addr;
use std::time::Instant;

use opencircuit::{
    cidr_contains, is_link_local_ipv4, is_loopback_ipv4, is_multicast_ipv4, is_private_ipv4,
    is_usable_host, network_bounds, next_ipv4, parse_and_normalize_cidr, parse_cidr, prev_ipv4,
    run_discovery_with_probes_and_progress, run_discovery_with_progress, subnet_mask,
    total_address_count, usable_host_count, usable_host_range, wildcard_mask, TcpConnectProbe,
};

const USAGE: &str = "Usage:\n  opencircuit normalize <ipv4-cidr>\n  opencircuit info <ipv4-cidr>\n  opencircuit contains <ipv4-cidr> <ipv4-address>\n  opencircuit usable <ipv4-cidr> <ipv4-address>\n  opencircuit next <ipv4-address>\n  opencircuit prev <ipv4-address>\n  opencircuit classify <ipv4-address>\n  opencircuit classify-cidr <ipv4-cidr>\n  opencircuit summary <ipv4-cidr>\n  opencircuit masks <ipv4-cidr>\n  opencircuit range <ipv4-cidr>\n  opencircuit overlap <ipv4-cidr-a> <ipv4-cidr-b>\n  opencircuit relation <ipv4-cidr-a> <ipv4-cidr-b>\n  opencircuit scan <ipv4-cidr> [--compact] [--all] [--no-dns]";

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
        "usable" => {
            if args.len() != 4 {
                return Err(String::from(USAGE));
            }

            let (ip, prefix) =
                parse_cidr(&args[2]).map_err(|err| format!("Invalid CIDR: {err}"))?;
            let candidate = args[3]
                .parse::<Ipv4Addr>()
                .map_err(|_| String::from("Invalid IPv4 address"))?;
            let usable = is_usable_host(ip, prefix, candidate)
                .map_err(|err| format!("Invalid CIDR: {err}"))?;

            Ok(usable.to_string())
        }
        "next" => {
            if args.len() != 3 {
                return Err(String::from(USAGE));
            }

            let ip = args[2]
                .parse::<Ipv4Addr>()
                .map_err(|_| String::from("Invalid IPv4 address"))?;
            let next = next_ipv4(ip).ok_or_else(|| String::from("No next IPv4 address"))?;

            Ok(next.to_string())
        }
        "prev" => {
            if args.len() != 3 {
                return Err(String::from(USAGE));
            }

            let ip = args[2]
                .parse::<Ipv4Addr>()
                .map_err(|_| String::from("Invalid IPv4 address"))?;
            let prev = prev_ipv4(ip).ok_or_else(|| String::from("No previous IPv4 address"))?;

            Ok(prev.to_string())
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
        "classify-cidr" => {
            if args.len() != 3 {
                return Err(String::from(USAGE));
            }

            let (ip, prefix) =
                parse_cidr(&args[2]).map_err(|err| format!("Invalid CIDR: {err}"))?;
            let normalized =
                parse_and_normalize_cidr(&args[2]).map_err(|err| format!("Invalid CIDR: {err}"))?;
            let (network, broadcast) =
                network_bounds(ip, prefix).map_err(|err| format!("Invalid CIDR: {err}"))?;

            Ok(format!(
                "cidr={normalized}\nnetwork={network}\nbroadcast={broadcast}\nprivate={}\nlink_local={}\nloopback={}\nmulticast={}",
                is_private_ipv4(network),
                is_link_local_ipv4(network),
                is_loopback_ipv4(network),
                is_multicast_ipv4(network)
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
        "scan" => {
            if args.len() < 3 {
                return Err(String::from(USAGE));
            }

            let mut compact = false;
            let mut no_dns = false;
            for flag in &args[3..] {
                match flag.as_str() {
                    "--compact" => compact = true,
                    "--all" => compact = false,
                    "--no-dns" => no_dns = true,
                    _ => return Err(String::from(USAGE)),
                }
            }

            let config = opencircuit::DiscoveryConfig {
                cidr: args[2].clone(),
                ..opencircuit::DiscoveryConfig::default()
            };
            let started = Instant::now();
            let mut progress_callback = |current: usize, total: usize, ip: Ipv4Addr| {
                eprintln!("[scan] probing {current}/{total}: {ip}");
            };
            let records = if no_dns {
                let tcp_probe = TcpConnectProbe::new(config.ports.clone(), config.timeout);
                run_discovery_with_probes_and_progress(
                    &config,
                    1024,
                    &[&tcp_probe],
                    &mut progress_callback,
                )
                .map_err(|err| format!("Scan failed: {err}"))?
            } else {
                run_discovery_with_progress(&config, 1024, &mut progress_callback)
                    .map_err(|err| format!("Scan failed: {err}"))?
            };
            let elapsed_ms = started.elapsed().as_millis();

            let displayed_records: Vec<opencircuit::DeviceRecord> = if compact {
                records
                    .iter()
                    .filter(|record| {
                        record.status == opencircuit::DiscoveryStatus::Up
                            || record.hostname.is_some()
                            || !record.open_ports.is_empty()
                    })
                    .cloned()
                    .collect()
            } else {
                records.clone()
            };

            let mut lines = Vec::with_capacity(displayed_records.len() + 1);
            lines.push(format!(
                "scanned_hosts={} records={} shown={} elapsed_ms={}",
                records.len(),
                records.len(),
                displayed_records.len(),
                elapsed_ms
            ));

            for record in displayed_records {
                let status = match record.status {
                    opencircuit::DiscoveryStatus::Up => "up",
                    opencircuit::DiscoveryStatus::Down => "down",
                    opencircuit::DiscoveryStatus::Unknown => "unknown",
                };
                let hostname = record.hostname.unwrap_or_else(|| String::from("-"));
                let hostname_source = record
                    .hostname_source
                    .map(|source| match source {
                        opencircuit::DiscoverySource::Ping => "ping",
                        opencircuit::DiscoverySource::TcpConnect => "tcp_connect",
                        opencircuit::DiscoverySource::Mdns => "mdns",
                        opencircuit::DiscoverySource::Netbios => "netbios",
                        opencircuit::DiscoverySource::ReverseDns => "reverse_dns",
                        opencircuit::DiscoverySource::Aggregated => "aggregated",
                    })
                    .unwrap_or("-");
                let ports = if record.open_ports.is_empty() {
                    String::from("-")
                } else {
                    record
                        .open_ports
                        .iter()
                        .map(std::string::ToString::to_string)
                        .collect::<Vec<String>>()
                        .join(",")
                };

                lines.push(format!(
                    "ip={} status={} hostname={} hostname_source={} open_ports={}",
                    record.ip, status, hostname, hostname_source, ports
                ));
            }

            Ok(lines.join("\n"))
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
