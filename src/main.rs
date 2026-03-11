use std::env;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use opencircuit::{
    cidr_contains, is_link_local_ipv4, is_loopback_ipv4, is_multicast_ipv4, is_private_ipv4,
    is_usable_host, network_bounds, next_ipv4, parse_and_normalize_cidr, parse_cidr, prev_ipv4,
    run_discovery_with_probes_and_progress, run_discovery_with_progress, subnet_mask,
    total_address_count, usable_host_count, usable_host_range, wildcard_mask, TcpConnectProbe,
};

const USAGE: &str = "Usage:\n  opencircuit normalize <ipv4-cidr>\n  opencircuit info <ipv4-cidr>\n  opencircuit contains <ipv4-cidr> <ipv4-address>\n  opencircuit usable <ipv4-cidr> <ipv4-address>\n  opencircuit next <ipv4-address>\n  opencircuit prev <ipv4-address>\n  opencircuit classify <ipv4-address>\n  opencircuit classify-cidr <ipv4-cidr>\n  opencircuit summary <ipv4-cidr>\n  opencircuit masks <ipv4-cidr>\n  opencircuit range <ipv4-cidr>\n  opencircuit overlap <ipv4-cidr-a> <ipv4-cidr-b>\n  opencircuit relation <ipv4-cidr-a> <ipv4-cidr-b>\n  opencircuit scan <ipv4-cidr> [--all] [--no-dns] [--deep|--balanced|--fast] [--ports <csv>] [--timeout-ms <n>] [--concurrency <n>]";

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

            #[derive(Clone, Copy, PartialEq, Eq)]
            enum ScanProfile {
                Fast,
                Balanced,
                Deep,
            }

            let mut config = opencircuit::DiscoveryConfig {
                cidr: args[2].clone(),
                ..opencircuit::DiscoveryConfig::default()
            };
            let mut show_all = false;
            let mut no_dns = false;
            let mut selected_profile: Option<ScanProfile> = None;
            let mut override_ports: Option<Vec<u16>> = None;
            let mut override_timeout_ms: Option<u64> = None;
            let mut override_concurrency: Option<usize> = None;
            let mut i = 3usize;
            while i < args.len() {
                match args[i].as_str() {
                    "--compact" => {
                        i += 1;
                    }
                    "--all" => {
                        show_all = true;
                        i += 1;
                    }
                    "--no-dns" => {
                        no_dns = true;
                        i += 1;
                    }
                    "--fast" => {
                        if selected_profile.is_some() {
                            return Err(String::from("Only one scan profile can be selected"));
                        }
                        selected_profile = Some(ScanProfile::Fast);
                        i += 1;
                    }
                    "--balanced" => {
                        if selected_profile.is_some() {
                            return Err(String::from("Only one scan profile can be selected"));
                        }
                        selected_profile = Some(ScanProfile::Balanced);
                        i += 1;
                    }
                    "--deep" => {
                        if selected_profile.is_some() {
                            return Err(String::from("Only one scan profile can be selected"));
                        }
                        selected_profile = Some(ScanProfile::Deep);
                        i += 1;
                    }
                    "--ports" => {
                        if i + 1 >= args.len() {
                            return Err(String::from("Missing value for --ports"));
                        }
                        override_ports = Some(parse_ports_csv(&args[i + 1])?);
                        i += 2;
                    }
                    "--timeout-ms" => {
                        if i + 1 >= args.len() {
                            return Err(String::from("Missing value for --timeout-ms"));
                        }
                        let timeout_ms = args[i + 1]
                            .parse::<u64>()
                            .map_err(|_| String::from("Invalid --timeout-ms value"))?;
                        if timeout_ms == 0 {
                            return Err(String::from("--timeout-ms must be greater than zero"));
                        }
                        override_timeout_ms = Some(timeout_ms);
                        i += 2;
                    }
                    "--concurrency" => {
                        if i + 1 >= args.len() {
                            return Err(String::from("Missing value for --concurrency"));
                        }
                        let concurrency = args[i + 1]
                            .parse::<usize>()
                            .map_err(|_| String::from("Invalid --concurrency value"))?;
                        if concurrency == 0 {
                            return Err(String::from("--concurrency must be greater than zero"));
                        }
                        override_concurrency = Some(concurrency);
                        i += 2;
                    }
                    _ => return Err(String::from(USAGE)),
                }
            }

            let profile = selected_profile.unwrap_or(ScanProfile::Deep);
            match profile {
                ScanProfile::Fast => {
                    config.timeout = Duration::from_millis(250);
                    config.concurrency = 128;
                    config.ports = vec![53, 80, 443];
                }
                ScanProfile::Balanced => {
                    config.timeout = Duration::from_millis(500);
                    config.concurrency = 64;
                    config.ports = vec![22, 53, 80, 139, 443, 445, 8008, 8009, 8080];
                }
                ScanProfile::Deep => {
                    config.timeout = Duration::from_millis(1000);
                    config.concurrency = 96;
                    config.ports = vec![
                        22, 53, 80, 123, 139, 443, 445, 554, 631, 1900, 5000, 7000, 7100, 8008,
                        8009, 8080, 8443, 8888, 62078,
                    ];
                }
            }

            if let Some(ports) = override_ports {
                config.ports = ports;
            }
            if let Some(timeout_ms) = override_timeout_ms {
                config.timeout = Duration::from_millis(timeout_ms);
            }
            if let Some(concurrency) = override_concurrency {
                config.concurrency = concurrency;
            }

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

            let displayed_records: Vec<opencircuit::DeviceRecord> = if show_all {
                records.clone()
            } else {
                records
                    .iter()
                    .filter(|record| record.status == opencircuit::DiscoveryStatus::Up)
                    .cloned()
                    .collect()
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

fn parse_ports_csv(raw: &str) -> Result<Vec<u16>, String> {
    if raw.trim().is_empty() {
        return Err(String::from("--ports cannot be empty"));
    }

    let mut ports = Vec::new();
    for part in raw.split(',') {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            return Err(String::from("Invalid --ports list"));
        }
        let port = trimmed
            .parse::<u16>()
            .map_err(|_| String::from("Invalid --ports list"))?;
        if port == 0 {
            return Err(String::from("Ports must be between 1 and 65535"));
        }
        ports.push(port);
    }

    if ports.is_empty() {
        return Err(String::from("--ports cannot be empty"));
    }

    Ok(ports)
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
