use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::io::ErrorKind;
use std::net::Ipv4Addr;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use opencircuit::{
    cidr_contains, is_link_local_ipv4, is_loopback_ipv4, is_multicast_ipv4, is_private_ipv4,
    is_usable_host, network_bounds, next_ipv4, parse_and_normalize_cidr, parse_cidr, prev_ipv4,
    run_discovery_with_probes_and_progress, run_discovery_with_progress, subnet_mask,
    total_address_count, usable_host_count, usable_host_range, wildcard_mask, TcpConnectProbe,
};

const DEFAULT_RECENT_MINUTES: u64 = 24 * 60;
const DEFAULT_STATE_FILE: &str = ".opencircuit-seen-cache.tsv";

const USAGE: &str = "Usage:\n  opencircuit normalize <ipv4-cidr>\n  opencircuit info <ipv4-cidr>\n  opencircuit contains <ipv4-cidr> <ipv4-address>\n  opencircuit usable <ipv4-cidr> <ipv4-address>\n  opencircuit next <ipv4-address>\n  opencircuit prev <ipv4-address>\n  opencircuit classify <ipv4-address>\n  opencircuit classify-cidr <ipv4-cidr>\n  opencircuit summary <ipv4-cidr>\n  opencircuit masks <ipv4-cidr>\n  opencircuit range <ipv4-cidr>\n  opencircuit overlap <ipv4-cidr-a> <ipv4-cidr-b>\n  opencircuit relation <ipv4-cidr-a> <ipv4-cidr-b>\n  opencircuit scan <ipv4-cidr>\n\nScan Options:\n  --all                                 Show offline records too\n  --no-dns                              Disable DNS/mDNS/NetBIOS hostname probes\n  --fast | --balanced | --deep          Scan profile (default: --deep)\n  --ports <csv>                         Override TCP ports list (example: 22,80,443)\n  --timeout-ms <n>                      Per-probe timeout in milliseconds\n  --concurrency <n>                     Concurrent host probes\n  --recent-minutes <n>                  Keep recently seen devices visible\n  --state-file <path>                   Local state cache file path\n  --dhcp-leases <path>                  Local DHCP lease file (authoritative source)\n  --dhcp-leases-ssh <user@host:/path>   Fetch DHCP leases via SSH\n\nHelp:\n  opencircuit help\n  opencircuit --help\n  opencircuit -h";

#[derive(Debug, Clone, PartialEq, Eq)]
struct DhcpLeaseEntry {
    mac: Option<String>,
    hostname: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SeenRecord {
    ip: Ipv4Addr,
    first_seen_unix_s: u64,
    last_seen_unix_s: u64,
    hostname: Option<String>,
    hostname_source: Option<opencircuit::DiscoverySource>,
    open_ports: Vec<u16>,
    mac: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Presence {
    Online,
    RecentlySeen,
    Offline,
}

impl Presence {
    fn as_str(self) -> &'static str {
        match self {
            Self::Online => "online",
            Self::RecentlySeen => "recently_seen",
            Self::Offline => "offline",
        }
    }
}

fn run(args: &[String]) -> Result<String, String> {
    if args.len() < 2 {
        return Err(String::from(USAGE));
    }

    if args[1] == "help" || args[1] == "--help" || args[1] == "-h" {
        return Ok(String::from(USAGE));
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
            let mut recent_minutes = DEFAULT_RECENT_MINUTES;
            let mut state_file = String::from(DEFAULT_STATE_FILE);
            let mut dhcp_leases_path: Option<String> = None;
            let mut dhcp_leases_ssh: Option<String> = None;
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
                    "--recent-minutes" => {
                        if i + 1 >= args.len() {
                            return Err(String::from("Missing value for --recent-minutes"));
                        }
                        recent_minutes = args[i + 1]
                            .parse::<u64>()
                            .map_err(|_| String::from("Invalid --recent-minutes value"))?;
                        i += 2;
                    }
                    "--state-file" => {
                        if i + 1 >= args.len() {
                            return Err(String::from("Missing value for --state-file"));
                        }
                        state_file = args[i + 1].clone();
                        if state_file.trim().is_empty() {
                            return Err(String::from("--state-file cannot be empty"));
                        }
                        i += 2;
                    }
                    "--dhcp-leases" => {
                        if i + 1 >= args.len() {
                            return Err(String::from("Missing value for --dhcp-leases"));
                        }
                        let path = args[i + 1].trim();
                        if path.is_empty() {
                            return Err(String::from("--dhcp-leases cannot be empty"));
                        }
                        dhcp_leases_path = Some(path.to_string());
                        i += 2;
                    }
                    "--dhcp-leases-ssh" => {
                        if i + 1 >= args.len() {
                            return Err(String::from("Missing value for --dhcp-leases-ssh"));
                        }
                        let target = args[i + 1].trim();
                        if target.is_empty() {
                            return Err(String::from("--dhcp-leases-ssh cannot be empty"));
                        }
                        dhcp_leases_ssh = Some(target.to_string());
                        i += 2;
                    }
                    _ => return Err(String::from(USAGE)),
                }
            }

            if dhcp_leases_path.is_some() && dhcp_leases_ssh.is_some() {
                return Err(String::from(
                    "Use only one DHCP lease source: --dhcp-leases or --dhcp-leases-ssh",
                ));
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

            let now_unix_s = unix_now_secs();
            let (default_gateway, default_interface) = load_default_route();
            let neighbor_macs = load_neighbor_mac_map(default_interface.as_deref());
            let dhcp_leases = if let Some(remote_target) = dhcp_leases_ssh.as_deref() {
                load_dhcp_leases_from_ssh(remote_target)
                    .map_err(|err| format!("Scan failed: {err}"))?
            } else {
                load_dhcp_leases_map(dhcp_leases_path.as_deref())
                    .map_err(|err| format!("Scan failed: {err}"))?
            };
            let (target_ip, target_prefix) = parse_cidr(&config.cidr)
                .map_err(|err| format!("Scan failed: Invalid CIDR: {err}"))?;
            let gateway_neighbors: HashSet<Ipv4Addr> = neighbor_macs
                .keys()
                .copied()
                .filter(|ip| cidr_contains(target_ip, target_prefix, *ip).unwrap_or(false))
                .collect();
            let dhcp_neighbors: HashSet<Ipv4Addr> = dhcp_leases
                .keys()
                .copied()
                .filter(|ip| cidr_contains(target_ip, target_prefix, *ip).unwrap_or(false))
                .collect();
            let mut seen_records =
                load_seen_records(&state_file).map_err(|err| format!("Scan failed: {err}"))?;
            update_seen_records(&mut seen_records, &records, now_unix_s, &neighbor_macs);
            if let Err(err) = save_seen_records(&state_file, &seen_records) {
                eprintln!("[scan] warning: could not persist state cache: {err}");
            }

            let recent_window_s = recent_minutes.saturating_mul(60);
            let mut displayed_records: Vec<(
                opencircuit::DeviceRecord,
                Presence,
                Option<String>,
                &'static str,
            )> = Vec::new();

            for record in &records {
                let cached = seen_records.iter().find(|entry| entry.ip == record.ip);

                let gateway_seen = gateway_neighbors.contains(&record.ip);
                let dhcp_seen = dhcp_neighbors.contains(&record.ip);
                let presence = if record.status == opencircuit::DiscoveryStatus::Up
                    || gateway_seen
                    || dhcp_seen
                {
                    Presence::Online
                } else if recent_window_s > 0
                    && cached
                        .map(|entry| {
                            now_unix_s.saturating_sub(entry.last_seen_unix_s) <= recent_window_s
                        })
                        .unwrap_or(false)
                {
                    Presence::RecentlySeen
                } else {
                    Presence::Offline
                };

                let mut merged = record.clone();
                if let Some(cached) = cached {
                    if merged.hostname.is_none() {
                        merged.hostname = cached.hostname.clone();
                    }
                    if merged.hostname_source.is_none() {
                        merged.hostname_source = cached.hostname_source.clone();
                    }
                    if merged.open_ports.is_empty() {
                        merged.open_ports = cached.open_ports.clone();
                    }
                }
                if let Some(lease) = dhcp_leases.get(&record.ip) {
                    if merged.hostname.is_none() {
                        merged.hostname = lease.hostname.clone();
                    }
                    if merged.hostname_source.is_none() && lease.hostname.is_some() {
                        merged.hostname_source = Some(opencircuit::DiscoverySource::Aggregated);
                    }
                }

                let mac = neighbor_macs
                    .get(&record.ip)
                    .cloned()
                    .or_else(|| {
                        dhcp_leases
                            .get(&record.ip)
                            .and_then(|lease| lease.mac.clone())
                    })
                    .or_else(|| cached.and_then(|entry| entry.mac.clone()));
                let connectivity_source = if record.status == opencircuit::DiscoveryStatus::Up
                    && (gateway_seen || dhcp_seen)
                {
                    "both"
                } else if record.status == opencircuit::DiscoveryStatus::Up {
                    "active_probe"
                } else if dhcp_seen {
                    "dhcp_lease"
                } else if gateway_seen {
                    "gateway_table"
                } else if presence == Presence::RecentlySeen {
                    "recent_cache"
                } else {
                    "none"
                };
                if show_all || presence != Presence::Offline {
                    displayed_records.push((merged, presence, mac, connectivity_source));
                }
            }

            let mut lines = Vec::with_capacity(displayed_records.len() + 1);
            lines.push(format!(
                "scanned_hosts={} records={} shown={} elapsed_ms={} recent_minutes={} gateway_ip={} gateway_iface={} gateway_neighbors={} dhcp_leases={}",
                records.len(),
                records.len(),
                displayed_records.len(),
                elapsed_ms,
                recent_minutes,
                default_gateway
                    .map(|ip| ip.to_string())
                    .unwrap_or_else(|| String::from("-")),
                default_interface.unwrap_or_else(|| String::from("-")),
                gateway_neighbors.len(),
                dhcp_neighbors.len()
            ));

            for (record, presence, mac, connectivity_source) in displayed_records {
                let status = match record.status {
                    opencircuit::DiscoveryStatus::Up => "up",
                    opencircuit::DiscoveryStatus::Down => "down",
                    opencircuit::DiscoveryStatus::Unknown => "unknown",
                };
                let hostname = record.hostname.unwrap_or_else(|| String::from("-"));
                let hostname_source = record
                    .hostname_source
                    .as_ref()
                    .map(|source| match source {
                        opencircuit::DiscoverySource::Ping => "ping",
                        opencircuit::DiscoverySource::Neighbor => "neighbor",
                        opencircuit::DiscoverySource::TcpConnect => "tcp_connect",
                        opencircuit::DiscoverySource::Mdns => "mdns",
                        opencircuit::DiscoverySource::Netbios => "netbios",
                        opencircuit::DiscoverySource::ReverseDns => "reverse_dns",
                        opencircuit::DiscoverySource::Aggregated => "aggregated",
                    })
                    .unwrap_or("-");
                let hostname_confidence =
                    hostname_confidence_score(record.hostname_source.as_ref());
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
                let mac_display = mac.unwrap_or_else(|| String::from("-"));

                lines.push(format!(
                    "ip={} status={} presence={} connectivity_source={} hostname={} hostname_source={} hostname_confidence={} mac={} open_ports={}",
                    record.ip,
                    status,
                    presence.as_str(),
                    connectivity_source,
                    hostname,
                    hostname_source,
                    hostname_confidence,
                    mac_display,
                    ports
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

fn unix_now_secs() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs(),
        Err(_) => 0,
    }
}

fn discovery_source_to_tag(source: &opencircuit::DiscoverySource) -> &'static str {
    match source {
        opencircuit::DiscoverySource::Ping => "ping",
        opencircuit::DiscoverySource::Neighbor => "neighbor",
        opencircuit::DiscoverySource::TcpConnect => "tcp_connect",
        opencircuit::DiscoverySource::Mdns => "mdns",
        opencircuit::DiscoverySource::Netbios => "netbios",
        opencircuit::DiscoverySource::ReverseDns => "reverse_dns",
        opencircuit::DiscoverySource::Aggregated => "aggregated",
    }
}

fn tag_to_discovery_source(tag: &str) -> Option<opencircuit::DiscoverySource> {
    match tag {
        "ping" => Some(opencircuit::DiscoverySource::Ping),
        "neighbor" => Some(opencircuit::DiscoverySource::Neighbor),
        "tcp_connect" => Some(opencircuit::DiscoverySource::TcpConnect),
        "mdns" => Some(opencircuit::DiscoverySource::Mdns),
        "netbios" => Some(opencircuit::DiscoverySource::Netbios),
        "reverse_dns" => Some(opencircuit::DiscoverySource::ReverseDns),
        "aggregated" => Some(opencircuit::DiscoverySource::Aggregated),
        _ => None,
    }
}

fn parse_ports_for_cache(raw: &str) -> Vec<u16> {
    raw.split(',')
        .filter_map(|part| part.trim().parse::<u16>().ok())
        .filter(|port| *port > 0)
        .collect()
}

fn normalize_mac(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let lower = trimmed.to_ascii_lowercase();
    let valid = lower.len() == 17
        && lower.chars().enumerate().all(|(idx, ch)| {
            if [2, 5, 8, 11, 14].contains(&idx) {
                ch == ':'
            } else {
                ch.is_ascii_hexdigit()
            }
        });
    if valid {
        Some(lower)
    } else {
        None
    }
}

fn load_default_route() -> (Option<Ipv4Addr>, Option<String>) {
    let output = Command::new("ip")
        .args(["route"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output();

    let Ok(output) = output else {
        return (None, None);
    };
    if !output.status.success() {
        return (None, None);
    }

    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with("default") {
            continue;
        }

        let tokens: Vec<&str> = trimmed.split_whitespace().collect();
        let mut gateway = None;
        let mut iface = None;
        for idx in 0..tokens.len() {
            if tokens[idx] == "via" && idx + 1 < tokens.len() {
                gateway = tokens[idx + 1].parse::<Ipv4Addr>().ok();
            }
            if tokens[idx] == "dev" && idx + 1 < tokens.len() {
                iface = Some(tokens[idx + 1].to_string());
            }
        }

        return (gateway, iface);
    }

    (None, None)
}

fn load_neighbor_mac_map(interface: Option<&str>) -> HashMap<Ipv4Addr, String> {
    let mut command = Command::new("ip");
    if let Some(interface) = interface {
        command.args(["neigh", "show", "dev", interface]);
    } else {
        command.args(["neigh"]);
    }

    let output = command
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output();

    let mut map = HashMap::new();
    let Ok(output) = output else {
        return map;
    };
    if !output.status.success() {
        return map;
    }

    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        let upper = line.to_ascii_uppercase();
        if upper.contains(" INCOMPLETE") || upper.contains(" FAILED") {
            continue;
        }

        let mut parts = line.split_whitespace();
        let Some(ip_raw) = parts.next() else {
            continue;
        };
        let Ok(ip) = ip_raw.parse::<Ipv4Addr>() else {
            continue;
        };

        let tokens: Vec<&str> = line.split_whitespace().collect();
        for idx in 0..tokens.len() {
            if tokens[idx] == "lladdr" && idx + 1 < tokens.len() {
                if let Some(mac) = normalize_mac(tokens[idx + 1]) {
                    map.insert(ip, mac);
                }
                break;
            }
        }
    }

    map
}

fn hostname_confidence_score(source: Option<&opencircuit::DiscoverySource>) -> u8 {
    match source {
        Some(opencircuit::DiscoverySource::Mdns) => 95,
        Some(opencircuit::DiscoverySource::Netbios) => 92,
        Some(opencircuit::DiscoverySource::ReverseDns) => 90,
        _ => 0,
    }
}

fn parse_dhcp_lease_line(line: &str) -> Option<(Ipv4Addr, DhcpLeaseEntry)> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }

    let parts: Vec<&str> = trimmed.split_whitespace().collect();
    if parts.len() < 3 {
        return None;
    }

    let lease_like = parts[0].parse::<u64>().is_ok();
    if lease_like {
        let mac = normalize_mac(parts[1]);
        let ip = parts[2].parse::<Ipv4Addr>().ok()?;
        let hostname = if parts.len() >= 4 && parts[3] != "*" && !parts[3].is_empty() {
            Some(parts[3].to_string())
        } else {
            None
        };
        return Some((ip, DhcpLeaseEntry { mac, hostname }));
    }

    if parts.len() >= 2 {
        let ip = parts[0].parse::<Ipv4Addr>().ok()?;
        let mut mac = None;
        let mut hostname = None;
        for token in &parts[1..] {
            if mac.is_none() {
                mac = normalize_mac(token);
                if mac.is_some() {
                    continue;
                }
            }
            if hostname.is_none() && *token != "*" {
                hostname = Some((*token).to_string());
            }
        }
        return Some((ip, DhcpLeaseEntry { mac, hostname }));
    }

    None
}

fn load_dhcp_leases_map(path: Option<&str>) -> Result<HashMap<Ipv4Addr, DhcpLeaseEntry>, String> {
    let Some(path) = path else {
        return Ok(HashMap::new());
    };

    let content = fs::read_to_string(path)
        .map_err(|err| format!("could not read DHCP leases file '{path}': {err}"))?;

    let mut map = HashMap::new();
    for line in content.lines() {
        if let Some((ip, entry)) = parse_dhcp_lease_line(line) {
            map.insert(ip, entry);
        }
    }

    Ok(map)
}

fn parse_ssh_lease_target(target: &str) -> Result<(String, String), String> {
    let Some(separator_idx) = target.find(':') else {
        return Err(String::from(
            "Invalid --dhcp-leases-ssh value, expected user@host:/path/to/leases",
        ));
    };

    let host = target[..separator_idx].trim();
    let path = target[separator_idx + 1..].trim();
    if host.is_empty() || path.is_empty() {
        return Err(String::from(
            "Invalid --dhcp-leases-ssh value, expected user@host:/path/to/leases",
        ));
    }

    Ok((host.to_string(), path.to_string()))
}

fn load_dhcp_leases_from_ssh(target: &str) -> Result<HashMap<Ipv4Addr, DhcpLeaseEntry>, String> {
    let (host, path) = parse_ssh_lease_target(target)?;

    let output = Command::new("ssh")
        .args([
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=3",
            &host,
            "cat",
            &path,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|err| format!("failed to execute ssh for DHCP leases: {err}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let detail = stderr.trim();
        if detail.is_empty() {
            return Err(format!(
                "ssh command failed while loading DHCP leases from {host}"
            ));
        }
        return Err(format!(
            "ssh command failed while loading DHCP leases from {host}: {detail}"
        ));
    }

    let content = String::from_utf8_lossy(&output.stdout);
    let mut map = HashMap::new();
    for line in content.lines() {
        if let Some((ip, entry)) = parse_dhcp_lease_line(line) {
            map.insert(ip, entry);
        }
    }

    Ok(map)
}

fn load_seen_records(path: &str) -> Result<Vec<SeenRecord>, String> {
    let content = match fs::read_to_string(path) {
        Ok(content) => content,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => {
            return Err(format!("could not read state file '{path}': {err}"));
        }
    };

    let mut records = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let parts: Vec<&str> = trimmed.split('\t').collect();
        if parts.len() < 6 {
            continue;
        }

        let Ok(ip) = parts[0].parse::<Ipv4Addr>() else {
            continue;
        };
        let Ok(first_seen_unix_s) = parts[1].parse::<u64>() else {
            continue;
        };
        let Ok(last_seen_unix_s) = parts[2].parse::<u64>() else {
            continue;
        };

        let hostname = if parts[3] == "-" || parts[3].is_empty() {
            None
        } else {
            Some(parts[3].to_string())
        };

        let hostname_source = if parts[4] == "-" || parts[4].is_empty() {
            None
        } else {
            tag_to_discovery_source(parts[4])
        };

        let open_ports = if parts[5].is_empty() || parts[5] == "-" {
            Vec::new()
        } else {
            parse_ports_for_cache(parts[5])
        };

        let mac = if parts.len() >= 7 && !parts[6].is_empty() && parts[6] != "-" {
            normalize_mac(parts[6])
        } else {
            None
        };

        records.push(SeenRecord {
            ip,
            first_seen_unix_s,
            last_seen_unix_s,
            hostname,
            hostname_source,
            open_ports,
            mac,
        });
    }

    Ok(records)
}

fn save_seen_records(path: &str, records: &[SeenRecord]) -> Result<(), String> {
    let mut lines = Vec::with_capacity(records.len());

    for record in records {
        let hostname = record.hostname.clone().unwrap_or_else(|| String::from("-"));
        let hostname_source = record
            .hostname_source
            .as_ref()
            .map(discovery_source_to_tag)
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
        let mac = record.mac.clone().unwrap_or_else(|| String::from("-"));
        lines.push(format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}",
            record.ip,
            record.first_seen_unix_s,
            record.last_seen_unix_s,
            hostname,
            hostname_source,
            ports,
            mac
        ));
    }

    fs::write(path, lines.join("\n"))
        .map_err(|err| format!("could not write state file '{path}': {err}"))
}

fn update_seen_records(
    seen_records: &mut Vec<SeenRecord>,
    records: &[opencircuit::DeviceRecord],
    now_unix_s: u64,
    neighbor_macs: &HashMap<Ipv4Addr, String>,
) {
    for record in records {
        if record.status != opencircuit::DiscoveryStatus::Up {
            continue;
        }

        if let Some(existing) = seen_records.iter_mut().find(|entry| entry.ip == record.ip) {
            existing.last_seen_unix_s = now_unix_s;

            if let Some(hostname) = record
                .hostname
                .as_ref()
                .filter(|name| !name.trim().is_empty())
            {
                existing.hostname = Some(hostname.clone());
            }
            if record.hostname_source.is_some() {
                existing.hostname_source = record.hostname_source.clone();
            }
            if !record.open_ports.is_empty() {
                existing.open_ports = record.open_ports.clone();
            }
            if let Some(mac) = neighbor_macs.get(&record.ip) {
                existing.mac = Some(mac.clone());
            }
        } else {
            seen_records.push(SeenRecord {
                ip: record.ip,
                first_seen_unix_s: now_unix_s,
                last_seen_unix_s: now_unix_s,
                hostname: record.hostname.clone(),
                hostname_source: record.hostname_source.clone(),
                open_ports: record.open_ports.clone(),
                mac: neighbor_macs.get(&record.ip).cloned(),
            });
        }
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
