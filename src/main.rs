use std::collections::HashMap;
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

const USAGE: &str = "Usage:\n  opencircuit normalize <ipv4-cidr>\n  opencircuit info <ipv4-cidr>\n  opencircuit contains <ipv4-cidr> <ipv4-address>\n  opencircuit usable <ipv4-cidr> <ipv4-address>\n  opencircuit next <ipv4-address>\n  opencircuit prev <ipv4-address>\n  opencircuit classify <ipv4-address>\n  opencircuit classify-cidr <ipv4-cidr>\n  opencircuit summary <ipv4-cidr>\n  opencircuit masks <ipv4-cidr>\n  opencircuit range <ipv4-cidr>\n  opencircuit overlap <ipv4-cidr-a> <ipv4-cidr-b>\n  opencircuit relation <ipv4-cidr-a> <ipv4-cidr-b>\n  opencircuit scan <ipv4-cidr> [--all] [--no-dns] [--deep|--balanced|--fast] [--ports <csv>] [--timeout-ms <n>] [--concurrency <n>] [--recent-minutes <n>] [--state-file <path>]";

#[derive(Debug, Clone, PartialEq, Eq)]
struct SeenRecord {
    ip: Ipv4Addr,
    first_seen_unix_s: u64,
    last_seen_unix_s: u64,
    hostname: Option<String>,
    hostname_source: Option<opencircuit::DiscoverySource>,
    open_ports: Vec<u16>,
    mac: Option<String>,
    device_hint: Option<String>,
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

            let now_unix_s = unix_now_secs();
            let neighbor_macs = load_neighbor_mac_map();
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
                Option<String>,
                String,
            )> = Vec::new();

            for record in &records {
                let cached = seen_records.iter().find(|entry| entry.ip == record.ip);

                let presence = if record.status == opencircuit::DiscoveryStatus::Up {
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

                let mac = neighbor_macs
                    .get(&record.ip)
                    .cloned()
                    .or_else(|| cached.and_then(|entry| entry.mac.clone()));
                let device_hint = infer_device_hint(&merged.open_ports)
                    .or_else(|| cached.and_then(|entry| entry.device_hint.clone()));
                let display_name = build_display_name(
                    record.ip,
                    merged.hostname.as_deref(),
                    device_hint.as_deref(),
                    mac.as_deref(),
                );

                if show_all || presence != Presence::Offline {
                    displayed_records.push((merged, presence, mac, device_hint, display_name));
                }
            }

            let mut lines = Vec::with_capacity(displayed_records.len() + 1);
            lines.push(format!(
                "scanned_hosts={} records={} shown={} elapsed_ms={} recent_minutes={}",
                records.len(),
                records.len(),
                displayed_records.len(),
                elapsed_ms,
                recent_minutes
            ));

            for (record, presence, mac, device_hint, display_name) in displayed_records {
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
                        opencircuit::DiscoverySource::Neighbor => "neighbor",
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
                let mac_display = mac.unwrap_or_else(|| String::from("-"));
                let hint_display = device_hint.unwrap_or_else(|| String::from("-"));

                lines.push(format!(
                    "ip={} status={} presence={} display_name={} hostname={} hostname_source={} mac={} device_hint={} open_ports={}",
                    record.ip,
                    status,
                    presence.as_str(),
                    display_name,
                    hostname,
                    hostname_source,
                    mac_display,
                    hint_display,
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

fn load_neighbor_mac_map() -> HashMap<Ipv4Addr, String> {
    let output = Command::new("ip")
        .args(["neigh"])
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

fn infer_device_hint(open_ports: &[u16]) -> Option<String> {
    if open_ports.contains(&62078) {
        return Some(String::from("apple_mobile_likely"));
    }
    if open_ports.contains(&8008) && open_ports.contains(&8009) {
        return Some(String::from("chromecast_or_tv_likely"));
    }
    if open_ports.contains(&445) || open_ports.contains(&139) {
        return Some(String::from("windows_or_samba_likely"));
    }
    None
}

fn short_mac_suffix(mac: &str) -> String {
    mac.split(':')
        .rev()
        .take(2)
        .collect::<Vec<&str>>()
        .into_iter()
        .rev()
        .collect::<Vec<&str>>()
        .join("")
}

fn build_display_name(
    ip: Ipv4Addr,
    hostname: Option<&str>,
    device_hint: Option<&str>,
    mac: Option<&str>,
) -> String {
    if let Some(name) = hostname.map(str::trim).filter(|name| !name.is_empty()) {
        return name.to_string();
    }

    if let Some(hint) = device_hint {
        if let Some(mac) = mac {
            return format!("{}-{}", hint, short_mac_suffix(mac));
        }
        return hint.to_string();
    }

    if let Some(mac) = mac {
        return format!("unknown-{}", short_mac_suffix(mac));
    }

    format!("unknown-{ip}")
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

        let device_hint = if parts.len() >= 8 && !parts[7].is_empty() && parts[7] != "-" {
            Some(parts[7].to_string())
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
            device_hint,
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
        let device_hint = record
            .device_hint
            .clone()
            .unwrap_or_else(|| String::from("-"));

        lines.push(format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            record.ip,
            record.first_seen_unix_s,
            record.last_seen_unix_s,
            hostname,
            hostname_source,
            ports,
            mac,
            device_hint
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
            let hint = infer_device_hint(&record.open_ports);
            if hint.is_some() {
                existing.device_hint = hint;
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
                device_hint: infer_device_hint(&record.open_ports),
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
