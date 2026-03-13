use std::collections::{HashMap, HashSet};
use std::env;
use std::net::Ipv4Addr;
use std::time::Instant;

use opencircuit::{
    cidr_contains, is_link_local_ipv4, is_loopback_ipv4, is_multicast_ipv4, is_private_ipv4,
    is_usable_host, network_bounds, parse_and_normalize_cidr, parse_cidr,
    run_discovery_with_probes_and_progress, run_discovery_with_progress, total_address_count,
    usable_host_count, usable_host_range, DiscoverySource, DiscoveryStatus, TcpConnectProbe,
};

use opencircuit::cli::{is_help_arg, USAGE};
use opencircuit::scan::{cache, config, dhcp, network, output::Header, output::Presence};

fn main() {
    let args: Vec<String> = env::args().collect();
    match run(&args) {
        Ok(out) => println!("{out}"),
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
}

fn run(args: &[String]) -> Result<String, String> {
    if args.len() < 2 {
        return Err(USAGE.to_string());
    }
    if is_help_arg(&args[1]) {
        return Ok(USAGE.to_string());
    }

    match args[1].as_str() {
        "normalize" => cmd_normalize(&args[2..]),
        "info" => cmd_info(&args[2..]),
        "contains" => cmd_contains(&args[2..]),
        "usable" => cmd_usable(&args[2..]),
        "next" => cmd_next(&args[2..]),
        "prev" => cmd_prev(&args[2..]),
        "classify" => cmd_classify(&args[2..]),
        "classify-cidr" => cmd_classify_cidr(&args[2..]),
        "summary" => cmd_summary(&args[2..]),
        "masks" => cmd_masks(&args[2..]),
        "range" => cmd_range(&args[2..]),
        "overlap" => cmd_overlap(&args[2..]),
        "relation" => cmd_relation(&args[2..]),
        "scan" => cmd_scan(&args[1..]),
        _ => Err(USAGE.to_string()),
    }
}

fn cmd_normalize(args: &[String]) -> Result<String, String> {
    ensure_len(args, 1)?;
    parse_and_normalize_cidr(&args[0]).map_err(|e| format!("Invalid CIDR: {e}"))
}

fn cmd_info(args: &[String]) -> Result<String, String> {
    ensure_len(args, 1)?;
    let (ip, prefix) = parse_cidr(&args[0]).map_err(|e| format!("Invalid CIDR: {e}"))?;
    let normalized =
        parse_and_normalize_cidr(&args[0]).map_err(|e| format!("Invalid CIDR: {e}"))?;
    let (network, broadcast) =
        network_bounds(ip, prefix).map_err(|e| format!("Invalid CIDR: {e}"))?;
    let (first, last) = usable_host_range(ip, prefix).map_err(|e| format!("Invalid CIDR: {e}"))?;
    Ok(format!("cidr={normalized}\nnetwork={network}\nbroadcast={broadcast}\nfirst_usable={first}\nlast_usable={last}"))
}

fn cmd_contains(args: &[String]) -> Result<String, String> {
    ensure_len(args, 2)?;
    let (ip, prefix) = parse_cidr(&args[0]).map_err(|e| format!("Invalid CIDR: {e}"))?;
    let candidate = args[1]
        .parse::<Ipv4Addr>()
        .map_err(|_| "Invalid IPv4 address")?;
    cidr_contains(ip, prefix, candidate)
        .map_err(|e| format!("Invalid CIDR: {e}"))
        .map(|b| b.to_string())
}

fn cmd_usable(args: &[String]) -> Result<String, String> {
    ensure_len(args, 2)?;
    let (ip, prefix) = parse_cidr(&args[0]).map_err(|e| format!("Invalid CIDR: {e}"))?;
    let candidate = args[1]
        .parse::<Ipv4Addr>()
        .map_err(|_| "Invalid IPv4 address")?;
    is_usable_host(ip, prefix, candidate)
        .map_err(|e| format!("Invalid CIDR: {e}"))
        .map(|b| b.to_string())
}

fn cmd_next(args: &[String]) -> Result<String, String> {
    ensure_len(args, 1)?;
    let ip = args[0]
        .parse::<Ipv4Addr>()
        .map_err(|_| "Invalid IPv4 address")?;
    opencircuit::net::address::next_ipv4(ip)
        .ok_or_else(|| "No next IPv4 address".to_string())
        .map(|i| i.to_string())
}

fn cmd_prev(args: &[String]) -> Result<String, String> {
    ensure_len(args, 1)?;
    let ip = args[0]
        .parse::<Ipv4Addr>()
        .map_err(|_| "Invalid IPv4 address")?;
    opencircuit::net::address::prev_ipv4(ip)
        .ok_or_else(|| "No previous IPv4 address".to_string())
        .map(|i| i.to_string())
}

fn cmd_classify(args: &[String]) -> Result<String, String> {
    ensure_len(args, 1)?;
    let ip = args[0]
        .parse::<Ipv4Addr>()
        .map_err(|_| "Invalid IPv4 address")?;
    Ok(format!(
        "ip={ip}\nprivate={}\nlink_local={}\nloopback={}\nmulticast={}",
        is_private_ipv4(ip),
        is_link_local_ipv4(ip),
        is_loopback_ipv4(ip),
        is_multicast_ipv4(ip)
    ))
}

fn cmd_classify_cidr(args: &[String]) -> Result<String, String> {
    ensure_len(args, 1)?;
    let (ip, prefix) = parse_cidr(&args[0]).map_err(|e| format!("Invalid CIDR: {e}"))?;
    let normalized =
        parse_and_normalize_cidr(&args[0]).map_err(|e| format!("Invalid CIDR: {e}"))?;
    let (network, broadcast) =
        network_bounds(ip, prefix).map_err(|e| format!("Invalid CIDR: {e}"))?;
    Ok(format!(
        "cidr={normalized}\nnetwork={network}\nbroadcast={broadcast}\nprivate={}\nlink_local={}\nloopback={}\nmulticast={}",
        is_private_ipv4(network),
        is_link_local_ipv4(network),
        is_loopback_ipv4(network),
        is_multicast_ipv4(network)
    ))
}

fn cmd_summary(args: &[String]) -> Result<String, String> {
    ensure_len(args, 1)?;
    let (_, prefix) = parse_cidr(&args[0]).map_err(|e| format!("Invalid CIDR: {e}"))?;
    let normalized =
        parse_and_normalize_cidr(&args[0]).map_err(|e| format!("Invalid CIDR: {e}"))?;
    let total = total_address_count(prefix).map_err(|e| format!("Invalid CIDR: {e}"))?;
    let usable = usable_host_count(prefix).map_err(|e| format!("Invalid CIDR: {e}"))?;
    Ok(format!("cidr={normalized} total={total} usable={usable}"))
}

fn cmd_masks(args: &[String]) -> Result<String, String> {
    ensure_len(args, 1)?;
    let (_, prefix) = parse_cidr(&args[0]).map_err(|e| format!("Invalid CIDR: {e}"))?;
    let normalized =
        parse_and_normalize_cidr(&args[0]).map_err(|e| format!("Invalid CIDR: {e}"))?;
    let subnet =
        opencircuit::net::math::subnet_mask(prefix).map_err(|e| format!("Invalid CIDR: {e}"))?;
    let wildcard =
        opencircuit::net::math::wildcard_mask(prefix).map_err(|e| format!("Invalid CIDR: {e}"))?;
    Ok(format!(
        "cidr={normalized}\nprefix={prefix}\nsubnet_mask={subnet}\nwildcard_mask={wildcard}"
    ))
}

fn cmd_range(args: &[String]) -> Result<String, String> {
    ensure_len(args, 1)?;
    let (ip, prefix) = parse_cidr(&args[0]).map_err(|e| format!("Invalid CIDR: {e}"))?;
    let normalized =
        parse_and_normalize_cidr(&args[0]).map_err(|e| format!("Invalid CIDR: {e}"))?;
    let (first, last) = usable_host_range(ip, prefix).map_err(|e| format!("Invalid CIDR: {e}"))?;
    let usable = usable_host_count(prefix).map_err(|e| format!("Invalid CIDR: {e}"))?;
    Ok(format!(
        "cidr={normalized}\nfirst={first}\nlast={last}\nusable={usable}"
    ))
}

fn cmd_overlap(args: &[String]) -> Result<String, String> {
    ensure_len(args, 2)?;
    let (a_ip, a_pfx) = parse_cidr(&args[0]).map_err(|e| format!("Invalid CIDR: {e}"))?;
    let (b_ip, b_pfx) = parse_cidr(&args[1]).map_err(|e| format!("Invalid CIDR: {e}"))?;
    let (a_start, a_end) = network_bounds(a_ip, a_pfx).map_err(|e| format!("Invalid CIDR: {e}"))?;
    let (b_start, b_end) = network_bounds(b_ip, b_pfx).map_err(|e| format!("Invalid CIDR: {e}"))?;
    let overlaps = u32::from(a_start) <= u32::from(b_end) && u32::from(b_start) <= u32::from(a_end);
    Ok(overlaps.to_string())
}

fn cmd_relation(args: &[String]) -> Result<String, String> {
    ensure_len(args, 2)?;
    let (a_ip, a_pfx) = parse_cidr(&args[0]).map_err(|e| format!("Invalid CIDR: {e}"))?;
    let (b_ip, b_pfx) = parse_cidr(&args[1]).map_err(|e| format!("Invalid CIDR: {e}"))?;
    let (a_start, a_end) = network_bounds(a_ip, a_pfx).map_err(|e| format!("Invalid CIDR: {e}"))?;
    let (b_start, b_end) = network_bounds(b_ip, b_pfx).map_err(|e| format!("Invalid CIDR: {e}"))?;
    let a_start = u32::from(a_start);
    let a_end = u32::from(a_end);
    let b_start = u32::from(b_start);
    let b_end = u32::from(b_end);

    let rel = if a_start == b_start && a_end == b_end {
        "equal"
    } else if a_start <= b_start && a_end >= b_end {
        "a_contains_b"
    } else if b_start <= a_start && b_end >= a_end {
        "b_contains_a"
    } else if a_start <= b_end && b_start <= a_end {
        "overlap"
    } else {
        "disjoint"
    };
    Ok(rel.to_string())
}

fn cmd_scan(args: &[String]) -> Result<String, String> {
    let cfg = config::parse_scan_args(args)?;

    let started = Instant::now();
    let mut progress = |cur: usize, total: usize, ip: Ipv4Addr| {
        eprintln!("[scan] probing {cur}/{total}: {ip}");
    };

    let records = if cfg.no_dns {
        let tcp = TcpConnectProbe::new(cfg.discovery.ports.clone(), cfg.discovery.timeout);
        run_discovery_with_probes_and_progress(&cfg.discovery, 1024, &[&tcp], &mut progress)
            .map_err(|e| format!("Scan failed: {e}"))?
    } else {
        run_discovery_with_progress(&cfg.discovery, 1024, &mut progress)
            .map_err(|e| format!("Scan failed: {e}"))?
    };

    let elapsed = started.elapsed().as_millis();
    let now = cache::unix_now_secs();

    let (gateway_ip, gateway_iface) = network::load_default_route();
    let neighbor_macs = network::load_neighbor_macs(gateway_iface.as_deref());

    let dhcp_leases = if let Some(ref ssh) = cfg.dhcp_leases_ssh {
        dhcp::load_dhcp_leases_ssh(ssh)?
    } else if let Some(ref path) = cfg.dhcp_leases_path {
        dhcp::load_dhcp_leases(path)?
    } else {
        HashMap::new()
    };

    let target_range = parse_cidr(&cfg.discovery.cidr).map_err(|e| format!("Invalid CIDR: {e}"))?;
    let gateway_neighbors: HashSet<_> = neighbor_macs
        .keys()
        .filter(|ip| cidr_contains(target_range.0, target_range.1, **ip).unwrap_or(false))
        .copied()
        .collect();
    let dhcp_in_range: HashSet<_> = dhcp_leases
        .keys()
        .filter(|ip| cidr_contains(target_range.0, target_range.1, **ip).unwrap_or(false))
        .copied()
        .collect();

    let mut seen = cache::load_seen_cache(&cfg.state_file).unwrap_or_default();
    update_seen_cache(&mut seen, &records, now, &neighbor_macs, &dhcp_leases);
    let seen_vec: Vec<_> = seen.values().cloned().collect();
    let _ = cache::save_seen_cache(&cfg.state_file, &seen_vec);

    let recent_window = cfg.recent_minutes.saturating_mul(60);
    let mut output_records = Vec::new();

    for record in &records {
        let cached = seen.get(&record.ip);
        let in_gateway = gateway_neighbors.contains(&record.ip);
        let in_dhcp = dhcp_in_range.contains(&record.ip);

        let presence = if record.status == DiscoveryStatus::Up || in_gateway || in_dhcp {
            Presence::Online
        } else if recent_window > 0
            && cached
                .map(|c| now.saturating_sub(c.last_seen_unix_s) <= recent_window)
                .unwrap_or(false)
        {
            Presence::RecentlySeen
        } else {
            Presence::Offline
        };

        if !cfg.show_all && presence == Presence::Offline {
            continue;
        }

        let connectivity = if record.status == DiscoveryStatus::Up && (in_gateway || in_dhcp) {
            "both"
        } else if record.status == DiscoveryStatus::Up {
            "active_probe"
        } else if in_dhcp {
            "dhcp_lease"
        } else if in_gateway {
            "gateway_table"
        } else if presence == Presence::RecentlySeen {
            "recent_cache"
        } else {
            "none"
        };

        let hostname = record
            .hostname
            .clone()
            .or_else(|| cached.and_then(|c| c.hostname.clone()))
            .or_else(|| dhcp_leases.get(&record.ip).and_then(|e| e.hostname.clone()));

        let hostname_source = if record.hostname_source.is_some() {
            record.hostname_source.clone()
        } else if dhcp_leases
            .get(&record.ip)
            .map(|e| e.hostname.is_some())
            .unwrap_or(false)
        {
            Some(DiscoverySource::Aggregated)
        } else {
            cached.and_then(|c| c.hostname_source.clone())
        };

        let mac = neighbor_macs
            .get(&record.ip)
            .cloned()
            .or_else(|| dhcp_leases.get(&record.ip).and_then(|e| e.mac.clone()))
            .or_else(|| cached.and_then(|c| c.mac.clone()));

        let open_ports = if !record.open_ports.is_empty() {
            record.open_ports.clone()
        } else {
            cached.map(|c| c.open_ports.clone()).unwrap_or_default()
        };

        let merged = opencircuit::DeviceRecord {
            ip: record.ip,
            status: record.status.clone(),
            hostname,
            hostname_source,
            latency_ms: record.latency_ms,
            open_ports,
            sources: record.sources.clone(),
            first_seen_at: record.first_seen_at,
            last_seen_at: record.last_seen_at,
        };

        use opencircuit::scan::output::OutputRecord;
        output_records.push(OutputRecord::from_record(
            &merged,
            presence,
            connectivity,
            mac,
        ));
    }

    let header = Header {
        scanned_hosts: records.len(),
        shown: output_records.len(),
        elapsed_ms: elapsed,
        recent_minutes: cfg.recent_minutes,
        gateway_ip: gateway_ip
            .map(|i| i.to_string())
            .unwrap_or_else(|| "-".to_string()),
        gateway_iface: gateway_iface.unwrap_or_else(|| "-".to_string()),
        gateway_neighbors: gateway_neighbors.len(),
        dhcp_leases: dhcp_in_range.len(),
    };

    let lines: Vec<String> = std::iter::once(header.format())
        .chain(output_records.into_iter().map(|r| r.format()))
        .collect();

    Ok(lines.join("\n"))
}

fn ensure_len(args: &[String], len: usize) -> Result<(), String> {
    if args.len() != len {
        return Err(USAGE.to_string());
    }
    Ok(())
}

fn update_seen_cache(
    seen: &mut HashMap<Ipv4Addr, cache::SeenRecord>,
    records: &[opencircuit::DeviceRecord],
    now: u64,
    neighbor_macs: &HashMap<Ipv4Addr, String>,
    dhcp_leases: &HashMap<Ipv4Addr, dhcp::DhcpLeaseEntry>,
) {
    for record in records {
        if record.status != DiscoveryStatus::Up {
            continue;
        }

        let entry = seen.entry(record.ip).or_insert_with(|| cache::SeenRecord {
            ip: record.ip,
            first_seen_unix_s: now,
            last_seen_unix_s: now,
            hostname: None,
            hostname_source: None,
            open_ports: Vec::new(),
            mac: None,
        });

        entry.last_seen_unix_s = now;

        if let Some(ref h) = record.hostname {
            if !h.trim().is_empty() {
                entry.hostname = Some(h.clone());
            }
        }
        if record.hostname_source.is_some() {
            entry.hostname_source = record.hostname_source.clone();
        }
        if !record.open_ports.is_empty() {
            entry.open_ports = record.open_ports.clone();
        }
        if let Some(m) = neighbor_macs.get(&record.ip) {
            entry.mac = Some(m.clone());
        }
        if let Some(lease) = dhcp_leases.get(&record.ip) {
            if entry.mac.is_none() {
                entry.mac = lease.mac.clone();
            }
        }
    }
}
