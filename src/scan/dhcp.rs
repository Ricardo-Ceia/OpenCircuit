use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::process::Command;
use std::process::Stdio;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhcpLeaseEntry {
    pub mac: Option<String>,
    pub hostname: Option<String>,
}

pub fn load_dhcp_leases(path: &str) -> Result<HashMap<Ipv4Addr, DhcpLeaseEntry>, String> {
    let content = std::fs::read_to_string(path).map_err(|e| format!("Read failed: {e}"))?;

    let mut map = HashMap::new();
    for line in content.lines() {
        if let Some((ip, entry)) = parse_lease_line(line) {
            map.insert(ip, entry);
        }
    }
    Ok(map)
}

pub fn load_dhcp_leases_ssh(target: &str) -> Result<HashMap<Ipv4Addr, DhcpLeaseEntry>, String> {
    let (host, path) = parse_ssh_target(target)?;

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
        .map_err(|e| format!("SSH failed: {e}"))?;

    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        return Err(format!("SSH error: {}", err));
    }

    let content = String::from_utf8_lossy(&output.stdout);
    let mut map = HashMap::new();
    for line in content.lines() {
        if let Some((ip, entry)) = parse_lease_line(line) {
            map.insert(ip, entry);
        }
    }
    Ok(map)
}

fn parse_ssh_target(target: &str) -> Result<(String, String), String> {
    let idx = target.find(':').ok_or("Invalid format: user@host:/path")?;
    let host = target[..idx].trim();
    let path = target[idx + 1..].trim();
    if host.is_empty() || path.is_empty() {
        return Err("Invalid format: user@host:/path".to_string());
    }
    Ok((host.to_string(), path.to_string()))
}

fn parse_lease_line(line: &str) -> Option<(Ipv4Addr, DhcpLeaseEntry)> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }

    let parts: Vec<&str> = trimmed.split_whitespace().collect();
    if parts.len() < 3 {
        return None;
    }

    // Try format: timestamp mac ip [hostname]
    if parts[0].parse::<u64>().is_ok() {
        let mac: Option<String> = normalize_mac(parts[1]);
        let ip: Ipv4Addr = parts[2].parse().ok()?;
        let hostname: Option<String> = if parts.len() >= 4 && parts[3] != "*" {
            Some(parts[3].to_string())
        } else {
            None
        };
        return Some((ip, DhcpLeaseEntry { mac, hostname }));
    }

    // Try format: ip mac [hostname]
    if let Ok(ip) = parts[0].parse::<Ipv4Addr>() {
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

fn normalize_mac(raw: &str) -> Option<String> {
    let s = raw.trim().to_ascii_lowercase();
    if s.len() != 17 {
        return None;
    }
    let valid = s.chars().enumerate().all(|(i, c)| {
        if [2, 5, 8, 11, 14].contains(&i) {
            c == ':'
        } else {
            c.is_ascii_hexdigit()
        }
    });
    if valid {
        Some(s)
    } else {
        None
    }
}
