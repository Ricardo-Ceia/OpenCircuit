use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::process::Command;
use std::process::Stdio;

pub fn load_default_route() -> (Option<Ipv4Addr>, Option<String>) {
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

    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with("default") {
            continue;
        }

        let tokens: Vec<&str> = trimmed.split_whitespace().collect();
        let mut gateway = None;
        let mut iface = None;

        for (i, token) in tokens.iter().enumerate() {
            if *token == "via" && i + 1 < tokens.len() {
                gateway = tokens[i + 1].parse().ok();
            }
            if *token == "dev" && i + 1 < tokens.len() {
                iface = Some(tokens[i + 1].to_string());
            }
        }
        return (gateway, iface);
    }

    (None, None)
}

pub fn load_neighbor_macs(interface: Option<&str>) -> HashMap<Ipv4Addr, String> {
    let mut cmd = Command::new("ip");
    if let Some(iface) = interface {
        cmd.args(["neigh", "show", "dev", iface]);
    } else {
        cmd.arg("neigh");
    }

    let output = match cmd.stdout(Stdio::piped()).stderr(Stdio::null()).output() {
        Ok(o) => o,
        Err(_) => return HashMap::new(),
    };

    if !output.status.success() {
        return HashMap::new();
    }

    let mut map = HashMap::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let upper = line.to_ascii_uppercase();
        if upper.contains("INCOMPLETE") || upper.contains("FAILED") {
            continue;
        }

        let ip: Option<Ipv4Addr> = line.split_whitespace().next().and_then(|s| s.parse().ok());
        let Some(ip) = ip else {
            continue;
        };

        let tokens: Vec<&str> = line.split_whitespace().collect();
        for (i, token) in tokens.iter().enumerate() {
            if *token == "lladdr" && i + 1 < tokens.len() {
                if let Some(mac) = normalize_mac(tokens[i + 1]) {
                    map.insert(ip, mac);
                }
                break;
            }
        }
    }
    map
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
