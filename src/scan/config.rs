use std::time::Duration;

use crate::DiscoveryConfig;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScanProfile {
    Fast,
    Balanced,
    Deep,
}

impl Default for ScanProfile {
    fn default() -> Self {
        Self::Deep
    }
}

impl ScanProfile {
    pub fn apply_to_config(self, config: &mut DiscoveryConfig) {
        match self {
            Self::Fast => {
                config.timeout = Duration::from_millis(250);
                config.concurrency = 128;
                config.ports = vec![53, 80, 443];
            }
            Self::Balanced => {
                config.timeout = Duration::from_millis(500);
                config.concurrency = 64;
                config.ports = vec![22, 53, 80, 139, 443, 445, 8008, 8009, 8080];
            }
            Self::Deep => {
                config.timeout = Duration::from_millis(1000);
                config.concurrency = 96;
                config.ports = vec![
                    22, 53, 80, 123, 139, 443, 445, 554, 631, 1900, 5000, 7000, 7100, 8008, 8009,
                    8080, 8443, 8888, 62078,
                ];
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub discovery: DiscoveryConfig,
    pub show_all: bool,
    pub no_dns: bool,
    pub profile: ScanProfile,
    pub recent_minutes: u64,
    pub state_file: String,
    pub dhcp_leases_path: Option<String>,
    pub dhcp_leases_ssh: Option<String>,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            discovery: DiscoveryConfig::default(),
            show_all: false,
            no_dns: false,
            profile: ScanProfile::default(),
            recent_minutes: 24 * 60,
            state_file: ".opencircuit-seen-cache.tsv".to_string(),
            dhcp_leases_path: None,
            dhcp_leases_ssh: None,
        }
    }
}

pub fn parse_scan_args(args: &[String]) -> Result<ScanConfig, String> {
    if args.len() < 2 {
        return Err(crate::cli::USAGE.to_string());
    }

    let mut config = ScanConfig::default();
    config.discovery.cidr = args[1].clone();

    let mut i = 2;
    let mut profile_set = false;
    while i < args.len() {
        match args[i].as_str() {
            "--all" => config.show_all = true,
            "--no-dns" => config.no_dns = true,
            "--fast" => {
                if profile_set {
                    return Err("Only one scan profile can be selected".to_string());
                }
                config.profile = ScanProfile::Fast;
                profile_set = true;
            }
            "--balanced" => {
                if profile_set {
                    return Err("Only one scan profile can be selected".to_string());
                }
                config.profile = ScanProfile::Balanced;
                profile_set = true;
            }
            "--deep" => {
                if profile_set {
                    return Err("Only one scan profile can be selected".to_string());
                }
                config.profile = ScanProfile::Deep;
                profile_set = true;
            }
            "--ports" => {
                config.discovery.ports =
                    parse_ports(&args[i + 1]).map_err(|_| "Invalid --ports list".to_string())?;
                i += 2;
                continue;
            }
            "--timeout-ms" => {
                let val: u64 = parse_num(&args[i + 1])
                    .map_err(|_| "--timeout-ms must be greater than zero".to_string())?;
                if val == 0 {
                    return Err("--timeout-ms must be greater than zero".to_string());
                }
                config.discovery.timeout = Duration::from_millis(val);
                i += 2;
                continue;
            }
            "--concurrency" => {
                let val: usize = parse_num(&args[i + 1])
                    .map_err(|_| "--concurrency must be greater than zero".to_string())?;
                if val == 0 {
                    return Err("--concurrency must be greater than zero".to_string());
                }
                config.discovery.concurrency = val;
                i += 2;
                continue;
            }
            "--recent-minutes" => {
                config.recent_minutes = parse_num(&args[i + 1])
                    .map_err(|_| "Invalid --recent-minutes value".to_string())?;
                i += 2;
                continue;
            }
            "--state-file" => {
                let val = args[i + 1].trim();
                if val.is_empty() {
                    return Err("--state-file cannot be empty".to_string());
                }
                config.state_file = val.to_string();
                i += 2;
                continue;
            }
            "--dhcp-leases" => {
                let val = args[i + 1].trim();
                if val.is_empty() {
                    return Err("--dhcp-leases cannot be empty".to_string());
                }
                config.dhcp_leases_path = Some(val.to_string());
                i += 2;
                continue;
            }
            "--dhcp-leases-ssh" => {
                let val = args[i + 1].trim();
                if val.is_empty() {
                    return Err("--dhcp-leases-ssh cannot be empty".to_string());
                }
                config.dhcp_leases_ssh = Some(val.to_string());
                i += 2;
                continue;
            }
            _ => return Err("Usage:".to_string()),
        }
        i += 1;
    }

    if config.dhcp_leases_path.is_some() && config.dhcp_leases_ssh.is_some() {
        return Err(
            "Use only one DHCP lease source: --dhcp-leases or --dhcp-leases-ssh".to_string(),
        );
    }

    config.profile.apply_to_config(&mut config.discovery);
    Ok(config)
}

fn parse_ports(raw: &str) -> Result<Vec<u16>, String> {
    let mut ports = Vec::new();
    for part in raw.split(',') {
        let port = part
            .trim()
            .parse()
            .map_err(|_| "Invalid port number".to_string())?;
        if port == 0 {
            return Err("Ports must be 1-65535".to_string());
        }
        ports.push(port);
    }
    Ok(ports)
}

fn parse_num<T: std::str::FromStr>(raw: &str) -> Result<T, String> {
    raw.parse().map_err(|_| "Invalid number".to_string())
}
