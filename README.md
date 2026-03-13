# OpenCircuit

A professional, vendor-agnostic home network discovery tool written in Rust.

## Features

- **Device Discovery**: Scan your local network to find connected devices
- **Multiple Probe Types**: Ping, TCP Connect, mDNS, NetBIOS, Reverse DNS, ARP Neighbor
- **Authoritative Sources**: Import DHCP leases from your router for reliable device identity
- **Presence Tracking**: Remembers previously seen devices even when they're offline
- **Hostname Resolution**: Automatic hostname detection from multiple sources
- **Confidence Scoring**: Know the reliability of each device's identity

## Quick Start

```bash
# Build
cargo build --release

# Basic scan
cargo run -- scan 192.168.1.0/24

# Show all devices (including offline)
cargo run -- scan 192.168.1.0/24 --all

# With DHCP leases from your router (via SSH)
cargo run -- scan 192.168.1.0/24 --dhcp-leases-ssh root@192.168.1.1:/tmp/dhcp.leases

# With local DHCP lease file
cargo run -- scan 192.168.1.0/24 --dhcp-leases /path/to/leases.txt

# Fast scan (fewer ports, lower timeout)
cargo run -- scan 192.168.1.0/24 --fast

# Deep scan (comprehensive, longer)
cargo run -- scan 192.168.1.0/24 --deep
```

## Output Format

Each scan outputs key-value pairs:

```
scanned_hosts=254 records=254 shown=4 elapsed_ms=66251 recent_minutes=1440 gateway_ip=192.168.1.1 gateway_iface=eth0 gateway_neighbors=5 dhcp_leases=10
ip=192.168.1.1 status=up presence=online connectivity_source=active_probe hostname=router.home hostname_source=reverse_dns hostname_confidence=90 mac=xx:xx:xx:xx:xx:xx open_ports=53,80,139,445
```

### Field Meanings

| Field | Description |
|-------|-------------|
| `status` | Current probe result: `up`, `down`, `unknown` |
| `presence` | Online presence: `online`, `recently_seen`, `offline` |
| `connectivity_source` | How device was detected: `active_probe`, `gateway_table`, `dhcp_lease`, `both`, `recent_cache`, `none` |
| `hostname_confidence` | Identity confidence: `95` (mDNS), `92` (NetBIOS), `90` (Reverse DNS), `0` (unverified) |

## Scan Profiles

| Profile | Timeout | Concurrency | Ports |
|---------|---------|-------------|-------|
| `--fast` | 250ms | 128 | 53,80,443 |
| `--balanced` | 500ms | 64 | 22,53,80,139,443,445,8008,8009,8080 |
| `--deep` (default) | 1000ms | 96 | Many including 62078 (Apple devices) |

## Options

```
--all                  Show offline devices too
--no-dns              Disable DNS/mDNS/NetBIOS hostname probes
--fast | --balanced | --deep   Scan profile (default: --deep)
--ports <csv>         Override TCP ports
--timeout-ms <n>      Per-probe timeout in milliseconds
--concurrency <n>     Concurrent host probes
--recent-minutes <n>  Keep recently seen devices visible (default: 1440)
--state-file <path>   Local state cache file
--dhcp-leases <path> Local DHCP lease file
--dhcp-leases-ssh <user@host:/path>  Fetch DHCP leases via SSH
```

## Building

```bash
# Development
cargo build

# Release (optimized)
cargo build --release

# Run tests
cargo test
```

## Use Cases

- **Home network mapping**: See all devices on your network
- **Device monitoring**: Track which devices are online
- **Troubleshooting**: Find IP addresses of known devices
- **Integration**: Use with home automation (JSON output coming soon)

## Why "bulletproof"?

- Strict hostname policy: Only verified hostnames are shown
- Confidence scoring: Know how reliable each identity is
- Multiple sources: Combine probes with router data for best coverage
- Persistence: Remember devices even when they go offline
