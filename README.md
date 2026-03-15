# OpenCircuit

A simple, professional home network discovery tool written in Go.

## Features

- **Automatic broad scanning** - Scans all common ports without flags
- **Multiple detection methods** - Neighbor table, DHCP leases, TCP probes, ping, DNS
- **Recent device memory** - Remembers devices even when offline
- **Zero configuration** - Just run `opencircuit scan <cidr>`

## Installation

```bash
# Build
go build -o opencircuit .

# Or install globally
sudo mv opencircuit /usr/local/bin/
```

## Usage

```bash
# Scan your network
opencircuit scan 192.168.1.0/24

# Show help
opencircuit help
```

## Output

```
scanned_hosts=254 shown=4
ip=192.168.1.1 status=up hostname=router ports=80,443
ip=192.168.1.9 status=recently_seen hostname=- ports=62078
```

## How It Works

1. **Neighbor Table** - Checks local ARP cache first (fastest)
2. **DHCP Leases** - Reads common lease files automatically
3. **TCP Probes** - Scans common ports (22, 53, 80, 443, etc.)
4. **Ping** - Fallback to ICMP ping
5. **Reverse DNS** - Gets hostname if available

Shows only devices that are:
- **up** - Currently responding
- **recently_seen** - In DHCP lease table but not currently responding

## Why Go?

- **Small binary** - Single static executable, runs on low-resource devices
- **Fast** - Native performance
- **Simple** - No dependencies, easy to build
- **Memory safe** - No manual memory management
