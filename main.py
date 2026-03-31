import socket
import subprocess
import concurrent.futures
import struct
import logging
import platform
import re
import time
import threading
import os
import sys
from mac_vendors import MAC_VENDORS
from device_history import load_history, save_history, merge_scan, format_last_seen, get_history_as_list, get_history_stats, _get_retention_hours

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

IS_WINDOWS = platform.system() == "Windows"
IS_LINUX   = platform.system() == "Linux"

def get_default_iface_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "0.0.0.0"

def generate_ips(subnet: str) -> list[str]:
    base_ip, prefix = subnet.split("/")
    octets = base_ip.split(".")
    num_hosts = 2 ** (32 - int(prefix)) - 2
    return [f"{octets[0]}.{octets[1]}.{octets[2]}.{i}" for i in range(1, num_hosts + 1)]

def ping_ip(ip: str) -> bool:
    cmd = ["ping", "-n", "1", "-w", "1000", ip] if IS_WINDOWS else ["ping", "-c", "1", "-W", "1", ip]
    return subprocess.run(cmd, capture_output=True, text=True).returncode == 0

def ping_sweep_parallel(ips: list[str], workers: int = 32) -> list[str]:
    live = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_ip = {executor.submit(ping_ip, ip): ip for ip in ips}
        for future in concurrent.futures.as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                if future.result():
                    log.info(f"UP: {ip}")
                    live.append(ip)
            except Exception:
                pass
    return live

def encode_dns_name(name: str) -> bytes:
    """Encode a dot-separated name into DNS wire format."""
    out = b""
    for label in name.rstrip(".").split("."):
        encoded = label.encode("ascii")
        out += bytes([len(encoded)]) + encoded
    return out + b"\x00"

def build_mdns_query(*questions: tuple[str, int]) -> bytes:
    """
    Build an mDNS query packet with one or more questions.
    Each question is (name, qtype) e.g. ("_services._dns-sd._udp.local", 12)
    """
    header = struct.pack("!HHHHHH",
        0,              # transaction ID (0 for mDNS)
        0x0000,         # flags: standard query
        len(questions), # qd_count
        0, 0, 0         # an, ns, ar counts
    )
    body = b""
    for name, qtype in questions:
        body += encode_dns_name(name)
        body += struct.pack("!HH", qtype, 1)  # qtype, qclass IN
    return header + body

# Services iPhones and Apple devices respond to
APPLE_SERVICES = [
    ("_apple-mobdev2._tcp.local",   12),  # iPhone/iPad device discovery
    ("_airplay._tcp.local",         12),  # AirPlay (Apple TV, HomePod)
    ("_raop._tcp.local",            12),  # AirPlay audio
    ("_companion-link._tcp.local",  12),  # Apple Watch / Handoff
    ("_homekit._tcp.local",         12),  # HomeKit devices
    ("_services._dns-sd._udp.local",12),  # General service browser
]

def parse_dns_name(data: bytes, offset: int, visited: frozenset = frozenset()) -> tuple[str, int]:
    parts = []
    while offset < len(data):
        if offset in visited:
            raise ValueError(f"Pointer cycle at offset {offset}")
        length = data[offset]
        if length == 0:
            return ".".join(parts), offset + 1
        if length >= 0xC0:
            if offset + 1 >= len(data):
                raise ValueError("Truncated compression pointer")
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            name, _ = parse_dns_name(data, pointer, visited | {offset})
            full = ".".join(parts + [name]) if parts else name
            return full, offset + 2
        if length > 63:
            raise ValueError(f"Label length {length} exceeds RFC 1035 max")
        end = offset + 1 + length
        if end > len(data):
            raise ValueError("Label extends beyond packet boundary")
        parts.append(data[offset + 1:end].decode("ascii"))
        offset = end
    return ".".join(parts), offset

def parse_mdns_packet(data: bytes, source_ip: str) -> list[dict]:
    """
    Parse any mDNS packet (query or response) and extract A records
    from the answer, authority, and additional sections.
    """
    if len(data) < 12:
        return []
    try:
        qd_count, an_count, ns_count, ar_count = struct.unpack_from("!HHHH", data, 4)
        total_rr = an_count + ns_count + ar_count

        if total_rr == 0:
            return []

        offset = 12

        # Skip questions
        for _ in range(qd_count):
            if offset >= len(data):
                return []
            _, offset = parse_dns_name(data, offset)
            offset += 4  # qtype + qclass

        results = []

        # Parse ALL resource record sections (answers + authority + additional)
        for _ in range(total_rr):
            if offset >= len(data):
                break
            name, offset = parse_dns_name(data, offset)
            if offset + 10 > len(data):
                break

            rtype, rclass, ttl, rd_length = struct.unpack_from("!HHIH", data, offset)
            offset += 10

            rclass &= 0x7FFF  # strip cache-flush bit
            if rclass != 1:
                offset += rd_length
                continue
            if offset + rd_length > len(data):
                break

            rdata = data[offset:offset + rd_length]
            offset += rd_length

            if rtype == 1 and rd_length == 4:  # A record
                ip = ".".join(map(str, rdata))
                results.append({"ip": ip, "hostname": name})

        return results

    except Exception as e:
        log.warning(f"mDNS parse error from {source_ip}: {e}")
        return []

def reverse_dns_lookup(ip: str) -> str | None:
    """Get hostname for an IP via reverse DNS."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname.rstrip(".")
    except socket.herror:
        return None

def bulk_reverse_dns(ips: list[str], workers: int = 16) -> dict[str, str]:
    """Reverse DNS lookup for multiple IPs in parallel."""
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_ip = {executor.submit(reverse_dns_lookup, ip): ip for ip in ips}
        for future in concurrent.futures.as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                hostname = future.result()
                if hostname:
                    results[ip] = hostname
            except Exception:
                pass
    return results

# ---------------------------------------------------------------------------
# Active service probing (100% certain - no guessing)
# ---------------------------------------------------------------------------

# iOS-specific ports that ONLY Apple devices use
IOS_PORTS = {
    62078: "lockdownd",   # iOS lockdown daemon (device pairing)
    7100:  "fontd",       # iOS font server
}

def probe_tcp_port(ip: str, port: int, timeout: float = 1.0) -> bool:
    """Check if a TCP port is open."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception:
        return False

def probe_ssdp(ip: str, timeout: float = 1.0) -> dict | None:
    """Send SSDP M-SEARCH and check for response."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.settimeout(timeout)
        query = (
            "M-SEARCH * HTTP/1.1\r\n"
            "HOST: 239.255.255.250:1900\r\n"
            "MAN: \"ssdp:discover\"\r\n"
            "MX: 1\r\n"
            "ST: ssdp:all\r\n"
            "\r\n"
        ).encode()
        sock.sendto(query, (ip, 1900))
        data, _ = sock.recvfrom(4096)
        sock.close()

        response = data.decode('utf-8', errors='ignore')
        info = {}
        for line in response.split('\r\n'):
            if ':' in line:
                key, _, value = line.partition(':')
                info[key.strip()] = value.strip()
        return info
    except Exception:
        return None

def probe_http(ip: str, port: int = 80, timeout: float = 1.0) -> str | None:
    """Send HTTP request and check response headers."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        request = f"GET / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n".encode()
        sock.send(request)
        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
            if b"\r\n\r\n" in response:
                break
        sock.close()

        response_str = response.decode('utf-8', errors='ignore')
        for line in response_str.split('\r\n'):
            if line.lower().startswith('server:'):
                return line.split(':', 1)[1].strip()
        return None
    except Exception:
        return None

def identify_device_services(ip: str) -> dict:
    """
    Probe device for identifying services.
    Returns dict with detected services and device type.
    """
    result = {"ip": ip, "services": [], "device_type": None}

    # Check iOS-specific ports (100% certain - only iOS uses these)
    for port, service in IOS_PORTS.items():
        if probe_tcp_port(ip, port, timeout=0.5):
            result["services"].append(f"{service} (port {port})")
            result["device_type"] = "Apple iOS Device"

    # Check for SSDP/UPnP response
    ssdp_info = probe_ssdp(ip, timeout=1.0)
    if ssdp_info:
        result["services"].append("UPnP/SSDP")
        if "SERVER" in ssdp_info:
            server = ssdp_info["SERVER"]
            if "iOS" in server or "iPhone" in server or "iPad" in server:
                result["device_type"] = "Apple iOS Device"
            elif "Darwin" in server or "Mac" in server:
                result["device_type"] = "Apple macOS Device"
            elif "Linux" in server or "Ubuntu" in server:
                result["device_type"] = "Linux Device"
            elif "Windows" in server:
                result["device_type"] = "Windows Device"

    # Check HTTP server header
    http_server = probe_http(ip, port=80, timeout=1.0)
    if http_server:
        result["services"].append(f"HTTP ({http_server})")
        if "iOS" in http_server or "AirPort" in http_server:
            result["device_type"] = "Apple Device"

    # Check HTTPS
    if probe_tcp_port(ip, 443, timeout=0.5):
        result["services"].append("HTTPS")

    return result

def bulk_service_probe(ips: list[str], workers: int = 16) -> dict[str, dict]:
    """Probe multiple IPs for services in parallel."""
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_ip = {executor.submit(identify_device_services, ip): ip for ip in ips}
        for future in concurrent.futures.as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                result = future.result()
                if result["services"]:
                    results[ip] = result
            except Exception:
                pass
    return results

# ---------------------------------------------------------------------------
# ARP / MAC vendor lookup
# ---------------------------------------------------------------------------

def get_arp_table() -> dict[str, str]:
    """Parse ARP table to get IP -> MAC mapping."""
    ip_to_mac = {}
    if IS_WINDOWS:
        result = subprocess.run(["arp", "-a"], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            match = re.match(r"\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})", line)
            if match:
                ip = match.group(1)
                mac = match.group(2).replace("-", ":").lower()
                ip_to_mac[ip] = mac
    elif IS_LINUX:
        try:
            with open("/proc/net/arp") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 4 and parts[0] != "IP":
                        ip_to_mac[parts[0]] = parts[3].lower()
        except FileNotFoundError:
            pass
    return ip_to_mac

def get_mac_vendor(mac: str) -> str | None:
    """Look up vendor from MAC address OUI prefix."""
    oui = mac[:8].upper()
    return MAC_VENDORS.get(oui)

def mac_discovery(ips: list[str]) -> dict[str, dict]:
    """Get MAC addresses and vendors for given IPs via ARP table."""
    arp_table = get_arp_table()
    results = {}
    for ip in ips:
        if ip in arp_table:
            mac = arp_table[ip]
            vendor = get_mac_vendor(mac)
            results[ip] = {"mac": mac, "vendor": vendor}
    return results

def make_mdns_socket(local_ip: str) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    if IS_LINUX:
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except (AttributeError, OSError):
            pass
        sock.bind(("224.0.0.251", 5353))
    else:
        sock.bind(("", 5353))

    mreq = struct.pack("4s4s",
        socket.inet_aton("224.0.0.251"),
        socket.inet_aton(local_ip)
    )
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    return sock

def mdns_discovery(live_ips: list[str], timeout: int = 10) -> dict[str, str]:
    """
    Active + passive mDNS discovery:
      1. Send queries for Apple services and for each live IP's hostname
      2. Collect all A records from any response that comes back
    """
    local_ip = get_default_iface_ip()
    log.info(f"Local IP: {local_ip}  |  Platform: {platform.system()}")

    try:
        sock = make_mdns_socket(local_ip)
    except PermissionError:
        log.error("Permission denied on port 5353. Run as sudo (Linux) or Administrator (Windows).")
        return {}

    # --- Send active queries ---

    # 1. Apple service queries (provokes PTR → SRV → A chain from iPhones)
    apple_query = build_mdns_query(*APPLE_SERVICES)
    sock.sendto(apple_query, ("224.0.0.251", 5353))
    log.info("Sent Apple service queries")

    # 2. Direct A record query for each live IP's likely hostname
    #    We ask for <hostname>.local where hostname = last label from reverse lookup
    #    This is a best-effort — we don't know the name yet, but probing
    #    common patterns can provoke responses
    for ip in live_ips:
        last_octet = ip.split(".")[-1]
        # Query the IP's reverse PTR — some devices respond with their name
        reverse = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
        ptr_query = build_mdns_query((reverse, 12))  # PTR query
        sock.sendto(ptr_query, ("224.0.0.251", 5353))

    log.info(f"Sent PTR queries for {len(live_ips)} live hosts")

    # --- Collect responses ---
    ip_to_hostname: dict[str, str] = {}
    sock.settimeout(1.0)

    elapsed = 0
    while elapsed < timeout:
        try:
            data, addr = sock.recvfrom(4096)
            source_ip = addr[0]
            if source_ip == local_ip:
                continue

            for record in parse_mdns_packet(data, source_ip):
                ip       = record["ip"]
                hostname = record["hostname"]
                if ip not in ip_to_hostname:
                    ip_to_hostname[ip] = hostname
                    log.info(f"Resolved: {ip} -> {hostname}")

        except socket.timeout:
            elapsed += 1
            print(f"\r  Listening... {timeout - elapsed}s remaining   ", end="", flush=True)

    print()
    sock.close()
    return ip_to_hostname

def run_single_scan(subnet: str, mdns_timeout: int = 10) -> list[dict]:
    """Perform a single scan cycle and return results."""
    log.info("Step 1: Ping sweep...")
    live_ips = set(ping_sweep_parallel(generate_ips(subnet)))
    log.info(f"Found {len(live_ips)} live hosts")

    log.info("Step 2: ARP/MAC vendor lookup...")
    mac_map = mac_discovery(list(live_ips))
    log.info(f"Found {len(mac_map)} MAC addresses")

    log.info("Step 3: Reverse DNS lookup...")
    rdns_map = bulk_reverse_dns(list(live_ips))
    log.info(f"Resolved {len(rdns_map)} hostnames via reverse DNS")

    log.info("Step 4: mDNS discovery...")
    mdns_map = mdns_discovery(list(live_ips), timeout=mdns_timeout)
    log.info(f"Resolved {len(mdns_map)} hostnames via mDNS")

    log.info("Step 5: Active service probing...")
    service_map = bulk_service_probe(list(live_ips))
    log.info(f"Identified {len(service_map)} devices via service probing")

    all_ips = live_ips | set(mdns_map.keys()) | set(rdns_map.keys()) | set(service_map.keys()) | set(service_map.keys())

    results = []
    for ip in sorted(all_ips, key=lambda x: list(map(int, x.split(".")))):
        hostname = mdns_map.get(ip) or rdns_map.get(ip, "unknown")
        mac_info = mac_map.get(ip, {})
        vendor = mac_info.get("vendor")
        mac = mac_info.get("mac", "unknown")

        service_info = service_map.get(ip, {})
        device_type = service_info.get("device_type")
        services = service_info.get("services", [])

        if hostname == "unknown" and device_type:
            hostname = device_type

        sources = []
        if ip in live_ips: sources.append("ping")
        if ip in mdns_map: sources.append("mdns")
        if ip in rdns_map: sources.append("rdns")
        if ip in mac_map: sources.append("arp")
        if ip in service_map: sources.append("probe")

        results.append({
            "ip": ip,
            "hostname": hostname,
            "mac": mac,
            "vendor": vendor,
            "device_type": device_type,
            "services": services,
            "source": "+".join(sources)
        })

    return results

def _background_scan_loop(subnet: str, history: dict, stop_event: threading.Event, mdns_timeout: int = 5):
    """Background thread that runs scans periodically."""
    retention_hours = _get_retention_hours()
    log.info(f"Background scanner started on {subnet} (retention: {retention_hours}h)")

    while not stop_event.is_set():
        try:
            current_scan = run_single_scan(subnet, mdns_timeout=mdns_timeout)
            log.info(f"DEBUG: current_scan has {len(current_scan)} devices: {[d['ip'] for d in current_scan]}")
            
            # merge_scan modifies history in place
            merge_scan(current_scan, history, retention_hours=retention_hours)
            log.info(f"DEBUG: history after merge has {len(history)} devices: {list(history.keys())}")
            
            save_history(history)
            log.info(f"Scan complete: {len(history)} devices in history")
        except Exception as e:
            log.error(f"Scan error: {e}")
            import traceback
            log.error(traceback.format_exc())

        # Wait for next scan, checking stop event periodically
        for _ in range(30):
            if stop_event.is_set():
                break
            time.sleep(1)

    log.info("Background scanner stopped")

def print_display(history: dict, scan_count: int):
    """Print the device table."""
    devices = get_history_as_list(history)
    stats = get_history_stats(history)
    retention = _get_retention_hours()

    # Clear screen (works on Windows and Linux)
    os.system('cls' if platform.system() == 'Windows' else 'clear')

    print("=" * 130)
    print(f"  NETWORK SCANNER - Scan #{scan_count} | Retention: {retention}h | Press Ctrl+C to exit")
    print("=" * 130)
    print(f"\n{'IP':<18} {'Hostname':<25} {'Status':<10} {'Last Seen':<12} {'Vendor':<15} {'MAC':<18} {'Source'}")
    print("-" * 130)

    for d in devices:
        vendor = d.get('vendor') or "unknown"
        mac = d.get('mac', 'unknown')
        status = "ONLINE" if d.get('status') == 'online' else "OFFLINE"
        last_seen = format_last_seen(d.get('last_seen', ''))
        sources = d.get('sources', d.get('source', []))
        if isinstance(sources, str):
            sources = sources.split('+') if sources else []

        print(f"{d['ip']:<18} {d['hostname']:<25} {status:<10} {last_seen:<12} {vendor:<15} {mac:<18} {'+'.join(sources)}")

    print("-" * 130)
    print(f"  Total: {stats['total']} | Online: {stats['online']} | Offline: {stats['offline']} | Named: {stats['named']}")
    print()

def main():
    subnet = "192.168.1.0/24"
    history = load_history()
    stop_event = threading.Event()

    # Start background scanner
    scan_thread = threading.Thread(
        target=_background_scan_loop,
        args=(subnet, history, stop_event, 5),
        daemon=True
    )
    scan_thread.start()

    # Main display loop
    scan_count = 0
    try:
        while True:
            scan_count += 1
            print_display(history, scan_count)

            # Wait for next display refresh
            for _ in range(5):
                if stop_event.is_set():
                    break
                time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping scanner...")
        stop_event.set()
        scan_thread.join(timeout=10)
        save_history(history)
        print("Scanner stopped. Goodbye!")

if __name__ == "__main__":
    main()
