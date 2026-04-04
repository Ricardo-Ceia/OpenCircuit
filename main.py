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
import ipaddress
from urllib.parse import urlsplit
from mac_vendors import MAC_VENDORS
from device_history import load_history, save_history, merge_scan, format_last_seen, get_history_as_list, get_history_stats, _get_retention_hours
from lockdownd import get_ios_device_info, get_model_display_name
from identity import resolve_label, assign_stable_aliases
from known_devices import get_known_name, set_known_name

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
        
        log.info(f"DEBUG SSDP: Response from {ip}: {info.get('ST', 'unknown')} | LOCATION: {info.get('LOCATION', 'none')} | SERVER: {info.get('SERVER', 'none')}")
        return info
    except Exception as e:
        log.info(f"DEBUG SSDP: No response from {ip}: {e}")
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

def fetch_http_full(ip: str, port: int = 80, timeout: float = 2.0) -> dict:
    """
    Fetch full HTTP response and extract useful info.
    Returns dict with headers, title, and body snippet.
    """
    result = {"server": None, "title": None, "headers": {}, "body_snippet": ""}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        request = f"GET / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n".encode()
        sock.send(request)
        response = b""
        while True:
            chunk = sock.recv(8192)
            if not chunk:
                break
            response += chunk
            if b"\r\n\r\n" in response and len(response) > 1000:
                break
        sock.close()

        response_str = response.decode('utf-8', errors='ignore')
        
        # Parse headers
        if "\r\n\r\n" in response_str:
            header_part, body = response_str.split("\r\n\r\n", 1)
            result["body_snippet"] = body[:500]
            
            for line in header_part.split('\r\n'):
                if ':' in line:
                    key, _, value = line.partition(':')
                    result["headers"][key.strip().lower()] = value.strip()
                    if key.strip().lower() == 'server':
                        result["server"] = value.strip()
        else:
            result["body_snippet"] = response_str[:500]

        # Extract title
        import re
        title_match = re.search(r'<title[^>]*>(.*?)</title>', response_str, re.IGNORECASE | re.DOTALL)
        if title_match:
            result["title"] = title_match.group(1).strip()

    except Exception:
        pass
    return result

def _resolve_ipv4_addresses(host: str, port: int) -> set[str]:
    try:
        info = socket.getaddrinfo(host, port, family=socket.AF_INET, type=socket.SOCK_STREAM)
    except Exception:
        return set()
    resolved: set[str] = set()
    for item in info:
        sockaddr = item[4]
        if not sockaddr:
            continue
        ip = sockaddr[0]
        if isinstance(ip, str):
            resolved.add(ip)
    return resolved


def _parse_safe_upnp_location(location_url: str, expected_ip: str) -> tuple[str, int, str] | None:
    try:
        parsed = urlsplit(location_url)
    except ValueError:
        return None

    if parsed.scheme.lower() != "http":
        return None
    if parsed.username or parsed.password:
        return None
    if not parsed.hostname:
        return None

    try:
        expected_ip_obj = ipaddress.ip_address(expected_ip)
    except ValueError:
        return None
    if not isinstance(expected_ip_obj, ipaddress.IPv4Address):
        return None
    if not (expected_ip_obj.is_private or expected_ip_obj.is_link_local):
        return None

    try:
        port = parsed.port or 80
    except ValueError:
        return None
    if port < 1 or port > 65535:
        return None

    resolved_ips = _resolve_ipv4_addresses(parsed.hostname, port)
    if expected_ip not in resolved_ips:
        return None

    path = parsed.path or "/"
    return expected_ip, port, path


def fetch_upnp_description(location_url: str, expected_ip: str, timeout: float = 2.0) -> dict:
    """
    Fetch and parse UPnP device description XML.
    Returns dict with manufacturer, model, friendlyName, etc.
    """
    result = {
        "manufacturer": None,
        "model_name": None,
        "model_number": None,
        "friendly_name": None,
        "device_type": None,
        "serial_number": None,
        "udn": None,
    }  # type: dict[str, str | None]
    
    # Common UPnP description paths to try
    upnp_paths = [
        "/description.xml",
        "/Description.xml",
        "/desc.xml",
        "/Desc.xml",
        "/devicedesc.xml",
        "/DeviceDescription.xml",
        "/upnp/description.xml",
        "/WebOSTV/desc.xml",
        "/webos/desc.xml",
        "/dial.xml",
        "/ssdp/desc.xml",
        "/device.xml",
        "/lg/smarttv/description.xml",
        "/secondscreen/desc.xml",
        "/",
    ]

    try:
        log.info(f"DEBUG UPnP: Fetching {location_url}")

        target = _parse_safe_upnp_location(location_url, expected_ip)
        if not target:
            log.info(f"DEBUG UPnP: Unsafe LOCATION for {expected_ip}, skipping")
            return result

        host, port, existing_path = target

        # Determine which paths to try
        if existing_path != '/':
            paths_to_try = [existing_path] + upnp_paths
        else:
            paths_to_try = upnp_paths
        
        log.info(f"DEBUG UPnP: Connecting to {host}:{port}, trying paths: {paths_to_try[:3]}...")

        for path in paths_to_try:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                sock.connect((host, port))
                request = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: OpenCircuitScanner/1.0\r\nConnection: close\r\n\r\n".encode()
                sock.send(request)
                
                response = b""
                while True:
                    chunk = sock.recv(8192)
                    if not chunk:
                        break
                    response += chunk
                    if b"\r\n\r\n" in response and len(response) > 500:
                        break
                sock.close()

                response_str = response.decode('utf-8', errors='ignore')
                
                # Extract XML body (after headers)
                if "\r\n\r\n" in response_str:
                    header_part, xml = response_str.split("\r\n\r\n", 1)
                else:
                    xml = response_str
                    header_part = ""

                # Check if this looks like UPnP XML
                if '<?xml' in xml or '<root' in xml or '<device' in xml:
                    log.info(f"DEBUG UPnP: Found valid XML at {path}")
                    log.info(f"DEBUG UPnP: Response headers: {header_part[:200]}")
                    log.info(f"DEBUG UPnP: XML body length: {len(xml)}")
                    log.info(f"DEBUG UPnP: XML preview: {xml[:300]}")
                    
                    # Parse XML fields
                    import re
                    fields = {
                        "manufacturer": "manufacturer",
                        "model_name": "modelName",
                        "model_number": "modelNumber",
                        "friendly_name": "friendlyName",
                        "device_type": "deviceType",
                        "serial_number": "serialNumber",
                        "udn": "UDN",
                    }
                    
                    for key, tag in fields.items():
                        match = re.search(f'<(?:\w+:)?{tag}>(.*?)</(?:\w+:)?{tag}>', xml, re.IGNORECASE | re.DOTALL)
                        if match:
                            result[key] = match.group(1).strip()
                            log.info(f"DEBUG UPnP: Found {key}={result[key]}")
                        else:
                            log.info(f"DEBUG UPnP: No match for {tag}")
                    
                    # If we found at least manufacturer, we're done
                    if result["manufacturer"]:
                        return result
                else:
                    log.info(f"DEBUG UPnP: Path {path} returned non-XML: {xml[:100]}")
                    
            except Exception as e:
                log.info(f"DEBUG UPnP: Path {path} failed: {e}")
                continue

    except Exception as e:
        log.info(f"DEBUG UPnP: Error fetching {location_url}: {e}")
        import traceback
        log.info(f"DEBUG UPnP: Traceback: {traceback.format_exc()}")
    
    return result

def build_fingerprint(ip: str, ssdp_info: dict, http_info: dict, upnp_info: dict) -> dict:
    """
    Combine all probing signals into a unified device fingerprint.
    Returns dict with manufacturer, model, friendly_name, device_type.
    """
    fingerprint: dict = {
        "manufacturer": None,
        "model": None,
        "friendly_name": None,
        "device_type": None,
        "model_number": None,
    }

    # UPnP XML has the most detailed info
    if upnp_info:
        fingerprint["manufacturer"] = upnp_info.get("manufacturer")
        fingerprint["model"] = upnp_info.get("model_name")
        fingerprint["friendly_name"] = upnp_info.get("friendly_name")
        fingerprint["model_number"] = upnp_info.get("model_number")
        
        # Parse device type from UPnP (e.g., "urn:schemas-upnp-org:device:MediaRenderer:1")
        device_type = upnp_info.get("device_type", "")
        if device_type:
            # Extract the type part (e.g., "MediaRenderer")
            parts = device_type.split(':')
            if len(parts) >= 2:
                fingerprint["device_type"] = parts[-2]

    return fingerprint

def identify_device_services(ip: str) -> dict:
    """
    Probe device for identifying services and build fingerprint.
    Returns dict with detected services, device type, and fingerprint.
    """
    result = {"ip": ip, "services": [], "device_type": None, "fingerprint": {}}

    # Check iOS-specific ports (100% certain - only iOS uses these)
    ios_detected = False
    for port, service in IOS_PORTS.items():
        if probe_tcp_port(ip, port, timeout=0.5):
            result["services"].append(f"{service} (port {port})")
            ios_detected = True
    
    # If iOS detected, try lockdownd handshake to get actual device name
    if ios_detected:
        ios_info = get_ios_device_info(ip, timeout=5.0)
        if ios_info and ios_info.get("device_name"):
            result["fingerprint"] = {
                "manufacturer": "Apple",
                "model": ios_info.get("model") or ios_info.get("model_identifier"),
                "friendly_name": ios_info["device_name"],
                "device_type": "iPhone",
                "model_number": ios_info.get("model_identifier"),
                "ios_version": ios_info.get("ios_version"),
                "udid": ios_info.get("udid"),
            }
            result["device_type"] = "iPhone"
            result["services"].append(f"lockdownd: {ios_info['device_name']}")
        else:
            # Lockdownd failed (phone locked or denied)
            result["fingerprint"] = {
                "manufacturer": "Apple",
                "model": None,
                "friendly_name": None,
                "device_type": "Apple iOS Device",
                "model_number": None,
            }
            result["device_type"] = "Apple iOS Device"

    # Check for SSDP/UPnP response
    ssdp_info = probe_ssdp(ip, timeout=1.0)
    if ssdp_info:
        result["services"].append("UPnP/SSDP")

    # Fetch full HTTP info (title + headers)
    http_info = fetch_http_full(ip, port=80, timeout=1.5)
    if http_info.get("server"):
        result["services"].append(f"HTTP ({http_info['server']})")
    if http_info.get("title"):
        result["services"].append(f"Title: {http_info['title']}")

    # Check HTTPS
    if probe_tcp_port(ip, 443, timeout=0.5):
        result["services"].append("HTTPS")

    # Fetch UPnP description if LOCATION header present
    upnp_info = {}
    if ssdp_info and "LOCATION" in ssdp_info:
        upnp_info = fetch_upnp_description(ssdp_info["LOCATION"], ip, timeout=2.0)
        if upnp_info.get("manufacturer"):
            result["services"].append(f"UPnP: {upnp_info['manufacturer']}")

    # Build unified fingerprint (only if not already set by lockdownd)
    if not result["fingerprint"]:
        fingerprint = build_fingerprint(ip, ssdp_info or {}, http_info, upnp_info)
        result["fingerprint"] = fingerprint

        # Use UPnP XML device type only (no heuristic fallback)
        if fingerprint.get("device_type") and not result["device_type"]:
            result["device_type"] = fingerprint["device_type"]

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

    all_ips = live_ips | set(mdns_map.keys()) | set(rdns_map.keys()) | set(service_map.keys())

    results = []
    for ip in sorted(all_ips, key=lambda x: list(map(int, x.split(".")))):
        mac_info = mac_map.get(ip, {})
        vendor = mac_info.get("vendor")
        mac = mac_info.get("mac", "unknown")

        service_info = service_map.get(ip, {})
        device_type = service_info.get("device_type")
        services = service_info.get("services", [])
        fingerprint = service_info.get("fingerprint", {})

        # Check for user-assigned name
        known_name = get_known_name(mac)

        # Strict label resolution — no guessing
        mdns_hostname = mdns_map.get(ip)
        rdns_hostname = rdns_map.get(ip)
        lockdownd_name = fingerprint.get("friendly_name") if fingerprint.get("device_type") == "iPhone" else None
        lockdownd_ok = any(s.startswith("lockdownd:") for s in services)
        upnp_name = fingerprint.get("friendly_name") if not lockdownd_ok else None
        upnp_type = fingerprint.get("device_type") if not lockdownd_ok else None
        ios_port = any("lockdownd (port" in s for s in services)

        label_info = resolve_label(
            mdns_hostname=mdns_hostname,
            lockdownd_device_name=lockdownd_name,
            lockdownd_success=lockdownd_ok,
            rdns_hostname=rdns_hostname,
            upnp_friendly_name=upnp_name,
            upnp_device_type=upnp_type,
            ios_port_detected=ios_port,
            known_name=known_name,
        )

        sources = []
        if ip in live_ips: sources.append("ping")
        if ip in mdns_map: sources.append("mdns")
        if ip in rdns_map: sources.append("rdns")
        if ip in mac_map: sources.append("arp")
        if ip in service_map: sources.append("probe")

        results.append({
            "ip": ip,
            "label": label_info["label"],
            "label_source": label_info["label_source"],
            "label_authoritative": label_info["label_authoritative"],
            "identity_status": label_info["identity_status"],
            "hostname": mdns_map.get(ip) or rdns_map.get(ip, "unknown"),
            "mac": mac,
            "vendor": vendor,
            "device_type": device_type,
            "fingerprint": fingerprint,
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

def _build_clue(d: dict) -> str:
    """Build a plain-English clue string for a device."""
    clues = []
    fingerprint = d.get("fingerprint", {})
    vendor = d.get("vendor")

    # Brand from fingerprint or vendor
    manufacturer = fingerprint.get("manufacturer")
    model = fingerprint.get("model")
    if manufacturer and model:
        clues.append(f"{manufacturer} {model}")
    elif manufacturer:
        clues.append(manufacturer)
    elif vendor:
        clues.append(vendor)

    return " · ".join(clues)


def print_display(history: dict, scan_count: int):
    """Print the device table."""
    devices = get_history_as_list(history)
    stats = get_history_stats(history)
    retention = _get_retention_hours()

    # Apply stable aliases for same-type devices
    devices = assign_stable_aliases(devices)

    # Sort: claimed first, then verified, identified, unidentified; online before offline
    _identity_order = {"claimed": 0, "verified": 1, "identified": 2, "unidentified": 3}
    _status_order = {"online": 0, "offline": 1}
    devices.sort(key=lambda d: (
        _identity_order.get(d.get("identity_status", "unidentified"), 9),
        _status_order.get(d.get("status", "offline"), 9),
        d.get("first_seen", ""),
    ))

    # Clear screen (no subprocess — avoids ConPTY input buffer disruption on Windows)
    sys.stdout.write("\033[2J\033[H")
    sys.stdout.flush()

    print("=" * 140)
    print(f"  NETWORK SCANNER - Scan #{scan_count} | Retention: {retention}h | Press Ctrl+C to exit")
    print("=" * 140)
    print(f"\n{'Label':<30} {'Clue':<28} {'Identity':<12} {'Status':<10} {'Last Seen':<12} {'IP':<18} {'Scans'}")
    print("-" * 140)

    for d in devices:
        label = d.get('label', d.get('hostname', 'Unidentified device'))
        identity = d.get('identity_status', 'unidentified')
        status = "ONLINE" if d.get('status') == 'online' else "OFFLINE"
        last_seen = format_last_seen(d.get('last_seen', ''))
        sources = d.get('sources', d.get('source', []))
        if isinstance(sources, str):
            sources = sources.split('+') if sources else []
        clue = _build_clue(d)

        print(f"{label:<30} {clue:<28} {identity:<12} {status:<10} {last_seen:<12} {d['ip']:<18} {'+'.join(sources)}")

    print("-" * 140)
    print(f"  Total: {stats['total']} | Online: {stats['online']} | Offline: {stats['offline']} | Verified: {stats['verified']} | Unidentified: {stats['unidentified']}")

    # Show unnamed device hint
    unnamed_count = sum(
        1 for d in devices
        if d.get("identity_status") == "unidentified" and d.get("status") == "online"
    )
    if unnamed_count > 0:
        print(f"  {unnamed_count} unnamed device(s) — type 'i' + Enter to name them")

    print()

def _is_device_offline(ip: str, retries: int = 2) -> bool:
    """Check if a device is offline by pinging it."""
    for _ in range(retries):
        if ping_ip(ip):
            return False
        time.sleep(0.3)
    return True


def _run_identify_flow(subnet: str):
    """Auto-detect identify flow. User disconnects Wi-Fi, system detects which device."""
    print("\n  Scanning network...\n")
    scan_results = run_single_scan(subnet, mdns_timeout=5)

    # Filter to only online unnamed devices with known MACs
    unnamed = []
    for d in scan_results:
        if d.get("identity_status") in ("claimed",):
            continue
        if d.get("label_source") == "known":
            continue
        if d.get("status") != "online":
            continue
        mac = d.get("mac", "unknown")
        if mac == "unknown":
            continue
        unnamed.append(d)

    if not unnamed:
        print("  No online unnamed devices found.\n")
        return

    assign_stable_aliases(unnamed)

    while unnamed:
        print(f"  {'Unnamed devices':}")
        print(f"  {'-' * 40}")
        for i, d in enumerate(unnamed, 1):
            label = d.get("label", "Unknown")
            clue = _build_clue(d)
            clue_str = f" ({clue})" if clue else ""
            print(f"  [{i}] {label}{clue_str} — online")

        print()
        try:
            choice = input("  Which device to name? (number, q=quit): ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return

        if choice.lower() == "q":
            break

        try:
            idx = int(choice) - 1
            if idx < 0 or idx >= len(unnamed):
                print("  Invalid number.\n")
                continue
        except ValueError:
            print("  Enter a number.\n")
            continue

        device = unnamed[idx]
        device_ip = device["ip"]
        mac = device.get("mac", "unknown")
        label = device.get("label", "Device")

        # Auto-detect: countdown while pinging
        print(f"\n  Disconnect Wi-Fi on that device NOW")
        print(f"  {'-' * 40}")

        went_offline = False
        for remaining in range(20, 0, -1):
            print(f"  Waiting... {remaining:2d}s  ", end="\r")
            if _is_device_offline(device_ip):
                went_offline = True
                break
            time.sleep(1)

        print(" " * 40, end="\r")  # clear countdown line

        if went_offline:
            print(f"  Detected: {device_ip} went offline ✓")
        else:
            print(f"  Device didn't go offline.")
            try:
                retry = input("  Try again? (y/n): ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                print()
                return
            if retry == "y":
                print()
                continue
            else:
                print()
                continue

        # Show clues and ask for name
        clue = _build_clue(device)
        detail = f" ({clue})" if clue else ""
        print(f"\n  Device{detail}")
        try:
            name = input("  What do you call this device? ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return

        if not name:
            print("  Name cannot be empty.\n")
            continue

        set_known_name(mac, name)
        print(f"  Saved '{name}' ✓\n")

        # Remove from list and continue
        unnamed.pop(idx)
        if not unnamed:
            print("  All devices named!\n")
            break

        assign_stable_aliases(unnamed)

    print("  Returning to live scan...\n")


def main():
    import uvicorn
    import webbrowser

    host = "127.0.0.1"
    port = 8080
    url = f"http://{host}:{port}"

    print(f"\n  OpenCircuit starting at {url}")
    print(f"  Opening browser...\n")

    # Open browser after a short delay
    threading.Timer(1.5, lambda: webbrowser.open(url)).start()

    uvicorn.run("server:app", host=host, port=port, log_level="info")

if __name__ == "__main__":
    main()
