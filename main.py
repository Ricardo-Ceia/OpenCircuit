import socket
import subprocess
import concurrent.futures
import struct
import logging
import platform

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

def discover_network(subnet: str, mdns_timeout: int = 10) -> list[dict]:
    log.info("Step 1: Ping sweep...")
    live_ips = set(ping_sweep_parallel(generate_ips(subnet)))
    log.info(f"Found {len(live_ips)} live hosts")

    log.info("Step 2: mDNS active+passive discovery...")
    mdns_map = mdns_discovery(list(live_ips), timeout=mdns_timeout)
    log.info(f"Resolved {len(mdns_map)} hostnames via mDNS")

    all_ips = live_ips | set(mdns_map.keys())

    results = []
    for ip in sorted(all_ips, key=lambda x: list(map(int, x.split(".")))):
        hostname = mdns_map.get(ip, "unknown")
        source = (
            "both" if ip in live_ips and ip in mdns_map else
            "ping" if ip in live_ips else
            "mdns"
        )
        results.append({"ip": ip, "hostname": hostname, "source": source})

    return results

def main():
    devices = discover_network("192.168.1.0/24", mdns_timeout=10)

    print(f"\n{'IP':<18} {'Hostname':<40} {'Source'}")
    print("-" * 65)
    for d in devices:
        print(f"{d['ip']:<18} {d['hostname']:<40} {d['source']}")

    print(f"\nTotal: {len(devices)} devices found")
    named   = sum(1 for d in devices if d['hostname'] != 'unknown')
    unnamed = len(devices) - named
    print(f"  Named (mDNS resolved): {named}")
    print(f"  Unnamed (no mDNS):     {unnamed}")

if __name__ == "__main__":
    main()
