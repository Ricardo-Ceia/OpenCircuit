from __future__ import annotations

import logging
import platform
import socket
import struct

from app.network.scan.ping import get_default_iface_ip

log = logging.getLogger(__name__)

IS_LINUX = platform.system() == "Linux"

APPLE_SERVICES = [
    ("_apple-mobdev2._tcp.local", 12),
    ("_airplay._tcp.local", 12),
    ("_raop._tcp.local", 12),
    ("_companion-link._tcp.local", 12),
    ("_homekit._tcp.local", 12),
    ("_services._dns-sd._udp.local", 12),
]


def encode_dns_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        encoded = label.encode("ascii")
        out += bytes([len(encoded)]) + encoded
    return out + b"\x00"


def build_mdns_query(*questions: tuple[str, int]) -> bytes:
    header = struct.pack(
        "!HHHHHH",
        0,
        0x0000,
        len(questions),
        0,
        0,
        0,
    )
    body = b""
    for name, qtype in questions:
        body += encode_dns_name(name)
        body += struct.pack("!HH", qtype, 1)
    return header + body


def parse_dns_name(data: bytes, offset: int, visited: frozenset[int] = frozenset()) -> tuple[str, int]:
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

        parts.append(data[offset + 1 : end].decode("ascii"))
        offset = end

    return ".".join(parts), offset


def parse_mdns_packet(data: bytes, source_ip: str) -> list[dict]:
    if len(data) < 12:
        return []

    try:
        qd_count, an_count, ns_count, ar_count = struct.unpack_from("!HHHH", data, 4)
        total_rr = an_count + ns_count + ar_count
        if total_rr == 0:
            return []

        offset = 12
        for _ in range(qd_count):
            if offset >= len(data):
                return []
            _, offset = parse_dns_name(data, offset)
            offset += 4

        results = []
        for _ in range(total_rr):
            if offset >= len(data):
                break

            name, offset = parse_dns_name(data, offset)
            if offset + 10 > len(data):
                break

            rtype, rclass, _, rd_length = struct.unpack_from("!HHIH", data, offset)
            offset += 10

            rclass &= 0x7FFF
            if rclass != 1:
                offset += rd_length
                continue

            if offset + rd_length > len(data):
                break

            rdata = data[offset : offset + rd_length]
            offset += rd_length

            if rtype == 1 and rd_length == 4:
                ip = ".".join(map(str, rdata))
                results.append({"ip": ip, "hostname": name})

        return results
    except (ValueError, struct.error, UnicodeDecodeError, TypeError) as exc:
        log.warning("mDNS parse error from %s: %s", source_ip, exc)
        return []


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

    mreq = struct.pack(
        "4s4s",
        socket.inet_aton("224.0.0.251"),
        socket.inet_aton(local_ip),
    )
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    return sock


def mdns_discovery(live_ips: list[str], timeout: int = 10) -> dict[str, str]:
    local_ip = get_default_iface_ip()
    log.info("Local IP: %s  |  Platform: %s", local_ip, platform.system())

    sock: socket.socket | None = None
    try:
        sock = make_mdns_socket(local_ip)
    except PermissionError:
        log.error("Permission denied on port 5353. Run as sudo (Linux) or Administrator (Windows).")
        return {}

    apple_query = build_mdns_query(*APPLE_SERVICES)
    sock.sendto(apple_query, ("224.0.0.251", 5353))
    log.info("Sent Apple service queries")

    for ip in live_ips:
        reverse = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
        ptr_query = build_mdns_query((reverse, 12))
        sock.sendto(ptr_query, ("224.0.0.251", 5353))
    log.info("Sent PTR queries for %d live hosts", len(live_ips))

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
                ip = record["ip"]
                hostname = record["hostname"]
                if ip not in ip_to_hostname:
                    ip_to_hostname[ip] = hostname
                    log.info("Resolved: %s -> %s", ip, hostname)
        except socket.timeout:
            elapsed += 1
            print(f"\r  Listening... {timeout - elapsed}s remaining   ", end="", flush=True)

    print()
    if sock is not None:
        sock.close()
    return ip_to_hostname
