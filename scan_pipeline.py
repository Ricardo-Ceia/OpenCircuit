from __future__ import annotations

import concurrent.futures
import ipaddress
import logging
import platform
import re
import socket
import struct
import subprocess
from urllib.parse import urlsplit

from device_history import get_history_as_list
from identity import resolve_label
from known_devices import get_known_name
from lockdownd import get_ios_device_info
from mac_vendors import MAC_VENDORS
from models import DeviceFingerprint, LabelInfo, ScannedDevice
from settings import load_main_runtime_settings

log = logging.getLogger(__name__)

RUNTIME_SETTINGS = load_main_runtime_settings()
DEBUG_PROBES = RUNTIME_SETTINGS.debug_probes

IS_WINDOWS = platform.system() == "Windows"
IS_LINUX = platform.system() == "Linux"


def _probe_debug(msg: str, *args):
    if DEBUG_PROBES:
        log.debug(msg, *args)


def get_default_iface_ip() -> str:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        ip = sock.getsockname()[0]
        sock.close()
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
                    log.info("UP: %s", ip)
                    live.append(ip)
            except Exception:
                continue
    return live


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


APPLE_SERVICES = [
    ("_apple-mobdev2._tcp.local", 12),
    ("_airplay._tcp.local", 12),
    ("_raop._tcp.local", 12),
    ("_companion-link._tcp.local", 12),
    ("_homekit._tcp.local", 12),
    ("_services._dns-sd._udp.local", 12),
]


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
    except Exception as exc:
        log.warning("mDNS parse error from %s: %s", source_ip, exc)
        return []


def reverse_dns_lookup(ip: str) -> str | None:
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname.rstrip(".")
    except socket.herror:
        return None


def bulk_reverse_dns(ips: list[str], workers: int = 16) -> dict[str, str]:
    results: dict[str, str] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_ip = {executor.submit(reverse_dns_lookup, ip): ip for ip in ips}
        for future in concurrent.futures.as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                hostname = future.result()
                if hostname:
                    results[ip] = hostname
            except Exception:
                continue
    return results


IOS_PORTS = {
    62078: "lockdownd",
    7100: "fontd",
}


def probe_tcp_port(ip: str, port: int, timeout: float = 1.0) -> bool:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def probe_ssdp(ip: str, timeout: float = 1.0) -> dict | None:
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

        response = data.decode("utf-8", errors="ignore")
        info: dict[str, str] = {}
        for line in response.split("\r\n"):
            if ":" in line:
                key, _, value = line.partition(":")
                info[key.strip()] = value.strip()

        _probe_debug(
            "SSDP response from %s st=%s location=%s server=%s",
            ip,
            info.get("ST", "unknown"),
            "present" if "LOCATION" in info else "none",
            "present" if "SERVER" in info else "none",
        )
        return info
    except Exception as exc:
        _probe_debug("SSDP no response from %s: %s", ip, exc)
        return None


def fetch_http_full(ip: str, port: int = 80, timeout: float = 2.0) -> dict:
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

        response_str = response.decode("utf-8", errors="ignore")
        if "\r\n\r\n" in response_str:
            header_part, body = response_str.split("\r\n\r\n", 1)
            result["body_snippet"] = body[:500]

            for line in header_part.split("\r\n"):
                if ":" in line:
                    key, _, value = line.partition(":")
                    normalized_key = key.strip().lower()
                    result["headers"][normalized_key] = value.strip()
                    if normalized_key == "server":
                        result["server"] = value.strip()
        else:
            result["body_snippet"] = response_str[:500]

        title_match = re.search(r"<title[^>]*>(.*?)</title>", response_str, re.IGNORECASE | re.DOTALL)
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
    result: dict[str, str | None] = {
        "manufacturer": None,
        "model_name": None,
        "model_number": None,
        "friendly_name": None,
        "device_type": None,
        "serial_number": None,
        "udn": None,
    }

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
        _probe_debug("UPnP location received for %s", expected_ip)
        target = _parse_safe_upnp_location(location_url, expected_ip)
        if not target:
            _probe_debug("UPnP skipped unsafe LOCATION for %s", expected_ip)
            return result

        host, port, existing_path = target
        paths_to_try = [existing_path] + upnp_paths if existing_path != "/" else upnp_paths
        _probe_debug("UPnP connect %s:%s paths=%s", host, port, paths_to_try[:3])

        for path in paths_to_try:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                sock.connect((host, port))
                request = (
                    f"GET {path} HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    "User-Agent: OpenCircuitScanner/1.0\r\n"
                    "Connection: close\r\n\r\n"
                ).encode()
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

                response_str = response.decode("utf-8", errors="ignore")
                if "\r\n\r\n" in response_str:
                    _, xml = response_str.split("\r\n\r\n", 1)
                else:
                    xml = response_str

                if "<?xml" in xml or "<root" in xml or "<device" in xml:
                    _probe_debug("UPnP XML candidate path=%s host=%s", path, host)
                    _probe_debug("UPnP XML body length=%d", len(xml))

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
                        match = re.search(
                            rf"<(?:\w+:)?{tag}>(.*?)</(?:\w+:)?{tag}>",
                            xml,
                            re.IGNORECASE | re.DOTALL,
                        )
                        if match:
                            result[key] = match.group(1).strip()
                            _probe_debug("UPnP field found: %s", key)
                        else:
                            _probe_debug("UPnP field missing: %s", tag)

                    if result["manufacturer"]:
                        return result
                else:
                    _probe_debug("UPnP path %s returned non-XML", path)
            except Exception as exc:
                _probe_debug("UPnP path %s failed for %s: %s", path, expected_ip, exc)
                continue
    except Exception as exc:
        _probe_debug("UPnP fetch error for %s: %s", expected_ip, exc)
        if DEBUG_PROBES:
            log.debug("UPnP traceback for %s", expected_ip, exc_info=True)

    return result


def build_fingerprint(ip: str, ssdp_info: dict, http_info: dict, upnp_info: dict) -> dict:
    fingerprint: dict[str, str | None] = {
        "manufacturer": None,
        "model": None,
        "friendly_name": None,
        "device_type": None,
        "model_number": None,
    }

    if upnp_info:
        fingerprint["manufacturer"] = upnp_info.get("manufacturer")
        fingerprint["model"] = upnp_info.get("model_name")
        fingerprint["friendly_name"] = upnp_info.get("friendly_name")
        fingerprint["model_number"] = upnp_info.get("model_number")

        device_type = upnp_info.get("device_type", "")
        if device_type:
            parts = device_type.split(":")
            if len(parts) >= 2:
                fingerprint["device_type"] = parts[-2]

    return fingerprint


def identify_device_services(ip: str) -> dict:
    result = {"ip": ip, "services": [], "device_type": None, "fingerprint": {}}

    ios_detected = False
    for port, service in IOS_PORTS.items():
        if probe_tcp_port(ip, port, timeout=0.5):
            result["services"].append(f"{service} (port {port})")
            ios_detected = True

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
            result["fingerprint"] = {
                "manufacturer": "Apple",
                "model": None,
                "friendly_name": None,
                "device_type": "Apple iOS Device",
                "model_number": None,
            }
            result["device_type"] = "Apple iOS Device"

    ssdp_info = probe_ssdp(ip, timeout=1.0)
    if ssdp_info:
        result["services"].append("UPnP/SSDP")

    http_info = fetch_http_full(ip, port=80, timeout=1.5)
    if http_info.get("server"):
        result["services"].append(f"HTTP ({http_info['server']})")
    if http_info.get("title"):
        result["services"].append(f"Title: {http_info['title']}")

    if probe_tcp_port(ip, 443, timeout=0.5):
        result["services"].append("HTTPS")

    upnp_info = {}
    if ssdp_info and "LOCATION" in ssdp_info:
        upnp_info = fetch_upnp_description(ssdp_info["LOCATION"], ip, timeout=2.0)
        if upnp_info.get("manufacturer"):
            result["services"].append(f"UPnP: {upnp_info['manufacturer']}")

    if not result["fingerprint"]:
        fingerprint = build_fingerprint(ip, ssdp_info or {}, http_info, upnp_info)
        result["fingerprint"] = fingerprint
        if fingerprint.get("device_type") and not result["device_type"]:
            result["device_type"] = fingerprint["device_type"]

    return result


def bulk_service_probe(ips: list[str], workers: int = 16) -> dict[str, dict]:
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
                continue
    return results


def get_arp_table() -> dict[str, str]:
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
            with open("/proc/net/arp") as handle:
                for line in handle:
                    parts = line.split()
                    if len(parts) >= 4 and parts[0] != "IP":
                        ip_to_mac[parts[0]] = parts[3].lower()
        except FileNotFoundError:
            pass
    return ip_to_mac


def get_mac_vendor(mac: str) -> str | None:
    oui = mac[:8].upper()
    return MAC_VENDORS.get(oui)


def mac_discovery(ips: list[str]) -> dict[str, dict]:
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
    sock.close()
    return ip_to_hostname


def run_single_scan(subnet: str, mdns_timeout: int = 10) -> list[dict]:
    log.info("Step 1: Ping sweep...")
    live_ips = set(ping_sweep_parallel(generate_ips(subnet)))
    log.info("Found %d live hosts", len(live_ips))

    log.info("Step 2: ARP/MAC vendor lookup...")
    mac_map = mac_discovery(list(live_ips))
    log.info("Found %d MAC addresses", len(mac_map))

    log.info("Step 3: Reverse DNS lookup...")
    rdns_map = bulk_reverse_dns(list(live_ips))
    log.info("Resolved %d hostnames via reverse DNS", len(rdns_map))

    log.info("Step 4: mDNS discovery...")
    mdns_map = mdns_discovery(list(live_ips), timeout=mdns_timeout)
    log.info("Resolved %d hostnames via mDNS", len(mdns_map))

    log.info("Step 5: Active service probing...")
    service_map = bulk_service_probe(list(live_ips))
    log.info("Identified %d devices via service probing", len(service_map))

    all_ips = live_ips | set(mdns_map.keys()) | set(rdns_map.keys()) | set(service_map.keys())

    scanned_devices: list[ScannedDevice] = []
    for ip in sorted(all_ips, key=lambda x: list(map(int, x.split(".")))):
        mac_info = mac_map.get(ip, {})
        vendor = mac_info.get("vendor")
        mac = mac_info.get("mac", "unknown")

        service_info = service_map.get(ip, {})
        device_type = service_info.get("device_type")
        services = service_info.get("services", [])
        fingerprint = service_info.get("fingerprint", {})

        known_name = get_known_name(mac)
        mdns_hostname = mdns_map.get(ip)
        rdns_hostname = rdns_map.get(ip)
        lockdownd_name = fingerprint.get("friendly_name") if fingerprint.get("device_type") == "iPhone" else None
        lockdownd_ok = any(s.startswith("lockdownd:") for s in services)
        upnp_name = fingerprint.get("friendly_name") if not lockdownd_ok else None
        upnp_type = fingerprint.get("device_type") if not lockdownd_ok else None
        ios_port = any("lockdownd (port" in s for s in services)

        resolved_label = resolve_label(
            mdns_hostname=mdns_hostname,
            lockdownd_device_name=lockdownd_name,
            lockdownd_success=lockdownd_ok,
            rdns_hostname=rdns_hostname,
            upnp_friendly_name=upnp_name,
            upnp_device_type=upnp_type,
            ios_port_detected=ios_port,
            known_name=known_name,
        )
        label_info = LabelInfo(
            label=resolved_label["label"],
            label_source=resolved_label["label_source"],
            label_authoritative=resolved_label["label_authoritative"],
            identity_status=resolved_label["identity_status"],
        )

        sources = []
        if ip in live_ips:
            sources.append("ping")
        if ip in mdns_map:
            sources.append("mdns")
        if ip in rdns_map:
            sources.append("rdns")
        if ip in mac_map:
            sources.append("arp")
        if ip in service_map:
            sources.append("probe")

        scanned_devices.append(
            ScannedDevice(
                ip=ip,
                label_info=label_info,
                hostname=mdns_map.get(ip) or rdns_map.get(ip, "unknown"),
                mac=mac,
                vendor=vendor,
                device_type=device_type,
                fingerprint=DeviceFingerprint.from_raw(fingerprint),
                services=list(services),
                source_channels=sources,
            )
        )

    return [device.to_record() for device in scanned_devices]


def get_sorted_history_devices(history: dict) -> list[dict]:
    return get_history_as_list(history)
