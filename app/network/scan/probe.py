from __future__ import annotations

import concurrent.futures
import ipaddress
import logging
import re
import socket
from urllib.parse import urlsplit

from app.network.lockdownd import get_ios_device_info

log = logging.getLogger(__name__)

IOS_PORTS = {
    62078: "lockdownd",
    7100: "fontd",
}


def _probe_debug(msg: str, *args):
    log.debug(msg, *args)


def probe_tcp_port(ip: str, port: int, timeout: float = 1.0) -> bool:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except OSError:
        return False


def probe_ssdp(ip: str, timeout: float = 1.0) -> dict | None:
    sock: socket.socket | None = None
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
        sock = None

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
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        _probe_debug("SSDP no response from %s: %s", ip, exc)
        return None
    finally:
        if sock is not None:
            sock.close()


def fetch_http_full(ip: str, port: int = 80, timeout: float = 2.0) -> dict:
    result = {"server": None, "title": None, "headers": {}, "body_snippet": ""}
    sock: socket.socket | None = None
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
        sock = None

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
    except (OSError, ValueError) as exc:
        _probe_debug("HTTP probe failed for %s:%s: %s", ip, port, exc)
    finally:
        if sock is not None:
            sock.close()

    return result


def _resolve_ipv4_addresses(host: str, port: int) -> set[str]:
    try:
        info = socket.getaddrinfo(host, port, family=socket.AF_INET, type=socket.SOCK_STREAM)
    except (socket.gaierror, OSError):
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
            sock: socket.socket | None = None
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
                sock = None

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
            except (OSError, UnicodeDecodeError, ValueError, re.error) as exc:
                _probe_debug("UPnP path %s failed for %s: %s", path, expected_ip, exc)
                continue
            finally:
                if sock is not None:
                    sock.close()
    except (OSError, ValueError, re.error) as exc:
        _probe_debug("UPnP fetch error for %s: %s", expected_ip, exc)

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
            except Exception as exc:
                log.debug("Service probe worker failed for %s: %s", ip, exc)
                continue
    return results
