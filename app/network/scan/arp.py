from __future__ import annotations

import platform
import re
import subprocess

from app.network.mac_vendors import MAC_VENDORS

IS_WINDOWS = platform.system() == "Windows"
IS_LINUX = platform.system() == "Linux"


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
