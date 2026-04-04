from __future__ import annotations

import concurrent.futures
import platform
import socket
import subprocess
import logging

log = logging.getLogger(__name__)

IS_WINDOWS = platform.system() == "Windows"


def get_default_iface_ip() -> str:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        ip = sock.getsockname()[0]
        sock.close()
        return ip
    except OSError:
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
            except Exception as exc:
                log.debug("Ping worker failed for %s: %s", ip, exc)
                continue
    return live
