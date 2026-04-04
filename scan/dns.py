from __future__ import annotations

import concurrent.futures
import logging
import socket

log = logging.getLogger(__name__)


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
            except Exception as exc:
                log.debug("Reverse DNS worker failed for %s: %s", ip, exc)
                continue
    return results
