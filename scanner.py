import threading
import time
import logging
from datetime import datetime

from main import (
    generate_ips,
    ping_sweep_parallel,
    mac_discovery,
    bulk_reverse_dns,
    mdns_discovery,
    bulk_service_probe,
)
from device_history import load_history, save_history, merge_scan

log = logging.getLogger(__name__)

class BackgroundScanner:
    """Runs network discovery in a background thread."""

    def __init__(self, subnet: str, mdns_timeout: int = 5, arp_interval: int = 30):
        self.subnet = subnet
        self.mdns_timeout = mdns_timeout
        self.arp_interval = arp_interval
        self._stop_event = threading.Event()
        self._thread = None
        self._lock = threading.Lock()
        self._current_devices = []
        self._history = load_history()
        self._last_scan_time = None

    def start(self):
        """Start the background scanner thread."""
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        log.info("Background scanner started")

    def stop(self):
        """Stop the background scanner thread."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        log.info("Background scanner stopped")

    def get_devices(self) -> list[dict]:
        """Get the current device list (thread-safe)."""
        with self._lock:
            return list(self._current_devices)

    def get_history(self) -> dict:
        """Get the current device history (thread-safe)."""
        with self._lock:
            return dict(self._history)

    def _run(self):
        """Main scanner loop."""
        log.info(f"Scanner running on {self.subnet}")

        while not self._stop_event.is_set():
            try:
                self._do_scan()
            except Exception as e:
                log.error(f"Scan error: {e}")

            # Wait for next scan, checking stop event periodically
            for _ in range(self.arp_interval):
                if self._stop_event.is_set():
                    break
                time.sleep(1)

    def _do_scan(self):
        """Perform a single scan cycle."""
        log.info("Starting scan cycle...")

        # Step 1: Ping sweep
        live_ips = set(ping_sweep_parallel(generate_ips(self.subnet)))
        log.info(f"Ping: {len(live_ips)} live hosts")

        # Step 2: ARP/MAC lookup
        mac_map = mac_discovery(list(live_ips))

        # Step 3: Reverse DNS
        rdns_map = bulk_reverse_dns(list(live_ips))

        # Step 4: mDNS (quick, reduced timeout for background)
        mdns_map = mdns_discovery(list(live_ips), timeout=min(self.mdns_timeout, 5))

        # Step 5: Service probing
        service_map = bulk_service_probe(list(live_ips))

        # Build current scan results
        all_ips = live_ips | set(mdns_map.keys()) | set(rdns_map.keys())
        current_scan = []
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

            current_scan.append({
                "ip": ip,
                "hostname": hostname,
                "mac": mac,
                "vendor": vendor,
                "services": services,
                "source": "+".join(sources)
            })

        # Merge with history
        with self._lock:
            self._history = merge_scan(current_scan, self._history)
            self._current_devices = list(self._history.values())
            self._current_devices.sort(key=lambda d: list(map(int, d["ip"].split("."))))
            self._last_scan_time = datetime.now()
            save_history(self._history)

        log.info(f"Scan complete: {len(self._current_devices)} devices in history")
