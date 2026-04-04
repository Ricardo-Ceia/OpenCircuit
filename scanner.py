from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
import logging
import threading
import time

from device_history import load_history, merge_scan, save_history

log = logging.getLogger(__name__)

ScanRunner = Callable[[str, int], list[dict]]
ScanCallback = Callable[[list[dict]], None]


def _default_scan_runner(subnet: str, mdns_timeout: int) -> list[dict]:
    from scan_pipeline import run_single_scan

    return run_single_scan(subnet, mdns_timeout=mdns_timeout)


def _ip_sort_key(device: dict) -> list[int]:
    ip = str(device.get("ip", "0.0.0.0"))
    try:
        return [int(part) for part in ip.split(".")]
    except ValueError:
        return [0, 0, 0, 0]


class BackgroundScanner:
    """Runs network discovery in a background thread."""

    def __init__(
        self,
        subnet: str,
        mdns_timeout: int = 5,
        arp_interval: int = 30,
        scan_runner: ScanRunner | None = None,
    ):
        self.subnet = subnet
        self.mdns_timeout = mdns_timeout
        self.arp_interval = arp_interval
        self._scan_runner = scan_runner or _default_scan_runner

        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._current_devices: list[dict] = []
        self._history: dict = load_history()
        self._last_scan_time: datetime | None = None
        self._on_scan_complete: list[ScanCallback] = []

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

    def register_callback(self, fn: ScanCallback):
        """Register a function called after each scan."""
        self._on_scan_complete.append(fn)

    def _run(self):
        """Main scanner loop."""
        log.info("Scanner running on %s", self.subnet)

        while not self._stop_event.is_set():
            try:
                self._do_scan()
            except Exception as exc:
                log.error("Scan error: %s", exc)

            for _ in range(self.arp_interval):
                if self._stop_event.is_set():
                    break
                time.sleep(1)

    def _do_scan(self):
        """Perform a single scan cycle and update history."""
        log.info("Starting scan cycle...")
        current_scan = self._scan_runner(self.subnet, min(self.mdns_timeout, 5))

        with self._lock:
            self._history = merge_scan(current_scan, self._history)
            self._current_devices = sorted(self._history.values(), key=_ip_sort_key)
            self._last_scan_time = datetime.now()
            save_history(self._history)

            current_devices_snapshot = list(self._current_devices)

        log.info("Scan complete: %d devices in history", len(current_devices_snapshot))

        for callback in self._on_scan_complete:
            try:
                callback(current_devices_snapshot)
            except Exception as exc:
                log.error("Scan callback error: %s", exc)
