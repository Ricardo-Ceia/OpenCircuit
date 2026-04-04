"""
Known devices: user-assigned friendly names persisted by MAC address.
These override all automatic label resolution.
"""

import os
import logging

from secure_storage import read_json, write_json_atomic

log = logging.getLogger(__name__)

KNOWN_DEVICES_FILE = os.environ.get(
    "KNOWN_DEVICES_FILE",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "known_devices.json"),
)


def load_known_devices() -> dict:
    """Load known devices from JSON file. Returns dict keyed by lowercase MAC."""
    if not os.path.exists(KNOWN_DEVICES_FILE):
        return {}
    data = read_json(KNOWN_DEVICES_FILE, default={})
    if not isinstance(data, dict):
        log.warning("Failed to load known devices: invalid JSON structure")
        return {}
    # Normalize MAC keys to lowercase
    return {k.lower(): v for k, v in data.items()}


def save_known_devices(data: dict):
    """Save known devices to JSON file."""
    try:
        write_json_atomic(KNOWN_DEVICES_FILE, data, indent=2)
    except OSError as e:
        log.warning(f"Failed to save known devices: {e}")


def get_known_name(mac: str) -> str | None:
    """Look up user-assigned name for a MAC address. Returns None if not found."""
    if not mac or mac == "unknown":
        return None
    data = load_known_devices()
    entry = data.get(mac.lower())
    if entry and isinstance(entry, dict):
        return entry.get("name")
    return None


def set_known_name(mac: str, name: str):
    """Assign a friendly name to a MAC address."""
    if not mac or mac == "unknown":
        raise ValueError("Cannot assign name to unknown MAC")
    data = load_known_devices()
    data[mac.lower()] = {
        "name": name,
        "claimed_at": __import__("datetime").datetime.now().isoformat(),
    }
    save_known_devices(data)
