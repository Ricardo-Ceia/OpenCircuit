"""
Known devices: user-assigned friendly names persisted by MAC address.
These override all automatic label resolution.
"""

import os
import logging
from datetime import datetime
from typing import Any

from app.storage.secure_storage import read_json, write_json_atomic

log = logging.getLogger(__name__)

KNOWN_DEVICES_FILE = os.environ.get(
    "KNOWN_DEVICES_FILE",
    os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "known_devices.json",
    ),
)


def _normalize_known_devices(data: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(data, dict):
        return {}

    normalized: dict[str, dict[str, Any]] = {}
    for mac, entry in data.items():
        if not isinstance(mac, str) or not isinstance(entry, dict):
            continue
        name = entry.get("name")
        if not isinstance(name, str):
            continue
        normalized[mac.lower()] = {
            "name": name,
            "claimed_at": entry.get("claimed_at"),
        }
    return normalized


def load_known_devices() -> dict:
    """Load known devices from JSON file. Returns dict keyed by lowercase MAC."""
    if not os.path.exists(KNOWN_DEVICES_FILE):
        return {}
    data = read_json(KNOWN_DEVICES_FILE, default={})
    normalized = _normalize_known_devices(data)
    if not normalized and isinstance(data, dict) and data:
        log.warning("Failed to load known devices: invalid JSON structure")
    return normalized


def save_known_devices(data: dict[str, dict[str, Any]]):
    """Save known devices to JSON file."""
    try:
        write_json_atomic(KNOWN_DEVICES_FILE, data, indent=2)
    except OSError as exc:
        log.warning("Failed to save known devices: %s", exc)


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
    normalized_name = name.strip()
    if not normalized_name:
        raise ValueError("Name cannot be empty")

    data = load_known_devices()
    data[mac.lower()] = {
        "name": normalized_name,
        "claimed_at": datetime.now().isoformat(),
    }
    save_known_devices(data)
