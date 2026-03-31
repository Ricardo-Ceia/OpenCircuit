import json
import os
from datetime import datetime, timedelta

HISTORY_FILE = "devices.json"
RETENTION_HOURS = 1  # Testing: 1 hour

def _get_history_path(filepath=HISTORY_FILE) -> str:
    """Get absolute path to history file relative to script location."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(script_dir, filepath)

def load_history(filepath=HISTORY_FILE) -> dict:
    """Load device history from JSON file."""
    abs_path = _get_history_path(filepath)
    if os.path.exists(abs_path):
        try:
            with open(abs_path) as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return {}
    return {}

def save_history(history: dict, filepath=HISTORY_FILE):
    """Save device history to JSON file."""
    abs_path = _get_history_path(filepath)
    with open(abs_path, 'w') as f:
        json.dump(history, f, indent=2)

def merge_scan(current_scan: list[dict], history: dict) -> dict:
    """
    Merge current scan results with history.
    - Updates last_seen for devices found in current scan
    - Marks devices not in current scan as offline
    - Removes devices older than retention period
    """
    now = datetime.now().isoformat()
    current_ips = set()

    for device in current_scan:
        ip = device["ip"]
        current_ips.add(ip)

        if ip in history:
            # Update existing device
            history[ip]["last_seen"] = now
            history[ip]["hostname"] = device.get("hostname", history[ip].get("hostname", "unknown"))
            history[ip]["mac"] = device.get("mac", history[ip].get("mac", "unknown"))
            history[ip]["vendor"] = device.get("vendor") or history[ip].get("vendor")
            history[ip]["sources"] = device.get("source", history[ip].get("sources", []))
            history[ip]["services"] = device.get("services", history[ip].get("services", []))
            history[ip]["status"] = "online"
        else:
            # New device
            history[ip] = {
                "ip": ip,
                "hostname": device.get("hostname", "unknown"),
                "mac": device.get("mac", "unknown"),
                "vendor": device.get("vendor"),
                "sources": device.get("source", []),
                "services": device.get("services", []),
                "first_seen": now,
                "last_seen": now,
                "status": "online"
            }

    # Mark devices not in current scan as offline
    for ip in history:
        if ip not in current_ips:
            history[ip]["status"] = "offline"

    # Remove devices older than retention period
    cutoff = datetime.now() - timedelta(hours=RETENTION_HOURS)
    expired_ips = []
    for ip, device in history.items():
        last_seen = datetime.fromisoformat(device["last_seen"])
        if last_seen < cutoff:
            expired_ips.append(ip)

    for ip in expired_ips:
        del history[ip]

    return history

def format_last_seen(iso_timestamp: str) -> str:
    """Format timestamp as human-readable relative time."""
    try:
        ts = datetime.fromisoformat(iso_timestamp)
        diff = datetime.now() - ts

        if diff.total_seconds() < 60:
            return "now"
        elif diff.total_seconds() < 3600:
            mins = int(diff.total_seconds() / 60)
            return f"{mins} min ago"
        elif diff.total_seconds() < 86400:
            hours = int(diff.total_seconds() / 3600)
            return f"{hours}h ago"
        else:
            days = int(diff.total_seconds() / 86400)
            return f"{days}d ago"
    except (ValueError, TypeError):
        return "unknown"

def get_history_as_list(history: dict) -> list[dict]:
    """Convert history dict to sorted list for display."""
    devices = list(history.values())
    devices.sort(key=lambda d: list(map(int, d["ip"].split("."))))
    return devices
