import json
import os
from datetime import datetime, timedelta

HISTORY_FILE = "devices.json"
# Default retention: 1 hour (testing). Override via RETENTION_HOURS env var.
DEFAULT_RETENTION_HOURS = 1

def _get_retention_hours() -> int:
    """Get retention hours from environment or default."""
    try:
        return int(os.environ.get("RETENTION_HOURS", DEFAULT_RETENTION_HOURS))
    except ValueError:
        return DEFAULT_RETENTION_HOURS

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

def clean_expired_devices(history: dict, retention_hours: int | None = None) -> list[str]:
    """
    Remove devices older than retention period.
    Returns list of removed IPs.
    """
    if retention_hours is None:
        retention_hours = _get_retention_hours()
    
    cutoff = datetime.now() - timedelta(hours=retention_hours)
    expired_ips = []
    
    for ip, device in list(history.items()):
        last_seen = datetime.fromisoformat(device.get("last_seen", ""))
        if last_seen < cutoff:
            expired_ips.append(ip)
            del history[ip]
    
    return expired_ips

def get_history_stats(history: dict) -> dict:
    """Get statistics about the device history."""
    if not history:
        return {"total": 0, "online": 0, "offline": 0, "claimed": 0, "verified": 0, "identified": 0, "unidentified": 0}

    return {
        "total": len(history),
        "online": sum(1 for d in history.values() if d.get("status") == "online"),
        "offline": sum(1 for d in history.values() if d.get("status") == "offline"),
        "claimed": sum(1 for d in history.values() if d.get("identity_status") == "claimed"),
        "verified": sum(1 for d in history.values() if d.get("identity_status") == "verified"),
        "identified": sum(1 for d in history.values() if d.get("identity_status") == "identified"),
        "unidentified": sum(1 for d in history.values() if d.get("identity_status") == "unidentified"),
    }

def merge_scan(current_scan: list[dict], history: dict, retention_hours: int | None = None) -> dict:
    """
    Merge current scan results with history.
    - Updates last_seen for devices found in current scan
    - Marks devices not in current scan as offline
    - Removes devices older than retention period
    - Enforces label precedence: authoritative labels are never overwritten by non-authoritative
    
    Args:
        current_scan: List of device dicts from current scan
        history: Existing history dict (modified in place)
        retention_hours: Override retention period (uses env var or default if None)
    
    Returns:
        The history dict (same object, modified in place)
    """
    if retention_hours is None:
        retention_hours = _get_retention_hours()
    
    now = datetime.now().isoformat()
    current_ips = set()

    for device in current_scan:
        ip = device["ip"]
        current_ips.add(ip)

        if ip in history:
            # Update existing device
            history[ip]["last_seen"] = now
            history[ip]["mac"] = device.get("mac", history[ip].get("mac", "unknown"))
            history[ip]["vendor"] = device.get("vendor") or history[ip].get("vendor")
            history[ip]["sources"] = device.get("source", history[ip].get("sources", []))
            history[ip]["services"] = device.get("services", history[ip].get("services", []))
            history[ip]["status"] = "online"

            # Label precedence: authoritative never overwritten by non-authoritative
            incoming_auth = device.get("label_authoritative", False)
            existing_auth = history[ip].get("label_authoritative", False)
            if incoming_auth or not existing_auth:
                history[ip]["label"] = device.get("label", history[ip].get("label", "Unidentified device"))
                history[ip]["label_source"] = device.get("label_source", history[ip].get("label_source", "unidentified"))
                history[ip]["label_authoritative"] = incoming_auth
                history[ip]["identity_status"] = device.get("identity_status", "unidentified")
            # Also keep hostname for backward compat
            history[ip]["hostname"] = device.get("hostname", history[ip].get("hostname", "unknown"))
            
            # Update fingerprint if available and has data
            fingerprint = device.get("fingerprint", {})
            if fingerprint and fingerprint.get("manufacturer"):
                # Merge fingerprint, preserving existing data if new one is empty
                existing_fp = history[ip].get("fingerprint", {})
                for key, value in fingerprint.items():
                    if value:  # Only update if new value is not empty
                        existing_fp[key] = value
                history[ip]["fingerprint"] = existing_fp
        else:
            # New device
            history[ip] = {
                "ip": ip,
                "label": device.get("label", "Unidentified device"),
                "label_source": device.get("label_source", "unidentified"),
                "label_authoritative": device.get("label_authoritative", False),
                "identity_status": device.get("identity_status", "unidentified"),
                "hostname": device.get("hostname", "unknown"),
                "mac": device.get("mac", "unknown"),
                "vendor": device.get("vendor"),
                "sources": device.get("source", []),
                "services": device.get("services", []),
                "fingerprint": device.get("fingerprint", {}),
                "first_seen": now,
                "last_seen": now,
                "status": "online"
            }

    # Mark devices not in current scan as offline
    for ip in history:
        if ip not in current_ips:
            history[ip]["status"] = "offline"

    # Remove expired devices
    expired = clean_expired_devices(history, retention_hours)
    if expired:
        from logging import getLogger
        getLogger(__name__).info(f"Removed {len(expired)} expired devices: {expired}")

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
