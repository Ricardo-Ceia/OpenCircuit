"""
Strict label resolution: no guessing, only authoritative or self-reported identity.

Authoritative (verified):
  - lockdownd DeviceName (requires trust handshake)
  - mDNS .local self-announced hostname

High-trust (identified):
  - Reverse DNS hostname (network-assigned, e.g. LGwebOSTV.home)
  - UPnP friendlyName from device description XML

Category fallback (unidentified):
  - Unidentified [device_type] when type is known
  - Unidentified device when nothing is available

Never used as label:
  - HTTP title, HTTP/SSDP server headers, MAC vendor
"""

from __future__ import annotations
from typing import Optional
import re

_UUID_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)

_LOCAL_TLDS = {".home", ".lan", ".local", ".internal"}


def _is_machine_generated(name: str) -> bool:
    """Check if a hostname is a machine-generated identifier, not a human name."""
    return bool(_UUID_PATTERN.match(name))


def _strip_local_tld(hostname: str) -> str:
    """Strip common local TLDs for cleaner display. LGwebOSTV.home -> LGwebOSTV"""
    h = hostname.strip()
    for tld in _LOCAL_TLDS:
        if h.lower().endswith(tld):
            return h[: -len(tld)]
    return h


def is_valid_rdns_label(hostname: str | None) -> bool:
    """Check if a reverse DNS hostname is a usable device label."""
    if not hostname:
        return False
    h = hostname.strip()
    if h.lower() == "unknown":
        return False
    # Must have a dot (FQDN like LGwebOSTV.home)
    if "." not in h:
        return False
    name = _strip_local_tld(h)
    if not name:
        return False
    # Skip PTR/in-addr.arpa
    if ".in-addr.arpa" in name.lower():
        return False
    # Skip IP-shaped names
    parts = name.split(".")
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return False
    # Skip machine-generated identifiers
    if _is_machine_generated(name.lower()):
        return False
    return True


def is_valid_mdns_label(hostname: str | None) -> bool:
    """Check if an mDNS hostname is a real device self-name, not generic."""
    if not hostname:
        return False
    h = hostname.strip().lower()
    if not h.endswith(".local"):
        return False
    name = h.removesuffix(".local")
    if not name:
        return False
    # Skip PTR/in-addr.arpa names (e.g. "1.0.168.192.in-addr.arpa")
    if ".in-addr.arpa" in name:
        return False
    # Skip IP-shaped names (e.g. "1.0.168.192")
    parts = name.split(".")
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return False
    # Skip machine-generated identifiers (UUIDs, random hex)
    if _is_machine_generated(name):
        return False
    return True


def _is_lockdownd_success(services: list[str]) -> bool:
    """Check if lockdownd returned a device name (trust handshake succeeded)."""
    return any(
        s.startswith("lockdownd:") and ":" in s[len("lockdownd:"):]
        for s in (services or [])
    )


def _extract_device_type_from_upnp(upnp_info: dict | None) -> str | None:
    """
    Extract human-readable device category from UPnP deviceType.
    e.g. 'urn:schemas-upnp-org:device:MediaRenderer:1' -> 'MediaRenderer'
    """
    if not upnp_info:
        return None
    dt = upnp_info.get("device_type", "")
    if not dt:
        return None
    parts = dt.split(":")
    if len(parts) >= 2:
        return parts[-2]
    return None


def resolve_label(
    *,
    mdns_hostname: str | None,
    lockdownd_device_name: str | None,
    lockdownd_success: bool,
    rdns_hostname: str | None = None,
    upnp_friendly_name: str | None,
    upnp_device_type: str | None,
    ios_port_detected: bool,
    known_name: str | None = None,
) -> dict:
    """
    Determine the authoritative display label for a device.

    Returns:
        label: The device name or "Unidentified [type]" / "Unidentified device"
        label_source: "known" | "lockdownd" | "mdns" | "rdns" | "upnp" | "device_type" | "unidentified"
        label_authoritative: True for known, lockdownd, or mDNS
        identity_status: "claimed" | "verified" | "identified" | "unidentified"
    """

    # 0. User-assigned name (claimed, highest priority)
    if known_name and known_name.strip():
        return {
            "label": known_name.strip(),
            "label_source": "known",
            "label_authoritative": True,
            "identity_status": "claimed",
        }

    # 1. Lockdownd DeviceName (verified, authoritative)
    if lockdownd_device_name and lockdownd_success:
        return {
            "label": lockdownd_device_name,
            "label_source": "lockdownd",
            "label_authoritative": True,
            "identity_status": "verified",
        }

    # 2. mDNS .local self-announced name (verified, authoritative)
    if mdns_hostname and is_valid_mdns_label(mdns_hostname):
        display = mdns_hostname.removesuffix(".local")
        return {
            "label": display,
            "label_source": "mdns",
            "label_authoritative": True,
            "identity_status": "verified",
        }

    # 3. Reverse DNS hostname (identified, non-authoritative)
    if rdns_hostname and is_valid_rdns_label(rdns_hostname):
        return {
            "label": _strip_local_tld(rdns_hostname),
            "label_source": "rdns",
            "label_authoritative": False,
            "identity_status": "identified",
        }

    # 4. UPnP friendlyName from XML (identified, non-authoritative)
    if upnp_friendly_name and upnp_friendly_name.strip():
        return {
            "label": upnp_friendly_name.strip(),
            "label_source": "upnp",
            "label_authoritative": False,
            "identity_status": "identified",
        }

    # 4. Unidentified [device_type] — best available type hint
    device_type = upnp_device_type
    if not device_type and ios_port_detected:
        device_type = "Apple iOS Device"

    if device_type:
        return {
            "label": f"Unidentified {device_type}",
            "label_source": "device_type",
            "label_authoritative": False,
            "identity_status": "unidentified",
        }

    # 5. Nothing at all
    return {
        "label": "Unidentified device",
        "label_source": "unidentified",
        "label_authoritative": False,
        "identity_status": "unidentified",
    }


def assign_stable_aliases(devices: list[dict]) -> list[dict]:
    """
    For same-type unidentified devices, assign stable numbered aliases.
    e.g. Two "Unidentified Apple iOS Device" -> "Apple iOS Device #1", "#2"
    Sorts by first_seen for stable ordering.

    Modifies devices in place and returns the list.
    """
    # Group by base label (strip "Unidentified " prefix for grouping)
    groups: dict[str, list[dict]] = {}
    for d in devices:
        identity = d.get("identity_status", "unidentified")
        if identity in ("verified", "claimed"):
            continue
        label = d.get("label", "Unidentified device")
        # Group key: strip "Unidentified " prefix for grouping
        if label.startswith("Unidentified "):
            key = label[len("Unidentified "):]
        else:
            key = label
        groups.setdefault(key, []).append(d)

    for key, group in groups.items():
        if len(group) < 2:
            continue
        # Sort by first_seen for stable ordering
        group.sort(
            key=lambda d: d.get("first_seen", ""),
            reverse=False,
        )
        for i, d in enumerate(group, 1):
            d["alias"] = f"{key} #{i}"
            # Update label to show alias
            d["label"] = d["alias"]

    return devices
