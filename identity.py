"""
Strict label resolution: no guessing, only authoritative or self-reported identity.

Authoritative (verified):
  - lockdownd DeviceName (requires trust handshake)
  - mDNS .local self-announced hostname

High-trust (identified):
  - UPnP friendlyName from device description XML

Category fallback (unidentified):
  - Unidentified [device_type] when type is known
  - Unidentified device when nothing is available

Never used as label:
  - HTTP title, HTTP/SSDP server headers, reverse DNS, MAC vendor
"""

from __future__ import annotations
from typing import Optional


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
    upnp_friendly_name: str | None,
    upnp_device_type: str | None,
    ios_port_detected: bool,
) -> dict:
    """
    Determine the authoritative display label for a device.

    Returns:
        label: The device name or "Unidentified [type]" / "Unidentified device"
        label_source: "lockdownd" | "mdns" | "upnp" | "device_type" | "unidentified"
        label_authoritative: True only for lockdownd or mDNS
        identity_status: "verified" | "identified" | "unidentified"
    """

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

    # 3. UPnP friendlyName from XML (identified, non-authoritative)
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
