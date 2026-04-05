from __future__ import annotations

import logging

from app.domain.identity import resolve_label
from app.domain.models import DeviceFingerprint, LabelInfo, ScannedDevice
from app.location.service import LocationService
from app.network.scan.arp import mac_discovery
from app.network.scan.dns import bulk_reverse_dns
from app.network.scan.mdns import mdns_discovery
from app.network.scan.ping import generate_ips, ping_sweep_parallel
from app.network.scan.probe import bulk_service_probe
from app.storage.known_devices import get_known_name

log = logging.getLogger(__name__)
_LOCATION_SERVICE = LocationService()


def run_single_scan(subnet: str, mdns_timeout: int = 10) -> list[dict]:
    log.info("Step 1: Ping sweep...")
    live_ips = set(ping_sweep_parallel(generate_ips(subnet)))
    log.info("Found %d live hosts", len(live_ips))

    log.info("Step 2: ARP/MAC vendor lookup...")
    mac_map = mac_discovery(list(live_ips))
    log.info("Found %d MAC addresses", len(mac_map))

    log.info("Step 3: Reverse DNS lookup...")
    rdns_map = bulk_reverse_dns(list(live_ips))
    log.info("Resolved %d hostnames via reverse DNS", len(rdns_map))

    log.info("Step 4: mDNS discovery...")
    mdns_map = mdns_discovery(list(live_ips), timeout=mdns_timeout)
    log.info("Resolved %d hostnames via mDNS", len(mdns_map))

    log.info("Step 5: Active service probing...")
    service_map = bulk_service_probe(list(live_ips))
    log.info("Identified %d devices via service probing", len(service_map))

    all_ips = live_ips | set(mdns_map.keys()) | set(rdns_map.keys()) | set(service_map.keys())

    scanned_devices: list[ScannedDevice] = []
    for ip in sorted(all_ips, key=lambda x: list(map(int, x.split(".")))):
        mac_info = mac_map.get(ip, {})
        vendor = mac_info.get("vendor")
        mac = mac_info.get("mac", "unknown")

        service_info = service_map.get(ip, {})
        device_type = service_info.get("device_type")
        services = service_info.get("services", [])
        fingerprint = service_info.get("fingerprint", {})

        known_name = get_known_name(mac)
        mdns_hostname = mdns_map.get(ip)
        rdns_hostname = rdns_map.get(ip)
        lockdownd_name = fingerprint.get("friendly_name") if fingerprint.get("device_type") == "iPhone" else None
        lockdownd_ok = any(s.startswith("lockdownd:") for s in services)
        upnp_name = fingerprint.get("friendly_name") if not lockdownd_ok else None
        upnp_type = fingerprint.get("device_type") if not lockdownd_ok else None
        ios_port = any("lockdownd (port" in s for s in services)

        resolved_label = resolve_label(
            mdns_hostname=mdns_hostname,
            lockdownd_device_name=lockdownd_name,
            lockdownd_success=lockdownd_ok,
            rdns_hostname=rdns_hostname,
            upnp_friendly_name=upnp_name,
            upnp_device_type=upnp_type,
            ios_port_detected=ios_port,
            known_name=known_name,
        )
        label_info = LabelInfo(
            label=resolved_label["label"],
            label_source=resolved_label["label_source"],
            label_authoritative=resolved_label["label_authoritative"],
            identity_status=resolved_label["identity_status"],
        )

        sources = []
        if ip in live_ips:
            sources.append("ping")
        if ip in mdns_map:
            sources.append("mdns")
        if ip in rdns_map:
            sources.append("rdns")
        if ip in mac_map:
            sources.append("arp")
        if ip in service_map:
            sources.append("probe")

        location_info = _LOCATION_SERVICE.get_estimate(mac)

        scanned_devices.append(
            ScannedDevice(
                ip=ip,
                label_info=label_info,
                hostname=mdns_map.get(ip) or rdns_map.get(ip, "unknown"),
                mac=mac,
                vendor=vendor,
                device_type=device_type,
                fingerprint=DeviceFingerprint.from_raw(fingerprint),
                services=list(services),
                source_channels=sources,
                location_hint=location_info["room"] if location_info else None,
                location_confidence=location_info["confidence"] if location_info else None,
                distance_meters=location_info.get("distance_meters") if location_info else None,
                rssi_dbm=location_info.get("rssi_dbm") if location_info else None,
                estimated_via=location_info["estimated_via"] if location_info else None,
            )
        )

    return [device.to_record() for device in scanned_devices]
