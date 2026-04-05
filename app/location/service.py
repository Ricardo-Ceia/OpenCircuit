from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any

from app.location.engine import (
    aggregate_calibration_samples,
    estimate_room,
    normalize_device_key,
    rssi_to_pseudo_meters,
)
from app.location import storage


BLE_RSSI_FIELDS = ("ble_rssi_dbm",)
_SERVICE_RSSI_PATTERN = re.compile(r"ble:rssi=(-?\d{1,3})", re.IGNORECASE)


def _extract_ble_rssi_dbm(device: dict[str, Any]) -> int | None:
    for field in BLE_RSSI_FIELDS:
        value = device.get(field)
        if isinstance(value, int):
            return value
        if isinstance(value, float) and value.is_integer():
            return int(value)

    services = device.get("services")
    if isinstance(services, list):
        for service in services:
            if not isinstance(service, str):
                continue
            match = _SERVICE_RSSI_PATTERN.search(service)
            if match is None:
                continue
            try:
                return int(match.group(1))
            except ValueError:
                continue

    return None


@dataclass
class LocationService:
    """Coordinates BLE location room calibration and room estimation."""

    def list_rooms(self) -> list[str]:
        return storage.load_rooms()

    def set_rooms(self, rooms: list[str]) -> list[str]:
        storage.save_rooms(rooms)
        return storage.load_rooms()

    def calibrate(self, *, room: str, sensor_position: str, samples: list[dict[str, Any]]) -> dict[str, Any]:
        if not room.strip():
            raise ValueError("Room cannot be empty")
        if not sensor_position.strip():
            raise ValueError("Sensor position cannot be empty")
        if not samples:
            raise ValueError("Calibration samples cannot be empty")

        room_name = room.strip()
        position_name = sensor_position.strip()

        normalized_samples = []
        for sample in samples:
            if not isinstance(sample, dict):
                continue
            device_key = sample.get("device_key")
            rssi_dbm = sample.get("rssi_dbm")
            if not isinstance(device_key, str) or not device_key.strip():
                continue
            if not isinstance(rssi_dbm, int):
                continue
            normalized_samples.append(
                {
                    "room": room_name,
                    "sensor_position": position_name,
                    "device_key": normalize_device_key(device_key),
                    "rssi_dbm": rssi_dbm,
                }
            )

        if not normalized_samples:
            raise ValueError("No valid calibration samples provided")

        existing = storage.load_fingerprints()
        remaining = [
            entry
            for entry in existing
            if not (entry["room"] == room_name and entry["sensor_position"] == position_name)
        ]
        new_entries = aggregate_calibration_samples(normalized_samples)
        merged = remaining + new_entries
        storage.save_fingerprints(merged)

        rooms = set(storage.load_rooms())
        rooms.add(room_name)
        storage.save_rooms(sorted(rooms))

        return {
            "room": room_name,
            "sensor_position": position_name,
            "sample_count": len(normalized_samples),
            "fingerprint_count": len(new_entries),
        }

    def estimate(self, *, sensor_position: str, samples: list[dict[str, Any]]) -> list[dict[str, Any]]:
        if not sensor_position.strip():
            raise ValueError("Sensor position cannot be empty")
        if not samples:
            raise ValueError("Estimate samples cannot be empty")

        position_name = sensor_position.strip()
        fingerprints = storage.load_fingerprints()
        if not fingerprints:
            return []

        estimates: list[dict[str, Any]] = []
        for sample in samples:
            if not isinstance(sample, dict):
                continue
            device_key = sample.get("device_key")
            rssi_dbm = sample.get("rssi_dbm")
            if not isinstance(device_key, str) or not device_key.strip():
                continue
            if not isinstance(rssi_dbm, int):
                continue

            normalized_key = normalize_device_key(device_key)
            result = estimate_room(
                sample={
                    "device_key": normalized_key,
                    "sensor_position": position_name,
                    "rssi_dbm": rssi_dbm,
                },
                fingerprints=fingerprints,
            )
            if not result:
                continue

            distance_meters = rssi_to_pseudo_meters(rssi_dbm)
            storage.set_estimate(
                normalized_key,
                room=result["room"],
                confidence=result["confidence"],
                estimated_via=result["estimated_via"],
                distance_meters=distance_meters,
                rssi_dbm=rssi_dbm,
            )
            estimates.append(
                {
                    "device_key": normalized_key,
                    "room": result["room"],
                    "confidence": result["confidence"],
                    "estimated_via": result["estimated_via"],
                    "distance_meters": distance_meters,
                    "rssi_dbm": rssi_dbm,
                }
            )

        return estimates

    def estimate_online_devices(self, *, devices: list[dict[str, Any]], sensor_position: str = "scanner") -> dict[str, Any]:
        if not sensor_position.strip():
            raise ValueError("Sensor position cannot be empty")

        online_devices = [d for d in devices if isinstance(d, dict) and d.get("status") == "online"]

        skipped: list[dict[str, Any]] = []
        samples: list[dict[str, Any]] = []

        for device in online_devices:
            mac = device.get("mac")
            if not isinstance(mac, str) or not mac.strip() or mac.strip().lower() == "unknown":
                skipped.append(
                    {
                        "ip": device.get("ip"),
                        "device_key": None,
                        "reason": "missing_device_key",
                    }
                )
                continue

            normalized_key = normalize_device_key(mac)
            rssi_dbm = _extract_ble_rssi_dbm(device)
            if rssi_dbm is None:
                skipped.append(
                    {
                        "ip": device.get("ip"),
                        "device_key": normalized_key,
                        "reason": "no_ble_signal",
                    }
                )
                continue

            samples.append(
                {
                    "device_key": normalized_key,
                    "rssi_dbm": rssi_dbm,
                }
            )

        estimates = self.estimate(sensor_position=sensor_position, samples=samples) if samples else []
        estimated_keys = {entry["device_key"] for entry in estimates if isinstance(entry.get("device_key"), str)}

        for sample in samples:
            device_key = sample["device_key"]
            if device_key in estimated_keys:
                continue
            skipped.append(
                {
                    "device_key": device_key,
                    "reason": "no_matching_fingerprint",
                }
            )

        return {
            "sensor_position": sensor_position.strip(),
            "estimated": estimates,
            "skipped": skipped,
            "estimated_count": len(estimates),
            "skipped_count": len(skipped),
            "online_count": len(online_devices),
        }

    def get_estimate(self, device_key: str) -> dict[str, Any] | None:
        if not isinstance(device_key, str) or not device_key.strip():
            return None
        return storage.get_estimate(normalize_device_key(device_key))
