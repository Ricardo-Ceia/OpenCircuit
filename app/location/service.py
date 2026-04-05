from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.location.engine import aggregate_calibration_samples, estimate_room, normalize_device_key
from app.location import storage


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

            storage.set_estimate(
                normalized_key,
                room=result["room"],
                confidence=result["confidence"],
                estimated_via=result["estimated_via"],
            )
            estimates.append(
                {
                    "device_key": normalized_key,
                    "room": result["room"],
                    "confidence": result["confidence"],
                    "estimated_via": result["estimated_via"],
                }
            )

        return estimates

    def get_estimate(self, device_key: str) -> dict[str, Any] | None:
        if not isinstance(device_key, str) or not device_key.strip():
            return None
        return storage.get_estimate(normalize_device_key(device_key))
