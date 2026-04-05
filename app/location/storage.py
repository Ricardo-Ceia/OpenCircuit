from __future__ import annotations

from datetime import datetime
import os
from typing import Any

from app.storage.secure_storage import read_json, write_json_atomic


def _project_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


LOCATION_ROOMS_FILE = os.environ.get("LOCATION_ROOMS_FILE", os.path.join(_project_root(), "location_rooms.json"))
LOCATION_FINGERPRINTS_FILE = os.environ.get(
    "LOCATION_FINGERPRINTS_FILE",
    os.path.join(_project_root(), "location_fingerprints.json"),
)
LOCATION_ESTIMATES_FILE = os.environ.get(
    "LOCATION_ESTIMATES_FILE",
    os.path.join(_project_root(), "location_estimates.json"),
)


def _normalize_str_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    normalized: list[str] = []
    for item in value:
        if not isinstance(item, str):
            continue
        name = item.strip()
        if not name:
            continue
        normalized.append(name)
    return sorted(set(normalized))


def load_rooms() -> list[str]:
    data = read_json(LOCATION_ROOMS_FILE, default=[])
    return _normalize_str_list(data)


def save_rooms(rooms: list[str]):
    write_json_atomic(LOCATION_ROOMS_FILE, _normalize_str_list(rooms), indent=2)


def load_fingerprints() -> list[dict[str, Any]]:
    data = read_json(LOCATION_FINGERPRINTS_FILE, default=[])
    if not isinstance(data, list):
        return []

    normalized: list[dict[str, Any]] = []
    for entry in data:
        if not isinstance(entry, dict):
            continue
        room_value = entry.get("room")
        sensor_position_value = entry.get("sensor_position")
        device_key_value = entry.get("device_key")
        rssi_median = entry.get("rssi_median")
        sample_count = entry.get("sample_count")
        if not isinstance(room_value, str):
            continue
        room = room_value.strip()
        if not room:
            continue
        if not isinstance(sensor_position_value, str):
            continue
        sensor_position = sensor_position_value.strip()
        if not sensor_position:
            continue
        if not isinstance(device_key_value, str):
            continue
        device_key = device_key_value.strip().lower()
        if not device_key:
            continue
        if not isinstance(rssi_median, (int, float)):
            continue
        if not isinstance(sample_count, int) or sample_count < 1:
            continue
        normalized.append(
            {
                "room": room,
                "sensor_position": sensor_position,
                "device_key": device_key,
                "rssi_median": float(rssi_median),
                "sample_count": sample_count,
            }
        )
    return normalized


def save_fingerprints(entries: list[dict[str, Any]]):
    write_json_atomic(LOCATION_FINGERPRINTS_FILE, entries, indent=2)


def load_estimates() -> dict[str, dict[str, Any]]:
    data = read_json(LOCATION_ESTIMATES_FILE, default={})
    if not isinstance(data, dict):
        return {}

    normalized: dict[str, dict[str, Any]] = {}
    for device_key, entry in data.items():
        if not isinstance(device_key, str) or not isinstance(entry, dict):
            continue
        room = entry.get("room")
        confidence = entry.get("confidence")
        estimated_via = entry.get("estimated_via")
        distance_meters = entry.get("distance_meters")
        rssi_dbm = entry.get("rssi_dbm")
        updated_at = entry.get("updated_at")
        if not isinstance(room, str) or not room.strip():
            continue
        if not isinstance(confidence, (int, float)):
            continue
        if not isinstance(estimated_via, str) or not estimated_via.strip():
            continue
        if distance_meters is not None and not isinstance(distance_meters, (int, float)):
            continue
        if rssi_dbm is not None and not isinstance(rssi_dbm, int):
            continue
        if not isinstance(updated_at, str) or not updated_at.strip():
            continue
        normalized[device_key.lower()] = {
            "room": room.strip(),
            "confidence": max(0.0, min(1.0, float(confidence))),
            "estimated_via": estimated_via.strip(),
            "distance_meters": round(max(0.0, float(distance_meters)), 2) if distance_meters is not None else None,
            "rssi_dbm": int(rssi_dbm) if rssi_dbm is not None else None,
            "updated_at": updated_at,
        }
    return normalized


def save_estimates(estimates: dict[str, dict[str, Any]]):
    write_json_atomic(LOCATION_ESTIMATES_FILE, estimates, indent=2)


def set_estimate(
    device_key: str,
    *,
    room: str,
    confidence: float,
    estimated_via: str,
    distance_meters: float,
    rssi_dbm: int,
):
    estimates = load_estimates()
    estimates[device_key.lower()] = {
        "room": room.strip(),
        "confidence": max(0.0, min(1.0, float(confidence))),
        "estimated_via": estimated_via.strip(),
        "distance_meters": round(max(0.0, float(distance_meters)), 2),
        "rssi_dbm": int(rssi_dbm),
        "updated_at": datetime.now().isoformat(),
    }
    save_estimates(estimates)


def get_estimate(device_key: str) -> dict[str, Any] | None:
    return load_estimates().get(device_key.lower())
