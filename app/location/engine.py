from __future__ import annotations

from collections import defaultdict
from statistics import median
from typing import Any


PSEUDO_TX_POWER_DBM = -59.0
PSEUDO_PATH_LOSS_EXPONENT = 2.0
MIN_PSEUDO_DISTANCE_METERS = 0.1
MAX_PSEUDO_DISTANCE_METERS = 120.0


def normalize_device_key(device_key: str) -> str:
    return device_key.strip().lower()


def aggregate_calibration_samples(samples: list[dict[str, Any]]) -> list[dict[str, Any]]:
    buckets: dict[tuple[str, str, str], list[int]] = defaultdict(list)

    for sample in samples:
        if not isinstance(sample, dict):
            continue
        room_value = sample.get("room")
        sensor_position_value = sample.get("sensor_position")
        device_key_value = sample.get("device_key")
        rssi_dbm = sample.get("rssi_dbm")

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
        device_key = device_key_value.strip()
        if not device_key:
            continue

        if not isinstance(rssi_dbm, int):
            continue

        key = (room, sensor_position, normalize_device_key(device_key))
        buckets[key].append(rssi_dbm)

    fingerprints: list[dict[str, Any]] = []
    for (room, sensor_position, device_key), values in buckets.items():
        if not values:
            continue
        fingerprints.append(
            {
                "room": room,
                "sensor_position": sensor_position,
                "device_key": device_key,
                "rssi_median": float(median(values)),
                "sample_count": len(values),
            }
        )
    return fingerprints


def _distance(sample_rssi: int, reference_rssi: float) -> float:
    return abs(float(sample_rssi) - reference_rssi)


def rssi_to_pseudo_meters(rssi_dbm: int) -> float:
    exponent = (PSEUDO_TX_POWER_DBM - float(rssi_dbm)) / (10.0 * PSEUDO_PATH_LOSS_EXPONENT)
    distance = 10.0**exponent
    distance = max(MIN_PSEUDO_DISTANCE_METERS, min(MAX_PSEUDO_DISTANCE_METERS, distance))
    return round(distance, 2)


def estimate_room(
    *,
    sample: dict[str, Any],
    fingerprints: list[dict[str, Any]],
    k_neighbors: int = 5,
) -> dict[str, Any] | None:
    if k_neighbors < 1:
        k_neighbors = 1

    device_key = sample.get("device_key")
    sensor_position = sample.get("sensor_position")
    rssi_dbm = sample.get("rssi_dbm")

    if not isinstance(device_key, str) or not device_key.strip():
        return None
    if not isinstance(sensor_position, str) or not sensor_position.strip():
        return None
    if not isinstance(rssi_dbm, int):
        return None

    normalized_key = normalize_device_key(device_key)
    position = sensor_position.strip()

    candidates: list[tuple[float, dict[str, Any]]] = []
    for entry in fingerprints:
        if not isinstance(entry, dict):
            continue
        if entry.get("device_key") != normalized_key:
            continue
        if entry.get("sensor_position") != position:
            continue

        room = entry.get("room")
        reference_rssi = entry.get("rssi_median")
        if not isinstance(room, str) or not room.strip():
            continue
        if not isinstance(reference_rssi, (int, float)):
            continue

        candidates.append((_distance(rssi_dbm, float(reference_rssi)), entry))

    if not candidates:
        return None

    candidates.sort(key=lambda item: item[0])
    neighbors = candidates[: min(k_neighbors, len(candidates))]

    weighted_votes: dict[str, float] = defaultdict(float)
    for distance, entry in neighbors:
        room = str(entry["room"])
        weight = 1.0 / (1.0 + distance)
        weighted_votes[room] += weight

    if not weighted_votes:
        return None

    sorted_votes = sorted(weighted_votes.items(), key=lambda item: item[1], reverse=True)
    best_room, best_vote = sorted_votes[0]
    second_vote = sorted_votes[1][1] if len(sorted_votes) > 1 else 0.0
    total_vote = sum(weighted_votes.values())

    confidence = 0.0 if total_vote == 0 else (best_vote - second_vote) / total_vote
    confidence = max(0.0, min(1.0, confidence))

    return {
        "room": best_room,
        "confidence": confidence,
        "estimated_via": "sms-fingerprint",
        "neighbors": [
            {
                "room": entry["room"],
                "distance": distance,
            }
            for distance, entry in neighbors
        ],
    }
