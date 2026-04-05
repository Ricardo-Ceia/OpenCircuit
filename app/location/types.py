from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class BleSample:
    room: str
    sensor_position: str
    device_key: str
    rssi_dbm: int
    timestamp: datetime


@dataclass(frozen=True)
class LocationEstimate:
    room: str
    confidence: float
    estimated_via: str
    distance_meters: float
    rssi_dbm: int
    updated_at: datetime


@dataclass(frozen=True)
class FingerprintEntry:
    room: str
    sensor_position: str
    device_key: str
    rssi_median: float
    sample_count: int
