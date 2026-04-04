"""Domain models for scan and API payloads."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class LabelInfo:
    label: str
    label_source: str
    label_authoritative: bool
    identity_status: str


@dataclass
class DeviceFingerprint:
    manufacturer: str | None = None
    model: str | None = None
    friendly_name: str | None = None
    device_type: str | None = None
    model_number: str | None = None
    ios_version: str | None = None
    udid: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_raw(cls, raw: dict[str, Any] | None) -> "DeviceFingerprint":
        if not raw:
            return cls()

        known_keys = {
            "manufacturer",
            "model",
            "friendly_name",
            "device_type",
            "model_number",
            "ios_version",
            "udid",
        }
        extra = {k: v for k, v in raw.items() if k not in known_keys}
        return cls(
            manufacturer=raw.get("manufacturer"),
            model=raw.get("model"),
            friendly_name=raw.get("friendly_name"),
            device_type=raw.get("device_type"),
            model_number=raw.get("model_number"),
            ios_version=raw.get("ios_version"),
            udid=raw.get("udid"),
            extra=extra,
        )

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "manufacturer": self.manufacturer,
            "model": self.model,
            "friendly_name": self.friendly_name,
            "device_type": self.device_type,
            "model_number": self.model_number,
        }
        if self.ios_version is not None:
            payload["ios_version"] = self.ios_version
        if self.udid is not None:
            payload["udid"] = self.udid
        payload.update(self.extra)
        return payload


@dataclass
class ScannedDevice:
    ip: str
    label_info: LabelInfo
    hostname: str
    mac: str
    vendor: str | None
    services: list[str] = field(default_factory=list)
    source_channels: list[str] = field(default_factory=list)
    fingerprint: DeviceFingerprint = field(default_factory=DeviceFingerprint)
    device_type: str | None = None

    def to_record(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "label": self.label_info.label,
            "label_source": self.label_info.label_source,
            "label_authoritative": self.label_info.label_authoritative,
            "identity_status": self.label_info.identity_status,
            "hostname": self.hostname,
            "mac": self.mac,
            "vendor": self.vendor,
            "device_type": self.device_type,
            "fingerprint": self.fingerprint.to_dict(),
            "services": list(self.services),
            "source": "+".join(self.source_channels),
        }
