from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, cast

from pydantic import ValidationError

from app.http.server_routes import EstimateOnlineRequest, _create_devices_response, create_routes


class FakeScanner:
    def __init__(self, devices: list[dict], history: dict):
        self._devices = devices
        self._history = history

    def get_devices(self) -> list[dict]:
        return self._devices

    def get_history(self) -> dict:
        return self._history


class FakeLocationService:
    def __init__(self, estimate: dict | None):
        self._estimate = estimate

    def get_estimate(self, device_key: str) -> dict | None:
        if device_key.lower() == "aa:bb:cc:dd:ee:ff":
            return self._estimate
        return None


def test_create_devices_response_hydrates_saved_location_estimate():
    scanner = FakeScanner(
        devices=[
            {
                "ip": "192.168.1.10",
                "label": "Phone",
                "label_source": "known",
                "label_authoritative": True,
                "identity_status": "claimed",
                "hostname": "phone.local",
                "mac": "aa:bb:cc:dd:ee:ff",
                "status": "online",
                "source": "ping",
                "services": [],
                "fingerprint": {},
            }
        ],
        history={
            "192.168.1.10": {
                "status": "online",
                "identity_status": "claimed",
            }
        },
    )
    location_service = FakeLocationService(
        {
            "room": "Office",
            "confidence": 0.8,
            "distance_meters": 1.25,
            "rssi_dbm": -62,
            "estimated_via": "sms-fingerprint",
            "updated_at": "2026-01-01T00:00:00",
        }
    )

    payload = _create_devices_response(cast(Any, scanner), location_service=cast(Any, location_service))

    assert payload["devices"][0]["location_hint"] == "Office"
    assert payload["devices"][0]["distance_meters"] == 1.25
    assert payload["devices"][0]["rssi_dbm"] == -62


def test_estimate_online_route_uses_scanner_devices():
    scanner = FakeScanner(devices=[{"ip": "192.168.1.2", "status": "online", "mac": "aa:bb"}], history={})

    routes = create_routes(
        scanner=cast(Any, scanner),
        require_api_auth=lambda _request: None,
        static_dir=Path("."),
        auth_token="token",
    )

    estimate_route = cast(Any, next(route for route in routes.routes if getattr(route, "path", "") == "/api/location/estimate-online"))
    endpoint = estimate_route.endpoint

    result = endpoint(EstimateOnlineRequest())
    if hasattr(result, "__await__"):
        result = asyncio.run(result)

    assert result["status"] == "ok"
    assert result["sensor_position"] == "scanner"
    assert result["estimated_count"] == 0
    assert result["online_count"] == 1
    assert result["skipped_count"] == 1
    assert result["skipped"][0]["reason"] == "no_ble_signal"


def test_estimate_online_request_accepts_sensor_position_alias():
    scanner = FakeScanner(devices=[{"ip": "192.168.1.2", "status": "online", "mac": "aa:bb"}], history={})

    routes = create_routes(
        scanner=cast(Any, scanner),
        require_api_auth=lambda _request: None,
        static_dir=Path("."),
        auth_token="token",
    )

    estimate_route = cast(Any, next(route for route in routes.routes if getattr(route, "path", "") == "/api/location/estimate-online"))
    endpoint = estimate_route.endpoint
    try:
        body = EstimateOnlineRequest.model_validate({"sensor_position": "desk"})
    except ValidationError:
        assert False, "EstimateOnlineRequest should accept sensor_position alias"

    result = asyncio.run(endpoint(body))

    assert result["status"] == "ok"
    assert result["sensor_position"] == "desk"
