from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel

from app.domain.identity import assign_stable_aliases
from app.location.service import LocationService
from app.network.scanner import BackgroundScanner
from app.storage.device_history import get_history_stats
from app.storage.known_devices import set_known_name
from app.http.server_auth import AUTH_COOKIE_NAME


class NameRequest(BaseModel):
    name: str


class RoomListRequest(BaseModel):
    rooms: list[str]


class BleSampleRequest(BaseModel):
    device_key: str
    rssi_dbm: int


class CalibrationRequest(BaseModel):
    room: str
    sensor_position: str
    samples: list[BleSampleRequest]


class EstimateRequest(BaseModel):
    sensor_position: str
    samples: list[BleSampleRequest]


class EstimateOnlineRequest(BaseModel):
    sensor_position: str = "scanner"


def _create_devices_response(scanner: BackgroundScanner, *, location_service: LocationService) -> dict[str, Any]:
    devices = [dict(device) for device in scanner.get_devices()]
    for device in devices:
        mac = device.get("mac")
        if not isinstance(mac, str) or not mac.strip() or mac.strip().lower() == "unknown":
            continue
        estimate = location_service.get_estimate(mac)
        if not estimate:
            continue
        device["location_hint"] = estimate.get("room")
        device["location_confidence"] = estimate.get("confidence")
        device["distance_meters"] = estimate.get("distance_meters")
        device["rssi_dbm"] = estimate.get("rssi_dbm")
        device["estimated_via"] = estimate.get("estimated_via")

    assign_stable_aliases(devices)
    stats = get_history_stats(scanner.get_history())
    return {
        "devices": devices,
        "stats": stats,
        "last_scan": datetime.now().isoformat(),
    }


def create_routes(*, scanner: BackgroundScanner, require_api_auth, static_dir: Path, auth_token: str) -> APIRouter:
    router = APIRouter()
    location_service = LocationService()

    @router.get("/")
    async def index():
        response = FileResponse(static_dir / "index.html")
        response.set_cookie(
            key=AUTH_COOKIE_NAME,
            value=auth_token,
            httponly=True,
            secure=False,
            samesite="strict",
            path="/",
        )
        return response

    @router.get("/robots.txt")
    async def robots():
        robots_path = static_dir / "robots.txt"
        if robots_path.exists():
            return FileResponse(robots_path)
        raise HTTPException(status_code=404, detail="Not found")

    @router.get("/api/devices", dependencies=[Depends(require_api_auth)])
    async def list_devices():
        return _create_devices_response(scanner, location_service=location_service)

    @router.get("/api/devices/{ip}", dependencies=[Depends(require_api_auth)])
    async def get_device(ip: str):
        history = scanner.get_history()
        device = history.get(ip)
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")
        return device

    @router.put("/api/devices/{mac}/name", dependencies=[Depends(require_api_auth)])
    async def name_device(mac: str, body: NameRequest):
        if not body.name or not body.name.strip():
            raise HTTPException(status_code=400, detail="Name cannot be empty")
        try:
            set_known_name(mac, body.name.strip())
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

        return {
            "mac": mac,
            "name": body.name.strip(),
            "status": "ok",
        }

    @router.get("/api/location/rooms", dependencies=[Depends(require_api_auth)])
    async def list_rooms():
        return {"rooms": location_service.list_rooms()}

    @router.put("/api/location/rooms", dependencies=[Depends(require_api_auth)])
    async def set_rooms(body: RoomListRequest):
        return {"rooms": location_service.set_rooms(body.rooms)}

    @router.post("/api/location/calibration", dependencies=[Depends(require_api_auth)])
    async def calibrate_location(body: CalibrationRequest):
        try:
            result = location_service.calibrate(
                room=body.room,
                sensor_position=body.sensor_position,
                samples=[sample.model_dump() for sample in body.samples],
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        return {"status": "ok", **result}

    @router.post("/api/location/estimate", dependencies=[Depends(require_api_auth)])
    async def estimate_location(body: EstimateRequest):
        try:
            estimates = location_service.estimate(
                sensor_position=body.sensor_position,
                samples=[sample.model_dump() for sample in body.samples],
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        return {"status": "ok", "estimates": estimates}

    @router.post("/api/location/estimate-online", dependencies=[Depends(require_api_auth)])
    async def estimate_online_location(body: EstimateOnlineRequest):
        try:
            result = location_service.estimate_online_devices(
                devices=[dict(device) for device in scanner.get_devices()],
                sensor_position=body.sensor_position,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        return {"status": "ok", **result}

    @router.get("/api/location/{device_key}", dependencies=[Depends(require_api_auth)])
    async def get_location(device_key: str):
        estimate = location_service.get_estimate(device_key)
        if not estimate:
            raise HTTPException(status_code=404, detail="Location estimate not found")
        return estimate

    return router
