from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel

from app.domain.identity import assign_stable_aliases
from app.network.scanner import BackgroundScanner
from app.storage.device_history import get_history_stats
from app.storage.known_devices import set_known_name
from app.http.server_auth import AUTH_COOKIE_NAME


class NameRequest(BaseModel):
    name: str


def _create_devices_response(scanner: BackgroundScanner) -> dict[str, Any]:
    devices = [dict(device) for device in scanner.get_devices()]
    assign_stable_aliases(devices)
    stats = get_history_stats(scanner.get_history())
    return {
        "devices": devices,
        "stats": stats,
        "last_scan": datetime.now().isoformat(),
    }


def create_routes(*, scanner: BackgroundScanner, require_api_auth, static_dir: Path, auth_token: str) -> APIRouter:
    router = APIRouter()

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
        return _create_devices_response(scanner)

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

    return router
