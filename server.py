"""
OpenCircuit Web Dashboard Server

FastAPI server that wraps the BackgroundScanner and serves the web frontend.
"""

import asyncio
import json
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from scanner import BackgroundScanner
from identity import assign_stable_aliases
from device_history import get_history_stats
from known_devices import get_known_name, set_known_name

log = logging.getLogger(__name__)

SUBNET = os.environ.get("SUBNET", "192.168.1.0/24")
scanner = BackgroundScanner(subnet=SUBNET)

# ─── WebSocket connection pool ────────────────────────────────────────────

connected_clients: set[WebSocket] = set()


async def broadcast_update(devices: list[dict]):
    """Push device updates to all connected WebSocket clients."""
    if not connected_clients:
        return
    stats = get_history_stats(scanner.get_history())
    assign_stable_aliases(devices)
    msg = json.dumps({
        "type": "scan_update",
        "devices": devices,
        "stats": stats,
        "last_scan": datetime.now().isoformat(),
    })
    dead = set()
    for ws in connected_clients:
        try:
            await ws.send_text(msg)
        except Exception:
            dead.add(ws)
    connected_clients -= dead


def _on_scan_done(devices: list[dict]):
    """Called by BackgroundScanner after each scan (runs in scanner thread)."""
    try:
        loop = asyncio.get_running_loop()
        loop.call_soon_threadsafe(lambda: asyncio.create_task(broadcast_update(devices)))
    except RuntimeError:
        pass


# ─── App lifecycle ────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    scanner.register_callback(_on_scan_done)
    scanner.start()
    log.info(f"Scanner started on {SUBNET}")
    yield
    scanner.stop()
    log.info("Scanner stopped")


app = FastAPI(title="OpenCircuit", lifespan=lifespan)

STATIC_DIR = Path(__file__).parent / "web" / "static"


# ─── REST endpoints ───────────────────────────────────────────────────────

@app.get("/")
async def index():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/devices")
async def list_devices():
    devices = scanner.get_devices()
    assign_stable_aliases(devices)
    stats = get_history_stats(scanner.get_history())
    return {
        "devices": devices,
        "stats": stats,
        "last_scan": datetime.now().isoformat(),
    }


@app.get("/api/devices/{ip}")
async def get_device(ip: str):
    history = scanner.get_history()
    device = history.get(ip)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    return device


class NameRequest(BaseModel):
    name: str


@app.put("/api/devices/{mac}/name")
async def name_device(mac: str, body: NameRequest):
    if not body.name or not body.name.strip():
        raise HTTPException(status_code=400, detail="Name cannot be empty")
    try:
        set_known_name(mac, body.name.strip())
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Trigger a rescan so labels update
    # (The background scanner will pick it up on next cycle)

    return {
        "mac": mac,
        "name": body.name.strip(),
        "status": "ok",
    }


# ─── WebSocket endpoint ──────────────────────────────────────────────────

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await ws.accept()
    connected_clients.add(ws)

    # Send current state immediately
    devices = scanner.get_devices()
    assign_stable_aliases(devices)
    stats = get_history_stats(scanner.get_history())
    await ws.send_text(json.dumps({
        "type": "full_state",
        "devices": devices,
        "stats": stats,
        "last_scan": datetime.now().isoformat(),
    }))

    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        connected_clients.discard(ws)
    except Exception:
        connected_clients.discard(ws)
