"""
OpenCircuit Web Dashboard Server

FastAPI server that wraps the BackgroundScanner and serves the web frontend.
"""

import asyncio
import json
import logging
import os
import secrets
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Request, Depends
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from scanner import BackgroundScanner
from identity import assign_stable_aliases
from device_history import get_history_stats
from known_devices import set_known_name
from settings import load_server_runtime_settings

log = logging.getLogger(__name__)

RUNTIME_SETTINGS = load_server_runtime_settings()
SUBNET = RUNTIME_SETTINGS.subnet
scanner = BackgroundScanner(subnet=SUBNET)
event_loop: Optional[asyncio.AbstractEventLoop] = None

AUTH_COOKIE_NAME = "opencircuit_session"
AUTH_HEADER_NAME = "x-opencircuit-token"
AUTH_TOKEN = os.environ.get("OPENCIRCUIT_API_TOKEN") or secrets.token_urlsafe(32)

WS_MAX_CLIENTS = RUNTIME_SETTINGS.ws_max_clients
WS_MAX_MESSAGE_BYTES = RUNTIME_SETTINGS.ws_max_message_bytes
WS_ALLOWED_CLIENT_MESSAGES = {"ping"}

# ─── WebSocket connection pool ────────────────────────────────────────────

connected_clients: set[WebSocket] = set()
last_broadcast_stamp = ""


CONFIGURED_ALLOWED_ORIGINS = RUNTIME_SETTINGS.configured_allowed_origins


def _allowed_origins_for_request(ws: WebSocket) -> set[str]:
    allowed = {
        "http://127.0.0.1:8080",
        "http://localhost:8080",
    }

    host = (ws.headers.get("host") or "").strip()
    if host:
        allowed.add(f"http://{host}")
        allowed.add(f"https://{host}")

    allowed.update(CONFIGURED_ALLOWED_ORIGINS)
    return allowed


def _is_allowed_ws_origin(ws: WebSocket) -> bool:
    origin = (ws.headers.get("origin") or "").strip().rstrip("/")
    if not origin:
        return False
    return origin in _allowed_origins_for_request(ws)


def _token_matches(candidate: str | None) -> bool:
    if not candidate:
        return False
    return secrets.compare_digest(candidate, AUTH_TOKEN)


def _request_is_authenticated(request: Request) -> bool:
    header_token = request.headers.get(AUTH_HEADER_NAME)
    cookie_token = request.cookies.get(AUTH_COOKIE_NAME)
    return _token_matches(header_token) or _token_matches(cookie_token)


def require_api_auth(request: Request):
    if _request_is_authenticated(request):
        return
    raise HTTPException(status_code=401, detail="Unauthorized")


def _websocket_is_authenticated(ws: WebSocket) -> bool:
    query_token = ws.query_params.get("token")
    cookie_token = ws.cookies.get(AUTH_COOKIE_NAME)
    return _token_matches(query_token) or _token_matches(cookie_token)


async def broadcast_update(devices: list[dict]):
    """Push device updates to all connected WebSocket clients."""
    global last_broadcast_stamp

    if not connected_clients:
        return
    stats = get_history_stats(scanner.get_history())
    payload_devices = [dict(d) for d in devices]
    assign_stable_aliases(payload_devices)

    stamp_parts = [
        str(stats.get("total", 0)),
        str(stats.get("online", 0)),
        str(stats.get("offline", 0)),
        str(stats.get("unidentified", 0)),
    ]
    for d in payload_devices:
        stamp_parts.append(
            f"{d.get('ip','')}|{d.get('label','')}|{d.get('identity_status','')}|{d.get('status','')}|{d.get('last_seen','')}|{d.get('label_source','')}"
        )
    stamp = "~".join(stamp_parts)
    if stamp == last_broadcast_stamp:
        return
    last_broadcast_stamp = stamp

    msg = json.dumps({
        "type": "scan_update",
        "devices": payload_devices,
        "stats": stats,
        "last_scan": datetime.now().isoformat(),
    })
    dead: set[WebSocket] = set()
    for ws in tuple(connected_clients):
        try:
            await ws.send_text(msg)
        except Exception:
            dead.add(ws)
    connected_clients.difference_update(dead)


def _on_scan_done(devices: list[dict]):
    """Called by BackgroundScanner after each scan (runs in scanner thread)."""
    if event_loop is None:
        return
    try:
        asyncio.run_coroutine_threadsafe(broadcast_update(devices), event_loop)
    except Exception as e:
        log.error(f"Failed to schedule WS broadcast: {e}")


# ─── App lifecycle ────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    global event_loop
    event_loop = asyncio.get_running_loop()
    scanner.register_callback(_on_scan_done)
    scanner.start()
    log.info(f"Scanner started on {SUBNET}")
    yield
    scanner.stop()
    log.info("Scanner stopped")


app = FastAPI(title="OpenCircuit", lifespan=lifespan)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)

    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "base-uri 'self'; "
        "object-src 'none'; "
        "frame-ancestors 'none'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self'; "
        "connect-src 'self' ws: wss:"
    )

    if request.url.scheme == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

    return response

PRIMARY_STATIC_DIR = Path(__file__).parent / "web" / "static-svelte"
LEGACY_STATIC_DIR = Path(__file__).parent / "web" / "static"
STATIC_DIR = PRIMARY_STATIC_DIR if PRIMARY_STATIC_DIR.exists() else LEGACY_STATIC_DIR

if (STATIC_DIR / "_app").exists():
    app.mount("/_app", StaticFiles(directory=STATIC_DIR / "_app"), name="svelte-app")


# ─── REST endpoints ───────────────────────────────────────────────────────

@app.get("/")
async def index():
    response = FileResponse(STATIC_DIR / "index.html")
    response.set_cookie(
        key=AUTH_COOKIE_NAME,
        value=AUTH_TOKEN,
        httponly=True,
        secure=False,
        samesite="strict",
        path="/",
    )
    return response


@app.get("/robots.txt")
async def robots():
    robots_path = STATIC_DIR / "robots.txt"
    if robots_path.exists():
        return FileResponse(robots_path)
    raise HTTPException(status_code=404, detail="Not found")


@app.get("/api/devices", dependencies=[Depends(require_api_auth)])
async def list_devices():
    devices = [dict(d) for d in scanner.get_devices()]
    assign_stable_aliases(devices)
    stats = get_history_stats(scanner.get_history())
    return {
        "devices": devices,
        "stats": stats,
        "last_scan": datetime.now().isoformat(),
    }


@app.get("/api/devices/{ip}", dependencies=[Depends(require_api_auth)])
async def get_device(ip: str):
    history = scanner.get_history()
    device = history.get(ip)
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")
    return device


class NameRequest(BaseModel):
    name: str


@app.put("/api/devices/{mac}/name", dependencies=[Depends(require_api_auth)])
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
    if not _is_allowed_ws_origin(ws):
        log.warning(
            "Rejected websocket connection from origin=%r host=%r",
            ws.headers.get("origin"),
            ws.headers.get("host"),
        )
        await ws.close(code=1008)
        return

    if not _websocket_is_authenticated(ws):
        log.warning(
            "Rejected websocket connection with missing/invalid auth from %r",
            ws.client,
        )
        await ws.close(code=1008)
        return

    if len(connected_clients) >= WS_MAX_CLIENTS:
        log.warning("Rejected websocket connection: max clients reached (%d)", WS_MAX_CLIENTS)
        await ws.close(code=1013)
        return

    await ws.accept()
    connected_clients.add(ws)

    # Send current state immediately
    devices = [dict(d) for d in scanner.get_devices()]
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
            message = await ws.receive_text()
            if len(message.encode("utf-8")) > WS_MAX_MESSAGE_BYTES:
                log.warning("Closing websocket: message too large from %r", ws.client)
                await ws.close(code=1009)
                return
            if message not in WS_ALLOWED_CLIENT_MESSAGES:
                log.warning("Closing websocket: invalid client message from %r", ws.client)
                await ws.close(code=1008)
                return
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        connected_clients.discard(ws)
