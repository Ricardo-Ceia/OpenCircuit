"""OpenCircuit Web Dashboard Server."""

from __future__ import annotations

import asyncio
import logging
import os
import secrets
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request, WebSocket
from fastapi.staticfiles import StaticFiles

from app.http.server_auth import AUTH_HEADER_NAME, AuthManager, AuthSettings
from app.http.server_routes import create_routes
from app.http.server_ws import WebSocketManager
from app.network.scanner import BackgroundScanner
from app.runtime.settings import load_server_runtime_settings

log = logging.getLogger(__name__)

RUNTIME_SETTINGS = load_server_runtime_settings()
SUBNET = RUNTIME_SETTINGS.subnet

AUTH_TOKEN = os.environ.get("OPENCIRCUIT_API_TOKEN") or secrets.token_urlsafe(32)

ROOT_DIR = Path(__file__).resolve().parents[2]
PRIMARY_STATIC_DIR = ROOT_DIR / "web" / "static-svelte"
LEGACY_STATIC_DIR = ROOT_DIR / "web" / "static"
STATIC_DIR = PRIMARY_STATIC_DIR if PRIMARY_STATIC_DIR.exists() else LEGACY_STATIC_DIR

WS_ALLOWED_CLIENT_MESSAGES = {"ping"}


def create_app() -> FastAPI:
    scanner = BackgroundScanner(subnet=SUBNET)
    auth = AuthManager(
        AuthSettings(
            token=AUTH_TOKEN,
            configured_allowed_origins=RUNTIME_SETTINGS.configured_allowed_origins,
        )
    )
    ws_manager = WebSocketManager(
        scanner=scanner,
        auth=auth,
        max_clients=RUNTIME_SETTINGS.ws_max_clients,
        max_message_bytes=RUNTIME_SETTINGS.ws_max_message_bytes,
        allowed_client_messages=WS_ALLOWED_CLIENT_MESSAGES,
    )

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        event_loop = asyncio.get_running_loop()

        def on_scan_done(devices: list[dict]):
            try:
                asyncio.run_coroutine_threadsafe(ws_manager.broadcast_update(devices), event_loop)
            except RuntimeError as exc:
                log.error("Failed to schedule WS broadcast: %s", exc)
            except OSError as exc:
                log.error("Failed to schedule WS broadcast: %s", exc)

        scanner.register_callback(on_scan_done)
        scanner.start()
        log.info("Scanner started on %s", SUBNET)
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

    if (STATIC_DIR / "_app").exists():
        app.mount("/_app", StaticFiles(directory=STATIC_DIR / "_app"), name="svelte-app")

    routes = create_routes(
        scanner=scanner,
        require_api_auth=auth.require_api_auth,
        static_dir=STATIC_DIR,
        auth_token=auth.token,
    )
    app.include_router(routes)

    @app.websocket("/ws")
    async def websocket_endpoint(ws: WebSocket):
        await ws_manager.handle_connection(ws)

    app.state.scanner = scanner
    app.state.auth = auth
    app.state.ws_manager = ws_manager
    app.state.subnet = SUBNET
    return app


app = create_app()

# Backward-compatible exports for existing tests/tools.
AUTH_COOKIE_NAME = "opencircuit_session"
AUTH_TOKEN = AUTH_TOKEN
scanner = app.state.scanner
connected_clients = app.state.ws_manager.connected_clients
WS_MAX_MESSAGE_BYTES = RUNTIME_SETTINGS.ws_max_message_bytes


def _request_is_authenticated(request: Request) -> bool:
    return app.state.auth.request_is_authenticated(request)


def require_api_auth(request: Request):
    return app.state.auth.require_api_auth(request)


def _is_allowed_ws_origin(ws) -> bool:
    return app.state.auth.is_allowed_ws_origin(ws)


async def websocket_endpoint(ws):
    await app.state.ws_manager.handle_connection(ws)
