import asyncio
import json
from dataclasses import dataclass, field

import pytest
from fastapi import HTTPException
from starlette.websockets import WebSocketDisconnect

import server


@dataclass
class DummyRequest:
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)


class FakeWebSocket:
    def __init__(
        self,
        *,
        origin: str | None,
        host: str = "127.0.0.1:8080",
        token: str | None = None,
        cookie_token: str | None = None,
        incoming: list[object] | None = None,
    ):
        self.headers = {}
        if origin is not None:
            self.headers["origin"] = origin
        self.headers["host"] = host
        self.query_params = {}
        if token is not None:
            self.query_params["token"] = token
        self.cookies = {}
        if cookie_token is not None:
            self.cookies[server.AUTH_COOKIE_NAME] = cookie_token
        self.client = ("127.0.0.1", 43210)
        self.accepted = False
        self.closed_code: int | None = None
        self.sent_messages: list[str] = []
        self._incoming = list(incoming or [])

    async def close(self, code: int = 1000):
        self.closed_code = code

    async def accept(self):
        self.accepted = True

    async def send_text(self, message: str):
        self.sent_messages.append(message)

    async def receive_text(self) -> str:
        if self._incoming:
            next_item = self._incoming.pop(0)
            if isinstance(next_item, Exception):
                raise next_item
            return str(next_item)
        raise WebSocketDisconnect(code=1000)


def test_request_authentication_accepts_header_or_cookie():
    header_only = DummyRequest(headers={server.AUTH_HEADER_NAME: server.AUTH_TOKEN})
    cookie_only = DummyRequest(cookies={server.AUTH_COOKIE_NAME: server.AUTH_TOKEN})

    assert server._request_is_authenticated(header_only) is True
    assert server._request_is_authenticated(cookie_only) is True


def test_request_authentication_rejects_missing_token():
    request = DummyRequest()
    with pytest.raises(HTTPException) as exc:
        server.require_api_auth(request)
    assert exc.value.status_code == 401


def test_allowed_ws_origin_matches_local_dashboard_host():
    ws = FakeWebSocket(origin="http://127.0.0.1:8080", token=server.AUTH_TOKEN)
    assert server._is_allowed_ws_origin(ws) is True


def test_websocket_rejects_missing_origin():
    ws = FakeWebSocket(origin=None, token=server.AUTH_TOKEN)

    asyncio.run(server.websocket_endpoint(ws))

    assert ws.accepted is False
    assert ws.closed_code == 1008


def test_websocket_rejects_invalid_token():
    ws = FakeWebSocket(origin="http://127.0.0.1:8080", token="invalid")

    asyncio.run(server.websocket_endpoint(ws))

    assert ws.accepted is False
    assert ws.closed_code == 1008


def test_websocket_accepts_valid_origin_and_token(monkeypatch):
    monkeypatch.setattr(server.scanner, "get_devices", lambda: [])
    monkeypatch.setattr(server.scanner, "get_history", lambda: {})
    server.connected_clients.clear()

    ws = FakeWebSocket(
        origin="http://127.0.0.1:8080",
        token=server.AUTH_TOKEN,
        incoming=["ping", WebSocketDisconnect(code=1000)],
    )

    asyncio.run(server.websocket_endpoint(ws))

    assert ws.accepted is True
    assert ws.closed_code is None
    assert ws not in server.connected_clients
    assert len(ws.sent_messages) == 1
    payload = json.loads(ws.sent_messages[0])
    assert payload["type"] == "full_state"


def test_websocket_closes_on_oversized_message(monkeypatch):
    monkeypatch.setattr(server.scanner, "get_devices", lambda: [])
    monkeypatch.setattr(server.scanner, "get_history", lambda: {})
    server.connected_clients.clear()

    oversized = "x" * (server.WS_MAX_MESSAGE_BYTES + 1)
    ws = FakeWebSocket(
        origin="http://127.0.0.1:8080",
        token=server.AUTH_TOKEN,
        incoming=[oversized],
    )

    asyncio.run(server.websocket_endpoint(ws))

    assert ws.accepted is True
    assert ws.closed_code == 1009


def test_websocket_closes_on_invalid_client_message(monkeypatch):
    monkeypatch.setattr(server.scanner, "get_devices", lambda: [])
    monkeypatch.setattr(server.scanner, "get_history", lambda: {})
    server.connected_clients.clear()

    ws = FakeWebSocket(
        origin="http://127.0.0.1:8080",
        token=server.AUTH_TOKEN,
        incoming=["hello"],
    )

    asyncio.run(server.websocket_endpoint(ws))

    assert ws.accepted is True
    assert ws.closed_code == 1008
