from __future__ import annotations

from datetime import datetime
import json
import logging

from fastapi import WebSocket, WebSocketDisconnect

from device_history import get_history_stats
from identity import assign_stable_aliases
from scanner import BackgroundScanner
from server_auth import AuthManager

log = logging.getLogger(__name__)


class WebSocketManager:
    def __init__(
        self,
        *,
        scanner: BackgroundScanner,
        auth: AuthManager,
        max_clients: int,
        max_message_bytes: int,
        allowed_client_messages: set[str],
    ):
        self._scanner = scanner
        self._auth = auth
        self._max_clients = max_clients
        self._max_message_bytes = max_message_bytes
        self._allowed_client_messages = set(allowed_client_messages)
        self.connected_clients: set[WebSocket] = set()
        self.last_broadcast_stamp = ""

    def _build_state_payload(self) -> dict:
        devices = [dict(d) for d in self._scanner.get_devices()]
        assign_stable_aliases(devices)
        stats = get_history_stats(self._scanner.get_history())
        return {
            "type": "full_state",
            "devices": devices,
            "stats": stats,
            "last_scan": datetime.now().isoformat(),
        }

    def _broadcast_stamp(self, devices: list[dict], stats: dict) -> str:
        parts = [
            str(stats.get("total", 0)),
            str(stats.get("online", 0)),
            str(stats.get("offline", 0)),
            str(stats.get("unidentified", 0)),
        ]
        for device in devices:
            parts.append(
                f"{device.get('ip','')}|{device.get('label','')}|{device.get('identity_status','')}|{device.get('status','')}|{device.get('last_seen','')}|{device.get('label_source','')}"
            )
        return "~".join(parts)

    async def broadcast_update(self, devices: list[dict]):
        if not self.connected_clients:
            return

        stats = get_history_stats(self._scanner.get_history())
        payload_devices = [dict(d) for d in devices]
        assign_stable_aliases(payload_devices)

        stamp = self._broadcast_stamp(payload_devices, stats)
        if stamp == self.last_broadcast_stamp:
            return
        self.last_broadcast_stamp = stamp

        message = json.dumps(
            {
                "type": "scan_update",
                "devices": payload_devices,
                "stats": stats,
                "last_scan": datetime.now().isoformat(),
            }
        )

        dead: set[WebSocket] = set()
        for client in tuple(self.connected_clients):
            try:
                await client.send_text(message)
            except Exception:
                dead.add(client)
        self.connected_clients.difference_update(dead)

    async def handle_connection(self, ws: WebSocket):
        if not self._auth.is_allowed_ws_origin(ws):
            log.warning(
                "Rejected websocket connection from origin=%r host=%r",
                ws.headers.get("origin"),
                ws.headers.get("host"),
            )
            await ws.close(code=1008)
            return

        if not self._auth.websocket_is_authenticated(ws):
            log.warning(
                "Rejected websocket connection with missing/invalid auth from %r",
                ws.client,
            )
            await ws.close(code=1008)
            return

        if len(self.connected_clients) >= self._max_clients:
            log.warning("Rejected websocket connection: max clients reached (%d)", self._max_clients)
            await ws.close(code=1013)
            return

        await ws.accept()
        self.connected_clients.add(ws)

        await ws.send_text(json.dumps(self._build_state_payload()))

        try:
            while True:
                message = await ws.receive_text()
                if len(message.encode("utf-8")) > self._max_message_bytes:
                    log.warning("Closing websocket: message too large from %r", ws.client)
                    await ws.close(code=1009)
                    return
                if message not in self._allowed_client_messages:
                    log.warning("Closing websocket: invalid client message from %r", ws.client)
                    await ws.close(code=1008)
                    return
        except WebSocketDisconnect:
            pass
        except Exception:
            pass
        finally:
            self.connected_clients.discard(ws)
