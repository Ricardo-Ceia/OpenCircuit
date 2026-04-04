from __future__ import annotations

from dataclasses import dataclass
import secrets

from fastapi import HTTPException, Request, WebSocket

AUTH_COOKIE_NAME = "opencircuit_session"
AUTH_HEADER_NAME = "x-opencircuit-token"


@dataclass(frozen=True)
class AuthSettings:
    token: str
    configured_allowed_origins: set[str]


class AuthManager:
    def __init__(self, settings: AuthSettings):
        self._settings = settings

    @property
    def token(self) -> str:
        return self._settings.token

    @property
    def configured_allowed_origins(self) -> set[str]:
        return set(self._settings.configured_allowed_origins)

    def allowed_origins_for_request(self, ws: WebSocket) -> set[str]:
        allowed = {
            "http://127.0.0.1:8080",
            "http://localhost:8080",
        }

        host = (ws.headers.get("host") or "").strip()
        if host:
            allowed.add(f"http://{host}")
            allowed.add(f"https://{host}")

        allowed.update(self._settings.configured_allowed_origins)
        return allowed

    def is_allowed_ws_origin(self, ws: WebSocket) -> bool:
        origin = (ws.headers.get("origin") or "").strip().rstrip("/")
        if not origin:
            return False
        return origin in self.allowed_origins_for_request(ws)

    def _token_matches(self, candidate: str | None) -> bool:
        if not candidate:
            return False
        return secrets.compare_digest(candidate, self._settings.token)

    def request_is_authenticated(self, request: Request) -> bool:
        header_token = request.headers.get(AUTH_HEADER_NAME)
        cookie_token = request.cookies.get(AUTH_COOKIE_NAME)
        return self._token_matches(header_token) or self._token_matches(cookie_token)

    def require_api_auth(self, request: Request):
        if self.request_is_authenticated(request):
            return
        raise HTTPException(status_code=401, detail="Unauthorized")

    def websocket_is_authenticated(self, ws: WebSocket) -> bool:
        query_token = ws.query_params.get("token")
        cookie_token = ws.cookies.get(AUTH_COOKIE_NAME)
        return self._token_matches(query_token) or self._token_matches(cookie_token)
