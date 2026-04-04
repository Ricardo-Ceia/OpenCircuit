"""Centralized environment configuration parsing."""

from __future__ import annotations

from dataclasses import dataclass
import os


def env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def env_int(name: str, default: int, *, min_value: int | None = None) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    if min_value is not None and value < min_value:
        return default
    return value


def env_csv_set(name: str) -> set[str]:
    raw = os.environ.get(name, "")
    return {item.strip().rstrip("/") for item in raw.split(",") if item.strip()}


@dataclass(frozen=True)
class MainRuntimeSettings:
    debug_probes: bool


@dataclass(frozen=True)
class ServerRuntimeSettings:
    subnet: str
    ws_max_clients: int
    ws_max_message_bytes: int
    configured_allowed_origins: set[str]


def load_main_runtime_settings() -> MainRuntimeSettings:
    return MainRuntimeSettings(
        debug_probes=env_bool("OPENCIRCUIT_DEBUG_PROBES", default=False),
    )


def load_server_runtime_settings() -> ServerRuntimeSettings:
    return ServerRuntimeSettings(
        subnet=os.environ.get("SUBNET", "192.168.1.0/24"),
        ws_max_clients=env_int("OPENCIRCUIT_WS_MAX_CLIENTS", default=12, min_value=1),
        ws_max_message_bytes=env_int("OPENCIRCUIT_WS_MAX_MESSAGE_BYTES", default=128, min_value=1),
        configured_allowed_origins=env_csv_set("OPENCIRCUIT_ALLOWED_ORIGINS"),
    )
