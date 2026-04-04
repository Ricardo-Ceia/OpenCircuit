"""Helpers for safer local JSON persistence."""

from __future__ import annotations

import json
import os
import tempfile
from typing import Any


def _reject_symlink(path: str):
    if os.path.lexists(path) and os.path.islink(path):
        raise OSError(f"Refusing symlink path: {path}")


def read_json(path: str, default: Any):
    """Read JSON from disk while rejecting symlink targets."""
    try:
        _reject_symlink(path)
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (FileNotFoundError, json.JSONDecodeError, OSError, ValueError):
        return default


def write_json_atomic(path: str, data: Any, *, indent: int = 2):
    """Atomically write JSON with restrictive file permissions when possible."""
    parent = os.path.dirname(path) or "."
    os.makedirs(parent, exist_ok=True)

    if os.path.islink(parent):
        raise OSError(f"Refusing symlink directory: {parent}")
    _reject_symlink(path)

    fd, tmp_path = tempfile.mkstemp(prefix=".tmp-", suffix=".json", dir=parent, text=True)
    try:
        try:
            os.fchmod(fd, 0o600)
        except (AttributeError, OSError):
            pass

        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=indent)
            handle.flush()
            os.fsync(handle.fileno())

        os.replace(tmp_path, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
