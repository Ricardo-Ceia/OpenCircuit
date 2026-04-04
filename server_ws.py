"""Backward-compatible module alias for websocket manager."""

import sys

from app.http import server_ws as _impl

sys.modules[__name__] = _impl
