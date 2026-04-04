"""Backward-compatible module alias for server routes."""

import sys

from app.http import server_routes as _impl

sys.modules[__name__] = _impl
