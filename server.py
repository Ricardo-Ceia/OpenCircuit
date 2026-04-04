"""Backward-compatible module alias for runtime server."""

import sys

from app.runtime import server as _impl

sys.modules[__name__] = _impl
