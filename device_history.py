"""Backward-compatible module alias for device history storage."""

import sys

from app.storage import device_history as _impl

sys.modules[__name__] = _impl
