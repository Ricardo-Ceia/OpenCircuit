"""Backward-compatible module alias for known device storage."""

import sys

from app.storage import known_devices as _impl

sys.modules[__name__] = _impl
