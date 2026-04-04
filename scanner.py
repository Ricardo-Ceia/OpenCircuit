"""Backward-compatible module alias for background scanner."""

import sys

from app.network import scanner as _impl

sys.modules[__name__] = _impl
