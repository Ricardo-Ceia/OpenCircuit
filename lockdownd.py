"""Backward-compatible module alias for lockdownd probing."""

import sys

from app.network import lockdownd as _impl

sys.modules[__name__] = _impl
