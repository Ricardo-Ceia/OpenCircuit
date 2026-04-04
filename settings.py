"""Backward-compatible module alias for runtime settings."""

import sys

from app.runtime import settings as _impl

sys.modules[__name__] = _impl
