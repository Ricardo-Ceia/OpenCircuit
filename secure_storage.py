"""Backward-compatible module alias for secure storage helpers."""

import sys

from app.storage import secure_storage as _impl

sys.modules[__name__] = _impl
