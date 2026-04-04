"""Backward-compatible module alias for CLI flow."""

import sys

from app.cli import flow as _impl

sys.modules[__name__] = _impl
