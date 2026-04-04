"""Backward-compatible module alias for scan pipeline."""

import sys

from app.network import scan_pipeline as _impl

sys.modules[__name__] = _impl
