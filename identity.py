"""Backward-compatible module alias for identity logic."""

import sys

from app.domain import identity as _impl

sys.modules[__name__] = _impl
