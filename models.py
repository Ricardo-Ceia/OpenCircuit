"""Backward-compatible module alias for domain models."""

import sys

from app.domain import models as _impl

sys.modules[__name__] = _impl
