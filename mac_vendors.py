"""Backward-compatible module alias for MAC vendor mappings."""

import sys

from app.network import mac_vendors as _impl

sys.modules[__name__] = _impl
