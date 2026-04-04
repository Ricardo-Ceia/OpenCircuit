"""Backward-compatible module alias for server auth."""

import sys

from app.http import server_auth as _impl

sys.modules[__name__] = _impl
