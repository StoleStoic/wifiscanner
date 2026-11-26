"""Scan sources. Each exposes `scan() -> (networks, connection|None)`."""

from __future__ import annotations

import sys


class ScanError(Exception):
    """A scan failed in a way the user can act on (message is shown in the UI)."""


def default_source() -> str:
    return "windows" if sys.platform == "win32" else "demo"
