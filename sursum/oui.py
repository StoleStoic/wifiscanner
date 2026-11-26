"""MAC vendor lookup backed by the bundled IEEE OUI registry."""

from __future__ import annotations

import gzip
import threading
from pathlib import Path

_DB: dict[str, str] | None = None
_LOCK = threading.Lock()
_PATH = Path(__file__).parent / "data" / "oui.txt.gz"


def _load() -> dict[str, str]:
    global _DB
    with _LOCK:
        if _DB is None:
            db: dict[str, str] = {}
            try:
                with gzip.open(_PATH, "rt", encoding="utf-8") as f:
                    for line in f:
                        p, _, name = line.rstrip("\n").partition("\t")
                        db[p] = name
            except OSError:
                pass
            _DB = db
    return _DB


def norm(mac: str) -> str:
    return mac.replace("-", ":").lower()


def is_local(mac: str) -> bool:
    """Locally administered (randomised / virtual) address."""
    try:
        return bool(int(norm(mac).split(":")[0], 16) & 0x02)
    except ValueError:
        return False


def vendor(mac: str) -> str:
    """Vendor name for a MAC; virtual BSSIDs fall back to the base (universal) address."""
    m = norm(mac).replace(":", "").upper()
    if len(m) < 6:
        return ""
    db = _load()
    hit = db.get(m[:6])
    if hit:
        return hit
    if is_local(mac):
        first = int(m[:2], 16) & ~0x02
        hit = db.get(f"{first:02X}{m[2:6]}")
        return f"Private (possibly {hit})" if hit else "Private / randomised"
    return ""
