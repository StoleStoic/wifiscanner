"""On-disk storage: settings, saved sessions, surveys and speed test history."""

from __future__ import annotations

import copy
import json
import os
import re
import sys
import threading
import time
from pathlib import Path
from typing import Any

DEFAULTS: dict[str, Any] = {
    "scan": {"source": "auto", "interval": 5, "max_age": 120, "interface": ""},
    "probes": [],  # {name, host, user, port, iface, key, sudo}
    "filters": [],  # {name, expr}
    "thresholds": {"good": -60, "fair": -70, "poor": -80},
    "home": {"ssids": [], "perimeter_m": 15, "path_loss_exp": 3.0, "lat": None, "lon": None},
    "inventory": {"aps": [], "neighbors": [], "devices": []},  # {bssid|mac, label}
    "speedtest": {"server": "cloudflare", "auto_roam": False, "roam_wait": 5, "continuous": False,
                  "interval": 300, "room": "", "rooms": ["Living room", "Kitchen", "Office", "Bedroom"],
                  "custom_url": ""},
    "ipscan": {"cidr": ""},
    "monitor": {"enabled": True, "interval": 30, "latency_ms": 150, "loss_pct": 20, "scope": "online"},
    "annotations": {},  # bssid -> note
    "ai": {"api_key": "", "model": "claude-opus-5-5"},
    "columns": [],
}


def data_dir() -> Path:
    env = os.environ.get("SURSUM_DATA")
    if env:
        p = Path(env)
    elif sys.platform == "win32":
        p = Path(os.environ.get("APPDATA", Path.home())) / "StoleSursum"
    else:
        p = Path.home() / ".sursum"
    p.mkdir(parents=True, exist_ok=True)
    (p / "sessions").mkdir(exist_ok=True)
    return p


def _merge(base: dict, over: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


class Store:
    def __init__(self, root: Path | None = None):
        self.root = root or data_dir()
        (self.root / "sessions").mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self.settings = _merge(DEFAULTS, self._read("settings.json", {}))

    def _read(self, name: str, default: Any) -> Any:
        try:
            return json.loads((self.root / name).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return default

    def _write(self, name: str, data: Any) -> None:
        with self._lock:
            tmp = self.root / (name + ".tmp")
            tmp.write_text(json.dumps(data), encoding="utf-8")
            tmp.replace(self.root / name)

    def update_settings(self, patch: dict) -> dict:
        with self._lock:
            self.settings = _merge(self.settings, patch)
            self._write("settings.json", self.settings)
            return self.settings

    def public_settings(self) -> dict:
        s = copy.deepcopy(self.settings)
        key = s["ai"].get("api_key") or ""
        s["ai"]["api_key"] = ""
        s["ai"]["has_key"] = bool(key or os.environ.get("ANTHROPIC_API_KEY"))
        return s

    # ---- generic documents (surveys, speed test history)
    def load(self, name: str, default: Any) -> Any:
        return self._read(name + ".json", default)

    def save(self, name: str, data: Any) -> None:
        self._write(name + ".json", data)

    # ---- sessions
    @staticmethod
    def _slug(name: str) -> str:
        return re.sub(r"[^A-Za-z0-9_.-]+", "_", name).strip("._")[:60] or "session"

    def list_sessions(self) -> list[dict]:
        out = []
        for f in sorted((self.root / "sessions").glob("*.json"), key=lambda p: -p.stat().st_mtime):
            try:
                d = json.loads(f.read_text(encoding="utf-8"))
                out.append({"id": f.stem, "name": d.get("name", f.stem), "saved": d.get("saved"),
                            "count": len(d.get("networks", [])), "source": d.get("source", "")})
            except (OSError, ValueError):
                continue
        return out

    def save_session(self, name: str, payload: dict) -> str:
        sid = f"{time.strftime('%Y%m%d-%H%M%S')}-{self._slug(name)}"
        payload = dict(payload, name=name, saved=time.time())
        self._write(f"sessions/{sid}.json", payload)
        return sid

    def get_session(self, sid: str) -> dict | None:
        return self._read(f"sessions/{self._slug(sid)}.json", None)

    def delete_session(self, sid: str) -> None:
        try:
            (self.root / "sessions" / f"{self._slug(sid)}.json").unlink()
        except OSError:
            pass
