"""Scan engine: runs the active scan source in the background and keeps state."""

from __future__ import annotations

import threading
import time
from collections import deque
from typing import Any, Callable

from . import channels, oui
from .scanners import ScanError, default_source

HISTORY = 240


def interference(nets: list[dict]) -> None:
    """Annotate each network with co-channel (cci) and adjacent-channel (aci) counts."""
    for a in nets:
        cci = aci = 0
        sa = (a["span_lo"], a["span_hi"])
        for b in nets:
            if a is b or a["band"] != b["band"]:
                continue
            if not channels.overlaps(sa, (b["span_lo"], b["span_hi"])):
                continue
            # Same primary channel (or wide channels sharing it): stations defer to each other.
            # Partial overlap with a different primary is the harmful adjacent-channel case.
            if a["channel"] == b["channel"] or (a["band"] != "2.4" and sa[0] <= b["freq"] <= sa[1]
                                                 and b["span_lo"] <= a["freq"] <= b["span_hi"]):
                cci += 1
            else:
                aci += 1
        a["cci"], a["aci"] = cci, aci


class Engine:
    def __init__(self, store, on_roam: Callable[[dict, dict | None], None] | None = None):
        self.store = store
        self.on_roam = on_roam
        self.lock = threading.RLock()
        self.networks: dict[str, dict] = {}
        self.history: dict[str, deque] = {}
        self.connection: dict | None = None
        self.conn_history: deque = deque(maxlen=HISTORY)
        self.roams: deque = deque(maxlen=100)
        self.error: str | None = None
        self.paused = False
        self.scans = 0
        self.last_scan = 0.0
        self.source = ""
        self.source_label = ""
        self._scanner: Any = None
        self._want_source: str | None = None
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._thread: threading.Thread | None = None

    # ---- lifecycle
    def start(self, source: str | None = None) -> None:
        self._want_source = source or self.store.settings["scan"]["source"]
        self._thread = threading.Thread(target=self._run, daemon=True, name="scan")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()

    def set_source(self, source: str) -> None:
        self._want_source = source
        self._wake.set()

    def clear(self) -> None:
        with self.lock:
            self.networks.clear()
            self.history.clear()
            self.conn_history.clear()

    def rescan(self) -> None:
        self._wake.set()

    def _make(self, source: str):
        if source in ("auto", ""):
            source = default_source()
        if source == "windows":
            from .scanners.windows import WindowsScanner
            return source, WindowsScanner(interface=self.store.settings["scan"].get("interface") or None)
        if source.startswith("remote:"):
            from .scanners.remote import RemoteScanner
            name = source.split(":", 1)[1]
            probe = next((p for p in self.store.settings["probes"] if p.get("name") == name), None)
            if not probe:
                raise ScanError(f"Remote probe '{name}' is not configured.")
            return source, RemoteScanner(probe)
        from .scanners.simulated import SimulatedScanner
        return "demo", SimulatedScanner()

    def _run(self) -> None:
        while not self._stop.is_set():
            if self._want_source is not None:
                want, self._want_source = self._want_source, None
                try:
                    if self._scanner:
                        self._scanner.close()
                    self.source, self._scanner = self._make(want)
                    self.source_label = self._scanner.label
                    self.error = None
                    self.clear()
                except ScanError as e:
                    self._scanner, self.source, self.source_label, self.error = None, want, want, str(e)
            if self._scanner and not self.paused:
                try:
                    nets, conn = self._scanner.scan()
                    self._merge(nets, conn)
                    self.error = None
                except ScanError as e:
                    self.error = str(e)
                except Exception as e:  # keep the loop alive whatever a driver throws
                    self.error = f"Scan failed: {e}"
            self._wake.wait(max(1.0, float(self.store.settings["scan"]["interval"])))
            self._wake.clear()

    def _merge(self, nets: list[dict], conn: dict | None) -> None:
        now = time.time()
        max_age = float(self.store.settings["scan"]["max_age"])
        with self.lock:
            for n in nets:
                old = self.networks.get(n["bssid"])
                if old:
                    n["first_seen"] = old["first_seen"]
                    n["seen"] = old["seen"] + (1 if n["last_seen"] != old["last_seen"] else 0)
                    n["rssi_max"] = max(old.get("rssi_max", old["rssi"]), n["rssi"])
                    n["rssi_min"] = min(old.get("rssi_min", old["rssi"]), n["rssi"])
                else:
                    n["rssi_max"] = n["rssi_min"] = n["rssi"]
                self.networks[n["bssid"]] = n
                if not old or n["last_seen"] != old["last_seen"]:
                    self.history.setdefault(n["bssid"], deque(maxlen=HISTORY)).append((round(now, 1), n["rssi"]))
            for b in [b for b, n in self.networks.items() if now - n["last_seen"] > max_age]:
                del self.networks[b]
                self.history.pop(b, None)
            cb = conn.get("bssid") if conn else None
            for n in self.networks.values():
                n["connected"] = n["bssid"] == cb
            if conn and cb in self.networks:
                net = self.networks[cb]
                conn.setdefault("channel", net["channel"])
                conn.update(band=net["band"], channel=net["channel"], width=net["width"], security=net["security"])
                conn["rssi"] = net["rssi"] if abs(net["last_seen"] - now) < 15 else conn.get("rssi")
            # a virtual BSSID has no vendor of its own: borrow it from a sibling radio of the same unit
            known = [n for n in self.networks.values() if n["vendor"] and not n["vendor"].startswith("Private")]
            for n in self.networks.values():
                if n.get("local_mac") and n["vendor"].startswith("Private"):
                    sib = next((k for k in known if oui.same_unit(k["bssid"], n["bssid"])), None)
                    if sib:
                        n["vendor"] = f"{sib['vendor']} (virtual)"
            interference(list(self.networks.values()))
            prev = self.connection
            self.connection = conn
            if conn:
                self.conn_history.append((round(now, 1), conn.get("rssi"), conn.get("bssid")))
            self.scans += 1
            self.last_scan = now
        if conn and prev and (conn.get("bssid") != prev.get("bssid") or conn.get("ssid") != prev.get("ssid")):
            ev = {"t": now, "from_bssid": prev.get("bssid"), "to_bssid": conn.get("bssid"),
                  "from_ssid": prev.get("ssid"), "to_ssid": conn.get("ssid"),
                  "from_rssi": prev.get("rssi"), "to_rssi": conn.get("rssi")}
            self.roams.append(ev)
            if self.on_roam:
                self.on_roam(ev, conn)

    # ---- views
    def snapshot(self, with_ies: bool = False) -> list[dict]:
        with self.lock:
            if with_ies:
                return [dict(n) for n in self.networks.values()]
            return [{k: v for k, v in n.items() if k not in ("ies", "ie_hex")} for n in self.networks.values()]

    def get(self, bssid: str) -> dict | None:
        with self.lock:
            n = self.networks.get(bssid.lower())
            return dict(n) if n else None

    def history_dump(self) -> dict[str, list]:
        with self.lock:
            return {b: list(h) for b, h in self.history.items()}

    def status(self) -> dict:
        return {"source": self.source, "label": self.source_label, "error": self.error, "paused": self.paused,
                "scans": self.scans, "last_scan": self.last_scan, "count": len(self.networks)}
