"""Continuous monitoring: is each device (and the internet) up, how fast does it answer, how much is lost.

A background loop pings every monitored address, keeps a rolling history, and logs events
when something goes down, comes back, or gets slow.
"""

from __future__ import annotations

import random
import re
import subprocess
import sys
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor

_NOWIN = {"creationflags": 0x08000000} if sys.platform == "win32" else {}
_TIME = re.compile(r"time[=<]\s*([\d.]+)\s*ms", re.I)
HISTORY = 2880          # samples kept per target (24 h at the default 30 s)
DOWN_AFTER = 3          # consecutive missed replies before a target counts as down
INTERNET = [("internet:1.1.1.1", "Internet (Cloudflare 1.1.1.1)", "1.1.1.1"), ("internet:8.8.8.8", "Internet (Google 8.8.8.8)", "8.8.8.8")]


def ping(ip: str, timeout_ms: int = 1000) -> float | None:
    """Round-trip time in ms, or None when there was no reply."""
    cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip] if sys.platform == "win32" else \
        ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), ip]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_ms / 1000 + 2, **_NOWIN)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if r.returncode != 0 or "unreachable" in r.stdout.lower():
        return None
    m = _TIME.search(r.stdout)
    return float(m.group(1)) if m else None


class Monitor:
    def __init__(self, store, registry, demo):
        self.store, self.registry, self.demo = store, registry, demo
        self.lock = threading.RLock()
        self.targets: dict[str, dict] = {}
        self.events: deque = deque(store.load("monitor_events", []), maxlen=1000)
        self.cycles = 0
        self.last_cycle = 0.0
        self._wake = threading.Event()
        threading.Thread(target=self._loop, daemon=True, name="monitor").start()

    def cfg(self) -> dict:
        return self.store.settings["monitor"]

    def _wanted(self) -> list[tuple[str, str, str, str]]:
        """(key, name, ip, kind) for everything that should be watched."""
        out = [(k, name, ip, "internet") for k, name, ip in INTERNET]
        scope = self.cfg().get("scope", "online")
        for d in self.registry.list():
            ip = (d.get("ips") or [None])[0]
            if not ip or d.get("self"):
                continue
            if scope == "authorized" and d.get("authorized") is not True and not d.get("gateway"):
                continue
            if scope == "online" and not d.get("online") and d["mac"] not in self.targets:
                continue
            name = d.get("name") or d.get("hostname") or d.get("model_guess") or d["mac"]
            out.append((d["mac"], name, ip, "gateway" if d.get("gateway") else "device"))
        return out

    def _event(self, t: dict, kind: str, text: str) -> None:
        self.events.append({"t": time.time(), "key": t["key"], "name": t["name"], "ip": t["ip"], "kind": kind, "text": text})

    def _record(self, t: dict, rtt: float | None, now: float) -> None:
        cfg = self.cfg()
        t["history"].append((round(now), None if rtt is None else round(rtt, 1)))
        t["last"] = rtt
        if rtt is None:
            t["misses"] += 1
            if t["up"] is not False and t["misses"] >= DOWN_AFTER:
                was = t["up"]
                t["up"], t["since"] = False, now
                if was:  # only report a change, not targets that were never reachable
                    self._event(t, "down", f"{t['name']} stopped answering.")
        else:
            if t["up"] is False:
                self._event(t, "up", f"{t['name']} is answering again after {max(1, round((now - t['since']) / 60))} min.")
            if t["up"] is not True:
                t["up"], t["since"] = True, now
            t["misses"] = 0
            limit = float(cfg.get("latency_ms", 150))
            slow = rtt > limit
            if slow and not t["slow"]:
                self._event(t, "slow", f"{t['name']} answered in {rtt:.0f} ms (limit {limit:.0f} ms).")
            t["slow"] = slow
        recent = [r for ts, r in t["history"] if ts >= now - 3600]
        loss = 100 * sum(r is None for r in recent) / max(1, len(recent))
        lossy = t["up"] is True and len(recent) >= 10 and loss >= float(cfg.get("loss_pct", 20))
        if lossy and not t["lossy"]:
            self._event(t, "loss", f"{t['name']} lost {loss:.0f}% of checks in the last hour.")
        t["lossy"] = lossy

    def _cycle(self) -> None:
        now = time.time()
        wanted = self._wanted()
        with self.lock:
            for key, name, ip, kind in wanted:
                t = self.targets.setdefault(key, {"key": key, "history": deque(maxlen=HISTORY), "up": None, "since": now,
                                                  "misses": 0, "last": None, "slow": False, "lossy": False})
                t.update(name=name, ip=ip, kind=kind)
            keep = {w[0] for w in wanted}
            for k in [k for k in self.targets if k not in keep]:
                del self.targets[k]
            todo = list(self.targets.values())
        if self.demo():
            res = [None if (t["ip"].endswith(".57") and int(now / 240) % 2) or random.random() < 0.03
                   else random.uniform(18, 30) if t["kind"] == "internet" else random.uniform(1, 9) * (12 if random.random() < 0.02 else 1)
                   for t in todo]
        else:
            with ThreadPoolExecutor(min(48, max(4, len(todo)))) as ex:
                res = list(ex.map(lambda t: ping(t["ip"]), todo))
        with self.lock:
            before = len(self.events)
            for t, r in zip(todo, res):
                self._record(t, r, now)
            self.cycles += 1
            self.last_cycle = now
            if len(self.events) != before:
                self.store.save("monitor_events", list(self.events))

    def _loop(self) -> None:
        while True:
            if self.cfg().get("enabled", True):
                try:
                    self._cycle()
                except Exception:  # one bad cycle must not stop monitoring
                    pass
            self._wake.wait(max(5.0, float(self.cfg().get("interval", 30))))
            self._wake.clear()

    def check_now(self) -> None:
        self._wake.set()

    def clear_events(self) -> None:
        with self.lock:
            self.events.clear()
            self.store.save("monitor_events", [])

    def status(self, detail: str | None = None) -> dict:
        now = time.time()
        with self.lock:
            rows = []
            for t in self.targets.values():
                h = list(t["history"])
                hour = [r for ts, r in h if ts >= now - 3600]
                ok = [r for r in hour if r is not None]
                rows.append({"key": t["key"], "name": t["name"], "ip": t["ip"], "kind": t["kind"], "up": t["up"],
                             "since": t["since"], "last": t["last"], "slow": t["slow"], "lossy": t["lossy"],
                             "avg": round(sum(ok) / len(ok), 1) if ok else None, "max": max(ok) if ok else None,
                             "loss": round(100 * (len(hour) - len(ok)) / len(hour), 1) if hour else None,
                             "uptime": round(100 * sum(r is not None for _, r in h) / len(h), 1) if h else None,
                             "samples": len(h), "spark": [r for _, r in h[-40:]]})
            out = {"targets": rows, "events": list(self.events)[-300:], "cycles": self.cycles, "last_cycle": self.last_cycle,
                   "enabled": self.cfg().get("enabled", True)}
            if detail and detail in self.targets:
                out["detail"] = {"key": detail, "history": list(self.targets[detail]["history"])}
            return out
