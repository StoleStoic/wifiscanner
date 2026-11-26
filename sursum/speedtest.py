"""Internet speed test (latency, download, upload) with auto-run on roaming."""

from __future__ import annotations

import http.client
import json
import threading
import time
import urllib.parse
import urllib.request
from typing import Any, Callable

UA = {"User-Agent": "sursum-wifi-scanner"}
CLOUDFLARE = {"id": "cloudflare", "name": "Cloudflare (nearest location, automatic)",
              "dl": "https://speed.cloudflare.com/__down?bytes=25000000",
              "ul": "https://speed.cloudflare.com/__up",
              "ping": "https://speed.cloudflare.com/__down?bytes=0"}
LIBRESPEED_LIST = "https://librespeed.org/backend-servers/servers.php"


def _join(base: str, path: str) -> str:
    return base.rstrip("/") + "/" + path.lstrip("/")


def fetch_servers() -> list[dict]:
    """Public LibreSpeed servers (many cities worldwide)."""
    req = urllib.request.Request(LIBRESPEED_LIST, headers=UA)
    with urllib.request.urlopen(req, timeout=10) as r:
        raw = json.loads(r.read().decode("utf-8", "replace"))
    out = []
    for s in raw:
        base = s.get("server", "")
        if base.startswith("//"):
            base = "https:" + base
        if not base.startswith("https://"):
            continue
        out.append({"id": f"ls-{s.get('id')}", "name": s.get("name", base),
                    "dl": _join(base, s.get("dlURL", "garbage.php")) + "?ckSize=100",
                    "ul": _join(base, s.get("ulURL", "empty.php")),
                    "ping": _join(base, s.get("pingURL", "empty.php"))})
    return sorted(out, key=lambda x: x["name"])


def custom_server(url: str) -> dict:
    """A self-hosted LibreSpeed backend, e.g. one on your own LAN to test WiFi speed only."""
    return {"id": "custom", "name": f"Custom: {url}", "dl": _join(url, "garbage.php") + "?ckSize=100",
            "ul": _join(url, "empty.php"), "ping": _join(url, "empty.php")}


def _latency(url: str, n: int = 8) -> tuple[float | None, float | None]:
    samples = []
    u = urllib.parse.urlsplit(url)
    if not urllib.request.getproxies():
        # One kept-alive connection, so each sample is a single request round trip.
        cls = http.client.HTTPSConnection if u.scheme == "https" else http.client.HTTPConnection
        try:
            c = cls(u.netloc, timeout=5)
            for _ in range(n + 1):
                t = time.perf_counter()
                c.request("GET", u.path + ("?" + u.query if u.query else ""), headers=UA)
                c.getresponse().read()
                samples.append((time.perf_counter() - t) * 1000)
            c.close()
        except (OSError, http.client.HTTPException):
            pass
    else:
        for _ in range(n):
            t = time.perf_counter()
            try:
                with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=5) as r:
                    r.read(1)
                samples.append((time.perf_counter() - t) * 1000)
            except OSError:
                pass
    if not samples:
        return None, None
    samples = samples[1:] or samples  # first one includes the TLS handshake
    jitter = sum(abs(a - b) for a, b in zip(samples, samples[1:])) / max(1, len(samples) - 1)
    return round(min(samples), 1), round(jitter, 1)


def _throughput(worker: Callable[[threading.Event, list], None], seconds: float, threads: int,
                progress: Callable[[float], None] | None) -> float:
    stop = threading.Event()
    counter = [0]
    ts = [threading.Thread(target=worker, args=(stop, counter), daemon=True) for _ in range(threads)]
    start = time.perf_counter()
    for t in ts:
        t.start()
    warm_bytes, warm_t = 0, start
    while time.perf_counter() - start < seconds:
        time.sleep(0.25)
        el = time.perf_counter() - start
        if el < 1.0:  # ignore the TCP ramp-up second
            warm_bytes, warm_t = counter[0], time.perf_counter()
        elif progress:
            progress((counter[0] - warm_bytes) * 8 / 1e6 / max(0.001, time.perf_counter() - warm_t))
    total, end = counter[0], time.perf_counter()
    stop.set()
    return round((total - warm_bytes) * 8 / 1e6 / max(0.001, end - warm_t), 2)


def run_test(server: dict, seconds: float = 7.0, threads: int = 4,
             progress: Callable[[str, float], None] | None = None) -> dict[str, Any]:
    res: dict[str, Any] = {"t": time.time(), "server": server["name"], "server_id": server["id"]}
    res["ping"], res["jitter"] = _latency(server["ping"])
    if res["ping"] is None:
        res["error"] = "Could not reach the speed test server."
        return res

    def down(stop: threading.Event, counter: list) -> None:
        while not stop.is_set():
            try:
                with urllib.request.urlopen(urllib.request.Request(server["dl"], headers=UA), timeout=10) as r:
                    while not stop.is_set():
                        chunk = r.read(65536)
                        if not chunk:
                            break
                        counter[0] += len(chunk)
            except Exception:
                time.sleep(0.2)

    blob = bytes(1024 * 1024)

    class Body:
        """Endless upload body that counts bytes as the socket takes them."""

        def __init__(self, stop: threading.Event, counter: list):
            self.stop, self.counter, self.sent = stop, counter, 0

        def read(self, n: int = 65536) -> bytes:
            if self.stop.is_set() or self.sent >= 25 * 1024 * 1024:
                return b""
            self.sent += n
            self.counter[0] += n
            return blob[:n]

    def up(stop: threading.Event, counter: list) -> None:
        while not stop.is_set():
            try:
                req = urllib.request.Request(server["ul"], data=Body(stop, counter), method="POST",
                                             headers={**UA, "Content-Type": "application/octet-stream",
                                                      "Content-Length": str(25 * 1024 * 1024)})
                urllib.request.urlopen(req, timeout=10).read()
            except Exception:
                time.sleep(0.2)

    res["download"] = _throughput(down, seconds, threads, (lambda v: progress("download", v)) if progress else None)
    res["upload"] = _throughput(up, seconds, threads, (lambda v: progress("upload", v)) if progress else None)
    if not res["download"] and not res["upload"]:
        res["error"] = "The speed test server did not transfer any data. Try another server."
    return res


class SpeedTester:
    """Runs tests on demand, continuously, or after a roam; keeps history on disk."""

    def __init__(self, store, get_connection: Callable[[], dict | None], demo: Callable[[], bool]):
        self.store = store
        self.get_connection = get_connection
        self.demo = demo
        self.history: list[dict] = store.load("speedtests", [])
        self.running = False
        self.phase = ""
        self.live = 0.0
        self.servers: list[dict] = [CLOUDFLARE]
        self.next_run = 0.0
        self._lock = threading.Lock()
        threading.Thread(target=self._loop, daemon=True, name="speedtest-timer").start()

    def server_list(self, refresh: bool = False) -> list[dict]:
        if refresh or len(self.servers) == 1:
            try:
                self.servers = [CLOUDFLARE] + fetch_servers()
            except (OSError, ValueError):
                pass
        return [{"id": s["id"], "name": s["name"]} for s in self.servers]

    def _server(self) -> dict:
        cfg = self.store.settings["speedtest"]
        if cfg["server"] == "custom" and cfg.get("custom_url", "").startswith("http"):
            return custom_server(cfg["custom_url"])
        return next((s for s in self.servers if s["id"] == cfg["server"]), CLOUDFLARE)

    def start(self, trigger: str = "manual", extra: dict | None = None) -> bool:
        with self._lock:
            if self.running:
                return False
            self.running = True
        threading.Thread(target=self._run, args=(trigger, extra or {}), daemon=True, name="speedtest").start()
        return True

    def _progress(self, phase: str, v: float) -> None:
        self.phase, self.live = phase, round(v, 1)

    def _run(self, trigger: str, extra: dict) -> None:
        try:
            self.phase, self.live = "latency", 0.0
            if self.demo():
                res = self._demo_result()
            else:
                res = run_test(self._server(), progress=self._progress)
            conn = self.get_connection() or {}
            res.update(trigger=trigger, room=self.store.settings["speedtest"].get("room", ""),
                       ssid=conn.get("ssid"), bssid=conn.get("bssid"), rssi=conn.get("rssi"),
                       channel=conn.get("channel"), band=conn.get("band"), **extra)
            self.history.append(res)
            self.history = self.history[-500:]
            self.store.save("speedtests", self.history)
        finally:
            self.phase = ""
            self.running = False

    def _demo_result(self) -> dict:
        import random
        conn = self.get_connection() or {}
        q = max(0.15, min(1.0, ((conn.get("rssi") or -60) + 90) / 40))
        for phase, top in (("download", 480 * q), ("upload", 38 * q)):
            for i in range(8):
                self._progress(phase, top * min(1, (i + 2) / 6) * random.uniform(0.9, 1.05))
                time.sleep(0.3)
        return {"t": time.time(), "server": "Demo server (simulated)", "server_id": "demo",
                "ping": round(random.uniform(9, 16), 1), "jitter": round(random.uniform(0.5, 3), 1),
                "download": round(480 * q * random.uniform(0.9, 1.05), 1),
                "upload": round(38 * q * random.uniform(0.9, 1.05), 1)}

    def on_roam(self, ev: dict, _conn: dict | None) -> None:
        cfg = self.store.settings["speedtest"]
        if not cfg.get("auto_roam"):
            return
        wait = max(0.0, float(cfg.get("roam_wait", 5)))
        threading.Timer(wait, lambda: self.start("roam", {"roam_from": ev.get("from_bssid")})).start()

    def _loop(self) -> None:
        while True:
            time.sleep(1)
            cfg = self.store.settings["speedtest"]
            if not cfg.get("continuous"):
                self.next_run = 0.0
                continue
            now = time.time()
            if not self.next_run:
                self.next_run = now + 1
            if now >= self.next_run and not self.running:
                self.next_run = now + max(15.0, float(cfg.get("interval", 300)))
                self.start("continuous")

    def status(self) -> dict:
        return {"running": self.running, "phase": self.phase, "live": self.live,
                "next_run": self.next_run, "history": self.history[-200:]}

    def clear(self) -> None:
        self.history = []
        self.store.save("speedtests", [])
