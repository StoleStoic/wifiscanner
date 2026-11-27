"""Local web server: JSON API plus the browser UI. Listens on 127.0.0.1 only."""

from __future__ import annotations

import json
import mimetypes
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from . import __version__, ai, analysis, routerlist
from .engine import Engine, interference
from .devices import TYPES, Registry
from .ipscan import IPScanner
from .scanners import ScanError, pcap
from .speedtest import SpeedTester
from .store import Store

WEB = Path(__file__).parent / "web"
MAX_BODY = 96 * 1024 * 1024


class App:
    def __init__(self, store: Store | None = None, source: str | None = None):
        self.store = store or Store()
        self.speed = SpeedTester(self.store, lambda: self.engine.connection, lambda: self.engine.source == "demo")
        self.engine = Engine(self.store, on_roam=self.speed.on_roam)
        self.registry = Registry(self.store)
        self.ipscan = IPScanner(self.store, lambda: self.engine.source == "demo", self.registry)
        self.identify: dict = {}
        self.identify_running = False
        self.ai_result: dict = {}
        self.ai_running = False
        self.engine.start(source)

    # ---- API handlers: return a JSON-serialisable object
    def get(self, path: str, q: dict) -> object:
        e = self.engine
        if path == "/api/state":
            return {"status": e.status(), "networks": e.snapshot(), "connection": e.connection,
                    "roams": list(e.roams), "version": __version__, "now": time.time()}
        if path == "/api/history":
            return {"history": e.history_dump(), "connection": list(e.conn_history)}
        if path == "/api/network":
            return e.get(q.get("bssid", [""])[0]) or {}
        if path == "/api/settings":
            return self.store.public_settings()
        if path == "/api/sessions":
            return self.store.list_sessions()
        if path == "/api/session":
            return self.store.get_session(q.get("id", [""])[0]) or {}
        if path == "/api/speedtest":
            return self.speed.status()
        if path == "/api/speedtest/servers":
            return self.speed.server_list(refresh=bool(q.get("refresh")))
        if path in ("/api/ipscan", "/api/devices"):
            return self.devices()
        if path == "/api/analysis":
            return self.analysis()
        if path == "/api/surveys":
            return self.store.load("surveys", {"surveys": []})
        raise KeyError(path)

    def analysis(self, nets: list[dict] | None = None) -> dict:
        nets = self.engine.snapshot() if nets is None else nets
        s, conn, lan = self.store.settings, self.engine.connection, self.registry.lan()
        return {"threats": analysis.classify(nets, conn, s, lan), "notes": analysis.notes(nets, conn, s, lan),
                "ai": self.ai_result, "ai_running": self.ai_running}

    def devices(self) -> dict:
        """Registry plus live facts: this PC's own link and the name of each device's access point."""
        conn, reg = self.engine.connection, self.registry
        mine = next((d for d in reg.list() if d["self"]), None)
        if mine and conn and conn.get("bssid") and (mine["ap"], mine["ap_source"]) != (conn["bssid"], "this PC"):
            reg.observe(mine["mac"], "lan", ap=conn["bssid"], ap_source="this PC", online=True)
        names = {n["bssid"]: n for n in self.engine.snapshot()}
        out = []
        for d in reg.list():
            ap = names.get(d["ap"] or "")
            d["ap_name"] = (ap["ssid"] or "(hidden)") if ap else None
            d["ap_band"] = f"{ap['band']} GHz ch {ap['channel']}" if ap else None
            out.append(d)
        return dict(self.ipscan.status(), devices=out, types=TYPES, identify=self.identify,
                    identify_running=self.identify_running)

    def _import(self, text: str) -> dict:
        """Merge a router's device list into the registry."""
        devs = routerlist.parse(text)
        if not devs:
            return dict(self.devices(), imported={"error": "No devices were recognised in that text. Copy the whole "
                                                           "Device List page of the AT&T gateway and paste it here."})
        nets = self.engine.snapshot()
        home = {d["ssid"] for d in devs if d["net_type"].lower() == "home" and d["ssid"]}
        linked = 0
        for d in devs:
            ap = routerlist.resolve_ap(d, nets, home)
            linked += bool(ap)
            self.registry.observe(d["mac"], "router", save=False, ip=d["ip"] or None, hostname=d["name"], online=d["online"],
                                  seen=d["seen"], conn=routerlist.describe(d), ap=ap, ap_source="router list")
        self.registry.mark_offline("router", {d["mac"] for d in devs})
        self.registry.save()
        return dict(self.devices(), imported={"count": len(devs), "online": sum(d["online"] for d in devs),
                                              "wifi": sum(d["link"] == "wifi" for d in devs), "linked": linked})

    def _identify(self, macs: list[str]) -> None:
        try:
            s = self.store.settings
            devs = [d for d in self.devices()["devices"] if d["mac"] in macs]
            res = ai.identify_devices(devs, s["ai"].get("api_key", ""), s["ai"].get("model") or "claude-opus-5-5")
            if "devices" in res:
                res = {"updated": self.registry.apply_ai(res["devices"]), "asked": len(devs)}
            self.identify = dict(res, t=time.time())
        except Exception as ex:
            self.identify = {"error": f"Identification failed: {ex}", "t": time.time()}
        finally:
            self.identify_running = False

    def _ai(self) -> None:
        try:
            nets = self.engine.snapshot()
            s, conn, lan = self.store.settings, self.engine.connection, self.registry.lan()
            snap = ai.build_snapshot(nets, conn, analysis.classify(nets, conn, s, lan),
                                     analysis.notes(nets, conn, s, lan), lan)
            self.ai_result = dict(ai.analyze(snap, s["ai"].get("api_key", ""), s["ai"].get("model") or "claude-opus-5-5"),
                                  t=time.time())
        except Exception as ex:  # never leave the UI spinning
            self.ai_result = {"error": f"Analysis failed: {ex}", "t": time.time()}
        finally:
            self.ai_running = False

    def post(self, path: str, body: bytes, q: dict) -> object:
        e = self.engine
        if path == "/api/pcap":
            try:
                nets, stats = pcap.read(body)
            except ScanError as ex:
                return {"error": str(ex)}
            interference(nets)
            for st in stats["stations"]:  # remember which device talked to which access point
                self.registry.observe(st["mac"], "capture", save=False, ap=st["bssid"], ap_source="capture",
                                      rssi=st["rssi"], frames=st["frames"], seen=st["seen"] or None)
            self.registry.save()
            return {"networks": nets, "stats": stats}
        data = json.loads(body or b"{}")
        if path == "/api/scan":
            act = data.get("action")
            if act == "pause":
                e.paused = True
            elif act == "resume":
                e.paused = False
                e.rescan()
            elif act == "clear":
                e.clear()
            elif act == "rescan":
                e.rescan()
            elif act == "source":
                self.store.update_settings({"scan": {"source": data["source"]}})
                e.set_source(data["source"])
            return e.status()
        if path == "/api/settings":
            if "ai" in data and not data["ai"].get("api_key"):
                data["ai"].pop("api_key", None)  # blank means "keep the stored key"
            if data.get("ai", {}).get("clear_key"):
                data["ai"]["api_key"] = ""
            data.get("ai", {}).pop("clear_key", None)
            data.get("ai", {}).pop("has_key", None)
            self.store.update_settings(data)
            return self.store.public_settings()
        if path == "/api/sessions":
            payload = {"source": e.source_label, "networks": e.snapshot(with_ies=True), "connection": e.connection,
                       "history": e.history_dump(), "notes": data.get("notes", "")}
            return {"id": self.store.save_session(data.get("name") or "Scan", payload)}
        if path == "/api/sessions/import":
            if not isinstance(data.get("networks"), list):
                return {"error": "That file is not a saved scan session."}
            return {"id": self.store.save_session(data.get("name") or "Imported", data)}
        if path == "/api/session/delete":
            self.store.delete_session(data.get("id", ""))
            return {"ok": True}
        if path == "/api/speedtest":
            if data.get("action") == "clear":
                self.speed.clear()
            else:
                self.speed.start(data.get("trigger", "manual"), data.get("extra"))
            return self.speed.status()
        if path == "/api/ipscan":
            self.ipscan.start()
            return self.ipscan.status()
        if path == "/api/devices":
            act, macs = data.get("action"), list(data.get("macs") or [])
            if act == "update":
                self.registry.update(macs, data.get("patch") or {})
            elif act == "forget":
                self.registry.forget(macs)
            elif act in ("import", "fetch"):
                try:
                    text = routerlist.fetch(data.get("host") or "192.168.1.254") if act == "fetch" else str(data.get("text") or "")
                except (OSError, ValueError) as ex:
                    return dict(self.devices(), imported={"error": "Could not read the device list from the gateway at that "
                                                                   f"address ({getattr(ex, 'reason', ex)}). Use option 2: copy the page and paste it."})
                return self._import(text)
            elif act == "identify" and not self.identify_running:
                self.identify_running = True
                threading.Thread(target=self._identify, args=(macs,), daemon=True, name="identify").start()
            return self.devices()
        if path == "/api/analysis/ai":
            if not self.ai_running:
                self.ai_running = True
                threading.Thread(target=self._ai, daemon=True, name="ai").start()
            return {"ai_running": True}
        if path == "/api/analysis":  # analyse a loaded session / capture instead of the live scan
            return self.analysis(data.get("networks") or [])
        if path == "/api/surveys":
            self.store.save("surveys", data)
            return {"ok": True}
        raise KeyError(path)


def make_handler(app: App, port: int):
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args) -> None:
            pass

        def _send(self, code: int, body: bytes, ctype: str = "application/json") -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, obj: object, code: int = 200) -> None:
            self._send(code, json.dumps(obj, default=str).encode())

        def _guard(self) -> bool:
            # Refuse requests that reach us under another host name (DNS rebinding).
            if self.headers.get("Host") not in allowed_hosts:
                self._json({"error": "forbidden"}, 403)
                return False
            return True

        def do_GET(self) -> None:  # noqa: N802
            if not self._guard():
                return
            u = urlparse(self.path)
            if u.path.startswith("/api/"):
                try:
                    self._json(app.get(u.path, parse_qs(u.query)))
                except KeyError:
                    self._json({"error": "not found"}, 404)
                except Exception as ex:
                    self._json({"error": str(ex)}, 500)
                return
            rel = "index.html" if u.path == "/" else u.path.lstrip("/")
            f = (WEB / rel).resolve()
            if WEB.resolve() not in f.parents or not f.is_file():
                self._send(404, b"not found", "text/plain")
                return
            # Fixed table first: Windows takes MIME types from the registry, which is often wrong.
            ctype = {".js": "text/javascript", ".css": "text/css", ".html": "text/html"}.get(
                f.suffix) or mimetypes.guess_type(f.name)[0] or "application/octet-stream"
            self._send(200, f.read_bytes(), ctype + ("; charset=utf-8" if ctype.startswith("text/") else ""))

        def do_POST(self) -> None:  # noqa: N802
            if not self._guard():
                return
            # A custom header cannot be sent cross-site without CORS, which we never grant.
            if self.headers.get("X-Sursum") != "1":
                self._json({"error": "forbidden"}, 403)
                return
            n = int(self.headers.get("Content-Length") or 0)
            if n > MAX_BODY:
                self._json({"error": "File is too large."}, 413)
                return
            body = self.rfile.read(n)
            u = urlparse(self.path)
            try:
                self._json(app.post(u.path, body, parse_qs(u.query)))
            except KeyError:
                self._json({"error": "not found"}, 404)
            except Exception as ex:
                self._json({"error": str(ex)}, 500)

    return Handler


def serve(app: App, port: int = 8737) -> ThreadingHTTPServer:
    last: OSError | None = None
    for p in range(port, port + 20):
        try:
            httpd = ThreadingHTTPServer(("127.0.0.1", p), make_handler(app, p))
            httpd.daemon_threads = True
            return httpd
        except OSError as ex:
            last = ex
    raise last  # type: ignore[misc]
