"""Desktop application entry point: the scanner in its own window, no console, no browser tab.

Used by the installed Windows program. `python -m sursum` remains the console/developer route.
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
import time
import traceback
import urllib.request
import webbrowser

from . import __version__
from .store import data_dir

TITLE = "Stole Sursum WiFi Scanner"
PORT = 8737
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # never route localhost via a proxy


def _log(msg: str) -> None:
    try:
        with open(data_dir() / "app.log", "a", encoding="utf-8") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}\n")
    except OSError:
        pass


def _already_running(port: int) -> bool:
    """True when another copy of the scanner is answering on the port."""
    try:
        with _OPENER.open(f"http://127.0.0.1:{port}/api/state", timeout=1.5) as r:
            return "networks" in json.load(r)
    except (OSError, ValueError):
        return False


def _window(url: str) -> None:
    """Show the UI in a native window (Edge WebView2, part of Windows 11). Blocks until it is closed."""
    import webview

    webview.settings["ALLOW_DOWNLOADS"] = True  # CSV / session exports
    webview.create_window(TITLE, url, width=1500, height=950, min_size=(1000, 650))
    _log("window: native")
    webview.start()


def _fallback(url: str, reason: str) -> None:
    """No WebView available: use the default browser and a small control window to quit from."""
    _log(f"window: browser fallback ({reason})")
    webbrowser.open(url)
    try:
        import tkinter as tk

        root = tk.Tk()
        root.title(TITLE)
        root.geometry("420x150")
        tk.Label(root, text="The scanner is running in your web browser.\nClose this window to stop it.",
                 pady=16).pack()
        tk.Button(root, text="Open scanner", width=18, command=lambda: webbrowser.open(url)).pack()
        tk.Button(root, text="Quit", width=18, command=root.destroy).pack(pady=6)
        root.mainloop()
    except Exception:
        _log("no control window available; running until the process is ended")
        threading.Event().wait()


def main() -> None:
    ap = argparse.ArgumentParser(prog="SursumWiFiScanner", description=TITLE)
    ap.add_argument("--demo", action="store_true", help="simulated environment instead of the WiFi adapter")
    ap.add_argument("--browser", action="store_true", help="use the default web browser instead of an app window")
    ap.add_argument("--port", type=int, default=PORT)
    args = ap.parse_args()
    if sys.stdout is None:  # windowed programs have no console to print to
        sys.stdout = sys.stderr = open(data_dir() / "app.log", "a", encoding="utf-8")  # noqa: SIM115
    _log(f"start {__version__} args={sys.argv[1:]}")
    httpd = app = None
    try:
        if _already_running(args.port):
            url = f"http://127.0.0.1:{args.port}/"  # second launch: just show the running scanner
            _log("joining the copy that is already running")
        else:
            from .server import App, serve

            app = App(source="demo" if args.demo else None)
            httpd = serve(app, args.port)
            threading.Thread(target=httpd.serve_forever, daemon=True, name="http").start()
            url = f"http://127.0.0.1:{httpd.server_address[1]}/"
        if args.browser:
            _fallback(url, "requested")
        else:
            try:
                _window(url)
            except Exception as e:
                _log(traceback.format_exc())
                _fallback(url, f"{type(e).__name__}: {e}")
    except Exception:
        _log(traceback.format_exc())
        raise
    finally:
        if app:
            app.engine.stop()
        if httpd:
            httpd.shutdown()
        _log("exit")


if __name__ == "__main__":
    main()
