"""Start the scanner: `python -m sursum` (add --demo for the simulated environment)."""

from __future__ import annotations

import argparse
import threading
import webbrowser

from . import __version__
from .server import App, serve


def main() -> None:
    ap = argparse.ArgumentParser(prog="sursum", description="Stole Sursum WiFi Scanner")
    ap.add_argument("--demo", action="store_true", help="use the simulated environment instead of the WiFi adapter")
    ap.add_argument("--port", type=int, default=8737)
    ap.add_argument("--no-browser", action="store_true", help="do not open the browser automatically")
    args = ap.parse_args()

    app = App(source="demo" if args.demo else None)
    httpd = serve(app, args.port)
    url = f"http://127.0.0.1:{httpd.server_address[1]}/"
    print(f"Stole Sursum WiFi Scanner {__version__}")
    print(f"Open {url} in your browser. Keep this window open while you use it; close it to quit.")
    if not args.no_browser:
        threading.Timer(0.8, webbrowser.open, args=(url,)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        app.engine.stop()


if __name__ == "__main__":
    main()
