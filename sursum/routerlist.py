"""Import the device list of an AT&T gateway (BGW210 / BGW320 "Device List" page).

The gateway knows every device it has handed an address to, including ones that are
switched off, sit behind another router's access point, or live on a different subnet
from this PC - none of which a scan from the PC can see. The list can be pasted as text
or fetched from the gateway's own web page.
"""

from __future__ import annotations

import html
import re
import time
import urllib.request

from . import oui

KEYS = ["MAC Address", "IPv4 Address / Name", "Name", "Last Activity", "Status", "Allocation",
        "Connection Type", "Connection Speed", "Mesh Client", "IPv6 Address", "Type", "Valid Lifetime",
        "Preferred Lifetime"]
_KEY = re.compile(r"^(%s)(?:\s+(.*))?$" % "|".join(re.escape(k) for k in sorted(KEYS, key=len, reverse=True)))
_MAC = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$", re.I)
_PLACEHOLDER = re.compile(r"^(unknown[0-9a-f]{12}|android device|linux|localhost|amazon|apple, inc\.)$", re.I)


def html_to_text(page: str) -> str:
    """Flatten the gateway's HTML table into the same 'Key<tab>Value' lines a copy-paste gives."""
    page = re.sub(r"(?is)<(script|style).*?</\1>", "", page)
    page = re.sub(r"(?i)</t[hd]>\s*<t[hd][^>]*>", "\t", page)
    page = re.sub(r"(?i)<br\s*/?>|</tr>|</p>|</div>", "\n", page)
    return html.unescape(re.sub(r"<[^>]+>", "", page))


def parse(text: str) -> list[dict]:
    devices: list[dict] = []
    cur: dict | None = None
    last_key = ""
    for raw in text.replace("\r", "").split("\n"):
        line = raw.strip()
        if not line:
            continue
        m = _KEY.match(line)
        if m and m.group(1) == "MAC Address" and _MAC.match((m.group(2) or "").strip()):
            cur = {"mac": oui.norm(m.group(2).strip()), "name": "", "ip": "", "online": False, "seen": None,
                   "link": "", "port": "", "band": "", "ssid": "", "net_type": "", "speed": "", "extra": []}
            devices.append(cur)
            last_key = "MAC Address"
            continue
        if cur is None:
            continue
        if not m:  # continuation lines under "Connection Type" for WiFi clients
            if last_key == "Connection Type":
                if re.match(r"^(2\.4|5|6) GHz", line):
                    cur["band"] = line.split()[0]
                    cur["extra"].append(line)
                elif line.startswith("Type:"):
                    cur["net_type"] = line.split(":", 1)[1].strip()
                elif line.startswith("Name:"):
                    cur["ssid"] = line.split(":", 1)[1].strip()
            continue
        key, val = m.group(1), (m.group(2) or "").strip()
        last_key = key
        if key == "IPv4 Address / Name":
            ip, _, name = val.partition("/")
            cur["ip"], cur["name"] = ip.strip(), name.strip()
        elif key == "Name" and not cur["name"]:
            cur["name"] = val
        elif key == "Status":
            cur["online"] = val.lower() == "on"
        elif key == "Last Activity":
            try:
                cur["seen"] = time.mktime(time.strptime(re.sub(r"\s+", " ", val), "%a %b %d %H:%M:%S %Y"))
            except ValueError:
                pass
        elif key == "Connection Type":
            if val.lower().startswith("wi-fi"):
                cur["link"] = "wifi"
            elif val.lower().startswith("ethernet"):
                cur["link"], cur["port"] = "ethernet", val.split()[-1]
        elif key == "Connection Speed":
            cur["speed"] = val
    for d in devices:
        if _PLACEHOLDER.match(d["name"]):
            d["generic_name"], d["name"] = d["name"], ""
        del d["extra"]
    return devices


def fetch(host: str = "192.168.1.254") -> str:
    """Read the Device List page straight from the gateway (no login is needed for this page)."""
    if not re.match(r"^[A-Za-z0-9.-]+$", host):
        raise ValueError("That is not a valid gateway address.")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(f"http://{host}/cgi-bin/devices.ha", timeout=8) as r:
        return html_to_text(r.read(4_000_000).decode("utf-8", "replace"))


def describe(d: dict) -> str:
    """Plain wording of how the gateway reaches the device."""
    if d["link"] == "wifi":
        return f"WiFi of the AT&T gateway: {d['ssid'] or 'network unknown'}" + (f", {d['band']} GHz" if d["band"] else "")
    if d["link"] == "ethernet":
        return f"AT&T gateway port {d['port']} (wired, or through an access point or router on that port)"
    return ""


def resolve_ap(d: dict, nets: list[dict], home_ssids: set[str]) -> str | None:
    """BSSID of the gateway radio a WiFi client uses, when the scan leaves exactly one candidate."""
    if d["link"] != "wifi" or not d["ssid"] or not d["band"]:
        return None
    gw = [n["bssid"] for n in nets if n["ssid"] in home_ssids]  # only the gateway broadcasts its Home name
    cand = [n["bssid"] for n in nets if n["ssid"] == d["ssid"] and n["band"] == d["band"]
            and (n["bssid"] in gw or any(oui.same_unit(n["bssid"], g) for g in gw))]
    return cand[0] if len(cand) == 1 else None
