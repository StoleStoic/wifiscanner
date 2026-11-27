"""Device registry: every client device seen by any scan, merged by MAC address and kept on disk.

Sources: the LAN scan (devices on your own network), capture files (which station talks
to which access point), this PC's own connection, and what the user sets by hand.
"""

from __future__ import annotations

import re
import threading
import time
from typing import Any

from . import oui

TYPES = ["Phone / tablet", "Computer", "TV / streaming", "Speaker", "Printer", "Camera", "Smart home",
         "Game console", "Network equipment", "Wearable", "Other", "Unknown"]
PORT_NAMES = {22: "SSH", 80: "Web page", 443: "Secure web page", 445: "Windows file sharing", 515: "Printing (LPD)",
              548: "Apple file sharing", 554: "Camera video (RTSP)", 631: "Printing (IPP)", 1883: "Smart-home messaging (MQTT)",
              3389: "Windows Remote Desktop", 5000: "UPnP / AirPlay", 7000: "AirPlay", 8009: "Chromecast",
              8080: "Web page (alt)", 9100: "Printing (raw)", 62078: "iPhone / iPad sync"}

_HOST = [
    (r"fire ?tv|google ?tv|roku|hopper|joey|chromecast|apple-?tv|firestick|bravia|webos|shield|\btv\b|-tv|tv-|tv$", "TV / streaming"),
    (r"playstation|ps[345]\b|xbox|nintendo|steamdeck", "Game console"),
    (r"iphone|ipad|android|galaxy|pixel|oneplus|redmi|huawei-|-phone|kindle|fold\d|flip\d|-s-[as]\d\d", "Phone / tablet"),
    (r"macbook|imac|mac-?mini|desktop-|laptop|thinkpad|surface|-pc\b|^pc-|win-|workstation|chromeos|chromebook", "Computer"),
    (r"echo|alexa|homepod|sonos|google-?home|nest-?(mini|audio|hub)|bose", "Speaker"),
    (r"printer|officejet|laserjet|deskjet|envy|epson|canon|brother|^hp[0-9a-f]{6}|^npi[0-9a-f]{6}", "Printer"),
    (r"cam\d*\b|_cam|cam[-_]|camera|ring-|doorbell|wyze|arlo|reolink|blink", "Camera"),
    (r"plug|bulb|light|hue|kasa|tasmota|^esp[-_]|shelly|thermostat|ecobee|switch-|smart|tuya|lifx|wemo|roomba|irobot", "Smart home"),
    (r"router|gateway|\bap\b|_ap$|^ap[a-z]|access-?point|extender|orbi|eero|unifi|mesh|zenwifi|bgw\d+", "Network equipment"),
    (r"watch|fitbit|garmin", "Wearable"),
]
_VENDOR = [
    (r"espressif|tuya|shelly|shenzhen .*(smart|iot)|belkin|lifx|signify|philips lighting|ecobee|irobot|xiaomi comm", "Smart home"),
    (r"sonos|bose|harman", "Speaker"),
    (r"roku|vizio|hisense|tcl |lg electronics|skyworth|funai", "TV / streaming"),
    (r"nintendo|sony interactive|valve", "Game console"),
    (r"canon|epson|brother|lexmark|kyocera|xerox|zebra", "Printer"),
    (r"ring |wyze|arlo|hikvision|dahua|axis comm|reolink|amcrest|lorex", "Camera"),
    (r"netgear|ubiquiti|arris|commscope|cisco|aruba|eero|linksys|asustek|mikrotik|zyxel|d-link|ruckus|juniper|sagemcom|technicolor|actiontec", "Network equipment"),
    (r"intel corp|dell|lenovo|micro-star|gigabyte|asrock|framework|microsoft|raspberry", "Computer"),
    (r"garmin|fitbit", "Wearable"),
    (r"samsung|motorola|oneplus|oppo|vivo|huawei|hmd global|google", "Phone / tablet"),
]


def guess_type(d: dict) -> tuple[str, str]:
    """Rule-based type guess. Returns (type, reason)."""
    host = (d.get("hostname") or "").lower()
    vendor = (d.get("vendor") or "").lower()
    ports = set(d.get("ports") or [])
    upnp = (d.get("upnp") or "").lower()
    if ports & {9100, 631, 515}:
        return "Printer", "answers on a printing port"
    if 8009 in ports:
        return "TV / streaming", "answers on the Chromecast port"
    if 62078 in ports:
        return "Phone / tablet", "answers on the iPhone/iPad sync port"
    if 554 in ports:
        return "Camera", "offers a video stream (RTSP)"
    if re.search(r"dish|echostar", vendor):
        return ("Network equipment", "Dish wireless access point") if re.search(r"_ap$|\bap\b", host) else ("TV / streaming", "Dish receiver")
    for pat, typ in _HOST:
        if host and re.search(pat, host):
            return typ, f"name '{d['hostname']}'"
    if upnp:
        for pat, typ in _HOST:
            if re.search(pat, upnp):
                return typ, f"announces itself as '{d['upnp'][:60]}'"
    if 3389 in ports or (445 in ports and "apple" not in vendor):
        return "Computer", "offers Windows sharing or Remote Desktop"
    if "apple" in vendor:
        return ("TV / streaming", "Apple device offering AirPlay") if 7000 in ports else ("Phone / tablet", "Apple device (could also be a Mac)")
    if "amazon" in vendor:
        return "Speaker", "Amazon device (Echo or Fire TV)"
    if "hewlett" in vendor or vendor.startswith("hp "):
        return "Computer", "HP device with no printing port open"
    for pat, typ in _VENDOR:
        if vendor and re.search(pat, vendor):
            return typ, f"made by {d['vendor']}"
    if d.get("random_mac"):
        return "Unknown", "uses a private (randomised) address, as phones, tablets and laptops do by default"
    return "Unknown", "not enough information"


class Registry:
    def __init__(self, store):
        self.store = store
        self.lock = threading.RLock()
        self.devs: dict[str, dict] = store.load("devices", {})
        # carry over devices marked as known in the first version's inventory
        for old in store.settings["inventory"].get("devices", []):
            if old.get("mac"):
                d = self._get(oui.norm(old["mac"]))
                if d["authorized"] is None:
                    d["authorized"] = True
                    d["name"] = d["name"] or old.get("label", "")
        if store.settings["inventory"].get("devices"):
            store.update_settings({"inventory": {"devices": []}})
            self._save()

    def _save(self) -> None:
        self.store.save("devices", self.devs)

    def _get(self, mac: str) -> dict:
        d = self.devs.get(mac)
        if not d:
            now = time.time()
            d = self.devs[mac] = {
                "mac": mac, "name": "", "type": "Unknown", "type_source": "auto", "type_reason": "",
                "authorized": None, "vendor": oui.vendor(mac), "random_mac": oui.is_local(mac),
                "ips": [], "hostname": "", "ports": [], "upnp": "", "ap": None, "ap_source": None,
                "sources": [], "first_seen": now, "last_seen": now, "online": False, "self": False,
                "gateway": False, "notes": "", "model_guess": "", "frames": 0, "rssi": None, "conn": ""}
        return d

    def observe(self, mac: str, source: str, save: bool = True, **facts: Any) -> dict:
        """Merge what one scan learned about a device."""
        mac = oui.norm(mac)
        with self.lock:
            d = self._get(mac)
            d.setdefault("conn", "")
            seen = facts.pop("seen", None) or time.time()
            d["last_seen"] = max(seen, d["last_seen"]) if len(d["sources"]) else seen
            d["first_seen"] = min(d["first_seen"], seen)
            if source not in d["sources"]:
                d["sources"].append(source)
            ip = facts.pop("ip", None)
            if ip:
                d["ips"] = [ip] + [x for x in d["ips"] if x != ip][:3]
            ap = facts.pop("ap", None)
            if ap and d["ap_source"] != "manual":
                d["ap"], d["ap_source"] = oui.norm(ap), facts.pop("ap_source", source)
            facts.pop("ap_source", None)
            for k in ("hostname", "upnp", "conn"):
                if facts.get(k):
                    d[k] = facts[k]
            if facts.get("ports"):
                d["ports"] = sorted(set(facts["ports"]))
            if "this_pc" in facts:
                d["self"] = bool(facts.pop("this_pc"))
            for k in ("online", "gateway", "rssi", "frames"):
                if k in facts and facts[k] is not None:
                    d[k] = facts[k]
            if d["self"] and d["authorized"] is None:
                d["authorized"], d["name"] = True, d["name"] or "This PC"
            if d["gateway"] and d["authorized"] is None:  # the router you are connected through
                d["authorized"], d["name"] = True, d["name"] or "Router"
            if d["type_source"] == "auto":
                d["type"], d["type_reason"] = ("Network equipment", "it is your router") if d["gateway"] else \
                    ("Computer", "this PC") if d["self"] else guess_type(d)
            if save:
                self._save()
            return d

    def mark_offline(self, source: str, keep: set[str]) -> None:
        with self.lock:
            for d in self.devs.values():
                if source in d["sources"] and d["mac"] not in keep:
                    d["online"] = False

    def update(self, macs: list[str], patch: dict) -> None:
        with self.lock:
            for mac in macs:
                d = self.devs.get(oui.norm(mac))
                if not d:
                    continue
                if "authorized" in patch:
                    d["authorized"] = patch["authorized"] if patch["authorized"] in (True, False) else None
                if "name" in patch:
                    d["name"] = str(patch["name"])[:80]
                if "notes" in patch:
                    d["notes"] = str(patch["notes"])[:500]
                if patch.get("type") in TYPES:
                    d["type"], d["type_source"], d["type_reason"] = patch["type"], "user", "set by you"
                if patch.get("type") == "auto":
                    d["type_source"] = "auto"
                    d["type"], d["type_reason"] = guess_type(d)
                if "ap" in patch:
                    d["ap"] = oui.norm(patch["ap"]) if patch["ap"] else None
                    d["ap_source"] = "manual" if patch["ap"] else None
            self._save()

    def apply_ai(self, results: list[dict]) -> int:
        n = 0
        with self.lock:
            for r in results:
                d = self.devs.get(oui.norm(r.get("mac", "")))
                if not d or d["type_source"] == "user" or r.get("type") not in TYPES:
                    continue
                d["type"], d["type_source"] = r["type"], "claude"
                d["type_reason"] = f"Claude ({r.get('confidence', 'low')} confidence): {r.get('reason', '')}"
                d["model_guess"] = r.get("likely_model", "")
                n += 1
            self._save()
        return n

    def forget(self, macs: list[str]) -> None:
        with self.lock:
            for mac in macs:
                self.devs.pop(oui.norm(mac), None)
            self._save()

    def save(self) -> None:
        with self.lock:
            self._save()

    def list(self) -> list[dict]:
        with self.lock:
            return [dict(d) for d in self.devs.values()]

    def lan(self) -> list[dict]:
        """Devices on the user's own network, in the shape the threat engine expects."""
        return [dict(d, ip=(d["ips"] or [""])[0], known=d["authorized"] is True)
                for d in self.list() if ("lan" in d["sources"] or "router" in d["sources"]) and d["online"]]
