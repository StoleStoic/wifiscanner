"""Simulated RF environment (demo mode).

Generates real information-element bytes for a believable neighbourhood so the
whole pipeline - parser, graphs, analysis, threat detection - can be exercised
without a WiFi adapter. Run with `--demo`, or pick "Demo" as the scan source.
"""

from __future__ import annotations

import math
import random
import struct
import time

from .. import channels, model

AKM_ID = {"PSK": 2, "SAE": 8, "802.1X": 1, "OWE": 18, "FT-PSK": 4, "802.1X-SHA256": 5}


def tlv(eid: int, body: bytes) -> bytes:
    return bytes([eid, len(body)]) + body


def ext(eid: int, body: bytes) -> bytes:
    return tlv(255, bytes([eid]) + body)


def rsn(akms: list[str], cipher: int = 4, pmf: str = "no") -> bytes:
    s = b"\x00\x0f\xac"
    caps = {"no": 0, "capable": 0x80, "required": 0xC0}[pmf]
    body = struct.pack("<H", 1) + s + bytes([cipher]) + struct.pack("<H", 1) + s + bytes([cipher])
    body += struct.pack("<H", len(akms)) + b"".join(s + bytes([AKM_ID[a]]) for a in akms)
    return tlv(48, body + struct.pack("<H", caps))


def wpa1() -> bytes:
    s = b"\x00\x50\xf2"
    return tlv(221, s + b"\x01" + struct.pack("<H", 1) + s + b"\x02" + struct.pack("<H", 1) + s + b"\x02"
               + struct.pack("<H", 1) + s + b"\x02")


def wps(name: str, maker: str, model_name: str, locked: bool = False) -> bytes:
    def a(t: int, v: bytes) -> bytes:
        return struct.pack(">HH", t, len(v)) + v
    body = a(0x104A, b"\x10") + a(0x1044, b"\x02") + a(0x1057, bytes([locked]))
    body += a(0x1021, maker.encode()) + a(0x1023, model_name.encode()) + a(0x1011, name.encode())
    return tlv(221, b"\x00\x50\xf2\x04" + body)


def build_ies(n: dict) -> bytes:  # noqa: C901
    band, ch, width, std = n["band"], n["channel"], n.get("width", 20), n["std"]
    streams = n.get("streams", 2)
    freq = channels.channel_to_freq(ch, band)
    out = tlv(0, b"" if n.get("hidden") else n["ssid"].encode())
    if band == "2.4":
        rates = [0x82, 0x84, 0x8B, 0x96] + ([0x0C, 0x12, 0x18, 0x24] if std != "b" else [])
        out += tlv(1, bytes(rates)) + tlv(3, bytes([ch]))
    else:
        out += tlv(1, bytes([0x8C, 0x12, 0x98, 0x24, 0xB0, 0x48, 0x60, 0x6C]))
    out += tlv(5, bytes([0, n.get("dtim", 2), 0, 0]))
    out += tlv(7, b"US " + (bytes([1, 11, 30]) if band == "2.4" else bytes([36, 4, 23, 149, 5, 30])))
    if n.get("stations") is not None:
        out += tlv(11, struct.pack("<HBH", n["stations"], int(n.get("util", 20) * 255 / 100), 0))
    if band == "2.4" and std != "b":
        out += tlv(42, bytes([0x02 if n.get("protection") else 0]))
        out += tlv(50, bytes([0x30, 0x48, 0x60, 0x6C]))
    sec = n.get("sec", "wpa2")
    if sec == "wpa2":
        out += rsn(["PSK"], pmf=n.get("pmf", "no"))
    elif sec == "wpa3":
        out += rsn(["SAE"], pmf="required")
    elif sec == "wpa23":
        out += rsn(["PSK", "SAE"], pmf="capable")
    elif sec == "ent":
        out += rsn(["802.1X"], pmf="capable")
    elif sec == "owe":
        out += rsn(["OWE"], pmf="required")
    elif sec == "wpa":
        out += wpa1()
    elif sec == "wpa-tkip2":
        out += rsn(["PSK"], cipher=2) + wpa1()
    if n.get("k"):
        out += tlv(70, bytes([0x73, 0, 0, 0, 0]))
    if n.get("r"):
        out += tlv(54, b"\x12\x34\x01")
    ht = std in ("n", "ac", "ax", "be")
    if ht and band != "6":
        cap = 0x01AD | (0x0042 if width >= 40 else 0)
        mcs = bytes([0xFF] * streams + [0] * (16 - streams))
        out += tlv(45, struct.pack("<HB", cap, 0x17) + mcs + bytes(7))
        sec_off = 0
        if width >= 40:
            center = channels.wide_center(freq, 40, band) if band == "5" else freq + (10 if ch <= 7 else -10)
            sec_off = 1 if center > freq else 3
        out += tlv(61, bytes([ch, sec_off | (4 if width >= 40 else 0)]) + bytes(20))
    out += tlv(127, bytes([0, 0, 0x08 if n.get("v") else 0, 0, 0, 0, 0, 0x40]))
    mcs_map = (0xFFFF << (2 * streams)) & 0xFFFF | int("10" * streams, 2)
    if std in ("ac", "ax", "be") and band == "5":
        vcap = 0x0F8259B2 | (0x80000 if n.get("mu") else 0)
        out += tlv(191, struct.pack("<IHHHH", vcap, mcs_map, 0, mcs_map, 0))
        if width >= 80:
            c80 = channels.freq_to_channel(channels.wide_center(freq, 80, "5"))
            c160 = channels.freq_to_channel(channels.wide_center(freq, 160, "5")) if width >= 160 else 0
            out += tlv(192, bytes([1, c80, c160]) + b"\xfc\xff")
        else:
            out += tlv(192, bytes([0, 0, 0]) + b"\xfc\xff")
    if std in ("ax", "be"):
        phy0 = 0x02 if band == "2.4" else (0x04 | (0x08 if width >= 160 else 0))
        phy = bytes([phy0, 0, 0, 0x80, 0x02 if n.get("mu") else 0, 0, 0, 0, 0, 0, 0])
        out += ext(35, bytes([0x05, 0, 0, 0, 0, 0]) + phy + struct.pack("<HH", mcs_map, mcs_map))
        params = 0x20000 if band == "6" else 0
        op = bytes([params & 0xFF, (params >> 8) & 0xFF, params >> 16, n.get("color", 7)]) + b"\xfc\xff"
        if band == "6":
            w = min(width, 160)
            code = {20: 0, 40: 1, 80: 2, 160: 3}[w]
            c0 = channels.freq_to_channel(channels.wide_center(freq, min(w, 80), "6"))
            c1 = channels.freq_to_channel(channels.wide_center(freq, 160, "6")) if w == 160 else 0
            op += bytes([ch, code, c0, c1, 6])
        out += ext(36, op)
    if std == "be":
        out += ext(108, bytes([0, 0, 0x22 if width >= 320 else 0x20]) + bytes(8) + bytes(3))
        code = {20: 0, 40: 1, 80: 2, 160: 3, 320: 4}[width]
        half = min(width, 320) // 2 if width > 20 else 20
        c0 = channels.freq_to_channel(channels.wide_center(freq, max(half, 20), band))
        c1 = channels.freq_to_channel(channels.wide_center(freq, width, band)) if width >= 160 else 0
        out += ext(106, bytes([1]) + bytes(4) + bytes([code, c0, c1]))
        if n.get("mlo"):
            out += ext(107, struct.pack("<H", 0x0010) + bytes([7]) + bytes.fromhex(n["mld"].replace(":", "")))
    out += tlv(221, b"\x00\x50\xf2\x02\x01\x01\x80" + bytes(17))
    if n.get("wps"):
        out += wps(n.get("name", n["ssid"]), n.get("maker", "Generic"), n.get("model", "Router"), n.get("wps_locked", False))
    if sec in ("wpa3", "wpa23"):
        out += tlv(244, b"\x20")
    return out


# name, bssid, band, channel, width, std, sec, base rssi, extras
HOME = "SursumHome"
NETS = [
    dict(ssid=HOME, bssid="3c:28:6d:a1:10:01", band="2.4", channel=1, width=20, std="ax", sec="wpa23", rssi=-48, stations=4, util=22, k=1, v=1, r=1),
    dict(ssid=HOME, bssid="3c:28:6d:a1:10:02", band="5", channel=44, width=80, std="ax", sec="wpa23", rssi=-52, stations=7, util=14, k=1, v=1, r=1, mu=1, streams=4),
    dict(ssid=HOME, bssid="3c:28:6d:a1:10:03", band="6", channel=37, width=160, std="ax", sec="wpa3", rssi=-60, stations=2, util=4, k=1, v=1, r=1, mu=1, streams=4),
    dict(ssid=HOME, bssid="3c:28:6d:a1:22:01", band="2.4", channel=11, width=20, std="ax", sec="wpa23", rssi=-66, stations=1, util=18, k=1, v=1, r=1),
    dict(ssid=HOME, bssid="3c:28:6d:a1:22:02", band="5", channel=149, width=80, std="ax", sec="wpa23", rssi=-68, stations=3, util=9, k=1, v=1, r=1, mu=1, streams=4),
    dict(ssid="SursumHome-IoT", bssid="3e:28:6d:a1:10:01", band="2.4", channel=1, width=20, std="n", sec="wpa2", rssi=-49, stations=9, util=22),
    dict(ssid="NETGEAR47", bssid="a0:40:a0:5c:11:9e", band="2.4", channel=3, width=40, std="n", sec="wpa2", rssi=-71, wps=1, maker="NETGEAR, Inc.", model="R6700", stations=3, util=41),
    dict(ssid="NETGEAR47-5G", bssid="a0:40:a0:5c:11:9f", band="5", channel=44, width=80, std="ac", sec="wpa2", rssi=-78, wps=1, maker="NETGEAR, Inc.", model="R6700"),
    dict(ssid="xfinitywifi", bssid="e6:f0:42:1d:77:b1", band="2.4", channel=6, width=20, std="n", sec="open", rssi=-74),
    dict(ssid="XFINITY", bssid="e6:f0:42:1d:77:b2", band="5", channel=157, width=80, std="ac", sec="ent", rssi=-80),
    dict(ssid="TP-Link_8C2A", bssid="50:c7:bf:3e:8c:2a", band="2.4", channel=6, width=20, std="n", sec="wpa-tkip2", rssi=-69, wps=1, maker="TP-Link", model="Archer C7", stations=2, util=35, protection=1),
    dict(ssid="Linksys00413", bssid="14:91:82:0c:4f:20", band="2.4", channel=9, width=20, std="g", sec="wep", rssi=-83),
    dict(ssid="", hidden=1, bssid="b4:fb:e4:91:0a:c3", band="5", channel=36, width=40, std="ac", sec="wpa2", rssi=-76),
    dict(ssid="Orbi-BE", bssid="80:cc:9c:42:d0:11", band="6", channel=33, width=320, std="be", sec="wpa3", rssi=-72, mlo=1, mld="80:cc:9c:42:d0:10", streams=4, stations=5, util=6),
    dict(ssid="Orbi-BE", bssid="80:cc:9c:42:d0:12", band="5", channel=100, width=160, std="be", sec="wpa23", rssi=-70, mlo=1, mld="80:cc:9c:42:d0:10", streams=4),
    dict(ssid="CafeGuest", bssid="f0:9f:c2:7a:01:5d", band="5", channel=149, width=20, std="ax", sec="owe", rssi=-84),
    dict(ssid="ATT-HOMEBASE", bssid="88:71:b1:d3:6e:f4", band="2.4", channel=11, width=20, std="ax", sec="wpa2", rssi=-77, pmf="capable"),
    dict(ssid="DIRECT-7A-HP OfficeJet", bssid="fa:da:0c:4b:2e:7a", band="2.4", channel=6, width=20, std="n", sec="wpa2", rssi=-63, wps=1, maker="HP", model="OfficeJet 8020"),
    # appear later: an evil twin of the home SSID and a travel router plugged into the home LAN
    dict(ssid=HOME, bssid="02:1a:11:f3:9c:40", band="2.4", channel=6, width=20, std="n", sec="open", rssi=-58, after=25),
    dict(ssid="TP-Link_Extender_77", bssid="98:da:c4:5b:77:11", band="2.4", channel=1, width=20, std="n", sec="open", rssi=-55, after=40),
]


class SimulatedScanner:
    name = "demo"
    label = "Demo (simulated environment)"

    def __init__(self, seed: int = 7):
        self.rng = random.Random(seed)
        self.t0 = time.time()
        self.boot = {n["bssid"]: self.t0 - self.rng.uniform(3600, 40 * 86400) for n in NETS}
        self.phase = {n["bssid"]: self.rng.uniform(0, 6.28) for n in NETS}

    def close(self) -> None:
        pass

    def scan(self) -> tuple[list[dict], dict | None]:
        now = time.time()
        el = now - self.t0
        out = []
        for n in NETS:
            if el < n.get("after", 0):
                continue
            if n["rssi"] < -80 and self.rng.random() < 0.15:
                continue  # weak networks drop out of some scans
            ph = self.phase[n["bssid"]]
            rssi = n["rssi"] + 4 * math.sin(el / 17 + ph) + self.rng.gauss(0, 1.5)
            # walk-around effect for the two home APs so roaming can be observed
            if n["bssid"].startswith("3c:28:6d:a1:10"):
                rssi += 9 * math.sin(el / 45)
            elif n["bssid"].startswith("3c:28:6d:a1:22"):
                rssi -= 9 * math.sin(el / 45)
            dyn = dict(n)
            if "stations" in n:
                dyn["util"] = max(1, min(95, n.get("util", 20) + 8 * math.sin(el / 30 + ph)))
            noise = -95 + self.rng.gauss(0, 1)
            out.append(model.build(n["bssid"], rssi, channels.channel_to_freq(n["channel"], n["band"]),
                                   build_ies(dyn), capability=0x0401 | (0x10 if n["sec"] != "open" else 0),
                                   tsf_us=int((now - self.boot[n["bssid"]]) * 1e6), noise=round(noise, 1)))
        mine = [x for x in out if x["ssid"] == HOME and x["security"] != "Open" and x["band"] == "5"]
        conn = None
        if mine:
            best = max(mine, key=lambda x: x["rssi"])
            conn = {"ssid": HOME, "bssid": best["bssid"], "phy": "HE (ax)", "rssi": best["rssi"],
                    "quality": best["quality"], "rx_rate": 1201.0 if best["rssi"] > -60 else 648.5,
                    "tx_rate": 1201.0 if best["rssi"] > -62 else 576.4, "adapter": "Simulated adapter",
                    "profile": HOME}
        return out, conn
