"""Remote scanning over SSH (WLAN Pi or any Linux box with `iw`).

Runs `iw dev <iface> scan` on the probe using the system `ssh` client with
key-based authentication (Windows 11 ships OpenSSH) and parses the text output.
"""

from __future__ import annotations

import re
import shlex
import subprocess
import time

from .. import channels, model, oui
from . import ScanError

_BSS = re.compile(r"^BSS ([0-9a-f:]{17})", re.I)
_NAME_OK = re.compile(r"^[A-Za-z0-9_.@:-]+$")


def _width_from(vht: dict, eht: dict, he6: dict, ht_sec: str | None) -> tuple[int, int | None]:
    """Return (width, centre channel or None)."""
    for d in (eht, he6):
        m = re.search(r"(\d+)\s*MHz", d.get("width", ""))
        if m:
            c = d.get("ccfs1") or d.get("ccfs0")
            return int(m.group(1)), c or None
    code = vht.get("width")
    if code is not None and code != 0:
        s0, s1 = vht.get("seg0", 0), vht.get("seg1", 0)
        if code == 2 or (s1 and abs(s1 - s0) == 8):
            return 160, s1 or s0
        return 80, s0
    return (40 if ht_sec in ("above", "below") else 20), None


def parse_iw_scan(text: str, noise_by_freq: dict[int, float] | None = None) -> list[dict]:  # noqa: C901
    nets = []
    blocks: list[list[str]] = []
    for line in text.splitlines():
        if _BSS.match(line):
            blocks.append([line])
        elif blocks:
            blocks[-1].append(line)
    now = time.time()
    for b in blocks:
        bssid = _BSS.match(b[0]).group(1).lower()  # type: ignore[union-attr]
        f: dict = {"rates": [], "basic": [], "akm": [], "pair": [], "wpa1": False, "caps": ""}
        vht: dict = {}
        eht: dict = {}
        he6: dict = {}
        section = ""
        std = set()
        for raw in b[1:]:
            line = raw.strip()
            top = raw.startswith("\t") and not raw.startswith("\t\t")
            if top:
                key, _, val = line.partition(":")
                val = val.strip()
                section = key
                if key == "freq":
                    f["freq"] = int(float(val.split()[0]))
                elif key == "signal":
                    f["rssi"] = float(val.split()[0])
                elif key == "TSF":
                    f["tsf"] = int(val.split()[0])
                elif key == "beacon interval":
                    f["bi"] = int(val.split()[0])
                elif key == "capability":
                    f["caps"] = val
                elif key == "last seen" and "ms ago" in val:
                    f["age"] = int(val.split()[0]) / 1000
                elif key == "SSID":
                    f["ssid"] = val
                elif key in ("Supported rates", "Extended supported rates"):
                    for r in val.split():
                        try:
                            f["rates"].append(float(r.rstrip("*")))
                            if r.endswith("*"):
                                f["basic"].append(float(r.rstrip("*")))
                        except ValueError:
                            pass
                elif key == "Country":
                    f["country"] = val.split()[0] if val else None
                elif key == "HT capabilities":
                    std.add("n")
                elif key == "VHT capabilities":
                    std.add("ac")
                elif key == "HE capabilities":
                    std.add("ax")
                elif key == "EHT capabilities":
                    std.add("be")
                elif key == "WPS":
                    f["wps"] = True
                elif key == "WPA":
                    f["wpa1"] = True
                elif key == "TIM":
                    m = re.search(r"DTIM Period (\d+)", val)
                    if m:
                        f["dtim"] = int(m.group(1))
                if key in ("RSN", "WPA", "WPS") and "*" in val:
                    line = val  # first attribute shares the header line
                else:
                    continue
            if not line.startswith("*"):
                continue
            k, _, v = line.lstrip("* ").partition(":")
            k, v = k.strip().lower(), v.strip()
            if section == "BSS Load":
                if k == "station count":
                    f["stations"] = int(v)
                elif k.startswith("channel utili"):
                    f["util"] = round(int(v.split("/")[0]) * 100 / 255, 1)
            elif section == "RSN":
                if k == "pairwise ciphers":
                    f["pair"] = v.split()
                elif k == "group cipher":
                    f["group"] = v
                elif k == "authentication suites":
                    f["akm"] = [a.replace("IEEE", "").strip() for a in re.split(r"\s+", v) if a]
                elif k == "capabilities":
                    f["pmf"] = "required" if "MFP-required" in v else "capable" if "MFP-capable" in v else "no"
            elif section == "WPS":
                if k == "device name":
                    f["wps_name"] = v
                elif k == "ap setup locked":
                    f["wps_locked"] = v.startswith("0x01")
            elif section == "HT operation":
                if k == "secondary channel offset":
                    f["sec"] = v if v in ("above", "below") else None
            elif section == "VHT operation":
                m = re.match(r"(\d+)", v)
                if m and k == "channel width":
                    vht["width"] = int(m.group(1))
                elif m and k == "center freq segment 1":
                    vht["seg0"] = int(m.group(1))
                elif m and k == "center freq segment 2":
                    vht["seg1"] = int(m.group(1))
            elif section in ("EHT Operation", "HE Operation") or section.startswith(("EHT", "HE")):
                tgt = eht if section.startswith("EHT") else he6
                if "channel width" in k:
                    tgt["width"] = v
                elif "center frequency segment 0" in k or "ccfs0" in k:
                    tgt["ccfs0"] = int(re.match(r"\d+", v).group(0)) if re.match(r"\d+", v) else 0
                elif "center frequency segment 1" in k or "ccfs1" in k:
                    tgt["ccfs1"] = int(re.match(r"\d+", v).group(0)) if re.match(r"\d+", v) else 0
                elif k == "bss color":
                    f["color"] = int(v) if v.isdigit() else None
        if "freq" not in f or "rssi" not in f:
            continue
        freq = f["freq"]
        band = channels.band_of(freq)
        width, cch = _width_from(vht, eht, he6, f.get("sec"))
        center = channels.channel_to_freq(cch, band) if cch else (
            freq + (10 if f.get("sec") == "above" else -10) if width == 40 and f.get("sec")
            else channels.wide_center(freq, width, band))
        akm = [a for a in f["akm"] if a]
        privacy = "Privacy" in f["caps"]
        if akm:
            ent = any("802.1X" in a for a in akm)
            sae, psk, owe = any("SAE" in a for a in akm), any("PSK" in a for a in akm), "OWE" in akm
            sec = ("Enhanced Open (OWE)" if owe else "WPA2-Enterprise" if ent else "WPA2/WPA3-Personal" if sae and psk
                   else "WPA3-Personal" if sae else "WPA/WPA2-Personal" if f["wpa1"] else "WPA2-Personal")
        elif f["wpa1"]:
            sec = "WPA-Personal"
        else:
            sec = "WEP" if privacy else "Open"
        order = []
        rates = sorted(set(f["rates"]))
        if band == "2.4":
            if any(r in (1, 2, 5.5, 11) for r in rates):
                order.append("b")
            if any(r >= 6 and r not in (11,) for r in rates):
                order.append("g")
        elif band == "5":
            order.append("a")
        order += [s for s in ("n", "ac", "ax", "be") if s in std and not (s == "ac" and band != "5")]
        top = order[-1] if order else ""
        noise = (noise_by_freq or {}).get(freq)
        seen = now - f.get("age", 0)
        lo, hi = channels.span(center, width)
        ssid = f.get("ssid", "")
        hidden = not ssid or set(ssid) <= {"\\", "x", "0"}
        n = {
            "bssid": bssid, "ssid": "" if hidden else ssid, "hidden": hidden, "band": band, "freq": freq,
            "channel": channels.freq_to_channel(freq), "width": width, "center_freq": center,
            "center_channel": channels.freq_to_channel(center), "secondary": f.get("sec"),
            "span_lo": lo, "span_hi": hi, "rssi": f["rssi"], "noise": noise,
            "snr": round(f["rssi"] - noise, 1) if noise is not None else None,
            "quality": model.quality(f["rssi"]), "vendor": oui.vendor(bssid), "local_mac": oui.is_local(bssid),
            "standards": order, "generation": {"be": "WiFi 7", "ax": "WiFi 6E" if band == "6" else "WiFi 6",
                                               "ac": "WiFi 5", "n": "WiFi 4"}.get(top, "Legacy"),
            "security": sec, "akm": akm, "ciphers": f["pair"], "group_cipher": f.get("group"),
            "pmf": f.get("pmf", "no"), "wps": bool(f.get("wps")), "wps_locked": bool(f.get("wps_locked")),
            "stations": f.get("stations"), "utilization": f.get("util"), "country": f.get("country"),
            "rates": rates, "basic_rates": sorted(set(f["basic"])), "max_rate": max(rates) if rates else 0,
            "streams": None, "beacon_interval": f.get("bi", 100), "dtim": f.get("dtim"),
            "uptime": round(f["tsf"] / 1e6) if f.get("tsf") else None, "bss_color": f.get("color"),
            "ap_name": f.get("wps_name"), "model": None, "tx_power": None, "protection": False,
            "k": "RadioMeasure" in f["caps"], "v": False, "r": any(a.startswith("FT") for a in akm),
            "wmm": False, "mu_mimo": False, "beamforming": False, "twt": False, "mlo": False,
            "hotspot2": False, "mode": "Ad-hoc" if "IBSS" in f["caps"] else "Infrastructure",
            "cap_flags": f["caps"].split("(")[0].split(), "capability": 0, "phy": None,
            "first_seen": seen, "last_seen": seen, "connected": "associated" in b[0], "seen": 1,
            "ies": [], "ie_note": "Raw tagged parameters are not available from remote iw scans.",
        }
        nets.append(n)
    return nets


def parse_survey(text: str) -> dict[int, float]:
    out: dict[int, float] = {}
    freq = None
    for line in text.splitlines():
        m = re.search(r"frequency:\s+(\d+)", line)
        if m:
            freq = int(m.group(1))
        m = re.search(r"noise:\s+(-?\d+)", line)
        if m and freq:
            out[freq] = float(m.group(1))
    return out


class RemoteScanner:
    name = "remote"

    def __init__(self, probe: dict):
        self.probe = probe
        self.label = f"Remote probe: {probe.get('name') or probe.get('host')}"
        for k in ("host", "user", "iface"):
            v = str(probe.get(k) or "")
            if not v or not _NAME_OK.match(v):
                raise ScanError(f"Remote probe needs a valid {k}.")

    def close(self) -> None:
        pass

    def command(self) -> list[str]:
        p = self.probe
        iface = shlex.quote(p["iface"])
        sudo = "sudo -n " if p.get("sudo", True) else ""
        remote = f"{sudo}iw dev {iface} scan; echo ===SURVEY===; {sudo}iw dev {iface} survey dump"
        cmd = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", "-o", "StrictHostKeyChecking=accept-new",
               "-p", str(int(p.get("port") or 22))]
        if p.get("key"):
            cmd += ["-i", str(p["key"])]
        return cmd + [f"{p['user']}@{p['host']}", remote]

    def scan(self) -> tuple[list[dict], dict | None]:
        try:
            r = subprocess.run(self.command(), capture_output=True, text=True, timeout=40)
        except FileNotFoundError as e:
            raise ScanError("The 'ssh' command was not found. Install the Windows OpenSSH Client feature.") from e
        except subprocess.TimeoutExpired as e:
            raise ScanError("Remote probe timed out.") from e
        scan_txt, _, survey = r.stdout.partition("===SURVEY===")
        if "BSS " not in scan_txt:
            err = (r.stderr or "no output").strip().splitlines()[-1][:200]
            raise ScanError(f"Remote scan failed: {err}")
        return parse_iw_scan(scan_txt, parse_survey(survey)), None
