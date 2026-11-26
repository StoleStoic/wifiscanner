"""Rule-based analysis: threat classification, distance estimates and advice notes.

Works fully offline. `ai.py` can optionally add Claude-written notes on top.
"""

from __future__ import annotations

import math
from typing import Any

from . import oui

PRIORITIES = ["Very High", "High", "Medium", "Low", "Very Low"]
SEVERITY = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
WEAK = ("Open", "WEP", "WPA-Personal")


def estimate_distance(n: dict, exponent: float = 3.0) -> dict[str, float]:
    """Log-distance path-loss estimate in metres. Rough: walls and antennas vary a lot."""
    tx = n.get("tx_power") if n.get("tx_power") is not None else (20 if n["band"] == "2.4" else 23)
    fspl_1m = 20 * math.log10(n["freq"]) - 27.55
    loss = tx - n["rssi"] - fspl_1m

    def d(e: float) -> float:
        return round(min(500.0, max(0.5, 10 ** (loss / (10 * e)))), 1)

    return {"m": d(exponent), "min": d(exponent + 0.7), "max": d(max(2.0, exponent - 0.7))}


def _mac_int(mac: str) -> int:
    v = int(oui.norm(mac).replace(":", ""), 16)
    return v & ~(0x02 << 40)  # ignore the locally-administered bit (virtual BSSIDs flip it)


def _near(a: str, b: str, span: int = 16) -> bool:
    try:
        return a != b and abs(_mac_int(a) - _mac_int(b)) <= span
    except ValueError:
        return False


def context(nets: list[dict], conn: dict | None, settings: dict) -> dict[str, Any]:
    inv = settings["inventory"]
    auth = {oui.norm(a["bssid"]): a.get("label", "") for a in inv["aps"] if a.get("bssid")}
    neigh = {oui.norm(a["bssid"]): a.get("label", "") for a in inv["neighbors"] if a.get("bssid")}
    home = {s for s in settings["home"]["ssids"] if s}
    home |= {n["ssid"] for n in nets if n["bssid"] in auth and n["ssid"]}
    mine = [n for n in nets if n["bssid"] in auth]
    if not auth and conn:  # nothing authorised yet: treat the connected network as "mine" for advice
        mine = [n for n in nets if n["ssid"] == conn.get("ssid") and n["ssid"]]
    return {"auth": auth, "neigh": neigh, "home": home, "mine": mine, "configured": bool(auth)}


def classify(nets: list[dict], conn: dict | None, settings: dict, lan: list[dict]) -> dict[str, Any]:
    """Sort every visible AP (and LAN device) into the threat classes."""
    ctx = context(nets, conn, settings)
    auth, neigh, home = ctx["auth"], ctx["neigh"], ctx["home"]
    exp = float(settings["home"].get("path_loss_exp", 3.0))
    perimeter = float(settings["home"].get("perimeter_m", 15))
    # LAN devices that could be an unapproved AP's wired side: not this PC, not the router,
    # not something you marked as known, and not an authorized AP's own interface.
    lan_macs = [d["mac"] for d in lan if d.get("mac") and not (d.get("self") or d.get("gateway") or d.get("known"))
                and d["mac"] not in auth and not any(_near(a, d["mac"]) for a in auth)]
    auth_sec = {n["ssid"]: n["security"] for n in nets if n["bssid"] in auth}
    items = []
    for n in nets:
        b = n["bssid"]
        dist = estimate_distance(n, exp)
        it = {"bssid": b, "ssid": n["ssid"], "band": n["band"], "channel": n["channel"], "rssi": n["rssi"],
              "security": n["security"], "vendor": n["vendor"], "distance": dist, "reasons": []}
        lan_hit = next((m for m in lan_macs if m == b or _near(m, b)), None)
        if b in auth:
            it.update(cls="authorized", severity="Info", label=auth[b] or "Authorized AP")
        elif b in neigh:
            it.update(cls="neighbor", severity="Low", label=neigh[b] or "Known neighbor")
            it["reasons"].append("Marked by you as a known neighbor.")
        elif not ctx["configured"]:
            it.update(cls="unclassified", severity="Info", label="Unclassified")
        elif n["ssid"] and n["ssid"] in home:
            adjacent = next((a for a in auth if _near(a, b)), None)
            weaker = n["security"] != auth_sec.get(n["ssid"], n["security"])
            if adjacent and not weaker:
                it.update(cls="unauthorized", severity="Medium", label="Unlisted radio of your AP?")
                it["reasons"].append(f"Broadcasts your SSID and its address is next to authorized AP {adjacent}; "
                                     "probably another radio of the same unit. Authorize it if it is yours.")
            else:
                it.update(cls="rogue", severity="Critical", label="Evil twin / SSID spoof")
                it["reasons"].append(f"Broadcasts your network name '{n['ssid']}' from a BSSID that is not in your authorized list.")
                if weaker:
                    it["reasons"].append(f"Its security ({n['security']}) differs from your real network "
                                         f"({auth_sec.get(n['ssid'])}) - a classic impersonation sign.")
        elif lan_hit:
            it.update(cls="rogue", severity="Critical", label="Rogue AP on your network")
            it["reasons"].append(f"Its radio address matches or sits next to {lan_hit}, a device found on your wired/LAN side. "
                                 "An unapproved AP appears to be plugged into your network.")
        elif any(_near(a, b) for a in auth):
            it.update(cls="unauthorized", severity="Medium", label="Unlisted radio of your AP?")
            it["reasons"].append("Address is adjacent to one of your authorized APs (often a guest or IoT network). "
                                 "Authorize it if you recognise it.")
        elif dist["m"] <= perimeter:
            it.update(cls="unauthorized", severity="High", label="Unauthorized AP in your airspace")
            it["reasons"].append(f"Unknown AP estimated about {dist['m']} m away, inside your {perimeter:g} m home perimeter.")
        else:
            it.update(cls="neighbor", severity="Low", label="Neighboring AP")
            it["reasons"].append(f"Unknown AP estimated about {dist['m']} m away, outside your home perimeter. "
                                 "Verify once, then mark it as a known neighbor.")
        if it["cls"] in ("rogue", "unauthorized") and n["security"] in WEAK:
            it["reasons"].append(f"Uses weak or no encryption ({n['security']}).")
        items.append(it)

    events = []
    if conn and ctx["configured"] and conn.get("bssid") and oui.norm(conn["bssid"]) not in auth:
        events.append({"cls": "accidental", "severity": "Medium", "label": "Accidental association",
                       "bssid": conn["bssid"], "ssid": conn.get("ssid"),
                       "reasons": [f"This PC is connected to '{conn.get('ssid')}' ({conn['bssid']}), "
                                   "which is not one of your authorized access points."]})
    clients = []
    for d in lan:
        if d.get("known") or d.get("gateway") or not d.get("mac"):
            continue
        if oui.norm(d["mac"]) in auth or any(_near(a, d["mac"]) for a in auth):
            continue  # an authorized AP's own LAN interface
        clients.append({"cls": "rogue_client", "severity": "High", "label": "Unknown device on your network",
                        "ip": d["ip"], "mac": d["mac"], "vendor": d.get("vendor"), "hostname": d.get("hostname"),
                        "reasons": ["Connected to your network but not in your known-devices list."
                                    + (" Uses a randomised (private) MAC address." if d.get("random_mac") else "")]})
    items.sort(key=lambda i: (SEVERITY[i["severity"]], -i["rssi"]))
    counts: dict[str, int] = {}
    for i in items + events + clients:
        counts[i["cls"]] = counts.get(i["cls"], 0) + 1
    return {"configured": ctx["configured"], "home_ssids": sorted(home), "aps": items, "events": events,
            "clients": clients, "counts": counts, "perimeter_m": perimeter}


def _best_channels(nets: list[dict], band: str) -> list[tuple[int, float]]:
    """Rank candidate 20 MHz channels by how much neighbouring signal lands on them."""
    cands = {"2.4": [1, 6, 11], "5": [36, 40, 44, 48, 149, 153, 157, 161]}.get(band, [])
    out = []
    for ch in cands:
        f = (2407 if band == "2.4" else 5000) + 5 * ch
        score = 0.0
        for n in nets:
            if n["band"] == band and n["span_lo"] < f + 10 and f - 10 < n["span_hi"]:
                score += 10 ** ((n["rssi"] + 100) / 20)  # stronger neighbours cost more
        out.append((ch, round(score, 1)))
    return sorted(out, key=lambda x: x[1])


def notes(nets: list[dict], conn: dict | None, settings: dict, lan: list[dict]) -> list[dict]:  # noqa: C901
    """Prioritised advice across Security, Connectivity, Performance and Configuration."""
    out: list[dict] = []

    def add(cat: str, pri: str, title: str, detail: str, article: str, bssid: str | None = None) -> None:
        out.append({"category": cat, "priority": pri, "title": title, "detail": detail,
                    "article": article, "bssid": bssid, "source": "rules"})

    ctx = context(nets, conn, settings)
    mine = ctx["mine"]
    th = classify(nets, conn, settings, lan)

    def who(n: dict) -> str:
        return f"{n['ssid'] or '(hidden)'} on {n['band']} GHz ch {n['channel']} ({n['bssid']})"

    # ---- security
    for t in th["aps"]:
        if t["cls"] == "rogue":
            add("Security", "Very High", f"{t['label']}: {t['ssid'] or '(hidden)'}", " ".join(t["reasons"]) +
                " Do not connect to it. Use the Locate tool to walk towards it and find the device.", "rogue-ap", t["bssid"])
        elif t["cls"] == "unauthorized" and t["severity"] == "High":
            add("Security", "High", f"Unauthorized AP nearby: {t['ssid'] or '(hidden)'}", " ".join(t["reasons"]) +
                " If it is yours, authorize it; if it is a neighbor, mark it so.", "unauthorized-ap", t["bssid"])
    for e in th["events"]:
        add("Security", "High", "This PC is connected to a non-authorized access point", " ".join(e["reasons"]) +
            " Disconnect and remove that network from Windows' saved networks if you did not intend this.",
            "accidental-association", e["bssid"])
    for c in th["clients"]:
        add("Security", "High", f"Unknown device on your network: {c['ip']}",
            f"{c['mac']} {c.get('vendor') or ''} {c.get('hostname') or ''}. ".replace("  ", " ") + c["reasons"][0] +
            " If you recognise it, add it to known devices; otherwise change your WiFi password.", "rogue-client")
    for n in mine:
        if n["security"] == "Open":
            add("Security", "Very High", f"Your network is open: {n['ssid']}",
                f"{who(n)} has no encryption; anyone in range can join and read traffic. Enable WPA3 or WPA2.", "open-network", n["bssid"])
        elif n["security"] == "WEP":
            add("Security", "Very High", f"Your network uses WEP: {n['ssid']}",
                f"{who(n)} uses WEP, which can be cracked in minutes. Switch to WPA2/WPA3.", "weak-encryption", n["bssid"])
        elif "TKIP" in n.get("ciphers", []) or n["security"].startswith("WPA-") or n["security"].startswith("WPA/"):
            add("Security", "High", f"Legacy WPA/TKIP enabled: {n['ssid']}",
                f"{who(n)} still accepts WPA1/TKIP. It is deprecated and caps speeds at 54 Mbps. Use WPA2-AES or WPA3 only.",
                "weak-encryption", n["bssid"])
        if n.get("wps") and not n.get("wps_locked"):
            add("Security", "High", f"WPS is enabled: {n['ssid']}",
                f"{who(n)} advertises WiFi Protected Setup. The WPS PIN can be brute-forced; turn WPS off in the router.",
                "wps", n["bssid"])
        if n["security"] == "WPA2-Personal":
            add("Security", "Low", f"WPA3 not enabled: {n['ssid']}",
                f"{who(n)} offers WPA2 only. If your devices support it, enable WPA2/WPA3 transition mode.", "wpa3", n["bssid"])
        if n["security"].startswith("WPA2") and n.get("pmf") == "no":
            add("Security", "Low", f"Protected Management Frames are off: {n['ssid']}",
                f"{who(n)} does not protect management frames, so clients can be knocked off with forged deauth frames. "
                "Set PMF / 802.11w to 'capable'.", "pmf", n["bssid"])
    secs = {}
    for n in mine:
        if n["band"] != "6":
            secs.setdefault(n["ssid"], set()).add(n["security"])
    for ssid, s in secs.items():
        if len(s) > 1:
            add("Configuration", "Medium", f"Inconsistent security on '{ssid}'",
                f"Your access points advertise different security for the same name: {', '.join(sorted(s))}. "
                "Roaming can fail; use identical settings on every AP.", "consistent-config")

    # ---- connectivity
    cn = next((n for n in nets if conn and n["bssid"] == conn.get("bssid")), None)
    if conn and conn.get("rssi") is not None:
        r = conn["rssi"]
        if r < -80:
            add("Connectivity", "Very High", "Very weak signal at this location",
                f"Connected at {r} dBm. Expect drops and very low speeds. Move closer, or add/relocate an access point.",
                "signal-strength", conn.get("bssid"))
        elif r < -70:
            add("Connectivity", "High", "Weak signal at this location",
                f"Connected at {r} dBm. Video calls and streaming may stutter; aim for -65 dBm or better.",
                "signal-strength", conn.get("bssid"))
        better = [n for n in nets if n["ssid"] == conn.get("ssid") and n["bssid"] != conn.get("bssid")
                  and n["rssi"] >= r + 10 and n["security"] == (cn or n)["security"]]
        if better:
            b = max(better, key=lambda n: n["rssi"])
            add("Connectivity", "Medium", "A stronger access point is available (sticky client)",
                f"You are on {conn.get('bssid')} at {r} dBm but {b['bssid']} ({b['band']} GHz ch {b['channel']}) is at "
                f"{b['rssi']} dBm. Toggle WiFi to re-select, and enable 802.11k/v on your APs to help roaming.",
                "roaming", b["bssid"])
    if cn and cn.get("snr") is not None and cn["snr"] < 20:
        add("Connectivity", "High", "Low signal-to-noise ratio",
            f"SNR is {cn['snr']} dB on your connected AP; below 20 dB forces slow data rates.", "signal-strength", cn["bssid"])
    if len({n["bssid"] for n in mine}) > 1:
        for ssid in {n["ssid"] for n in mine}:
            group = [n for n in mine if n["ssid"] == ssid]
            if len(group) > 1 and not any(n.get("k") or n.get("v") or n.get("r") for n in group):
                add("Connectivity", "Low", f"Roaming assistance not advertised on '{ssid}'",
                    "None of your APs advertise 802.11k/v/r. Devices will cling to a far AP longer than they should.", "roaming")

    # ---- performance
    for n in mine:
        if n["band"] == "2.4" and n["width"] >= 40:
            add("Performance", "High", f"40 MHz channel in 2.4 GHz: {n['ssid']}",
                f"{who(n)} uses a 40 MHz channel, which covers most of the band and collides with neighbors. Set 20 MHz.",
                "channel-width", n["bssid"])
        if n["band"] == "2.4" and n["channel"] not in (1, 6, 11):
            add("Configuration", "High", f"Non-standard 2.4 GHz channel {n['channel']}: {n['ssid']}",
                f"{who(n)} overlaps two of the standard channels (1/6/11) and suffers adjacent-channel interference. "
                "Use 1, 6 or 11.", "channel-planning", n["bssid"])
        if n.get("aci", 0) >= 2 and n["band"] == "2.4":
            add("Performance", "High", f"Adjacent-channel interference on {n['ssid']}",
                f"{n['aci']} networks partly overlap {who(n)}. Unlike same-channel neighbors, they cannot coordinate "
                "with you and simply corrupt each other's frames.", "interference", n["bssid"])
        if n.get("cci", 0) >= 4:
            best = _best_channels([x for x in nets if x["bssid"] != n["bssid"]], n["band"])
            hint = f" Channel {best[0][0]} currently looks quietest." if best and best[0][0] != n["channel"] else ""
            add("Performance", "Medium" if n["cci"] < 8 else "High", f"Crowded channel {n['channel']}: {n['ssid']}",
                f"{n['cci']} other networks share the channel with {who(n)}; airtime is split between all of them.{hint}",
                "interference", n["bssid"])
        if n.get("utilization") is not None and n["utilization"] >= 50:
            add("Performance", "Very High" if n["utilization"] >= 75 else "High",
                f"High channel utilization ({n['utilization']:.0f}%): {n['ssid']}",
                f"{who(n)} reports the channel busy {n['utilization']:.0f}% of the time. Move to a quieter channel or band.",
                "channel-utilization", n["bssid"])
        if n.get("stations") is not None and n["stations"] >= 30:
            add("Performance", "Medium", f"Many clients on one radio ({n['stations']}): {n['ssid']}",
                f"{who(n)} serves {n['stations']} stations. Spread devices across bands or add an AP.", "client-load", n["bssid"])
        if n["band"] == "5" and n["width"] == 20 and any(x in n.get("standards", []) for x in ("ac", "ax", "be")):
            add("Performance", "Medium", f"Narrow 20 MHz channel in 5 GHz: {n['ssid']}",
                f"{who(n)} could use 40 or 80 MHz for two to four times the throughput if the band is not crowded.",
                "channel-width", n["bssid"])
        if n["band"] == "2.4" and any(r in (1, 2, 5.5, 11) for r in n.get("basic_rates", [])):
            add("Performance", "Low", f"Legacy 802.11b rates enabled: {n['ssid']}",
                f"{who(n)} keeps 1-11 Mbps basic rates; beacons sent that slowly eat airtime. Disable 802.11b rates "
                "unless you own a very old device.", "legacy-rates", n["bssid"])
        if n.get("protection"):
            add("Performance", "Low", f"802.11b protection mode active: {n['ssid']}",
                f"{who(n)} detected an 802.11b device nearby and is using protection frames, lowering throughput.",
                "legacy-rates", n["bssid"])
        if n.get("generation") in ("Legacy", "WiFi 4") and n["band"] != "2.4":
            add("Configuration", "Low", f"Older WiFi generation: {n['ssid']}",
                f"{who(n)} is {n['generation']}. A WiFi 6 or newer access point would improve speed and capacity.",
                "wifi-generations", n["bssid"])
        if n.get("beacon_interval") and n["beacon_interval"] != 100:
            add("Configuration", "Very Low", f"Unusual beacon interval ({n['beacon_interval']} TU): {n['ssid']}",
                f"{who(n)} does not use the standard 100 TU; some devices roam or sleep poorly with other values.",
                "consistent-config", n["bssid"])
        if n.get("hidden"):
            add("Configuration", "Very Low", "Hidden network name",
                f"{n['bssid']} hides its SSID. That gives no real security and makes your devices broadcast the name "
                "everywhere they go.", "hidden-ssid", n["bssid"])
    for band in ("2.4", "5"):
        m = [n for n in mine if n["band"] == band]
        if m:
            best = _best_channels([x for x in nets if x not in m], band)
            cur = {n["channel"] for n in m}
            if best and best[0][0] not in cur and band == "2.4":
                add("Performance", "Low", f"Quietest {band} GHz channel right now: {best[0][0]}",
                    f"Your APs use channel(s) {', '.join(map(str, sorted(cur)))}. Based on neighbors currently visible, "
                    f"channel {best[0][0]} has the least competing signal.", "channel-planning")
    if mine and not any(n["band"] in ("5", "6") for n in mine):
        add("Configuration", "Medium", "No 5 GHz or 6 GHz network seen",
            "Only 2.4 GHz radios of your network are visible. 5/6 GHz is much faster and far less crowded; enable it "
            "if the router supports it.", "bands")
    if not ctx["configured"]:
        add("Configuration", "Medium", "Tell the scanner which access points are yours",
            "Threat detection needs your authorized AP list. Open the Threats tab and authorize your own access points; "
            "everything else can then be classified as rogue, unauthorized or neighboring.", "getting-started")
    out.sort(key=lambda x: PRIORITIES.index(x["priority"]))
    return out
