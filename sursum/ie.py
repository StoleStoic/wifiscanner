"""802.11 information element (tagged parameter) parser.

`parse_ies(raw)` walks the tag/length/value stream found in beacons and probe
responses and returns a list of decoded elements. `summarize(...)` folds those
elements into the flat record the UI works with (width, security, standards...).
Everything here is pure Python and platform independent.
"""

from __future__ import annotations

import struct
from typing import Any

from . import channels

CIPHERS = {0: "Group", 1: "WEP-40", 2: "TKIP", 4: "CCMP", 5: "WEP-104", 6: "BIP-CMAC-128",
           8: "GCMP-128", 9: "GCMP-256", 10: "CCMP-256", 11: "BIP-GMAC-128",
           12: "BIP-GMAC-256", 13: "BIP-CMAC-256"}
AKMS = {1: "802.1X", 2: "PSK", 3: "FT-802.1X", 4: "FT-PSK", 5: "802.1X-SHA256",
        6: "PSK-SHA256", 7: "TDLS", 8: "SAE", 9: "FT-SAE", 11: "Suite-B", 12: "Suite-B-192",
        13: "FT-802.1X-SHA384", 14: "FILS-SHA256", 15: "FILS-SHA384", 18: "OWE",
        19: "FT-PSK-SHA384", 20: "PSK-SHA384", 24: "SAE-EXT-KEY", 25: "FT-SAE-EXT-KEY"}

IE_NAMES = {
    0: "SSID", 1: "Supported Rates", 3: "DS Parameter Set", 5: "TIM", 7: "Country",
    11: "QBSS Load", 32: "Power Constraint", 33: "Power Capability", 35: "TPC Report",
    37: "Channel Switch Announcement", 42: "ERP Information", 45: "HT Capabilities",
    48: "RSN", 50: "Extended Supported Rates", 54: "Mobility Domain", 59: "Supported Operating Classes",
    61: "HT Operation", 67: "BSS Available Admission Capacity", 70: "RM Enabled Capabilities",
    71: "Multiple BSSID", 74: "Overlapping BSS Scan Parameters", 107: "Interworking",
    108: "Advertisement Protocol", 111: "Roaming Consortium", 113: "Mesh Configuration",
    114: "Mesh ID", 127: "Extended Capabilities", 133: "Cisco CCX1 (AP Name)",
    191: "VHT Capabilities", 192: "VHT Operation", 195: "Transmit Power Envelope",
    201: "Reduced Neighbor Report", 221: "Vendor Specific", 244: "RSN Extension",
}
EXT_NAMES = {
    35: "HE Capabilities", 36: "HE Operation", 37: "UORA Parameter Set", 38: "MU EDCA Parameter Set",
    39: "Spatial Reuse Parameter Set", 59: "HE 6 GHz Band Capabilities",
    106: "EHT Operation", 107: "Multi-Link", 108: "EHT Capabilities", 109: "TID-to-Link Mapping",
}
WPS_ATTRS = {0x1011: "device_name", 0x1021: "manufacturer", 0x1023: "model_name",
             0x1024: "model_number", 0x1042: "serial_number"}


def _hex(b: bytes) -> str:
    return b.hex(" ")


def _rate(v: int) -> tuple[float, bool] | None:
    """Decode a rate byte to (Mbps, is_basic); None for BSS membership selectors."""
    val = v & 0x7F
    if val >= 122:  # membership selectors (HT=127, VHT=126, HE=122, SAE H2E=123 ...)
        return None
    return val / 2, bool(v & 0x80)


def _suite(b: bytes, table: dict[int, str]) -> str:
    oui, typ = b[:3], b[3]
    if oui == b"\x00\x0f\xac":
        return table.get(typ, f"type-{typ}")
    if oui == b"\x00\x50\xf2":  # WPA1 suites
        return {1: "802.1X", 2: "PSK"}.get(typ, f"type-{typ}") if table is AKMS else \
            {1: "WEP-40", 2: "TKIP", 4: "CCMP", 5: "WEP-104"}.get(typ, f"type-{typ}")
    if oui == b"\x50\x6f\x9a" and table is AKMS:
        return {1: "OSEN", 2: "DPP"}.get(typ, f"WFA-{typ}")
    return f"{oui.hex(':')}-{typ}"


def _parse_rsn(d: bytes, wpa1: bool = False) -> dict[str, Any]:
    out: dict[str, Any] = {"pairwise": [], "akm": []}
    try:
        pos = 2  # version
        out["version"] = struct.unpack_from("<H", d, 0)[0]
        out["group"] = _suite(d[pos:pos + 4], CIPHERS)
        pos += 4
        n = struct.unpack_from("<H", d, pos)[0]
        pos += 2
        for _ in range(n):
            out["pairwise"].append(_suite(d[pos:pos + 4], CIPHERS))
            pos += 4
        n = struct.unpack_from("<H", d, pos)[0]
        pos += 2
        for _ in range(n):
            out["akm"].append(_suite(d[pos:pos + 4], AKMS))
            pos += 4
        if not wpa1 and pos + 2 <= len(d):
            caps = struct.unpack_from("<H", d, pos)[0]
            pos += 2
            out["pmf_required"] = bool(caps & 0x40)
            out["pmf_capable"] = bool(caps & 0x80)
            if pos + 2 <= len(d):
                n = struct.unpack_from("<H", d, pos)[0]
                pos += 2 + 16 * n
                if pos + 4 <= len(d):
                    out["group_mgmt"] = _suite(d[pos:pos + 4], CIPHERS)
    except (struct.error, IndexError):
        out["truncated"] = True
    return out


def _parse_wps(d: bytes) -> dict[str, Any]:
    out: dict[str, Any] = {}
    pos = 0
    while pos + 4 <= len(d):
        typ, ln = struct.unpack_from(">HH", d, pos)
        val = d[pos + 4:pos + 4 + ln]
        pos += 4 + ln
        if typ == 0x1044 and val:
            out["state"] = {1: "Not configured", 2: "Configured"}.get(val[0], str(val[0]))
        elif typ == 0x1057 and val:
            out["ap_setup_locked"] = bool(val[0])
        elif typ == 0x104A and val:
            out["version"] = f"{val[0] >> 4}.{val[0] & 0xF}"
        elif typ == 0x1041 and val:
            out["selected_registrar"] = bool(val[0])
        elif typ in WPS_ATTRS:
            out[WPS_ATTRS[typ]] = val.decode("utf-8", "replace").strip("\x00 ")
    return out


def _mcs_map_streams(m: int) -> int:
    """Count spatial streams in a VHT/HE 2-bits-per-stream MCS map (3 = unsupported)."""
    return sum(1 for i in range(8) if (m >> (2 * i)) & 3 != 3)


def _decode(eid: int, ext: int | None, d: bytes) -> dict[str, Any]:  # noqa: C901
    o: dict[str, Any] = {}
    if eid == 0:
        o["ssid"] = d.decode("utf-8", "replace")
        o["hidden"] = len(d) == 0 or not any(d)
    elif eid in (1, 50):
        rates = [r for r in map(_rate, d) if r]
        o["rates"] = [r[0] for r in rates]
        o["basic"] = [r[0] for r in rates if r[1]]
        o["selectors"] = [v & 0x7F for v in d if (v & 0x7F) >= 122]
    elif eid == 3 and d:
        o["channel"] = d[0]
    elif eid == 5 and len(d) >= 3:
        o.update(dtim_count=d[0], dtim_period=d[1], bitmap_control=d[2],
                 multicast_buffered=bool(d[2] & 1))
    elif eid == 7 and len(d) >= 3:
        o["country"] = d[:2].decode("ascii", "replace")
        o["environment"] = {0x20: "Any", 0x49: "Indoor", 0x4F: "Outdoor"}.get(d[2], hex(d[2]))
        trip = []
        for i in range(3, len(d) - 2, 3):
            if d[i] >= 201:  # operating-class triplet
                continue
            trip.append({"first_channel": d[i], "channels": d[i + 1],
                         "max_tx_dbm": struct.unpack_from("b", d, i + 2)[0]})
        o["triplets"] = trip
    elif eid == 11 and len(d) >= 5:
        sta, util, cap = struct.unpack_from("<HBH", d, 0)
        o.update(stations=sta, utilization_pct=round(util * 100 / 255, 1), admission_capacity=cap)
    elif eid == 32 and d:
        o["power_constraint_db"] = d[0]
    elif eid == 35 and len(d) >= 2:
        o.update(tx_power_dbm=struct.unpack_from("b", d, 0)[0], link_margin_db=struct.unpack_from("b", d, 1)[0])
    elif eid == 37 and len(d) >= 3:
        o.update(mode=d[0], new_channel=d[1], count=d[2])
    elif eid == 42 and d:
        o.update(non_erp_present=bool(d[0] & 1), use_protection=bool(d[0] & 2),
                 barker_preamble=bool(d[0] & 4))
    elif eid == 45 and len(d) >= 19:
        cap = struct.unpack_from("<H", d, 0)[0]
        o.update(ldpc=bool(cap & 1), width_40=bool(cap & 2), sgi_20=bool(cap & 0x20),
                 sgi_40=bool(cap & 0x40), forty_intolerant=bool(cap & 0x4000),
                 streams=sum(1 for i in range(4) if d[3 + i]) or 1,
                 max_ampdu_exp=d[2] & 3)
    elif eid == 48:
        o.update(_parse_rsn(d))
    elif eid == 54 and len(d) >= 3:
        o.update(mdid=d[:2].hex(), ft_over_ds=bool(d[2] & 1))
    elif eid == 61 and len(d) >= 2:
        off = d[1] & 3
        o.update(primary_channel=d[0],
                 secondary={1: "above", 3: "below"}.get(off),
                 sta_width_any=bool(d[1] & 4))
        if len(d) >= 3:
            o["protection"] = ["none", "nonmember", "20mhz", "non-ht-mixed"][d[2] & 3]
    elif eid == 70 and len(d) >= 1:
        o.update(link_measurement=bool(d[0] & 1), neighbor_report=bool(d[0] & 2),
                 beacon_passive=bool(d[0] & 0x10), beacon_active=bool(d[0] & 0x20))
    elif eid == 71 and d:
        o["max_bssid_indicator"] = d[0]
    elif eid == 107 and d:
        o.update(access_network_type=d[0] & 0xF, internet=bool(d[0] & 0x10))
    elif eid == 127:
        bit = lambda n: len(d) > n // 8 and bool(d[n // 8] & (1 << (n % 8)))  # noqa: E731
        o.update(bss_transition=bit(19), proxy_arp=bit(12), twt_responder=bit(78),
                 interworking=bit(31), ftm_responder=bit(70))
    elif eid == 133 and len(d) >= 26:
        o["ap_name"] = d[10:26].decode("utf-8", "replace").strip("\x00 ")
    elif eid == 191 and len(d) >= 12:
        cap = struct.unpack_from("<I", d, 0)[0]
        rx = struct.unpack_from("<H", d, 4)[0]
        o.update(streams=_mcs_map_streams(rx) or 1, width_set=(cap >> 2) & 3,
                 sgi_80=bool(cap & 0x20), sgi_160=bool(cap & 0x40),
                 su_beamformer=bool(cap & 0x800), mu_beamformer=bool(cap & 0x80000))
    elif eid == 192 and len(d) >= 3:
        o.update(width_code=d[0], seg0=d[1], seg1=d[2])
    elif eid == 195 and len(d) >= 2:
        o["max_tx_dbm"] = [struct.unpack_from("b", d, i)[0] / 2 for i in range(1, len(d))]
    elif eid == 244 and d:
        o["sae_h2e"] = bool(d[0] & 0x20)
    elif eid == 221 and len(d) >= 4:
        oui, typ, body = d[:3], d[3], d[4:]
        o["oui"] = oui.hex(":")
        o["type"] = typ
        if oui == b"\x00\x50\xf2":
            if typ == 1:
                o["kind"] = "WPA"
                o.update(_parse_rsn(body, wpa1=True))
            elif typ == 2:
                o["kind"] = "WMM"
                if len(body) >= 3:
                    o["uapsd"] = bool(body[2] & 0x80)
            elif typ == 4:
                o["kind"] = "WPS"
                o.update(_parse_wps(body))
            else:
                o["kind"] = "Microsoft"
        elif oui == b"\x50\x6f\x9a":
            o["kind"] = {9: "Wi-Fi Direct (P2P)", 0x10: "Hotspot 2.0", 0x12: "MBO",
                         0x1C: "OWE Transition", 0x16: "Multi-AP"}.get(typ, "Wi-Fi Alliance")
            if typ == 0x1C and len(body) >= 7:
                o["owe_bssid"] = body[:6].hex(":")
                o["owe_ssid"] = body[7:7 + body[6]].decode("utf-8", "replace")
        elif oui == b"\x00\x0b\x86" and typ == 1 and len(body) >= 2 and body[0] == 3:
            o["kind"] = "Aruba"
            o["ap_name"] = body[2:].decode("utf-8", "replace").strip("\x00 ")
        elif oui == b"\x00\x0c\x42" and len(d) >= 30:
            o["kind"] = "MikroTik"
        else:
            o["kind"] = "Vendor"
    elif eid == 255 and ext is not None:
        if ext == 35 and len(d) >= 21:
            phy0 = d[6]
            rx80 = struct.unpack_from("<H", d, 17)[0]
            o.update(streams=_mcs_map_streams(rx80) or 1,
                     width_40_24=bool(phy0 & 0x02), width_80_5=bool(phy0 & 0x04),
                     width_160=bool(phy0 & 0x08), width_80p80=bool(phy0 & 0x10),
                     twt_responder=bool(d[0] & 0x04),
                     su_beamformer=bool(d[9] & 0x80), mu_beamformer=bool(d[10] & 0x02))
        elif ext == 36 and len(d) >= 6:
            params = d[0] | d[1] << 8 | d[2] << 16
            o.update(bss_color=d[3] & 0x3F, bss_color_disabled=bool(d[3] & 0x80),
                     default_pe_duration=params & 7, twt_required=bool(params & 8))
            pos = 6
            if params & 0x4000 and len(d) >= pos + 3:
                o["vht_op"] = {"width_code": d[pos], "seg0": d[pos + 1], "seg1": d[pos + 2]}
                pos += 3
            if params & 0x8000:
                pos += 1
            if params & 0x20000 and len(d) >= pos + 5:
                ctl = d[pos + 1]
                o["six_ghz"] = {"primary_channel": d[pos], "width_code": ctl & 3,
                                "duplicate_beacon": bool(ctl & 4), "reg_info": (ctl >> 3) & 7,
                                "seg0": d[pos + 2], "seg1": d[pos + 3], "min_rate": d[pos + 4]}
        elif ext == 106 and len(d) >= 5:
            o["info_present"] = bool(d[0] & 1)
            if d[0] & 1 and len(d) >= 8:
                o.update(width_code=d[5] & 7, ccfs0=d[6], ccfs1=d[7])
                if d[0] & 2 and len(d) >= 10:
                    o["disabled_subchannels"] = f"{struct.unpack_from('<H', d, 8)[0]:016b}"
        elif ext == 108 and len(d) >= 11:
            phy0 = d[2]
            o.update(width_320=bool(phy0 & 0x02), su_beamformer=bool(phy0 & 0x20))
        elif ext == 107 and len(d) >= 2:
            ctl = struct.unpack_from("<H", d, 0)[0]
            o["ml_type"] = {0: "Basic", 1: "Probe Request", 2: "Reconfiguration"}.get(ctl & 7, str(ctl & 7))
            if ctl & 7 == 0 and len(d) >= 9:
                o["mld_address"] = d[3:9].hex(":")
    return o


def parse_ies(raw: bytes) -> list[dict[str, Any]]:
    """Split a tagged-parameter blob into decoded elements, tolerant of truncation."""
    out = []
    pos = 0
    while pos + 2 <= len(raw):
        eid, ln = raw[pos], raw[pos + 1]
        body = raw[pos + 2:pos + 2 + ln]
        pos += 2 + ln
        ext = None
        data = body
        if eid == 255 and body:
            ext, data = body[0], body[1:]
            name = EXT_NAMES.get(ext, f"Extension {ext}")
        else:
            name = IE_NAMES.get(eid, f"Element {eid}")
        try:
            dec = _decode(eid, ext, data)
        except (struct.error, IndexError, ValueError):
            dec = {"error": "malformed"}
        if eid == 221 and dec.get("kind"):
            name = f"Vendor Specific: {dec['kind']}"
        out.append({"id": eid, "ext": ext, "name": name, "len": ln, "hex": _hex(body), "decoded": dec})
    return out


def _find(ies: list[dict], eid: int, ext: int | None = None, kind: str | None = None) -> dict | None:
    for e in ies:
        if e["id"] == eid and e["ext"] == ext and (kind is None or e["decoded"].get("kind") == kind):
            return e["decoded"]
    return None


def _max_rate(std: str, width: int, streams: int, sgi: bool, legacy: list[float]) -> float:
    if std == "be":
        nsd = {20: 234, 40: 468, 80: 980, 160: 1960, 320: 3920}.get(width, 234)
        return round(nsd * 12 * 5 / 6 * streams / 13.6, 1)
    if std == "ax":
        nsd = {20: 234, 40: 468, 80: 980, 160: 1960}.get(min(width, 160), 234)
        return round(nsd * 10 * 5 / 6 * streams / 13.6, 1)
    if std == "ac":
        w = min(width, 160)
        nsd = {20: 52, 40: 108, 80: 234, 160: 468}.get(w, 52)
        coding = 3 / 4 if w == 20 else 5 / 6
        return round(nsd * 8 * coding * streams / (3.6 if sgi else 4.0), 1)
    if std == "n":
        nsd = 108 if width >= 40 else 52
        return round(nsd * 6 * 5 / 6 * streams / (3.6 if sgi else 4.0), 1)
    return max(legacy) if legacy else 0.0


def summarize(ies: list[dict], freq_mhz: int, capability: int) -> dict[str, Any]:  # noqa: C901
    """Fold decoded elements into a flat network summary."""
    band = channels.band_of(freq_mhz)
    s: dict[str, Any] = {"band": band, "freq": freq_mhz, "channel": channels.freq_to_channel(freq_mhz)}

    ssid = _find(ies, 0)
    s["ssid"] = "" if not ssid or ssid["hidden"] else ssid["ssid"]
    s["hidden"] = not ssid or ssid["hidden"]

    rates: list[float] = []
    basic: list[float] = []
    for eid in (1, 50):
        r = _find(ies, eid)
        if r:
            rates += r["rates"]
            basic += r["basic"]
    s["rates"] = sorted(set(rates))
    s["basic_rates"] = sorted(set(basic))

    ht, htop = _find(ies, 45), _find(ies, 61)
    vht, vhtop = _find(ies, 191), _find(ies, 192)
    he, heop = _find(ies, 255, 35), _find(ies, 255, 36)
    eht, ehtop = _find(ies, 255, 108), _find(ies, 255, 106)

    # ---- standards
    std = []
    if band == "2.4":
        if any(r in (1, 2, 5.5, 11) for r in rates):
            std.append("b")
        if any(r in (6, 9, 12, 18, 24, 36, 48, 54) for r in rates):
            std.append("g")
    elif band == "5":
        std.append("a")
    if ht:
        std.append("n")
    if vht and band == "5":
        std.append("ac")
    if he:
        std.append("ax")
    if eht:
        std.append("be")
    s["standards"] = std
    top = std[-1] if std else ""
    s["generation"] = {"be": "WiFi 7", "ax": "WiFi 6E" if band == "6" else "WiFi 6", "ac": "WiFi 5",
                       "n": "WiFi 4"}.get(top, "Legacy")

    # ---- channel width and centre frequency
    width, center, secondary = 20, freq_mhz, None
    if htop and htop.get("secondary") and band != "6":
        width, secondary = 40, htop["secondary"]
        center = freq_mhz + (10 if secondary == "above" else -10)

    def from_vht(op: dict) -> None:
        nonlocal width, center
        code, s0, s1 = op["width_code"], op["seg0"], op["seg1"]
        if code == 0:
            return
        if code == 2 or (code == 1 and s1 and abs(s1 - s0) == 8):
            width, center = 160, channels.channel_to_freq(s1 if code == 1 else s0, "5")
        elif code == 3 or (code == 1 and s1 and abs(s1 - s0) > 16):
            width, center = 160, channels.channel_to_freq(s0, "5")  # 80+80 shown by primary segment
            s["eighty_plus_eighty"] = True
        else:
            width, center = 80, channels.channel_to_freq(s0, "5")

    if band == "5":
        if vhtop:
            from_vht(vhtop)
        elif heop and heop.get("vht_op"):
            from_vht(heop["vht_op"])
    if band == "6" and heop and heop.get("six_ghz"):
        g = heop["six_ghz"]
        width = [20, 40, 80, 160][g["width_code"]]
        cch = g["seg0"]
        if g["width_code"] == 3 and g["seg1"]:
            cch = g["seg1"]
        center = channels.channel_to_freq(cch, "6") if cch else channels.wide_center(freq_mhz, width, "6")
    if ehtop and "width_code" in ehtop:
        w = {0: 20, 1: 40, 2: 80, 3: 160, 4: 320}.get(ehtop["width_code"], width)
        cch = ehtop["ccfs1"] or ehtop["ccfs0"]
        if w >= width and cch:
            width, center = w, channels.channel_to_freq(cch, band)
    lo, hi = channels.span(center, width)
    s.update(width=width, center_freq=center, secondary=secondary, span_lo=lo, span_hi=hi,
             center_channel=channels.freq_to_channel(center))

    # ---- streams and theoretical max rate
    streams = max([x["streams"] for x in (ht, vht, he) if x and x.get("streams")] or [1])
    sgi = bool((ht and (ht["sgi_20"] or ht["sgi_40"])) or (vht and vht["sgi_80"]))
    s["streams"] = streams
    s["max_rate"] = _max_rate(top, width, streams, sgi, rates)

    # ---- security
    rsn, wpa = _find(ies, 48), _find(ies, 221, kind="WPA")
    privacy = bool(capability & 0x10)
    akm = list(rsn["akm"]) if rsn else []
    pair = list(rsn["pairwise"]) if rsn else []
    if wpa:
        pair += [c for c in wpa["pairwise"] if c not in pair]
    ent = any(a.replace("FT-", "").startswith(("802.1X", "Suite-B")) for a in akm)
    psk = any("PSK" in a for a in akm)
    sae = any("SAE" in a for a in akm)
    owe = "OWE" in akm
    if rsn:
        if owe:
            label = "Enhanced Open (OWE)"
        elif ent:
            wpa3e = any(a in ("Suite-B", "Suite-B-192", "FT-802.1X-SHA384") for a in akm) or \
                (rsn.get("pmf_required") and any("SHA256" in a for a in akm))
            label = "WPA3-Enterprise" if wpa3e else "WPA2-Enterprise"
        elif sae and psk:
            label = "WPA2/WPA3-Personal"
        elif sae:
            label = "WPA3-Personal"
        elif psk:
            label = "WPA/WPA2-Personal" if wpa else "WPA2-Personal"
        else:
            label = "RSN (" + ", ".join(akm) + ")"
    elif wpa:
        label = "WPA-Enterprise" if "802.1X" in wpa["akm"] else "WPA-Personal"
        akm = list(wpa["akm"])
    elif privacy:
        label = "WEP"
    else:
        label = "Open"
    s.update(security=label, akm=akm, ciphers=pair,
             group_cipher=(rsn or wpa or {}).get("group"),
             pmf="required" if rsn and rsn.get("pmf_required") else
             "capable" if rsn and rsn.get("pmf_capable") else "no")

    wps = _find(ies, 221, kind="WPS")
    s["wps"] = bool(wps)
    if wps:
        s["wps_info"] = wps
        s["wps_locked"] = bool(wps.get("ap_setup_locked"))

    # ---- load, uptime-independent extras
    q = _find(ies, 11)
    s["stations"] = q["stations"] if q else None
    s["utilization"] = q["utilization_pct"] if q else None
    c = _find(ies, 7)
    s["country"] = c["country"] if c else None
    t = _find(ies, 35)
    s["tx_power"] = t["tx_power_dbm"] if t else None
    tim = _find(ies, 5)
    s["dtim"] = tim["dtim_period"] if tim else None
    erp = _find(ies, 42)
    s["protection"] = bool(erp and erp["use_protection"])
    s["bss_color"] = heop["bss_color"] if heop else None
    xc = _find(ies, 127) or {}
    s["k"] = bool(_find(ies, 70))
    s["v"] = bool(xc.get("bss_transition"))
    s["r"] = bool(_find(ies, 54)) or any(a.startswith("FT-") for a in akm)
    s["wmm"] = bool(_find(ies, 221, kind="WMM"))
    s["mu_mimo"] = bool((vht and vht["mu_beamformer"]) or (he and he["mu_beamformer"]))
    s["beamforming"] = bool((vht and vht["su_beamformer"]) or (he and he["su_beamformer"]))
    s["twt"] = bool((he and he["twt_responder"]) or xc.get("twt_responder"))
    s["hotspot2"] = bool(_find(ies, 221, kind="Hotspot 2.0"))
    ml = _find(ies, 255, 107)
    s["mlo"] = bool(ml)
    s["mld_address"] = ml.get("mld_address") if ml else None
    name = None
    for e in ies:
        if e["decoded"].get("ap_name"):
            name = e["decoded"]["ap_name"]
    if not name and wps and wps.get("device_name"):
        name = wps["device_name"]
    s["ap_name"] = name
    s["model"] = " ".join(x for x in ((wps or {}).get("manufacturer"), (wps or {}).get("model_name")) if x) or None
    s["ie_ouis"] = sorted({e["decoded"]["oui"] for e in ies if e["id"] == 221 and "oui" in e["decoded"]})
    return s
