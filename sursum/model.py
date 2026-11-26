"""Builds the flat network record shared by every scan source."""

from __future__ import annotations

import time
from typing import Any

from . import ie, oui

CAP_BITS = [(0x0001, "ESS"), (0x0002, "IBSS"), (0x0010, "Privacy"), (0x0020, "Short Preamble"),
            (0x0100, "Spectrum Mgmt"), (0x0200, "QoS"), (0x0400, "Short Slot"),
            (0x0800, "APSD"), (0x1000, "Radio Measurement")]


def quality(rssi: float) -> int:
    """Map dBm to a 0-100 quality figure (-100 dBm -> 0, -50 dBm -> 100)."""
    return int(max(0, min(100, 2 * (rssi + 100))))


def build(bssid: str, rssi: float, freq_mhz: int, raw_ies: bytes, *, capability: int = 0x0001,
          beacon_interval: int = 100, tsf_us: int | None = None, noise: float | None = None,
          last_seen: float | None = None, phy: str | None = None,
          keep_ies: bool = True) -> dict[str, Any]:
    ies = ie.parse_ies(raw_ies)
    n = ie.summarize(ies, freq_mhz, capability)
    bssid = oui.norm(bssid)
    now = time.time()
    n.update(
        bssid=bssid, rssi=round(rssi, 1), noise=noise,
        snr=round(rssi - noise, 1) if noise is not None else None,
        quality=quality(rssi), vendor=oui.vendor(bssid), local_mac=oui.is_local(bssid),
        beacon_interval=beacon_interval, capability=capability,
        cap_flags=[name for bit, name in CAP_BITS if capability & bit],
        mode="Ad-hoc" if capability & 2 else "Infrastructure",
        uptime=round(tsf_us / 1e6) if tsf_us else None,
        phy=phy, last_seen=last_seen or now, first_seen=last_seen or now,
        connected=False, seen=1,
    )
    if keep_ies:
        n["ies"] = ies
        n["ie_hex"] = raw_ies.hex()
    return n

