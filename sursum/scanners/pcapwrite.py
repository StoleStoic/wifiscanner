"""Save scan results as a PCAPNG capture that Wireshark opens.

Each access point becomes one beacon frame rebuilt from what the scan recorded: its
address, capability bits, beacon interval, uptime timestamp and the raw information
elements, wrapped in a radiotap header carrying the channel and signal strength.
"""

from __future__ import annotations

import struct


def _block(btype: int, body: bytes) -> bytes:
    body += b"\x00" * (-len(body) % 4)
    total = len(body) + 12
    return struct.pack("<II", btype, total) + body + struct.pack("<I", total)


def _option(code: int, value: bytes) -> bytes:
    return struct.pack("<HH", code, len(value)) + value + b"\x00" * (-len(value) % 4)


def beacon(n: dict) -> bytes | None:
    try:
        ies = bytes.fromhex(n.get("ie_hex") or "")
        bssid = bytes.fromhex(n["bssid"].replace(":", ""))
    except ValueError:
        return None
    if not ies or len(bssid) != 6:
        return None
    flags = 0x00A0 if n.get("band") == "2.4" else 0x0140  # CCK|2GHz or OFDM|5GHz
    rssi = max(-127, min(0, int(round(n.get("rssi", -100)))))
    # radiotap: present = flags, channel, dBm antenna signal
    rt = struct.pack("<BBHI", 0, 0, 16, (1 << 1) | (1 << 3) | (1 << 5)) + struct.pack("<BxHHbx", 0, int(n["freq"]), flags, rssi)
    hdr = b"\x80\x00\x00\x00" + b"\xff" * 6 + bssid + bssid + b"\x00\x00"
    fixed = struct.pack("<QHH", int((n.get("uptime") or 0) * 1_000_000), int(n.get("beacon_interval") or 100) & 0xFFFF,
                        int(n.get("capability") or 0x0001) & 0xFFFF)
    return rt + hdr + fixed + ies


def write(nets: list[dict], comment: str = "Stole Sursum WiFi Scanner") -> tuple[bytes, int]:
    """Return (pcapng bytes, number of access points written)."""
    out = _block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1) + _option(4, comment.encode()) + _option(0, b""))
    out += _block(1, struct.pack("<HHI", 127, 0, 0) + _option(9, b"\x06") + _option(0, b""))  # radiotap, microseconds
    count = 0
    for n in sorted(nets, key=lambda x: x.get("last_seen") or 0):
        frame = beacon(n)
        if not frame:
            continue
        ts = int((n.get("last_seen") or 0) * 1_000_000)
        out += _block(6, struct.pack("<IIIII", 0, ts >> 32, ts & 0xFFFFFFFF, len(frame), len(frame)) + frame)
        count += 1
    return out, count
