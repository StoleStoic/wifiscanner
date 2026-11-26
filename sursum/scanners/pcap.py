"""Read beacons / probe responses out of pcap and pcapng capture files."""

from __future__ import annotations

import struct

from .. import channels, ie, model
from . import ScanError

LINK_80211, LINK_RADIOTAP = 105, 127
# radiotap fields 0..13 as (size, alignment)
_RT = [(8, 8), (1, 1), (1, 1), (4, 2), (2, 2), (1, 1), (1, 1), (2, 2), (2, 2), (2, 2), (1, 1), (1, 1), (1, 1), (1, 1)]


def _radiotap(pkt: bytes) -> tuple[bytes, dict]:
    if len(pkt) < 8:
        return b"", {}
    _ver, _pad, length, present = struct.unpack_from("<BBHI", pkt, 0)
    info: dict = {}
    pos = 8
    p = present
    while p & 0x80000000 and pos + 4 <= len(pkt):  # extended present bitmaps
        p = struct.unpack_from("<I", pkt, pos)[0]
        pos += 4
    fcs = False
    for bit, (size, align) in enumerate(_RT):
        if not present & (1 << bit):
            continue
        pos = (pos + align - 1) & ~(align - 1)
        if pos + size > length:
            break
        if bit == 1:
            fcs = bool(pkt[pos] & 0x10)
        elif bit == 3:
            info["freq"] = struct.unpack_from("<H", pkt, pos)[0]
        elif bit == 5:
            info["rssi"] = struct.unpack_from("b", pkt, pos)[0]
        elif bit == 6:
            info["noise"] = struct.unpack_from("b", pkt, pos)[0]
        pos += size
    frame = pkt[length:]
    return (frame[:-4] if fcs and len(frame) > 4 else frame), info


def _frames(data: bytes):
    """Yield (linktype, timestamp, packet) from pcap or pcapng bytes."""
    if len(data) < 24:
        raise ScanError("File is too short to be a capture.")
    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
        e = "<" if magic[0] in (0xD4, 0x4D) else ">"
        div = 1e9 if magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d") else 1e6
        link = struct.unpack_from(e + "I", data, 20)[0] & 0xFFFF
        pos = 24
        while pos + 16 <= len(data):
            sec, frac, incl, _orig = struct.unpack_from(e + "IIII", data, pos)
            pos += 16
            yield link, sec + frac / div, data[pos:pos + incl]
            pos += incl
    elif magic == b"\x0a\x0d\x0d\x0a":
        e = "<"
        links: list[int] = []
        pos = 0
        while pos + 12 <= len(data):
            btype = struct.unpack_from(e + "I", data, pos)[0]
            if btype == 0x0A0D0D0A:
                e = "<" if data[pos + 8:pos + 12] == b"\x4d\x3c\x2b\x1a" else ">"
                links = []
            blen = struct.unpack_from(e + "I", data, pos + 4)[0]
            if blen < 12 or pos + blen > len(data):
                break
            body = data[pos + 8:pos + blen - 4]
            if btype == 1:
                links.append(struct.unpack_from(e + "H", body, 0)[0])
            elif btype == 6 and len(body) >= 20:
                iface, hi, lo, cap, _orig = struct.unpack_from(e + "IIIII", body, 0)
                if iface < len(links):
                    yield links[iface], ((hi << 32) | lo) / 1e6, body[20:20 + cap]
            elif btype == 3 and links and len(body) >= 4:
                yield links[0], 0.0, body[4:]
            pos += blen
    else:
        raise ScanError("Not a pcap or pcapng file.")


def read(data: bytes) -> tuple[list[dict], dict]:
    nets: dict[str, dict] = {}
    stats = {"packets": 0, "beacons": 0, "unsupported": 0}
    for link, ts, pkt in _frames(data):
        stats["packets"] += 1
        if link == LINK_RADIOTAP:
            frame, info = _radiotap(pkt)
        elif link == LINK_80211:
            frame, info = pkt, {}
        else:
            stats["unsupported"] += 1
            continue
        if len(frame) < 36 or frame[0] not in (0x80, 0x50):  # beacon / probe response
            continue
        stats["beacons"] += 1
        bssid = frame[16:22].hex(":")
        tsf, interval, cap = struct.unpack_from("<QHH", frame, 24)
        raw = frame[36:]
        freq = info.get("freq")
        if not freq:
            ch = 0
            for e in ie.parse_ies(raw):
                if e["id"] == 3 and e["decoded"].get("channel"):
                    ch = e["decoded"]["channel"]
                elif e["id"] == 61 and not ch and e["decoded"].get("primary_channel"):
                    ch = e["decoded"]["primary_channel"]
            freq = channels.channel_to_freq(ch, channels.guess_band_for_channel(ch)) if ch else 0
        if not freq:
            continue
        n = model.build(bssid, info.get("rssi", -100), freq, raw, capability=cap, beacon_interval=interval,
                        tsf_us=tsf, noise=info.get("noise"), last_seen=ts or None)
        old = nets.get(bssid)
        if old:
            n["first_seen"] = old["first_seen"]
            n["seen"] = old["seen"] + 1
            if "rssi" not in info:
                n["rssi"] = old["rssi"]
        nets[bssid] = n
    if stats["packets"] and not stats["beacons"]:
        if stats["unsupported"] == stats["packets"]:
            raise ScanError("This capture is not an 802.11 monitor-mode capture (no radiotap / 802.11 frames).")
        raise ScanError("No beacons or probe responses found in this capture.")
    return list(nets.values()), stats
