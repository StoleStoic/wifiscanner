"""Frequency / channel arithmetic for the 2.4, 5 and 6 GHz bands."""

from __future__ import annotations


def band_of(freq_mhz: int) -> str:
    if 2400 <= freq_mhz <= 2500:
        return "2.4"
    if 4900 <= freq_mhz < 5925:
        return "5"
    if 5925 <= freq_mhz <= 7125:
        return "6"
    return "?"


def freq_to_channel(freq_mhz: int) -> int:
    if freq_mhz == 2484:
        return 14
    if 2400 <= freq_mhz < 2484:
        return (freq_mhz - 2407) // 5
    if 4900 <= freq_mhz < 5925:
        return (freq_mhz - 5000) // 5
    if freq_mhz == 5935:
        return 2
    if 5925 <= freq_mhz <= 7125:
        return (freq_mhz - 5950) // 5
    return 0


def channel_to_freq(channel: int, band: str) -> int:
    if band == "2.4":
        return 2484 if channel == 14 else 2407 + 5 * channel
    if band == "5":
        return 5000 + 5 * channel
    if band == "6":
        return 5935 if channel == 2 else 5950 + 5 * channel
    return 0


def guess_band_for_channel(channel: int) -> str:
    """Best effort when only a channel number is known (pcap without radiotap)."""
    return "2.4" if 1 <= channel <= 14 else "5"


def wide_center(primary_freq: int, width: int, band: str) -> int:
    """Centre frequency of the standard 40/80/160/320 MHz block holding a primary channel.

    Used as a fallback when an AP's operation element does not spell out the centre.
    """
    if width <= 20 or band == "2.4":
        return primary_freq
    if band == "5":
        ch = freq_to_channel(primary_freq)
        base = 36 if ch < 149 else 149
        n = width // 20
        idx = (ch - base) // 4
        block = idx // n
        first = base + block * n * 4
        return channel_to_freq(first, "5") + (width - 20) // 2
    if band == "6":
        ch = freq_to_channel(primary_freq)
        n = width // 20
        idx = (ch - 1) // 4
        block = idx // n
        first = 1 + block * n * 4
        return channel_to_freq(first, "6") + (width - 20) // 2
    return primary_freq


def span(center_freq: int, width: int) -> tuple[float, float]:
    half = width / 2
    return center_freq - half, center_freq + half


def overlaps(a: tuple[float, float], b: tuple[float, float]) -> bool:
    return a[0] < b[1] and b[0] < a[1]
