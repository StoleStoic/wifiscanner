"""LAN device discovery: ping sweep + ARP table, to spot unknown (rogue) clients."""

from __future__ import annotations

import ipaddress
import re
import socket
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from . import oui

_MAC = re.compile(r"([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})")
_IP = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")
_NOWIN = {"creationflags": 0x08000000} if sys.platform == "win32" else {}


def _run(cmd: list[str], timeout: float = 8) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, **_NOWIN).stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""


def local_ip() -> str | None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 9))  # no packet is sent for UDP connect
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()


def gateway() -> str | None:
    if sys.platform == "win32":
        m = re.search(r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)", _run(["route", "print", "-4", "0.0.0.0"]), re.M)
    else:
        m = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", _run(["ip", "route"]))
    return m.group(1) if m else None


def arp_table() -> dict[str, str]:
    out: dict[str, str] = {}
    text = _run(["arp", "-a"]) if sys.platform == "win32" else (_run(["ip", "neigh"]) or _run(["arp", "-an"]))
    for line in text.splitlines():
        ip, mac = _IP.search(line), _MAC.search(line)
        if ip and mac:
            m = oui.norm(mac.group(1))
            if m not in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00") and not m.startswith("01:00:5e"):
                out[ip.group(1)] = m
    return out


def _ping(ip: str) -> bool:
    cmd = ["ping", "-n", "1", "-w", "500", ip] if sys.platform == "win32" else ["ping", "-c", "1", "-W", "1", ip]
    try:
        return subprocess.run(cmd, capture_output=True, timeout=3, **_NOWIN).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _name(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return ""


DEMO = [("192.168.1.1", "3c:28:6d:a1:10:00", "router.lan"), ("192.168.1.20", "f4:5c:89:aa:10:21", "brians-laptop"),
        ("192.168.1.23", "a4:83:e7:1c:5b:02", "iPhone"), ("192.168.1.31", "50:c7:bf:11:22:33", "kitchen-plug"),
        ("192.168.1.44", "3c:28:6d:a1:10:0d", ""), ("192.168.1.57", "de:ad:4e:7f:01:9a", "")]


class IPScanner:
    def __init__(self, store, demo):
        self.store, self.demo = store, demo
        self.devices: list[dict] = []
        self.running = False
        self.progress = 0.0
        self.error: str | None = None
        self.scanned_at = 0.0
        self.network = ""

    def start(self) -> bool:
        if self.running:
            return False
        self.running = True
        threading.Thread(target=self._run, daemon=True, name="ipscan").start()
        return True

    def _run(self) -> None:
        try:
            self.error, self.progress = None, 0.0
            if self.demo():
                time.sleep(1.2)
                self.network = "192.168.1.0/24 (simulated)"
                self.devices = [self._dev(ip, mac, name, ip == "192.168.1.1", ip == "192.168.1.20") for ip, mac, name in DEMO]
                return
            me = local_ip()
            cidr = self.store.settings["ipscan"].get("cidr") or (f"{me}/24" if me else "")
            try:
                net = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                self.error = "Could not determine the local network. Set it in Settings (for example 192.168.1.0/24)."
                return
            if net.num_addresses > 4096:
                self.error = "Network is too large to sweep (limit is 4096 addresses)."
                return
            self.network = str(net)
            hosts = [str(h) for h in net.hosts()]
            done = 0
            alive = set()

            def probe(ip: str) -> None:
                nonlocal done
                if _ping(ip):
                    alive.add(ip)
                done += 1
                self.progress = done / len(hosts)

            with ThreadPoolExecutor(64) as ex:
                list(ex.map(probe, hosts))
            arp = {ip: mac for ip, mac in arp_table().items() if ipaddress.ip_address(ip) in net}
            gw = gateway()
            ips = sorted(set(arp) | alive, key=lambda i: tuple(int(x) for x in i.split(".")))
            with ThreadPoolExecutor(32) as ex:
                names = dict(zip(ips, ex.map(_name, ips)))
            self.devices = [self._dev(ip, arp.get(ip, ""), names.get(ip, ""), ip == gw, ip == me) for ip in ips]
        finally:
            self.scanned_at = time.time()
            self.running = False
            self.progress = 1.0

    def _dev(self, ip: str, mac: str, name: str, is_gw: bool, is_me: bool) -> dict:
        known = {oui.norm(d["mac"]): d.get("label", "") for d in self.store.settings["inventory"]["devices"] if d.get("mac")}
        return {"ip": ip, "mac": mac, "hostname": name, "vendor": oui.vendor(mac) if mac else "",
                "random_mac": oui.is_local(mac) if mac else False, "gateway": is_gw, "self": is_me,
                "known": mac in known or is_me, "label": known.get(mac, "This PC" if is_me else "")}

    def status(self) -> dict:
        known = {oui.norm(d["mac"]): d.get("label", "") for d in self.store.settings["inventory"]["devices"] if d.get("mac")}
        for d in self.devices:  # reflect inventory edits without a rescan
            d["known"] = d["mac"] in known or d["self"]
            d["label"] = known.get(d["mac"], "This PC" if d["self"] else "")
        return {"running": self.running, "progress": round(self.progress, 2), "error": self.error,
                "scanned_at": self.scanned_at, "network": self.network, "devices": self.devices}
