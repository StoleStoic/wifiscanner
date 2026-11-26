"""Device discovery on your own network: ping sweep, ARP table, service probes and UPnP announcements."""

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


PROBE_PORTS = [22, 80, 443, 445, 515, 548, 554, 631, 1883, 3389, 5000, 7000, 8009, 8080, 9100, 62078]


def open_ports(ip: str) -> list[int]:
    """Which well-known service ports answer. Used only as evidence of what kind of device it is."""
    out = []

    def one(port: int) -> None:
        try:
            with socket.create_connection((ip, port), timeout=0.6):
                out.append(port)
        except OSError:
            pass

    with ThreadPoolExecutor(len(PROBE_PORTS)) as ex:
        list(ex.map(one, PROBE_PORTS))
    return sorted(out)


def ssdp(wait: float = 2.5) -> dict[str, str]:
    """UPnP discovery: many TVs, speakers, consoles and routers describe themselves when asked."""
    found: dict[str, str] = {}
    msg = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n").encode()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.settimeout(0.4)
        s.sendto(msg, ("239.255.255.250", 1900))
        end = time.time() + wait
        while time.time() < end:
            try:
                data, (ip, _port) = s.recvfrom(2048)
            except socket.timeout:
                continue
            m = re.search(r"^server:\s*(.+?)\s*$", data.decode("utf-8", "replace"), re.I | re.M)
            if m and len(m.group(1)) > len(found.get(ip, "")):
                found[ip] = m.group(1)[:120]
    except OSError:
        pass
    finally:
        s.close()
    return found


def local_mac(ip: str | None) -> str:
    """MAC address of the adapter that holds our own IP (it is never in the ARP table)."""
    if not ip:
        return ""
    if sys.platform == "win32":
        blocks = re.split(r"\r?\n(?=\S)", _run(["ipconfig", "/all"]))
    else:
        blocks = re.split(r"\n(?=\d+: )", _run(["ip", "addr"]))
    for b in blocks:
        if re.search(rf"(?<![\d.]){re.escape(ip)}(?![\d.])", b):
            m = _MAC.search(b)
            if m:
                return oui.norm(m.group(1))
    return ""


# ip, mac, hostname, open ports, access point it uses (simulated only)
DEMO = [("192.168.1.1", "3c:28:6d:a1:10:00", "router.lan", [80, 443], None),
        ("192.168.1.20", "00:12:f0:aa:10:21", "my-laptop", [445, 3389], "3c:28:6d:a1:10:02"),
        ("192.168.1.23", "a4:83:e7:1c:5b:02", "iPhone", [62078], "3c:28:6d:a1:10:03"),
        ("192.168.1.24", "f0:18:98:3c:77:d1", "Living-Room-TV", [7000], "3c:28:6d:a1:22:02"),
        ("192.168.1.31", "50:c7:bf:11:22:33", "kitchen-plug", [80], "3e:28:6d:a1:10:01"),
        ("192.168.1.35", "30:05:5c:9a:41:0e", "BRW30055C9A410E", [80, 631, 9100], "3c:28:6d:a1:22:01"),
        ("192.168.1.40", "24:0a:c4:5e:19:f2", "esp-thermostat", [80], "3e:28:6d:a1:10:01"),
        ("192.168.1.44", "98:da:c4:5b:77:10", "", [80], None),
        ("192.168.1.57", "de:ad:4e:7f:01:9a", "", [], None),
        ("192.168.1.58", "7a:11:c2:04:9b:33", "", [], "98:da:c4:5b:77:11")]
# stations a monitor-mode capture would reveal on other people's access points
DEMO_OTHERS = [("d4:f5:47:10:22:01", "a0:40:a0:5c:11:9e"), ("5c:e9:31:aa:07:14", "a0:40:a0:5c:11:9e"),
               ("b8:27:eb:44:19:c0", "50:c7:bf:3e:8c:2a"), ("f6:02:8d:51:6e:aa", "80:cc:9c:42:d0:12"),
               ("3a:9c:11:d0:44:02", "80:cc:9c:42:d0:11"), ("ac:bc:32:7f:20:99", "02:1a:11:f3:9c:40")]


class IPScanner:
    def __init__(self, store, demo, registry):
        self.store, self.demo, self.registry = store, demo, registry
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
        reg = self.registry
        try:
            self.error, self.progress = None, 0.0
            if self.demo():
                time.sleep(1.2)
                self.network = "192.168.1.0/24 (simulated)"
                for ip, mac, name, ports, ap in DEMO:
                    reg.observe(mac, "lan", save=False, ip=ip, hostname=name, ports=ports, online=True,
                                gateway=ip == "192.168.1.1", this_pc=ip == "192.168.1.20", ap=ap, ap_source="simulated")
                for mac, ap in DEMO_OTHERS:
                    reg.observe(mac, "capture", save=False, ap=ap, ap_source="simulated")
                reg.mark_offline("lan", {d[1] for d in DEMO})
                reg.save()
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
                self.progress = 0.7 * done / len(hosts)

            with ThreadPoolExecutor(64) as ex:
                list(ex.map(probe, hosts))
            arp = {ip: mac for ip, mac in arp_table().items() if ipaddress.ip_address(ip) in net}
            gw = gateway()
            if me and (mine := local_mac(me)):
                arp[me] = mine
            ips = sorted(arp, key=lambda i: tuple(int(x) for x in i.split(".")))
            upnp = ssdp()
            self.progress = 0.8
            with ThreadPoolExecutor(32) as ex:
                names = dict(zip(ips, ex.map(_name, ips)))
                ports = dict(zip(ips, ex.map(open_ports, ips)))
            for ip in ips:
                reg.observe(arp[ip], "lan", save=False, ip=ip, hostname=names.get(ip, ""), ports=ports.get(ip),
                            upnp=upnp.get(ip, ""), online=True, gateway=ip == gw, this_pc=ip == me)
            reg.mark_offline("lan", set(arp.values()))
            reg.save()
        except Exception as e:  # never leave the UI stuck on "scanning"
            self.error = f"Scan failed: {e}"
        finally:
            self.scanned_at = time.time()
            self.running = False
            self.progress = 1.0

    def status(self) -> dict:
        return {"running": self.running, "progress": round(self.progress, 2), "error": self.error,
                "scanned_at": self.scanned_at, "network": self.network}
