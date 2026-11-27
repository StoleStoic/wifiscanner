"""Unit tests (stdlib unittest; also runs under pytest)."""

import ctypes
import struct
import tempfile
import unittest
from pathlib import Path

from sursum import analysis, channels, ie, model, oui
from sursum.engine import interference
from sursum.scanners import ScanError, pcap, remote, simulated
from sursum.scanners import windows as win
from sursum.store import DEFAULTS, Store, _merge


def net(**kw):
    base = dict(ssid="Home", bssid="aa:bb:cc:00:00:01", band="5", channel=44, width=80, std="ax", sec="wpa23")
    base.update(kw)
    freq = channels.channel_to_freq(base["channel"], base["band"])
    cap = 0x0401 | (0x10 if base["sec"] != "open" else 0)
    return model.build(base["bssid"], base.get("rssi", -50), freq, simulated.build_ies(base), capability=cap)


class Channels(unittest.TestCase):
    def test_roundtrip(self):
        for band, chans in (("2.4", [1, 6, 11, 14]), ("5", [36, 64, 100, 165]), ("6", [1, 37, 233])):
            for c in chans:
                f = channels.channel_to_freq(c, band)
                self.assertEqual(channels.band_of(f), band)
                self.assertEqual(channels.freq_to_channel(f), c)

    def test_wide_centres(self):
        self.assertEqual(channels.freq_to_channel(channels.wide_center(5220, 80, "5")), 42)
        self.assertEqual(channels.freq_to_channel(channels.wide_center(5500, 160, "5")), 114)
        self.assertEqual(channels.freq_to_channel(channels.wide_center(5745, 80, "5")), 155)
        self.assertEqual(channels.freq_to_channel(channels.wide_center(6115, 320, "6")), 31)
        self.assertEqual(channels.freq_to_channel(channels.wide_center(6135, 160, "6")), 47)


class Parser(unittest.TestCase):
    def test_widths_and_generations(self):
        cases = [
            (dict(band="2.4", channel=6, width=20, std="g", sec="wep"), 20, 6, "Legacy", "WEP"),
            (dict(band="2.4", channel=3, width=40, std="n", sec="wpa2"), 40, 5, "WiFi 4", "WPA2-Personal"),
            (dict(band="5", channel=44, width=80, std="ac", sec="wpa2"), 80, 42, "WiFi 5", "WPA2-Personal"),
            (dict(band="5", channel=100, width=160, std="ax", sec="wpa23"), 160, 114, "WiFi 6", "WPA2/WPA3-Personal"),
            (dict(band="6", channel=37, width=160, std="ax", sec="wpa3"), 160, 47, "WiFi 6E", "WPA3-Personal"),
            (dict(band="6", channel=33, width=320, std="be", sec="wpa3"), 320, 31, "WiFi 7", "WPA3-Personal"),
            (dict(band="5", channel=149, width=20, std="ax", sec="owe"), 20, 149, "WiFi 6", "Enhanced Open (OWE)"),
            (dict(band="5", channel=157, width=80, std="ac", sec="ent"), 80, 155, "WiFi 5", "WPA2-Enterprise"),
            (dict(band="2.4", channel=1, width=20, std="n", sec="open"), 20, 1, "WiFi 4", "Open"),
            (dict(band="2.4", channel=1, width=20, std="n", sec="wpa-tkip2"), 20, 1, "WiFi 4", "WPA/WPA2-Personal"),
        ]
        for kw, width, centre, gen, sec in cases:
            n = net(**kw)
            self.assertEqual((n["width"], n["center_channel"], n["generation"], n["security"]), (width, centre, gen, sec), kw)
            self.assertEqual(n["span_hi"] - n["span_lo"], width)

    def test_details(self):
        n = net(stations=7, util=40, wps=1, maker="ACME", model="X1", name="Den AP", k=1, v=1, r=1, mu=1, streams=4)
        self.assertEqual(n["stations"], 7)
        self.assertAlmostEqual(n["utilization"], 40, delta=1)
        self.assertTrue(n["wps"] and n["k"] and n["v"] and n["r"] and n["mu_mimo"])
        self.assertEqual((n["streams"], n["ap_name"], n["model"], n["country"], n["pmf"]), (4, "Den AP", "ACME X1", "US", "capable"))
        self.assertEqual(n["max_rate"], 2402.0)  # 4 streams, 80 MHz, HE MCS 11
        names = [e["name"] for e in n["ies"]]
        for want in ("SSID", "Supported Rates", "TIM", "Country", "QBSS Load", "RSN", "HT Capabilities", "HE Operation"):
            self.assertIn(want, names)

    def test_hidden_and_truncated(self):
        self.assertTrue(net(hidden=1)["hidden"])
        raw = simulated.build_ies(dict(ssid="x", band="5", channel=36, std="ax", sec="wpa3"))
        for cut in range(0, len(raw), 7):  # must never raise on a cut-off element stream
            ie.summarize(ie.parse_ies(raw[:cut]), 5180, 0x11)
        ie.parse_ies(bytes(range(256)) * 3)

    def test_vendor(self):
        self.assertIn("NETGEAR", oui.vendor("a0:40:a0:5c:11:9e"))
        self.assertTrue(oui.is_local("02:1a:11:f3:9c:40"))
        self.assertTrue(oui.vendor("02:1a:11:f3:9c:40").startswith("Private"))


class WindowsStructs(unittest.TestCase):
    def test_layout_matches_wlanapi(self):
        e = win.WLAN_BSS_ENTRY
        self.assertEqual(ctypes.sizeof(e), 360)
        self.assertEqual((e.dot11Bssid.offset, e.lRssi.offset, e.ullTimestamp.offset, e.ulChCenterFrequency.offset,
                          e.wlanRateSet.offset, e.ulIeOffset.offset), (40, 56, 72, 92, 96, 352))
        self.assertEqual(win.WLAN_BSS_LIST.wlanBssEntries.offset, 8)
        self.assertEqual(ctypes.sizeof(win.GUID), 16)
        self.assertAlmostEqual(win._filetime_to_unix(116444736000000000), 0)


    def test_scanner_binds_on_windows(self):
        import sys
        if sys.platform != "win32":
            self.skipTest("Windows only")
        try:  # a build machine may have no WLAN service or adapter; anything else is a real bug
            s = win.WindowsScanner(scan_wait=0.1)
            try:
                s.scan()
            finally:
                s.close()
        except ScanError as e:
            print("WLAN not available on this machine:", e)


class Captures(unittest.TestCase):
    def _pcap(self, with_radiotap=True):
        out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 127 if with_radiotap else 105)
        for i, n in enumerate(simulated.NETS[:6]):
            freq = channels.channel_to_freq(n["channel"], n["band"])
            frame = b"\x80\x00\x00\x00" + b"\xff" * 6 + bytes.fromhex(n["bssid"].replace(":", "")) * 2 + b"\x00\x00"
            frame += struct.pack("<QHH", 5_000_000, 100, 0x0411) + simulated.build_ies(n)
            if with_radiotap:  # flags, channel, antenna signal
                rt = struct.pack("<BBHI", 0, 0, 16, (1 << 1) | (1 << 3) | (1 << 5)) + struct.pack("<BxHHb", 0, freq, 0, -40 - i) + b"\x00"
                frame = rt + frame
            out += struct.pack("<IIII", 1000 + i, 0, len(frame), len(frame)) + frame
        return out

    def test_radiotap(self):
        nets, stats = pcap.read(self._pcap())
        self.assertEqual((len(nets), stats["beacons"]), (6, 6))
        by = {n["bssid"]: n for n in nets}
        home6 = by["3c:28:6d:a1:10:03"]
        self.assertEqual((home6["band"], home6["channel"], home6["width"], home6["rssi"]), ("6", 37, 160, -42))

    def test_raw_80211_uses_ds_channel(self):
        nets, _ = pcap.read(self._pcap(with_radiotap=False))
        self.assertIn(("2.4", 1), {(n["band"], n["channel"]) for n in nets})

    def test_rejects_junk(self):
        with self.assertRaises(ScanError):
            pcap.read(b"this is not a capture file at all......")


class Remote(unittest.TestCase):
    def test_command_is_safe(self):
        with self.assertRaises(ScanError):
            remote.RemoteScanner({"host": "pi; rm -rf /", "user": "wlanpi", "iface": "wlan0"})
        cmd = remote.RemoteScanner({"host": "10.0.0.5", "user": "wlanpi", "iface": "wlan0", "port": 2222}).command()
        self.assertEqual(cmd[0], "ssh")
        self.assertIn("BatchMode=yes", cmd)
        self.assertIn("wlanpi@10.0.0.5", cmd)

    def test_survey(self):
        self.assertEqual(remote.parse_survey("Survey data from wlan0\n\tfrequency:\t5220 MHz [in use]\n\tnoise:\t\t-93 dBm\n"), {5220: -93.0})


class Threats(unittest.TestCase):
    def setUp(self):
        s = simulated.SimulatedScanner()
        s.t0 -= 100
        self.nets, self.conn = s.scan()
        interference(self.nets)
        self.settings = _merge(DEFAULTS, {})
        self.settings["inventory"]["aps"] = [{"bssid": n["bssid"], "label": "mine"} for n in self.nets
                                             if n["ssid"] == simulated.HOME and n["security"] != "Open"]
        self.lan = [dict(ip="192.168.1.44", mac="98:da:c4:5b:77:10", known=False, gateway=False, self=False),
                    dict(ip="192.168.1.1", mac="3c:28:6d:a1:10:00", known=False, gateway=True, self=False)]

    def cls(self, **kw):
        t = analysis.classify(self.nets, kw.get("conn", self.conn), self.settings, kw.get("lan", self.lan))
        return t, {a["bssid"]: a for a in t["aps"]}

    def test_classes(self):
        t, by = self.cls()
        self.assertEqual(by["02:1a:11:f3:9c:40"]["label"], "Evil twin / SSID spoof")
        self.assertEqual(by["98:da:c4:5b:77:11"]["label"], "AP attached to your network")
        _, by2 = self.cls(lan=[dict(self.lan[0], authorized=False)])
        self.assertEqual((by2["98:da:c4:5b:77:11"]["label"], by2["98:da:c4:5b:77:11"]["severity"]), ("Rogue AP on your network", "Critical"))
        _, by3 = self.cls(lan=[dict(self.lan[0], known=True, authorized=True, name="Den extender")])
        self.assertEqual(by3["98:da:c4:5b:77:11"]["label"], "Network of your own device")
        self.assertEqual(by["3e:28:6d:a1:10:01"]["cls"], "unauthorized")  # own IoT radio: asks, never "rogue"
        self.assertEqual(by["3c:28:6d:a1:10:02"]["cls"], "authorized")
        self.assertEqual(by["14:91:82:0c:4f:20"]["cls"], "neighbor")
        self.assertEqual([c["ip"] for c in t["clients"]], ["192.168.1.44"])
        self.assertEqual(t["aps"][0]["severity"], "Critical")

    def test_without_lan_scan_extender_is_not_rogue(self):
        _, by = self.cls(lan=[])
        self.assertNotEqual(by["98:da:c4:5b:77:11"]["label"], "AP attached to your network")

    def test_accidental_association(self):
        t, _ = self.cls(conn={"ssid": "xfinitywifi", "bssid": "e6:f0:42:1d:77:b1", "rssi": -70})
        self.assertEqual(t["events"][0]["cls"], "accidental")

    def test_unconfigured(self):
        self.settings["inventory"]["aps"] = []
        t, _ = self.cls()
        self.assertFalse(t["configured"])
        self.assertEqual(set(a["cls"] for a in t["aps"]), {"unclassified"})

    def test_notes(self):
        notes = analysis.notes(self.nets, self.conn, self.settings, self.lan)
        titles = " | ".join(n["title"] for n in notes)
        self.assertIn("Evil twin", titles)
        self.assertEqual(notes[0]["priority"], "Very High")
        self.assertTrue(all(n["category"] in ("Security", "Connectivity", "Performance", "Configuration") for n in notes))

    def test_distance_monotonic(self):
        near = analysis.estimate_distance(dict(rssi=-40, freq=5220, band="5"))
        far = analysis.estimate_distance(dict(rssi=-80, freq=5220, band="5"))
        self.assertLess(near["m"], far["m"])
        self.assertLessEqual(near["min"], near["m"])
        self.assertLessEqual(near["m"], near["max"])


class Storage(unittest.TestCase):
    def test_settings_and_sessions(self):
        with tempfile.TemporaryDirectory() as d:
            st = Store(Path(d))
            st.update_settings({"ai": {"api_key": "secret"}, "scan": {"interval": 9}})
            self.assertEqual(Store(Path(d)).settings["scan"]["interval"], 9)
            pub = st.public_settings()
            self.assertEqual(pub["ai"]["api_key"], "")  # the key is never sent back to the browser
            self.assertTrue(pub["ai"]["has_key"])
            sid = st.save_session("../../evil name", {"networks": [{"bssid": "x"}]})
            self.assertEqual([p.parent.name for p in Path(d).rglob("*evil*")], ["sessions"])
            self.assertEqual(st.get_session(sid)["networks"], [{"bssid": "x"}])
            self.assertIsNone(st.get_session("../settings"))
            st.delete_session(sid)
            self.assertEqual(st.list_sessions(), [])


if __name__ == "__main__":
    unittest.main()


class Devices(unittest.TestCase):
    def setUp(self):
        from sursum.devices import Registry
        self.dir = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.dir.name))
        self.reg = Registry(self.store)

    def tearDown(self):
        self.dir.cleanup()

    def test_type_rules(self):
        from sursum.devices import guess_type
        cases = [(dict(hostname="BRW30055C9A410E", vendor="Brother Industries", ports=[80, 631, 9100]), "Printer"),
                 (dict(hostname="iPhone", vendor="Apple, Inc.", ports=[62078]), "Phone / tablet"),
                 (dict(hostname="Living-Room-TV", vendor="Apple, Inc.", ports=[7000]), "TV / streaming"),
                 (dict(hostname="kitchen-plug", vendor="TP-LINK TECHNOLOGIES CO.,LTD."), "Smart home"),
                 (dict(hostname="", vendor="Espressif Inc."), "Smart home"),
                 (dict(hostname="DESKTOP-4F2K", vendor="Intel Corporate", ports=[445, 3389]), "Computer"),
                 (dict(hostname="", vendor="NETGEAR"), "Network equipment"),
                 (dict(hostname="", vendor="", random_mac=True), "Unknown")]
        for d, want in cases:
            self.assertEqual(guess_type(d)[0], want, d)

    def test_merge_authorize_and_persist(self):
        from sursum.devices import Registry
        r = self.reg
        r.observe("A4-83-E7-1C-5B-02", "lan", ip="192.168.1.23", hostname="iPhone", ports=[62078], online=True)
        r.observe("a4:83:e7:1c:5b:02", "capture", ap="3C:28:6D:A1:10:03", ap_source="capture")
        d = r.list()[0]
        self.assertEqual((len(r.list()), d["type"], d["ap"], d["sources"], d["authorized"]),
                         (1, "Phone / tablet", "3c:28:6d:a1:10:03", ["lan", "capture"], None))
        r.update([d["mac"]], {"authorized": False, "name": "Stranger", "type": "Camera", "ap": "aa:bb:cc:dd:ee:ff"})
        r.observe(d["mac"], "capture", ap="11:22:33:44:55:66")  # a scan must not override what the user set
        d = Registry(self.store).list()[0]
        self.assertEqual((d["authorized"], d["name"], d["type"], d["ap"], d["ap_source"]),
                         (False, "Stranger", "Camera", "aa:bb:cc:dd:ee:ff", "manual"))
        r.observe("3c:28:6d:a1:10:00", "lan", ip="192.168.1.1", gateway=True, online=True)
        r.observe("00:12:f0:aa:10:21", "lan", ip="192.168.1.20", this_pc=True, online=True)
        by = {x["mac"]: x for x in r.lan()}
        self.assertTrue(by["3c:28:6d:a1:10:00"]["known"] and by["00:12:f0:aa:10:21"]["known"])
        self.assertFalse(by["a4:83:e7:1c:5b:02"]["known"])
        self.assertEqual(r.apply_ai([{"mac": "a4:83:e7:1c:5b:02", "type": "Speaker", "confidence": "high", "reason": "x", "likely_model": ""}]), 0)

    def test_threat_levels_follow_authorization(self):
        r = self.reg
        r.observe("de:ad:4e:7f:01:9a", "lan", ip="192.168.1.57", online=True)
        r.observe("a4:83:e7:1c:5b:02", "lan", ip="192.168.1.23", online=True, ap="e6:f0:42:1d:77:b1")
        r.update(["de:ad:4e:7f:01:9a"], {"authorized": False})
        s = simulated.SimulatedScanner()
        nets, conn = s.scan()
        settings = _merge(DEFAULTS, {})
        settings["inventory"]["aps"] = [{"bssid": n["bssid"]} for n in nets if n["ssid"] == simulated.HOME]
        t = analysis.classify(nets, conn, settings, r.lan())
        self.assertEqual({c["mac"]: c["severity"] for c in t["clients"]}, {"de:ad:4e:7f:01:9a": "High", "a4:83:e7:1c:5b:02": "Medium"})
        r.update(["a4:83:e7:1c:5b:02"], {"authorized": True})  # my phone, but on the neighbour's AP
        t = analysis.classify(nets, conn, settings, r.lan())
        self.assertEqual([e["cls"] for e in t["events"]], ["accidental"])

    def test_capture_reveals_station_links(self):
        cap = Captures()._pcap()
        ap = bytes.fromhex("3c286da11002")
        sta = bytes.fromhex("a483e71c5b02")
        for _ in range(3):  # data frames from the station to the AP (ToDS)
            frame = b"\x08\x01\x00\x00" + ap + sta + ap + b"\x00\x00" + bytes(20)
            rt = struct.pack("<BBHI", 0, 0, 16, (1 << 1) | (1 << 3) | (1 << 5)) + struct.pack("<BxHHb", 0, 5220, 0, -61) + b"\x00"
            cap += struct.pack("<IIII", 2000, 0, len(rt + frame), len(rt + frame)) + rt + frame
        bogus = b"\x08\x01\x00\x00" + bytes.fromhex("001122334455") + sta + bytes(8) + bytes(20)  # AP never beaconed
        cap += struct.pack("<IIII", 2001, 0, len(bogus), len(bogus)) + bogus
        _, stats = pcap.read(cap)
        self.assertEqual([(s["mac"], s["bssid"], s["frames"], s["rssi"]) for s in stats["stations"]],
                         [("a4:83:e7:1c:5b:02", "3c:28:6d:a1:10:02", 3, -61)])


class RealHome(unittest.TestCase):
    """Address patterns taken from a real multi-AP home scan."""

    def test_same_unit(self):
        yes = [("e8:9c:25:00:1a:40", "e8:9c:25:00:1a:48"), ("74:ac:b9:27:52:30", "7a:ac:b9:27:52:30"),
               ("74:ac:b9:27:52:30", "82:ac:b9:28:52:30"), ("d0:21:f9:86:60:dd", "d2:21:f9:b6:60:de"),
               ("cc:28:aa:5e:a6:52", "cc:28:aa:5e:a6:55"), ("0c:7c:28:97:89:ec", "0c:7c:28:97:89:f4"),
               ("e4:38:83:49:dd:6e", "e6:38:83:19:dd:6f")]
        no = [("10:7c:61:50:76:c0", "10:7c:61:50:77:80"), ("74:ac:b9:27:52:30", "74:83:c2:bd:7b:2b"),
              ("0c:7c:28:97:89:ec", "0c:7c:28:d2:cb:d8"), ("e8:9c:25:00:1a:40", "cc:28:aa:5e:a6:52")]
        for a, b in yes:
            self.assertTrue(oui.same_unit(a, b), (a, b))
        for a, b in no:
            self.assertFalse(oui.same_unit(a, b), (a, b))

    def test_own_mesh_is_not_called_rogue(self):
        def ap(bssid, ssid, sec="wpa2", band="5", channel=44, hidden=0, rssi=-60):
            return net(bssid=bssid, ssid=ssid, sec=sec, band=band, channel=channel, hidden=hidden, rssi=rssi,
                       width=20 if band == "2.4" else 80, std="ax")
        nets = [ap("e8:9c:25:00:1a:40", "Caveat", band="2.4", channel=11), ap("e8:9c:25:00:1a:44", "Caveat"),
                ap("cc:28:aa:5e:a6:55", "private"), ap("10:7c:61:50:76:c4", "private"),
                ap("10:7c:61:50:77:84", "ASUS", sec="open"),
                ap("74:ac:b9:27:52:30", "vcissgroup", band="2.4", channel=1), ap("7a:ac:b9:27:52:30", "", hidden=1, band="2.4", channel=1),
                ap("bc:07:1d:2d:dc:c7", "Grinnfamily", rssi=-85)]
        interference(nets)
        s = _merge(DEFAULTS, {})
        s["home"]["ssids"] = ["Caveat", "private", "ASUS", "vcissgroup"]
        s["inventory"]["aps"] = [{"bssid": "e8:9c:25:00:1a:40"}, {"bssid": "74:ac:b9:27:52:30"}]
        by = {t["bssid"]: t for t in analysis.classify(nets, None, s, [])["aps"]}
        self.assertEqual(by["e8:9c:25:00:1a:44"]["label"], "Unlisted radio of your AP")       # other band, same unit
        self.assertEqual(by["7a:ac:b9:27:52:30"]["label"], "Unlisted radio of your AP")       # hidden virtual network
        self.assertEqual((by["cc:28:aa:5e:a6:55"]["cls"], by["cc:28:aa:5e:a6:55"]["severity"]), ("unauthorized", "High"))
        self.assertEqual(by["10:7c:61:50:77:84"]["label"], "Unprotected AP using your network name")
        self.assertEqual(by["bc:07:1d:2d:dc:c7"]["cls"], "neighbor")
        self.assertEqual([t["bssid"] for t in by.values() if t["label"] == "Evil twin / SSID spoof"], [])
        far = analysis.estimate_distance(dict(rssi=-79, freq=5300, band="5", tx_power=127))
        self.assertLess(far["m"], 200)  # a nonsense transmit-power report must not blow up the estimate


class RouterList(unittest.TestCase):
    SAMPLE = """MAC Address\t00:d2:b1:56:83:d2
IPv4 Address / Name\t192.168.1.243 / amazon-bf873151a
Last Activity\tThu Nov 26 18:54:30 2026
Status\ton
Allocation\tdhcp
Connection Type\tEthernet LAN-2
Connection Speed\t1000Mbps fullduplex
Mesh Client\tNo
IPv6 Address\tfe80::2d2:b1ff:fe56:83d2
Type\tslaac
Valid Lifetime\tforever
MAC Address\t38:a5:c9:4e:d0:8e
IPv4 Address / Name\t192.168.1.233 / unknown38a5c94ed08e
Last Activity\tThu Nov 26 18:54:30 2026
Status\ton
Allocation\tdhcp
Connection Type\tWi-Fi Wi-Fi 5 bars  
2.4 GHz
Type: Guest
Name: GuestNet
Connection Speed
Mesh Client\tNo
MAC Address\t84:e6:57:0e:16:51
Name\tPS5
Last Activity\tTue Nov 17 02:30:44 2026
Status\toff
Allocation\tdhcp
Connection Type\tWi-Fi
5 GHz Radio-2
Type: Home
Name: HomeNet
Connection Speed
Mesh Client\tNo
"""

    def test_parse_pasted_and_html(self):
        from sursum import routerlist
        for text in (self.SAMPLE, self.SAMPLE.replace("\t", "   "),
                     routerlist.html_to_text("<table>" + "".join(
                         f"<tr><th>{a}</th><td>{b}</td></tr>" if b or "\t" in ln else f"<tr><td>{a}</td></tr>"
                         for ln in self.SAMPLE.splitlines() for a, _, b in [ln.partition("\t")]) + "</table>")):
            d = routerlist.parse(text)
            self.assertEqual([x["mac"] for x in d], ["00:d2:b1:56:83:d2", "38:a5:c9:4e:d0:8e", "84:e6:57:0e:16:51"], text[:60])
            self.assertEqual((d[0]["ip"], d[0]["name"], d[0]["online"], d[0]["link"], d[0]["port"]),
                             ("192.168.1.243", "amazon-bf873151a", True, "ethernet", "LAN-2"))
            self.assertEqual((d[1]["name"], d[1]["link"], d[1]["band"], d[1]["ssid"], d[1]["net_type"]), ("", "wifi", "2.4", "GuestNet", "Guest"))
            self.assertEqual((d[2]["name"], d[2]["online"], d[2]["band"], d[2]["ssid"]), ("PS5", False, "5", "HomeNet"))
            self.assertLess(d[2]["seen"], d[0]["seen"])

    def test_resolve_gateway_radio(self):
        from sursum import routerlist
        nets = [dict(bssid="0c:7c:28:97:89:ec", ssid="HomeNet", band="2.4"), dict(bssid="0c:7c:28:97:89:ed", ssid="GuestNet", band="2.4"),
                dict(bssid="74:ac:b9:27:52:30", ssid="GuestNet", band="2.4"),  # another AP with the guest name
                dict(bssid="0c:7c:28:97:89:f4", ssid="HomeNet", band="5"), dict(bssid="0c:7c:28:97:89:f0", ssid="HomeNet", band="5")]
        d = routerlist.parse(self.SAMPLE)
        self.assertEqual(routerlist.resolve_ap(d[1], nets, {"HomeNet"}), "0c:7c:28:97:89:ed")
        self.assertIsNone(routerlist.resolve_ap(d[2], nets, {"HomeNet"}))   # two 5 GHz radios: not guessed
        self.assertIsNone(routerlist.resolve_ap(d[0], nets, {"HomeNet"}))

    def test_names_from_a_real_list(self):
        from sursum.devices import guess_type
        for host, vendor, want in [("32OnnRokuTV", "", "TV / streaming"), ("Amazon Fire TV", "Amazon", "TV / streaming"),
                                   ("GoogleTV8513", "", "TV / streaming"), ("Hopper3-br", "Dish Technologies Corp", "TV / streaming"),
                                   ("Joey_AP", "Dish Technologies Corp", "Network equipment"), ("HL_CAM4-80482CE03C12", "", "Camera"),
                                   ("Canon22b25c", "CANON INC.", "Printer"), ("Sony PlayStation 4", "", "Game console"), ("PS5", "", "Game console"),
                                   ("kindle-a0f006932", "", "Phone / tablet"), ("My-Info-s-Z-Fold8", "", "Phone / tablet"),
                                   ("DESKTOP-IK9VS3F", "", "Computer"), ("chromeos", "", "Computer"), ("ZenWiFi_XT8-7780", "", "Network equipment"),
                                   ("APNanoLivingRoom", "Ubiquiti Inc", "Network equipment")]:
            self.assertEqual(guess_type(dict(hostname=host, vendor=vendor))[0], want, host)


class PcapngExport(unittest.TestCase):
    def test_written_capture_reads_back_identically(self):
        from sursum.scanners import pcapwrite
        s = simulated.SimulatedScanner()
        s.t0 -= 100
        nets, _ = s.scan()
        blob, count = pcapwrite.write(nets)
        self.assertEqual(count, len(nets))
        self.assertEqual(blob[:4], b"\n\r\r\n")
        back, stats = pcap.read(blob)
        self.assertEqual(stats["beacons"], len(nets))
        a, b = {n["bssid"]: n for n in nets}, {n["bssid"]: n for n in back}
        self.assertEqual(set(a), set(b))
        for k in a:
            for f in ("ssid", "channel", "band", "width", "security", "generation", "ie_hex", "beacon_interval"):
                self.assertEqual(a[k][f], b[k][f], (k, f))
            self.assertEqual(round(a[k]["rssi"]), b[k]["rssi"])
        self.assertEqual(pcapwrite.write([{"bssid": "aa:bb:cc:dd:ee:ff", "ie_hex": ""}])[1], 0)  # nothing to rebuild from


class Monitoring(unittest.TestCase):
    def setUp(self):
        from sursum.devices import Registry
        from sursum.monitor import Monitor
        self.dir = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.dir.name))
        self.store.settings["monitor"]["enabled"] = False  # drive cycles by hand
        self.reg = Registry(self.store)
        self.reg.observe("aa:aa:aa:00:00:01", "lan", ip="10.0.0.5", hostname="tv", online=True)
        self.mon = Monitor(self.store, self.reg, lambda: False)

    def tearDown(self):
        self.dir.cleanup()

    def run_cycles(self, replies):
        import sursum.monitor as m
        real = m.ping
        try:
            for r in replies:
                m.ping = lambda ip, timeout_ms=1000, r=r: r.get(ip, 20.0)
                self.mon._cycle()
        finally:
            m.ping = real

    def test_down_up_slow_events_and_stats(self):
        self.run_cycles([{}] * 3)
        t = next(x for x in self.mon.status()["targets"] if x["ip"] == "10.0.0.5")
        self.assertEqual((t["up"], t["loss"], t["avg"], t["uptime"]), (True, 0.0, 20.0, 100.0))
        self.run_cycles([{"10.0.0.5": None}] * 2)
        self.assertEqual([e["kind"] for e in self.mon.status()["events"]], [])        # two misses: not down yet
        self.run_cycles([{"10.0.0.5": None}])
        self.run_cycles([{"10.0.0.5": 400.0}, {}])
        self.assertEqual([e["kind"] for e in self.mon.status()["events"]], ["down", "up", "slow"])
        st = self.mon.status("aa:aa:aa:00:00:01")
        t = next(x for x in st["targets"] if x["ip"] == "10.0.0.5")
        self.assertEqual((t["up"], t["samples"], len(st["detail"]["history"])), (True, 8, 8))
        self.assertAlmostEqual(t["loss"], 37.5)
        self.assertEqual({x["kind"] for x in st["targets"]}, {"device", "internet"})

    def test_never_reachable_target_raises_no_alarm(self):
        self.run_cycles([{"10.0.0.5": None}] * 5)
        self.assertEqual(self.mon.status()["events"], [])

    def test_ping_parsing(self):
        import sursum.monitor as m
        self.assertEqual(float(m._TIME.search("Reply from 1.1.1.1: bytes=32 time=14ms TTL=57").group(1)), 14)
        self.assertEqual(float(m._TIME.search("Reply from 192.168.1.1: bytes=32 time<1ms TTL=64").group(1)), 1)
        self.assertEqual(float(m._TIME.search("64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=0.512 ms").group(1)), 0.512)
