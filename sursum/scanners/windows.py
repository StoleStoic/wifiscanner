"""Windows Native WiFi (wlanapi.dll) scanner via ctypes.

Uses WlanScan + WlanGetNetworkBssList, which returns every BSS the adapter
heard together with the raw information elements from its beacon / probe
response - the same bytes a packet capture would show. No driver, admin
rights or monitor mode needed.

Limits imposed by Windows: no noise floor is exposed, and only what the
adapter itself supports is visible (a WiFi 6E/7 adapter is needed for 6 GHz).
Windows 11 also requires Location access to be enabled for WiFi scanning.
"""

from __future__ import annotations

import ctypes
import time
from ctypes import POINTER, Structure, byref, c_ubyte, c_uint8, c_uint16, c_uint32, c_uint64, c_int32, c_void_p, c_wchar

from .. import model
from . import ScanError

# Fixed-width types are used throughout (not wintypes) so that structure sizes
# are identical on every platform and can be unit-tested off Windows.


class GUID(Structure):
    _fields_ = [("Data1", c_uint32), ("Data2", c_uint16), ("Data3", c_uint16), ("Data4", c_ubyte * 8)]

    def __str__(self) -> str:
        d4 = bytes(self.Data4)
        return f"{{{self.Data1:08X}-{self.Data2:04X}-{self.Data3:04X}-{d4[:2].hex().upper()}-{d4[2:].hex().upper()}}}"


class WLAN_INTERFACE_INFO(Structure):
    _fields_ = [("InterfaceGuid", GUID), ("strInterfaceDescription", c_wchar * 256), ("isState", c_uint32)]


class WLAN_INTERFACE_INFO_LIST(Structure):
    _fields_ = [("dwNumberOfItems", c_uint32), ("dwIndex", c_uint32), ("InterfaceInfo", WLAN_INTERFACE_INFO * 1)]


class DOT11_SSID(Structure):
    _fields_ = [("uSSIDLength", c_uint32), ("ucSSID", c_ubyte * 32)]


class WLAN_RATE_SET(Structure):
    _fields_ = [("uRateSetLength", c_uint32), ("usRateSet", c_uint16 * 126)]


class WLAN_BSS_ENTRY(Structure):
    _fields_ = [
        ("dot11Ssid", DOT11_SSID), ("uPhyId", c_uint32), ("dot11Bssid", c_ubyte * 6),
        ("dot11BssType", c_uint32), ("dot11BssPhyType", c_uint32), ("lRssi", c_int32),
        ("uLinkQuality", c_uint32), ("bInRegDomain", c_uint8), ("usBeaconPeriod", c_uint16),
        ("ullTimestamp", c_uint64), ("ullHostTimestamp", c_uint64),
        ("usCapabilityInformation", c_uint16), ("ulChCenterFrequency", c_uint32),
        ("wlanRateSet", WLAN_RATE_SET), ("ulIeOffset", c_uint32), ("ulIeSize", c_uint32),
    ]


class WLAN_BSS_LIST(Structure):
    _fields_ = [("dwTotalSize", c_uint32), ("dwNumberOfItems", c_uint32), ("wlanBssEntries", WLAN_BSS_ENTRY * 1)]


class WLAN_ASSOCIATION_ATTRIBUTES(Structure):
    _fields_ = [("dot11Ssid", DOT11_SSID), ("dot11BssType", c_uint32), ("dot11Bssid", c_ubyte * 6),
                ("dot11PhyType", c_uint32), ("uDot11PhyIndex", c_uint32),
                ("wlanSignalQuality", c_uint32), ("ulRxRate", c_uint32), ("ulTxRate", c_uint32)]


class WLAN_SECURITY_ATTRIBUTES(Structure):
    _fields_ = [("bSecurityEnabled", c_int32), ("bOneXEnabled", c_int32),
                ("dot11AuthAlgorithm", c_uint32), ("dot11CipherAlgorithm", c_uint32)]


class WLAN_CONNECTION_ATTRIBUTES(Structure):
    _fields_ = [("isState", c_uint32), ("wlanConnectionMode", c_uint32), ("strProfileName", c_wchar * 256),
                ("wlanAssociationAttributes", WLAN_ASSOCIATION_ATTRIBUTES),
                ("wlanSecurityAttributes", WLAN_SECURITY_ATTRIBUTES)]


PHY_TYPES = {1: "FHSS", 2: "DSSS", 4: "OFDM (a)", 5: "HR-DSSS (b)", 6: "ERP (g)", 7: "HT (n)",
             8: "VHT (ac)", 9: "DMG (ad)", 10: "HE (ax)", 11: "EHT (be)"}
ERROR_ACCESS_DENIED = 5
WLAN_INTF_OPCODE_CURRENT_CONNECTION = 7
WLAN_INTERFACE_STATE_CONNECTED = 1
FILETIME_EPOCH_DELTA = 11644473600  # seconds between 1601 and 1970


def _filetime_to_unix(ft: int) -> float:
    return ft / 1e7 - FILETIME_EPOCH_DELTA


class WindowsScanner:
    name = "windows"
    label = "This PC (Windows WLAN API)"

    def __init__(self, scan_wait: float = 3.5, interface: str | None = None):
        self.scan_wait = scan_wait
        self.adapter = ""
        self.interface = interface
        try:
            self._api = ctypes.WinDLL("wlanapi.dll")  # type: ignore[attr-defined]
        except (AttributeError, OSError) as e:
            raise ScanError(f"Windows WLAN API unavailable: {e}") from e
        a = self._api
        a.WlanOpenHandle.argtypes = [c_uint32, c_void_p, POINTER(c_uint32), POINTER(c_void_p)]
        a.WlanEnumInterfaces.argtypes = [c_void_p, c_void_p, POINTER(POINTER(WLAN_INTERFACE_INFO_LIST))]
        a.WlanScan.argtypes = [c_void_p, POINTER(GUID), c_void_p, c_void_p, c_void_p]
        a.WlanGetNetworkBssList.argtypes = [c_void_p, POINTER(GUID), c_void_p, c_uint32, c_int32,
                                            c_void_p, POINTER(POINTER(WLAN_BSS_LIST))]
        a.WlanQueryInterface.argtypes = [c_void_p, POINTER(GUID), c_uint32, c_void_p,
                                         POINTER(c_uint32), POINTER(c_void_p), c_void_p]
        a.WlanFreeMemory.argtypes = [c_void_p]
        a.WlanCloseHandle.argtypes = [c_void_p, c_void_p]
        for fn in (a.WlanOpenHandle, a.WlanEnumInterfaces, a.WlanScan, a.WlanGetNetworkBssList,
                   a.WlanQueryInterface, a.WlanCloseHandle):
            fn.restype = c_uint32
        self._handle = c_void_p()
        ver = c_uint32()
        rc = a.WlanOpenHandle(2, None, byref(ver), byref(self._handle))
        if rc:
            raise ScanError(f"WlanOpenHandle failed (error {rc}). Is the WLAN AutoConfig service running?")

    def close(self) -> None:
        if self._handle:
            self._api.WlanCloseHandle(self._handle, None)
            self._handle = c_void_p()

    def interfaces(self) -> list[tuple[GUID, str, int]]:
        plist = POINTER(WLAN_INTERFACE_INFO_LIST)()
        rc = self._api.WlanEnumInterfaces(self._handle, None, byref(plist))
        if rc:
            raise ScanError(f"WlanEnumInterfaces failed (error {rc})")
        try:
            n = plist.contents.dwNumberOfItems
            arr = ctypes.cast(ctypes.addressof(plist.contents.InterfaceInfo),
                              POINTER(WLAN_INTERFACE_INFO * n)).contents
            out = []
            for it in arr:
                g = GUID.from_buffer_copy(bytes(it.InterfaceGuid))
                out.append((g, it.strInterfaceDescription, it.isState))
            return out
        finally:
            self._api.WlanFreeMemory(plist)

    def _pick(self) -> tuple[GUID, str, int]:
        ifs = self.interfaces()
        if not ifs:
            raise ScanError("No WiFi adapter found. Check that WiFi is turned on.")
        if self.interface:
            for i in ifs:
                if self.interface.lower() in i[1].lower() or self.interface.lower() == str(i[0]).lower():
                    return i
        return ifs[0]

    def _connection(self, guid: GUID, desc: str) -> dict | None:
        size = c_uint32()
        pdata = c_void_p()
        rc = self._api.WlanQueryInterface(self._handle, byref(guid), WLAN_INTF_OPCODE_CURRENT_CONNECTION,
                                          None, byref(size), byref(pdata), None)
        if rc or not pdata:
            return None
        try:
            ca = ctypes.cast(pdata, POINTER(WLAN_CONNECTION_ATTRIBUTES)).contents
            if ca.isState != WLAN_INTERFACE_STATE_CONNECTED:
                return None
            aa = ca.wlanAssociationAttributes
            q = aa.wlanSignalQuality
            return {
                "ssid": bytes(aa.dot11Ssid.ucSSID[:aa.dot11Ssid.uSSIDLength]).decode("utf-8", "replace"),
                "bssid": bytes(aa.dot11Bssid).hex(":"),
                "phy": PHY_TYPES.get(aa.dot11PhyType, str(aa.dot11PhyType)),
                "quality": q, "rssi": round(q / 2 - 100, 1),
                "rx_rate": aa.ulRxRate / 1000, "tx_rate": aa.ulTxRate / 1000,
                "profile": ca.strProfileName, "adapter": desc,
            }
        finally:
            self._api.WlanFreeMemory(pdata)

    def scan(self) -> tuple[list[dict], dict | None]:
        guid, desc, _state = self._pick()
        self.adapter = desc
        scan_rc = self._api.WlanScan(self._handle, byref(guid), None, None, None)  # busy is non-fatal
        time.sleep(self.scan_wait)
        plist = POINTER(WLAN_BSS_LIST)()
        rc = self._api.WlanGetNetworkBssList(self._handle, byref(guid), None, 3, 0, None, byref(plist))
        if rc == ERROR_ACCESS_DENIED:
            raise ScanError("Windows denied WiFi scan access. Turn on Settings > Privacy & security > "
                            "Location > 'Location services' and 'Let desktop apps access your location', "
                            "then scanning resumes automatically.")
        if rc:
            raise ScanError(f"WlanGetNetworkBssList failed (error {rc})")
        if scan_rc and not plist.contents.dwNumberOfItems:
            self._api.WlanFreeMemory(plist)
            raise ScanError(f"The WiFi adapter '{desc}' could not scan (Windows error {scan_rc}). Check that WiFi is "
                            "switched on in Windows. It does not need to be connected to a network: scanning works "
                            "while this PC is on Ethernet.")
        nets = []
        try:
            base = ctypes.addressof(plist.contents.wlanBssEntries)
            total = plist.contents.dwTotalSize
            list_addr = ctypes.addressof(plist.contents)
            for i in range(plist.contents.dwNumberOfItems):
                addr = base + i * ctypes.sizeof(WLAN_BSS_ENTRY)
                e = WLAN_BSS_ENTRY.from_address(addr)
                end = (addr - list_addr) + e.ulIeOffset + e.ulIeSize
                raw = ctypes.string_at(addr + e.ulIeOffset, e.ulIeSize) if end <= total else b""
                seen = _filetime_to_unix(e.ullHostTimestamp) if e.ullHostTimestamp else time.time()
                nets.append(model.build(
                    bytes(e.dot11Bssid).hex(":"), e.lRssi, e.ulChCenterFrequency // 1000, raw,
                    capability=e.usCapabilityInformation, beacon_interval=e.usBeaconPeriod,
                    tsf_us=e.ullTimestamp, last_seen=seen,
                    phy=PHY_TYPES.get(e.dot11BssPhyType, str(e.dot11BssPhyType))))
        finally:
            self._api.WlanFreeMemory(plist)
        return nets, self._connection(guid, desc)
