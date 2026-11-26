# Stole Sursum WiFi Scanner

A personal WiFi scanner, analyser, troubleshooter and threat detector for Windows 11.
It runs entirely on your own PC and shows its screens in your web browser.

## Start it

1. Install **Python 3.12 or newer** once, from the Microsoft Store (search "Python") or
   <https://www.python.org/downloads/>.
2. Download this repository (green **Code** button > **Download ZIP**) and unzip it.
3. Double-click **`Start Sursum WiFi Scanner.bat`**. A black window opens and your browser
   shows the scanner. Keep the black window open while you use it; close it to quit.

To look around without a WiFi adapter, double-click **`Start Demo Mode.bat`**: it shows a
simulated neighbourhood that includes an evil twin and a rogue access point.

Every push to GitHub also builds a single-file `SursumWiFiScanner.exe` that needs no
Python: open the repository's **Actions** tab, pick the latest run, and download the
`SursumWiFiScanner-windows` artifact.

**Windows must allow location access**, or it blocks WiFi scanning: Settings > Privacy &
security > Location, switch on *Location services* and *Let desktop apps access your location*.

## First steps

1. **Scan** tab: every access point in range, one row per radio.
2. **Threats** tab: click your own network name. From then on everything else is sorted
   into rogue, unauthorized or neighboring.
3. **Devices** tab: click *Scan my network*, then name each device and mark it authorized or not.
4. **Analysis** tab: read from the top; it lists what to fix first.

## What it does

| Tab | Contents |
| --- | --- |
| Scan | 55 columns per access point (signal, channel, width, vendor, security, stations, AP uptime, …), freeform filter with saved filters, CSV export, copy for Excel, and the raw tagged parameters of each beacon. |
| Spectrum | 2.4, 5 and 6 GHz spectrum with primary channel markers for 20/40/80/160/320 MHz channels; co-channel and adjacent-channel interference charts. |
| Signal | Signal vs. time, and a signal ranking with adjustable thresholds, for any band or the band your PC is on. |
| Threats | Rogue AP, unauthorized AP, rogue client, accidental association and neighbor classification; threat vector map; authorized inventory import/export; a locator that tracks one BSSID so you can walk to it. |
| Analysis | Prioritised notes (Very High to Very Low) on security, connectivity, performance and configuration, each linked to a help article. Optional deeper review by Claude. |
| Speed Test | Single, repeating, or automatic on roaming, with a choice of servers and a room label on each result. |
| Survey | Click-where-you-stand survey on a floor plan image, passive or active, with heatmaps per SSID or BSSID, adjustable colour range, speed tests at points, and estimated access point positions. |
| Devices | Every device seen by any scan, merged into one list: type, maker, addresses, services, the access point it uses, first and last seen. Authorize, name and categorize each one (or many at once); optional identification by Claude. |
| Map | All access points and devices and what is connected to what. Right-click for options. |
| Sessions | Save, reopen, import, download and compare scans; open pcap / pcapng captures. |
| Settings, Help | Scan timing, home perimeter, remote probes, Claude key; filter syntax and articles. |

Supports 802.11 a/b/g/n/ac/ax/be (WiFi 4 to WiFi 7) on 2.4, 5 and 6 GHz.

### Filter syntax

`&` and · `,` or · `!` not · `^` or that binds tighter than `&` · `( )` grouping · `column:text`,
`column=value`, `column>number`.
Example: `5ghz & wpa3 ^ wpa2 , rssi>-60 & !neighbor`. The Help tab has the full list.

### Optional extras

- **Claude analysis**: `py -m pip install anthropic`, then enter an Anthropic API key in Settings.
  Only a summary of the current scan is sent, and only when you press the button.
- **Remote scanning** with a WLAN Pi or any Linux device over SSH: see Help > Remote scanning.

## Limits you should know about

- **Noise and SNR are not available on Windows.** Windows does not expose the noise floor.
  They are shown for remote Linux probes and for capture files that contain them.
- **6 GHz needs a WiFi 6E or WiFi 7 adapter.** The scanner sees only what your adapter receives.
- **Distances are rough.** They come from signal strength alone; a wall can double or halve them.
  A single adapter cannot sense direction, so map directions are real only for access points
  located through a Survey.
- **Rogue detection is evidence, not proof.** "Rogue AP on your network" means a radio address
  matches a device seen on your LAN; "evil twin" means your network name on an unknown radio.
  Confirm by locating the device.
- **It detects access points, not other people's client devices.** Devices on your own network
  are found by the network scan in the Devices tab.
- **Which device uses which access point is mostly not observable from Windows.** The link is known for this PC,
  for devices seen in a monitor-mode capture file, and where you set it yourself. Other devices are shown on
  "My network" with the access point unknown.
- Windows updates signal readings every few seconds, so the locator moves in steps.

## Privacy and safety

The program listens only on `127.0.0.1` (this PC). Settings, sessions and surveys are stored in
`%APPDATA%\StoleSursum`. Nothing leaves the PC except speed tests and, if you use it, Claude analysis.
It only listens to beacons that access points broadcast publicly; it does not join, probe or attack
other networks.

## For developers

```bash
python -m sursum --demo          # run with the simulated environment
```

```bash
python -m unittest discover -s tests
```

Pure Python standard library; `sursum/scanners/windows.py` calls the Windows Native WiFi API
(`wlanapi.dll`) through `ctypes`. The UI in `sursum/web` is plain JavaScript modules with no build step.
