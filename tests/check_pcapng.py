"""Write a scan as PCAPNG and confirm Wireshark's reader (tshark) sees every access point in it."""
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from sursum.scanners import pcapwrite, simulated  # noqa: E402

s = simulated.SimulatedScanner()
s.t0 -= 100
nets, _ = s.scan()
path = Path(tempfile.mkdtemp()) / "scan.pcapng"
path.write_bytes(pcapwrite.write(nets)[0])
r = subprocess.run(["tshark", "-r", str(path), "-T", "fields", "-e", "wlan.bssid", "-e", "radiotap.channel.freq",
                    "-e", "radiotap.dbm_antsignal"], capture_output=True, text=True)
rows = [ln.split("\t") for ln in r.stdout.splitlines() if ln.strip()]
print(f"tshark exit {r.returncode}, {len(rows)} frames read, {len(nets)} written")
print(r.stderr[-800:])
want = {(n["bssid"], str(n["freq"]), str(round(n["rssi"]))) for n in nets}
got = {(b, f, sig) for b, f, sig in (row[:3] for row in rows if len(row) >= 3)}
missing = want - got
if missing:
    print("missing or different:", sorted(missing)[:5], "| sample read:", rows[:3])
    sys.exit(1)
print("Every access point was read back by Wireshark with the right address, channel and signal.")
