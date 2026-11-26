// Help: getting started, filter syntax, and the support articles linked from analysis notes.
import { h, $ } from './util.js';

export const ARTICLES = {
  'getting-started': { title: 'Getting started', body: ['The Scan tab lists every access point your WiFi adapter can hear. Each row is one radio (BSSID); a mesh or dual-band router appears as several rows with the same name.', 'Open the Threats tab and click your own network name so the scanner knows which access points are yours. Everything else is then sorted into rogue, unauthorized or neighboring.', 'Then read the Analysis tab from the top: it lists what to fix first.'] },
  'rogue-ap': { title: 'Rogue access points and evil twins', body: ['A rogue access point is one you did not set up that is either attached to your own network or pretending to be it. An "evil twin" copies your network name so that phones and laptops join it instead of your real router, letting its owner read or alter traffic.', 'The scanner flags an AP as rogue when it uses your network name from a radio that is not on your authorized list, especially with weaker security, or when its address matches a device seen on your wired network.', 'What to do: do not connect to it. Use Locate (Threats tab) and walk with the laptop until the signal peaks to find the device. If it turns out to be your own equipment, such as a new extender, mark it as Mine.'] },
  'unauthorized-ap': { title: 'Unauthorized access points', body: ['An unknown access point whose signal is strong enough to be inside your home perimeter. It may be a neighbor\'s router close to a shared wall, a visitor\'s phone hotspot, a printer or TV broadcasting its own setup network, or something placed deliberately.', 'Check the vendor and name, then mark it as Neighbor if you recognise it. Printers, streaming sticks and smart plugs often broadcast "DIRECT-" or "setup" networks: switch that feature off in the device.'] },
  'accidental-association': { title: 'Accidental association', body: ['Your PC joined an access point that is not yours, usually because Windows remembered an open network with the same name. Traffic then flows through someone else\'s equipment.', 'In Windows: Settings > Network & internet > WiFi > Manage known networks, and forget networks you do not use. Turn off "Connect automatically" for public networks.'] },
  'rogue-client': { title: 'Unknown devices on your network', body: ['The IP Scanner found a device on your network that you have not marked as known. Most turn out to be your own phones, TVs and smart-home gadgets, so go through the list once and name them.', 'If a device remains unexplained, change your WiFi password (and the router admin password) so that everything must rejoin, and check the router\'s own client list.'] },
  'open-network': { title: 'Open networks', body: ['An open network has no encryption: anyone within range can join, and traffic can be read off the air. Enable WPA3 or WPA2 with a long passphrase. For guests, use the router\'s guest network with its own password.'] },
  'weak-encryption': { title: 'WEP and WPA/TKIP', body: ['WEP can be cracked in minutes with free tools, and the original WPA with TKIP is also broken and limits speed to 54 Mbps. In the router\'s wireless security settings choose "WPA2-Personal (AES)" or "WPA2/WPA3". Devices too old for WPA2 should be replaced or isolated on a separate network.'] },
  wps: { title: 'WiFi Protected Setup (WPS)', body: ['WPS lets devices join with a button press or an 8-digit PIN. The PIN method can be guessed in hours regardless of how strong your password is. Turn WPS off in the router settings; joining by password still works.'] },
  wpa3: { title: 'WPA3', body: ['WPA3 protects against offline password guessing and is required on the 6 GHz band. "WPA2/WPA3 transition" mode lets old and new devices share one network. If an older device stops connecting after the change, switch back or give it a separate WPA2 network.'] },
  pmf: { title: 'Protected Management Frames (802.11w)', body: ['Without PMF, anyone can forge "disconnect" frames and knock your devices off the network, which is also the first step of many password-capture attacks. Set PMF to "capable" (optional) so that modern devices use it and old ones still connect.'] },
  'consistent-config': { title: 'Consistent settings across access points', body: ['Devices roam smoothly only when every access point with the same name uses the same security type, password and basic settings. A mismatch makes devices refuse to roam, or drop the connection as you move.'] },
  'signal-strength': { title: 'Signal strength and SNR', body: ['Signal is measured in dBm; closer to zero is stronger. Around -50 is excellent, -65 is good for video calls, -70 is the practical minimum for reliable use, and below -80 connections drop.', 'What matters for speed is signal above the noise floor (SNR): 25 dB or more allows fast rates, under 15 dB is slow. Note that Windows does not expose noise readings, so SNR is only shown for remote probes and captures.', 'To improve it: move the router higher and more central, away from metal and thick walls, or add a wired access point or mesh node.'] },
  roaming: { title: 'Roaming and sticky clients', body: ['Devices, not access points, decide when to roam, and many hang on to a weak AP long after a stronger one is available. 802.11k and 802.11v let the network suggest better APs, and 802.11r speeds up the switch. Enable them if your system offers the option (sometimes called "fast roaming" or "assisted roaming").', 'Auto speed test on roaming (Speed Test tab) shows whether throughput recovers after each handoff.'] },
  'channel-width': { title: 'Channel width', body: ['Wider channels carry more data but overlap more neighbors and reach less far. In 2.4 GHz always use 20 MHz: 40 MHz covers most of the band. In 5 GHz, 80 MHz suits most homes; drop to 40 MHz in dense apartment blocks. 160 MHz and 320 MHz are for 6 GHz or very quiet 5 GHz environments.'] },
  'channel-planning': { title: 'Choosing channels', body: ['In 2.4 GHz only channels 1, 6 and 11 do not overlap each other. Any other channel interferes with two of them at once. In 5 GHz and 6 GHz, 20 MHz channels do not overlap, so the question is only how many networks share yours.', 'Use the Spectrum tab to find the emptiest slot, and give each of your own access points a different channel.'] },
  interference: { title: 'Co-channel and adjacent-channel interference', body: ['Co-channel: networks on the same channel hear each other and take turns. Capacity is shared, but it works. Adjacent-channel: partly overlapping networks cannot decode each other and simply corrupt each other\'s frames, which is much worse.', 'A strong neighbor on your exact channel is therefore better than one a couple of channels away.'] },
  'channel-utilization': { title: 'Channel utilization', body: ['Some access points report how busy the channel is. Above 50% you will notice slowdowns at peak times; above 75% the channel is saturated. Move to a quieter channel or band, or move heavy users to 5/6 GHz.'] },
  'client-load': { title: 'Clients per access point', body: ['Each radio shares its airtime among all connected devices. More than about 30 active devices on one radio degrades everyone. Spread devices across bands, or add an access point.'] },
  'legacy-rates': { title: 'Legacy 802.11b rates', body: ['Beacons and other housekeeping frames are sent at the lowest "basic" rate. If that is 1 Mbps, they occupy the air about ten times longer than at 12 Mbps. Disabling 802.11b rates (sometimes "minimum rate" or "legacy support") frees airtime; only do so if you own no pre-2005 devices.'] },
  'wifi-generations': { title: 'WiFi generations', body: ['WiFi 4 = 802.11n, WiFi 5 = 802.11ac (5 GHz only), WiFi 6 = 802.11ax, WiFi 6E = 802.11ax on 6 GHz, WiFi 7 = 802.11be with 320 MHz channels and multi-link operation. Your PC can only see and use what its own adapter supports: a WiFi 6E or WiFi 7 adapter is needed to scan 6 GHz.'] },
  'hidden-ssid': { title: 'Hidden network names', body: ['Hiding the SSID does not hide the network: the name is still visible whenever a device connects. It also makes your own devices call out the name wherever they are. Leave the name visible and rely on a strong password.'] },
  bands: { title: '2.4, 5 and 6 GHz', body: ['2.4 GHz reaches furthest but is slow and crowded, with only three usable channels. 5 GHz is much faster with many channels. 6 GHz is the cleanest and fastest but has the shortest range and needs WiFi 6E/7 devices. Use 5 or 6 GHz for anything that matters and leave 2.4 GHz to smart-home gadgets.'] },
};

const SECTIONS = [
  ['filters', 'Filter syntax', [
    'Type in the filter box on the Scan tab. The filter also applies to the Spectrum and Signal tabs.',
    h('table', {}, h('tbody', {}, [
      ['text', 'Rows containing the text anywhere: name, MAC, vendor, security, "5ghz", "ch36", "80mhz", "wifi 6", "802.11ax", "wps", "connected", "rogue", "neighbor"…'],
      ['a & b', 'AND: both must match'], ['a , b', 'OR: either side matches (lowest priority: separates whole alternatives)'],
      ['a ^ b', 'OR that binds tighter than &:  5ghz & wpa3 ^ wpa2  means 5 GHz AND (WPA3 OR WPA2)'],
      ['!a', 'NOT'], ['( … )', 'Grouping'], ['"my, network"', 'Quote text that contains special characters'],
      ['column:text', 'Text within one column, e.g. ssid:home, vendor:netgear, security:wpa3'],
      ['column=value', 'Exact match, e.g. channel=6, band=5, width=80, wps=yes'],
      ['column>n  <  >=  <=  !=', 'Numeric comparison, e.g. rssi>-65, stations>=10, utilization>50, width>=80'],
    ].map(([a, b]) => h('tr', {}, h('td', {}, h('kbd', {}, a)), h('td', { class: 'wrap' }, b))))),
    'Column names: ssid, bssid, vendor, rssi, band, channel, width, generation, standards, security, akm, ciphers, pmf, wps, stations, utilization, uptime, max_rate, cci, aci, snr, noise, threat, distance, country, and every other column key. Short forms: ch, sec, signal, mac, sta, util, bw.',
    'Examples:  rssi>-70 & !neighbor      band=2.4 & channel!=1 & channel!=6 & channel!=11      open , wep , wps=yes      ssid:home & 5ghz ^ 6ghz']],
  ['windows', 'Windows notes and limits', [
    'Location access must be on, or Windows blocks WiFi scanning: Settings > Privacy & security > Location, enable "Location services" and "Let desktop apps access your location".',
    'Windows does not report the noise floor, so Noise and SNR are empty for local scans. They are filled in for remote Linux probes and for pcap files that contain them.',
    'Windows refreshes its list of networks every few seconds and keeps weak networks briefly after they vanish. Signal readings therefore update in steps, not continuously.',
    'Your adapter only reports what it can receive: 6 GHz needs a WiFi 6E or WiFi 7 adapter with current drivers.',
    'The scanner detects access points, not the individual devices connected to other people\'s networks. Devices on your own network are found by the IP Scanner.']],
  ['remote', 'Remote scanning with a WLAN Pi or Linux device', [
    'One-time setup on your PC (PowerShell): run  ssh-keygen -t ed25519  and accept the defaults, then copy the key to the probe:  type $env:USERPROFILE\\.ssh\\id_ed25519.pub | ssh wlanpi@PROBE-IP "mkdir -p .ssh; cat >> .ssh/authorized_keys"',
    'Check that  ssh wlanpi@PROBE-IP "sudo -n iw dev wlan0 scan" | more  prints networks without asking for a password. WLAN Pi allows this out of the box; on other Linux systems allow passwordless sudo for iw, or log in as root and untick "sudo".',
    'Then add the probe in Settings and select it as the scan source at the top right. Remote scans show noise and SNR when the driver provides them, but not the raw tagged parameters.']],
  ['distance', 'Distance and location estimates', [
    'Distances are computed from signal strength alone, assuming a typical transmit power and a wall factor you can tune in Settings. A single wall can change the result by a factor of two, so treat them as "near / next door / far".',
    'A WiFi adapter cannot sense direction. To place access points on a map, do a Survey: the scanner fits each access point\'s position to the signal it measured at every point you clicked, which works reasonably with ten or more points spread through the home.']],
];

export function mount(el, slug) {
  el.append(h('article', {},
    h('h2', {}, 'Help'),
    SECTIONS.map(([id, title, body]) => [h('h3', { id: 'a-' + id }, title), body.map(b => (typeof b === 'string' ? h('p', {}, b) : b))]),
    h('h2', { style: 'margin-top:28px' }, 'Support articles'),
    Object.entries(ARTICLES).map(([id, a]) => [h('h3', { id: 'a-' + id }, a.title), a.body.map(p => h('p', {}, p))])));
  if (slug) setTimeout(() => $('#a-' + slug)?.scrollIntoView(), 0);
}
