import { $, h, api, sel, toast, setTheme, theme, download } from './util.js';
import { S, on, init, emit, setLoaded } from './state.js';
import * as scan from './scan.js';
import * as charts from './charts.js';
import * as speed from './speed.js';
import * as survey from './survey.js';
import * as threats from './threats.js';
import * as analysis from './analysis.js';
import * as devices from './devices.js';
import * as netmap from './map.js';
import * as sessions from './sessions.js';
import * as settings from './settings.js';
import * as help from './help.js';

const TABS = [
  ['scan', 'Scan', scan], ['spectrum', 'Spectrum', charts.spectrum], ['signal', 'Signal', charts.signal],
  ['threats', 'Threats', threats], ['analysis', 'Analysis', analysis], ['speed', 'Speed Test', speed],
  ['devices', 'Devices', devices], ['map', 'Map', netmap],
  ['survey', 'Survey', survey], ['sessions', 'Sessions', sessions],
  ['settings', 'Settings', settings], ['help', 'Help', help],
];
let current = null;

export function go(tab, arg) {
  S.tab = tab;
  current?.unmount?.();
  const main = $('#main');
  main.className = '';
  main.replaceChildren();
  current = TABS.find(t => t[0] === tab)[2];
  current.mount(main, arg);
  renderTabs();
}
window.sursumGo = go;

function renderTabs() {
  const c = S.threats?.counts || {};
  const alerts = (c.rogue || 0) + (c.accidental || 0) + (c.rogue_client || 0);
  const pendingDev = S.devices.filter(d => d.authorized == null && d.sources.includes('lan')).length;
  const hi = S.notes.filter(n => n.priority === 'Very High' || n.priority === 'High').length;
  $('#tabs').replaceChildren(...TABS.map(([id, label]) => h('button', { class: S.tab === id ? 'on' : '', onclick: () => go(id) }, label,
    id === 'threats' && alerts ? h('span', { class: 'badge bad' }, alerts) : null,
    id === 'analysis' && hi ? h('span', { class: 'badge poor' }, hi) : null,
    id === 'devices' && pendingDev ? h('span', { class: 'badge fair' }, pendingDev) : null)));
}

function renderStatus() {
  const c = S.conn, st = S.status;
  $('#connbar').replaceChildren(...(c ? [
    h('span', {}, 'Connected ', h('b', {}, c.ssid || '?')), h('span', {}, c.bssid),
    h('span', {}, h('b', {}, `${c.rssi ?? '?'} dBm`)),
    c.channel ? h('span', {}, `${c.band} GHz ch ${c.channel} / ${c.width} MHz`) : null,
    c.rx_rate ? h('span', {}, `↓${c.rx_rate} ↑${c.tx_rate} Mbps link`) : null,
  ] : [h('span', {}, S.offline ? 'The scanner has stopped — close this window and start it again from the Start menu.' : 'Not connected to WiFi')]));
  const probes = (S.settings?.probes || []).map(p => ['remote:' + p.name, 'Remote: ' + p.name]);
  $('#scanctl').replaceChildren(
    h('span', { class: 'dim' }, S.loaded ? '' : `${st.count ?? 0} networks · scan ${st.scans ?? 0}`),
    sel([['windows', 'This PC'], ['demo', 'Demo'], ...probes], st.source, async v => { await api('/api/scan', { action: 'source', source: v }); S.history = {}; }, { title: 'Scan source' }),
    h('button', { onclick: () => api('/api/scan', { action: st.paused ? 'resume' : 'pause' }) }, st.paused ? '▶ Resume' : '❚❚ Pause'),
    h('button', { title: 'Forget all networks and start fresh', onclick: async () => { await api('/api/scan', { action: 'clear' }); S.history = {}; } }, 'Clear'));
  const b = $('#banner');
  if (S.loaded) {
    b.hidden = false; b.className = 'info';
    b.replaceChildren(`Viewing saved data: ${S.loaded.name} (${S.loaded.networks.length} networks). `,
      h('button', { class: 'small', onclick: () => setLoaded(null) }, 'Back to live scan'));
  } else if (st.error) { b.hidden = false; b.className = ''; b.textContent = st.error; }
  else if (st.source === 'demo') {
    b.hidden = false; b.className = 'info';
    b.textContent = 'Demo mode: these networks are simulated. Choose "This PC" at the top right to scan with your WiFi adapter.';
  } else b.hidden = true;
}

on('status', renderStatus);
on('view', renderStatus);
on('settings', renderStatus);
on('analysis', renderTabs);
on('data', () => current?.update?.());
on('analysis', () => current?.onAnalysis?.());
on('select', b => current?.onSelect?.(b));
on('devices', () => { current?.onDevices?.(); renderTabs(); });
window.addEventListener('resize', () => current?.update?.());

// ---- commands from the native menu bar (and usable from anywhere in the UI)
const press = async (tab, label) => { go(tab); await new Promise(r => setTimeout(r, 60)); [...document.querySelectorAll('#main button')].find(b => b.textContent.trim().startsWith(label))?.click(); };
function about() {
  const box = h('div', { id: 'about', onclick: e => e.target === box && box.remove() }, h('div', {},
    h('h2', {}, 'Stole Sursum WiFi Scanner'), h('p', {}, `Version ${S.version || ''}`),
    h('p', { class: 'dim' }, 'Personal WiFi scanning, analysis, troubleshooting and threat detection for Windows 11. Everything runs on this PC; nothing leaves it except speed tests and, when you use them, the Claude features.'),
    h('div', { class: 'row', style: 'justify-content:flex-end;margin-top:14px' }, h('button', { class: 'primary', onclick: () => box.remove() }, 'OK'))));
  document.body.append(box);
}
const COMMANDS = {
  'session-save': () => press('sessions', 'Save current scan'), 'session-import': () => press('sessions', 'Import session file'),
  'pcap-open': () => press('sessions', 'Open pcap file'),
  'export-csv': () => download(`wifi-scan-${new Date().toISOString().slice(0, 19).replace(/:/g, '')}.csv`, scan.toDelimited(','), 'text/csv'),
  copy: async () => { await navigator.clipboard.writeText(scan.toDelimited('\t')); toast('Copied. Paste into Excel.'); },
  find: () => { go('scan'); $('#filter')?.focus(); },
  clear: async () => { await api('/api/scan', { action: 'clear' }); S.history = {}; },
  columns: () => press('scan', 'Columns'),
  pause: () => api('/api/scan', { action: 'pause' }), resume: () => api('/api/scan', { action: 'resume' }), rescan: () => api('/api/scan', { action: 'rescan' }),
  'source-windows': () => api('/api/scan', { action: 'source', source: 'windows' }), 'source-demo': () => api('/api/scan', { action: 'source', source: 'demo' }),
  'scan-devices': () => press('devices', 'Scan my network'), 'speedtest': () => press('speed', 'Run speed test'),
  locate: () => (S.selected ? go('threats', { locate: S.selected }) : toast('Select an access point in the Scan tab first.')),
  'ask-claude': () => press('analysis', 'Ask Claude'), identify: () => press('devices', 'Identify'),
  'theme-light': () => { setTheme('light'); go(S.tab); }, 'theme-dark': () => { setTheme('dark'); go(S.tab); },
  'export-analysis': () => press('analysis', 'Export CSV'),
  'help-filters': () => go('help', 'filters'), about,
};
let ready = false; const queued = [];  // menu clicks made before the first data has loaded wait for it
const runCommand = cmd => { try { cmd.startsWith('tab:') ? go(cmd.slice(4)) : COMMANDS[cmd]?.(); } catch (e) { toast(String(e), true); } };
window.sursumMenu = cmd => { if (cmd) ready ? runCommand(cmd) : queued.push(cmd); return ready ? S.tab : 'loading'; };
document.addEventListener('keydown', e => { if (e.ctrlKey && e.key.toLowerCase() === 'f') { e.preventDefault(); COMMANDS.find(); } if (e.ctrlKey && e.key.toLowerCase() === 's') { e.preventDefault(); COMMANDS['session-save'](); } });

let saved = null; try { saved = localStorage.getItem('theme'); } catch { /* storage unavailable */ }
setTheme(saved || 'light');

init().then(() => { go('scan'); ready = true; queued.splice(0).forEach(runCommand); }).catch(e => { toast('Could not reach the scanner backend: ' + e.message, true); });
