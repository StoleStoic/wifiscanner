import { $, h, api, sel, toast } from './util.js';
import { S, on, init, emit, setLoaded } from './state.js';
import * as scan from './scan.js';
import * as charts from './charts.js';
import * as speed from './speed.js';
import * as survey from './survey.js';
import * as threats from './threats.js';
import * as analysis from './analysis.js';
import * as ipscan from './ipscan.js';
import * as sessions from './sessions.js';
import * as settings from './settings.js';
import * as help from './help.js';

const TABS = [
  ['scan', 'Scan', scan], ['spectrum', 'Spectrum', charts.spectrum], ['signal', 'Signal', charts.signal],
  ['threats', 'Threats', threats], ['analysis', 'Analysis', analysis], ['speed', 'Speed Test', speed],
  ['survey', 'Survey', survey], ['ipscan', 'IP Scanner', ipscan], ['sessions', 'Sessions', sessions],
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
  const hi = S.notes.filter(n => n.priority === 'Very High' || n.priority === 'High').length;
  $('#tabs').replaceChildren(...TABS.map(([id, label]) => h('button', { class: S.tab === id ? 'on' : '', onclick: () => go(id) }, label,
    id === 'threats' && alerts ? h('span', { class: 'badge bad' }, alerts) : null,
    id === 'analysis' && hi ? h('span', { class: 'badge poor' }, hi) : null)));
}

function renderStatus() {
  const c = S.conn, st = S.status;
  $('#connbar').replaceChildren(...(c ? [
    h('span', {}, 'Connected ', h('b', {}, c.ssid || '?')), h('span', {}, c.bssid),
    h('span', {}, h('b', {}, `${c.rssi ?? '?'} dBm`)),
    c.channel ? h('span', {}, `${c.band} GHz ch ${c.channel} / ${c.width} MHz`) : null,
    c.rx_rate ? h('span', {}, `↓${c.rx_rate} ↑${c.tx_rate} Mbps link`) : null,
  ] : [h('span', {}, S.offline ? 'Scanner is not running — start it again from the Start menu or the .bat file.' : 'Not connected to WiFi')]));
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
window.addEventListener('resize', () => current?.update?.());

init().then(() => go('scan')).catch(e => { toast('Could not reach the scanner backend: ' + e.message, true); });
