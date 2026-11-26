// Shared application state. Views subscribe with on() and re-render on 'data'.
import { api } from './util.js';
import { compile } from './filter.js';

export const S = {
  live: [], conn: null, status: {}, roams: [], now: 0, settings: null,
  history: {},          // bssid -> [[t, rssi], ...]
  connHistory: [],
  loaded: null,         // {name, networks, history, connection} when viewing a saved session / capture
  selected: null,       // bssid
  filterText: '', filter: () => true, filterError: null,
  threats: null, notes: [], ai: {}, aiRunning: false,
  tab: 'scan',
};
const subs = {};
export const on = (ev, fn) => (subs[ev] ||= []).push(fn);
export const emit = (ev, arg) => (subs[ev] || []).forEach(f => f(arg));

export const nets = () => (S.loaded ? S.loaded.networks : S.live);
export const visible = () => nets().filter(S.filter);
export const hist = b => (S.loaded ? S.loaded.history?.[b] : S.history[b]) || [];
export const th = () => S.settings?.thresholds || { good: -60, fair: -70, poor: -80 };
export const conn = () => (S.loaded ? S.loaded.connection : S.conn);
export const threatOf = b => S.threats?.aps.find(t => t.bssid === b);

export function setFilter(text) {
  S.filterText = text;
  const c = compile(text);
  S.filter = c.fn; S.filterError = c.error || null;
  emit('data');
}
export function select(bssid) { S.selected = bssid; emit('select', bssid); }
export function setLoaded(ds) { S.loaded = ds; S.selected = null; refreshAnalysis(); emit('data'); emit('view'); }

export async function saveSettings(patch) {
  S.settings = await api('/api/settings', patch);
  emit('settings');
  await refreshAnalysis();
}

export async function refreshAnalysis() {
  const a = S.loaded ? await api('/api/analysis', { networks: S.loaded.networks.map(({ ies, ie_hex, ...n }) => n) }) : await api('/api/analysis');
  S.threats = a.threats; S.notes = a.notes; S.ai = a.ai || {}; S.aiRunning = a.ai_running;
  const cls = Object.fromEntries(a.threats.aps.map(t => [t.bssid, t]));
  for (const n of nets()) { n.threat = cls[n.bssid]?.cls; n.distance = cls[n.bssid]?.distance?.m; n._text = undefined; }
  emit('analysis');
}

let tick = 0;
export async function poll() {
  try {
    const d = await api('/api/state');
    const seenBefore = Object.fromEntries(S.live.map(n => [n.bssid, n]));
    S.live = d.networks; S.conn = d.connection; S.status = d.status; S.roams = d.roams; S.now = d.now; S.version = d.version;
    for (const n of S.live) {
      const o = seenBefore[n.bssid];
      n.threat = o?.threat; n.distance = o?.distance;
      const hs = (S.history[n.bssid] ||= []);
      if (!hs.length || hs[hs.length - 1][0] < n.last_seen - 0.5) { hs.push([n.last_seen, n.rssi]); if (hs.length > 300) hs.shift(); }
    }
    if (d.connection) { S.connHistory.push([d.now, d.connection.rssi, d.connection.bssid]); if (S.connHistory.length > 600) S.connHistory.shift(); }
    S.offline = false;
    if (!S.loaded) emit('data');
    emit('status');
    if (tick++ % 3 === 0 && !S.loaded) refreshAnalysis();
  } catch (e) { S.offline = true; emit('status'); }
}

export async function init() {
  S.settings = await api('/api/settings');
  const hd = await api('/api/history');
  S.history = hd.history || {};
  await poll();
  await refreshAnalysis();
  setInterval(poll, 2000);
}
