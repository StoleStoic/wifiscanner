// Scan view: sortable network table, freeform filter, export, and the SSID details panel.
import { $, h, api, color, sigClass, SIG, duration, clock, download, toast, esc, menu } from './util.js';
import { mark } from './threats.js';
import { S, nets, visible, th, setFilter, select, saveSettings, hist } from './state.js';
import { drawSpectrum, spectrumClick, quickBar } from './charts.js';

const yes = v => (v ? 'Yes' : '');
const list = v => (v || []).join(', ');
export const COLS = [
  { k: 'ssid', l: 'SSID', d: 1, f: n => n.ssid || '(hidden)' },
  { k: 'bssid', l: 'BSSID (MAC)', d: 1 },
  { k: 'vendor', l: 'Vendor', d: 1 },
  { k: 'rssi', l: 'Signal dBm', d: 1, n: 1 },
  { k: 'band', l: 'Band', d: 1, f: n => n.band + ' GHz' },
  { k: 'channel', l: 'Channel', d: 1, n: 1 },
  { k: 'width', l: 'Width MHz', d: 1, n: 1 },
  { k: 'generation', l: 'WiFi', d: 1 },
  { k: 'security', l: 'Security', d: 1 },
  { k: 'threat', l: 'Class', d: 1 },
  { k: 'note', l: 'Note', d: 1 },
  { k: 'stations', l: 'Stations', d: 1, n: 1 },
  { k: 'utilization', l: 'Ch. util %', d: 1, n: 1 },
  { k: 'uptime', l: 'AP uptime', d: 1, n: 1, f: n => duration(n.uptime) },
  { k: 'max_rate', l: 'Max rate Mbps', d: 1, n: 1 },
  { k: 'cci', l: 'Co-ch', d: 1, n: 1 }, { k: 'aci', l: 'Adj-ch', d: 1, n: 1 },
  { k: 'noise', l: 'Noise dBm', n: 1 }, { k: 'snr', l: 'SNR dB', n: 1 }, { k: 'quality', l: 'Quality %', n: 1 },
  { k: 'distance', l: 'Est. dist m', n: 1 },
  { k: 'ap_name', l: 'AP name' }, { k: 'model', l: 'Model' },
  { k: 'center_channel', l: 'Centre ch', n: 1 }, { k: 'freq', l: 'Freq MHz', n: 1 }, { k: 'center_freq', l: 'Centre MHz', n: 1 },
  { k: 'secondary', l: 'Secondary ch' },
  { k: 'standards', l: '802.11', f: n => list(n.standards) },
  { k: 'streams', l: 'Streams', n: 1 },
  { k: 'akm', l: 'Auth (AKM)', f: n => list(n.akm) }, { k: 'ciphers', l: 'Ciphers', f: n => list(n.ciphers) },
  { k: 'pmf', l: 'PMF' }, { k: 'wps', l: 'WPS', f: n => yes(n.wps) },
  { k: 'basic_rates', l: 'Basic rates', f: n => list(n.basic_rates) }, { k: 'rates', l: 'Rates', f: n => list(n.rates) },
  { k: 'beacon_interval', l: 'Beacon TU', n: 1 }, { k: 'dtim', l: 'DTIM', n: 1 },
  { k: 'country', l: 'Country' }, { k: 'tx_power', l: 'Tx power dBm', n: 1 }, { k: 'bss_color', l: 'BSS color', n: 1 },
  { k: 'k', l: '11k', f: n => yes(n.k) }, { k: 'v', l: '11v', f: n => yes(n.v) }, { k: 'r', l: '11r', f: n => yes(n.r) },
  { k: 'wmm', l: 'WMM', f: n => yes(n.wmm) }, { k: 'mu_mimo', l: 'MU-MIMO', f: n => yes(n.mu_mimo) },
  { k: 'beamforming', l: 'Beamforming', f: n => yes(n.beamforming) }, { k: 'twt', l: 'TWT', f: n => yes(n.twt) },
  { k: 'mlo', l: 'MLO', f: n => yes(n.mlo) }, { k: 'hotspot2', l: 'Hotspot 2.0', f: n => yes(n.hotspot2) },
  { k: 'mode', l: 'Mode' }, { k: 'rssi_max', l: 'Max dBm', n: 1 }, { k: 'rssi_min', l: 'Min dBm', n: 1 },
  { k: 'first_seen', l: 'First seen', n: 1, f: n => clock(n.first_seen) },
  { k: 'last_seen', l: 'Last seen', n: 1, f: n => clock(n.last_seen) }, { k: 'seen', l: 'Times seen', n: 1 },
];
const CLASS = { authorized: ['Mine', 'good'], rogue: ['ROGUE', 'bad'], unauthorized: ['Unauthorized', 'poor'],
  neighbor: ['Neighbor', 'info'], unclassified: ['—', ''] };
const text = (c, n) => (c.f ? c.f(n) : n[c.k] ?? '');
let sort = { k: 'rssi', dir: -1 }, root, shown = null;

const active = () => { const want = S.settings?.columns?.length ? S.settings.columns : COLS.filter(c => c.d).map(c => c.k); return COLS.filter(c => want.includes(c.k)); };

export function rows() {
  const c = COLS.find(x => x.k === sort.k) || COLS[0];
  return visible().sort((a, b) => {
    const x = a[c.k], y = b[c.k];
    if (x == null && y == null) return 0; if (x == null) return 1; if (y == null) return -1;
    return (typeof x === 'number' ? x - y : String(x).localeCompare(String(y))) * sort.dir;
  });
}
export function toDelimited(sep) {
  const cols = active(), q = v => { v = String(v); return sep === ',' && /[",\n]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v; };
  return [cols.map(c => q(c.l)).join(sep), ...rows().map(n => cols.map(c => q(text(c, n))).join(sep))].join('\r\n');
}

export function mount(el) {
  root = el; el.className = 'fill';
  const input = h('input', { type: 'text', id: 'filter', value: S.filterText, spellcheck: 'false',
    placeholder: 'Filter, e.g.  5ghz & wpa3 ^ wpa2 , rssi>-60 & !neighbor      (& and   , or   ! not   ^ or-within-and)',
    oninput: e => setFilter(e.target.value) });
  const saved = () => h('select', { onchange: e => { if (e.target.value) { input.value = e.target.value; setFilter(e.target.value); } e.target.selectedIndex = 0; } },
    h('option', { value: '' }, 'Saved filters…'), (S.settings.filters || []).map(f => h('option', { value: f.expr }, f.name)));
  const bar = h('div', { class: 'filterbar' }, input, h('span', { id: 'savedf' }, saved()),
    h('button', { title: 'Save the current filter for quick recall', onclick: async () => {
      if (!S.filterText.trim()) return toast('Type a filter first.');
      const name = prompt('Name for this filter:', S.filterText); if (!name) return;
      await saveSettings({ filters: [...S.settings.filters.filter(f => f.name !== name), { name, expr: S.filterText }] });
      $('#savedf').replaceChildren(saved()); toast('Filter saved.');
    } }, 'Save filter'),
    h('button', { title: 'Delete a saved filter', onclick: async () => {
      const name = prompt('Delete which saved filter?\n' + S.settings.filters.map(f => '• ' + f.name).join('\n')); if (!name) return;
      await saveSettings({ filters: S.settings.filters.filter(f => f.name !== name) }); $('#savedf').replaceChildren(saved());
    } }, '✕'),
    h('button', { onclick: e => columnMenu(e.target) }, 'Columns'),
    h('button', { title: 'Copy the table so it pastes straight into Excel', onclick: async () => { await navigator.clipboard.writeText(toDelimited('\t')); toast('Copied. Paste into Excel.'); } }, 'Copy for Excel'),
    h('button', { onclick: () => download(`wifi-scan-${new Date().toISOString().slice(0, 19).replace(/:/g, '')}.csv`, toDelimited(','), 'text/csv') }, 'Export CSV'),
    h('button', { title: 'Save the networks shown as a capture file that Wireshark opens', onclick: savePcapng }, 'Save PCAPNG'),
    h('span', { id: 'fcount', class: 'dim' }));
  const top = h('div', { class: 'tablewrap', id: 'scantop', style: `flex:0 0 ${split}%` }, h('table', { id: 'nettable' }));
  // drag the divider to give the table or the lower pane more room
  const divider = h('div', { class: 'divider', title: 'Drag to resize', onpointerdown: e => {
    const box = el.querySelector('.split').getBoundingClientRect(), move = m => { split = Math.max(15, Math.min(80, (m.clientY - box.top) / box.height * 100)); top.style.flex = `0 0 ${split}%`; update(); };
    e.target.setPointerCapture(e.pointerId); e.target.onpointermove = move; e.target.onpointerup = () => { e.target.onpointermove = null; try { localStorage.setItem('split', split); } catch { /* ignore */ } };
  } });
  el.append(h('div', { class: 'filterbar', id: 'scanquick' }), bar,
    h('div', { class: 'split' }, top, divider,
      h('div', { class: 'pane' }, h('div', { class: 'panetabs', id: 'panetabs' }),
        h('div', { class: 'panebody' }, h('canvas', { id: 'scanspec', onclick: spectrumClick }), h('div', { id: 'details' })))),
    h('div', { class: 'statusbar', id: 'scanstatus' }));
  update(); details(S.selected);
}
let pane = 'spectrum', split = 42;
try { split = +localStorage.getItem('split') || 42; } catch { /* ignore */ }
function paneTabs() {
  $('#panetabs').replaceChildren(...[['details', 'Network Details'], ['spectrum', 'Spectrum'], ['advanced', 'Advanced Details']].map(([k, l]) =>
    h('button', { class: k === pane ? 'on' : '', onclick: () => { pane = k; update(); details(S.selected); } }, l)));
  $('#scanspec').style.display = pane === 'spectrum' ? 'block' : 'none';
  const d = $('#details'); d.style.display = pane === 'spectrum' ? 'none' : 'block'; d.dataset.mode = pane;
}

// Save what is displayed as a Wireshark-readable capture (one rebuilt beacon per access point).
export async function savePcapng() {
  const shown = rows(); let list = shown;
  if (!S.loaded) { const full = await Promise.all(shown.map(n => api('/api/network?bssid=' + n.bssid))); list = full.filter(n => n.bssid); }
  const r = await api('/api/pcapng', { networks: list });
  if (!r.count) return toast('Nothing to save: these entries carry no raw beacon data (remote scans do not).', true);
  const bin = Uint8Array.from(atob(r.b64), c => c.charCodeAt(0));
  const a = h('a', { href: URL.createObjectURL(new Blob([bin], { type: 'application/octet-stream' })), download: `wifi-scan-${new Date().toISOString().slice(0, 19).replace(/:/g, '')}.pcapng` });
  document.body.append(a); a.click(); a.remove();
  toast(`Saved ${r.count} access point(s) as PCAPNG` + (r.count < shown.length ? ` (${shown.length - r.count} had no raw beacon data).` : '.'));
}

function columnMenu(btn) {
  if ($('.menu')) return $('.menu').remove();
  const want = new Set(active().map(c => c.k));
  const m = h('div', { class: 'menu' }, COLS.map(c => h('label', {}, h('input', { type: 'checkbox', checked: want.has(c.k), onchange: e => {
    e.target.checked ? want.add(c.k) : want.delete(c.k);
    saveSettings({ columns: COLS.filter(x => want.has(x.k)).map(x => x.k) }).then(update);
  } }), ' ' + c.l)));
  const r = btn.getBoundingClientRect();
  m.style.top = r.bottom + 4 + 'px'; m.style.right = Math.max(8, innerWidth - r.right) + 'px';
  document.body.append(m);
  setTimeout(() => document.addEventListener('click', function f(e) { if (!m.contains(e.target)) { m.remove(); document.removeEventListener('click', f); } }), 0);
}

export function update() {
  if (!root?.isConnected) return;
  if (!root.querySelector('.menu')) $('#scanquick').replaceChildren(quickBar());
  paneTabs();
  if (pane === 'spectrum') drawSpectrum($('#scanspec'), visible(), S.quick.band);
  const total = nets().length, vis = visible().length, st = S.status;
  $('#scanstatus').replaceChildren(h('span', {}, `Networks found: ${total}, displayed: ${vis} (${total ? Math.round(vis / total * 100) : 0}%)`),
    h('span', {}, S.loaded ? `Viewing saved data: ${S.loaded.name}` : st.paused ? 'Scanning paused' : `Scanning: ${st.adapter || st.label || ''}`),
    h('span', {}, S.loaded ? '' : S.conn ? `Connected to ${S.conn.ssid}` : 'Not associated (WiFi scanning does not need a WiFi connection)'));
  const cols = active(), rs = rows(), t = th();
  $('#filter').classList.toggle('err', !!S.filterError);
  $('#filter').title = S.filterError || '';
  $('#fcount').textContent = S.filterError ? S.filterError : `${rs.length} of ${nets().length}`;
  const head = h('tr', {}, cols.map(c => h('th', { class: c.n ? 'num' : '', onclick: () => { sort = { k: c.k, dir: sort.k === c.k ? -sort.dir : (c.n ? -1 : 1) }; update(); } },
    c.l + (sort.k === c.k ? (sort.dir > 0 ? ' ▲' : ' ▼') : ''))));
  const body = rs.map(n => h('tr', { class: (n.bssid === S.selected ? 'sel ' : '') + (n.connected ? 'me' : ''), onclick: () => select(n.bssid), oncontextmenu: e => {
    e.preventDefault(); select(n.bssid);
    const td = e.target.closest('td'), col = td ? cols[[...td.parentElement.children].indexOf(td)] : null, raw = col ? n[col.k] : null;
    const val = raw == null || raw === '' || Array.isArray(raw) ? null : typeof raw === 'boolean' ? (raw ? 'yes' : 'no') : String(raw);
    const lit = v => (/[,&^()! ]/.test(v) ? `"${v}"` : v), add = t => { const f = S.filterText.trim() ? `${S.filterText.trim()} & ${t}` : t; $('#filter').value = f; setFilter(f); };
    menu(e.clientX, e.clientY, [...(val != null ? [[`Show only ${col.l} = ${val}`, () => add(`${col.k}=${lit(val)}`)], [`Hide ${col.l} = ${val}`, () => add(`${col.k}!=${lit(val)}`)], ['Copy this value', () => navigator.clipboard.writeText(val)], null] : []),
      [n.note ? 'Edit note…' : 'Add note…', async () => { const t = prompt(`Note for ${n.ssid || n.bssid}:`, n.note || ''); if (t != null) { await saveSettings({ annotations: { [n.bssid]: t.trim() } }); n.note = t.trim(); update(); } }], null,
      ['Mark as mine (authorized)', () => mark([n.bssid], 'auth')], ['Mark as neighbor', () => mark([n.bssid], 'neighbor')], ['Remove mark', () => mark([n.bssid], 'none')], null,
      ['Locate this access point', () => window.sursumGo('threats', { locate: n.bssid })], ['Show its devices on the Map', () => window.sursumGo('map', { ap: n.bssid })], ['Copy BSSID', () => navigator.clipboard.writeText(n.bssid)]]);
  } }, cols.map(c => {
    if (c.k === 'ssid') return h('td', {}, h('span', { class: 'chip', style: `background:${color(n.bssid)}` }), n.ssid || h('span', { class: 'dim' }, '(hidden)'), n.connected ? h('span', { class: 'badge good', style: 'margin-left:6px' }, 'connected') : null);
    if (c.k === 'rssi') { const k = sigClass(n.rssi, t); return h('td', { class: 'num' }, n.rssi, h('span', { class: 'bar' }, h('i', { style: `width:${n.quality}%;background:${SIG[k]}` }))); }
    if (c.k === 'security') { const weak = ['Open', 'WEP', 'WPA-Personal'].includes(n.security); return h('td', {}, weak ? h('span', { class: 'badge bad' }, n.security) : n.security, n.wps ? h('span', { class: 'badge fair', style: 'margin-left:5px' }, 'WPS') : null); }
    if (c.k === 'threat') { const [l, k] = CLASS[n.threat] || ['', '']; return h('td', {}, k ? h('span', { class: 'badge ' + k }, l) : l); }
    return h('td', { class: c.n ? 'num' : '' }, String(text(c, n)));
  })));
  $('#nettable').replaceChildren(h('thead', {}, head), h('tbody', {}, body.length ? body : h('tr', {}, h('td', { colspan: cols.length, class: 'dim', style: 'padding:30px;text-align:center' },
    nets().length ? 'No networks match the filter.' : 'Scanning… networks appear here within a few seconds.'))));
  if (S.selected && shown !== S.selected) details(S.selected);
}
export const onSelect = b => { update(); details(b); root?.querySelector('#nettable tr.sel')?.scrollIntoView({ block: 'nearest' }); };
export const onAnalysis = update;

// ---- details panel: summary + raw tagged parameters
function decoded(d) {
  const rowsOut = Object.entries(d).filter(([, v]) => v !== null && v !== '').map(([k, v]) =>
    `<tr><td class="dim">${esc(k.replace(/_/g, ' '))}</td><td>${esc(Array.isArray(v) ? v.map(x => typeof x === 'object' ? JSON.stringify(x) : x).join(', ') : typeof v === 'object' ? JSON.stringify(v) : v)}</td></tr>`).join('');
  return rowsOut ? `<table>${rowsOut}</table>` : '';
}
async function details(bssid) {
  const box = $('#details'); if (!box) return;
  shown = bssid;
  let n = nets().find(x => x.bssid === bssid);
  if (!n) return box.replaceChildren(h('p', { class: 'dim', style: 'padding:14px' }, 'Select a network in the table or the spectrum to see its details here.'));
  if (!S.loaded) { const full = await api('/api/network?bssid=' + bssid); if (shown !== bssid) return; if (full.bssid) n = { ...n, ...full, threat: n.threat, distance: n.distance }; }
  const t = S.threats?.aps.find(x => x.bssid === bssid), hs = hist(bssid);
  const dl = (pairs) => h('dl', {}, pairs.filter(p => p[1] != null && p[1] !== '').flatMap(([a, b]) => [h('dt', {}, a), h('dd', {}, String(b))]));
  box.replaceChildren(
    h('div', { class: 'row' }, h('h2', { style: 'margin:0' }, h('span', { class: 'chip', style: `background:${color(bssid)}` }), n.ssid || '(hidden)'),
      h('span', { class: 'dim' }, `${n.bssid} · ${n.band} GHz ch ${n.channel} @ ${n.width} MHz`),
      h('button', { class: 'small', title: 'Track this access point’s signal to find it physically', onclick: () => window.sursumGo('threats', { locate: bssid }) }, 'Locate')),
    h('div', { class: 'sumpart' },
    t && t.cls !== 'unclassified' ? h('p', {}, h('b', { class: 'sev-' + t.severity }, t.label), ' ', h('span', { class: 'dim' }, t.reasons.join(' '))) : null,
    h('div', { class: 'cols' }, h('div', {}, h('h3', {}, 'Radio'),
    dl([['BSSID', n.bssid], ['Vendor', n.vendor], ['AP name', n.ap_name], ['Model', n.model], ['Signal', `${n.rssi} dBm (${n.quality}%)`],
      ['Seen range', hs.length ? `${Math.min(...hs.map(x => x[1]))} to ${Math.max(...hs.map(x => x[1]))} dBm` : null],
      ['Noise / SNR', n.noise != null ? `${n.noise} dBm / ${n.snr} dB` : 'Not reported by this adapter'],
      ['Est. distance', t ? `~${t.distance.m} m (range ${t.distance.min}–${t.distance.max} m)` : null],
      ['Band / channel', `${n.band} GHz, primary channel ${n.channel} (${n.freq} MHz)`],
      ['Channel width', `${n.width} MHz, centre channel ${n.center_channel} (${n.center_freq} MHz)` + (n.secondary ? `, secondary ${n.secondary}` : '')],
      ['Standard', `${n.generation} (802.11 ${(n.standards || []).join('/')})`], ['Streams / max rate', `${n.streams ?? '?'} × / ${n.max_rate} Mbps`],
      ['Stations', n.stations], ['Channel utilization', n.utilization != null ? n.utilization + ' %' : null],
      ['Co / adjacent-channel', `${n.cci ?? 0} / ${n.aci ?? 0} networks`], ['AP uptime', duration(n.uptime)],
      ['Beacon / DTIM', `${n.beacon_interval} TU / ${n.dtim ?? '?'}`], ['Country', n.country], ['Tx power', n.tx_power != null ? n.tx_power + ' dBm' : null]])),
    h('div', {}, h('h3', {}, 'Security'),
    dl([['Security', n.security], ['Authentication', list(n.akm)], ['Pairwise ciphers', list(n.ciphers)], ['Group cipher', n.group_cipher],
      ['Management frame protection', n.pmf], ['WPS', n.wps ? (n.wps_locked ? 'Enabled (locked)' : 'Enabled') : 'Off'],
      ['Capabilities', list(n.cap_flags)],
      ['Features', [n.k && '802.11k', n.v && '802.11v', n.r && '802.11r', n.wmm && 'WMM', n.mu_mimo && 'MU-MIMO', n.beamforming && 'Beamforming', n.twt && 'TWT', n.mlo && 'Multi-Link', n.hotspot2 && 'Hotspot 2.0'].filter(Boolean).join(', ')]])))),
    h('div', { class: 'iepart' }, (n.ies || []).length ? h('div', { class: 'tablewrap' }, h('table', { class: 'ietable' },
      h('thead', {}, h('tr', {}, ['ID', 'Length', 'Information Element', 'Details'].map(x => h('th', {}, x)))),
      h('tbody', {}, (n.ies || []).flatMap(e => {
        const sum = Object.entries(e.decoded).filter(([, v]) => v !== null && v !== '' && typeof v !== 'object').slice(0, 4).map(([k, v]) => `${k.replace(/_/g, ' ')}: ${v}`).join(', ');
        const more = h('tr', { class: 'iemore', hidden: true }, h('td', { colspan: 4 }, h('div', { html: decoded(e.decoded) }), h('code', { class: 'hex' }, e.hex)));
        return [h('tr', { style: 'cursor:pointer', onclick: () => { more.hidden = !more.hidden; } }, h('td', { class: 'num' }, e.ext != null ? `${e.id} / ${e.ext}` : e.id), h('td', { class: 'num' }, `${e.len} bytes`), h('td', {}, '▸ ', h('b', {}, e.name)), h('td', { class: 'wrap dim' }, sum)), more];
      }))))
      : h('p', { class: 'dim' }, n.ie_note || 'No raw elements available for this entry.')));
}
