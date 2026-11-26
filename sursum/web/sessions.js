// Sessions: save, load, import, compare, and open packet captures.
import { $, h, api, stamp, download, pickFile, toast, sel } from './util.js';
import { S, setLoaded } from './state.js';

let root, list = [], cmp = { a: 'live', b: '' }, cmpOut = null;
async function refresh() { list = await api('/api/sessions'); if (root?.isConnected) render(); }
const fetchSet = async id => (id === 'live' ? { name: 'Live scan', networks: S.live } : await api('/api/session?id=' + encodeURIComponent(id)));

async function compare() {
  if (!cmp.b) return toast('Pick a saved session to compare with.');
  const [A, B] = await Promise.all([fetchSet(cmp.a), fetchSet(cmp.b)]);
  const a = Object.fromEntries(A.networks.map(n => [n.bssid, n])), b = Object.fromEntries(B.networks.map(n => [n.bssid, n])), rows = [];
  for (const k of new Set([...Object.keys(a), ...Object.keys(b)])) {
    const x = a[k], y = b[k], n = x || y, ch = [];
    if (x && y) {
      if (x.channel !== y.channel) ch.push(`channel ${y.channel} → ${x.channel}`);
      if (x.width !== y.width) ch.push(`width ${y.width} → ${x.width} MHz`);
      if (x.security !== y.security) ch.push(`security ${y.security} → ${x.security}`);
      if (x.ssid !== y.ssid) ch.push(`SSID "${y.ssid}" → "${x.ssid}"`);
    }
    rows.push({ n, state: !y ? 'Only in A' : !x ? 'Only in B' : ch.length ? 'Changed' : 'Same', ra: x?.rssi, rb: y?.rssi, ch: ch.join('; ') });
  }
  const ord = { 'Only in A': 0, 'Only in B': 1, Changed: 2, Same: 3 };
  cmpOut = { A: A.name, B: B.name, rows: rows.sort((p, q) => ord[p.state] - ord[q.state] || (q.ra ?? q.rb) - (p.ra ?? p.rb)) };
  render();
}

export function mount(el) { root = el; refresh(); }
function render() {
  const opts = [['live', 'Live scan'], ...list.map(s => [s.id, s.name])];
  root.replaceChildren(
    h('div', { class: 'row', style: 'margin-bottom:12px' },
      h('button', { class: 'primary', onclick: async () => { const name = prompt('Name for this scan session:', 'Home ' + new Date().toLocaleDateString()); if (!name) return; await api('/api/sessions', { name }); toast('Session saved.'); refresh(); } }, 'Save current scan'),
      h('button', { onclick: async () => {
        const f = await pickFile('.json'); if (!f) return;
        let d; try { d = JSON.parse(await f.text()); } catch { return toast('That file is not a session file.', true); }
        const r = await api('/api/sessions/import', d); r.error ? toast(r.error, true) : (toast('Session imported.'), refresh());
      } }, 'Import session file'),
      h('button', { title: 'Open a monitor-mode capture (pcap or pcapng) and list the access points in it', onclick: async () => {
        const f = await pickFile('.pcap,.pcapng,.cap'); if (!f) return;
        const r = await api('/api/pcap', await f.arrayBuffer(), true);
        if (r.error) return toast(r.error, true);
        setLoaded({ name: `${f.name} (${r.stats.beacons} beacons)`, networks: r.networks, history: {}, connection: null }); window.sursumGo('scan');
      } }, 'Open pcap file')),
    h('div', { class: 'tablewrap' }, h('table', {}, h('thead', {}, h('tr', {}, ['Name', 'Saved', 'Networks', 'Source', ''].map(x => h('th', {}, x)))),
      h('tbody', {}, list.length ? list.map(s => h('tr', {}, h('td', {}, s.name), h('td', {}, stamp(s.saved)), h('td', { class: 'num' }, s.count), h('td', {}, s.source),
        h('td', {}, h('button', { class: 'small', onclick: async () => { const d = await api('/api/session?id=' + encodeURIComponent(s.id)); setLoaded({ name: d.name, networks: d.networks, history: d.history || {}, connection: d.connection }); window.sursumGo('scan'); } }, 'Open'), ' ',
          h('button', { class: 'small', onclick: async () => download(s.id + '.json', JSON.stringify(await api('/api/session?id=' + encodeURIComponent(s.id))), 'application/json') }, 'Download'), ' ',
          h('button', { class: 'small danger', onclick: async () => { if (confirm(`Delete "${s.name}"?`)) { await api('/api/session/delete', { id: s.id }); refresh(); } } }, 'Delete'))))
        : h('tr', {}, h('td', { colspan: 5, class: 'dim', style: 'padding:24px;text-align:center' }, 'No saved sessions yet. Save a scan to analyse it later or compare it with another day or place.'))))),
    h('div', { class: 'card', style: 'margin-top:14px' }, h('h2', {}, 'Compare'),
      h('div', { class: 'row' }, 'A', sel(opts, cmp.a, v => { cmp.a = v; }), 'against B', sel([['', 'Choose…'], ...opts], cmp.b, v => { cmp.b = v; }), h('button', { onclick: compare }, 'Compare')),
      cmpOut ? [h('p', { class: 'dim' }, `A = ${cmpOut.A}, B = ${cmpOut.B}. ${cmpOut.rows.filter(r => r.state === 'Only in A').length} only in A, ${cmpOut.rows.filter(r => r.state === 'Only in B').length} only in B, ${cmpOut.rows.filter(r => r.state === 'Changed').length} changed.`),
        h('div', { class: 'tablewrap' }, h('table', {}, h('thead', {}, h('tr', {}, ['Result', 'SSID', 'BSSID', 'Band / ch', 'Signal A', 'Signal B', 'Difference', 'What changed'].map(x => h('th', {}, x)))),
          h('tbody', {}, cmpOut.rows.map(r => h('tr', {}, h('td', {}, h('span', { class: 'badge ' + ({ 'Only in A': 'good', 'Only in B': 'poor', Changed: 'fair' }[r.state] || '') }, r.state)), h('td', {}, r.n.ssid || '(hidden)'), h('td', {}, r.n.bssid), h('td', {}, `${r.n.band} GHz / ${r.n.channel}`),
            h('td', { class: 'num' }, r.ra ?? '—'), h('td', { class: 'num' }, r.rb ?? '—'), h('td', { class: 'num' }, r.ra != null && r.rb != null ? (r.ra - r.rb > 0 ? '+' : '') + (r.ra - r.rb).toFixed(1) + ' dB' : ''), h('td', {}, r.ch))))))] : null));
}
