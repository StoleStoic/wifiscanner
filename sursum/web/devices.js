// Devices: every client device seen by any scan, with authorize / categorize controls and details.
import { $, h, api, stamp, download, toast, sel, AUTH, menu } from './util.js';
import { S, nets, deviceAction, refreshDevices } from './state.js';

let root, view = 'all', q = '', picked = new Set(), shown = null, timer = null, sort = { k: 'last_seen', dir: -1 };
const PORTS = { 22: 'SSH', 80: 'Web page', 443: 'Secure web page', 445: 'Windows file sharing', 515: 'Printing', 548: 'Apple file sharing', 554: 'Camera video', 631: 'Printing', 1883: 'Smart-home messaging', 3389: 'Remote Desktop', 5000: 'UPnP / AirPlay', 7000: 'AirPlay', 8009: 'Chromecast', 8080: 'Web page', 9100: 'Printing', 62078: 'iPhone / iPad sync' };
const VIEWS = { all: ['All', () => true], mine: ['On my network', d => d.sources.includes('lan')], pending: ['Unreviewed', d => d.authorized == null && d.sources.includes('lan')],
  denied: ['Not authorized', d => d.authorized === false], unknown: ['Unknown type', d => d.type === 'Unknown'], other: ['Seen on other networks', d => !d.sources.includes('lan')] };
export const label = d => d.name || d.hostname || d.model_guess || (d.type !== 'Unknown' ? d.type : '') || d.mac;
const apText = d => (d.ap ? `${d.ap_name ?? 'not in range'} · ${d.ap_band ?? d.ap}` : '');

function rows() {
  const needle = q.toLowerCase();
  return S.devices.filter(VIEWS[view][1]).filter(d => !needle || [label(d), d.mac, d.vendor, d.type, d.hostname, d.ips.join(' '), d.ap_name, d.notes].join(' ').toLowerCase().includes(needle))
    .sort((a, b) => { const x = sort.k === 'name' ? label(a) : a[sort.k] ?? '', y = sort.k === 'name' ? label(b) : b[sort.k] ?? ''; return (typeof x === 'number' ? x - y : String(x).localeCompare(String(y))) * sort.dir; });
}
const authSel = (d, macs) => sel([['null', 'Unreviewed'], ['true', 'Authorized'], ['false', 'Not authorized']], String(d ? d.authorized : null),
  v => deviceAction('update', macs || [d.mac], { authorized: v === 'null' ? null : v === 'true' }), d ? { style: `color:${AUTH[d.authorized][1]}` } : {});
const typeSel = (d, macs) => sel(d ? S.deviceTypes : [['', 'Set type…'], ...S.deviceTypes], d ? d.type : '', v => v && deviceAction('update', macs || [d.mac], { type: v }));

async function identify(macs) {
  if (!S.settings.ai.has_key) return toast('Add your Anthropic API key in Settings first.', true);
  if (!macs.length) return toast('No devices to identify in this view.');
  await deviceAction('identify', macs);
  clearInterval(timer);
  timer = setInterval(async () => { await refreshDevices(); const st = S.devStatus; if (!st.identify_running) { clearInterval(timer); st.identify.error ? toast(st.identify.error, true) : toast(`Claude identified ${st.identify.updated} of ${st.identify.asked} device(s).`); } }, 2500);
}

export function mount(el, arg) {
  root = el; el.className = 'fill';
  if (arg?.mac) { shown = arg.mac; view = 'all'; q = ''; }
  el.append(h('div', { id: 'devtop' }), h('div', { class: 'scanwrap' }, h('div', { class: 'tablewrap' }, h('table', { id: 'devtable' })), h('aside', { id: 'details' })));
  render(); detail();
}
export const unmount = () => clearInterval(timer);
export const onDevices = () => { if (root?.isConnected && !root.querySelector('#details input:focus, #details textarea:focus, #devq:focus')) { render(); detail(); } };

function render() {
  const st = S.devStatus, rs = rows(), count = k => S.devices.filter(VIEWS[k][1]).length;
  $('#devtop').replaceChildren(
    h('div', { class: 'filterbar' },
      h('button', { class: 'primary', disabled: st.running, onclick: async () => { await api('/api/ipscan', {}); const t = setInterval(async () => { await refreshDevices(); if (!S.devStatus.running) { clearInterval(t); S.devStatus.error && toast(S.devStatus.error, true); } }, 700); } }, st.running ? `Scanning… ${Math.round(st.progress * 100)}%` : 'Scan my network'),
      h('div', { class: 'seg' }, Object.entries(VIEWS).map(([k, [l]]) => h('button', { class: k === view ? 'on' : '', onclick: () => { view = k; picked.clear(); render(); } }, `${l} (${count(k)})`))),
      h('input', { type: 'text', id: 'devq', placeholder: 'Search name, address, maker…', value: q, oninput: e => { q = e.target.value; table(); } }),
      h('button', { disabled: st.identify_running, title: 'Send the evidence for devices of unknown type to Claude for identification', onclick: () => identify((picked.size ? [...picked] : rs.filter(d => d.type === 'Unknown' || d.type_source === 'auto').map(d => d.mac))) }, st.identify_running ? 'Claude is identifying…' : picked.size ? `Identify ${picked.size} with Claude` : 'Identify with Claude'),
      h('button', { onclick: () => download('devices.csv', ['name,type,authorized,maker,ip,mac,hostname,access_point,link_source,first_seen,last_seen,notes', ...rs.map(d => [label(d), d.type, AUTH[d.authorized][0], d.vendor, d.ips[0] || '', d.mac, d.hostname, apText(d), d.ap_source || '', new Date(d.first_seen * 1000).toISOString(), new Date(d.last_seen * 1000).toISOString(), d.notes].map(v => `"${String(v ?? '').replace(/"/g, '""')}"`).join(','))].join('\r\n'), 'text/csv') }, 'Export CSV')),
    picked.size ? h('div', { class: 'filterbar' }, h('b', {}, `${picked.size} selected:`),
      h('button', { onclick: () => deviceAction('update', [...picked], { authorized: true }) }, 'Authorize'), h('button', { onclick: () => deviceAction('update', [...picked], { authorized: false }) }, 'Not authorized'),
      typeSel(null, [...picked]), h('button', { class: 'danger', onclick: () => confirm(`Forget ${picked.size} device(s)? They reappear if seen again.`) && deviceAction('forget', [...picked]).then(() => picked.clear()) }, 'Forget'),
      h('button', { onclick: () => { picked.clear(); render(); } }, 'Clear selection')) : null,
    st.error ? h('div', { class: 'note', style: 'border-color:#ef5b5b' }, st.error) : null);
  table();
}

function table() {
  const rs = rows(), th = (k, l, n) => h('th', { class: n ? 'num' : '', onclick: () => { sort = { k, dir: sort.k === k ? -sort.dir : 1 }; table(); } }, l + (sort.k === k ? (sort.dir > 0 ? ' ▲' : ' ▼') : ''));
  $('#devtable').replaceChildren(
    h('thead', {}, h('tr', {}, h('th', {}, h('input', { type: 'checkbox', checked: rs.length && rs.every(d => picked.has(d.mac)), onchange: e => { rs.forEach(d => (e.target.checked ? picked.add(d.mac) : picked.delete(d.mac))); render(); } })),
      th('name', 'Device'), th('authorized', 'Authorization'), th('type', 'Type'), th('vendor', 'Maker'), th('ips', 'IP address'), th('mac', 'MAC address'), th('ap_name', 'Connected to'), th('last_seen', 'Last seen'))),
    h('tbody', {}, rs.length ? rs.map(d => h('tr', { class: d.mac === shown ? 'sel' : '', onclick: e => { if (!['SELECT', 'INPUT', 'OPTION'].includes(e.target.tagName)) { shown = d.mac; table(); detail(); } },
      oncontextmenu: e => { e.preventDefault(); menu(e.clientX, e.clientY, [['Authorize', () => deviceAction('update', [d.mac], { authorized: true })], ['Not authorized', () => deviceAction('update', [d.mac], { authorized: false })], null, ['Show on map', () => window.sursumGo('map', { mac: d.mac })], ['Identify with Claude', () => identify([d.mac])]]); } },
      h('td', {}, h('input', { type: 'checkbox', checked: picked.has(d.mac), onchange: e => { e.target.checked ? picked.add(d.mac) : picked.delete(d.mac); render(); } })),
      h('td', {}, h('span', { class: 'dot', style: `background:${d.online ? '#3ecf8e' : '#b5b5b5'}`, title: d.online ? 'Answered in the last network scan' : 'Not seen in the last network scan' }), label(d),
        d.self ? h('span', { class: 'badge info', style: 'margin-left:6px' }, 'This PC') : d.gateway ? h('span', { class: 'badge info', style: 'margin-left:6px' }, 'Router') : null),
      h('td', {}, authSel(d)), h('td', {}, typeSel(d), d.type_source === 'claude' ? h('span', { class: 'badge info', style: 'margin-left:5px' }, 'Claude') : null),
      h('td', {}, d.vendor), h('td', {}, d.ips[0] || ''), h('td', {}, d.mac, d.random_mac ? h('span', { class: 'badge', style: 'margin-left:6px', title: 'Randomised private address' }, 'private') : null),
      h('td', {}, d.ap ? apText(d) : h('span', { class: 'dim' }, d.sources.includes('lan') ? 'My network — access point unknown' : '')), h('td', {}, stamp(d.last_seen))))
      : h('tr', {}, h('td', { colspan: 9, class: 'dim', style: 'padding:26px;text-align:center' }, S.devices.length ? 'No devices in this view.' : 'No devices yet. Click "Scan my network" to list everything connected to your network.'))));
}

function detail() {
  const box = $('#details'), d = S.devices.find(x => x.mac === shown);
  if (!box) return;
  if (!d) return box.replaceChildren(h('p', { class: 'dim' }, 'Select a device to see everything known about it and to name, categorize or authorize it.'),
    h('p', { class: 'dim' }, 'Devices come from three places: the network scan (everything on your own network), capture files opened in Sessions (which device talks to which access point, for any network in range), and this PC’s own connection.'));
  const aps = nets().filter(n => n.threat === 'authorized' || n.bssid === d.ap).map(n => [n.bssid, `${n.ssid || '(hidden)'} · ${n.band} GHz ch ${n.channel} · ${n.bssid}`]);
  if (d.ap && !aps.some(a => a[0] === d.ap)) aps.push([d.ap, `${d.ap} (not in range now)`]);
  const dl = pairs => h('dl', {}, pairs.filter(p => p[1] != null && p[1] !== '').flatMap(([a, b]) => [h('dt', {}, a), h('dd', {}, b)]));
  const SRC = { 'this PC': 'reported by this PC', capture: 'seen in a capture file', manual: 'set by you', simulated: 'simulated (demo)' };
  box.replaceChildren(
    h('div', { class: 'row' }, h('h2', { class: 'grow', style: 'margin:0' }, label(d)), h('button', { class: 'small', onclick: () => window.sursumGo('map', { mac: d.mac }) }, 'Show on map')),
    h('h3', {}, 'Yours to set'),
    dl([['Name', h('input', { type: 'text', value: d.name, placeholder: d.hostname || 'Give it a name', style: 'width:100%', onchange: e => deviceAction('update', [d.mac], { name: e.target.value.trim() }) })],
      ['Authorization', authSel(d)], ['Type', h('span', { class: 'row' }, typeSel(d), d.type_source !== 'auto' ? h('button', { class: 'small', onclick: () => deviceAction('update', [d.mac], { type: 'auto' }) }, 'Reset to automatic') : null)],
      ['Access point', sel([['', 'Unknown'], ...aps], d.ap || '', v => deviceAction('update', [d.mac], { ap: v || null }))],
      ['Notes', h('textarea', { rows: 2, style: 'width:100%', onchange: e => deviceAction('update', [d.mac], { notes: e.target.value }) }, d.notes)]]),
    h('h3', {}, 'What the scanner found'),
    dl([['Type guess', `${d.type} — ${d.type_reason || 'no evidence yet'}`], ['Likely model', d.model_guess], ['Maker', d.vendor || 'Not in the registry'],
      ['MAC address', d.mac + (d.random_mac ? ' (private, randomised: it can change, and then appears as a new device)' : '')],
      ['IP address', d.ips.join(', ')], ['Network name', d.hostname], ['Describes itself as', d.upnp],
      ['Services answering', d.ports.length ? d.ports.map(p => `${PORTS[p] || 'port'} (${p})`).join(', ') : d.sources.includes('lan') ? 'None of the common ones' : null],
      ['Connected to', d.ap ? `${apText(d)} — ${SRC[d.ap_source] || d.ap_source}` : d.sources.includes('lan') ? 'Your network; the access point is not known. Windows cannot observe this from the air. Set it above if you know it.' : null],
      ['Signal in capture', d.rssi != null ? d.rssi + ' dBm' : null], ['Seen by', d.sources.map(s => ({ lan: 'network scan', capture: 'capture file' }[s] || s)).join(', ')],
      ['Status', d.online ? 'Online in the last network scan' : 'Not in the last network scan'], ['First seen', stamp(d.first_seen)], ['Last seen', stamp(d.last_seen)]]),
    h('div', { class: 'row', style: 'margin-top:12px' }, h('button', { onclick: () => identify([d.mac]) }, 'Identify with Claude'),
      h('button', { class: 'danger', onclick: () => confirm('Forget this device? It reappears if seen again.') && deviceAction('forget', [d.mac]).then(() => { shown = null; detail(); }) }, 'Forget device')));
}
