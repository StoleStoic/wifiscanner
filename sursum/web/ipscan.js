// IP scanner: devices on the local network, with known/unknown marking.
import { $, h, api, stamp, download } from './util.js';
import { S, saveSettings } from './state.js';

let root, st = { devices: [] }, timer;
async function tick() { st = await api('/api/ipscan'); if (root?.isConnected) render(); if (!st.running) clearInterval(timer); }
async function setKnown(d, known) {
  const i = S.settings.inventory, devices = i.devices.filter(x => x.mac !== d.mac);
  if (known) { const label = prompt('Name for this device:', d.hostname || d.vendor || ''); if (label == null) return; devices.push({ mac: d.mac, label }); }
  await saveSettings({ inventory: { ...i, devices } }); tick();
}
export function mount(el) { root = el; tick(); }
export const unmount = () => clearInterval(timer);
function render() {
  const unknown = st.devices.filter(d => !d.known && !d.gateway && d.mac);
  root.replaceChildren(
    h('div', { class: 'row', style: 'margin-bottom:12px' },
      h('button', { class: 'primary', disabled: st.running, onclick: async () => { await api('/api/ipscan', {}); clearInterval(timer); timer = setInterval(tick, 700); tick(); } }, st.running ? `Scanning… ${Math.round(st.progress * 100)}%` : 'Scan my network'),
      h('span', { class: 'dim' }, st.scanned_at ? `${st.devices.length} device(s) on ${st.network} · ${stamp(st.scanned_at)}` : 'Finds every device answering on the network this PC is connected to.'),
      h('span', { class: 'grow' }),
      st.devices.length ? h('button', { onclick: () => download('lan-devices.csv', ['ip,mac,vendor,hostname,known,label', ...st.devices.map(d => [d.ip, d.mac, `"${d.vendor}"`, d.hostname, d.known, `"${d.label}"`].join(','))].join('\r\n'), 'text/csv') }, 'Export CSV') : null),
    st.error ? h('div', { class: 'note', style: 'border-color:#ef5b5b' }, st.error) : null,
    st.scanned_at ? h('div', { class: 'kpis' },
      h('div', { class: 'kpi' }, h('div', { class: 'v' }, st.devices.length), h('div', { class: 'l' }, 'Devices found')),
      h('div', { class: 'kpi' }, h('div', { class: 'v', style: unknown.length ? 'color:var(--poor)' : 'color:var(--good)' }, unknown.length), h('div', { class: 'l' }, 'Unknown devices'))) : null,
    h('div', { class: 'tablewrap' }, h('table', {}, h('thead', {}, h('tr', {}, ['Status', 'IP address', 'MAC address', 'Vendor', 'Hostname', 'Name', ''].map(x => h('th', {}, x)))),
      h('tbody', {}, st.devices.length ? st.devices.map(d => h('tr', {},
        h('td', {}, d.self ? h('span', { class: 'badge info' }, 'This PC') : d.gateway ? h('span', { class: 'badge info' }, 'Router') : d.known ? h('span', { class: 'badge good' }, 'Known') : h('span', { class: 'badge poor' }, 'Unknown')),
        h('td', {}, d.ip), h('td', {}, d.mac || '—', d.random_mac ? h('span', { class: 'badge', style: 'margin-left:6px', title: 'Randomised private address, as phones use by default' }, 'private') : null),
        h('td', {}, d.vendor), h('td', {}, d.hostname), h('td', {}, d.label),
        h('td', {}, d.self || !d.mac ? null : d.known ? h('button', { class: 'small', onclick: () => setKnown(d, false) }, 'Forget') : h('button', { class: 'small', onclick: () => setKnown(d, true) }, 'Mark as known'))))
        : h('tr', {}, h('td', { colspan: 7, class: 'dim', style: 'padding:24px;text-align:center' }, 'Run a scan to list the devices on your network.'))))),
    h('p', { class: 'dim', style: 'margin-top:10px' }, 'Mark every device you recognise as known. Anything left as Unknown is reported in the Threats tab as a possible rogue client. Phones often show a "private" address that changes per network; identify them by switching their WiFi off and rescanning.'));
}
