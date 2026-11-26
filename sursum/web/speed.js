// Speed test view: manual / continuous / on-roam tests, room tagging and history.
import { $, h, api, sel, canvas, INK, stamp, download, toast } from './util.js';
import { S, saveSettings } from './state.js';

let root, st = { history: [] }, servers = [], timer;
const cfg = () => S.settings.speedtest;
const set = patch => saveSettings({ speedtest: patch });

async function tick() {
  st = await api('/api/speedtest');
  if (!root?.isConnected) return;
  live(); if (tick.n !== st.history.length || tick.r !== st.running) { tick.n = st.history.length; tick.r = st.running; table(); }
}
function live() {
  const last = st.history[st.history.length - 1], b = $('#live'); if (!b) return;
  const run = st.running, v = (label, val, unit, on) => h('div', { class: 'kpi', style: on ? 'border-color:var(--accent)' : '' }, h('div', { class: 'v' }, val ?? '—', h('small', { class: 'dim', style: 'font-size:13px' }, ' ' + unit)), h('div', { class: 'l' }, label));
  b.replaceChildren(
    v('Download', run && st.phase === 'download' ? st.live : last?.download, 'Mbps', run && st.phase === 'download'),
    v('Upload', run && st.phase === 'upload' ? st.live : run && st.phase !== 'upload' ? null : last?.upload, 'Mbps', run && st.phase === 'upload'),
    v('Latency', run ? null : last?.ping, 'ms', run && st.phase === 'latency'), v('Jitter', run ? null : last?.jitter, 'ms'),
    v('Next automatic test', cfg().continuous && st.next_run ? Math.max(0, Math.round(st.next_run - Date.now() / 1000)) : null, 's'));
  $('#runbtn').disabled = run; $('#runbtn').textContent = run ? `Testing ${st.phase}…` : 'Run speed test now';
}
function table() {
  const hs = [...st.history].reverse(), cv = $('#spchart');
  $('#sphist').replaceChildren(h('thead', {}, h('tr', {}, ['Time', 'Trigger', 'Room', 'Download', 'Upload', 'Latency', 'Jitter', 'SSID', 'Access point', 'Signal', 'Band / ch', 'Server'].map(x => h('th', {}, x)))),
    h('tbody', {}, hs.length ? hs.map(r => h('tr', {}, h('td', {}, stamp(r.t)), h('td', {}, h('span', { class: 'badge ' + (r.trigger === 'roam' ? 'fair' : '') }, r.trigger + (r.roam_from ? ` from ${r.roam_from}` : ''))), h('td', {}, r.room || ''),
      r.error ? h('td', { colspan: 4, class: 'sev-Critical' }, r.error) : [h('td', { class: 'num' }, r.download + ' Mbps'), h('td', { class: 'num' }, r.upload + ' Mbps'), h('td', { class: 'num' }, r.ping + ' ms'), h('td', { class: 'num' }, r.jitter + ' ms')],
      h('td', {}, r.ssid || ''), h('td', {}, r.bssid || ''), h('td', { class: 'num' }, r.rssi != null ? r.rssi + ' dBm' : ''), h('td', {}, r.band ? `${r.band} GHz / ${r.channel}` : ''), h('td', {}, r.server)))
      : h('tr', {}, h('td', { colspan: 12, class: 'dim', style: 'padding:20px;text-align:center' }, 'No tests yet.'))));
  const ok = st.history.filter(r => !r.error).slice(-40), { ctx, w, h: hgt } = canvas(cv), max = Math.max(10, ...ok.map(r => r.download)), L = 44, B = hgt - 22;
  ctx.textAlign = 'right'; ctx.textBaseline = 'middle';
  for (let i = 0; i <= 4; i++) { const y = B - (B - 10) * i / 4; ctx.strokeStyle = INK.grid; ctx.beginPath(); ctx.moveTo(L, y); ctx.lineTo(w - 8, y); ctx.stroke(); ctx.fillStyle = INK.axis; ctx.fillText(Math.round(max * i / 4), L - 6, y); }
  const bw = (w - L - 8) / Math.max(8, ok.length);
  ok.forEach((r, i) => {
    const x = L + i * bw;
    ctx.fillStyle = r.trigger === 'roam' ? '#e6c84f' : '#5aa9f5'; ctx.fillRect(x + bw * 0.12, B - r.download / max * (B - 10), bw * 0.45, r.download / max * (B - 10));
    ctx.fillStyle = '#3ecf8e'; ctx.fillRect(x + bw * 0.58, B - r.upload / max * (B - 10), bw * 0.3, r.upload / max * (B - 10));
  });
  ctx.textAlign = 'left'; ctx.fillStyle = INK.dim; ctx.textBaseline = 'top'; ctx.fillText('Mbps — blue: download (yellow when triggered by roaming), green: upload', L, B + 6);
}

export async function mount(el) {
  root = el; const c = cfg();
  const serverSel = h('span', { id: 'srvsel' }, sel([[c.server, 'Loading servers…']], c.server, () => {}));
  el.append(
    h('div', { class: 'kpis', id: 'live' }),
    h('div', { class: 'card' },
      h('div', { class: 'row' }, h('button', { class: 'primary', id: 'runbtn', onclick: async () => { await api('/api/speedtest', { trigger: 'manual' }); tick(); } }, 'Run speed test now'),
        'Server', serverSel, h('button', { class: 'small', onclick: () => loadServers(true) }, 'Refresh list'),
        'Room', h('span', { id: 'roomsel' })),
      h('div', { class: 'row', style: 'margin-top:10px' },
        h('label', {}, h('input', { type: 'checkbox', checked: c.auto_roam, onchange: e => set({ auto_roam: e.target.checked }) }), ' Test automatically when this PC roams (access point or network name changes)'),
        'wait', h('input', { type: 'number', min: 0, max: 120, value: c.roam_wait, onchange: e => set({ roam_wait: +e.target.value }) }), 'seconds after the roam'),
      h('div', { class: 'row', style: 'margin-top:6px' },
        h('label', {}, h('input', { type: 'checkbox', checked: c.continuous, onchange: e => set({ continuous: e.target.checked }) }), ' Repeat continuously every'),
        h('input', { type: 'number', min: 15, max: 86400, value: c.interval, onchange: e => set({ interval: +e.target.value }) }), 'seconds',
        h('span', { class: 'dim' }, '(each test uses roughly 100–500 MB of data on a fast line)')),
      h('div', { class: 'row', style: 'margin-top:6px' }, 'Own server (optional LibreSpeed address, e.g. one on your LAN to test WiFi alone)',
        h('input', { type: 'text', style: 'width:280px', placeholder: 'http://192.168.1.10/backend', value: c.custom_url, onchange: e => set({ custom_url: e.target.value.trim() }).then(() => loadServers()) }))),
    h('div', { class: 'card' }, h('canvas', { id: 'spchart', class: 'chart short' })),
    h('div', { class: 'row', style: 'margin-bottom:8px' }, h('h2', { class: 'grow', style: 'margin:0' }, 'History'),
      h('button', { onclick: () => download('speedtests.csv', ['time,trigger,room,download_mbps,upload_mbps,ping_ms,jitter_ms,ssid,bssid,rssi_dbm,band,channel,server',
        ...st.history.map(r => [new Date(r.t * 1000).toISOString(), r.trigger, `"${r.room || ''}"`, r.download ?? '', r.upload ?? '', r.ping ?? '', r.jitter ?? '', `"${r.ssid || ''}"`, r.bssid || '', r.rssi ?? '', r.band || '', r.channel || '', `"${r.server}"`].join(','))].join('\r\n'), 'text/csv') }, 'Export CSV'),
      h('button', { class: 'danger', onclick: async () => { if (confirm('Delete all speed test history?')) { await api('/api/speedtest', { action: 'clear' }); tick(); } } }, 'Clear history')),
    h('div', { class: 'tablewrap' }, h('table', { id: 'sphist' })));
  rooms(); tick.n = -1; await tick(); timer = setInterval(tick, 1000); loadServers();
}
function rooms() {
  const c = cfg();
  $('#roomsel').replaceChildren(sel([['', '(none)'], ...c.rooms, ['+', '+ Add a room…']], c.room, async v => {
    if (v === '+') { const n = prompt('Room name:'); if (n) await set({ rooms: [...new Set([...c.rooms, n])], room: n }); } else await set({ room: v });
    rooms();
  }));
}
async function loadServers(refresh) {
  servers = await api('/api/speedtest/servers' + (refresh ? '?refresh=1' : ''));
  if (!$('#srvsel')) return;
  const opts = servers.map(s => [s.id, s.name]); if (cfg().custom_url) opts.push(['custom', 'Own server: ' + cfg().custom_url]);
  $('#srvsel').replaceChildren(sel(opts, cfg().server, v => set({ server: v })));
  if (refresh) toast(`${servers.length} servers available.`);
}
export const unmount = () => clearInterval(timer);
