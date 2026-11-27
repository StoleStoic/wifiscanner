// Monitor: continuous up/down, response time and packet loss for every device and the internet.
import { $, h, api, canvas, INK, stamp, clock, download, csvCell, sel, duration } from './util.js';
import { S, saveSettings } from './state.js';

let root, st = { targets: [], events: [] }, picked = null, timer, sort = 'state';
const KIND = { down: ['Down', 'bad'], up: ['Recovered', 'good'], slow: ['Slow', 'fair'], loss: ['Packet loss', 'poor'] };
const cfg = () => S.settings.monitor;
const state = t => (t.up === false ? 0 : t.slow || t.lossy ? 1 : t.up === null ? 3 : 2);

async function tick() {
  st = await api('/api/monitor' + (picked ? '?detail=' + encodeURIComponent(picked) : ''));
  if (root?.isConnected && !root.querySelector('input:focus')) render();
}
function spark(vals) {
  const cv = h('canvas', { width: 120, height: 22, style: 'width:120px;height:22px' }), c = cv.getContext('2d'), max = Math.max(10, ...vals.filter(v => v != null));
  vals.forEach((v, i) => { const x = i * 3; if (v == null) { c.fillStyle = '#ef5b5b'; c.fillRect(x, 0, 2, 22); } else { const hh = Math.max(2, v / max * 20); c.fillStyle = '#5aa9f5'; c.fillRect(x, 22 - hh, 2, hh); } });
  return cv;
}
function chart() {
  const cv = $('#monchart'); if (!cv || !st.detail) return;
  const { ctx, w, h: hgt } = canvas(cv), pts = st.detail.history, L = 46, B = hgt - 24, T = 12;
  if (!pts.length) return;
  const t0 = pts[0][0], t1 = Math.max(pts[pts.length - 1][0], t0 + 60), max = Math.max(20, ...pts.map(p => p[1] || 0)) * 1.15;
  const x = t => L + (t - t0) / (t1 - t0) * (w - L - 10), y = v => B - v / max * (B - T);
  ctx.textAlign = 'right'; ctx.textBaseline = 'middle';
  for (let i = 0; i <= 4; i++) { ctx.strokeStyle = INK.grid; ctx.beginPath(); ctx.moveTo(L, y(max * i / 4)); ctx.lineTo(w - 10, y(max * i / 4)); ctx.stroke(); ctx.fillStyle = INK.axis; ctx.fillText(Math.round(max * i / 4) + ' ms', L - 6, y(max * i / 4)); }
  ctx.fillStyle = 'rgba(239,91,91,.55)';
  for (const [t, v] of pts) if (v == null) ctx.fillRect(x(t) - 1, T, 2.5, B - T);
  ctx.strokeStyle = '#5aa9f5'; ctx.lineWidth = 1.6; ctx.beginPath(); let pen = false;
  for (const [t, v] of pts) { if (v == null) { pen = false; continue; } pen ? ctx.lineTo(x(t), y(v)) : ctx.moveTo(x(t), y(v)); pen = true; }
  ctx.stroke(); ctx.lineWidth = 1;
  const lim = cfg().latency_ms; if (lim < max) { ctx.setLineDash([4, 4]); ctx.strokeStyle = '#e6c84f'; ctx.beginPath(); ctx.moveTo(L, y(lim)); ctx.lineTo(w - 10, y(lim)); ctx.stroke(); ctx.setLineDash([]); }
  ctx.textAlign = 'center'; ctx.textBaseline = 'top'; ctx.fillStyle = INK.axis;
  for (let i = 0; i <= 4; i++) { const t = t0 + (t1 - t0) * i / 4; ctx.fillText(clock(t), Math.max(L + 24, Math.min(w - 34, x(t))), B + 6); }
}

export function mount(el, arg) { root = el; if (arg?.key) picked = arg.key; tick(); timer = setInterval(tick, 5000); }
export const unmount = () => clearInterval(timer);

function render() {
  const ts = [...st.targets].sort((a, b) => (sort === 'state' ? state(a) - state(b) : 0) || (a.kind === 'internet' ? -1 : 0) - (b.kind === 'internet' ? -1 : 0) || a.name.localeCompare(b.name));
  const dev = ts.filter(t => t.kind !== 'internet'), net = ts.filter(t => t.kind === 'internet'), up = dev.filter(t => t.up).length, down = dev.filter(t => t.up === false).length;
  const inet = net.some(t => t.up) ? 'Up' : net.some(t => t.up === false) ? 'DOWN' : '…', inetMs = Math.min(...net.filter(t => t.last != null).map(t => t.last));
  const kpi = (v, l, cls) => h('div', { class: 'kpi' }, h('div', { class: 'v', style: cls ? `color:var(--${cls})` : '' }, v), h('div', { class: 'l' }, l));
  const num = (k, attrs) => h('input', { type: 'number', value: cfg()[k], ...attrs, onchange: e => saveSettings({ monitor: { [k]: +e.target.value } }) });
  const sel_ = st.targets.find(t => t.key === picked);
  root.replaceChildren(
    h('div', { class: 'kpis' }, kpi(inet, 'Internet', inet === 'Up' ? 'good' : inet === 'DOWN' ? 'bad' : ''), kpi(Number.isFinite(inetMs) ? inetMs.toFixed(0) + ' ms' : '—', 'Internet response time'),
      kpi(up, 'Devices answering', 'good'), kpi(down, 'Devices down', down ? 'bad' : ''), kpi(dev.filter(t => t.slow || t.lossy).length, 'Slow or losing packets', dev.some(t => t.slow || t.lossy) ? 'fair' : ''), kpi(dev.filter(t => t.up === null).length, 'Never answered')),
    h('div', { class: 'card' }, h('div', { class: 'row' },
      h('label', {}, h('input', { type: 'checkbox', checked: cfg().enabled, onchange: e => saveSettings({ monitor: { enabled: e.target.checked } }).then(tick) }), ' Monitoring on'),
      'Check every', num('interval', { min: 5, max: 3600 }), 'seconds', h('span', {}, 'Watch'), sel([['online', 'devices seen online'], ['authorized', 'authorized devices only'], ['all', 'every known device']], cfg().scope, v => saveSettings({ monitor: { scope: v } })),
      h('span', {}, 'Slow above'), num('latency_ms', { min: 5 }), 'ms', h('span', {}, 'Loss alert at'), num('loss_pct', { min: 1, max: 100 }), '%',
      h('span', { class: 'grow' }), h('button', { onclick: async () => { await api('/api/monitor', {}); setTimeout(tick, 2500); } }, 'Check now'),
      h('span', { class: 'dim' }, st.last_cycle ? `last check ${clock(st.last_cycle)}` : 'starting…'))),
    !dev.length ? h('div', { class: 'note' }, 'No devices to watch yet. Run "Scan my network" or "Import router list" in the Devices tab; every device with an IP address is then checked here automatically.') : null,
    sel_ ? h('div', { class: 'card' }, h('div', { class: 'row' }, h('h2', { class: 'grow', style: 'margin:0' }, `${sel_.name} · ${sel_.ip}`), h('span', { class: 'dim' }, `${sel_.samples} checks · red bars = no reply · dashed line = slow limit`),
      sel_.kind !== 'internet' ? h('button', { class: 'small', onclick: () => window.sursumGo('devices', { mac: sel_.key }) }, 'Open device') : null, h('button', { class: 'small', onclick: () => { picked = null; render(); } }, 'Close')), h('canvas', { id: 'monchart', class: 'chart short' })) : null,
    h('div', { class: 'tablewrap' }, h('table', {}, h('thead', {}, h('tr', {}, ['Status', 'Name', 'IP address', 'Now', 'Average (1 h)', 'Worst (1 h)', 'Loss (1 h)', 'Answered (all checks)', 'Recent', 'In this state since'].map(x => h('th', {}, x)))),
      h('tbody', {}, ts.map(t => h('tr', { class: t.key === picked ? 'sel' : '', style: 'cursor:pointer', onclick: () => { picked = t.key; tick(); } },
        h('td', {}, t.up === false ? h('span', { class: 'badge bad' }, 'Down') : t.up === null ? h('span', { class: 'badge' }, 'No reply yet') : t.slow ? h('span', { class: 'badge fair' }, 'Slow') : t.lossy ? h('span', { class: 'badge poor' }, 'Losing packets') : h('span', { class: 'badge good' }, 'Up')),
        h('td', {}, t.name, t.kind === 'gateway' ? h('span', { class: 'badge info', style: 'margin-left:6px' }, 'Router') : null), h('td', {}, t.ip),
        h('td', { class: 'num' }, t.last != null ? t.last.toFixed(t.last < 10 ? 1 : 0) + ' ms' : '—'), h('td', { class: 'num' }, t.avg != null ? t.avg + ' ms' : '—'), h('td', { class: 'num' }, t.max != null ? t.max + ' ms' : '—'),
        h('td', { class: 'num', style: t.loss >= cfg().loss_pct ? 'color:var(--bad)' : '' }, t.loss != null ? t.loss + ' %' : '—'), h('td', { class: 'num' }, t.uptime != null ? t.uptime + ' %' : '—'),
        h('td', {}, spark(t.spark)), h('td', {}, t.up === null ? '' : `${stamp(t.since)} (${duration(Date.now() / 1000 - t.since)})`)))))),
    h('div', { class: 'row', style: 'margin:14px 0 8px' }, h('h2', { class: 'grow', style: 'margin:0' }, `Events (${st.events.length})`),
      h('button', { onclick: () => download('monitor-events.csv', ['time,event,name,ip,detail', ...st.events.map(e => [new Date(e.t * 1000).toISOString(), e.kind, e.name, e.ip, e.text].map(csvCell).join(','))].join('\r\n'), 'text/csv') }, 'Export CSV'),
      h('button', { class: 'danger', onclick: async () => { if (confirm('Clear the event log?')) { await api('/api/monitor', { action: 'clear' }); tick(); } } }, 'Clear')),
    h('div', { class: 'tablewrap' }, h('table', {}, h('tbody', {}, st.events.length ? [...st.events].reverse().map(e => h('tr', {}, h('td', {}, stamp(e.t)), h('td', {}, h('span', { class: 'badge ' + KIND[e.kind][1] }, KIND[e.kind][0])), h('td', { class: 'wrap' }, e.text), h('td', {}, e.ip)))
      : h('tr', {}, h('td', { class: 'dim', style: 'padding:18px;text-align:center' }, 'No events yet. Devices going down, coming back, answering slowly or losing packets are logged here.'))))),
    h('p', { class: 'dim', style: 'margin-top:10px' }, 'Monitoring runs only while this program is open. A device counts as down after three missed checks in a row. Some phones and tablets do not answer these checks while asleep, so "No reply yet" or short "Down" periods on those are normal. Devices behind a different router than this PC cannot be reached and stay at "No reply yet".'));
  chart();
}
