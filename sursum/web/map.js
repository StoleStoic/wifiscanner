// Map: every access point and device, and which device is connected to which access point.
import { $, h, canvas, INK, SEV, AUTH, menu, sel } from './util.js';
import { S, nets, select, deviceAction, threatOf } from './state.js';
import { label } from './devices.js';

let root, scope = 'mine', focus = null, hits = [], hover = null;
const SOLID = ['this PC', 'capture', 'simulated'], SEVN = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };
const apColor = n => (n.threat === 'authorized' ? '#3ecf8e' : SEV[threatOf(n.bssid)?.severity] || '#8892a6');
const devColor = d => (d.sources.includes('lan') || d.authorized != null ? AUTH[d.authorized][1] : '#8892a6');

function model() {
  const all = nets(), byB = Object.fromEntries(all.map(n => [n.bssid, n]));
  const devs = S.devices.filter(d => scope === 'all' || d.sources.includes('lan') || byB[d.ap]?.threat === 'authorized');
  const need = new Set(devs.map(d => d.ap).filter(Boolean));
  let aps = all.filter(n => n.threat === 'authorized' || need.has(n.bssid) || scope === 'all' || n.threat === 'rogue');
  for (const b of need) if (!byB[b]) aps.push({ bssid: b, ssid: 'Not in range now', band: '?', channel: '?', ghost: true });
  return { aps, devs };
}

function draw() {
  const cv = $('#netmap'); if (!cv) return;
  const { aps, devs } = model(), ROW = 20, GAP = 14, wide = cv.parentElement.clientWidth;
  const mine = aps.filter(n => n.threat === 'authorized').sort((a, b) => a.bssid.localeCompare(b.bssid));
  const others = aps.filter(n => n.threat !== 'authorized').sort((a, b) => (SEVN[threatOf(a.bssid)?.severity] ?? 9) - (SEVN[threatOf(b.bssid)?.severity] ?? 9) || (a.ssid || '').localeCompare(b.ssid || ''));
  const loose = devs.filter(d => !d.ap || !aps.some(n => n.bssid === d.ap));
  // tree layout: hub -> your access points -> their devices; other access points in a second pair of columns
  const block = (n, list) => ({ n, list, hgt: Math.max(46, list.length * ROW + 12) });
  const colA = mine.map(n => block(n, devs.filter(d => d.ap === n.bssid)));
  if (loose.length || !mine.length) colA.push(block(null, loose));
  const colB = others.map(n => block(n, devs.filter(d => d.ap === n.bssid)));
  const total = col => col.reduce((a, b) => a + b.hgt + GAP, 0);
  cv.style.height = Math.max(cv.parentElement.clientHeight - 4, total(colA) + 40, total(colB) + 40) + 'px';
  const { ctx, w, h: hgt } = canvas(cv);
  hits = [];
  const X = { hub: 60, apA: 290, devA: 440, apB: Math.max(760, w * 0.58), devB: Math.max(910, w * 0.58 + 150) }, hubY = Math.max(60, total(colA) / 2 + 20);
  const curve = (x1, y1, x2, y2, col, dashed, hot) => { ctx.strokeStyle = col; ctx.lineWidth = hot ? 2.4 : 1.2; ctx.setLineDash(dashed ? [4, 4] : []); ctx.beginPath(); ctx.moveTo(x1, y1); ctx.bezierCurveTo((x1 + x2) / 2, y1, (x1 + x2) / 2, y2, x2, y2); ctx.stroke(); ctx.setLineDash([]); ctx.lineWidth = 1; };
  ctx.textBaseline = 'middle';
  const text = (t, x, y, col) => { const tw = ctx.measureText(t).width, x0 = ctx.textAlign === 'right' ? x - tw : x; ctx.fillStyle = 'rgba(22,27,46,.88)'; ctx.fillRect(x0 - 3, y - 7, tw + 6, 14); ctx.fillStyle = col; ctx.fillText(t, x, y); };
  const column = (col, xa, xd, fromHub, links) => {
    let y = 20;
    for (const b of col) {
      const cy = y + b.hgt / 2, n = b.n, hot = n && (focus === n.bssid || S.selected === n.bssid);
      if (links && fromHub) curve(X.hub + 22, hubY, xa - 13, cy, n ? 'rgba(62,207,142,.45)' : 'rgba(136,146,166,.45)', !n, false);
      b.list.forEach((d, i) => {
        const dy = y + 6 + ROW / 2 + i * ROW + Math.max(0, (b.hgt - 12 - b.list.length * ROW) / 2), dhot = focus === d.mac || (focus && focus === d.ap);
        if (links) { curve(xa + 13, cy, xd - 8, dy, dhot ? '#fff' : devColor(d), !n || !SOLID.includes(d.ap_source), dhot); return; }
        ctx.fillStyle = devColor(d); ctx.strokeStyle = focus === d.mac ? '#fff' : d.self ? '#5aa9f5' : '#0e1220'; ctx.lineWidth = focus === d.mac || d.self ? 2.5 : 1.5;
        ctx.beginPath(); ctx.arc(xd, dy, 6, 0, 7); ctx.fill(); ctx.stroke(); ctx.lineWidth = 1;
        ctx.textAlign = 'left'; ctx.fillStyle = focus === d.mac ? '#fff' : INK.text; const name = (d.name || d.hostname || d.model_guess || d.mac).slice(0, 30); ctx.fillText(name, xd + 12, dy);
        ctx.fillStyle = INK.dim; ctx.fillText(`${d.type === 'Unknown' ? 'unknown type' : d.type}${d.ips[0] ? ' · ' + d.ips[0] : ''}`, xd + 20 + ctx.measureText(name).width, dy);
        hits.push({ x: xd, y: dy, r: 9, dev: d });
      });
      if (links) { y += b.hgt + GAP; continue; }
      if (n) {
        ctx.fillStyle = n.ghost ? '#4a5270' : apColor(n); ctx.strokeStyle = hot ? '#fff' : '#0e1220'; ctx.lineWidth = hot ? 3 : 2;
        ctx.beginPath(); ctx.roundRect(xa - 12, cy - 12, 24, 24, 5); ctx.fill(); ctx.stroke(); ctx.lineWidth = 1;
        ctx.fillStyle = '#0e1220'; ctx.textAlign = 'center'; ctx.font = 'bold 10px system-ui'; ctx.fillText('AP', xa, cy + 1); ctx.font = '11px system-ui';
        ctx.textAlign = 'right'; text((n.ssid || '(hidden)').slice(0, 22), xa - 18, cy - 7, INK.text);
        text(n.ghost ? n.bssid : `${n.band} GHz ch ${n.channel} · ${n.rssi} dBm`, xa - 18, cy + 7, INK.dim);
        hits.push({ x: xa, y: cy, r: 15, ap: n });
      } else {
        ctx.strokeStyle = '#8892a6'; ctx.setLineDash([3, 3]); ctx.beginPath(); ctx.roundRect(xa - 12, cy - 12, 24, 24, 5); ctx.stroke(); ctx.setLineDash([]);
        ctx.textAlign = 'center'; ctx.fillStyle = INK.axis; ctx.fillText('?', xa, cy + 1);
        ctx.textAlign = 'right'; text('Access point', xa - 18, cy - 7, INK.axis); text('not known', xa - 18, cy + 7, INK.axis);
      }
      y += b.hgt + GAP;
    }
  };
  for (const links of [true, false]) { column(colA, X.apA, X.devA, true, links); column(colB, X.apB, X.devB, false, links); }
  ctx.fillStyle = '#1c2238'; ctx.strokeStyle = '#3ecf8e'; ctx.lineWidth = 2; ctx.beginPath(); ctx.arc(X.hub, hubY, 24, 0, 7); ctx.fill(); ctx.stroke(); ctx.lineWidth = 1;
  ctx.textAlign = 'center'; ctx.fillStyle = INK.text; ctx.fillText('My', X.hub, hubY - 6); ctx.fillText('network', X.hub, hubY + 7);
  if (colB.length) { ctx.textAlign = 'left'; ctx.fillStyle = INK.dim; ctx.fillText('OTHER ACCESS POINTS IN RANGE', X.apB - 110, 8); }
  $('#mapinfo').textContent = `${aps.length} access point(s), ${devs.length} device(s). ${loose.length} device(s) on your network have no known access point.`;
}

const hit = e => { const r = e.target.getBoundingClientRect(), mx = e.clientX - r.left, my = e.clientY - r.top; return [...hits].reverse().find(p => Math.hypot(p.x - mx, p.y - my) <= p.r); };
function tip(e) {
  const t = hit(e), box = $('#tip');
  if (!t) { box.hidden = true; e.target.style.cursor = 'default'; return; }
  e.target.style.cursor = 'pointer'; box.hidden = false; box.style.left = e.clientX + 14 + 'px'; box.style.top = e.clientY + 14 + 'px';
  if (t.dev) { const d = t.dev; box.textContent = `${label(d)}\n${d.type} · ${AUTH[d.authorized][0]}\n${d.vendor || 'Maker unknown'}\n${d.ips[0] || ''} ${d.mac}\n${d.ap ? 'Link: ' + ({ manual: 'set by you', capture: 'seen in a capture', 'this PC': 'reported by this PC', simulated: 'simulated' }[d.ap_source] || d.ap_source) : 'Access point unknown'}`; }
  else { const n = t.ap, th = threatOf(n.bssid); box.textContent = `${n.ssid || '(hidden)'}\n${n.bssid}\n${n.ghost ? 'Not in range now' : `${n.band} GHz ch ${n.channel} · ${n.rssi} dBm · ${n.security}`}\n${th ? th.label : ''}\n${S.devices.filter(d => d.ap === n.bssid).length} known device(s)`; }
}
function ctxMenu(e) {
  e.preventDefault(); const t = hit(e); if (!t) return;
  if (t.dev) { const d = t.dev; menu(e.clientX, e.clientY, [['Open in Devices', () => window.sursumGo('devices', { mac: d.mac })], null, ['Authorize', () => deviceAction('update', [d.mac], { authorized: true })], ['Not authorized', () => deviceAction('update', [d.mac], { authorized: false })], ['Unreviewed', () => deviceAction('update', [d.mac], { authorized: null })]]); }
  else { const n = t.ap; menu(e.clientX, e.clientY, [['Highlight its devices', () => { focus = n.bssid; draw(); }], ['Show in Scan', () => { select(n.bssid); window.sursumGo('scan'); }], ['Locate this access point', () => window.sursumGo('threats', { locate: n.bssid })]]); }
}

export function mount(el, arg) {
  root = el; el.className = 'fill';
  focus = arg?.mac || arg?.ap || null;
  if (arg?.ap || (arg?.mac && !S.devices.find(d => d.mac === arg.mac)?.sources.includes('lan'))) scope = 'all';
  el.append(
    h('div', { class: 'row', style: 'margin-bottom:8px' },
      h('div', { class: 'seg' }, [['mine', 'My network'], ['all', 'Everything in range']].map(([k, l]) => h('button', { id: 'sc-' + k, onclick: () => { scope = k; update(); } }, l))),
      h('span', { class: 'dim', id: 'mapinfo' }), h('span', { class: 'grow' }),
      [['#3ecf8e', 'Authorized'], ['#f0913a', 'Unreviewed'], ['#ef5b5b', 'Not authorized / rogue'], ['#8892a6', 'Other networks']].map(([c, l]) => h('span', {}, h('span', { class: 'dot', style: `background:${c}` }), l)),
      h('span', { class: 'dim' }, '■ access point  ● device  — observed link  ┄ assumed or set by you')),
    h('div', { class: 'card grow', style: 'margin:0;min-height:0;overflow:auto;padding:6px' }, h('canvas', { id: 'netmap', onmousemove: tip, onmouseleave: () => { $('#tip').hidden = true; }, oncontextmenu: ctxMenu,
      onclick: e => { const t = hit(e); if (t?.dev) window.sursumGo('devices', { mac: t.dev.mac }); else if (t?.ap) { focus = t.ap.bssid; select(t.ap.bssid); } else { focus = null; draw(); } } })),
    h('p', { class: 'dim', style: 'margin:8px 0 0' }, 'Left-click a device to open it; right-click anything for options. A link is drawn solid only when it was observed (this PC’s own connection, or a capture file). Windows cannot see from the air which device uses which access point, so devices without evidence hang off "My network" until you assign them in the Devices tab.'),
    h('div', { id: 'tip', hidden: true }));
  update();
}
export function update() { if (!root?.isConnected) return; for (const k of ['mine', 'all']) $('#sc-' + k).className = k === scope ? 'on' : ''; draw(); }
export const onDevices = update, onAnalysis = update, onSelect = update;
