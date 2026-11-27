// Threat view: classification of every AP, radar map, inventory management and the BSSID locator.
import { $, h, canvas, INK, SEV, AUTH, menu, download, pickFile, toast, color, sigClass, SIG, sameUnit } from './util.js';
import { S, nets, th, hist, saveSettings, select } from './state.js';
import { estimates } from './survey.js';

let root, locate = null, audio = null, lastBeep = 0, beepOn = false, peak = -200;
const CLS = { rogue: 'Rogue AP', unauthorized: 'Unauthorized AP', rogue_client: 'Unauthorized / unreviewed device', accidental: 'Accidental association',
  neighbor: 'Neighboring AP', authorized: 'Authorized (yours)', unclassified: 'Unclassified' };
const CLS_SEV = { rogue: 'Critical', unauthorized: 'High', rogue_client: 'High', accidental: 'Medium', neighbor: 'Low', authorized: 'Info' };
const inv = () => S.settings.inventory;

async function mark(bssids, kind, label) {
  const set = new Set(bssids), i = inv();
  const aps = i.aps.filter(a => !set.has(a.bssid)), neighbors = i.neighbors.filter(a => !set.has(a.bssid));
  const add = bssids.map(b => ({ bssid: b, label: label ?? (nets().find(n => n.bssid === b)?.ssid || '') }));
  if (kind === 'auth') aps.push(...add);
  if (kind === 'neighbor') neighbors.push(...add);
  await saveSettings({ inventory: { ...i, aps, neighbors } });
}

function hashAngle(b) { let x = 0; for (const c of b) x = (x * 33 + c.charCodeAt(0)) >>> 0; return (x % 3600) / 3600 * Math.PI * 2; }

function drawRadar(cv) {
  const { ctx, w, h: hgt } = canvas(cv), cx = w / 2, cy = hgt / 2, R = Math.min(w, hgt) / 2 - 22, maxD = 150;
  const r = d => R * Math.log(1 + Math.min(d, maxD)) / Math.log(1 + maxD);
  ctx.textAlign = 'left'; ctx.textBaseline = 'middle';
  for (const d of [5, 10, 20, 40, 80, 150]) {
    ctx.strokeStyle = INK.grid; ctx.beginPath(); ctx.arc(cx, cy, r(d), 0, 7); ctx.stroke();
    ctx.fillStyle = INK.dim; ctx.fillText(d + ' m', cx + 3, cy - r(d) + 7);
  }
  const per = S.threats.perimeter_m;
  ctx.setLineDash([5, 4]); ctx.strokeStyle = '#3ecf8e'; ctx.beginPath(); ctx.arc(cx, cy, r(per), 0, 7); ctx.stroke(); ctx.setLineDash([]);
  ctx.fillStyle = '#3ecf8e'; ctx.fillText('home perimeter', cx + r(per) * 0.72, cy + r(per) * 0.72 + 8);
  ctx.fillStyle = INK.text; ctx.beginPath(); ctx.arc(cx, cy, 4, 0, 7); ctx.fill(); ctx.fillText('This PC', cx + 8, cy);
  const est = estimates(), hits = [];
  for (const t of [...S.threats.aps].reverse()) {
    const e = est[t.bssid];
    const a = e ? Math.atan2(e.dy, e.dx) : hashAngle(t.bssid), px = cx + r(t.distance.m) * Math.cos(a), py = cy + r(t.distance.m) * Math.sin(a);
    const col = t.cls === 'authorized' ? '#3ecf8e' : SEV[t.severity], big = t.cls === 'rogue' || t.bssid === S.selected;
    if (t.cls === 'rogue' || t.cls === 'unauthorized') {  // threat vector from the PC
      ctx.strokeStyle = col; ctx.globalAlpha = 0.45; ctx.beginPath(); ctx.moveTo(cx, cy); ctx.lineTo(px, py); ctx.stroke(); ctx.globalAlpha = 1;
    }
    ctx.fillStyle = col; ctx.beginPath(); ctx.arc(px, py, big ? 7 : 4.5, 0, 7); ctx.fill();
    if (e) { ctx.strokeStyle = INK.text; ctx.lineWidth = 1.5; ctx.stroke(); ctx.lineWidth = 1; }
    if (big || t.severity !== 'Low' && t.cls !== 'unclassified') { ctx.fillStyle = INK.text; ctx.fillText(t.ssid || '(hidden)', px + 9, py); }
    // little dots: the devices known to use this access point
    S.devices.filter(d => d.ap === t.bssid).slice(0, 14).forEach((d, i, arr) => {
      const da = a + Math.PI + (i - (arr.length - 1) / 2) * 0.5, dx = px + 15 * Math.cos(da), dy = py + 15 * Math.sin(da);
      ctx.fillStyle = d.sources.includes('lan') || d.sources.includes('router') || d.authorized != null ? AUTH[d.authorized][1] : '#8892a6';
      ctx.beginPath(); ctx.arc(dx, dy, 2.6, 0, 7); ctx.fill();
    });
    hits.push({ px, py, b: t.bssid });
  }
  cv._hit = (mx, my) => hits.find(p => Math.hypot(p.px - mx, p.py - my) < 9)?.b;
}

function beep(rssi) {
  if (!beepOn) return;
  audio ||= new (window.AudioContext || window.webkitAudioContext)();
  const o = audio.createOscillator(), g = audio.createGain();
  o.frequency.value = 400 + Math.max(0, rssi + 95) * 18; g.gain.value = 0.08;
  o.connect(g).connect(audio.destination); o.start(); o.stop(audio.currentTime + 0.09);
}
function locatorTick() {
  if (!locate || !root?.isConnected) return;
  const n = nets().find(x => x.bssid === locate);
  if (n && beepOn) {
    const gap = 1500 - Math.max(0, Math.min(60, n.rssi + 95)) * 22;  // closer = faster
    if (performance.now() - lastBeep > gap) { lastBeep = performance.now(); beep(n.rssi); }
  }
  setTimeout(locatorTick, 120);
}

function locator() {
  const n = nets().find(x => x.bssid === locate), box = $('#locator');
  if (!box) return;
  if (!locate) return box.replaceChildren();
  const hs = hist(locate).slice(-40), t = th();
  if (n) peak = Math.max(peak, n.rssi);
  const stale = n ? S.now - n.last_seen > 12 : true, trend = hs.length > 3 ? hs[hs.length - 1][1] - hs[hs.length - 4][1] : 0;
  box.replaceChildren(h('div', { class: 'card' },
    h('div', { class: 'row' }, h('h2', { class: 'grow', style: 'margin:0' }, 'Locate: ', n?.ssid || '(hidden)', h('span', { class: 'dim' }, '  ' + locate)),
      h('label', {}, h('input', { type: 'checkbox', checked: beepOn, onchange: e => { beepOn = e.target.checked; beep(n?.rssi ?? -70); } }), ' Sound (faster and higher = closer)'),
      h('button', { onclick: () => { peak = -200; locator(); } }, 'Reset peak'), h('button', { onclick: () => { locate = null; beepOn = false; locator(); } }, 'Stop')),
    h('div', { class: 'row', style: 'margin-top:10px;gap:28px' },
      h('div', {}, h('div', { class: 'big', style: `color:${n && !stale ? SIG[sigClass(n.rssi, t)] : 'var(--dim)'}` }, n ? n.rssi : '—'), h('div', { class: 'dim' }, stale ? 'dBm · not heard in the last scans' : 'dBm now')),
      h('div', {}, h('div', { class: 'big', style: 'font-size:36px' }, peak > -200 ? peak : '—'), h('div', { class: 'dim' }, 'peak dBm')),
      h('div', {}, h('div', { class: 'big', style: 'font-size:36px' }, trend > 1.5 ? '▲ warmer' : trend < -1.5 ? '▼ colder' : '• steady'), h('div', { class: 'dim' }, 'trend')),
      h('div', {}, h('div', { class: 'big', style: 'font-size:36px' }, n?.distance != null ? `~${n.distance} m` : '—'), h('div', { class: 'dim' }, 'rough distance')),
      h('canvas', { id: 'loccv', class: 'grow', style: 'height:110px;min-width:240px' })),
    h('p', { class: 'dim' }, 'Carry the laptop and walk slowly; pause a few seconds between steps because Windows refreshes signal readings every few seconds. Move in the direction that gets warmer. The signal peaks when you are next to the device.')));
  const cv = $('#loccv'), { ctx, w, h: hgt } = canvas(cv);
  if (hs.length > 1) {
    ctx.strokeStyle = color(locate); ctx.lineWidth = 2; ctx.beginPath();
    hs.forEach((p, i) => { const x = i / (hs.length - 1) * (w - 4) + 2, y = 4 + (Math.min(-20, Math.max(-100, p[1])) + 20) / -80 * (hgt - 8); i ? ctx.lineTo(x, y) : ctx.moveTo(x, y); });
    ctx.stroke();
  }
}

export function mount(el, arg) {
  root = el;
  if (arg?.locate) { locate = arg.locate; peak = -200; }
  el.append(h('div', { id: 'locator' }), h('div', { id: 'thbody' }));
  render(); locatorTick();
}
export const update = () => { if (root?.isConnected) { locator(); if ($('#radar')) drawRadar($('#radar')); } };
export const onAnalysis = () => root?.isConnected && render();
export const onSelect = () => root?.isConnected && render();
export const onDevices = () => root?.isConnected && $('#radar') && drawRadar($('#radar'));

const WEAKSEC = ['Open', 'WEP'];
const picked = new Set();
let showAll = false;
const isAuth = b => inv().aps.some(a => a.bssid === b);
// every radio that belongs to the same physical units as the given access points
const withSiblings = list => { const all = nets(), out = new Set(list.map(n => n.bssid)); for (const n of all) if (list.some(m => sameUnit(m.bssid, n.bssid))) out.add(n.bssid); return [...out]; };

async function claim(ssid, group) {
  // An unencrypted copy of an otherwise protected network is the classic evil twin: never auto-authorize it.
  const ok = group.some(n => !WEAKSEC.includes(n.security)) ? group.filter(n => !WEAKSEC.includes(n.security)) : group;
  const ids = withSiblings(ok).filter(b => !WEAKSEC.includes(nets().find(n => n.bssid === b)?.security) || ok.some(n => n.bssid === b));
  await saveSettings({ home: { ssids: [...new Set([...S.settings.home.ssids, ssid])] } });
  await mark(ids, 'auth');
  toast(`Authorized ${ids.length} radio(s) for "${ssid}"` + (ids.length > ok.length ? `, including ${ids.length - ok.length} hidden or extra network(s) on the same units.` : '.') +
    (ok.length < group.length ? ` ${group.length - ok.length} with that name but no encryption was left out and stays flagged.` : ''));
}
async function disown(ssid, group) {
  await saveSettings({ home: { ssids: S.settings.home.ssids.filter(x => x !== ssid) } });
  await mark(group.map(n => n.bssid), 'none');
}

// "Your networks": always available, so access points can be added or removed at any time.
function setup() {
  const groups = {}, home = new Set(S.threats.home_ssids);
  for (const n of nets()) if (n.ssid) (groups[n.ssid] ||= []).push(n);
  for (const s of home) groups[s] ||= [];
  const mineSsid = S.conn?.ssid, best = g => Math.max(-200, ...g.map(n => n.rssi));
  let list = Object.entries(groups).sort((a, b) => home.has(b[0]) - home.has(a[0]) || (b[0] === mineSsid) - (a[0] === mineSsid) || best(b[1]) - best(a[1]));
  const hiddenCount = list.length; if (!showAll) list = list.filter(([s], i) => home.has(s) || i < 10);
  const siblings = S.threats.aps.filter(t => t.label === 'Unlisted radio of your AP').map(t => t.bssid);
  return h('div', { class: 'card' }, h('h2', {}, S.threats.configured ? 'Your networks' : 'Step 1: tell the scanner which networks are yours'),
    h('p', { class: 'dim' }, 'Click "These are mine" for each of your own network names. That authorizes every access point currently broadcasting the name, plus the hidden and extra networks on the same units. Do it at home, when only your real equipment carries those names. Individual access points can also be set with the Mine / Neighbor buttons in the table below, or by right-clicking a row in the Scan tab.'),
    h('div', { class: 'tablewrap' }, h('table', {}, h('tbody', {}, list.map(([ssid, g]) => {
      const a = g.filter(n => isAuth(n.bssid)).length, weak = g.filter(n => WEAKSEC.includes(n.security)).length;
      return h('tr', {}, h('td', {}, h('b', {}, ssid), ssid === mineSsid ? h('span', { class: 'badge good', style: 'margin-left:6px' }, 'connected') : null),
        h('td', {}, g.length ? `${g.length} access point radio(s) in range, strongest ${best(g)} dBm` : 'not in range right now'),
        h('td', {}, a === g.length && g.length ? h('span', { class: 'badge good' }, 'all authorized') : a ? h('span', { class: 'badge fair' }, `${a} of ${g.length} authorized`) : home.has(ssid) ? h('span', { class: 'badge poor' }, 'named as yours, none authorized') : h('span', { class: 'dim' }, 'not yours'),
          weak ? h('span', { class: 'badge bad', style: 'margin-left:6px' }, `${weak} without encryption`) : null),
        h('td', {}, g.length && a < g.length - (g.some(n => !WEAKSEC.includes(n.security)) ? weak : 0) ? h('button', { class: 'small primary', onclick: () => claim(ssid, g) }, a ? `Authorize the other ${g.length - a - weak}` : 'These are mine') : null, ' ',
          a || home.has(ssid) ? h('button', { class: 'small', onclick: () => disown(ssid, g) }, 'Not mine') : null));
    })))),
    h('div', { class: 'row', style: 'margin-top:8px' },
      siblings.length ? h('button', { class: 'primary', onclick: async () => { await mark(siblings, 'auth'); toast(`Added ${siblings.length} radio(s).`); } }, `Add all radios of my access points (${siblings.length})`) : null,
      hiddenCount > list.length || showAll ? h('button', { onclick: () => { showAll = !showAll; render(); } }, showAll ? 'Show fewer networks' : `Show all ${hiddenCount} network names`) : null));
}

function render() {
  const T = S.threats, body = $('#thbody');
  if (!T || !body) return;
  const c = T.counts, kpi = (k) => h('div', { class: 'kpi' }, h('div', { class: 'v sev-' + CLS_SEV[k] }, c[k] || 0), h('div', { class: 'l' }, CLS[k]));
  const act = t => h('td', {},
    t.cls !== 'authorized' ? h('button', { class: 'small', onclick: () => mark([t.bssid], 'auth') }, 'Mine') : null, ' ',
    !(t.cls === 'neighbor' && S.settings.inventory.neighbors.some(a => a.bssid === t.bssid)) && t.cls !== 'authorized' ? h('button', { class: 'small', onclick: () => mark([t.bssid], 'neighbor') }, 'Neighbor') : null, ' ',
    inv().aps.concat(inv().neighbors).some(a => a.bssid === t.bssid) ? h('button', { class: 'small', onclick: () => mark([t.bssid], 'none') }, 'Unmark') : null, ' ',
    h('button', { class: 'small', onclick: () => { locate = t.bssid; peak = -200; select(t.bssid); locator(); scrollTo(0, 0); $('#main').scrollTop = 0; } }, 'Locate'));
  body.replaceChildren(
    setup(),
    h('div', { class: 'kpis' }, ['rogue', 'unauthorized', 'rogue_client', 'accidental', 'neighbor', 'authorized'].map(kpi)),
    [...T.events, ...T.clients].map(e => h('div', { class: 'note', style: `border-color:${SEV[e.severity]}` },
      h('div', { class: 't sev-' + e.severity }, `${e.severity}: ${e.label}`, e.cls === 'rogue_client' ? ` — ${e.hostname || e.type || ''} ${e.ip || ''} (${e.mac}) ${e.vendor || ''}` : ''),
      h('div', {}, e.reasons.join(' '), e.mac ? h('a', { href: '#', style: 'margin-left:8px', onclick: ev => { ev.preventDefault(); window.sursumGo('devices', { mac: e.mac }); } }, 'Open device') : null))),
    h('div', { class: 'grid2' },
      h('div', { class: 'card' }, h('h2', {}, 'Threat vector map'),
        h('canvas', { id: 'radar', style: 'height:420px', oncontextmenu: e => {
          e.preventDefault(); const r = e.target.getBoundingClientRect(), b = e.target._hit?.(e.clientX - r.left, e.clientY - r.top); if (!b) return;
          const n = S.devices.filter(d => d.ap === b).length;
          menu(e.clientX, e.clientY, [[`Show devices (${n})`, () => window.sursumGo('map', { ap: b })], ['Locate this access point', () => { locate = b; peak = -200; select(b); locator(); $('#main').scrollTop = 0; }], null,
            ['Mark as mine', () => mark([b], 'auth')], ['Mark as neighbor', () => mark([b], 'neighbor')], ['Show in Scan', () => { select(b); window.sursumGo('scan'); }]]);
        }, onclick: e => { const r = e.target.getBoundingClientRect(), b = e.target._hit?.(e.clientX - r.left, e.clientY - r.top); if (b) select(b); } }),
        h('p', { class: 'dim' }, 'Small dots next to an access point are the devices known to use it; right-click an access point and choose Show devices to see them on the Map. Distance from this PC is estimated from signal strength (walls can easily double or halve it). Direction is only real for outlined dots, which were located from a walk-through Survey; a single WiFi adapter cannot sense direction, so other dots are placed at an arbitrary angle. Use Locate to find a device.')),
      h('div', { class: 'card' }, h('h2', {}, 'How access points are classified'),
        [['Critical', 'Rogue access point', 'Uses your network name from an unknown radio (evil twin), or its address matches a device on your own LAN.'],
          ['High', 'Unauthorized access point', 'Unknown AP estimated inside your home perimeter. Becomes rogue if tied to your network.'],
          ['High', 'Rogue client', 'A device on your network that you marked as not authorized (Medium while still unreviewed).'],
          ['Medium', 'Accidental association', 'This PC is connected to an AP that is not on your authorized list.'],
          ['Low', 'Neighboring access point', 'Outside your perimeter, or marked by you as a known neighbor.']].map(([s, t, d]) =>
          h('p', {}, h('b', { class: 'sev-' + s }, `${s} · ${t}. `), h('span', { class: 'dim' }, d))),
        h('h3', {}, 'Authorized inventory'),
        h('p', { class: 'dim' }, `${inv().aps.length} authorized AP(s), ${inv().neighbors.length} known neighbor(s). Home network name(s): ${T.home_ssids.join(', ') || 'none yet'}.`),
        h('div', { class: 'row' },
          h('button', { onclick: () => download('ap-inventory.csv', ['class,severity,ssid,bssid,vendor,band,channel,rssi_dbm,est_distance_m,security,reason',
            ...T.aps.map(t => [t.cls, t.severity, t.ssid, t.bssid, t.vendor, t.band, t.channel, t.rssi, t.distance.m, t.security, t.reasons.join(' ')].map(v => `"${String(v ?? '').replace(/"/g, '""')}"`).join(','))].join('\r\n'), 'text/csv') }, 'Export detected APs (CSV)'),
          h('button', { title: 'CSV with one BSSID per line, optionally followed by a label', onclick: async () => {
            const f = await pickFile('.csv,.txt'); if (!f) return;
            const found = [...(await f.text()).matchAll(/((?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2})[",;\t ]*([^",;\r\n]*)/gi)].map(m => ({ bssid: m[1].toLowerCase().replace(/-/g, ':'), label: m[2].trim() }));
            if (!found.length) return toast('No BSSIDs found in that file.', true);
            await saveSettings({ inventory: { ...inv(), aps: [...inv().aps.filter(a => !found.some(x => x.bssid === a.bssid)), ...found] } });
            toast(`Imported ${found.length} authorized AP(s).`);
          } }, 'Import authorized list (CSV)'),
          inv().aps.length ? h('button', { class: 'danger', onclick: () => confirm('Clear your authorized and neighbor lists?') && saveSettings({ inventory: { ...inv(), aps: [], neighbors: [] }, home: { ssids: [] } }) }, 'Reset inventory') : null))),
    picked.size ? h('div', { class: 'filterbar' }, h('b', {}, `${picked.size} selected:`),
      h('button', { onclick: () => mark([...picked], 'auth').then(() => picked.clear()) }, 'Mark as mine'), h('button', { onclick: () => mark([...picked], 'neighbor').then(() => picked.clear()) }, 'Mark as neighbor'),
      h('button', { onclick: () => mark([...picked], 'none').then(() => picked.clear()) }, 'Unmark'), h('button', { onclick: () => { picked.clear(); render(); } }, 'Clear selection')) : null,
    h('div', { class: 'tablewrap' }, h('table', {}, h('thead', {}, h('tr', {}, [h('input', { type: 'checkbox', title: 'Select all', checked: T.aps.length && T.aps.every(t => picked.has(t.bssid)), onchange: e => { T.aps.forEach(t => (e.target.checked ? picked.add(t.bssid) : picked.delete(t.bssid))); render(); } }), 'Severity', 'Class', 'SSID', 'BSSID', 'Vendor', 'Band / ch', 'Signal', 'Est. distance', 'Security', 'Why', 'Actions'].map(x => h('th', {}, x)))),
      h('tbody', {}, T.aps.map(t => h('tr', { class: t.bssid === S.selected ? 'sel' : '', onclick: e => !['BUTTON', 'INPUT'].includes(e.target.tagName) && select(t.bssid) },
        h('td', {}, h('input', { type: 'checkbox', checked: picked.has(t.bssid), onchange: e => { e.target.checked ? picked.add(t.bssid) : picked.delete(t.bssid); render(); } })),
        h('td', { class: 'sev-' + t.severity }, h('b', {}, t.severity)), h('td', {}, t.label), h('td', {}, t.ssid || '(hidden)'), h('td', {}, t.bssid), h('td', {}, t.vendor),
        h('td', {}, `${t.band} GHz / ${t.channel}`), h('td', { class: 'num' }, t.rssi + ' dBm'), h('td', { class: 'num' }, `~${t.distance.m} m`),
        h('td', {}, t.security), h('td', { class: 'wrap dim' }, t.reasons.join(' ')), act(t)))))));
  drawRadar($('#radar')); locator();
}

export { mark };
