// Walk-through survey: floor plan, calibration, passive/active points, heatmaps and AP position estimates.
import { $, h, api, sel, toast, pickFile, download, color, INK, SEV } from './util.js';
import { S, nets, conn } from './state.js';

let doc = { surveys: [] }, cur = null, root, img = null, calib = null, mode = 'passive', withSpeed = false, busy = false;
let metric = 'ssid', target = '', range = { lo: -85, hi: -45 }, opacity = 0.6, showEst = true;
api('/api/surveys').then(d => { doc = d.surveys ? d : { surveys: [] }; cur = doc.surveys[doc.surveys.length - 1] || null; });
const save = () => api('/api/surveys', doc);
const isSpeed = () => metric === 'down' || metric === 'up';

function value(p) {
  const r = p.readings || {};
  if (metric === 'ssid') { const v = Object.keys(r).filter(b => p.names?.[b] === target).map(b => r[b]); return v.length ? Math.max(...v) : null; }
  if (metric === 'bssid') return r[target] ?? null;
  if (metric === 'best') { const v = Object.values(r); return v.length ? Math.max(...v) : null; }
  if (metric === 'conn') return p.conn?.rssi ?? null;
  return p.speed ? (metric === 'down' ? p.speed.download : p.speed.upload) ?? null : null;
}
function ramp(t) {  // 0 = bad (red) .. 1 = good (green)
  t = Math.max(0, Math.min(1, t));
  const stops = [[239, 91, 91], [240, 145, 58], [230, 200, 79], [62, 207, 142], [56, 150, 255]], x = t * (stops.length - 1), i = Math.min(stops.length - 2, Math.floor(x)), f = x - i;
  return stops[i].map((c, k) => Math.round(c + (stops[i + 1][k] - c) * f));
}

// Best-fit position per BSSID from all survey points (log-distance model, grid search that may land outside the plan).
export function estimates(s = cur) {
  const out = {};
  if (!s || !s.mpp || s.points.length < 3) return out;
  const n = S.settings?.home?.path_loss_exp || 3, home = S.settings?.home || {}, by = {};
  for (const p of s.points) for (const [b, r] of Object.entries(p.readings || {})) (by[b] ||= []).push([p.x, p.y, r]);
  const th = (s.north || 0) * Math.PI / 180;
  for (const [b, pts] of Object.entries(by)) {
    const rs = pts.map(p => p[2]);
    if (pts.length < 3 || Math.max(...rs) - Math.min(...rs) < 8) continue;  // no usable gradient
    let best = null;
    const G = 48, x0 = -s.w, x1 = 2 * s.w, y0 = -s.h, y1 = 2 * s.h;
    for (let i = 0; i <= G; i++) for (let j = 0; j <= G; j++) {
      const x = x0 + (x1 - x0) * i / G, y = y0 + (y1 - y0) * j / G;
      const pred = pts.map(p => -10 * n * Math.log10(Math.max(0.7, Math.hypot(p[0] - x, p[1] - y) * s.mpp)));
      const A = pts.reduce((a, p, k) => a + p[2] - pred[k], 0) / pts.length;
      const err = pts.reduce((a, p, k) => a + (p[2] - A - pred[k]) ** 2, 0);
      if (!best || err < best.err) best = { x, y, err };
    }
    const dx = (best.x - s.w / 2) * s.mpp, dy = (best.y - s.h / 2) * s.mpp, up = -dy;
    const e = { x: best.x, y: best.y, dx, dy, n: pts.length, rms: Math.sqrt(best.err / pts.length), outside: best.x < 0 || best.y < 0 || best.x > s.w || best.y > s.h };
    if (home.lat != null && home.lon != null && home.lat !== '') {
      const north = up * Math.cos(th) - dx * Math.sin(th), east = up * Math.sin(th) + dx * Math.cos(th);
      e.lat = +home.lat + north / 111320; e.lon = +home.lon + east / (111320 * Math.cos(+home.lat * Math.PI / 180));
    }
    out[b] = e;
  }
  return out;
}

function draw() {
  const cv = $('#plan'); if (!cv || !cur) return;
  const s = cur, ctx = cv.getContext('2d');
  cv.width = s.w; cv.height = s.h;
  if (img) ctx.drawImage(img, 0, 0, s.w, s.h);
  else {
    ctx.fillStyle = '#10152a'; ctx.fillRect(0, 0, s.w, s.h); ctx.strokeStyle = 'rgba(255,255,255,.08)';
    const step = 1 / s.mpp;
    for (let x = 0; x < s.w; x += step) { ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, s.h); ctx.stroke(); }
    for (let y = 0; y < s.h; y += step) { ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(s.w, y); ctx.stroke(); }
    ctx.fillStyle = INK.dim; ctx.font = '12px system-ui'; ctx.fillText('1 m grid — upload a floor plan image for a real map', 10, 18);
  }
  const pts = s.points.map(p => [p.x, p.y, value(p)]).filter(p => p[2] != null);
  if (pts.length) {
    const cell = Math.max(4, Math.round(s.w / 160)), gw = Math.ceil(s.w / cell), gh = Math.ceil(s.h / cell);
    const off = new OffscreenCanvas(gw, gh), octx = off.getContext('2d'), im = octx.createImageData(gw, gh);
    const reach = s.mpp ? 7 / s.mpp : Math.hypot(s.w, s.h) * 0.22;
    for (let j = 0; j < gh; j++) for (let i = 0; i < gw; i++) {
      const x = (i + 0.5) * cell, y = (j + 0.5) * cell; let num = 0, den = 0, near = 1e9;
      for (const p of pts) { const d = Math.hypot(p[0] - x, p[1] - y) + 1; near = Math.min(near, d); const wgt = 1 / (d * d); num += p[2] * wgt; den += wgt; }
      const c = ramp((num / den - range.lo) / (range.hi - range.lo)), k = (j * gw + i) * 4;
      im.data[k] = c[0]; im.data[k + 1] = c[1]; im.data[k + 2] = c[2];
      im.data[k + 3] = 255 * opacity * Math.max(0, Math.min(1, 1.6 - near / reach));
    }
    octx.putImageData(im, 0, 0);
    ctx.imageSmoothingEnabled = true; ctx.drawImage(off, 0, 0, s.w, s.h);
  }
  const u = isSpeed() ? '' : '';
  ctx.font = `${Math.max(11, s.w / 90)}px system-ui`; ctx.textAlign = 'center';
  s.points.forEach((p, i) => {
    const v = value(p), r = Math.max(5, s.w / 180);
    ctx.fillStyle = v == null ? '#667089' : `rgb(${ramp((v - range.lo) / (range.hi - range.lo))})`;
    ctx.strokeStyle = '#fff'; ctx.lineWidth = 2; ctx.beginPath(); ctx.arc(p.x, p.y, r, 0, 7); ctx.fill(); ctx.stroke();
    ctx.fillStyle = '#fff'; ctx.strokeStyle = '#000'; ctx.lineWidth = 3;
    const txt = v == null ? '–' : Math.round(v) + u; ctx.strokeText(txt, p.x, p.y - r - 4); ctx.fillText(txt, p.x, p.y - r - 4);
    if (p.pending) { ctx.fillText('testing…', p.x, p.y + r + 14); }
  });
  if (showEst) {
    const est = estimates(s);
    for (const [b, e] of Object.entries(est)) {
      const t = S.threats?.aps.find(x => x.bssid === b); if (!t) continue;
      if (metric === 'bssid' ? b !== target : metric === 'ssid' ? t.ssid !== target : t.cls !== 'rogue' && t.cls !== 'unauthorized' && t.cls !== 'authorized') continue;
      const x = Math.max(14, Math.min(s.w - 14, e.x)), y = Math.max(14, Math.min(s.h - 14, e.y)), r = Math.max(8, s.w / 110);
      ctx.fillStyle = t.cls === 'authorized' ? '#3ecf8e' : SEV[t.severity]; ctx.strokeStyle = '#000'; ctx.lineWidth = 2;
      ctx.beginPath(); ctx.moveTo(x, y - r); ctx.lineTo(x + r, y); ctx.lineTo(x, y + r); ctx.lineTo(x - r, y); ctx.closePath(); ctx.fill(); ctx.stroke();
      ctx.fillStyle = '#fff'; ctx.lineWidth = 3;
      const lab = (t.ssid || b) + (e.outside ? ' (outside plan)' : '');
      ctx.strokeText(lab, x, y + r + 14); ctx.fillText(lab, x, y + r + 14);
    }
  }
  if (calib) { ctx.fillStyle = '#5aa9f5'; calib.forEach(c => { ctx.beginPath(); ctx.arc(c[0], c[1], 6, 0, 7); ctx.fill(); }); }
}

async function loadImage() {
  img = null;
  if (cur?.image) { const i = new Image(); i.src = cur.image; await i.decode().catch(() => {}); img = i; }
}

async function addPoint(x, y) {
  if (busy) return toast('Wait for the current measurement to finish.');
  const c = conn(), live = nets();
  if (!live.length) return toast('No scan data yet.', true);
  const p = { x, y, t: Date.now() / 1000, mode, readings: Object.fromEntries(live.filter(n => S.now - n.last_seen < 15 || S.loaded).map(n => [n.bssid, n.rssi])),
    names: Object.fromEntries(live.map(n => [n.bssid, n.ssid])), conn: c ? { bssid: c.bssid, ssid: c.ssid, rssi: c.rssi, rx: c.rx_rate, tx: c.tx_rate } : null };
  cur.points.push(p);
  if (mode === 'active' && withSpeed) {
    busy = true; p.pending = true; draw();
    await api('/api/speedtest', { trigger: 'survey' });
    let st; do { await new Promise(r => setTimeout(r, 1000)); st = await api('/api/speedtest'); } while (st.running);
    const last = st.history[st.history.length - 1];
    if (last && !last.error) p.speed = { download: last.download, upload: last.upload, ping: last.ping };
    delete p.pending; busy = false;
  }
  await save(); render();
}

function click(e) {
  const cv = e.target, r = cv.getBoundingClientRect(), x = (e.clientX - r.left) * cv.width / r.width, y = (e.clientY - r.top) * cv.height / r.height;
  if (calib) {
    calib.push([x, y]); draw();
    if (calib.length === 2) {
      const m = parseFloat(prompt('Real distance between the two points you clicked, in metres (1 m = 3.28 ft):', '5'));
      if (m > 0) { cur.mpp = m / Math.hypot(calib[1][0] - calib[0][0], calib[1][1] - calib[0][1]); save(); toast(`Calibrated: plan is ${(cur.w * cur.mpp).toFixed(1)} m wide.`); }
      calib = null; render();
    }
    return;
  }
  addPoint(x, y);
}

async function create(withImage) {
  const name = prompt('Name for this survey (for example "Ground floor"):', 'My home'); if (!name) return;
  const s = { id: Date.now(), name, image: null, w: 1200, h: 800, mpp: 20 / 1200, north: 0, points: [] };
  if (withImage) {
    const f = await pickFile('image/*'); if (!f) return;
    const bmp = await createImageBitmap(f), k = Math.min(1, 1600 / Math.max(bmp.width, bmp.height));
    const c = h('canvas', {}); c.width = Math.round(bmp.width * k); c.height = Math.round(bmp.height * k);
    c.getContext('2d').drawImage(bmp, 0, 0, c.width, c.height);
    Object.assign(s, { image: c.toDataURL('image/jpeg', 0.85), w: c.width, h: c.height, mpp: null });
  }
  doc.surveys.push(s); cur = s; await save(); await loadImage(); render();
  if (withImage) toast('Plan loaded. Next: click Calibrate and mark two points a known distance apart.');
}

export async function mount(el) { root = el; await loadImage(); render(); }
export const onAnalysis = () => root?.isConnected && draw();

function render() {
  if (!root?.isConnected) return;
  const s = cur;
  if (!s) return root.replaceChildren(h('div', { class: 'card' }, h('h2', {}, 'WiFi survey'),
    h('p', {}, 'Walk around your home and click your position on a floor plan. Each click records every network heard at that spot, and the result is drawn as a coverage heatmap.'),
    h('div', { class: 'row' }, h('button', { class: 'primary', onclick: () => create(true) }, 'Start with a floor plan image'), h('button', { onclick: () => create(false) }, 'Start with a blank 20 × 13 m grid'))));
  const ssids = [...new Set(s.points.flatMap(p => Object.values(p.names || {})).concat(nets().map(n => n.ssid)).filter(Boolean))].sort();
  const bssids = [...new Set(s.points.flatMap(p => Object.keys(p.readings || {})).concat(nets().map(n => n.bssid)))];
  const nameOf = b => { for (const p of s.points) if (p.names?.[b] != null) return p.names[b]; return nets().find(n => n.bssid === b)?.ssid || ''; };
  if (metric === 'ssid' && !ssids.includes(target)) target = conn()?.ssid && ssids.includes(conn().ssid) ? conn().ssid : ssids[0] || '';
  if (metric === 'bssid' && !bssids.includes(target)) target = S.selected && bssids.includes(S.selected) ? S.selected : bssids[0] || '';
  const setMetric = v => { metric = v; range = v === 'down' ? { lo: 0, hi: 500 } : v === 'up' ? { lo: 0, hi: 50 } : { lo: -85, hi: -45 }; render(); };
  const est = estimates(s), num = (k) => h('input', { type: 'number', value: range[k], onchange: e => { range[k] = +e.target.value; draw(); } });
  const estRows = Object.entries(est).map(([b, e]) => ({ b, e, t: S.threats?.aps.find(x => x.bssid === b) })).filter(x => x.t).sort((a, b) => ({ Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 }[a.t.severity] - { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 }[b.t.severity]));
  root.replaceChildren(
    h('div', { class: 'row', style: 'margin-bottom:10px' },
      sel(doc.surveys.map(x => [x.id, x.name]), s.id, async v => { cur = doc.surveys.find(x => x.id == v); await loadImage(); render(); }),
      h('button', { onclick: () => create(true) }, 'New from image'), h('button', { onclick: () => create(false) }, 'New blank'),
      h('div', { class: 'seg' }, ['passive', 'active'].map(m => h('button', { class: mode === m ? 'on' : '', title: m === 'passive' ? 'Record every network heard at each point' : 'Also record the connected link (and optionally a speed test) at each point', onclick: () => { mode = m; render(); } }, m[0].toUpperCase() + m.slice(1)))),
      mode === 'active' ? h('label', {}, h('input', { type: 'checkbox', checked: withSpeed, onchange: e => { withSpeed = e.target.checked; } }), ' Speed test at each point') : null,
      h('button', { class: calib ? 'primary' : '', onclick: () => { calib = calib ? null : []; draw(); if (calib) toast('Click two points on the plan that are a known distance apart (e.g. two ends of a wall).'); render(); } }, calib ? 'Cancel calibration' : 'Calibrate scale'),
      h('button', { disabled: !s.points.length, onclick: async () => { s.points.pop(); await save(); render(); } }, 'Undo last point'),
      h('button', { disabled: !s.points.length, onclick: () => download(`survey-${s.name}.csv`, ['point,x_m,y_m,time,ssid,bssid,rssi_dbm,connected_bssid,download_mbps,upload_mbps',
        ...s.points.flatMap((p, i) => Object.entries(p.readings).map(([b, r]) => [i + 1, (p.x * (s.mpp || 0)).toFixed(2), (p.y * (s.mpp || 0)).toFixed(2), new Date(p.t * 1000).toISOString(), `"${p.names?.[b] || ''}"`, b, r, p.conn?.bssid || '', p.speed?.download ?? '', p.speed?.upload ?? ''].join(',')))].join('\r\n'), 'text/csv') }, 'Export CSV'),
      h('button', { class: 'danger', onclick: async () => { if (confirm(`Delete survey "${s.name}"?`)) { doc.surveys = doc.surveys.filter(x => x !== s); cur = doc.surveys[doc.surveys.length - 1] || null; await save(); await loadImage(); render(); } } }, 'Delete')),
    h('div', { class: 'row', style: 'margin-bottom:10px' }, 'Heatmap of',
      sel([['ssid', 'Network name (SSID)'], ['bssid', 'One access point (BSSID)'], ['best', 'Strongest signal of any network'], ['conn', 'Connected signal'], ['down', 'Download speed'], ['up', 'Upload speed']], metric, setMetric),
      metric === 'ssid' ? sel(ssids, target, v => { target = v; draw(); }) : metric === 'bssid' ? sel(bssids.map(b => [b, `${nameOf(b) || '(hidden)'} — ${b}`]), target, v => { target = v; draw(); }) : null,
      'Colour range', num('lo'), 'to', num('hi'), h('span', {}, isSpeed() ? 'Mbps' : 'dBm'),
      h('span', {}, 'Opacity'), h('input', { type: 'range', min: 0.1, max: 1, step: 0.05, value: opacity, oninput: e => { opacity = +e.target.value; draw(); } }),
      h('label', {}, h('input', { type: 'checkbox', checked: showEst, onchange: e => { showEst = e.target.checked; draw(); } }), ' Show estimated AP positions')),
    h('p', { class: 'dim' }, s.mpp ? `${s.points.length} point(s). Scale: ${(s.w * s.mpp).toFixed(1)} × ${(s.h * s.mpp).toFixed(1)} m. Stand still for a few seconds, then click where you are on the plan.` : 'This plan is not calibrated yet — click "Calibrate scale" so distances and AP positions can be computed.',
      mode === 'active' && !conn() ? ' Active mode needs a WiFi connection.' : ''),
    h('div', { class: 'plan' }, h('canvas', { id: 'plan', onclick: click })),
    estRows.length ? h('div', { class: 'card', style: 'margin-top:14px' }, h('h2', {}, 'Estimated access point positions'),
      h('p', { class: 'dim' }, 'Best fit of signal strength across your survey points. Expect errors of several metres; more points spread over more rooms give a better fit. ',
        'Plan "up" points ', h('input', { type: 'number', value: s.north || 0, min: 0, max: 359, onchange: async e => { s.north = +e.target.value; await save(); render(); } }), '° clockwise from north. ',
        S.settings.home.lat == null || S.settings.home.lat === '' ? 'Set your home latitude/longitude in Settings to get approximate map coordinates.' : ''),
      h('div', { class: 'tablewrap' }, h('table', {}, h('thead', {}, h('tr', {}, ['Class', 'SSID', 'BSSID', 'Points', 'From plan centre', 'Where', 'Fit error', 'Approx. coordinates'].map(x => h('th', {}, x)))),
        h('tbody', {}, estRows.map(({ b, e, t }) => h('tr', {}, h('td', { class: 'sev-' + t.severity }, t.label), h('td', {}, h('span', { class: 'chip', style: `background:${color(b)}` }), t.ssid || '(hidden)'), h('td', {}, b),
          h('td', { class: 'num' }, e.n), h('td', { class: 'num' }, `${Math.round(Math.hypot(e.dx, e.dy))} m`), h('td', {}, e.outside ? 'Outside the plan (neighboring property?)' : 'Inside the plan'),
          h('td', { class: 'num' }, `±${e.rms.toFixed(1)} dB`),
          h('td', {}, e.lat != null ? h('a', { href: `https://www.openstreetmap.org/?mlat=${e.lat.toFixed(6)}&mlon=${e.lon.toFixed(6)}#map=19/${e.lat.toFixed(6)}/${e.lon.toFixed(6)}`, target: '_blank', rel: 'noopener' }, `${e.lat.toFixed(5)}, ${e.lon.toFixed(5)}`) : '—'))))))) : null);
  draw();
}
