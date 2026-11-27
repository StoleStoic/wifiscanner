// Spectrum, interference, signal-vs-time and signal-rank views.
import { $, h, canvas, color, INK, SIG, sigClass, sel } from './util.js';
import { S, nets, visible, th, hist, select, conn, saveSettings, setQuick } from './state.js';

const range = (a, b, step) => Array.from({ length: Math.floor((b - a) / step) + 1 }, (_, i) => a + i * step);
// Axis segments. k stretches a segment relative to its width in MHz (2.4 GHz is narrow but crowded).
const SEG = {
  '2.4': { lo: 2400, hi: 2496, name: 'ISM 2.4 GHz', chans: range(1, 14, 1), f: c => (c === 14 ? 2484 : 2407 + 5 * c), every: 1 },
  '5a': { lo: 5160, hi: 5340, name: 'UNII-1 / 2A', chans: range(36, 64, 4), f: c => 5000 + 5 * c, every: 1 },
  '5b': { lo: 5480, hi: 5905, name: 'UNII-2C / 3 / 4', chans: [...range(100, 144, 4), ...range(149, 177, 4)], f: c => 5000 + 5 * c, every: 1 },
  '6': { lo: 5945, hi: 7125, name: 'UNII-5 to 8 (6 GHz)', chans: range(1, 233, 4), f: c => 5950 + 5 * c, every: 4 },
};
const VIEWS = { '2.4': [['2.4', 1]], '5': [['5a', 1], ['5b', 1]], '6': [['6', 1]], all: [['2.4', 5], ['5a', 1.3], ['5b', 1.3], ['6', 0.55]] };
export const BANDS = { '2.4': { chans: SEG['2.4'].chans, f: SEG['2.4'].f }, '5': { chans: [...SEG['5a'].chans, ...SEG['5b'].chans], f: SEG['5a'].f }, '6': { chans: SEG['6'].chans, f: SEG['6'].f } };
let root;
const PAD = { l: 44, r: 44, t: 30, b: 50 }, GAP = 22;
const DARK = { bg: '#0b0f26', grid: 'rgba(255,255,255,.10)', axis: '#8fa0c8', text: '#e6ebff', band: '#5aa9f5' };
const hue = b => { let x = 0; for (const c of b) x = (x * 31 + c.charCodeAt(0)) >>> 0; return (x * 137.508) % 360; };
const tint = (b, a = 1, l = 62) => `hsla(${hue(b)}, 85%, ${l}%, ${a})`;
const yOf = (rssi, hgt, pad = PAD) => pad.t + (Math.min(-10, Math.max(-100, rssi)) + 10) / -90 * (hgt - pad.t - pad.b);
export const shortName = n => n.ssid || `${(n.vendor || 'Hidden').replace(/^Private.*?(possibly |$)/, '').replace(/\(virtual\)|[,.]? ?(Inc|Corp|LLC|Ltd|Co|GmbH|Technologies|Networks|Systems|COMPUTER|Solutions).*$/gi, '').trim() || 'Hidden'}:${n.bssid.slice(9).toUpperCase()}`;

// Draws the spectrum on a dark canvas. view: 'all' | '2.4' | '5' | '6'. The selected network is drawn solid.
export function drawSpectrum(cv, list, view) {
  const { ctx, w, h: hgt } = canvas(cv), base = hgt - PAD.b;
  let segs = VIEWS[view] || VIEWS.all;
  if (view === 'all' && !list.some(n => n.band === '6')) segs = segs.filter(s => s[0] !== '6');  // adapter hears no 6 GHz
  const total = segs.reduce((a, [k, m]) => a + (SEG[k].hi - SEG[k].lo) * m, 0), px = (w - PAD.l - PAD.r - GAP * (segs.length - 1)) / total;
  const start = {}; let cur = PAD.l;
  for (const [k, m] of segs) { start[k] = [cur, px * m]; cur += (SEG[k].hi - SEG[k].lo) * px * m + GAP; }
  const x = f => { for (const [k] of segs) if (f <= SEG[k].hi + 1) return start[k][0] + (Math.max(SEG[k].lo, f) - SEG[k].lo) * start[k][1]; return w - PAD.r; };
  const inView = n => segs.some(([k]) => n.freq >= SEG[k].lo && n.freq <= SEG[k].hi);
  ctx.fillStyle = DARK.bg; ctx.fillRect(0, 0, w, hgt);
  ctx.textBaseline = 'middle'; ctx.setLineDash([3, 4]);
  for (let d = -10; d >= -90; d -= 10) {
    ctx.strokeStyle = DARK.grid; ctx.beginPath(); ctx.moveTo(PAD.l, yOf(d, hgt)); ctx.lineTo(w - PAD.r, yOf(d, hgt)); ctx.stroke();
    ctx.fillStyle = d <= -80 ? '#ef5b5b' : d >= -60 ? '#3ecf8e' : DARK.axis; ctx.textAlign = 'right'; ctx.fillText(d, PAD.l - 8, yOf(d, hgt)); ctx.textAlign = 'left'; ctx.fillText(d, w - PAD.r + 8, yOf(d, hgt));
  }
  ctx.setLineDash([]);
  const sel = list.find(n => n.bssid === S.selected && inView(n));
  ctx.textAlign = 'center';
  for (const [k] of segs) {
    const g = SEG[k], x0 = start[k][0], x1 = x0 + (g.hi - g.lo) * start[k][1];
    ctx.strokeStyle = k === '2.4' ? '#f0913a' : DARK.band; ctx.lineWidth = 2; ctx.beginPath(); ctx.moveTo(x0, PAD.t - 8); ctx.lineTo(x1, PAD.t - 8); ctx.stroke(); ctx.lineWidth = 1;
    ctx.fillStyle = DARK.text; ctx.font = 'bold 11px system-ui'; ctx.textBaseline = 'bottom'; ctx.fillText(g.name, (x0 + x1) / 2, PAD.t - 11); ctx.font = '11px system-ui';
    ctx.strokeStyle = DARK.axis; ctx.beginPath(); ctx.moveTo(x0, base); ctx.lineTo(x1, base); ctx.stroke();
    ctx.textBaseline = 'top';
    const step = Math.max(1, Math.ceil(26 / ((g.f(g.chans[1]) - g.f(g.chans[0])) * start[k][1])));
    g.chans.forEach((c, i) => {
      const hot = sel && sel.channel === c && sel.freq === g.f(c);
      if (i % step && !hot) return;
      ctx.fillStyle = hot ? '#ffd166' : k === '2.4' && [1, 6, 11].includes(c) ? '#f0913a' : DARK.axis; ctx.font = hot ? 'bold 13px system-ui' : '11px system-ui';
      ctx.fillText(c, x(g.f(c)), base + 7);
    });
    ctx.font = '11px system-ui';
  }
  const shown = list.filter(inView).sort((a, b) => a.rssi - b.rssi), hits = [];
  const shape = n => { const lo = x(n.span_lo), hi = x(n.span_hi), top = yOf(n.rssi, hgt), sl = Math.min(6, (hi - lo) * 0.1); ctx.beginPath(); ctx.moveTo(lo, base); ctx.lineTo(lo + sl, top); ctx.lineTo(hi - sl, top); ctx.lineTo(hi, base); return { lo, hi, top, sl }; };
  for (const n of shown) {
    if (n === sel) continue;
    const g = shape(n), dim = sel ? 0.45 : 1;
    ctx.fillStyle = tint(n.bssid, 0.10 * dim); ctx.fill(); ctx.strokeStyle = tint(n.bssid, 0.95 * dim); ctx.lineWidth = n.connected ? 2.4 : 1.3; ctx.stroke();
    if (n.width > 20) { ctx.fillStyle = tint(n.bssid, 0.16 * dim); ctx.fillRect(Math.max(g.lo + g.sl, x(n.freq - 10)), g.top, Math.min(g.hi - g.sl, x(n.freq + 10)) - Math.max(g.lo + g.sl, x(n.freq - 10)), base - g.top); }
    hits.push({ n, ...g });
  }
  ctx.lineWidth = 1; ctx.textBaseline = 'bottom'; ctx.textAlign = 'center'; ctx.font = '13px system-ui';
  const used = [];
  for (const { n, lo, hi, top } of [...hits].reverse()) {
    const txt = shortName(n), tw = ctx.measureText(txt).width, cx = Math.max(PAD.l + tw / 2, Math.min(w - PAD.r - tw / 2, (lo + hi) / 2));
    let y = top - 5; while (used.some(u => Math.abs(u.y - y) < 14 && Math.abs(u.cx - cx) < (u.tw + tw) / 2 + 4) && y > Math.max(PAD.t + 16, top - 5 - 14 * 4)) y -= 14;
    used.push({ cx, y, tw }); ctx.fillStyle = tint(n.bssid, sel ? 0.5 : 0.95, 68); ctx.fillText(txt, cx, y);
  }
  if (sel) {  // the selected network: solid, on top, with a boxed label and a caption
    const g = shape(sel);
    ctx.fillStyle = tint(sel.bssid, 0.88, 52); ctx.fill(); ctx.strokeStyle = '#fff'; ctx.lineWidth = 2; ctx.stroke(); ctx.lineWidth = 1;
    if (sel.width > 20) { ctx.fillStyle = 'rgba(255,255,255,.28)'; ctx.fillRect(x(sel.freq - 10), g.top, x(sel.freq + 10) - x(sel.freq - 10), base - g.top); }
    ctx.font = 'bold 15px system-ui'; const txt = shortName(sel), tw = ctx.measureText(txt).width + 22, cx = Math.max(PAD.l + tw / 2, Math.min(w - PAD.r - tw / 2, (g.lo + g.hi) / 2)), by = Math.max(PAD.t + 4, g.top - 44);
    ctx.fillStyle = 'rgba(11,15,38,.92)'; ctx.strokeStyle = tint(sel.bssid, 1, 62); ctx.lineWidth = 2; ctx.beginPath(); ctx.roundRect(cx - tw / 2, by, tw, 30, 6); ctx.fill(); ctx.stroke(); ctx.lineWidth = 1;
    ctx.fillStyle = '#fff'; ctx.textBaseline = 'middle'; ctx.fillText(txt, cx, by + 16);
    ctx.font = '13px system-ui'; ctx.textAlign = 'left'; ctx.fillStyle = DARK.text;
    ctx.fillText(`${shortName(sel)}  ·  ${sel.bssid}  ·  Ch. ${sel.channel} @ ${sel.width} MHz  ·  ${sel.rssi} dBm  ·  ${sel.security}`, PAD.l, hgt - 12);
    hits.push({ n: sel, ...g });
  } else { ctx.font = '12px system-ui'; ctx.textAlign = 'left'; ctx.textBaseline = 'middle'; ctx.fillStyle = DARK.axis; ctx.fillText(shown.length ? 'Click a network to highlight it.' : 'No networks in this view.', PAD.l, hgt - 12); }
  ctx.font = '11px system-ui';
  cv._hit = (mx, my) => hits.filter(g => mx >= g.lo && mx <= g.hi && my >= g.top - 4 && my <= base).sort((a, b) => (b.n === sel) - (a.n === sel) || a.n.rssi - b.n.rssi).find(g => g.n !== sel)?.n
    || hits.find(g => g.n === sel && mx >= g.lo && mx <= g.hi && my >= g.top - 4 && my <= base)?.n;
}
export const spectrumClick = e => { const r = e.target.getBoundingClientRect(), n = e.target._hit?.(e.clientX - r.left, e.clientY - r.top); select(n ? n.bssid : null); };

function bars(cv, labels, values, mine, title, col) {
  const PAD = { l: 44, r: 12, t: 18, b: 34 };
  const { ctx, w, h: hgt } = canvas(cv), max = Math.max(4, ...values), bw = (w - PAD.l - PAD.r) / labels.length, base = hgt - PAD.b;
  ctx.textAlign = 'right'; ctx.textBaseline = 'middle';
  for (let i = 0; i <= 4; i++) {
    const v = Math.round(max * i / 4), y = base - (base - PAD.t) * i / 4;
    ctx.strokeStyle = INK.grid; ctx.beginPath(); ctx.moveTo(PAD.l, y); ctx.lineTo(w - PAD.r, y); ctx.stroke();
    ctx.fillStyle = INK.axis; ctx.fillText(v, PAD.l - 6, y);
  }
  ctx.textAlign = 'center';
  labels.forEach((l, i) => {
    const bh = values[i] / max * (base - PAD.t), bx = PAD.l + i * bw;
    ctx.fillStyle = mine.has(l) ? '#3ecf8e' : col; ctx.fillRect(bx + bw * 0.15, base - bh, bw * 0.7, bh);
    ctx.textBaseline = 'top'; ctx.fillStyle = INK.axis;
    if (labels.length <= 30 || (l - 1) % 16 === 0) ctx.fillText(l, bx + bw / 2, base + 6);
    if (values[i] && bw > 14) { ctx.textBaseline = 'bottom'; ctx.fillStyle = INK.text; ctx.fillText(values[i], bx + bw / 2, base - bh - 2); }
  });
  ctx.textAlign = 'left'; ctx.textBaseline = 'top'; ctx.fillStyle = INK.text; ctx.fillText(title, PAD.l, 2);
}

export const spectrum = {
  mount(el) {
    root = el;
    el.append(
      h('div', { class: 'row', style: 'margin-bottom:10px' }, h('span', { id: 'specquick' }),
        h('span', { class: 'dim grow', style: 'text-align:right' }, 'Shape width = channel width; lighter block = primary channel. Click a network to highlight it; click empty space to clear.')),
      h('div', { class: 'card', style: 'padding:0;overflow:hidden' }, h('canvas', { class: 'chart', id: 'spec', style: 'height:430px', onclick: spectrumClick })),
      h('div', { class: 'grid2' },
        h('div', { class: 'card' }, h('h2', { id: 'ccih' }, 'Co-channel interference'), h('p', { class: 'dim' }, 'Networks sharing each primary channel. They take turns, so airtime is divided.'), h('canvas', { class: 'chart short', id: 'cci' })),
        h('div', { class: 'card' }, h('h2', { id: 'acih' }, 'Adjacent-channel interference'), h('p', { class: 'dim' }, 'Networks that partly overlap each channel from a different primary. They cannot coordinate and corrupt each other.'), h('canvas', { class: 'chart short', id: 'aci' }))));
    this.update();
  },
  update() {
    if (!root?.isConnected || !$('#spec')) return;
    const list = visible(), view = S.quick.band;
    $('#specquick').replaceChildren(quickBar());
    drawSpectrum($('#spec'), list, view);
    const b = view !== 'all' ? view : (list.find(n => n.bssid === S.selected)?.band || conn()?.band || '2.4'), B = BANDS[b], inBand = list.filter(n => n.band === b);
    const mine = new Set(inBand.filter(n => n.threat === 'authorized' || n.connected).map(n => n.channel));
    const co = B.chans.map(c => inBand.filter(n => n.channel === c).length);
    const adj = B.chans.map(c => { const f = B.f(c); return inBand.filter(n => n.channel !== c && n.span_lo < f + 10 && f - 10 < n.span_hi).length; });
    $('#ccih').textContent = `Co-channel interference — ${b} GHz`; $('#acih').textContent = `Adjacent-channel interference — ${b} GHz`;
    bars($('#cci'), B.chans, co, mine, 'Access points per primary channel (green = yours)', '#5aa9f5');
    bars($('#aci'), B.chans, adj, mine, 'Overlapping access points per channel', '#f0913a');
  },
  onSelect() { this.update(); }, onAnalysis() { this.update(); },
};

// Quick filter bar shared by the Scan and Spectrum tabs: band, open/secure and a network-name picker.
export function quickBar() {
  const all = nets(), q = S.quick, count = f => all.filter(f).length;
  const seg = (items, key) => h('div', { class: 'seg' }, items.map(([v, l, f]) => h('button', { class: q[key] === v ? 'on' : '', onclick: () => setQuick({ [key]: v }) }, `${l} (${count(f)})`)));
  const open = n => n.security === 'Open' || n.security.startsWith('Enhanced Open');
  const names = [...new Set(all.map(n => n.ssid || ''))].sort((a, b) => a.localeCompare(b));
  return h('span', { class: 'row' },
    seg([['all', 'All', () => true], ['2.4', '2.4 GHz', n => n.band === '2.4'], ['5', '5 GHz', n => n.band === '5'], ['6', '6 GHz', n => n.band === '6']], 'band'),
    seg([['all', 'Any security', () => true], ['open', 'Open', open], ['secure', 'Secure', n => !open(n)]], 'sec'),
    h('button', { class: q.ssids ? 'primary' : '', title: 'Show only the network names you tick', onclick: e => namePicker(e.currentTarget, names) }, q.ssids ? `Networks: ${q.ssids.size} of ${names.length} ▾` : 'Networks: all ▾'));
}
function namePicker(btn, names) {
  if ($('.menu')) return $('.menu').remove();
  const all = nets(), chosen = new Set(S.quick.ssids || names);
  const apply = () => setQuick({ ssids: chosen.size === names.length ? null : new Set(chosen) });
  const box = h('div', { class: 'menu', style: 'columns:auto;min-width:260px' },
    h('div', { class: 'row', style: 'margin-bottom:6px' }, h('button', { class: 'small', onclick: () => { names.forEach(n => chosen.add(n)); apply(); m(); } }, 'All'), h('button', { class: 'small', onclick: () => { chosen.clear(); apply(); m(); } }, 'None'),
      h('button', { class: 'small', onclick: () => { chosen.clear(); all.filter(n => n.threat === 'authorized').forEach(n => chosen.add(n.ssid || '')); apply(); m(); } }, 'Only mine')),
    h('div', { id: 'namelist' }));
  const m = () => $('#namelist').replaceChildren(...names.map(n => h('label', {}, h('input', { type: 'checkbox', checked: chosen.has(n), onchange: e => { e.target.checked ? chosen.add(n) : chosen.delete(n); apply(); } }), ` ${n || '(hidden networks)'} `, h('span', { class: 'dim' }, `(${all.filter(x => (x.ssid || '') === n).length})`))));
  const r = btn.getBoundingClientRect(); box.style.top = r.bottom + 4 + 'px'; box.style.left = Math.min(r.left, innerWidth - 300) + 'px';
  document.body.append(box); m();
  setTimeout(() => document.addEventListener('pointerdown', function f(e) { if (!box.contains(e.target) && e.target !== btn) { box.remove(); document.removeEventListener('pointerdown', f); } }), 0);
}

// ---- signal vs time + rank
let sameBand = false, windowSec = 300;
function drawTime(cv, list) {
  const { ctx, w, h: hgt } = canvas(cv), t = th(), base = hgt - PAD.b;
  const end = S.loaded ? Math.max(0, ...list.flatMap(n => hist(n.bssid).map(p => p[0]))) : S.now, start = end - windowSec;
  const x = tt => PAD.l + (tt - start) / windowSec * (w - PAD.l - PAD.r);
  ctx.textAlign = 'right'; ctx.textBaseline = 'middle';
  for (let d = -100; d <= -20; d += 10) {
    ctx.strokeStyle = INK.grid; ctx.beginPath(); ctx.moveTo(PAD.l, yOf(d, hgt)); ctx.lineTo(w - PAD.r, yOf(d, hgt)); ctx.stroke();
    ctx.fillStyle = INK.axis; ctx.fillText(d, PAD.l - 6, yOf(d, hgt));
  }
  ctx.setLineDash([4, 4]);
  for (const k of ['good', 'fair', 'poor']) { ctx.strokeStyle = SIG[k]; ctx.globalAlpha = 0.55; ctx.beginPath(); ctx.moveTo(PAD.l, yOf(t[k], hgt)); ctx.lineTo(w - PAD.r, yOf(t[k], hgt)); ctx.stroke(); }
  ctx.setLineDash([]); ctx.globalAlpha = 1;
  ctx.textAlign = 'center'; ctx.textBaseline = 'top'; ctx.fillStyle = INK.axis;
  for (let i = 0; i <= 5; i++) { const s = Math.round(windowSec * (1 - i / 5)); ctx.fillText(s ? `-${s >= 120 ? Math.round(s / 60) + ' min' : s + ' s'}` : 'now', PAD.l + (w - PAD.l - PAD.r) * i / 5, base + 6); }
  ctx.save(); ctx.beginPath(); ctx.rect(PAD.l, PAD.t - 6, w - PAD.l - PAD.r, base - PAD.t + 8); ctx.clip();
  for (const n of list) {
    const pts = hist(n.bssid).filter(p => p[0] >= start - 30);
    if (!pts.length) continue;
    ctx.strokeStyle = color(n.bssid); ctx.lineWidth = n.bssid === S.selected || n.connected ? 2.6 : 1.3;
    ctx.beginPath(); pts.forEach((p, i) => (i ? ctx.lineTo(x(p[0]), yOf(p[1], hgt)) : ctx.moveTo(x(p[0]), yOf(p[1], hgt)))); ctx.stroke();
    if (pts.length === 1) { ctx.fillStyle = color(n.bssid); ctx.fillRect(x(pts[0][0]) - 2, yOf(pts[0][1], hgt) - 2, 4, 4); }
  }
  ctx.restore(); ctx.lineWidth = 1;
}

export const signal = {
  mount(el) {
    root = el;
    const t = th(), num = k => h('input', { type: 'number', value: t[k], max: -20, min: -100, onchange: e => saveSettings({ thresholds: { [k]: +e.target.value } }).then(() => this.update()) });
    el.append(
      h('div', { class: 'row', style: 'margin-bottom:10px' },
        h('div', { class: 'seg' }, h('button', { id: 'anyb', onclick: () => { sameBand = false; this.update(); } }, 'Any band'), h('button', { id: 'sameb', onclick: () => { sameBand = true; this.update(); } }, 'Same band as my device')),
        'Window', sel([[60, '1 min'], [300, '5 min'], [900, '15 min']], windowSec, v => { windowSec = +v; this.update(); }),
        h('span', { class: 'grow' }),
        h('span', { style: `color:${SIG.good}` }, 'Good ≥'), num('good'), h('span', { style: `color:${SIG.fair}` }, 'Fair ≥'), num('fair'), h('span', { style: `color:${SIG.poor}` }, 'Poor ≥'), num('poor'), h('span', { class: 'dim' }, 'dBm')),
      h('div', { class: 'card' }, h('h2', {}, 'Signal vs. time'), h('canvas', { class: 'chart', id: 'sigtime' }), h('div', { id: 'legend', class: 'row', style: 'margin-top:8px' })),
      h('div', { class: 'card' }, h('h2', {}, 'Signal rank'), h('div', { id: 'rank' })));
    this.update();
  },
  update() {
    if (!root?.isConnected || !$('#sigtime')) return;
    $('#anyb').className = sameBand ? '' : 'on'; $('#sameb').className = sameBand ? 'on' : '';
    const t = th(), myBand = conn()?.band;
    let list = visible().filter(n => !sameBand || !myBand || n.band === myBand).sort((a, b) => b.rssi - a.rssi);
    const top = list.filter((n, i) => i < 14 || n.bssid === S.selected || n.connected);
    drawTime($('#sigtime'), top);
    $('#legend').replaceChildren(...top.map(n => h('span', { style: 'cursor:pointer;' + (n.bssid === S.selected ? 'font-weight:700' : ''), onclick: () => select(n.bssid) },
      h('span', { class: 'chip', style: `background:${color(n.bssid)}` }), `${n.ssid || '(hidden)'} ${n.band}G/${n.channel}`)),
      list.length > top.length ? h('span', { class: 'dim' }, `+${list.length - top.length} weaker networks not drawn — narrow them with the Scan filter`) : null);
    $('#rank').replaceChildren(...list.map(n => {
      const k = sigClass(n.rssi, t);
      return h('div', { class: 'row', style: 'gap:8px;margin:3px 0;cursor:pointer', onclick: () => select(n.bssid) },
        h('span', { style: 'width:230px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;' + (n.bssid === S.selected ? 'font-weight:700' : '') },
          h('span', { class: 'chip', style: `background:${color(n.bssid)}` }), n.ssid || '(hidden)', h('span', { class: 'dim' }, ` ${n.band}G ch${n.channel}`)),
        h('span', { class: 'grow', style: 'background:var(--panel2);border-radius:4px;height:14px;overflow:hidden' },
          h('i', { style: `display:block;height:100%;width:${Math.max(2, (n.rssi + 100) / 80 * 100)}%;background:${SIG[k]}` })),
        h('span', { style: 'width:70px;text-align:right;font-variant-numeric:tabular-nums' }, n.rssi + ' dBm'),
        h('span', { class: 'badge ' + k, style: 'width:46px;text-align:center' }, k));
    }));
  },
  onSelect() { this.update(); },
};
