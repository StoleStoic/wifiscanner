// Spectrum, interference, signal-vs-time and signal-rank views.
import { $, h, canvas, color, INK, SIG, sigClass, sel } from './util.js';
import { S, visible, th, hist, select, conn, saveSettings } from './state.js';

const BANDS = {
  '2.4': { segs: [[2400, 2496]], chans: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14], f: c => (c === 14 ? 2484 : 2407 + 5 * c), label: () => true },
  '5': { segs: [[5160, 5340], [5480, 5905]], f: c => 5000 + 5 * c, label: () => true,
    chans: [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165, 169, 173, 177] },
  '6': { segs: [[5945, 7125]], f: c => 5950 + 5 * c, label: c => (c - 1) % 16 === 0,
    chans: Array.from({ length: 59 }, (_, i) => 1 + 4 * i) },
};
let band = '2.4', root;
const PAD = { l: 44, r: 12, t: 18, b: 34 }, GAP = 26;

function scale(b, w) {
  const segs = BANDS[b].segs, total = segs.reduce((a, s) => a + s[1] - s[0], 0);
  const px = (w - PAD.l - PAD.r - GAP * (segs.length - 1)) / total;
  return f => {
    let x = PAD.l;
    for (const [lo, hi] of segs) {
      if (f <= hi) return x + (Math.max(lo, f) - lo) * px;
      x += (hi - lo) * px + GAP;
    }
    return w - PAD.r;
  };
}
const yOf = (rssi, hgt) => PAD.t + (Math.min(-20, Math.max(-100, rssi)) + 20) / -80 * (hgt - PAD.t - PAD.b);

function drawSpectrum(cv, list) {
  const { ctx, w, h: hgt } = canvas(cv), x = scale(band, w), B = BANDS[band], base = hgt - PAD.b;
  ctx.textAlign = 'right'; ctx.textBaseline = 'middle';
  for (let d = -100; d <= -20; d += 10) {
    ctx.strokeStyle = INK.grid; ctx.beginPath(); ctx.moveTo(PAD.l, yOf(d, hgt)); ctx.lineTo(w - PAD.r, yOf(d, hgt)); ctx.stroke();
    ctx.fillStyle = INK.axis; ctx.fillText(d, PAD.l - 6, yOf(d, hgt));
  }
  ctx.textAlign = 'center'; ctx.textBaseline = 'top';
  for (const c of B.chans) {
    const cx = x(B.f(c));
    ctx.strokeStyle = INK.grid; ctx.beginPath(); ctx.moveTo(cx, base); ctx.lineTo(cx, base + 4); ctx.stroke();
    if (B.label(c)) { ctx.fillStyle = INK.axis; ctx.fillText(c, cx, base + 6); }
  }
  ctx.fillStyle = INK.dim; ctx.fillText('Channel', (PAD.l + w - PAD.r) / 2, base + 20);
  ctx.save(); ctx.translate(11, hgt / 2); ctx.rotate(-Math.PI / 2); ctx.fillText('dBm', 0, 0); ctx.restore();
  const labels = [];
  for (const n of [...list].sort((a, b) => a.rssi - b.rssi)) {
    const lo = x(n.span_lo), hi = x(n.span_hi), top = yOf(n.rssi, hgt), slope = Math.min(8, (hi - lo) * 0.12), selected = n.bssid === S.selected;
    ctx.beginPath(); ctx.moveTo(lo, base); ctx.lineTo(lo + slope, top); ctx.lineTo(hi - slope, top); ctx.lineTo(hi, base);
    ctx.fillStyle = color(n.bssid, selected ? 0.38 : 0.14); ctx.fill();
    ctx.strokeStyle = color(n.bssid); ctx.lineWidth = selected || n.connected ? 2.5 : 1.2; ctx.stroke();
    if (n.width > 20) {  // primary 20 MHz inside a bonded channel
      const pl = Math.max(lo + slope, x(n.freq - 10)), ph = Math.min(hi - slope, x(n.freq + 10));
      ctx.fillStyle = color(n.bssid, 0.3); ctx.fillRect(pl, top, ph - pl, base - top);
    }
    ctx.fillStyle = color(n.bssid); ctx.fillRect(x(n.freq) - 1, top - 4, 2, 4);
    labels.push({ n, cx: (lo + hi) / 2, top });
  }
  ctx.lineWidth = 1; ctx.textBaseline = 'bottom';
  const used = [];
  for (const { n, cx, top } of labels.reverse()) {
    const txt = `${n.ssid || '(hidden)'} · ${n.channel}${n.width > 20 ? '/' + n.width : ''}`, tw = ctx.measureText(txt).width;
    let y = top - 6;
    while (used.some(u => Math.abs(u.y - y) < 12 && Math.abs(u.cx - cx) < (u.tw + tw) / 2 + 6) && y > PAD.t + 10) y -= 12;
    used.push({ cx, y, tw });
    ctx.fillStyle = color(n.bssid); ctx.fillText(txt, Math.max(PAD.l + tw / 2, Math.min(w - PAD.r - tw / 2, cx)), y);
  }
  cv._hit = (mx, my) => labels.filter(({ n }) => mx >= x(n.span_lo) && mx <= x(n.span_hi) && my >= yOf(n.rssi, hgt) - 4 && my <= base)
    .sort((a, b) => a.n.rssi - b.n.rssi)[0]?.n;
}

function bars(cv, labels, values, mine, title, col) {
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
    if (conn()?.band && !spectrum._picked) band = conn().band;
    el.append(
      h('div', { class: 'row', style: 'margin-bottom:10px' },
        h('div', { class: 'seg', id: 'bandseg' }), h('span', { class: 'dim', id: 'speccount' }),
        h('span', { class: 'dim grow', style: 'text-align:right' }, 'Shape width = channel width; darker block and tick = primary channel. Uses the Scan tab filter. Click a network to select it.')),
      h('div', { class: 'card' }, h('canvas', { class: 'chart', id: 'spec', onclick: e => { const r = e.target.getBoundingClientRect(), n = e.target._hit?.(e.clientX - r.left, e.clientY - r.top); if (n) select(n.bssid); } })),
      h('div', { class: 'grid2' },
        h('div', { class: 'card' }, h('h2', {}, 'Co-channel interference'), h('p', { class: 'dim' }, 'Networks sharing each primary channel. They take turns, so airtime is divided.'), h('canvas', { class: 'chart short', id: 'cci' })),
        h('div', { class: 'card' }, h('h2', {}, 'Adjacent-channel interference'), h('p', { class: 'dim' }, 'Networks that partly overlap each channel from a different primary. They cannot coordinate and corrupt each other.'), h('canvas', { class: 'chart short', id: 'aci' }))));
    this.update();
  },
  update() {
    if (!root?.isConnected || !$('#spec')) return;
    const all = visible(), list = all.filter(n => n.band === band);
    $('#bandseg').replaceChildren(...['2.4', '5', '6'].map(b => h('button', { class: b === band ? 'on' : '', onclick: () => { band = b; spectrum._picked = true; this.update(); } },
      `${b} GHz (${all.filter(n => n.band === b).length})`)));
    $('#speccount').textContent = list.length ? '' : `No ${band} GHz networks in view` + (band === '6' ? ' (needs a WiFi 6E/7 adapter).' : '.');
    drawSpectrum($('#spec'), list);
    const B = BANDS[band], mine = new Set(list.filter(n => n.threat === 'authorized' || n.connected).map(n => n.channel));
    const co = B.chans.map(c => list.filter(n => n.channel === c).length);
    const adj = B.chans.map(c => { const f = B.f(c); return list.filter(n => n.channel !== c && n.span_lo < f + 10 && f - 10 < n.span_hi).length; });
    bars($('#cci'), B.chans, co, mine, 'Access points per primary channel (green = yours)', '#5aa9f5');
    bars($('#aci'), B.chans, adj, mine, 'Overlapping access points per channel', '#f0913a');
  },
  onSelect() { this.update(); }, onAnalysis() { this.update(); },
};

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
