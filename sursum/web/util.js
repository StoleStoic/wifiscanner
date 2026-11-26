// Small DOM, formatting and canvas helpers shared by every view.
export const $ = (s, r = document) => r.querySelector(s);
export const $$ = (s, r = document) => [...r.querySelectorAll(s)];

// The DOM's own append/replaceChildren turn null and arrays into text; make them accept
// the same loose child lists as h() so views can pass conditionals and mapped arrays.
const loose = a => a.flat(Infinity).filter(k => k != null && k !== false);
for (const m of ['append', 'replaceChildren']) {
  const native = Element.prototype[m];
  Element.prototype[m] = function (...kids) { return native.apply(this, loose(kids)); };
}

export function h(tag, attrs, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else if (k === 'class') e.className = v;
    else if (k === 'html') e.innerHTML = v;
    else if (k === 'value') e.value = v;
    else if (k === 'checked' || k === 'selected' || k === 'disabled') e[k] = !!v;
    else e.setAttribute(k, v === true ? '' : v);
  }
  e.append(...kids);
  return e;
}

export async function api(path, body, raw) {
  const opt = body === undefined ? {} : {
    method: 'POST', headers: { 'X-Sursum': '1', 'Content-Type': raw ? 'application/octet-stream' : 'application/json' },
    body: raw ? body : JSON.stringify(body),
  };
  const r = await fetch(path, opt);
  return r.json();
}

export function toast(msg, bad) {
  const t = h('div', { class: 'toast' + (bad ? ' bad' : '') }, msg);
  $('#toasts').append(t);
  setTimeout(() => t.remove(), 4200);
}

export const esc = s => String(s ?? '').replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

export function duration(sec) {
  if (sec == null) return '';
  const d = Math.floor(sec / 86400), hh = Math.floor(sec % 86400 / 3600), m = Math.floor(sec % 3600 / 60);
  return d ? `${d}d ${hh}h` : hh ? `${hh}h ${m}m` : `${m}m ${Math.floor(sec % 60)}s`;
}
export const clock = t => t ? new Date(t * 1000).toLocaleTimeString() : '';
export const stamp = t => t ? new Date(t * 1000).toLocaleString() : '';
export const ago = (t, now) => { const s = Math.max(0, Math.round(now - t)); return s < 60 ? `${s}s ago` : `${Math.round(s / 60)}m ago`; };

// Stable, well-separated colour per BSSID.
export function color(bssid, alpha = 1) {
  let x = 0;
  for (const c of bssid || '') x = (x * 31 + c.charCodeAt(0)) >>> 0;
  return `hsla(${(x * 137.508) % 360}, 72%, 62%, ${alpha})`;
}
export function sigClass(rssi, th) {
  return rssi >= th.good ? 'good' : rssi >= th.fair ? 'fair' : rssi >= th.poor ? 'poor' : 'bad';
}
export const SIG = { good: '#3ecf8e', fair: '#e6c84f', poor: '#f0913a', bad: '#ef5b5b' };
export const SEV = { Critical: '#ef5b5b', High: '#f0913a', Medium: '#e6c84f', Low: '#5aa9f5', Info: '#8892a6' };

export function canvas(cv) {
  const dpr = window.devicePixelRatio || 1, r = cv.getBoundingClientRect();
  const w = Math.max(50, r.width), ht = Math.max(50, r.height);
  if (cv.width !== Math.round(w * dpr) || cv.height !== Math.round(ht * dpr)) { cv.width = Math.round(w * dpr); cv.height = Math.round(ht * dpr); }
  const ctx = cv.getContext('2d');
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, w, ht);
  ctx.font = '11px system-ui, "Segoe UI", sans-serif';
  return { ctx, w, h: ht };
}
export const INK = { grid: 'rgba(255,255,255,.07)', axis: '#8892a6', text: '#c9d1e0', dim: '#667089' };

export function download(name, text, type = 'text/plain') {
  const a = h('a', { href: URL.createObjectURL(new Blob([text], { type })), download: name });
  document.body.append(a); a.click(); a.remove();
}
export function pickFile(accept) {
  return new Promise(res => {
    const i = h('input', { type: 'file', accept, onchange: () => res(i.files[0]) });
    i.click();
  });
}
export const sel = (opts, value, onchange, attrs = {}) =>
  h('select', { ...attrs, onchange: e => onchange(e.target.value) },
    opts.map(o => { const [v, l] = Array.isArray(o) ? o : [o, o]; return h('option', { value: v, selected: String(v) === String(value) }, l); }));
