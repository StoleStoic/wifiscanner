// Freeform filter language.
//   ,  OR  (lowest precedence: separates whole alternatives)
//   &  AND
//   ^  OR that binds tighter than AND:  5 & wpa3 ^ wpa2  =  5 AND (wpa3 OR wpa2)
//   !  NOT (prefix)      ( )  grouping      "..."  literal text
// A term is bare text (matches any column), or column:text, column=value,
// column!=value, column>n, column>=n, column<n, column<=n.
const ALIAS = { ch: 'channel', chan: 'channel', sec: 'security', signal: 'rssi', mac: 'bssid', name: 'ssid',
  std: 'standards', gen: 'generation', sta: 'stations', util: 'utilization', bw: 'width', freq: 'freq', enc: 'security' };

function tokenize(src) {
  const out = []; let i = 0, cur = '', quoted = false;
  const flush = () => { if (cur.trim() || quoted) out.push({ t: 'term', v: cur.trim() }); cur = ''; quoted = false; };
  while (i < src.length) {
    const c = src[i];
    if (c === '"') { const j = src.indexOf('"', i + 1); const end = j < 0 ? src.length : j; cur += src.slice(i + 1, end); quoted = true; i = end + 1; continue; }
    if (c === '!' && !cur.trim() && src[i + 1] !== '=') { out.push({ t: '!' }); i++; continue; }
    if (',&^()'.includes(c)) { flush(); out.push({ t: c }); i++; continue; }
    cur += c; i++;
  }
  flush();
  return out;
}

function term(text) {
  const m = text.match(/^([a-z_.0-9]+)\s*(!=|>=|<=|:|=|>|<)\s*(.*)$/i);
  if (!m || (/^[\d.]+$/.test(m[1]) && m[2] === ':')) {
    const needle = text.toLowerCase();
    return n => (n._text ??= rowText(n)).includes(needle);
  }
  const key = ALIAS[m[1].toLowerCase()] || m[1].toLowerCase(), op = m[2], want = m[3].trim().toLowerCase();
  const num = parseFloat(want);
  return n => {
    let v = n[key];
    if (v == null) return op === '!=';
    if (Array.isArray(v)) v = v.join(' ');
    if (typeof v === 'boolean') v = v ? 'yes true 1' : 'no false 0';
    const s = String(v).toLowerCase();
    switch (op) {
      case ':': return s.includes(want);
      case '=': return typeof n[key] === 'number' ? n[key] === num : typeof n[key] === 'boolean' ? s.split(' ').includes(want) : s === want;
      case '!=': return typeof n[key] === 'number' ? n[key] !== num : typeof n[key] === 'boolean' ? !s.split(' ').includes(want) : s !== want;
      case '>': return +v > num; case '<': return +v < num;
      case '>=': return +v >= num; case '<=': return +v <= num;
    }
  };
}

export function rowText(n) {
  return [n.ssid || '(hidden)', n.bssid, n.vendor, n.ap_name, n.band + 'ghz', 'ch' + n.channel, n.width + 'mhz', n.generation,
    (n.standards || []).map(s => '802.11' + s).join(' '), n.security, (n.akm || []).join(' '), (n.ciphers || []).join(' '),
    n.wps ? 'wps' : '', n.connected ? 'connected' : '', n.country, n.model, n.threat || ''].join(' ').toLowerCase();
}

// Returns {fn, error}. An empty expression matches everything.
export function compile(src) {
  src = (src || '').trim();
  if (!src) return { fn: () => true };
  const toks = tokenize(src); let p = 0;
  const peek = () => toks[p]?.t;
  function unary() {
    if (peek() === '!') { p++; const f = unary(); return n => !f(n); }
    if (peek() === '(') { p++; const f = or(); if (peek() !== ')') throw new Error('Missing )'); p++; return f; }
    if (peek() === 'term') return term(toks[p++].v);
    throw new Error(p >= toks.length ? 'Filter ends unexpectedly' : `Unexpected "${toks[p].t}"`);
  }
  const chain = (next, sym, comb) => () => { const fs = [next()]; while (peek() === sym) { p++; fs.push(next()); } return fs.length === 1 ? fs[0] : comb(fs); };
  const tight = chain(unary, '^', fs => n => fs.some(f => f(n)));
  const and = chain(tight, '&', fs => n => fs.every(f => f(n)));
  const or = chain(and, ',', fs => n => fs.some(f => f(n)));
  try {
    const fn = or();
    if (p < toks.length) throw new Error(`Unexpected "${toks[p].t === 'term' ? toks[p].v : toks[p].t}"`);
    return { fn };
  } catch (e) { return { fn: () => true, error: e.message }; }
}
