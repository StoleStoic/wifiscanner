// Settings: scanning, home / threat parameters, remote probes and the Claude API key.
import { h, toast, sel } from './util.js';
import { S, saveSettings } from './state.js';

let root;
const F = (label, control, hint) => h('label', { class: 'field' }, h('span', {}, label), h('span', { class: 'row' }, control, hint ? h('span', { class: 'dim' }, hint) : null));
const num = (val, onsave, attrs = {}) => h('input', { type: 'number', value: val ?? '', ...attrs, onchange: e => onsave(e.target.value === '' ? null : +e.target.value) });
const txt = (val, onsave, attrs = {}) => h('input', { type: 'text', value: val ?? '', ...attrs, onchange: e => onsave(e.target.value.trim()) });

export function mount(el) { root = el; render(); }
function render() {
  const s = S.settings, save = p => saveSettings(p).then(() => toast('Saved.'));
  const probe = (p, i) => h('div', { class: 'row', style: 'margin-bottom:6px' },
    ...[['name', 'Name', 110], ['host', 'Host or IP', 150], ['user', 'User', 90], ['port', 'Port', 60], ['iface', 'Interface', 80], ['key', 'Private key file (optional)', 250]].map(([k, ph, w]) =>
      h('input', { type: 'text', placeholder: ph, title: ph, style: `width:${w}px`, value: p[k] ?? '', onchange: e => { p[k] = e.target.value.trim(); } })),
    h('label', {}, h('input', { type: 'checkbox', checked: p.sudo !== false, onchange: e => { p.sudo = e.target.checked; } }), ' sudo'),
    h('button', { class: 'small danger', onclick: () => { s.probes.splice(i, 1); saveSettings({ probes: s.probes }).then(render); } }, 'Remove'));
  root.replaceChildren(
    h('div', { class: 'card' }, h('h2', {}, 'Scanning'),
      F('Seconds between scans', num(s.scan.interval, v => save({ scan: { interval: Math.max(1, v || 5) } }), { min: 1, max: 600 }), 'Windows needs about 4 s per scan on top of this.'),
      F('Forget a network after', num(s.scan.max_age, v => save({ scan: { max_age: Math.max(10, v || 120) } }), { min: 10 }), 'seconds without hearing it'),
      F('WiFi adapter', txt(s.scan.interface, v => save({ scan: { interface: v } }), { placeholder: 'automatic' }), 'Part of the adapter name, only needed with more than one adapter. Applies after restart.')),
    h('div', { class: 'card' }, h('h2', {}, 'Home and threat detection'),
      F('My network names (SSIDs)', txt(s.home.ssids.join(', '), v => save({ home: { ssids: v.split(',').map(x => x.trim()).filter(Boolean) } }), { style: 'width:320px' }), 'comma separated'),
      F('Home perimeter', num(s.home.perimeter_m, v => save({ home: { perimeter_m: v || 15 } }), { min: 1 }), 'metres from this PC; unknown APs estimated closer than this are flagged as unauthorized'),
      F('Wall factor (path-loss exponent)', num(s.home.path_loss_exp, v => save({ home: { path_loss_exp: Math.min(5, Math.max(2, v || 3)) } }), { min: 2, max: 5, step: 0.1 }), '2 = open air, 3 = typical house, 4 = many thick walls. Higher values give shorter distance estimates.'),
      F('Home latitude', num(s.home.lat, v => save({ home: { lat: v } }), { step: 'any', style: 'width:140px' }), 'optional; used with a Survey to give approximate coordinates of located APs'),
      F('Home longitude', num(s.home.lon, v => save({ home: { lon: v } }), { step: 'any', style: 'width:140px' })),
      F('Network to sweep in IP Scanner', txt(s.ipscan.cidr, v => save({ ipscan: { cidr: v } }), { placeholder: 'automatic, e.g. 192.168.1.0/24' }))),
    h('div', { class: 'card' }, h('h2', {}, 'Remote scanning probes (WLAN Pi or any Linux device)'),
      h('p', { class: 'dim' }, 'The probe is reached with the SSH client built into Windows, using key-based login (no passwords), and runs "iw dev <interface> scan". After saving, pick the probe in the scan-source list at the top right. See Help for the one-time setup.'),
      s.probes.map(probe),
      h('div', { class: 'row' }, h('button', { onclick: () => { s.probes.push({ name: 'wlanpi', host: '', user: 'wlanpi', port: 22, iface: 'wlan0', key: '', sudo: true }); render(); } }, 'Add probe'),
        s.probes.length ? h('button', { class: 'primary', onclick: () => {
          const bad = s.probes.find(p => !/^[\w.@:-]+$/.test(p.name || '') || !p.host || !p.user || !p.iface);
          if (bad) return toast('Each probe needs a name (letters/digits), host, user and interface.', true);
          save({ probes: s.probes });
        } }, 'Save probes') : null)),
    h('div', { class: 'card' }, h('h2', {}, 'Claude analysis'),
      h('p', { class: 'dim' }, 'Optional. With an Anthropic API key, the Analysis tab can ask Claude for a deeper review of your scan. The key is stored only on this PC. Usage is billed to your Anthropic account.'),
      F('Anthropic API key', h('input', { type: 'password', placeholder: s.ai.has_key ? 'A key is saved — type a new one to replace it' : 'sk-ant-…', style: 'width:340px', onchange: e => e.target.value && save({ ai: { api_key: e.target.value.trim() } }).then(render) }),
        s.ai.has_key ? h('button', { class: 'small danger', onclick: () => saveSettings({ ai: { clear_key: true } }).then(render) }, 'Remove key') : null),
      F('Model', sel([['claude-opus-5-5', 'Claude Opus 5.5 (recommended)'], ['claude-sonnet-5-5', 'Claude Sonnet 5.5 (faster, cheaper)'], ['claude-haiku-5-5', 'Claude Haiku 5.5 (cheapest)']], s.ai.model, v => save({ ai: { model: v } })))),
    h('p', { class: 'dim' }, `Stole Sursum WiFi Scanner ${S.version || ''}. All data stays on this PC except speed tests and, if you use it, Claude analysis.`));
}
