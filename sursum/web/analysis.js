// Analysis view: prioritised notes from the rule engine, plus optional Claude notes.
import { $, h, api, toast, stamp, download, csvCell } from './util.js';
import { S, select, refreshAnalysis } from './state.js';
import { ARTICLES } from './help.js';

let root, cat = 'All', timer = null;
const PRI = { 'Very High': '#ef5b5b', High: '#f0913a', Medium: '#e6c84f', Low: '#5aa9f5', 'Very Low': '#8892a6' };
const ORDER = Object.keys(PRI);

const note = n => h('div', { class: 'note', style: `border-color:${PRI[n.priority]}` },
  h('div', { class: 'row' }, h('span', { class: 'badge', style: `color:${PRI[n.priority]}` }, n.priority), h('span', { class: 'badge' }, n.category),
    n.source === 'claude' ? h('span', { class: 'badge info' }, 'Claude') : null, h('span', { class: 't grow' }, n.title)),
  h('div', { style: 'margin-top:4px' }, n.detail),
  h('div', { class: 'row', style: 'margin-top:4px' },
    ARTICLES[n.article] ? h('a', { href: '#', onclick: e => { e.preventDefault(); window.sursumGo('help', n.article); } }, 'Read: ' + ARTICLES[n.article].title) : null,
    n.bssid ? h('a', { href: '#', onclick: e => { e.preventDefault(); select(n.bssid); window.sursumGo('scan'); } }, 'Show this access point') : null));

const table = (list, sep) => [['Priority', 'Category', 'Title', 'Detail', 'BSSID', 'Source', 'Help article'], ...list.map(n => [n.priority, n.category, n.title, n.detail, n.bssid || '', n.source === 'claude' ? 'Claude' : 'Built-in rules', ARTICLES[n.article]?.title || ''])]
  .map(r => r.map(v => (sep === ',' ? csvCell(v) : String(v).replace(/[\t\r\n]+/g, ' '))).join(sep)).join('\r\n');

async function askClaude() {
  if (!S.settings.ai.has_key) return toast('Add your Anthropic API key in Settings first.', true);
  if (S.loaded) return toast('Claude analysis runs on the live scan. Go back to the live scan first.');
  await api('/api/analysis/ai', {}); S.aiRunning = true; render();
  clearInterval(timer);
  timer = setInterval(async () => { await refreshAnalysis(); if (!S.aiRunning) { clearInterval(timer); if (S.ai.error) toast(S.ai.error, true); } }, 2500);
}

export function mount(el) { root = el; render(); }
export const onAnalysis = () => root?.isConnected && render();
export const unmount = () => clearInterval(timer);

function render() {
  const all = [...S.notes, ...(S.ai.notes || [])].sort((a, b) => ORDER.indexOf(a.priority) - ORDER.indexOf(b.priority));
  const list = all.filter(n => cat === 'All' || n.category === cat), count = p => all.filter(n => n.priority === p).length;
  root.replaceChildren(
    h('div', { class: 'kpis' }, ORDER.map(p => h('div', { class: 'kpi' }, h('div', { class: 'v', style: `color:${PRI[p]}` }, count(p)), h('div', { class: 'l' }, p)))),
    h('div', { class: 'row', style: 'margin-bottom:12px' },
      h('div', { class: 'seg' }, ['All', 'Security', 'Connectivity', 'Performance', 'Configuration'].map(c => h('button', { class: c === cat ? 'on' : '', onclick: () => { cat = c; render(); } },
        `${c} (${c === 'All' ? all.length : all.filter(n => n.category === c).length})`))),
      h('span', { class: 'grow' }),
      h('button', { title: 'Copy the notes shown so they paste straight into Excel', onclick: async () => { await navigator.clipboard.writeText(table(list, '\t')); toast('Copied. Paste into Excel.'); } }, 'Copy for Excel'),
      h('button', { onclick: () => download(`wifi-analysis-${new Date().toISOString().slice(0, 19).replace(/:/g, '')}.csv`, table(list, ','), 'text/csv') }, 'Export CSV'),
      h('button', { class: 'primary', disabled: S.aiRunning, onclick: askClaude }, S.aiRunning ? 'Claude is analysing…' : 'Ask Claude for a deeper analysis')),
    S.ai.summary ? h('div', { class: 'card' }, h('h2', {}, 'Claude’s summary'), h('p', {}, S.ai.summary), h('p', { class: 'dim' }, `${stamp(S.ai.t)} · ${S.ai.model || ''} · Claude’s notes are marked below and describe the scan at that time.`)) : null,
    S.ai.error ? h('div', { class: 'note', style: 'border-color:#ef5b5b' }, S.ai.error) : null,
    list.length ? list.map(note) : h('p', { class: 'dim' }, all.length ? 'Nothing in this category.' : 'No findings yet. Notes appear once networks have been scanned.'),
    h('p', { class: 'dim', style: 'margin-top:14px' }, 'The built-in notes come from rules that run on this PC and work offline. "Ask Claude" sends a summary of the current scan (network names, BSSIDs, channels, signal, security and LAN device addresses) to Anthropic using your API key.'));
}
