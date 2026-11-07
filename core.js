'use strict';
/* LIFEBOAT client core: state, safe templating, API, realtime, chrome. No frameworks, no CDNs. */

// ---------------------------------------------------------------- safe templating
// Every interpolated value is HTML-escaped unless explicitly wrapped in raw().
// Combined with a strict CSP (no inline script), this shuts the door on XSS.
const ESC = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ESC[c]);
class Raw { constructor(s) { this.s = s; } toString() { return this.s; } }
const raw = (s) => new Raw(s);
const renderVal = (v) => (v == null || v === false ? '' : v instanceof Raw ? v.s : Array.isArray(v) ? v.map(renderVal).join('') : esc(v));
function html(strings, ...vals) {
  let out = strings[0];
  for (let i = 0; i < vals.length; i++) out += renderVal(vals[i]) + strings[i + 1];
  return new Raw(out);
}
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
function setHTML(el, content) { if (typeof el === 'string') el = $(el); if (el) el.innerHTML = renderVal(content); }

// ---------------------------------------------------------------- icons (hand-drawn, inline)
const ICONS = {
  home: 'M3 11l9-8 9 8M5 9.5V21h5v-6h4v6h5V9.5',
  alert: 'M12 3l10 18H2L12 3zM12 10v5M12 18h.01',
  list: 'M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01',
  chat: 'M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z',
  phone: 'M22 16.9v3a2 2 0 0 1-2.2 2 19.8 19.8 0 0 1-8.6-3.1 19.5 19.5 0 0 1-6-6A19.8 19.8 0 0 1 2.1 4.2 2 2 0 0 1 4.1 2h3a2 2 0 0 1 2 1.7c.1.9.4 1.8.7 2.7a2 2 0 0 1-.5 2.1L8 9.8a16 16 0 0 0 6 6l1.3-1.3a2 2 0 0 1 2.1-.4c.9.3 1.8.6 2.7.7a2 2 0 0 1 1.7 2z',
  users: 'M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM23 21v-2a4 4 0 0 0-3-3.9M16 3.1a4 4 0 0 1 0 7.8',
  shield: 'M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z',
  lock: 'M5 11h14v10H5zM8 11V7a4 4 0 0 1 8 0v4',
  plus: 'M12 5v14M5 12h14',
  check: 'M20 6L9 17l-5-5',
  x: 'M18 6L6 18M6 6l12 12',
  clock: 'M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zM12 7v5l3 3',
  file: 'M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8zM14 2v6h6M8 13h8M8 17h5',
  db: 'M12 8c4.4 0 8-1.3 8-3s-3.6-3-8-3-8 1.3-8 3 3.6 3 8 3zM4 5v14c0 1.7 3.6 3 8 3s8-1.3 8-3V5M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3',
  scale: 'M12 3v18M7 21h10M5 7h14M5 7l-3 7a3 3 0 0 0 6 0zM19 7l-3 7a3 3 0 0 0 6 0z',
  target: 'M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zM12 18a6 6 0 1 0 0-12 6 6 0 0 0 0 12zM12 14a2 2 0 1 0 0-4 2 2 0 0 0 0 4z',
  box: 'M21 8l-9-5-9 5v8l9 5 9-5zM3 8l9 5 9-5M12 13v8',
  upload: 'M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M17 8l-5-5-5 5M12 3v12',
  download: 'M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4M7 10l5 5 5-5M12 15V3',
  printer: 'M6 9V2h12v7M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2M6 14h12v8H6z',
  tv: 'M2 7h20v13H2zM17 2l-5 5-5-5',
  sliders: 'M4 21v-7M4 10V3M12 21v-9M12 8V3M20 21v-5M20 12V3M1 14h6M9 8h6M17 16h6',
  search: 'M11 19a8 8 0 1 0 0-16 8 8 0 0 0 0 16zM21 21l-4.3-4.3',
  activity: 'M22 12h-4l-3 9L9 3l-3 9H2',
  flag: 'M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1zM4 22v-7',
  logout: 'M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9',
  copy: 'M9 9h13v13H9zM5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1',
  send: 'M22 2L11 13M22 2l-7 20-4-9-9-4z',
  bell: 'M18 8a6 6 0 0 0-12 0c0 7-3 9-3 9h18s-3-2-3-9M13.7 21a2 2 0 0 1-3.4 0',
  help: 'M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20zM9.1 9a3 3 0 0 1 5.8 1c0 2-3 3-3 3M12 17h.01',
  edit: 'M12 20h9M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4z',
  strike: 'M3 6h18M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6M10 11v6M14 11v6M9 6V4h6v2',
  zap: 'M13 2L3 14h9l-1 8 10-12h-9z',
  moon: 'M21 12.8A9 9 0 1 1 11.2 3 7 7 0 0 0 21 12.8z',
  eye: 'M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8zM12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6z',
  key: 'M21 2l-2 2m-7.6 7.6a5.5 5.5 0 1 1-7.8 7.8 5.5 5.5 0 0 1 7.8-7.8zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4',
  arrow: 'M5 12h14M12 5l7 7-7 7',
};
const icon = (n) => raw(`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="${ICONS[n] || ''}"/></svg>`);
const LOGO = raw('<svg viewBox="0 0 32 32" aria-hidden="true"><path d="M4 18h24l-3.5 8h-17z" fill="#ff6b35"/><path d="M16 4v12M16 5l8 10h-8" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round"/><path d="M2 29c3 0 3-1.5 6-1.5s3 1.5 6 1.5 3-1.5 6-1.5 3 1.5 6 1.5" fill="none" stroke="#4da3ff" stroke-width="1.6"/></svg>');

// ---------------------------------------------------------------- state
const S = {
  me: null, csrf: null, perms: {}, roles: {}, org: null, lockdown: { on: false }, users: [], channels: [],
  phases: [], categories: {}, dataTypes: {}, states: {}, online: new Set(), inc: new Map(), msgs: new Map(),
  unread: {}, conn: 'down', serverOffset: 0, idleMs: 30 * 60e3, tls: true, loaded: false,
  scribeKind: 'note', theme: 'dark',
};
const store = {
  get(k, d) { try { const v = localStorage.getItem('lb:' + k); return v == null ? d : JSON.parse(v); } catch { return d; } },
  set(k, v) { try { localStorage.setItem('lb:' + k, JSON.stringify(v)); } catch { /* storage may be blocked */ } },
};

// ---------------------------------------------------------------- API
let lastTouch = Date.now();
async function api(method, path, body, opts = {}) {
  const headers = { Accept: 'application/json' };
  let payload;
  if (body instanceof Blob) { headers['Content-Type'] = 'application/octet-stream'; payload = body; Object.assign(headers, opts.headers || {}); }
  else if (body !== undefined) { headers['Content-Type'] = 'application/json'; payload = JSON.stringify(body); }
  if (S.csrf) headers['X-CSRF-Token'] = S.csrf;
  let res;
  try {
    res = await fetch(path, { method, headers, body: payload, credentials: 'same-origin', cache: 'no-store' });
  } catch {
    throw new Error('Cannot reach the LIFEBOAT server. Check your connection.');
  }
  if (method !== 'GET') lastTouch = Date.now();
  const data = (res.headers.get('content-type') || '').includes('json') ? await res.json().catch(() => null) : null;
  if (!res.ok) {
    if (res.status === 401 && S.me && !opts.quiet401) sessionEnded('Your session ended. Please sign in again.');
    const e = new Error(data?.error || `Request failed (${res.status})`);
    e.status = res.status;
    throw e;
  }
  return data;
}
async function act(promise, okMsg) {
  try { const r = await promise; if (okMsg) toast(okMsg, 'ok'); return r; } catch (e) { toast(e.message, 'err'); return null; }
}

// ---------------------------------------------------------------- time
const nowMs = () => Date.now() + S.serverOffset;
const pad = (n) => String(n).padStart(2, '0');
function fmtUTC(iso, secs = false) {
  if (!iso) return '-';
  const d = new Date(iso);
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}${secs ? ':' + pad(d.getUTCSeconds()) : ''}Z`;
}
const fmtTimeUTC = (iso) => { const d = new Date(iso); return `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}Z`; };
function fmtLocal(iso) {
  if (!iso) return '-';
  return new Date(iso).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}
function human(ms) {
  ms = Math.abs(ms);
  const d = Math.floor(ms / 864e5), h = Math.floor(ms / 36e5) % 24, m = Math.floor(ms / 6e4) % 60, s = Math.floor(ms / 1e3) % 60;
  if (d) return `${d}d ${h}h`;
  if (h) return `${h}h ${pad(m)}m`;
  if (m) return `${m}m ${pad(s)}s`;
  return `${s}s`;
}
function ago(iso) {
  if (!iso) return '';
  const ms = nowMs() - new Date(iso).getTime();
  return ms < 45e3 ? 'just now' : human(ms).split(' ')[0] + ' ago';
}
function elapsed(ms) {
  ms = Math.max(0, ms);
  const d = Math.floor(ms / 864e5), h = Math.floor(ms / 36e5) % 24, m = Math.floor(ms / 6e4) % 60, s = Math.floor(ms / 1e3) % 60;
  return `${d ? d + 'd ' : ''}${pad(h)}:${pad(m)}:${pad(s)}`;
}
function cdState(iso, done) {
  if (done) return { cls: 'done', text: 'done' };
  if (!iso) return { cls: '', text: '' };
  const diff = new Date(iso).getTime() - nowMs();
  if (diff < 0) return { cls: 'over', text: 'OVERDUE ' + human(diff) };
  return { cls: diff < 6 * 36e5 ? 'urgent' : diff < 24 * 36e5 ? 'soon' : 'ok', text: 'in ' + human(diff) };
}
const countdown = (iso, done) => { const c = cdState(iso, done); return html`<span class="cd ${c.cls}" data-cd="${iso || ''}" ${done ? raw('data-done="1"') : ''}>${c.text}</span>`; };
const since = (iso, end) => html`<span class="tplus" data-since="${iso}" ${end ? raw(`data-end="${esc(end)}"`) : ''}>T+ ${elapsed((end ? new Date(end).getTime() : nowMs()) - new Date(iso).getTime())}</span>`;
function toLocalInput(iso) {
  const d = iso ? new Date(iso) : new Date(nowMs());
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}
const fromLocalInput = (v) => (v ? new Date(v).toISOString() : null);

// one ticker drives every clock and countdown on screen, no re-render needed
setInterval(() => {
  for (const el of $$('[data-since]')) {
    const end = el.dataset.end ? new Date(el.dataset.end).getTime() : nowMs();
    el.textContent = 'T+ ' + elapsed(end - new Date(el.dataset.since).getTime());
  }
  for (const el of $$('[data-cd]')) {
    if (!el.dataset.cd) continue;
    const c = cdState(el.dataset.cd, el.dataset.done);
    el.textContent = c.text;
    el.className = 'cd ' + c.cls;
  }
  const u = $('#clock-utc'), l = $('#clock-local');
  if (u) { const d = new Date(nowMs()); u.textContent = `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`; }
  if (l) l.textContent = new Date(nowMs()).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
  const w = $('#wall-clock');
  if (w) { const d = new Date(nowMs()); w.textContent = `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}Z`; }
}, 1000);

// ---------------------------------------------------------------- people helpers
const userById = (id) => S.users.find((u) => u.id === id);
const userName = (id) => (id ? userById(id)?.displayName || 'Unknown' : 'LIFEBOAT');
const PALETTE = ['#e8590c', '#1c7ed6', '#2b8a3e', '#ae3ec9', '#c2255c', '#0c8599', '#5f3dc4', '#e67700', '#364fc7', '#087f5b'];
function initials(name) { return String(name || '?').split(/\s+/).filter(Boolean).slice(0, 2).map((p) => p[0]).join(''); }
function avatar(id, sm = false, showOnline = false) {
  const u = userById(id);
  let h = 0;
  for (const c of String(id || 'x')) h = (h * 31 + c.charCodeAt(0)) >>> 0;
  return html`<span class="avatar ${sm ? 'sm' : ''}" data-color="${PALETTE[h % PALETTE.length]}" title="${u ? u.displayName + ' · ' + (S.roles[u.role] || u.role) : 'LIFEBOAT'}">${u ? initials(u.displayName) : '⛵'}${showOnline ? html`<i class="dot ${S.online.has(id) ? 'on' : ''}"></i>` : ''}</span>`;
}
// CSP blocks inline style attributes, so colors are applied through the DOM after render.
function paint(root = document) {
  const pick = (sel) => [...(root.matches?.(sel) ? [root] : []), ...$$(sel, root)];
  for (const el of pick('[data-color]')) el.style.background = el.dataset.color;
  for (const el of pick('[data-w]')) el.style.width = el.dataset.w + '%';
}
new MutationObserver((muts) => { for (const m of muts) for (const n of m.addedNodes) if (n.nodeType === 1) paint(n); }).observe(document.documentElement, { childList: true, subtree: true });

// ---------------------------------------------------------------- incident helpers
const phaseById = (id) => S.phases.find((p) => p.id === id) || { label: id, short: id };
const phaseIndex = (id) => S.phases.findIndex((p) => p.id === id);
const sevChip = (s, pulse = true) => html`<span class="chip sev sev-${s} ${pulse && s === 1 ? 'pulse' : ''}">SEV${s}</span>`;
const SEV_TEXT = { 1: 'Critical', 2: 'High', 3: 'Medium', 4: 'Low' };
const SEV_DESC = { 1: 'Business stopped, or sensitive data stolen or locked', 2: 'Major systems or many people affected', 3: 'Limited impact, contained to a few systems', 4: 'Suspicious activity, still being checked' };
const isActive = (i) => i.status !== 'closed';
const allIncidents = () => [...S.inc.values()].sort((a, b) => a.severity - b.severity || b.detectedAt.localeCompare(a.detectedAt));
const live = (arr) => (arr || []).filter((x) => !x.deleted);
const openObligations = (inc) => inc.obligations.filter((o) => o.status !== 'done' && o.status !== 'na');
function miniPhases(inc) {
  const idx = phaseIndex(inc.status);
  return html`<span class="mini-phases" title="${phaseById(inc.status).label}">${S.phases.slice(0, 5).map((p, i) => html`<i class="${i < idx || inc.status === 'closed' ? 'done' : i === idx ? 'cur' : ''}"></i>`)}</span>`;
}
function progressBar(done, total) {
  const pct = total ? Math.round((done / total) * 100) : 0;
  return html`<div class="progress" title="${done}/${total}"><i data-w="${pct}"></i></div>`;
}
const STATUS_LABEL = {
  encrypted: ['Encrypted', 'Locked by ransomware'], exfiltrated: ['Exfiltrated', 'Copied out by the attacker'], accessed: ['Accessed', 'Viewed, not known to be copied'],
  deleted: ['Deleted', 'Destroyed or wiped'], corrupted: ['Altered', 'Modified or corrupted'], 'at-risk': ['At risk', 'Exposed, status unknown'],
  secured: ['Secured', 'Confirmed safe / access cut'], restored: ['Restored', 'Recovered from backup'],
};
const statusChip = (s) => html`<span class="chip st st-${s}">${STATUS_LABEL[s]?.[0] || s}</span>`;

// ---------------------------------------------------------------- UI primitives
function toast(msg, type = '', onClick) {
  const el = document.createElement('div');
  el.className = 'toast ' + type;
  el.textContent = msg;
  el.addEventListener('click', () => { el.remove(); onClick && onClick(); });
  $('#toasts').append(el);
  setTimeout(() => el.remove(), type === 'urgent' ? 15000 : type === 'err' ? 7000 : 3500);
}

let modalCloseCb = null;
function modal(content, { wide = false, cls = '', onClose = null } = {}) {
  const root = $('#modal-root');
  root.innerHTML = renderVal(html`<div class="modal-back"><div class="modal ${wide ? 'wide' : ''} ${cls}" role="dialog" aria-modal="true">${content}</div></div>`);
  const back = root.firstElementChild;
  back.addEventListener('mousedown', (e) => { if (e.target === back) closeModal(); });
  modalCloseCb = onClose;
  const f = $('[autofocus]', root) || $('input:not([type=hidden]):not([type=checkbox]), textarea, select', root);
  if (f) setTimeout(() => f.focus(), 20);
  return back.firstElementChild;
}
function closeModal() {
  $('#modal-root').innerHTML = '';
  const cb = modalCloseCb;
  modalCloseCb = null;
  cb && cb();
}
const modalOpen = () => !!$('#modal-root').firstElementChild;
const mHead = (title, sub) => html`<div class="modal-head"><div><h2>${title}</h2>${sub ? html`<p>${sub}</p>` : ''}</div><button class="iconbtn" type="button" data-a="closeModal" aria-label="Close">${icon('x')}</button></div>`;

function confirmBox(title, text, okLabel = 'Confirm', danger = false) {
  return new Promise((resolve) => {
    let done = false;
    const finish = (v) => { if (!done) { done = true; resolve(v); } };
    modal(html`${mHead(title)}<div class="modal-body"><p class="muted">${text}</p></div>
      <div class="modal-foot"><button class="btn" type="button" id="cf-no">Cancel</button><button class="btn ${danger ? 'danger' : 'primary'}" type="button" id="cf-yes" autofocus>${okLabel}</button></div>`, { onClose: () => finish(false) });
    $('#cf-no').onclick = () => closeModal();
    $('#cf-yes').onclick = () => { finish(true); closeModal(); };
  });
}

/** Ask for one value. type: text | textarea | datetime | select. Resolves to the value, or undefined if cancelled. */
function ask(title, { label = '', value = '', type = 'text', options = [], hint = '', okLabel = 'Save', allowClear = false } = {}) {
  return new Promise((resolve) => {
    let done = false;
    const finish = (v) => { if (!done) { done = true; resolve(v); } };
    let input;
    if (type === 'textarea') input = html`<textarea id="ask-v" rows="6">${value}</textarea>`;
    else if (type === 'datetime') input = html`<input type="datetime-local" id="ask-v" value="${toLocalInput(value)}"><span class="hint">Your local time. Stored and shown in UTC.</span>`;
    else if (type === 'select') input = html`<select id="ask-v">${options.map(([v, l]) => html`<option value="${v}" ${v === value ? raw('selected') : ''}>${l}</option>`)}</select>`;
    else input = html`<input type="text" id="ask-v" value="${value}">`;
    modal(html`<form id="ask-f">${mHead(title)}<div class="modal-body"><label class="field">${label}${input}${hint ? html`<span class="hint">${hint}</span>` : ''}</label></div>
      <div class="modal-foot">${allowClear ? html`<button class="btn ghost" type="button" id="ask-clear">Clear</button><span class="grow"></span>` : ''}<button class="btn" type="button" data-a="closeModal">Cancel</button><button class="btn primary">${okLabel}</button></div></form>`, { onClose: () => finish(undefined) });
    if (type === 'datetime') { const b = document.createElement('button'); b.type = 'button'; b.className = 'btn sm'; b.textContent = 'Now'; b.onclick = () => ($('#ask-v').value = toLocalInput()); $('#ask-v').after(b); }
    $('#ask-f').onsubmit = (e) => { e.preventDefault(); const v = $('#ask-v').value; finish(type === 'datetime' ? fromLocalInput(v) : v); closeModal(); };
    const c = $('#ask-clear'); if (c) c.onclick = () => { finish(null); closeModal(); };
  });
}

async function copyText(text, label = 'Copied') {
  try { await navigator.clipboard.writeText(text); toast(label, 'ok'); } catch {
    const t = document.createElement('textarea'); t.value = text; document.body.append(t); t.select();
    try { document.execCommand('copy'); toast(label, 'ok'); } catch { toast('Copy failed. Select the text manually.', 'err'); }
    t.remove();
  }
}
function downloadText(name, text, type = 'text/plain') {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = document.createElement('a'); a.href = url; a.download = name; document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
const csvCell = (v) => { let s = String(v ?? ''); if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; return '"' + s.replace(/"/g, '""') + '"'; };
const toCsv = (rows) => rows.map((r) => r.map(csvCell).join(',')).join('\r\n');

// Focus-safe re-render: live updates never steal your cursor or wipe what you are typing.
function withFocus(fn) {
  const a = document.activeElement;
  const id = a && a.id;
  let val, ss, se;
  if (id && 'value' in a) { val = a.value; try { ss = a.selectionStart; se = a.selectionEnd; } catch { /* not a text input */ } }
  const keep = $$('[data-keep]').filter((e) => e.id).map((e) => [e.id, e.type === 'checkbox' ? e.checked : e.value]);
  const scrolls = $$('[data-scroll]').map((e) => [e.dataset.scroll, e.scrollTop, e.scrollHeight - e.scrollTop - e.clientHeight < 40]);
  const opened = $$('details[id]').filter((d) => d.open).map((d) => d.id);
  fn();
  for (const [i, v] of keep) { const e = document.getElementById(i); if (e) { if (e.type === 'checkbox') e.checked = v; else e.value = v; } }
  for (const i of opened) { const d = document.getElementById(i); if (d) d.open = true; }
  for (const [k, top, atBottom] of scrolls) { const e = $(`[data-scroll="${k}"]`); if (e) e.scrollTop = atBottom ? e.scrollHeight : top; }
  if (id) {
    const e = document.getElementById(id);
    if (e && e !== document.activeElement) {
      e.focus();
      if (val !== undefined) { e.value = val; try { e.setSelectionRange(ss, se); } catch { /* ignore */ } }
    }
  }
}

// ---------------------------------------------------------------- event delegation (CSP: no inline handlers)
const A = {};
A.closeModal = () => closeModal();
document.addEventListener('click', (e) => {
  const t = e.target.closest('[data-a]');
  if (!t || t.disabled) return;
  const fn = A[t.dataset.a];
  if (fn) { if (t.tagName !== 'INPUT') e.preventDefault(); fn(t, e); }
});
document.addEventListener('change', (e) => {
  const t = e.target.closest('[data-change]');
  if (t && A[t.dataset.change]) A[t.dataset.change](t, e);
});
document.addEventListener('submit', (e) => {
  const f = e.target.closest('form[data-submit]');
  if (f) { e.preventDefault(); A[f.dataset.submit](f, e); }
});
const formData = (f) => Object.fromEntries(new FormData(f));

// ---------------------------------------------------------------- realtime
let es = null, reconnectTimer = null;
function setConn(c) {
  S.conn = c;
  const el = $('#conn');
  if (el) { el.className = 'conn ' + c; el.innerHTML = renderVal(c === 'live' ? html`<i class="dot on"></i>LIVE` : html`<i class="dot"></i>RECONNECTING`); }
}
function connectStream() {
  if (es) es.close();
  es = new EventSource('/api/stream');
  const on = (type, fn) => es.addEventListener(type, (e) => { try { fn(JSON.parse(e.data)); } catch (err) { console.error(err); } });
  on('hello', (d) => {
    S.serverOffset = new Date(d.serverTime).getTime() - Date.now();
    const wasDown = S.conn !== 'live';
    setConn('live');
    if (wasDown && S.loaded) resync();
  });
  on('incident', async (d) => {
    try { const inc = await api('GET', '/api/incidents/' + d.id, undefined, { quiet401: true }); S.inc.set(inc.id, inc); } catch (e) { if (e.status === 404) S.inc.delete(d.id); }
    refresh('incident', d.id);
  });
  on('message', (m) => {
    const list = S.msgs.get(m.channelId) || [];
    if (!list.some((x) => x.id === m.id)) list.push(m);
    S.msgs.set(m.channelId, list);
    const viewing = currentChannel() === m.channelId && document.hasFocus();
    if (!viewing && m.userId !== S.me.id) S.unread[m.channelId] = (S.unread[m.channelId] || 0) + 1;
    if (viewing) markRead(m.channelId);
    if (m.userId !== S.me.id) {
      const ch = S.channels.find((c) => c.id === m.channelId);
      if (m.urgent) { toast(`URGENT from ${userName(m.userId)} in #${ch?.name}: ${m.text.slice(0, 140)}`, 'urgent', () => (location.hash = '#/comms/' + m.channelId)); beep(); }
      else if (!viewing) toast(`${userName(m.userId)} in #${ch?.name}: ${m.text.slice(0, 100)}`, '', () => (location.hash = '#/comms/' + m.channelId));
    }
    refresh('message', m.channelId);
  });
  on('ack', (d) => {
    const m = (S.msgs.get(d.channelId) || []).find((x) => x.id === d.id);
    if (m) m.acks[d.userId] = d.at;
    refresh('message', d.channelId);
  });
  on('presence', (d) => { S.online = new Set(d.online); refresh('presence'); });
  on('notify', (d) => toast(d.text, 'urgent', () => d.incidentId && (location.hash = '#/i/' + d.incidentId + '/tasks')));
  on('users', () => resync(false));
  on('channels', () => resync(false));
  on('org', () => resync());
  on('lockdown', (d) => { S.lockdown = d; refresh('lockdown'); if (d.on) toast('LOCKDOWN ACTIVATED. Non-admin users have been signed out.', 'urgent'); });
  on('logout', (d) => sessionEnded(d.reason === 'lockdown' ? 'LIFEBOAT was placed in lockdown by an administrator.' : d.reason === 'expired' ? 'Signed out after inactivity, for security.' : 'Your session was ended.'));
  es.onerror = () => {
    setConn('down');
    if (es.readyState === 2) {
      clearTimeout(reconnectTimer);
      reconnectTimer = setTimeout(async () => { try { await api('GET', '/api/me'); connectStream(); } catch { /* 401 handled by api() */ } }, 3000);
    }
  };
}
function beep() {
  try {
    const ctx = new (window.AudioContext || window.webkitAudioContext)();
    const o = ctx.createOscillator(), g = ctx.createGain();
    o.connect(g); g.connect(ctx.destination); o.frequency.value = 880; g.gain.value = 0.06;
    o.start(); o.stop(ctx.currentTime + 0.18);
  } catch { /* audio unavailable */ }
}

async function loadBootstrap() {
  const b = await api('GET', '/api/bootstrap');
  Object.assign(S, { org: b.org, lockdown: b.lockdown, users: b.users, channels: b.channels, phases: b.phases, categories: b.categories, dataTypes: b.dataTypes, states: b.states });
  S.online = new Set(b.online);
  return b;
}
async function resync(full = true) {
  try {
    const b = await loadBootstrap();
    if (full) {
      const incs = await Promise.all(b.incidents.map((i) => api('GET', '/api/incidents/' + i.id).catch(() => null)));
      S.inc = new Map(incs.filter(Boolean).map((i) => [i.id, i]));
      await Promise.all(S.channels.map(loadMessages));
    } else {
      for (const c of S.channels) if (!S.msgs.has(c.id)) await loadMessages(c);
      const visible = new Set(b.incidents.map((i) => i.id));
      for (const id of [...S.inc.keys()]) if (!visible.has(id)) S.inc.delete(id);
      for (const i of b.incidents) if (!S.inc.has(i.id)) { const full = await api('GET', '/api/incidents/' + i.id).catch(() => null); if (full) S.inc.set(full.id, full); }
    }
    refresh('all');
  } catch (e) { console.error(e); }
}
async function loadMessages(c) {
  const list = await api('GET', `/api/channels/${c.id}/messages`).catch(() => []);
  S.msgs.set(c.id, list);
  const lastRead = store.get('read:' + S.me.id + ':' + c.id, null);
  S.unread[c.id] = list.filter((m) => m.userId !== S.me.id && (!lastRead || m.at > lastRead)).length;
}
function markRead(chId) {
  S.unread[chId] = 0;
  const list = S.msgs.get(chId) || [];
  if (list.length) store.set('read:' + S.me.id + ':' + chId, list[list.length - 1].at);
}
const urgentPending = () => [...S.msgs.values()].flat().filter((m) => m.urgent && m.userId !== S.me.id && !m.acks[S.me.id]);

// ---------------------------------------------------------------- idle protection
let lastActivity = Date.now(), idleWarned = false;
for (const ev of ['keydown', 'pointerdown', 'pointermove', 'wheel', 'touchstart']) addEventListener(ev, () => { lastActivity = Date.now(); }, { passive: true, capture: true });
setInterval(() => {
  if (!S.me) return;
  const t = Date.now();
  if (lastActivity > lastTouch && t - lastTouch > 60e3) { api('POST', '/api/ping', {}).catch(() => {}); idleWarned = false; }
  if (!idleWarned && t - lastTouch > S.idleMs - 90e3 && t - lastActivity > S.idleMs - 90e3) {
    idleWarned = true;
    toast('You will be signed out in about 90 seconds due to inactivity. Move the mouse or press a key to stay signed in.', 'urgent');
  }
}, 5000);

// ---------------------------------------------------------------- theme
function applyTheme(t) { S.theme = t; document.documentElement.dataset.theme = t; store.set('theme', t); }
applyTheme(store.get('theme', 'dark'));
