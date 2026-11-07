/* IRONROOM front-end.
 * Security rule for this file: user data is ONLY ever inserted with textContent / DOM
 * properties via h(). No innerHTML, no eval, no inline handlers (CSP enforces this). */
'use strict';

const S = {
  meta: null, user: null, csrf: null, incidents: [], cur: null, data: null, tab: 'overview',
  chan: 'incident', channel: [], users: [], online: [], ws: null, live: false, lastApi: Date.now(),
  urgent: null, wsEverOpen: false, skew: 0, unread: { incident: 0, team: 0 },
  tz: (() => { try { return localStorage.getItem('ironroom_tz') || 'local'; } catch (_) { return 'local'; } })(),
  tlFilter: { q: '', hideSys: false },
};
const nowMs = () => Date.now() + S.skew;   // server-corrected clock

// ---------- tiny DOM helper (safe by construction) ----------
function h(tag, props, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (k === 'value') el.value = v;
    else if (k === 'checked') el.checked = !!v;
    else if (k === 'src' && !(String(v).startsWith('data:image/png') || String(v).startsWith('/'))) continue;
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const c of kids.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}
const $ = (id) => document.getElementById(id);
function mount(el, ...kids) { if (!el) return; el.replaceChildren(...kids.flat(Infinity).filter(Boolean)); }
function safeRender(el, fn) {
  // don't yank inputs out from under someone who is typing
  if (!el) return;
  const a = document.activeElement;
  if (a && el.contains(a) && /INPUT|TEXTAREA|SELECT/.test(a.tagName)) {
    if (!el._pending) {
      el._pending = true;
      a.addEventListener('blur', () => setTimeout(() => { el._pending = false; safeRender(el, fn); }, 150), { once: true });
    }
    return;
  }
  fn(el);
}

// ---------- API ----------
async function api(method, path, body) {
  const r = await fetch(path, {
    method, credentials: 'same-origin', cache: 'no-store',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': S.csrf || '' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  let j = null;
  try { j = await r.json(); } catch (_) { /* ignore */ }
  if (r.status === 401) {
    if (S.user) signedOut(j && j.error);
    throw new Error((j && j.error) || 'Signed out');
  }
  if (!r.ok) throw new Error((j && j.error) || ('Error ' + r.status));
  S.lastApi = Date.now();
  return j;
}
const can = (p) => S.user && S.user.perms.includes(p);

// ---------- formatting ----------
const toDate = (x) => (typeof x === 'number' ? new Date(x * 1000) : new Date(x));
const tzName = () => (S.tz === 'utc' ? 'UTC' : (new Date().toLocaleTimeString(undefined, { timeZoneName: 'short' }).split(' ').pop()));
// Full timestamp in the user's chosen zone. 24h clock, seconds, zone label: unambiguous for the record.
function fmt(x, opt = {}) {
  if (!x) return '—';
  const d = toDate(x);
  if (isNaN(d)) return String(x);
  if (S.tz === 'utc') {
    const iso = d.toISOString().replace('T', ' ');
    return (opt.short ? iso.slice(5, 16) : iso.slice(0, 19)) + (opt.short ? 'Z' : ' UTC');
  }
  return d.toLocaleString(undefined, opt.short
    ? { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', hour12: false }
    : { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false, timeZoneName: 'short' });
}
function fmtTime(x) {
  const d = toDate(x);
  if (S.tz === 'utc') return d.toISOString().slice(11, 19) + 'Z';
  return d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
}
function fmtDay(x) {
  const d = toDate(x);
  if (S.tz === 'utc') return d.toISOString().slice(0, 10) + ' (UTC)';
  return d.toLocaleDateString(undefined, { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' });
}
// <time> element: shows chosen zone, hover shows UTC + local + relative
function ts(x, opt = {}) {
  if (!x) return h('span', { class: 'muted' }, '—');
  const d = toDate(x);
  if (isNaN(d)) return h('span', {}, String(x));
  return h('time', {
    datetime: d.toISOString(), class: 'ts',
    title: `${d.toISOString().replace('T', ' ').slice(0, 19)} UTC\n${d.toLocaleString(undefined, { hour12: false, timeZoneName: 'long' })}`,
  }, opt.timeOnly ? fmtTime(x) : fmt(x, opt), opt.rel ? h('span', { class: 'muted' }, ' (', liveRel(x), ')') : null);
}
// spans that the 1-second ticker keeps current
function liveRel(x) { const s = h('span', { class: 'live-rel' }, rel(x)); s.dataset.t = toDate(x).getTime(); return s; }
function liveDur(dueMs) { const s = h('span', { class: 'live-dur' }, dur(dueMs - nowMs())); s.dataset.due = dueMs; return s; }
function liveElapsed(fromMs) { const s = h('span', { class: 'live-el' }, elapsed(nowMs() - fromMs)); s.dataset.from = fromMs; return s; }
function elapsed(ms) {
  if (ms < 0 || isNaN(ms)) return '—';
  const d = Math.floor(ms / 864e5), hh = Math.floor(ms % 864e5 / 36e5), mm = Math.floor(ms % 36e5 / 6e4), ss = Math.floor(ms % 6e4 / 1000);
  return d ? `${d}d ${hh}h ${mm}m` : hh ? `${hh}h ${mm}m` : `${mm}m ${ss}s`;
}
function rel(iso) {
  const d = toDate(iso);
  const s = (nowMs() - d) / 1000;
  if (isNaN(s)) return '';
  if (s < -60) return 'in ' + elapsed(-s * 1000);
  if (s < 60) return 'just now';
  if (s < 3600) return Math.floor(s / 60) + 'm ago';
  if (s < 86400) return Math.floor(s / 3600) + 'h ago';
  return Math.floor(s / 86400) + 'd ago';
}
function toLocalInput(iso) {
  const d = new Date(iso);
  if (!iso || isNaN(d)) return '';
  return new Date(d - d.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
}
const fromLocalInput = (v) => (v ? new Date(v).toISOString() : '');
const n = (x) => (x == null ? '—' : Number(x).toLocaleString());
const dsClass = (st) => 'pill ds ds-' + String(st || 'Unknown').split(' ')[0];
function dur(ms) {
  const neg = ms < 0; ms = Math.abs(ms);
  const d = Math.floor(ms / 864e5), hh = Math.floor(ms % 864e5 / 36e5), mm = Math.floor(ms % 36e5 / 6e4);
  const t = d ? `${d}d ${hh}h` : hh ? `${hh}h ${mm}m` : `${mm}m`;
  return neg ? t + ' overdue' : t + ' left';
}

// ---------- toasts / modals ----------
function toast(msg, kind = '') {
  const t = h('div', { class: 'toast ' + kind }, msg);
  $('toasts').append(t);
  setTimeout(() => t.remove(), kind === 'urgent' ? 12000 : 4000);
}
function modal(title, body, { wide = false } = {}) {
  const close = () => { $('modal-layer').replaceChildren(); };
  const ov = h('div', { class: 'overlay', onclick: (e) => { if (e.target === ov) close(); } },
    h('div', { class: 'modal' + (wide ? ' wide' : ''), role: 'dialog', 'aria-modal': 'true' },
      h('div', { class: 'modal-h' }, h('h2', {}, title), h('button', { class: 'btn ghost right', onclick: close, 'aria-label': 'Close' }, '✕ Close')),
      body));
  mount($('modal-layer'), ov);
  const f = ov.querySelector('input,textarea,select');
  if (f) f.focus();
  return close;
}
document.addEventListener('keydown', (e) => { if (e.key === 'Escape') $('modal-layer').replaceChildren(); });
async function run(btn, fn) {
  if (btn) btn.disabled = true;
  try { return await fn(); } catch (e) { toast(e.message, 'bad'); } finally { if (btn) btn.disabled = false; }
}

// ---------- boot ----------
async function boot() {
  const t0 = Date.now();
  S.meta = await (await fetch('/api/meta', { cache: 'no-store' })).json();
  S.skew = S.meta.server_time * 1000 - (t0 + Date.now()) / 2;
  try {
    const s = await api('GET', '/api/session');
    S.user = s.user; S.csrf = s.csrf;
    afterLogin();
  } catch (_) { renderLogin(); }
}

function signedOut(reason) {
  S.user = null; S.csrf = null; S.data = null; S.cur = null;
  if (S.ws) { S.ws.onclose = null; S.ws.close(); S.ws = null; }
  $('modal-layer').replaceChildren();
  renderLogin(reason || 'You were signed out.');
}

// ---------- login ----------
function renderLogin(notice) {
  let errBox = h('div');
  const user = h('input', { type: 'text', id: 'u', autocomplete: 'username', autocapitalize: 'none', spellcheck: 'false' });
  const pw = h('input', { type: 'password', id: 'p', autocomplete: 'current-password' });
  const code = h('input', { type: 'text', id: 'c', class: 'code-input', inputmode: 'numeric', maxlength: '6', autocomplete: 'one-time-code', placeholder: '••••••' });
  const btn = h('button', { class: 'btn primary big', type: 'submit' }, 'Sign in');
  const form = h('form', {
    class: 'steps', onsubmit: async (e) => {
      e.preventDefault();
      mount(errBox);
      await run(btn, async () => {
        try {
          const r = await api('POST', '/api/login', { username: user.value, password: pw.value, code: code.value });
          S.user = r.user; S.csrf = r.csrf;
          afterLogin();
        } catch (err) { mount(errBox, h('div', { class: 'err' }, err.message)); code.value = ''; code.focus(); }
      });
    },
  },
    h('label', { class: 'f', for: 'u' }, h('span', {}, h('span', { class: 'step-n' }, '1'), 'Username'), user),
    h('label', { class: 'f', for: 'p' }, h('span', {}, h('span', { class: 'step-n' }, '2'), 'Password'), pw),
    h('label', { class: 'f', for: 'c' }, h('span', {}, h('span', { class: 'step-n' }, '3'), '6-digit code from your authenticator app'), code),
    errBox, btn);
  mount($('root'), h('div', { class: 'login' }, h('div', { class: 'card' },
    h('div', { class: 'brand' }, h('div', { class: 'logo' }, '▣'), 'IRONROOM'),
    h('h1', {}, 'Incident Command Center'),
    h('div', { class: 'muted small' }, 'Secure, out-of-band workspace. Use this instead of corporate email or chat during an incident.'),
    notice ? h('div', { class: 'okbox', style: null }, notice) : null,
    form,
    h('div', { class: 'fp' }, 'Before signing in, confirm your browser shows this certificate fingerprint (ask the administrator in person or by phone):', h('br'), S.meta.fingerprint))));
  user.focus();
}

function renderMustChange() {
  const cur = h('input', { type: 'password', autocomplete: 'current-password' });
  const n1 = h('input', { type: 'password', autocomplete: 'new-password' });
  const n2 = h('input', { type: 'password', autocomplete: 'new-password' });
  const err = h('div');
  const btn = h('button', { class: 'btn primary big', type: 'submit' }, 'Save new password');
  mount($('root'), h('div', { class: 'login' }, h('div', { class: 'card' },
    h('div', { class: 'brand' }, h('div', { class: 'logo' }, '▣'), 'IRONROOM'),
    h('h1', {}, `Welcome, ${S.user.display}`),
    h('div', { class: 'muted small' }, 'First sign-in: replace the temporary password you were given. Use 12+ characters — a short sentence works well.'),
    h('form', {
      class: 'steps', onsubmit: (e) => {
        e.preventDefault(); mount(err);
        if (n1.value !== n2.value) { mount(err, h('div', { class: 'err' }, 'The two new passwords don’t match')); return; }
        run(btn, async () => {
          try { const r = await api('POST', '/api/me/password', { current: cur.value, new: n1.value }); S.user = r.user; toast('Password updated'); afterLogin(); }
          catch (er) { mount(err, h('div', { class: 'err' }, er.message)); }
        });
      },
    },
      h('label', { class: 'f' }, 'Temporary password', cur),
      h('label', { class: 'f' }, 'New password (12+ characters)', n1),
      h('label', { class: 'f' }, 'Type new password again', n2), err, btn),
    h('button', { class: 'btn ghost', onclick: logout }, 'Sign out'))));
  cur.focus();
}

async function logout() { try { await api('POST', '/api/logout'); } catch (_) { /* ignore */ } signedOut('Signed out.'); }

// ---------- main app ----------
async function afterLogin() {
  if (S.user.must_change) return renderMustChange();
  renderShell();
  connectWS();
  await Promise.all([loadIncidents(), loadUsers(), loadChannel()]);
  if (S.incidents.length && !S.cur) {
    const act = S.incidents.find((i) => i.status === 'Active');
    if (act) return openIncident(act.id);
  }
  renderMain();
}

function renderShell() {
  mount($('root'), h('div', { class: 'app' },
    h('div', {},
      h('header', { class: 'topbar' },
        h('div', { class: 'brand' }, h('div', { class: 'logo' }, '▣'), 'IRONROOM'),
        h('div', { class: 'live', id: 'live' }),
        h('div', { class: 'clockbar', id: 'clock', title: 'All times are taken from the IRONROOM server clock' }),
        h('button', { class: 'btn sm', id: 'tzbtn', onclick: toggleTz, title: 'Switch how every timestamp is displayed' }),
        h('div', { class: 'small muted', id: 'idle' }),
        h('div', { class: 'right row' },
          h('button', { class: 'btn ghost', onclick: showHelp, title: 'Quick guide' }, '? Help'),
          can('users') ? h('button', { class: 'btn', onclick: showTeam }, '👥 Team & Access') : h('button', { class: 'btn ghost', onclick: showTeam }, '👥 Team'),
          can('audit') ? h('button', { class: 'btn', onclick: showAudit }, '🧾 Audit log') : null,
          can('lockdown') ? h('button', { class: 'btn danger', onclick: showLockdown, title: 'Sign everyone out immediately' }, '⛔ Lockdown') : null,
          h('div', { class: 'who' }, h('div', {}, S.user.display), h('div', { class: 'muted tiny' }, S.user.role_label)),
          h('button', { class: 'btn ghost', onclick: logout }, 'Sign out'))),
      h('div', { id: 'urgent-banner' })),
    h('div', { class: 'body', id: 'body' },
      h('aside', { class: 'side', id: 'side' }),
      h('main', { class: 'main', id: 'main' }),
      h('section', { class: 'comms', id: 'comms' }))));
  renderLive(); renderSide(); renderComms(); tick();
}

function toggleTz() {
  S.tz = S.tz === 'utc' ? 'local' : 'utc';
  try { localStorage.setItem('ironroom_tz', S.tz); } catch (_) { /* ignore */ }
  renderShell(); renderMain(); toast(`Showing all times in ${S.tz === 'utc' ? 'UTC' : 'local time (' + tzName() + ')'}`);
}
function tick() {
  const c = $('clock');
  if (c) {
    const n = new Date(nowMs());
    mount(c, h('span', { class: 'big-time' }, n.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }), ' ', tzName() === 'UTC' ? '' : new Date().toLocaleTimeString(undefined, { timeZoneName: 'short' }).split(' ').pop()),
      h('span', { class: 'muted' }, ' · ' + n.toISOString().slice(11, 19) + ' UTC'),
      Math.abs(S.skew) > 120000 ? h('span', { class: 'skew' }, ` ⚠ this device's clock is off by ${elapsed(Math.abs(S.skew))}. IRONROOM uses server time`) : null);
  }
  const b = $('tzbtn');
  if (b && !b.dataset.v) { b.dataset.v = 1; b.textContent = `🕒 Times: ${S.tz === 'utc' ? 'UTC' : 'Local'} ⇄`; }
  document.querySelectorAll('.live-rel').forEach((e) => { e.textContent = rel(+e.dataset.t / 1000); });
  document.querySelectorAll('.live-dur').forEach((e) => { e.textContent = dur(+e.dataset.due - nowMs()); });
  document.querySelectorAll('.live-el').forEach((e) => { e.textContent = elapsed(nowMs() - +e.dataset.from); });
}
setInterval(tick, 1000);
setInterval(() => { if (S.user) fetch('/api/time', { cache: 'no-store' }).then((r) => r.json()).then((r) => { S.skew = r.server_time * 1000 - Date.now(); }).catch(() => {}); }, 300000);

function renderLive() {
  mount($('live'), h('span', { class: 'dot ' + (S.live ? 'on' : 'off') }), S.live ? 'Live — updates appear instantly' : 'Reconnecting…');
}

setInterval(() => {
  if (!S.user || !$('idle')) return;
  const left = S.meta.idle_timeout * 1000 - (Date.now() - S.lastApi);
  if (left < 120000 && left > 0) {
    mount($('idle'), h('button', { class: 'btn sm danger', onclick: () => api('GET', '/api/session').then(() => toast('Still signed in')) }, `Auto sign-out in ${Math.ceil(left / 1000)}s — click to stay`));
  } else mount($('idle'));
}, 1000);

// ---------- data loading ----------
async function loadIncidents() { S.incidents = await api('GET', '/api/incidents'); renderSide(); if (!S.cur) renderMain(); }
async function loadUsers() { S.users = await api('GET', '/api/users'); }
async function loadChannel() { S.channel = await api('GET', '/api/channel'); if (S.chan === 'team' || !S.cur) renderMsgs(); }
async function openIncident(id) {
  S.cur = id;
  S.data = await api('GET', `/api/incidents/${id}`);
  S.chan = 'incident';
  renderSide(); renderMain(); renderComms();
}
async function refreshIncident() {
  if (!S.cur) return;
  S.data = await api('GET', `/api/incidents/${S.cur}`);
  renderIncidentParts();
}
let incTimer = null;
const debouncedIncidents = () => { clearTimeout(incTimer); incTimer = setTimeout(loadIncidents, 250); };

// ---------- websocket ----------
let backoff = 1000;
function connectWS() {
  const ws = new WebSocket(`wss://${location.host}/ws`);
  S.ws = ws;
  ws.onopen = () => {
    S.live = true; backoff = 1000; renderLive();
    if (S.wsEverOpen) { loadIncidents(); loadChannel(); refreshIncident(); }
    S.wsEverOpen = true;
  };
  ws.onmessage = (m) => { try { onEvent(JSON.parse(m.data)); } catch (_) { /* ignore */ } };
  ws.onclose = (e) => {
    S.live = false; renderLive();
    if (!S.user) return;
    if (e.code === 4001) { api('GET', '/api/session').catch(() => {}); return; }
    setTimeout(() => S.user && connectWS(), backoff = Math.min(backoff * 2, 15000));
  };
}
setInterval(() => { if (S.ws && S.ws.readyState === 1) S.ws.send('ping'); }, 25000);

function upsert(list, e) {
  const i = list.findIndex((x) => x.id === e.id);
  if (i >= 0) list[i] = e; else list.push(e);
}

function onEvent(ev) {
  switch (ev.type) {
    case 'entry': case 'entry_update': {
      const e = ev.entry;
      if (e.kind === 'message') {
        if (e.urgent && e.author_id !== S.user.id && ev.type === 'entry') urgentAlert(e);
        if (e.incident_id === 0) {
          upsert(S.channel, e);
          if (S.chan === 'team') renderMsgs(); else if (ev.type === 'entry') { S.unread.team++; renderChan(); }
          return;
        }
        if (S.data && S.data.incident.id === e.incident_id && S.chan !== 'incident' && ev.type === 'entry') { S.unread.incident++; renderChan(); }
      }
      if (S.data && S.data.incident.id === e.incident_id) {
        upsert(S.data.entries[e.kind], e);
        if (e.kind === 'message') { if (S.chan === 'incident') renderMsgs(); }
        else renderIncidentParts();
      }
      break;
    }
    case 'incidents': debouncedIncidents(); break;
    case 'incident': if (S.cur === ev.incident_id) refreshIncident(); break;
    case 'presence': S.online = ev.online; renderOnline(); break;
    case 'users': loadUsers(); break;
    case 'signed_out': signedOut('An administrator ended all sessions (Lockdown). Sign in again if you are authorized.'); break;
    default: break;
  }
}

function urgentAlert(e) {
  const inc = S.incidents.find((i) => i.id === e.incident_id);
  const where = inc ? `${inc.ref} · ` : 'Team · ';
  toast(`🚨 URGENT from ${e.author}: ${e.text}`, 'urgent');
  S.urgent = { ...e, where };
  renderUrgent();
  let k = 0; const orig = document.title;
  const t = setInterval(() => { document.title = (k++ % 2) ? orig : '🚨 URGENT — IRONROOM'; if (k > 12) { clearInterval(t); document.title = orig; } }, 700);
}
function renderUrgent() {
  const b = $('urgent-banner');
  if (!b) return;
  if (!S.urgent) return mount(b);
  const u = S.urgent;
  mount(b, h('div', { class: 'banner-urgent' }, '🚨', h('span', {}, `${u.where}${u.author}: `), h('span', { class: 'grow' }, u.text),
    u.incident_id ? h('button', { class: 'btn sm', onclick: () => { openIncident(u.incident_id); S.urgent = null; renderUrgent(); } }, 'Open') : null,
    h('button', { class: 'btn sm', onclick: () => { S.urgent = null; renderUrgent(); } }, 'Dismiss')));
}

// ---------- sidebar ----------
function renderSide() {
  const el = $('side');
  if (!el) return;
  mount(el,
    can('incident.create') ? h('button', { class: 'btn primary big', onclick: showDeclare }, '＋ Declare new incident') : null,
    h('button', { class: 'inc-card' + (S.cur ? '' : ' sel'), onclick: () => { S.cur = null; S.data = null; S.chan = 'team'; renderSide(); renderMain(); renderComms(); } },
      h('div', { class: 't' }, '🏠 Overview of all incidents')),
    h('h3', {}, 'Incidents'),
    S.incidents.length ? S.incidents.map((i) => h('button', { class: 'inc-card' + (S.cur === i.id ? ' sel' : ''), onclick: () => openIncident(i.id) },
      h('div', { class: 'row wrap' }, h('span', { class: 'pill sev-' + i.severity }, i.severity), h('span', { class: 'pill st-' + i.status }, i.status), h('span', { class: 'tiny muted mono right' }, i.ref)),
      h('div', { class: 't' }, i.title),
      h('div', { class: 'm' }, `Phase: ${i.phase} · ${i.tasks_done}/${i.tasks_total} tasks`),
      h('div', { class: 'm' }, i.status === 'Closed' ? 'Closed' : ['⏱ T+ ', liveElapsed(toDate(i.discovered_at || i.created).getTime())], ' · updated ', liveRel(i.updated || i.created)),
      (i.exfil || i.encrypted) ? h('div', { class: 'row', style: null }, i.exfil ? h('span', { class: 'pill ds ds-Exfiltrated' }, 'Data exfiltrated') : null, i.encrypted ? h('span', { class: 'pill ds ds-Encrypted' }, 'Encrypted') : null) : null))
      : h('div', { class: 'empty small' }, 'No incidents yet.'));
}

// ---------- main area ----------
function renderMain() {
  const el = $('main');
  if (!el) return;
  if (!S.cur || !S.data) return renderHome(el);
  mount(el,
    h('div', { id: 'ihead' }), h('div', { id: 'phases', class: 'phases' }), h('div', { id: 'next' }),
    h('div', { id: 'tabs', class: 'tabs', role: 'tablist' }), h('div', { id: 'tabc' }));
  renderIncidentParts(true);
}

function renderHome(el) {
  const active = S.incidents.filter((i) => i.status !== 'Closed');
  const tiles = [
    ['Active incidents', active.length], ['Critical (SEV1)', active.filter((i) => i.severity === 'SEV1').length],
    ['Data sets affected', active.reduce((a, i) => a + i.scope_count, 0)], ['Open tasks', active.reduce((a, i) => a + i.tasks_total - i.tasks_done, 0)]];
  mount(el,
    h('h2', {}, 'Command overview'),
    h('div', { class: 'hero' }, tiles.map(([l, v]) => h('div', { class: 'tile' }, h('div', { class: 'v' }, v), h('div', { class: 'l' }, l)))),
    active.length ? h('div', { class: 'card' }, h('h3', {}, 'Active incidents'),
      h('table', {}, h('thead', {}, h('tr', {}, ['Ref', 'Incident', 'Severity', 'Phase', 'Discovered', 'Open for', 'Last update', 'Records at risk', 'Progress', ''].map((x) => h('th', {}, x)))),
        h('tbody', {}, active.map((i) => h('tr', {},
          h('td', { class: 'mono small' }, i.ref), h('td', {}, i.title), h('td', {}, h('span', { class: 'pill sev-' + i.severity }, i.severity)),
          h('td', {}, i.phase), h('td', { class: 'small' }, ts(i.discovered_at, { short: true })),
          h('td', { class: 'mono small' }, liveElapsed(toDate(i.discovered_at || i.created).getTime())),
          h('td', { class: 'small' }, liveRel(i.updated || i.created)), h('td', {}, n(i.records)),
          h('td', {}, (() => { const p = h('div', { class: 'progress' }, h('div')); p.firstChild.style.width = (i.tasks_total ? 100 * i.tasks_done / i.tasks_total : 0) + '%'; return p; })()),
          h('td', {}, h('button', { class: 'btn sm', onclick: () => openIncident(i.id) }, 'Open →'))))))) : null,
    h('div', { class: 'card', style: null }, h('h3', {}, 'If this is your first time here'),
      h('ol', {},
        h('li', {}, 'Something happened? Click ', h('b', {}, '＋ Declare new incident'), ' on the left. It takes 20 seconds.'),
        h('li', {}, 'Talk to the team in the ', h('b', {}, 'chat on the right'), ' — never on corporate email/Teams, which the attacker may be reading.'),
        h('li', {}, 'Inside an incident, follow the yellow ', h('b', {}, '“Do this next”'), ' box. It always tells you the next step.'),
        h('li', {}, 'On phone calls, ask the caller for the ', h('b', {}, 'verification phrase'), ' shown on the incident page to confirm they’re really on the team.'))));
  el.querySelectorAll('.card').forEach((c, i) => { if (i) c.classList.add('mt'); });
}

function counts() {
  const e = S.data.entries;
  return { scope: e.scope.length, timeline: e.timeline.length, tasks: e.task.filter((t) => !t.done).length, ioc: e.ioc.length };
}

function renderIncidentParts(full) {
  if (!S.data) return;
  const inc = S.data.incident;
  safeRender($('ihead'), (el) => mount(el, h('div', { class: 'ihead' },
    h('div', { class: 'grow' },
      h('div', { class: 'ref' }, `${inc.ref} · ${inc.category} · Commander: ${inc.commander || '—'} · Declared `, ts(inc.created)),
      h('h2', {}, inc.title),
      h('div', { class: 'row wrap' },
        h('label', { class: 'row small muted' }, 'Severity', sel(S.meta.severities, inc.severity, (v) => patchInc({ severity: v }), !can('incident.edit'), 'pill sev-' + inc.severity)),
        h('label', { class: 'row small muted' }, 'Status', sel(S.meta.statuses, inc.status, (v) => patchInc({ status: v }), !can('incident.edit'))),
        h('button', { class: 'btn sm ghost', onclick: showHistory, title: 'Every change to phase, severity and status, with time and person' }, '🕘 Change history')),
      h('div', { class: 'iclock' },
        h('span', { class: 'tplus' }, inc.status === 'Closed' ? 'Closed' : ['⏱ T+ ', liveElapsed(toDate(inc.discovered_at || inc.created).getTime())]),
        h('span', {}, 'since discovery (', ts(inc.discovered_at, { short: true }), ')'),
        h('span', {}, `In ${inc.phase} for `, liveElapsed(toDate(phaseAt(inc.phase, true) || inc.created).getTime())),
        h('span', {}, 'Last updated ', liveRel(inc.updated || inc.created), inc.updated_by ? ` by ${inc.updated_by}` : ''))),
    h('div', { class: 'phrase', title: 'Use on phone/video calls to confirm the other person is really on the response team.' },
      h('div', { class: 'tiny muted' }, '📞 PHONE VERIFICATION PHRASE'), h('b', {}, S.data.phrase.phrase),
      h('div', { class: 'tiny muted' }, `Changes hourly (next at ${new Date(S.data.phrase.expires * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })})`)))));
  const pi = S.meta.phases.indexOf(inc.phase);
  mount($('phases'), S.meta.phases.map((p, i) => h('button', {
    class: 'phase' + (i < pi ? ' done' : i === pi ? ' cur' : ''), disabled: !can('incident.edit'),
    title: can('incident.edit') ? `Move incident to ${p}` : p,
    onclick: () => { if (i !== pi) confirmBox(`Move incident to the “${p}” phase?`, () => patchInc({ phase: p })); },
  }, h('span', { class: 'n' }, `Step ${i + 1}`), (i < pi ? '✓ ' : '') + p,
    phaseAt(p) && i <= pi ? h('span', { class: 'pt' }, fmt(phaseAt(p), { short: true })) : null)));
  safeRender($('next'), renderNext);
  const c = counts();
  const tabs = [['overview', 'Overview'], ['scope', 'Affected data', c.scope], ['timeline', 'Timeline', c.timeline], ['tasks', 'Tasks', c.tasks], ['ioc', 'Indicators (IOCs)', c.ioc], ['evidence', 'Evidence', S.data.entries.evidence.length], ['report', 'Report']];
  mount($('tabs'), tabs.map(([k, l, cnt]) => h('button', { class: 'tab' + (S.tab === k ? ' on' : ''), role: 'tab', onclick: () => { S.tab = k; renderIncidentParts(true); } }, l, cnt != null ? h('span', { class: 'cnt' }, cnt) : null)));
  const tabc = $('tabc');
  const r = { overview: tabOverview, scope: tabScope, timeline: tabTimeline, tasks: tabTasks, ioc: tabIoc, evidence: tabEvidence, report: tabReport }[S.tab];
  if (full) mount(tabc); // new tab: build fresh
  r(tabc, full);
}

// time the incident (first / most recently) entered a phase, from the change history
function phaseAt(p, last) {
  const hs = ((S.data && S.data.incident.history) || []).filter((x) => x.field === 'phase' && x.to === p);
  if (!hs.length) return p === 'Detection' && S.data ? new Date(S.data.incident.created * 1000).toISOString() : null;
  return (last ? hs[hs.length - 1] : hs[0]).at;
}
function statusAt(st) {
  const hs = ((S.data && S.data.incident.history) || []).filter((x) => x.field === 'status' && x.to === st);
  return hs.length ? hs[hs.length - 1].at : null;
}
// Standard IR response-time metrics
function metrics() {
  const inc = S.data.incident;
  const t = (x) => (x ? toDate(x).getTime() : null);
  const occ = t(inc.occurred_at), disc = t(inc.discovered_at), decl = inc.created * 1000;
  const end = inc.status === 'Closed' ? t(statusAt('Closed')) : null;
  const span = (a, b, running) => (a && b ? elapsed(b - a) : a && running ? [liveElapsed(a), h('span', { class: 'inprog' }, ' ⏳ ongoing')] : '—');
  return [
    ['Dwell time', span(occ, disc), 'Attacker activity began → discovered'],
    ['Time to declare', span(disc, decl), 'Discovered → incident declared'],
    ['Time to contain', span(disc, t(phaseAt('Eradication')), true), 'Discovered → containment complete'],
    ['Time to recover', span(disc, t(phaseAt('Post-Incident')), true), 'Discovered → recovery complete'],
    ['Total duration', span(disc || decl, end, true), 'Discovered → closed'],
  ];
}
function metricsCard() {
  return h('div', { class: 'card' }, h('h3', {}, '📈 Response time metrics'),
    h('div', { class: 'metrics' }, metrics().map(([l, v, d]) => h('div', { class: 'metric' }, h('div', { class: 'mv mono' }, v), h('div', { class: 'ml' }, l), h('div', { class: 'tiny muted' }, d)))));
}
function showHistory() {
  const hs = [...(S.data.incident.history || [])].reverse();
  const L = { phase: 'Phase', status: 'Status', severity: 'Severity' };
  modal('Change history', h('div', { class: 'col' },
    h('div', { class: 'small muted' }, `Every change to phase, status and severity. Times in ${S.tz === 'utc' ? 'UTC' : 'local time'}; hover any time for UTC.`),
    hs.length ? h('table', {}, h('thead', {}, h('tr', {}, ['When', 'What', 'From', 'To', 'By'].map((x) => h('th', {}, x)))),
      h('tbody', {}, hs.map((x) => h('tr', {}, h('td', { class: 'small' }, ts(x.at, { rel: true })), h('td', {}, L[x.field] || x.field), h('td', { class: 'muted' }, x.from || '(new)'), h('td', {}, h('b', {}, x.to)), h('td', { class: 'small' }, x.by)))))
      : h('div', { class: 'empty' }, 'No changes yet.')), { wide: true });
}

function sel(options, value, onchange, disabled, cls) {
  const s = h('select', { disabled, class: cls || null, onchange: (e) => onchange(e.target.value) }, options.map((o) => h('option', { value: o }, o)));
  s.value = value || '';
  return s;
}

async function patchInc(p) {
  try { S.data.incident = await api('PATCH', `/api/incidents/${S.cur}`, p); renderIncidentParts(); return true; }
  catch (e) { toast(e.message, 'bad'); refreshIncident(); return false; }
}

function confirmBox(text, yes) {
  const close = modal('Please confirm', h('div', { class: 'col' }, h('div', {}, text),
    h('div', { class: 'row' }, h('button', { class: 'btn primary', onclick: () => { close(); yes(); } }, 'Yes, do it'), h('button', { class: 'btn', onclick: () => close() }, 'Cancel'))));
}

// ---------- "Do this next" ----------
function renderNext(el) {
  const inc = S.data.incident, E = S.data.entries;
  const phaseTasks = E.task.filter((t) => t.phase === inc.phase);
  const open = phaseTasks.filter((t) => !t.done);
  const warns = [];
  if (!E.scope.length && S.meta.phases.indexOf(inc.phase) >= 1) warns.push(['No affected data recorded yet — add it on the Affected data tab.', 'scope']);
  if (E.scope.some((s) => s.status === 'Unknown')) warns.push([`${E.scope.filter((s) => s.status === 'Unknown').length} data set(s) still have Unknown status.`, 'scope']);
  if (!inc.counsel_engaged) warns.push(['Outside counsel not engaged yet (protects privilege of the investigation).', 'overview']);
  if (inc.category === 'Ransomware' && !inc.backups_verified) warns.push(['Backups not yet verified as clean and isolated.', 'overview']);
  for (const c of clocks()) {
    if (c.done) continue;
    const left = c.due - nowMs();
    if (left < 0) warns.push([`OVERDUE: ${c.name} (${dur(left)})`, 'overview']);
    else if (left < 48 * 36e5) warns.push([`Deadline soon: ${c.name} — ${dur(left)}`, 'overview']);
  }
  const nextPhase = S.meta.phases[S.meta.phases.indexOf(inc.phase) + 1];
  mount(el, h('div', { class: 'card next' },
    h('div', { class: 'row' }, h('h3', {}, `👉 Do this next — ${inc.phase} phase`), h('span', { class: 'small muted right' }, `${phaseTasks.length - open.length} of ${phaseTasks.length} done`)),
    open.length ? open.slice(0, 3).map((t) => taskRow(t, true)) :
      h('div', { class: 'row', style: null }, h('div', { class: 'grow' }, '✅ All tasks for this phase are done.'),
        nextPhase && can('incident.edit') ? h('button', { class: 'btn primary', onclick: () => patchInc({ phase: nextPhase }) }, `Move to ${nextPhase} →`) : null),
    open.length > 3 ? h('button', { class: 'btn ghost sm', onclick: () => { S.tab = 'tasks'; renderIncidentParts(true); } }, `+ ${open.length - 3} more tasks in this phase`) : null,
    warns.map(([w, tab]) => h('div', { class: 'warnline' }, '⚠️', h('span', { class: 'grow' }, w), h('button', { class: 'btn sm ghost', onclick: () => { S.tab = tab; renderIncidentParts(true); } }, 'Go →')))));
}

function taskRow(t, compact) {
  const cb = h('input', { type: 'checkbox', checked: t.done, disabled: !can('entry.write'), 'aria-label': t.title, onchange: (e) => patchEntry(t.id, { done: e.target.checked }) });
  return h('div', { class: 'task' + (t.done ? ' done' : '') }, cb,
    h('div', { class: 'grow' }, h('div', { class: 'tt' }, t.title),
      t.done && t.done_by ? h('div', { class: 'tiny muted' }, `✓ Done by ${t.done_by} · `, ts(t.done_at, { rel: true })) : null),
    compact ? (t.assignee ? h('span', { class: 'pill ds ds-Unknown' }, t.assignee) : null)
      : sel(['', ...S.users.filter((u) => u.active).map((u) => u.display)], t.assignee, (v) => patchEntry(t.id, { assignee: v }), !can('entry.write')));
}

async function patchEntry(id, p) {
  try { const e = await api('PATCH', `/api/entries/${id}`, p); upsert(S.data.entries[e.kind], e); renderIncidentParts(); }
  catch (e) { toast(e.message, 'bad'); }
}
async function addEntry(kind, p, iid) {
  const e = await api('POST', `/api/incidents/${iid ?? S.cur}/entries`, { kind, ...p });
  if (S.data && e.incident_id === S.data.incident.id && kind !== 'message') { upsert(S.data.entries[kind], e); renderIncidentParts(); }
  return e;
}

// ---------- regulatory clocks ----------
function addBusinessDays(d, k) { const x = new Date(d); while (k > 0) { x.setDate(x.getDate() + 1); if (x.getDay() % 6) k--; } return x; }
function clocks() {
  if (!S.data) return [];
  const inc = S.data.incident, sc = S.data.entries.scope;
  const base = new Date(inc.discovered_at || inc.created * 1000);
  const done = new Set(inc.notices_done || []);
  const personal = ['PII', 'PHI (health)', 'PCI (card data)', 'Financial', 'Credentials', 'Employee / HR', 'Customer data'];
  const isPers = (s) => (s.data_types || []).some((t) => personal.includes(t));
  const inJ = (codes) => sc.filter((s) => (s.jurisdictions || []).some((j) => codes.includes(j.toUpperCase())));
  const recs = (a) => a.reduce((x, s) => x + (s.records || 0), 0);
  const has = (t) => sc.some((s) => (s.data_types || []).includes(t));
  const out = [];
  const add = (name, due, basis) => out.push({ name, due, basis, done: done.has(name) });
  add('Cyber insurance carrier', new Date(+base + 24 * 36e5), 'Most policies: notice “as soon as practicable”. Check your policy.');
  if (inJ(['EU', 'EEA', 'UK']).length) add('GDPR / UK GDPR — supervisory authority', new Date(+base + 72 * 36e5), 'Art. 33: within 72 hours of becoming aware');
  if (has('PHI (health)')) {
    add('HIPAA — affected individuals', new Date(+base + 60 * 864e5), '45 CFR 164.404: without unreasonable delay, ≤ 60 days');
    if (recs(sc.filter((s) => (s.data_types || []).includes('PHI (health)'))) >= 500) add('HIPAA — HHS & media (500+ people)', new Date(+base + 60 * 864e5), '45 CFR 164.406/408');
  }
  const tx = inJ(['TX']).filter(isPers);
  if (tx.length) {
    add('Texas — affected individuals', new Date(+base + 60 * 864e5), 'Tex. Bus. & Com. Code §521.053: ≤ 60 days');
    if (recs(tx) >= 250) add('Texas Attorney General (250+ Texans)', new Date(+base + 30 * 864e5), '§521.053(i): ≤ 30 days');
  }
  if (has('PCI (card data)')) add('Card brands / acquiring bank', new Date(+base + 24 * 36e5), 'PCI DSS & merchant agreement: notify immediately');
  if (inc.materiality_at) add('SEC Form 8-K, Item 1.05', addBusinessDays(new Date(inc.materiality_at), 4), '4 business days after materiality determination');
  return out;
}

function clocksCard(editable) {
  const list = clocks();
  const inc = S.data.incident;
  const toggle = (name, on) => {
    const s = new Set(inc.notices_done || []);
    if (on) s.add(name); else s.delete(name);
    patchInc({ notices_done: [...s] });
  };
  return h('div', { class: 'card' },
    h('div', { class: 'row' }, h('h3', {}, '⏱ Notification deadlines'), h('span', { class: 'tiny muted right' }, 'Default reminders based on the affected data — confirm with counsel. Not legal advice.')),
    list.map((c) => {
      const left = c.due - nowMs();
      const cls = c.done ? 'ok' : left < 0 ? 'overdue' : left < 48 * 36e5 ? 'soon' : '';
      return h('div', { class: 'clock ' + cls },
        h('label', { class: 'check' }, h('input', { type: 'checkbox', checked: c.done, disabled: !editable, onchange: (e) => toggle(c.name, e.target.checked) })),
        h('div', { class: 'grow' }, h('div', {}, c.name), h('div', { class: 'tiny muted' }, c.basis)),
        h('div', { class: 'due' }, c.done ? 'Sent ✓' : liveDur(c.due.getTime()), h('div', { class: 'tiny muted' }, 'due ', ts(c.due.toISOString(), { short: true }))));
    }),
    h('div', { class: 'tiny muted', style: null }, 'Tip: record which states/countries people live in on the Affected data tab, and the materiality decision date below, to activate more clocks.'));
}

// ---------- Overview tab ----------
function tabOverview(el) {
  safeRender(el, () => {
    const inc = S.data.incident, ed = can('incident.edit');
    const savedMark = h('span', { class: 'saved' }, 'Saved ✓');
    const flash = () => { savedMark.classList.add('show'); setTimeout(() => savedMark.classList.remove('show'), 1500); };
    const field = (k, label, kind = 'text', hint) => {
      let inp;
      if (kind === 'area') inp = h('textarea', { value: inc[k] || '', disabled: !ed });
      else if (kind === 'dt') inp = h('input', { type: 'datetime-local', value: toLocalInput(inc[k]), disabled: !ed });
      else inp = h('input', { type: 'text', value: inc[k] || '', disabled: !ed });
      inp.addEventListener('change', async () => { if (await patchInc({ [k]: kind === 'dt' ? fromLocalInput(inp.value) : inp.value })) flash(); });
      return h('label', { class: 'f' }, label, hint ? h('span', { class: 'hint tiny' }, hint) : null, inp);
    };
    const flag = (k, label) => h('label', { class: 'check' }, h('input', { type: 'checkbox', checked: !!inc[k], disabled: !ed, onchange: (e) => patchInc({ [k]: e.target.checked }).then((ok) => ok && flash()) }), label);
    mount(el,
      h('div', { class: 'row' }, h('span', { class: 'small muted' }, ed ? 'Changes save automatically when you leave a field.' : 'Read-only for your role.'), savedMark),
      h('div', { class: 'grid2', style: null },
        h('div', { class: 'card col' }, h('h3', {}, 'What happened'),
          field('title', 'Short title'),
          field('summary', 'Summary', 'area', 'Plain language: what do we know right now?'),
          field('business_impact', 'Business impact', 'area', 'What can’t people do? Which clients/offices are affected?'),
          field('affected_systems', 'Affected systems', 'area'),
          field('attack_vector', 'How did they get in? (attack vector)'),
          field('threat_actor', 'Who is behind it? (threat actor, if known)'),
          inc.category === 'Ransomware' ? field('ransom_demand', 'Ransom demand (amount / deadline)') : null),
        h('div', { class: 'col' },
          metricsCard(),
          h('div', { class: 'card col' }, h('h3', {}, 'When & who'),
            h('div', { class: 'grid2' },
              field('occurred_at', 'Started (best estimate)', 'dt'),
              field('discovered_at', 'Discovered', 'dt', 'Starts the notification clocks')),
            field('detection_source', 'How was it detected?'),
            field('reported_by', 'Reported by'),
            field('materiality_at', 'Materiality determined (public companies)', 'dt', 'Starts the SEC 4-business-day clock'),
            field('external_refs', 'External case numbers', 'text', 'FBI IC3 #, insurer claim #, forensics engagement #')),
          h('div', { class: 'card col' }, h('h3', {}, 'Key decisions & notifications'),
            flag('counsel_engaged', 'Outside counsel engaged'), flag('forensics_engaged', 'Forensics firm engaged (through counsel)'),
            flag('insurer_notified', 'Cyber insurer notified'), flag('le_notified', 'Law enforcement notified (FBI / Secret Service)'),
            flag('regulators_notified', 'Regulators notified'), flag('backups_verified', 'Backups verified clean & isolated')),
          clocksCard(ed))));
  });
}

// ---------- Affected data (scope) tab ----------
function tabScope(el, full) {
  if (full) mount(el, h('div', { id: 'scope-body' }));
  safeRender($('scope-body'), (b) => {
    const sc = S.data.entries.scope;
    const groups = ['Exfiltrated', 'Encrypted', 'Accessed', 'Unknown', 'Contained', 'Restored'];
    const g = (k) => sc.filter((s) => (s.status || '').startsWith(k) || (k === 'Accessed' && /Deleted|Modified/.test(s.status)));
    mount(b,
      h('div', { class: 'row' }, h('div', { class: 'grow' }, h('h2', {}, 'Affected data'), h('div', { class: 'small muted' }, 'Every set of data that may have been touched, and what happened to it. Update the status as you learn more.')),
        can('entry.write') ? h('button', { class: 'btn primary', onclick: () => scopeForm() }, '＋ Add affected data') : null),
      h('div', { class: 'tiles', style: null }, groups.map((k) => {
        const a = g(k);
        return h('div', { class: 'tile ' + k }, h('div', { class: 'v' }, a.length), h('div', { class: 'l' }, `${k === 'Encrypted' ? 'Encrypted / locked' : k === 'Accessed' ? 'Accessed / altered' : k} · ${n(a.reduce((x, s) => x + (s.records || 0), 0))} records`));
      })),
      h('br'),
      sc.length ? h('div', { class: 'card' }, h('table', {},
        h('thead', {}, h('tr', {}, ['Data set', 'Kinds of data', 'Records', 'What happened', 'Confidence', 'People in', ''].map((x) => h('th', {}, x)))),
        h('tbody', {}, sc.map((s) => h('tr', {},
          h('td', {}, h('b', {}, s.name), h('div', { class: 'tiny muted' }, s.system || ''), s.notes ? h('div', { class: 'tiny' }, s.notes) : null),
          h('td', {}, h('div', { class: 'chips' }, (s.data_types || []).map((t) => h('span', { class: 'pill ds ds-Unknown' }, t)))),
          h('td', {}, n(s.records)),
          h('td', {}, can('entry.write') ? sel(S.meta.scope_statuses, s.status, (v) => patchEntry(s.id, { status: v }), false, dsClass(s.status)) : h('span', { class: dsClass(s.status) }, s.status),
            (s.status_history || []).length ? h('div', { class: 'tiny muted' }, 'since ', ts(s.status_history[s.status_history.length - 1].at, { short: true }),
              ' · ', h('button', { class: 'linkbtn', onclick: () => scopeHistory(s) }, `history (${s.status_history.length})`)) : null),
          h('td', {}, can('entry.write') ? sel(S.meta.confidence, s.confidence, (v) => patchEntry(s.id, { confidence: v })) : s.confidence),
          h('td', { class: 'small' }, (s.jurisdictions || []).join(', ') || '—'),
          h('td', {}, can('entry.write') ? h('button', { class: 'btn sm', onclick: () => scopeForm(s) }, 'Edit') : null))))))
        : h('div', { class: 'empty' }, 'Nothing recorded yet. Click “Add affected data” for each file share, database, mailbox or system whose data may be involved.'));
  });
}

function scopeHistory(s) {
  const hs = [...(s.status_history || [])].reverse();
  modal(`Status history: ${s.name}`, h('div', { class: 'col' },
    h('div', { class: 'small muted' }, 'Each time our understanding of this data changed, with when and who. Useful for regulators and insurers.'),
    h('table', {}, h('thead', {}, h('tr', {}, ['When', 'Status', 'Confidence', 'By'].map((x) => h('th', {}, x)))),
      h('tbody', {}, hs.map((x) => h('tr', {}, h('td', { class: 'small' }, ts(x.at, { rel: true })), h('td', {}, h('span', { class: dsClass(x.status) }, x.status)), h('td', {}, x.confidence), h('td', { class: 'small' }, x.by)))))));
}

function chipPicker(options, selected) {
  const set = new Set(selected || []);
  const wrap = h('div', { class: 'chips' });
  const draw = () => mount(wrap, options.map((o) => h('button', { type: 'button', class: 'chip' + (set.has(o) ? ' on' : ''), onclick: () => { set.has(o) ? set.delete(o) : set.add(o); draw(); } }, (set.has(o) ? '✓ ' : '') + o)));
  draw();
  return { el: wrap, get: () => [...set] };
}
function segPicker(options, value, describe) {
  let v = value;
  const wrap = h('div', { class: 'seg' });
  const draw = () => mount(wrap, options.map((o) => h('button', { type: 'button', class: v === o ? 'on' : '', onclick: () => { v = o; draw(); } }, h('b', {}, o), describe ? h('span', {}, describe[o] || '') : null)));
  draw();
  return { el: wrap, get: () => v };
}

function scopeForm(s) {
  s = s || {};
  const name = h('input', { type: 'text', value: s.name || '', placeholder: 'e.g. HR database, Client files share, CFO mailbox' });
  const system = h('input', { type: 'text', value: s.system || '', placeholder: 'Server / location, e.g. FS01 \\\\clients' });
  const types = chipPicker(S.meta.data_types, s.data_types);
  const recs = h('input', { type: 'number', min: '0', value: s.records ?? '', placeholder: 'Approximate is fine' });
  const desc = { Unknown: 'Not sure yet', Accessed: 'Viewed by attacker', Exfiltrated: 'Copied out / stolen', 'Encrypted (ransomware)': 'Locked by ransomware', Deleted: 'Destroyed', Modified: 'Altered / tampered', Contained: 'Attacker access cut off', Restored: 'Back to normal' };
  const status = segPicker(S.meta.scope_statuses, s.status || 'Unknown', desc);
  const conf = segPicker(S.meta.confidence, s.confidence || 'Suspected', { Suspected: 'Possible, unverified', Likely: 'Evidence points to it', Confirmed: 'Proven by evidence' });
  const jur = chipPicker(['TX', 'CA', 'NY', 'FL', 'IL', 'OK', 'Other US', 'EU', 'UK', 'Canada'], s.jurisdictions);
  const notes = h('textarea', { value: s.notes || '', placeholder: 'Evidence, who confirmed it, next check…' });
  const btn = h('button', { class: 'btn primary big' }, s.id ? 'Save changes' : 'Add to affected data');
  const close = modal(s.id ? 'Edit affected data' : 'Add affected data', h('div', { class: 'col' },
    h('div', { class: 'grid2' }, h('label', { class: 'f' }, 'What data? *', name), h('label', { class: 'f' }, 'Where is it stored?', system)),
    h('label', { class: 'f' }, 'What kinds of information are in it? (tap all that apply)', types.el),
    h('label', { class: 'f' }, 'What happened to it?', status.el),
    h('div', { class: 'grid2' }, h('label', { class: 'f' }, 'How sure are we?', conf.el), h('label', { class: 'f' }, 'How many records / people?', recs)),
    h('label', { class: 'f' }, 'Where do the affected people live? (drives notification deadlines)', jur.el),
    h('label', { class: 'f' }, 'Notes', notes), btn), { wide: true });
  btn.onclick = () => run(btn, async () => {
    const p = { name: name.value, system: system.value, data_types: types.get(), records: recs.value === '' ? null : Number(recs.value), status: status.get(), confidence: conf.get(), jurisdictions: jur.get(), notes: notes.value };
    if (s.id) await patchEntry(s.id, p); else await addEntry('scope', p);
    close(); toast('Affected data saved');
  });
}

// ---------- Timeline tab ----------
function tabTimeline(el, full) {
  if (full) {
    const at = h('input', { type: 'datetime-local', step: '1', value: toLocalInput(new Date(nowMs()).toISOString()) });
    const nowBtn = h('button', { class: 'btn sm', type: 'button', onclick: () => { at.value = toLocalInput(new Date(nowMs()).toISOString()); } }, 'Now');
    const txt = h('textarea', { placeholder: 'What happened? e.g. “Disconnected FS01 from the network”' });
    const src = h('input', { type: 'text', placeholder: 'Source (e.g. firewall logs, J. Okafor)' });
    const priv = h('input', { type: 'checkbox' });
    const btn = h('button', { class: 'btn primary' }, 'Add to timeline');
    btn.onclick = () => run(btn, async () => {
      if (!txt.value.trim()) return toast('Describe what happened first', 'bad');
      await addEntry('timeline', { at: fromLocalInput(at.value), text: txt.value, source: src.value, privileged: priv.checked });
      txt.value = ''; src.value = ''; priv.checked = false; at.value = toLocalInput(new Date(nowMs()).toISOString());
    });
    const q = h('input', { type: 'text', placeholder: '🔎 Search timeline…', value: S.tlFilter.q, oninput: (e) => { S.tlFilter.q = e.target.value; drawTl(); } });
    const hide = h('input', { type: 'checkbox', checked: S.tlFilter.hideSys, onchange: (e) => { S.tlFilter.hideSys = e.target.checked; drawTl(); } });
    mount(el,
      can('entry.write') ? h('div', { class: 'card col' }, h('h3', {}, 'Log an event'),
        h('div', { class: 'grid3' }, h('label', { class: 'f' }, 'When did it happen? (your local time)', h('div', { class: 'row' }, at, nowBtn)), h('label', { class: 'f span2' }, 'Source', src)),
        h('label', { class: 'f' }, 'What happened', txt),
        h('div', { class: 'row' },
          can('read.priv') ? h('label', { class: 'check small' }, priv, '🔒 Privileged & confidential — at the direction of counsel (hidden from responders/viewers)') : null,
          h('span', { class: 'right' }, btn))) : null,
      h('div', { class: 'row tlbar' }, h('div', { class: 'grow' }, q), h('label', { class: 'check small' }, hide, 'Hide automatic entries'),
        h('span', { class: 'small muted' }, `Times in ${S.tz === 'utc' ? 'UTC' : tzName()}`)),
      h('div', { id: 'tl-list' }));
  }
  drawTl();
}
function drawTl() {
  safeRender($('tl-list'), (b) => {
    const q = S.tlFilter.q.trim().toLowerCase();
    const all = [...S.data.entries.timeline].sort((x, y) => new Date(x.at) - new Date(y.at));
    const items = all.filter((t) => (!S.tlFilter.hideSys || !t.is_system) && (!q || `${t.text} ${t.source} ${t.author}`.toLowerCase().includes(q)));
    let day = '';
    mount(b, items.length ? h('div', { class: 'card' },
      items.length < all.length ? h('div', { class: 'small muted' }, `Showing ${items.length} of ${all.length} entries`) : null,
      h('div', { class: 'tl' }, items.map((t) => {
        const logged = t.logged_at || (t.created && new Date(t.created * 1000).toISOString());
        const lag = logged ? toDate(logged) - toDate(t.at) : 0;
        const dk = fmtDay(t.at);
        const sep = dk !== day ? h('div', { class: 'daysep' }, (day = dk)) : null;
        return [sep, h('div', { class: 'tl-item' + (t.is_system ? ' sys' : '') + (t.privileged ? ' priv' : '') },
          h('div', { class: 'when' }, h('b', { class: 'mono' }, ts(t.at, { timeOnly: true })), ' · ', t.source || t.author, t.privileged ? h('span', { class: 'pill priv-tag' }, ' 🔒 Privileged') : null),
          h('div', { class: 'txt' + (t.is_system ? ' muted small' : '') }, t.text),
          !t.is_system ? h('div', { class: 'logged' }, 'Logged ', ts(logged), ` by ${t.author}`,
            lag > 15 * 60000 ? h('span', { class: 'pill late', title: 'Recorded after the event happened - normal for reconstructed events' }, `recorded ${elapsed(lag)} after event`) : null,
            t.edited_by ? h('span', {}, ' · edited by ', t.edited_by, ' ', ts(t.edited_at, { short: true })) : null) : null)];
      }))) : h('div', { class: 'empty' }, all.length ? 'No entries match your search.' : 'No events yet.'));
  });
}

// ---------- Tasks tab ----------
function tabTasks(el, full) {
  if (full) {
    const title = h('input', { type: 'text', placeholder: 'New task, e.g. “Reset all domain admin passwords”' });
    const ph = sel(S.meta.phases, S.data.incident.phase, () => {});
    const btn = h('button', { class: 'btn primary' }, 'Add task');
    btn.onclick = () => run(btn, async () => { if (!title.value.trim()) return; await addEntry('task', { title: title.value, phase: ph.value }); title.value = ''; });
    title.addEventListener('keydown', (e) => { if (e.key === 'Enter') btn.click(); });
    mount(el, can('entry.write') ? h('div', { class: 'card row' }, h('div', { class: 'grow' }, title), ph, btn) : null, h('br'), h('div', { id: 'task-list' }));
  }
  safeRender($('task-list'), (b) => {
    const T = S.data.entries.task, cur = S.data.incident.phase;
    const order = [cur, ...S.meta.phases.filter((p) => p !== cur)];
    mount(b, order.map((p) => {
      const ts = T.filter((t) => t.phase === p);
      if (!ts.length) return null;
      const d = ts.filter((t) => t.done).length;
      const bar = h('div', { class: 'progress' }, h('div'));
      bar.firstChild.style.width = (100 * d / ts.length) + '%';
      return h('div', { class: 'card', style: null },
        h('div', { class: 'row' }, h('h3', {}, (p === cur ? '▶ ' : '') + p + (p === cur ? ' (current phase)' : '')), h('span', { class: 'right small muted' }, `${d}/${ts.length}`)),
        bar, ts.map((t) => taskRow(t, false)));
    }));
    b.querySelectorAll('.card').forEach((c) => { c.classList.add('mb'); });
  });
}

// ---------- IOC tab ----------
function tabIoc(el, full) {
  if (full) {
    const type = sel(S.meta.ioc_types, 'IP address', () => {});
    const val = h('input', { type: 'text', placeholder: 'Value, e.g. 185.220.101.4' });
    const note = h('input', { type: 'text', placeholder: 'Note (where seen)' });
    const btn = h('button', { class: 'btn primary' }, 'Add');
    btn.onclick = () => run(btn, async () => { if (!val.value.trim()) return; await addEntry('ioc', { type: type.value, value: val.value, note: note.value }); val.value = ''; note.value = ''; });
    mount(el,
      h('div', { class: 'row' }, h('div', { class: 'grow' }, h('h2', {}, 'Indicators of compromise'), h('div', { class: 'small muted' }, 'IP addresses, domains, file hashes and accounts linked to the attacker. Share with IT to block.')),
        h('button', { class: 'btn', onclick: () => { navigator.clipboard.writeText(S.data.entries.ioc.map((i) => i.value).join('\n')).then(() => toast('Copied all IOC values')); } }, '📋 Copy all values')),
      h('br'),
      can('entry.write') ? h('div', { class: 'card row' }, type, h('div', { class: 'grow' }, val), h('div', { class: 'grow' }, note), btn) : null,
      h('br'), h('div', { id: 'ioc-list' }));
  }
  safeRender($('ioc-list'), (b) => {
    const I = S.data.entries.ioc;
    mount(b, I.length ? h('div', { class: 'card' }, h('table', {}, h('thead', {}, h('tr', {}, ['Type', 'Value', 'Note', 'Added by'].map((x) => h('th', {}, x)))),
      h('tbody', {}, I.map((i) => h('tr', {}, h('td', {}, i.type), h('td', { class: 'mono small' }, i.value), h('td', { class: 'small' }, i.note), h('td', { class: 'small muted' }, `${i.author} · `, ts(i.created, { short: true })))))))
      : h('div', { class: 'empty' }, 'No indicators recorded yet.'));
  });
}

// ---------- Evidence tab ----------
const bytes = (b) => (b < 1024 ? b + ' B' : b < 1048576 ? (b / 1024).toFixed(1) + ' KB' : (b / 1048576).toFixed(1) + ' MB');
function tabEvidence(el, full) {
  if (full) {
    const file = h('input', { type: 'file', class: 'filein' });
    const desc = h('input', { type: 'text', placeholder: 'What is it and where did it come from? e.g. “Ransom note from FS01 root share”' });
    const coll = h('input', { type: 'datetime-local', step: '1' });
    const status = h('span', { class: 'small muted' });
    const btn = h('button', { class: 'btn primary' }, '🔒 Seal & upload');
    btn.onclick = () => run(btn, async () => {
      const f = file.files[0];
      if (!f) return toast('Choose a file first', 'bad');
      if (f.size > S.meta.max_upload) return toast(`Too large (max ${bytes(S.meta.max_upload)})`, 'bad');
      mount(status, 'Encrypting & uploading…');
      const r = await fetch(`/api/incidents/${S.cur}/evidence`, {
        method: 'POST', credentials: 'same-origin', body: f,
        headers: { 'Content-Type': 'application/octet-stream', 'X-CSRF-Token': S.csrf, 'X-Filename': encodeURIComponent(f.name),
          'X-Description': encodeURIComponent(desc.value), 'X-Collected-At': encodeURIComponent(fromLocalInput(coll.value)) },
      });
      const j = await r.json().catch(() => ({}));
      if (!r.ok) { mount(status); throw new Error(j.error || 'Upload failed'); }
      S.lastApi = Date.now();
      upsert(S.data.entries.evidence, j); renderIncidentParts();
      file.value = ''; desc.value = ''; coll.value = '';
      mount(status, h('span', { class: 'okc' }, `✓ Sealed. SHA-256 ${j.sha256.slice(0, 16)}…`));
    });
    mount(el,
      h('div', { class: 'row' }, h('div', { class: 'grow' }, h('h2', {}, 'Evidence locker'),
        h('div', { class: 'small muted' }, 'Files are encrypted on upload and fingerprinted (SHA-256). Every download is logged with time and person: a chain of custody you can hand to forensics, insurers or law enforcement.'))),
      h('br'),
      can('entry.write') ? h('div', { class: 'card col' }, h('h3', {}, 'Add evidence'),
        h('div', { class: 'grid3' }, h('label', { class: 'f' }, '1. File', file), h('label', { class: 'f span2' }, '2. Description', desc)),
        h('div', { class: 'row wrap' }, h('label', { class: 'f' }, '3. When was it collected? (optional)', coll), h('div', { class: 'grow' }), status, btn)) : null,
      h('br'), h('div', { id: 'ev-list' }));
  }
  safeRender($('ev-list'), (b) => {
    const E = [...S.data.entries.evidence].reverse();
    mount(b, E.length ? E.map((e) => h('div', { class: 'card ev mb' },
      h('div', { class: 'row' }, h('div', { class: 'grow' }, h('b', {}, '📄 ', e.name), h('span', { class: 'muted small' }, ` · ${bytes(e.size)}`), h('div', { class: 'small' }, e.description || '')),
        can('entry.write') ? h('a', { class: 'btn', href: `/api/evidence/${e.id}`, download: e.name }, '⬇ Download') : h('span', { class: 'tiny muted' }, 'Download requires responder role')),
      h('div', { class: 'kvs small' },
        h('span', { class: 'muted' }, 'SHA-256'), h('span', { class: 'mono hash' }, e.sha256, ' ', h('button', { class: 'linkbtn', onclick: () => navigator.clipboard.writeText(e.sha256).then(() => toast('Hash copied')) }, 'copy')),
        h('span', { class: 'muted' }, 'Collected'), e.collected_at ? ts(e.collected_at) : h('span', { class: 'muted' }, 'not recorded'),
        h('span', { class: 'muted' }, 'Logged'), h('span', {}, ts(e.logged_at), ` by ${e.author}`)),
      h('details', {}, h('summary', { class: 'small' }, `Chain of custody (${e.custody.length} events)`),
        h('table', {}, h('tbody', {}, e.custody.map((c) => h('tr', {}, h('td', { class: 'small mono' }, ts(c.at)), h('td', {}, c.action), h('td', { class: 'small' }, c.by), h('td', { class: 'mono tiny muted' }, c.ip))))))))
      : h('div', { class: 'empty' }, 'No evidence yet. Upload ransom notes, screenshots, log extracts, phishing emails (.eml), etc.'));
  });
}

// ---------- Report tab ----------
function tabReport(el) {
  safeRender(el, () => {
    const inc = S.data.incident, E = S.data.entries;
    const kv = (pairs) => h('div', { class: 'kv' }, pairs.flatMap(([k, v]) => [h('div', {}, k), h('div', {}, v || '—')]));
    const yn = (b) => (b ? 'Yes' : 'No');
    mount(el, h('div', { class: 'card report' },
      h('div', { class: 'row no-print' },
        h('button', { class: 'btn primary', onclick: () => window.print() }, '🖨 Print / Save as PDF'),
        h('a', { class: 'btn', href: `/api/incidents/${inc.id}/export`, download: `${inc.ref}.json` }, '⬇ Download evidence package (JSON)'),
        h('span', { class: 'small muted' }, 'The JSON includes the audit-chain verification result.')),
      h('br'),
      can('read.priv') ? h('div', { class: 'conf' }, 'Privileged & Confidential — Attorney-Client Communication / Attorney Work Product') : h('div', { class: 'conf' }, 'Confidential'),
      h('br'),
      h('h1', {}, `${inc.ref}: ${inc.title}`),
      h('div', { class: 'small muted' }, `Generated ${fmt(new Date(nowMs()).toISOString())} by ${S.user.display} · All times ${S.tz === 'utc' ? 'in UTC' : 'in local time (' + tzName() + ')'}, 24-hour clock, from the IRONROOM server clock`),
      h('h4', {}, 'Response time metrics'),
      h('table', {}, h('tbody', {}, metrics().map(([l, v, d]) => h('tr', {}, h('td', {}, l), h('td', { class: 'mono' }, v), h('td', { class: 'small' }, d))))),
      h('h4', {}, 'Phase & status history'),
      h('table', {}, h('thead', {}, h('tr', {}, ['When', 'Change', 'By'].map((x) => h('th', {}, x)))),
        h('tbody', {}, (inc.history || []).map((x) => h('tr', {}, h('td', { class: 'small mono' }, fmt(x.at)), h('td', {}, `${x.field[0].toUpperCase() + x.field.slice(1)}: ${x.from || '(new)'} → ${x.to}`), h('td', { class: 'small' }, x.by))))),
      h('h4', {}, 'Incident details'),
      kv([['Category', inc.category], ['Severity', inc.severity], ['Status', inc.status], ['Current phase', inc.phase], ['Incident commander', inc.commander],
        ['Started (est.)', fmt(inc.occurred_at)], ['Discovered', fmt(inc.discovered_at)], ['Detected by', inc.detection_source], ['Reported by', inc.reported_by],
        ['Attack vector', inc.attack_vector], ['Threat actor', inc.threat_actor], ['Affected systems', inc.affected_systems], ['Ransom demand', inc.ransom_demand], ['External references', inc.external_refs]]),
      h('h4', {}, 'Summary'), h('div', { class: 'tl-item' }, h('div', { class: 'txt' }, inc.summary || '—')),
      h('h4', {}, 'Business impact'), h('div', { class: 'txt' }, inc.business_impact || '—'),
      h('h4', {}, 'Notifications & engagement'),
      kv([['Outside counsel', yn(inc.counsel_engaged)], ['Forensics firm', yn(inc.forensics_engaged)], ['Cyber insurer', yn(inc.insurer_notified)], ['Law enforcement', yn(inc.le_notified)], ['Regulators', yn(inc.regulators_notified)], ['Backups verified', yn(inc.backups_verified)]]),
      h('h4', {}, 'Notification deadlines'),
      h('table', {}, h('tbody', {}, clocks().map((c) => h('tr', {}, h('td', {}, c.name), h('td', {}, fmt(c.due.toISOString())), h('td', {}, c.done ? 'Sent' : 'Pending'))))),
      h('h4', {}, `Affected data (${E.scope.length})`),
      h('table', {}, h('thead', {}, h('tr', {}, ['Data set', 'Location', 'Kinds', 'Records', 'Status', 'Status since', 'Confidence', 'Jurisdictions'].map((x) => h('th', {}, x)))),
        h('tbody', {}, E.scope.map((s) => h('tr', {}, h('td', {}, s.name), h('td', {}, s.system), h('td', {}, (s.data_types || []).join(', ')), h('td', {}, n(s.records)), h('td', {}, s.status),
          h('td', { class: 'small' }, (s.status_history || []).length ? fmt(s.status_history[s.status_history.length - 1].at) : '—'), h('td', {}, s.confidence), h('td', {}, (s.jurisdictions || []).join(', ')))))),
      h('h4', {}, 'Timeline'),
      h('table', {}, h('thead', {}, h('tr', {}, ['Event time', 'What happened', 'Source', 'Logged'].map((x) => h('th', {}, x)))),
        h('tbody', {}, [...E.timeline].sort((a, b) => new Date(a.at) - new Date(b.at)).map((t) => h('tr', {}, h('td', { class: 'small mono' }, fmt(t.at)), h('td', {}, t.text, t.privileged ? ' [PRIVILEGED]' : ''), h('td', { class: 'small' }, t.source || t.author),
          h('td', { class: 'tiny' }, t.is_system ? 'automatic' : `${fmt(t.logged_at || t.created)} · ${t.author}`))))),
      h('h4', {}, `Evidence (${E.evidence.length})`),
      h('table', {}, h('thead', {}, h('tr', {}, ['File', 'SHA-256', 'Collected', 'Logged by', 'Custody events'].map((x) => h('th', {}, x)))),
        h('tbody', {}, E.evidence.map((e) => h('tr', {}, h('td', {}, e.name), h('td', { class: 'mono tiny hash' }, e.sha256), h('td', { class: 'small' }, fmt(e.collected_at)), h('td', { class: 'small' }, `${e.author}, ${fmt(e.logged_at)}`), h('td', {}, e.custody.length))))),
      h('h4', {}, 'Indicators of compromise'),
      h('table', {}, h('tbody', {}, E.ioc.map((i) => h('tr', {}, h('td', {}, i.type), h('td', { class: 'mono small' }, i.value), h('td', {}, i.note))))),
      h('h4', {}, 'Response tasks'),
      h('table', {}, h('tbody', {}, E.task.map((t) => h('tr', {}, h('td', {}, t.done ? '☑' : '☐'), h('td', {}, t.title), h('td', { class: 'small' }, t.phase), h('td', { class: 'small' }, t.done_by ? `${t.done_by}, ${fmt(t.done_at)}` : (t.assignee ? `Assigned: ${t.assignee}` : '')))))),
    ));
  });
}

// ---------- comms ----------
function renderComms() {
  const el = $('comms');
  if (!el) return;
  const inIncident = !!(S.cur && S.data);
  if (!inIncident) S.chan = 'team';
  const txt = h('textarea', { id: 'composer', placeholder: 'Type a message… (Enter to send, Shift+Enter for new line)', 'aria-label': 'Message' });
  const urgent = h('input', { type: 'checkbox' });
  const priv = h('input', { type: 'checkbox' });
  const btn = h('button', { class: 'btn primary right' }, 'Send');
  const send = () => run(btn, async () => {
    if (!txt.value.trim()) return;
    await addEntry('message', { text: txt.value, urgent: urgent.checked, privileged: priv.checked }, S.chan === 'team' ? 0 : S.cur);
    txt.value = ''; urgent.checked = false; priv.checked = false; txt.focus();
  });
  btn.onclick = send;
  txt.addEventListener('keydown', (e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send(); } });
  mount(el,
    h('div', { class: 'comms-head' },
      h('div', { class: 'row' }, h('h3', {}, '💬 Secure team chat')),
      h('div', { class: 'chan', id: 'chan' }),
      h('div', { class: 'online', id: 'online' })),
    h('div', { class: 'msgs', id: 'msgs', 'aria-live': 'polite' }),
    can('chat') ? h('div', { class: 'composer' }, txt,
      h('div', { class: 'row wrap' },
        h('label', { class: 'check small' }, urgent, '🚨 Urgent (alerts everyone)'),
        can('read.priv') ? h('label', { class: 'check small' }, priv, '🔒 Privileged') : null, btn)) : null);
  S.unread[S.chan] = 0;
  renderChan(); renderOnline(); renderMsgs();
}
function renderChan() {
  const inIncident = !!(S.cur && S.data);
  const badge = (k) => (S.unread[k] ? h('span', { class: 'badge' }, S.unread[k]) : null);
  const go = (k) => { S.chan = k; S.unread[k] = 0; const b = $('msgs'); if (b) delete b.dataset.init; renderChan(); renderMsgs(); };
  mount($('chan'),
    h('button', { class: S.chan === 'incident' ? 'on' : '', disabled: !inIncident, onclick: () => go('incident') }, inIncident ? `This incident (${S.data.incident.ref})` : 'This incident', badge('incident')),
    h('button', { class: S.chan === 'team' ? 'on' : '', onclick: () => go('team') }, 'Whole team', badge('team')));
}
function renderOnline() {
  mount($('online'), h('span', { class: 'tiny muted' }, 'Online now:'), S.online.map((u) => h('span', { class: 'pill', title: u.role }, '● ' + u.display)));
}
function renderMsgs() {
  const box = $('msgs');
  if (!box) return;
  const list = S.chan === 'team' ? S.channel : (S.data ? S.data.entries.message : []);
  const nearBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 80;
  let day = '';
  mount(box, list.length ? list.map((m) => [fmtDay(m.created) !== day ? h('div', { class: 'daysep' }, (day = fmtDay(m.created))) : null, h('div', { class: 'msg' + (m.author_id === S.user.id ? ' me' : '') + (m.urgent ? ' urgent' : '') + (m.privileged ? ' priv' : '') },
    h('div', { class: 'hdr' }, h('b', {}, m.author), h('span', {}, m.author_role || ''), h('span', { class: 'right mono' }, ts(m.created, { timeOnly: true }))),
    m.urgent ? h('div', { class: 'tiny' }, '🚨 URGENT') : null, m.privileged ? h('div', { class: 'tiny' }, '🔒 Privileged & confidential') : null,
    h('div', { class: 'txt' }, m.text),
    S.chan === 'incident' && can('entry.write') ? h('div', { class: 'act' }, h('button', {
      class: 'btn sm ghost', onclick: (e) => run(e.target, async () => { await addEntry('timeline', { at: new Date(m.created * 1000).toISOString(), text: m.text, source: `Chat — ${m.author}`, privileged: !!m.privileged }); toast('Added to timeline'); }),
    }, '↳ Add to timeline')) : null)])
    : h('div', { class: 'empty small' }, S.chan === 'team' ? 'Team-wide channel. Use for anything not tied to one incident.' : 'No messages for this incident yet.'));
  if (nearBottom || !box.dataset.init) { box.scrollTop = box.scrollHeight; box.dataset.init = '1'; }
}

// ---------- declare incident ----------
function showDeclare() {
  const title = h('input', { type: 'text', placeholder: 'e.g. Files encrypted on Dallas file server' });
  const cat = segPicker(S.meta.categories, 'Other');
  const sev = segPicker(S.meta.severities, 'SEV2', { SEV1: 'Critical — business stopped or data stolen', SEV2: 'High — major systems affected', SEV3: 'Medium — contained, limited impact', SEV4: 'Low — minor / suspicious' });
  const when = h('input', { type: 'datetime-local', value: toLocalInput(new Date().toISOString()) });
  const summary = h('textarea', { placeholder: 'Optional: what do we know so far?' });
  const btn = h('button', { class: 'btn primary big' }, '🚨 Declare incident');
  const close = modal('Declare a new incident', h('div', { class: 'col' },
    h('div', { class: 'small muted' }, 'Just the basics — you can fill in everything else later. A checklist for the incident type is created automatically.'),
    h('label', { class: 'f' }, '1. Short title *', title),
    h('label', { class: 'f' }, '2. What kind of incident? (best guess is fine)', cat.el),
    h('label', { class: 'f' }, '3. How bad is it?', sev.el),
    h('div', { class: 'grid2' }, h('label', { class: 'f' }, '4. When was it discovered?', when), h('label', { class: 'f' }, 'Notes', summary)),
    btn), { wide: true });
  btn.onclick = () => run(btn, async () => {
    if (!title.value.trim()) { title.focus(); return toast('Give it a short title', 'bad'); }
    const r = await api('POST', '/api/incidents', { title: title.value, category: cat.get(), severity: sev.get(), discovered_at: fromLocalInput(when.value), summary: summary.value });
    close(); await loadIncidents(); S.tab = 'overview'; openIncident(r.id); toast(`${r.ref} declared. Team notified.`);
  });
}

// ---------- team & access ----------
async function showTeam() {
  await loadUsers();
  const body = h('div', { class: 'col' });
  const draw = () => {
    const admin = can('users');
    const name = h('input', { type: 'text', placeholder: 'Full name, e.g. Dana Rivera' });
    const uname = h('input', { type: 'text', placeholder: 'username, e.g. d.rivera', autocapitalize: 'none' });
    const role = segPicker(Object.keys(S.meta.roles), 'responder', {
      admin: 'Manages people & security', commander: 'Runs the response', responder: 'Does the hands-on work', legal: 'Counsel; sees privileged items', viewer: 'Executives: read + chat'});
    const addBtn = h('button', { class: 'btn primary' }, 'Add person & create sign-in card');
    addBtn.onclick = () => run(addBtn, async () => {
      const r = await api('POST', '/api/users', { display: name.value, username: uname.value, role: role.get() });
      await loadUsers(); showEnrollment(r.enrollment, r.user.display);
    });
    name.addEventListener('input', () => { if (!uname.dataset.touched) uname.value = name.value.trim().toLowerCase().replace(/\s+/g, '.').replace(/[^a-z0-9._-]/g, ''); });
    uname.addEventListener('input', () => { uname.dataset.touched = '1'; });
    mount(body,
      admin ? h('div', { class: 'card col' }, h('h3', {}, 'Add a person'),
        h('div', { class: 'grid2' }, h('label', { class: 'f' }, 'Full name', name), h('label', { class: 'f' }, 'Username', uname)),
        h('label', { class: 'f' }, 'Role', role.el), h('div', {}, addBtn),
        h('div', { class: 'tiny muted' }, 'You’ll get a one-time sign-in card (temporary password + authenticator QR code). Hand it over in person or read it by phone after verifying identity. It is never shown again.')) : null,
      h('div', { class: 'card' }, h('table', {},
        h('thead', {}, h('tr', {}, ['Person', 'Role', 'Status', 'Last sign-in', admin ? 'Actions' : ''].map((x) => h('th', {}, x)))),
        h('tbody', {}, S.users.map((u) => h('tr', {},
          h('td', {}, h('b', {}, u.display), u.online ? h('span', { class: 'pill', style: null }, ' ● online') : null, h('div', { class: 'tiny muted mono' }, u.username)),
          h('td', {}, admin && u.id !== S.user.id ? sel(Object.keys(S.meta.roles), u.role, (v) => run(null, async () => { await api('PATCH', `/api/users/${u.id}`, { role: v }); toast('Role updated'); await loadUsers(); draw(); })) : u.role_label),
          h('td', {}, u.active ? (u.must_change ? 'Invited (not signed in yet)' : 'Active') : h('span', { class: 'pill st-Active' }, 'Disabled')),
          h('td', { class: 'small' }, u.last_login ? ts(u.last_login, { rel: true }) : 'Never'),
          h('td', {}, admin && u.id !== S.user.id ? h('div', { class: 'row' },
            h('button', { class: 'btn sm', onclick: () => confirmBox(`Reset ${u.display}'s password and authenticator? They'll be signed out and need a new sign-in card.`, () => run(null, async () => { const r = await api('POST', `/api/users/${u.id}/reset`); showEnrollment(r.enrollment, u.display); })) }, 'Reset sign-in'),
            h('button', { class: 'btn sm ' + (u.active ? 'danger' : ''), onclick: () => run(null, async () => { await api('PATCH', `/api/users/${u.id}`, { active: !u.active }); toast(u.active ? `${u.display} disabled and signed out` : `${u.display} re-enabled`); await loadUsers(); draw(); }) }, u.active ? 'Disable' : 'Enable')) : null)))))));
  };
  draw();
  modal(can('users') ? 'Team & access control' : 'Response team', body, { wide: true });
}

function showEnrollment(e, who) {
  modal(`Sign-in card for ${who}`, h('div', { class: 'col' },
    h('div', { class: 'err' }, 'Shown only once. Give it to the person directly, then close this window.'),
    h('div', { class: 'enroll' },
      h('img', { src: e.qr, alt: 'Authenticator QR code' }),
      h('div', { class: 'col' },
        h('div', {}, h('b', {}, 'IRONROOM sign-in card')),
        h('div', {}, h('div', { class: 'muted tiny' }, 'Username'), h('div', { class: 'mono' }, e.username)),
        h('div', {}, h('div', { class: 'muted tiny' }, 'Temporary password (change at first sign-in)'), h('div', { class: 'mono' }, e.temp_password)),
        h('div', {}, h('div', { class: 'muted tiny' }, 'Authenticator key (if you can’t scan)'), h('div', { class: 'mono small' }, e.totp_secret)),
        h('div', { class: 'tiny muted' }, '1) Install any authenticator app (Google/Microsoft Authenticator, Authy). 2) Scan the QR code. 3) Sign in with username, password and the 6-digit code.'))),
    h('div', { class: 'row' }, h('button', { class: 'btn', onclick: () => window.print() }, '🖨 Print card'))));
}

// ---------- audit ----------
async function showAudit() {
  const rows = await api('GET', '/api/audit');
  const res = h('div');
  const vbtn = h('button', { class: 'btn primary' }, '🔍 Verify audit log integrity');
  vbtn.onclick = () => run(vbtn, async () => {
    const r = await api('GET', '/api/audit/verify');
    mount(res, r.ok ? h('div', { class: 'okbox' }, `✓ Intact. ${r.checked} entries verified; no record has been altered, removed or reordered. Chain head: ${r.head.slice(0, 24)}…`)
      : h('div', { class: 'err' }, `✗ TAMPERING DETECTED at entry #${r.broken_at} (${r.reason}). Preserve this machine as evidence.`));
  });
  modal('Audit log', h('div', { class: 'col' },
    h('div', { class: 'small muted' }, 'Every sign-in, change and export is recorded. Each entry is cryptographically chained to the one before it, so any edit or deletion is detectable.'),
    h('div', { class: 'row' }, vbtn), res,
    h('div', { class: 'card' }, h('table', {}, h('thead', {}, h('tr', {}, ['Time', 'Who', 'Action', 'Target', 'Device IP', 'Hash'].map((x) => h('th', {}, x)))),
      h('tbody', {}, rows.map((r) => h('tr', {}, h('td', { class: 'small mono' }, ts(r.ts)), h('td', {}, r.actor), h('td', { class: /fail|LOCK/.test(r.action) ? 'mono small' : 'mono small' }, r.action), h('td', { class: 'small' }, r.target), h('td', { class: 'mono tiny' }, r.ip), h('td', { class: 'mono tiny muted' }, r.hash))))))), { wide: true });
}

// ---------- lockdown ----------
function showLockdown() {
  const inp = h('input', { type: 'text', placeholder: 'Type LOCKDOWN' });
  const btn = h('button', { class: 'btn danger big' }, '⛔ Sign everyone out now');
  const close = modal('Emergency lockdown', h('div', { class: 'col' },
    h('div', {}, 'Use this if you think an IRONROOM account or device is compromised. ', h('b', {}, 'Every session is ended immediately'), ' — including yours. People must sign in again with their password and authenticator code.'),
    h('div', { class: 'small muted' }, 'Afterwards: disable the suspected account in Team & Access, and review the Audit log.'),
    inp, btn));
  btn.onclick = () => run(btn, async () => {
    if (inp.value.trim() !== 'LOCKDOWN') return toast('Type LOCKDOWN to confirm', 'bad');
    const r = await api('POST', '/api/admin/lockdown');
    close(); signedOut(`Lockdown complete: ${r.killed} session(s) ended.`);
  });
}

// ---------- help ----------
function showHelp() {
  const item = (t, d) => h('div', { class: 'card' }, h('b', {}, t), h('div', { class: 'small muted' }, d));
  modal('Quick guide', h('div', { class: 'grid2' },
    item('👉 Do this next', 'The yellow box always shows the next 3 tasks for the current phase and any warnings. Tick them off as you go.'),
    item('Steps 1–6 (phase bar)', 'The standard incident lifecycle: Detection → Analysis → Containment → Eradication → Recovery → Post-Incident. Click a step to move the incident.'),
    item('Affected data', 'Record each data set that may be involved and what happened to it: accessed, stolen (exfiltrated), locked by ransomware, etc.'),
    item('Timeline', 'Write down what happened and when. Changes to phase, status and data are logged here automatically.'),
    item('💬 Chat', 'Talk here, not on email/Teams. Tick “Urgent” to pop an alert on everyone’s screen. Hover a message to add it to the timeline.'),
    item('📞 Verification phrase', 'Attackers impersonate executives by phone. Ask callers to read the phrase shown on the incident page.'),
    item('⏱ Deadlines', 'Notification deadlines appear automatically based on the type of data and where affected people live. Confirm with counsel.'),
    item('🔒 Privileged', 'Counsel and commanders can mark notes privileged; responders and viewers won’t see them.')), { wide: true });
}

boot();
