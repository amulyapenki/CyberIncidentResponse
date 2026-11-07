'use strict';
/* LIFEBOAT views. Depends on core.js. */

const can = (p) => !!S.perms[p];
const UI = { tlKind: 'all', tlStruck: false, taskMine: false, incFilter: 'active', incSearch: '', auditQ: '' };
let current = null;

// ================================================================ AUTH
const authState = { mode: 'login', enroll: null, status: null };

async function renderAuth(notice) {
  current = null;
  try { authState.status = await api('GET', '/api/auth/status'); } catch { authState.status = null; }
  if (authState.status?.setupPending && authState.mode === 'login' && !notice) authState.mode = 'invite';
  drawAuth(notice);
}

function drawAuth(notice) {
  const st = authState.status || {};
  const m = authState.mode;
  let body;
  if (m === 'enroll') {
    const e = authState.enroll;
    body = html`
      <h2>Set up two-factor sign-in</h2>
      <p class="muted small">Open an authenticator app on your phone (Google Authenticator, Microsoft Authenticator, 1Password, Authy…), tap <b>+</b>, and scan this code.</p>
      <svg class="qr" viewBox="0 0 ${e.qr.size} ${e.qr.size}" shape-rendering="crispEdges" role="img" aria-label="QR code for authenticator"><rect width="100%" height="100%" fill="#fff"/><path d="${e.qr.path}" fill="#000"/></svg>
      <details><summary class="small muted">Can't scan? Type this key instead</summary><div class="secret" >${e.secret.match(/.{1,4}/g).join(' ')}</div></details>
      <form data-submit="enrollConfirm" class="col">
        <label class="field">Enter the 6-digit code the app shows
          <input name="totp" id="en-code" class="code-input" inputmode="numeric" autocomplete="one-time-code" maxlength="6" pattern="[0-9]{6}" required placeholder="••••••" autofocus></label>
        <div id="auth-err"></div>
        <button class="btn primary block xl">Activate my account</button>
      </form>`;
  } else {
    body = html`
      <div class="seg-tabs"><button type="button" class="${m === 'login' ? 'on' : ''}" data-a="authMode" data-m="login">Sign in</button><button type="button" class="${m === 'invite' ? 'on' : ''}" data-a="authMode" data-m="invite">I have an invite code</button></div>
      ${m === 'login' ? html`
        <form data-submit="login" class="col" autocomplete="on">
          <label class="field">Username<input name="username" id="li-user" autocomplete="username" autocapitalize="none" spellcheck="false" required autofocus></label>
          <label class="field">Password<input type="password" name="password" id="li-pass" autocomplete="current-password" required></label>
          <label class="field">6-digit code from your authenticator app<input name="totp" id="li-code" class="code-input" inputmode="numeric" autocomplete="one-time-code" maxlength="6" pattern="[0-9]{6}" required placeholder="••••••"></label>
          <div id="auth-err"></div>
          <button class="btn primary block xl">${icon('lock')} Sign in</button>
        </form>` : html`
        ${st.setupPending ? html`<p class="small muted">First time? Use the <b>administrator username and one-time code</b> printed in the LIFEBOAT server console.</p>` : html`<p class="small muted">Your administrator gave you a one-time code in person or by phone.</p>`}
        <form data-submit="enroll" class="col">
          <label class="field">Username<input name="username" autocapitalize="none" spellcheck="false" required autofocus></label>
          <label class="field">One-time invite code<input name="code" class="mono" placeholder="XXXXX-XXXXX-XXXXX" autocomplete="off" required></label>
          <label class="field">Choose a password <span class="hint">At least 12 characters. A short sentence is easy to remember and hard to guess.</span><input type="password" name="password" autocomplete="new-password" minlength="12" required></label>
          <label class="field">Type it again<input type="password" name="password2" autocomplete="new-password" minlength="12" required></label>
          <div id="auth-err"></div>
          <button class="btn primary block xl">Continue ${icon('arrow')}</button>
        </form>`}`;
  }
  setHTML('#app', html`
    <div class="auth"><div class="auth-card">
      <div class="auth-brand">${LOGO}<h1>LIFEBOAT</h1><p>Out-of-band incident command</p></div>
      ${st.lockdown ? html`<div class="banner lockdown" >LOCKDOWN IN EFFECT: administrators only</div><br>` : ''}
      ${notice ? html`<div class="error-box">${notice}</div><br>` : ''}
      <div class="panel col">${body}</div>
      <div class="auth-foot">
        <span class="lock-icon">${icon('lock')} ${st.tls ? 'Encrypted connection' : 'Local connection'}</span> · Encrypted at rest · Every action audited<br>
        Never enter your LIFEBOAT password into any other system.
      </div>
    </div></div>`);
  const code = $('#li-code');
  if (code) code.addEventListener('input', () => { code.value = code.value.replace(/\D/g, ''); if (code.value.length === 6 && $('#li-user').value && $('#li-pass').value) code.form.requestSubmit(); });
  const en = $('#en-code');
  if (en) en.addEventListener('input', () => { en.value = en.value.replace(/\D/g, ''); if (en.value.length === 6) en.form.requestSubmit(); });
}
const authErr = (msg) => setHTML('#auth-err', html`<div class="error-box">${msg}</div>`);

A.authMode = (t) => { authState.mode = t.dataset.m; drawAuth(); };
A.login = async (f) => {
  const btn = $('button.primary', f); btn.disabled = true;
  try {
    await api('POST', '/api/auth/login', formData(f));
    await startSession(await api('GET', '/api/me'));
  } catch (e) { authErr(e.message); f.totp.value = ''; f.totp.focus(); btn.disabled = false; }
};
A.enroll = async (f) => {
  const d = formData(f);
  if (d.password !== d.password2) return authErr('The two passwords do not match.');
  try {
    authState.enroll = await api('POST', '/api/auth/enroll', { username: d.username, code: d.code, password: d.password });
    authState.mode = 'enroll';
    drawAuth();
  } catch (e) { authErr(e.message); }
};
A.enrollConfirm = async (f) => {
  try {
    await api('POST', '/api/auth/enroll/confirm', { enrollToken: authState.enroll.enrollToken, totp: f.totp.value });
    authState.enroll = null; authState.mode = 'login';
    await startSession(await api('GET', '/api/me'));
    toast('Welcome aboard. Your account is protected with two-factor sign-in.', 'ok');
  } catch (e) { authErr(e.message); f.totp.value = ''; }
};
A.logout = async () => {
  await api('POST', '/api/auth/logout', {}).catch(() => {});
  sessionEnded('You have signed out.');
};

async function startSession(me) {
  Object.assign(S, { me: me.user, csrf: me.csrf, perms: me.perms, roles: me.roles, idleMs: me.idleMinutes * 60e3, tls: me.tls });
  S.serverOffset = new Date(me.serverTime).getTime() - Date.now();
  lastTouch = Date.now();
  await resync();
  S.loaded = true;
  if (location.hash.startsWith('#/wall')) route(); else { renderShell(); route(); }
  connectStream();
}
function sessionEnded(msg) {
  if (!S.me) return;
  Object.assign(S, { me: null, csrf: null, loaded: false, inc: new Map(), msgs: new Map(), unread: {} });
  if (es) { es.close(); es = null; }
  closeModal();
  renderAuth(msg);
}

// ================================================================ SHELL
function renderShell() {
  setHTML('#app', html`<div class="shell">
    <header class="topbar">
      <a class="brand" href="#/">${LOGO}<span>LIFEBOAT<small id="org-name">${S.org.name}</small></span></a>
      <button class="btn ghost sm" data-a="palette" title="Search & commands">${icon('search')} Jump to… <kbd>Ctrl K</kbd></button>
      <span class="grow"></span>
      <div class="clocks"><span><b id="clock-utc">--:--:--</b> UTC</span><span class="local"><b id="clock-local">--:--</b> local</span></div>
      <span id="conn" class="conn"></span>
      <div id="online" class="online-stack"></div>
      <button class="iconbtn" data-a="help" title="Help (?)">${icon('help')}</button>
      <button class="iconbtn" data-a="theme" title="Light / dark">${icon('moon')}</button>
      <span class="row small"><span id="me-av"></span><span class="col" ><b>${S.me.displayName}</b></span></span>
      <button class="iconbtn" data-a="logout" title="Sign out">${icon('logout')}</button>
    </header>
    <nav class="sidebar" id="side"></nav>
    <main class="main" id="main"><div id="banners"></div><div id="view" class="view"></div></main>
  </div>`);
  setConn(S.conn);
  updateChrome();
}

function updateChrome() {
  if (!$('#side') || !S.me) return;
  const p = parts();
  const activeIncs = allIncidents().filter(isActive);
  const unread = Object.values(S.unread).reduce((a, b) => a + b, 0);
  const nav = (href, ic, label, on, badge) => html`<a class="nav ${on ? 'active' : ''}" href="${href}">${icon(ic)}<span>${label}</span>${badge ? html`<span class="badge">${badge}</span>` : ''}</a>`;
  setHTML('#side', html`
    ${nav('#/', 'home', 'Command', !p[0])}
    ${nav('#/incidents', 'alert', 'Incidents', p[0] === 'incidents', activeIncs.length || '')}
    ${nav('#/comms', 'chat', 'Comms', p[0] === 'comms', unread || '')}
    ${nav('#/contacts', 'phone', 'Contacts', p[0] === 'contacts')}
    ${nav('#/wall', 'tv', 'Wallboard', false)}
    ${can('admin') ? nav('#/admin', 'shield', 'Admin', p[0] === 'admin') : can('audit.read') ? nav('#/admin/audit', 'shield', 'Audit log', p[0] === 'admin') : ''}
    ${activeIncs.length ? html`<div class="nav-sep"></div><div class="nav-label">ACTIVE INCIDENTS</div>
      ${activeIncs.map((i) => html`<a class="side-incident ${p[0] === 'i' && p[1] === i.id ? 'active' : ''}" href="#/i/${i.id}">${sevChip(i.severity, false)}<span class="grow nowrap">${i.codename}</span></a>`)}` : ''}
    <span class="grow side-extra"></span>
    ${can('incident.create') ? html`<button class="btn primary block side-extra" data-a="declare">${icon('zap')} Declare incident</button>` : ''}
  `);
  setHTML('#online', [...S.online].slice(0, 6).map((id) => avatar(id, true)));
  setHTML('#me-av', avatar(S.me.id, true, true));
  const urgent = urgentPending();
  setHTML('#banners', html`
    ${S.lockdown?.on ? html`<div class="banner lockdown">${icon('lock')} LOCKDOWN ACTIVE · Only administrators can use LIFEBOAT right now</div>` : ''}
    ${!S.tls ? html`<div class="banner insecure">Running without HTTPS (local only). Run <span class="mono">npm run cert</span> before use on a network.</div>` : ''}
    ${urgent.length ? html`<div class="banner urgent" data-a="goUrgent">${icon('bell')} ${urgent.length} urgent message${urgent.length > 1 ? 's' : ''} waiting for your acknowledgment. Click to view</div>` : ''}`);
  const sev1 = activeIncs.filter((i) => i.severity === 1).length;
  document.title = `${unread ? `(${unread}) ` : ''}${sev1 ? '🔴 ' : ''}LIFEBOAT`;
}
A.goUrgent = () => { const m = urgentPending()[0]; if (m) location.hash = '#/comms/' + m.channelId; };
A.theme = () => applyTheme(S.theme === 'dark' ? 'light' : 'dark');

// ================================================================ ROUTER
function parts() { return location.hash.replace(/^#\/?/, '').split('/').filter(Boolean).map(decodeURIComponent); }
addEventListener('hashchange', route);

function route() {
  if (!S.me || !S.loaded) return;
  const [a, b, c] = parts();
  if (a === 'wall') {
    current = WallView();
    current.mount($('#app'));
    return;
  }
  if (!$('#side')) renderShell();
  const prev = current;
  let v;
  if (!a) v = DashView();
  else if (a === 'incidents') v = IncidentsView();
  else if (a === 'i') v = IncidentView(b, c || 'overview');
  else if (a === 'comms') v = CommsView(b);
  else if (a === 'contacts') v = ContactsView();
  else if (a === 'admin') v = AdminView(b || (can('admin') ? 'people' : 'audit'));
  else v = { mount(el) { setHTML(el, html`<div class="empty"><h2>Page not found</h2><p><a href="#/">Back to Command</a></p></div>`); } };
  current = v;
  const view = $('#view');
  view.className = 'view' + (v.flush ? ' flush' : '');
  const sameIncident = prev?.incId && prev.incId === v.incId;
  if (!sameIncident) $('#main').scrollTop = 0;
  view.innerHTML = '';
  v.mount(view);
  updateChrome();
}
function refresh(what, id) {
  if (!S.loaded || !current) return;
  updateChrome();
  if (current.update) withFocus(() => current.update(what, id));
}
function currentChannel() { return current?.channelId ? current.channelId() : null; }

// ================================================================ COMMAND CENTER
function DashView() {
  return { mount(el) { this.el = el; this.update(); }, update(what) { if (what === 'message' || what === 'ack') return; setHTML(this.el, dashHTML()); } };
}

function incCard(i) {
  const tasks = live(i.tasks);
  const done = tasks.filter((t) => t.status === 'done').length;
  const next = openObligations(i).find((o) => o.dueAt);
  return html`<a class="inc-card s${i.severity}" href="#/i/${i.id}">
    <div class="row between wrap"><div class="row wrap">${sevChip(i.severity)}<span class="mono small">${i.ref}</span><span class="codename">${i.codename}</span><span class="chip">${phaseById(i.status).label}</span>${i.access === 'restricted' ? html`<span class="chip" title="Need-to-know">${icon('lock')}</span>` : ''}</div>
    ${since(i.detectedAt, i.closedAt)}</div>
    <div class="inc-title">${i.title}</div>
    <div class="row wrap small muted">
      ${miniPhases(i)}
      <span class="row" ><span class="nowrap">${done}/${tasks.length} tasks</span></span>
      ${next ? html`<span class="nowrap">${icon('scale')}</span><span class="grow nowrap">${next.title.length > 42 ? next.title.slice(0, 40) + '…' : next.title} ${countdown(next.dueAt)}</span>` : html`<span class="grow"></span>`}
      ${avatar(i.leadId, true)}
    </div>
  </a>`;
}
function deadlineRow(o, inc) {
  return html`<a class="deadline" href="#/i/${inc.id}/obligations"><div><b>${o.title}</b><div class="tiny muted">${inc.codename} · ${o.who}</div></div><div class="right">${countdown(o.dueAt)}<div class="tiny dim">${fmtUTC(o.dueAt)}</div></div></a>`;
}

function dashHTML() {
  const incs = allIncidents();
  const active = incs.filter(isActive);
  const deadlines = active.flatMap((i) => openObligations(i).filter((o) => o.dueAt).map((o) => ({ o, i }))).sort((a, b) => a.o.dueAt.localeCompare(b.o.dueAt));
  const in72 = deadlines.filter((d) => new Date(d.o.dueAt).getTime() - nowMs() < 72 * 36e5);
  const overdue = deadlines.filter((d) => new Date(d.o.dueAt).getTime() < nowMs());
  const myTasks = active.flatMap((i) => live(i.tasks).filter((t) => t.assigneeId === S.me.id && t.status !== 'done').map((t) => ({ t, i })));
  const activity = active.flatMap((i) => live(i.timeline).map((e) => ({ e, i }))).sort((a, b) => b.e.loggedAt.localeCompare(a.e.loggedAt)).slice(0, 14);
  const hr = new Date().getHours();
  const greet = hr < 5 ? 'Working late' : hr < 12 ? 'Good morning' : hr < 18 ? 'Good afternoon' : 'Good evening';
  const team = S.users.filter((u) => u.status === 'active');
  const setup = can('admin') ? [
    ['Set organization profile', S.org.name !== 'Your Organization', '#/admin/org'],
    ['Add cyber insurance details', !!S.org.insurance?.carrier, '#/admin/org'],
    ['Add 3+ emergency contacts', (S.org.contacts || []).length >= 3, '#/contacts'],
    ['Invite your response team', S.users.length >= 3, '#/admin/people'],
  ] : [];
  const setupLeft = setup.filter((s) => !s[1]);

  return html`
    <div class="page-head">
      <div><h1>${greet}, ${S.me.displayName.split(' ')[0]}.</h1>
      <p>${active.length ? html`<b>${active.length}</b> active incident${active.length > 1 ? 's' : ''}. ${overdue.length ? html`<b class="cd over">${overdue.length} deadline${overdue.length > 1 ? 's' : ''} overdue</b>` : in72.length ? `${in72.length} deadline${in72.length > 1 ? 's' : ''} in the next 72 hours.` : ''}` : 'All clear. No active incidents.'}</p></div>
      ${can('incident.create') ? html`<button class="btn primary xl" data-a="declare">${icon('zap')} Declare an incident</button>` : ''}
    </div>

    ${setupLeft.length ? html`<div class="next-up"><h3>Get ready before you need it · ${setup.length - setupLeft.length}/${setup.length} done</h3>
      <div class="row wrap">${setup.map(([l, ok, href]) => html`<a class="btn sm ${ok ? 'ghost' : ''}" href="${href}">${ok ? icon('check') : icon('arrow')} ${l}</a>`)}</div></div>` : ''}

    <div class="grid g4">
      <div class="panel stat ${active.length ? 'alert' : ''}"><div class="n">${active.length}</div><div class="l">Active incidents</div></div>
      <div class="panel stat ${active.some((i) => i.severity === 1) ? 'alert' : ''}"><div class="n">${active.filter((i) => i.severity === 1).length}</div><div class="l">SEV1 critical</div></div>
      <div class="panel stat ${overdue.length ? 'alert' : ''}"><div class="n">${in72.length}</div><div class="l">Legal deadlines ≤ 72h${overdue.length ? html` · <span class="cd over">${overdue.length} overdue</span>` : ''}</div></div>
      <div class="panel stat"><div class="n">${myTasks.length}</div><div class="l">Tasks assigned to me</div></div>
    </div>
    <br>
    <div class="grid g-main">
      <div class="col">
        <section class="panel">
          <div class="panel-head"><h3>${icon('alert')} Active incidents</h3><a class="small" href="#/incidents">All incidents ${icon('arrow')}</a></div>
          ${active.length ? active.map(incCard) : html`<div class="empty">${icon('shield')}<h3>All clear</h3><p>When something looks wrong, declare an incident. It takes 20 seconds and loads the right checklist automatically.</p>
            ${can('incident.create') ? html`<button class="btn primary" data-a="declare">${icon('zap')} Declare an incident</button>` : ''}</div>`}
        </section>
        <section class="panel">
          <div class="panel-head"><h3>${icon('activity')} Latest activity</h3></div>
          <div class="panel-body tight">${activity.length ? activity.map(({ e, i }) => html`<a class="list-item click" href="#/i/${i.id}/timeline">
            <span class="mono tiny dim nowrap">${fmtTimeUTC(e.at)}</span><span class="chip k-${e.kind}">${e.kind}</span><span class="grow">${e.text}</span><span class="tiny muted nowrap">${i.codename}</span></a>`) : html`<div class="empty small">Nothing yet.</div>`}</div>
        </section>
      </div>
      <div class="col">
        <section class="panel">
          <div class="panel-head"><h3>${icon('scale')} Notification clock</h3><span class="tiny muted">Legal & contractual deadlines</span></div>
          ${deadlines.length ? deadlines.slice(0, 8).map(({ o, i }) => deadlineRow(o, i)) : html`<div class="empty small">No running deadlines. Record compromised data in an incident's <b>Scope</b> tab and deadlines are worked out for you.</div>`}
        </section>
        <section class="panel">
          <div class="panel-head"><h3>${icon('check')} My tasks</h3></div>
          ${myTasks.length ? myTasks.slice(0, 10).map(({ t, i }) => html`<a class="list-item click" href="#/i/${i.id}/tasks"><span class="chip">${phaseById(t.phase).short}</span><span class="grow">${t.title}</span><span class="tiny muted">${i.codename}</span></a>`) : html`<div class="empty small">Nothing assigned to you.</div>`}
        </section>
        <section class="panel">
          <div class="panel-head"><h3>${icon('users')} Response team</h3><span class="tiny muted">${S.online.size} online</span></div>
          <div class="panel-body tight">${team.sort((a, b) => S.online.has(b.id) - S.online.has(a.id)).slice(0, 12).map((u) => html`<div class="list-item">${avatar(u.id, true, true)}<span class="grow">${u.displayName}<div class="tiny muted">${S.roles[u.role]}${u.title ? ' · ' + u.title : ''}</div></span>${u.phone ? html`<a class="tiny mono" href="tel:${u.phone}">${u.phone}</a>` : ''}</div>`)}</div>
        </section>
      </div>
    </div>`;
}

// ================================================================ DECLARE
A.declare = () => {
  if (!can('incident.create')) return;
  modal(html`<form data-submit="declareSubmit">
    ${mHead('Declare an incident', 'Only the first box is required. You can change everything later.')}
    <div class="modal-body">
      <label class="field">What is happening? <input name="title" required maxlength="200" placeholder="e.g. Files encrypted on file server, ransom note on screens" autofocus></label>
      <div class="field"><span class="field-l">What kind of incident? <span class="hint">Best guess is fine. This loads the right checklist.</span></span>
        <input type="hidden" name="category" value="other">
        <div class="pick-grid">${Object.entries(S.categories).map(([k, l]) => html`<button type="button" class="pick ${k === 'other' ? 'on' : ''}" data-a="pick" data-group="category" data-v="${k}">${l}</button>`)}</div></div>
      <div class="field"><span class="field-l">How bad is it?</span>
        <input type="hidden" name="severity" value="2">
        <div class="sev-pick">${[1, 2, 3, 4].map((s) => html`<button type="button" class="pick s${s} ${s === 2 ? 'on' : ''}" data-a="pick" data-group="severity" data-v="${s}">${sevChip(s, false)} ${SEV_TEXT[s]}<small>${SEV_DESC[s]}</small></button>`)}</div></div>
      <div class="form-grid">
        <label class="field">When was it discovered? <input type="datetime-local" name="detectedAt" value="${toLocalInput()}"></label>
        <label class="field">Anything else we know? <span class="hint">Optional</span><textarea name="summary" rows="2" placeholder="Who noticed, what they saw…"></textarea></label>
      </div>
      <label class="check"><input type="checkbox" name="privileged" checked><span><b>Privileged & Confidential</b><br><span class="small muted">Mark records as prepared at the direction of counsel. Recommended: bring in counsel early.</span></span></label>
      <label class="check"><input type="checkbox" name="restricted"><span><b>Need-to-know only</b><br><span class="small muted">Only you, and people you add, can see it. Use this for insider threats or when a staff account may be involved.</span></span></label>
    </div>
    <div class="modal-foot"><button class="btn" type="button" data-a="closeModal">Cancel</button><button class="btn primary xl">${icon('zap')} Declare incident</button></div>
  </form>`, { wide: true });
};
A.pick = (t) => {
  const g = t.dataset.group;
  $$(`[data-group="${g}"]`).forEach((x) => x.classList.toggle('on', x === t));
  const inp = $(`input[name="${g}"]`, t.closest('form'));
  if (inp) inp.value = t.dataset.v;
};
A.declareSubmit = async (f) => {
  const d = formData(f);
  const btn = $('button.primary', f); btn.disabled = true;
  const inc = await act(api('POST', '/api/incidents', {
    title: d.title, category: d.category, severity: Number(d.severity), detectedAt: fromLocalInput(d.detectedAt),
    summary: d.summary, privileged: !!d.privileged, restricted: !!d.restricted,
  }));
  btn.disabled = false;
  if (!inc) return;
  S.inc.set(inc.id, inc);
  await resync(false);
  closeModal();
  location.hash = '#/i/' + inc.id;
  toast(`${inc.ref} declared as "${inc.codename}". ${inc.tasks.length} checklist steps loaded and an incident room opened.`, 'ok');
};

// ================================================================ INCIDENT LIST
function IncidentsView() {
  return {
    mount(el) {
      this.el = el;
      setHTML(el, html`<div class="page-head"><div><h1>Incidents</h1><p>Every incident, newest and most severe first.</p></div>
        <div class="row"><input type="search" id="inc-q" data-keep placeholder="Search ref, codename, title…" value="${UI.incSearch}">
        ${can('incident.create') ? html`<button class="btn primary" data-a="declare">${icon('zap')} Declare</button>` : ''}</div></div><div id="inc-list"></div>`);
      $('#inc-q').addEventListener('input', (e) => { UI.incSearch = e.target.value; this.update(); });
      this.update();
    },
    update(what) {
      if (what === 'message' || what === 'ack') return;
      const q = UI.incSearch.toLowerCase();
      const list = allIncidents().filter((i) => (UI.incFilter === 'all' || (UI.incFilter === 'active') === isActive(i)) && (!q || `${i.ref} ${i.codename} ${i.title} ${i.category}`.toLowerCase().includes(q)));
      setHTML('#inc-list', html`<div class="row" ><div class="seg">${['active', 'closed', 'all'].map((f) => html`<button type="button" class="${UI.incFilter === f ? 'on' : ''}" data-a="incFilter" data-f="${f}">${f[0].toUpperCase() + f.slice(1)}</button>`)}</div></div><br>
        <div class="panel table-wrap"><table class="t"><thead><tr><th>Sev</th><th>Ref</th><th>Incident</th><th>Phase</th><th>Detected (UTC)</th><th>Elapsed</th><th>Lead</th><th>Next deadline</th></tr></thead><tbody>
        ${list.map((i) => { const n = openObligations(i).find((o) => o.dueAt); return html`<tr class="click" data-a="go" data-href="#/i/${i.id}">
          <td>${sevChip(i.severity)}</td><td class="mono nowrap">${i.ref}<div class="codename">${i.codename}</div></td><td><b>${i.title}</b><div class="tiny muted">${S.categories[i.category]}</div></td>
          <td class="nowrap">${miniPhases(i)}<div class="tiny muted">${phaseById(i.status).label}</div></td><td class="mono small nowrap">${fmtUTC(i.detectedAt)}</td><td class="small">${since(i.detectedAt, i.closedAt)}</td>
          <td>${avatar(i.leadId, true)}</td><td class="small">${n ? countdown(n.dueAt) : html`<span class="dim">-</span>`}</td></tr>`; })}
        </tbody></table>${list.length ? '' : html`<div class="empty">No incidents match.</div>`}</div>`);
    },
  };
}
A.incFilter = (t) => { UI.incFilter = t.dataset.f; refresh(); };
A.go = (t) => { location.hash = t.dataset.href; };

// ================================================================ INCIDENT WORKSPACE
const TABS = [
  ['overview', 'Overview', 'home'], ['timeline', 'Timeline', 'clock'], ['scope', 'Scope & Data', 'db'], ['tasks', 'Tasks', 'check'],
  ['obligations', 'Legal Deadlines', 'scale'], ['iocs', 'Indicators', 'target'], ['evidence', 'Evidence', 'box'], ['room', 'Room', 'chat'], ['report', 'Report', 'file'],
];

function IncidentView(id, tab) {
  return {
    incId: id, tab,
    channelId() { return tab === 'room' ? S.channels.find((c) => c.incidentId === id)?.id : null; },
    mount(el) { this.el = el; this.update(); if (tab === 'room') scrollChat(); },
    update(what, xid) {
      if ((what === 'message' || what === 'ack' || what === 'presence') && tab !== 'room') { if (what === 'message') this.tabsOnly(); return; }
      if (what === 'incident' && xid !== id) return;
      const inc = S.inc.get(id);
      if (!inc) { setHTML(this.el, html`<div class="empty"><h2>Incident not found</h2><p>It may be restricted to need-to-know members.</p><a href="#/">Back to Command</a></div>`); return; }
      setHTML(this.el, incidentHTML(inc, tab));
      if (tab === 'room') { const ch = S.channels.find((c) => c.incidentId === id); if (ch && document.hasFocus()) markRead(ch.id); }
    },
    tabsOnly() { const inc = S.inc.get(id); if (inc) setHTML('#inc-tabs', tabsHTML(inc, tab)); },
  };
}

function tabsHTML(inc, tab) {
  const ch = S.channels.find((c) => c.incidentId === inc.id);
  const over = openObligations(inc).filter((o) => o.dueAt && new Date(o.dueAt).getTime() < nowMs()).length;
  const counts = {
    timeline: live(inc.timeline).length, scope: live(inc.scope).length, tasks: live(inc.tasks).filter((t) => t.status !== 'done').length,
    obligations: openObligations(inc).length, iocs: live(inc.iocs).length, evidence: inc.evidence.length, room: ch ? S.unread[ch.id] || 0 : 0,
  };
  return TABS.map(([k, l, ic]) => html`<a class="tab ${tab === k ? 'active' : ''}" href="#/i/${inc.id}/${k}">${icon(ic)}${l}${counts[k] ? html`<span class="badge ${(k === 'obligations' && over) || (k === 'room' && counts.room) ? 'hot' : ''}">${counts[k]}</span>` : ''}</a>`);
}

function incidentHTML(inc, tab) {
  const idx = phaseIndex(inc.status);
  const w = can('incident.write');
  const body = { overview: tabOverview, timeline: tabTimeline, scope: tabScope, tasks: tabTasks, obligations: tabObligations, iocs: tabIocs, evidence: tabEvidence, room: tabRoom, report: tabReport }[tab] || tabOverview;
  return html`
    ${inc.privileged ? html`<div class="banner priv">${icon('scale')} PRIVILEGED & CONFIDENTIAL · ATTORNEY-CLIENT COMMUNICATION / ATTORNEY WORK PRODUCT · PREPARED AT THE DIRECTION OF COUNSEL</div>` : ''}
    <div class="inc-head">
      <div class="grow">
        <div class="row wrap">${sevChip(inc.severity)}<span class="mono">${inc.ref}</span><span class="codename">${inc.codename}</span><span class="chip">${S.categories[inc.category]}</span>
          ${inc.access === 'restricted' ? html`<span class="chip" title="Need-to-know">${icon('lock')} Need-to-know</span>` : ''}${inc.status === 'closed' ? html`<span class="chip">CLOSED</span>` : ''}</div>
        <h1 ${w ? raw('data-a="editFact" data-k="title"') : ''} title="${w ? 'Click to rename' : ''}">${inc.title}</h1>
        <div class="small muted">Lead ${userName(inc.leadId)} · Detected ${fmtUTC(inc.detectedAt)} · Updated ${ago(inc.updatedAt)}</div>
      </div>
      <div class="big-clock">${since(inc.detectedAt, inc.closedAt)}<div class="small muted">${inc.closedAt ? 'total duration' : 'since detection'}</div></div>
    </div>
    <div class="phases">${S.phases.slice(0, 5).map((p, i) => html`<button type="button" class="phase ${i < idx || inc.status === 'closed' ? 'done' : i === idx ? 'cur' : ''}" ${w ? raw(`data-a="setPhase" data-phase="${p.id}"`) : ''} title="${p.hint}">
      <div class="n">${i < idx || inc.status === 'closed' ? '✓ ' : ''}STEP ${i + 1}</div><div class="t">${p.label}</div><div class="h">${p.hint}</div></button>`)}
      ${can('incident.manage') ? (inc.status === 'closed' ? html`<button type="button" class="btn" data-a="setPhase" data-phase="post">Reopen</button>` : html`<button type="button" class="btn" data-a="setPhase" data-phase="closed">${icon('check')} Close</button>`) : ''}
    </div>
    ${w && inc.status !== 'closed' ? html`<form class="scribe" data-submit="scribe" data-id="${inc.id}">
      <div class="kinds">${['note', 'action', 'finding', 'decision', 'comms'].map((k) => html`<button type="button" class="k-${k} ${S.scribeKind === k ? 'on' : ''}" data-a="scribeKind" data-k="${k}">${k[0].toUpperCase() + k.slice(1)}</button>`)}</div>
      <input type="text" id="scribe-text" data-keep autocomplete="off" maxlength="4000" placeholder="What just happened? Type and press Enter. It is timestamped for you.">
      <input type="datetime-local" id="scribe-at" data-keep class="${UI.backdate ? '' : 'hidden'}" title="When it happened (local time)">
      <button type="button" class="iconbtn" data-a="backdate" title="Log at a different time">${icon('clock')}</button>
      <button class="btn primary sm">Log</button>
    </form>` : ''}
    <nav class="tabs" id="inc-tabs">${tabsHTML(inc, tab)}</nav>
    <div id="tab-body">${body(inc)}</div>`;
}

A.scribeKind = (t) => { S.scribeKind = t.dataset.k; $$('.scribe .kinds button').forEach((b) => b.classList.toggle('on', b === t)); $('#scribe-text').focus(); };
A.backdate = () => { UI.backdate = !UI.backdate; const el = $('#scribe-at'); el.classList.toggle('hidden', !UI.backdate); if (UI.backdate) { el.value = toLocalInput(); el.focus(); } };
A.scribe = async (f) => {
  const input = $('#scribe-text');
  const text = input.value.trim();
  if (!text) return;
  const at = UI.backdate ? fromLocalInput($('#scribe-at').value) : null;
  input.value = '';
  const r = await act(api('POST', `/api/incidents/${f.dataset.id}/timeline`, { text, kind: S.scribeKind, at }));
  if (!r) input.value = text; else { toast(`Logged at ${fmtTimeUTC(r.at)}`, 'ok'); await reloadInc(f.dataset.id); }
  input.focus();
};

async function reloadInc(id) {
  const inc = await api('GET', '/api/incidents/' + id).catch(() => null);
  if (inc) { S.inc.set(id, inc); refresh('incident', id); }
  return inc;
}
async function patchInc(id, body, msg = 'Saved') {
  const r = await act(api('PATCH', '/api/incidents/' + id, body), msg);
  if (r) { S.inc.set(r.id, r); refresh('incident', r.id); }
  return r;
}
const curInc = () => S.inc.get(current?.incId);

A.setPhase = async (t) => {
  const inc = curInc();
  const to = t.dataset.phase;
  if (to === inc.status) return;
  if (to === 'closed') {
    const open = live(inc.tasks).filter((x) => x.status !== 'done').length;
    const ob = openObligations(inc).filter((o) => o.level === 'required').length;
    if (!(await confirmBox('Close this incident?', `${open} tasks are still open and ${ob} required notifications are not marked done. Closing keeps everything on record (legal hold) and can be undone.`, 'Close incident', true))) return;
  }
  patchInc(inc.id, { status: to }, `Phase: ${phaseById(to).label}`);
};

// ---------- overview
const FACTS = {
  title: { t: 'Rename incident', type: 'text' },
  summary: { t: 'Situation summary', type: 'textarea', hint: 'Plain language: what happened, what is affected, what we are doing.' },
  category: { t: 'Incident type', type: 'select', opts: () => Object.entries(S.categories) },
  severity: { t: 'Severity', type: 'select', opts: () => [1, 2, 3, 4].map((s) => [String(s), `SEV${s} · ${SEV_TEXT[s]}: ${SEV_DESC[s]}`]), parse: Number },
  detectedAt: { t: 'When was it discovered?', type: 'datetime', hint: 'Most legal clocks start here.' },
  occurredAt: { t: 'When did the attacker first get in?', type: 'datetime', clear: true, hint: 'Best estimate. Update as forensics learns more.' },
  containedAt: { t: 'When was it contained?', type: 'datetime', clear: true },
  breachDeterminedAt: { t: 'Breach determination', type: 'datetime', clear: true, hint: 'When counsel determined a reportable breach occurred. Many state-law clocks run from this moment.' },
  materialityDeterminedAt: { t: 'Materiality determination (SEC)', type: 'datetime', clear: true, hint: 'Form 8-K Item 1.05 is due 4 business days after this.' },
  attackVector: { t: 'How did they get in?', type: 'text', hint: 'e.g. Phishing email → stolen VPN credentials (no MFA)' },
  affectedSystems: { t: 'Affected systems', type: 'textarea', hint: 'One per line', get: (i) => i.affectedSystems.join('\n'), parse: (v) => v.split(/\n|,/).map((s) => s.trim()).filter(Boolean) },
  leadId: { t: 'Incident lead', type: 'select', opts: () => S.users.filter((u) => u.status === 'active').map((u) => [u.id, `${u.displayName} (${S.roles[u.role]})`]) },
  privileged: { t: 'Privilege marking', type: 'select', opts: () => [['true', 'Privileged & Confidential (direction of counsel)'], ['false', 'Not privileged']], get: (i) => String(i.privileged), parse: (v) => v === 'true' },
};
A.editFact = async (t) => {
  const inc = curInc();
  const k = t.dataset.k;
  const f = FACTS[k];
  const v = await ask(f.t, { type: f.type, value: f.get ? f.get(inc) : f.type === 'select' ? String(inc[k] ?? '') : inc[k] || '', options: f.opts ? f.opts() : [], hint: f.hint, allowClear: f.clear });
  if (v === undefined) return;
  patchInc(inc.id, { [k]: f.parse ? f.parse(v ?? '') : v });
};

function tabOverview(inc) {
  const w = can('incident.write');
  const L = can('legal.write');
  const phase = phaseById(inc.status);
  const nextIdx = phaseIndex(inc.status) + 1;
  const nextPhase = S.phases[nextIdx];
  const phaseTasks = live(inc.tasks).filter((t) => t.phase === inc.status && t.status !== 'done');
  const scope = live(inc.scope);
  const byStatus = {};
  for (const s of scope) byStatus[s.status] = (byStatus[s.status] || 0) + (s.records || 0);
  const ob = openObligations(inc).filter((o) => o.dueAt).slice(0, 4);
  const fact = (k, label, val, editable = w) => html`<dt>${label}</dt><dd>${editable ? html`<span class="editable" data-a="editFact" data-k="${k}">${val || html`<span class="dim">Not set (click to add)</span>`}</span>` : val || html`<span class="dim">-</span>`}</dd>`;
  return html`
    ${inc.status !== 'closed' ? html`<div class="next-up">
      <h3>Next up · ${phase.label}: ${phase.hint}</h3>
      ${phaseTasks.length ? phaseTasks.slice(0, 4).map((t) => taskRow(inc, t, true)) : html`<p class="muted small">Checklist for this phase is complete.</p>`}
      <div class="row wrap"><a class="btn sm ghost" href="#/i/${inc.id}/tasks">See full checklist ${icon('arrow')}</a><span class="grow"></span>
      ${w && nextPhase && nextPhase.id !== 'closed' ? html`<button class="btn sm ${phaseTasks.length ? '' : 'primary'}" data-a="setPhase" data-phase="${nextPhase.id}">Move to ${nextPhase.label} ${icon('arrow')}</button>` : ''}</div>
    </div>` : ''}
    <div class="grid g-main">
      <div class="col">
        <section class="panel"><div class="panel-head"><h3>${icon('file')} Situation</h3>${w ? html`<button class="btn sm ghost" data-a="editFact" data-k="summary">${icon('edit')} Edit</button>` : ''}</div>
          <div class="panel-body prewrap">${inc.summary || html`<span class="dim">No summary yet. Write 2-3 sentences anyone could understand: what happened, what's affected, what we're doing.</span>`}</div></section>
        <section class="panel"><div class="panel-head"><h3>${icon('list')} Key facts</h3><span class="tiny muted">Click any value to update</span></div>
          <div class="panel-body"><dl class="facts">
            ${fact('category', 'Type', S.categories[inc.category])}
            ${fact('severity', 'Severity', html`${sevChip(inc.severity, false)} ${SEV_TEXT[inc.severity]}`)}
            ${fact('detectedAt', 'Discovered', fmtUTC(inc.detectedAt))}
            ${fact('occurredAt', 'First attacker activity', inc.occurredAt && fmtUTC(inc.occurredAt))}
            ${fact('containedAt', 'Contained', inc.containedAt && fmtUTC(inc.containedAt))}
            ${fact('attackVector', 'Entry point', inc.attackVector)}
            ${fact('affectedSystems', 'Affected systems', inc.affectedSystems.length ? inc.affectedSystems.map((s) => html`<span class="chip">${s}</span> `) : '')}
            ${fact('leadId', 'Incident lead', userName(inc.leadId), w && can('incident.manage'))}
            ${fact('breachDeterminedAt', 'Breach determined', inc.breachDeterminedAt && fmtUTC(inc.breachDeterminedAt), L)}
            ${S.org.publiclyTraded ? fact('materialityDeterminedAt', 'Materiality determined', inc.materialityDeterminedAt && fmtUTC(inc.materialityDeterminedAt), L) : ''}
            ${fact('privileged', 'Privilege', inc.privileged ? 'Privileged & Confidential' : 'Not privileged', L)}
          </dl></div></section>
        <section class="panel"><div class="panel-head"><h3>${icon('clock')} Recent timeline</h3><a class="small" href="#/i/${inc.id}/timeline">Full timeline ${icon('arrow')}</a></div>
          <div class="panel-body tight">${live(inc.timeline).slice(-8).reverse().map((e) => html`<div class="list-item"><span class="mono tiny dim nowrap">${fmtUTC(e.at)}</span><span class="chip k-${e.kind}">${e.kind}</span><span class="grow small">${e.text}</span></div>`)}</div></section>
      </div>
      <div class="col">
        <section class="panel"><div class="panel-head"><h3>${icon('db')} Data compromised</h3><a class="small" href="#/i/${inc.id}/scope">Scope ${icon('arrow')}</a></div>
          <div class="panel-body">${scope.length ? html`<div class="col">${Object.entries(byStatus).sort((a, b) => b[1] - a[1]).map(([s, n]) => html`<div class="row between">${statusChip(s)}<b class="mono">${n.toLocaleString()} records</b></div>`)}
            <div class="tiny muted">${scope.length} data set${scope.length > 1 ? 's' : ''} tracked</div></div>` : html`<p class="muted small">No affected data recorded yet. ${w ? html`<a href="#/i/${inc.id}/scope">Add what you know</a>; "suspected" is fine.` : ''}</p>`}</div></section>
        <section class="panel"><div class="panel-head"><h3>${icon('scale')} Legal deadlines</h3><a class="small" href="#/i/${inc.id}/obligations">All ${icon('arrow')}</a></div>
          ${ob.length ? ob.map((o) => deadlineRow(o, inc)) : html`<div class="empty small">No timed obligations yet.</div>`}</section>
        <section class="panel"><div class="panel-head"><h3>${icon('users')} Who can see this</h3>${can('incident.manage') ? html`<button class="btn sm ghost" data-a="manageAccess">${icon('lock')} Manage</button>` : ''}</div>
          <div class="panel-body small">${inc.access === 'restricted' ? html`<p><b>Need-to-know.</b> Only these people (plus administrators):</p><div class="row wrap">${[...new Set([inc.leadId, inc.createdBy, ...(inc.members || [])])].map((id) => html`<span class="row">${avatar(id, true, true)} ${userName(id)}</span>`)}</div>` : html`<p class="muted">Everyone with a LIFEBOAT account can see this incident.</p>`}</div></section>
      </div>
    </div>`;
}

A.manageAccess = () => {
  const inc = curInc();
  const users = S.users.filter((u) => u.status === 'active');
  modal(html`<form id="acc-f">${mHead('Who can see this incident?', 'Restrict when the attacker could be an insider, or the matter is especially sensitive.')}
    <div class="modal-body">
      <label class="check"><input type="radio" name="access" value="all" ${inc.access !== 'restricted' ? raw('checked') : ''}><span><b>Everyone on LIFEBOAT</b></span></label>
      <label class="check"><input type="radio" name="access" value="restricted" ${inc.access === 'restricted' ? raw('checked') : ''}><span><b>Need-to-know only</b><br><span class="small muted">Only the people ticked below, the lead and administrators.</span></span></label>
      <div class="type-pick">${users.map((u) => html`<label class="check"><input type="checkbox" name="m" value="${u.id}" ${(inc.members || []).includes(u.id) ? raw('checked') : ''}> ${u.displayName}</label>`)}</div>
    </div><div class="modal-foot"><button class="btn" type="button" data-a="closeModal">Cancel</button><button class="btn primary">Save</button></div></form>`);
  $('#acc-f').onsubmit = async (e) => {
    e.preventDefault();
    const f = e.target;
    await patchInc(inc.id, { access: f.access.value, members: $$('input[name=m]:checked', f).map((x) => x.value) }, 'Access updated');
    closeModal();
  };
};

// ---------- timeline
function tabTimeline(inc) {
  const kinds = ['all', 'action', 'finding', 'decision', 'comms', 'note', 'system'];
  const items = inc.timeline.filter((e) => (UI.tlStruck || !e.deleted) && (UI.tlKind === 'all' || e.kind === UI.tlKind));
  return html`<div class="row between wrap"><div class="seg">${kinds.map((k) => html`<button type="button" class="${UI.tlKind === k ? 'on' : ''}" data-a="tlKind" data-k="${k}">${k}</button>`)}</div>
    <div class="row"><label class="row small muted"><input type="checkbox" data-change="tlStruck" ${UI.tlStruck ? raw('checked') : ''}> Show struck entries</label>
    <button class="btn sm" data-a="tlCsv">${icon('download')} CSV</button></div></div><br>
    <div class="panel tl">${items.length ? items.map((e) => html`<div class="tl-item ${e.deleted ? 'struck' : ''} k-${e.kind}-row">
      <div class="t">${fmtUTC(e.at, true)}<div class="tiny dim">${fmtLocal(e.at)} local</div></div>
      <div><span class="chip k-${e.kind}">${e.kind}</span> <span class="txt">${e.text}</span>
        <div class="tiny dim">${userName(e.by)}${e.loggedAt && Math.abs(new Date(e.loggedAt) - new Date(e.at)) > 120e3 ? ` · logged ${fmtUTC(e.loggedAt)}` : ''}${e.deleted ? ` · struck by ${userName(e.deleted.by)} ${fmtUTC(e.deleted.at)}` : ''}</div></div>
      <div>${!e.deleted && e.kind !== 'system' && can('incident.write') && (e.by === S.me.id || can('incident.manage')) ? html`<button class="iconbtn" data-a="strike" data-list="timeline" data-id="${e.id}" title="Strike (kept on record)">${icon('strike')}</button>` : ''}</div>
    </div>`) : html`<div class="empty">Nothing logged yet. Use the bar above: type what happened and press Enter.</div>`}</div>
    <p class="tiny dim">Times in UTC (forensic standard). Struck entries are never destroyed, only marked, to preserve the record under legal hold.</p>`;
}
A.tlKind = (t) => { UI.tlKind = t.dataset.k; refresh(); };
A.tlStruck = (t) => { UI.tlStruck = t.checked; refresh(); };
A.tlCsv = () => {
  const inc = curInc();
  downloadText(`${inc.ref}-timeline.csv`, toCsv([['time_utc', 'kind', 'entry', 'by', 'logged_utc', 'struck'], ...inc.timeline.map((e) => [e.at, e.kind, e.text, userName(e.by), e.loggedAt, e.deleted ? 'yes' : ''])]), 'text/csv');
};
A.strike = async (t) => {
  if (!(await confirmBox('Strike this entry?', 'It stays on record (crossed out) with your name and the time. Nothing is ever destroyed during an incident.', 'Strike', true))) return;
  const inc = curInc();
  if (await act(api('DELETE', `/api/incidents/${inc.id}/${t.dataset.list}/${t.dataset.id}`), 'Struck from record')) reloadInc(inc.id);
};

// ---------- scope
function tabScope(inc) {
  const w = can('incident.write');
  const rows = inc.scope.filter((s) => !s.deleted);
  const struck = inc.scope.filter((s) => s.deleted);
  const total = rows.reduce((a, s) => a + (s.records || 0), 0);
  const byStatus = {};
  for (const s of rows) { byStatus[s.status] ||= { n: 0, sets: 0 }; byStatus[s.status].n += s.records || 0; byStatus[s.status].sets++; }
  const residents = {};
  for (const s of rows) for (const [k, v] of Object.entries(s.residents || {})) residents[k] = (residents[k] || 0) + v;
  return html`
    <div class="page-head"><div><h2>What data is affected, and what state is it in?</h2><p class="small">Record each data set as you learn about it. "Suspected" is fine and can be updated later. Legal deadlines update automatically.</p></div>
      ${w ? html`<button class="btn primary" data-a="scopeAdd">${icon('plus')} Add affected data</button>` : ''}</div>
    ${rows.length ? html`<div class="scope-bars">
      <div class="scope-bar"><div class="n">${total.toLocaleString()}</div><div class="l muted">Total records</div></div>
      ${Object.keys(STATUS_LABEL).filter((s) => byStatus[s]).map((s) => html`<div class="scope-bar">${statusChip(s)}<div class="n">${byStatus[s].n.toLocaleString()}</div><div class="tiny muted">${byStatus[s].sets} data set${byStatus[s].sets > 1 ? 's' : ''}</div></div>`)}
    </div>
    ${Object.keys(residents).length ? html`<p class="small muted">Affected people by location: ${Object.entries(residents).sort((a, b) => b[1] - a[1]).map(([k, v]) => html`<span class="chip">${k} ${v.toLocaleString()}</span> `)}</p>` : ''}
    <div class="panel table-wrap"><table class="t"><thead><tr><th>Data set</th><th>Data types</th><th class="right">Records</th><th>People by location</th><th>Status</th><th>Confidence</th><th>Updated</th><th></th></tr></thead><tbody>
      ${rows.map((s) => html`<tr>
        <td><b>${s.asset}</b>${s.system ? html`<div class="tiny muted">${s.system}</div>` : ''}${s.notes ? html`<div class="tiny dim">${s.notes}</div>` : ''}</td>
        <td>${s.dataTypes.map((t) => html`<span class="chip" title="${S.dataTypes[t]}">${t.toUpperCase()}</span> `)}</td>
        <td class="right mono">${(s.records || 0).toLocaleString()}</td>
        <td class="small">${Object.entries(s.residents || {}).map(([k, v]) => `${k} ${v.toLocaleString()}`).join(' · ') || html`<span class="dim">-</span>`}</td>
        <td>${w ? html`<select class="small" data-change="scopeQuick" data-id="${s.id}" data-f="status">${Object.entries(STATUS_LABEL).map(([k, [l]]) => html`<option value="${k}" ${k === s.status ? raw('selected') : ''}>${l}</option>`)}</select>` : statusChip(s.status)}</td>
        <td>${w ? html`<select class="small" data-change="scopeQuick" data-id="${s.id}" data-f="confidence">${['confirmed', 'suspected', 'ruled-out'].map((k) => html`<option value="${k}" ${k === s.confidence ? raw('selected') : ''}>${k}</option>`)}</select>` : s.confidence}</td>
        <td class="tiny muted nowrap">${userName(s.updatedBy)}<br>${ago(s.updatedAt)}${s.history?.length > 1 ? html`<br><span title="${s.history.map((h) => `${fmtUTC(h.at)} ${h.status}/${h.confidence} by ${userName(h.by)}`).join('\n')}">${s.history.length} changes</span>` : ''}</td>
        <td class="nowrap">${w ? html`<button class="iconbtn" data-a="scopeEdit" data-id="${s.id}" title="Edit">${icon('edit')}</button><button class="iconbtn" data-a="strike" data-list="scope" data-id="${s.id}" title="Strike">${icon('strike')}</button>` : ''}</td>
      </tr>`)}</tbody></table></div>
    ${struck.length ? html`<p class="tiny dim">${struck.length} struck data set(s) retained on record.</p>` : ''}` : html`<div class="panel empty">${icon('db')}<h3>No affected data recorded yet</h3><p>Start with what you suspect, e.g. "File server: client folders, status At risk, suspected."</p>${w ? html`<button class="btn primary" data-a="scopeAdd">${icon('plus')} Add affected data</button>` : ''}</div>`}`;
}

function parseResidents(text) {
  const out = {};
  const re = /([A-Za-z]{2,4})\s*[:=\s]\s*([\d,._]+)/g;
  let m;
  while ((m = re.exec(text))) out[m[1].toUpperCase()] = Number(m[2].replace(/[,._]/g, ''));
  return out;
}
function scopeModal(inc, row) {
  const r = row || { asset: '', system: '', dataTypes: [], records: 0, residents: {}, status: 'at-risk', confidence: 'suspected', notes: '' };
  modal(html`<form id="scope-f">${mHead(row ? 'Update affected data' : 'Add affected data', 'Describe one data set: a database, a file share, a mailbox, a system.')}
    <div class="modal-body">
      <div class="form-grid">
        <label class="field">What data? <input name="asset" required maxlength="200" value="${r.asset}" placeholder="e.g. Client billing database"></label>
        <label class="field">Where does it live? <input name="system" maxlength="200" value="${r.system}" placeholder="e.g. FS01 \\\\finance share, SQL-PRD-02"></label>
      </div>
      <div class="field"><span>What state is it in?</span><input type="hidden" name="status" value="${r.status}">
        <div class="pick-grid">${Object.entries(STATUS_LABEL).map(([k, [l, d]]) => html`<button type="button" class="pick ${k === r.status ? 'on' : ''}" data-a="pick" data-group="status" data-v="${k}">${statusChip(k)}<small>${d}</small></button>`)}</div></div>
      <div class="field"><span>How sure are we?</span><input type="hidden" name="confidence" value="${r.confidence}">
        <div class="seg">${[['confirmed', 'Confirmed'], ['suspected', 'Suspected'], ['ruled-out', 'Ruled out']].map(([k, l]) => html`<button type="button" class="${k === r.confidence ? 'on' : ''}" data-a="pickSeg" data-group="confidence" data-v="${k}">${l}</button>`)}</div></div>
      <div class="field"><span>What kinds of information? <span class="hint">Tick all that apply</span></span>
        <div class="type-pick">${Object.entries(S.dataTypes).map(([k, l]) => html`<label class="check"><input type="checkbox" name="dt" value="${k}" ${r.dataTypes.includes(k) ? raw('checked') : ''}> ${l}</label>`)}</div></div>
      <div class="form-grid">
        <label class="field">Number of records / people <input type="number" name="records" min="0" value="${r.records || ''}" placeholder="0"></label>
        <label class="field">Where do the affected people live? <span class="hint">e.g. TX:1200, CA:340, EU:25 (state codes, EU, UK)</span>
          <input name="residents" value="${Object.entries(r.residents || {}).map(([k, v]) => `${k}:${v}`).join(', ')}" placeholder="TX:1200, CA:340"></label>
        <label class="field full">Notes <textarea name="notes" rows="2" maxlength="2000">${r.notes || ''}</textarea></label>
      </div>
    </div>
    <div class="modal-foot"><button class="btn" type="button" data-a="closeModal">Cancel</button><button class="btn primary">${row ? 'Save changes' : 'Add to scope'}</button></div></form>`, { wide: true });
  $('#scope-f').onsubmit = async (e) => {
    e.preventDefault();
    const f = e.target;
    const before = new Set(inc.obligations.map((o) => o.id));
    const body = {
      asset: f.asset.value, system: f.system.value, status: f.status.value, confidence: f.confidence.value,
      dataTypes: $$('input[name=dt]:checked', f).map((x) => x.value), records: Number(f.records.value || 0), residents: parseResidents(f.residents.value), notes: f.notes.value,
    };
    const res = await act(api(row ? 'PATCH' : 'POST', `/api/incidents/${inc.id}/scope${row ? '/' + row.id : ''}`, body), row ? 'Scope updated' : 'Added to scope');
    if (!res) return;
    closeModal();
    const fresh = await reloadInc(inc.id);
    const added = fresh ? fresh.obligations.filter((o) => !before.has(o.id)) : [];
    if (added.length) toast(`⚖ ${added.length} new notification obligation${added.length > 1 ? 's' : ''} triggered: ${added.map((o) => o.title).join('; ')}. Click to review.`, 'urgent', () => (location.hash = `#/i/${inc.id}/obligations`));
  };
}
A.pickSeg = (t) => { const g = t.dataset.group; $$(`[data-group="${g}"]`).forEach((x) => x.classList.toggle('on', x === t)); const i = $(`input[name="${g}"]`, t.closest('form')); if (i) i.value = t.dataset.v; };
A.scopeAdd = () => scopeModal(curInc());
A.scopeEdit = (t) => { const inc = curInc(); scopeModal(inc, inc.scope.find((s) => s.id === t.dataset.id)); };
A.scopeQuick = async (t) => {
  const inc = curInc();
  const before = new Set(inc.obligations.map((o) => o.id));
  if (await act(api('PATCH', `/api/incidents/${inc.id}/scope/${t.dataset.id}`, { [t.dataset.f]: t.value }), 'Scope updated')) {
    const fresh = await reloadInc(inc.id);
    const added = fresh ? fresh.obligations.filter((o) => !before.has(o.id)) : [];
    if (added.length) toast(`⚖ New obligation triggered: ${added.map((o) => o.title).join('; ')}`, 'urgent', () => (location.hash = `#/i/${inc.id}/obligations`));
  }
};

// ---------- tasks
function taskRow(inc, t, compact = false) {
  const w = can('incident.write');
  const users = S.users.filter((u) => u.status === 'active');
  return html`<div class="task ${t.status === 'done' ? 'done' : ''}">
    <input type="checkbox" ${t.status === 'done' ? raw('checked') : ''} ${w ? '' : raw('disabled')} data-change="taskDone" data-id="${t.id}" title="Mark done">
    <span class="title">${t.title}${t.status === 'blocked' ? html` <span class="chip st st-encrypted">BLOCKED</span>` : t.status === 'doing' ? html` <span class="chip k-comms">IN PROGRESS</span>` : ''}
      ${t.status === 'done' ? html`<div class="tiny dim">Done by ${userName(t.doneBy)} ${ago(t.doneAt)}</div>` : ''}</span>
    ${t.due && t.status !== 'done' ? countdown(t.due) : ''}
    ${!compact && w && t.status !== 'done' ? html`<select data-change="taskStatus" data-id="${t.id}" title="Status"><option value="open" ${t.status === 'open' ? raw('selected') : ''}>To do</option><option value="doing" ${t.status === 'doing' ? raw('selected') : ''}>In progress</option><option value="blocked" ${t.status === 'blocked' ? raw('selected') : ''}>Blocked</option></select>` : ''}
    ${w ? html`<select data-change="taskAssign" data-id="${t.id}" title="Assign"><option value="">Unassigned</option>${users.map((u) => html`<option value="${u.id}" ${u.id === t.assigneeId ? raw('selected') : ''}>${u.displayName}</option>`)}</select>` : t.assigneeId ? avatar(t.assigneeId, true) : ''}
    ${!compact && w ? html`<button class="iconbtn" data-a="strike" data-list="tasks" data-id="${t.id}" title="Remove (kept on record)">${icon('strike')}</button>` : ''}
  </div>`;
}
function tabTasks(inc) {
  const w = can('incident.write');
  const tasks = live(inc.tasks).filter((t) => !UI.taskMine || t.assigneeId === S.me.id);
  return html`
    ${w ? html`<form class="panel panel-body row wrap" data-submit="addTask" data-id="${inc.id}">
      <input id="task-new" data-keep class="grow" placeholder="Add a task… e.g. Pull firewall logs for 10.0.4.0/24" maxlength="300" required>
      <select name="phase" id="task-phase" data-keep>${S.phases.slice(0, 5).map((p) => html`<option value="${p.id}" ${p.id === inc.status ? raw('selected') : ''}>${p.label}</option>`)}</select>
      <select name="assigneeId" id="task-who" data-keep><option value="">Unassigned</option>${S.users.filter((u) => u.status === 'active').map((u) => html`<option value="${u.id}">${u.displayName}</option>`)}</select>
      <button class="btn primary">${icon('plus')} Add</button></form><br>` : ''}
    <div class="row between"><p class="small muted">Checklist loaded from the <b>${S.categories[inc.category]}</b> playbook. Tick items off as you go.</p>
      <label class="row small muted"><input type="checkbox" data-change="taskMine" ${UI.taskMine ? raw('checked') : ''}> Only my tasks</label></div>
    <div class="col">${S.phases.slice(0, 5).map((p) => {
      const list = tasks.filter((t) => t.phase === p.id);
      if (!list.length) return '';
      const done = list.filter((t) => t.status === 'done').length;
      return html`<section class="panel phase-group ${p.id === inc.status ? 'cur' : ''}"><h4><span>${p.label}${p.id === inc.status ? ' · current phase' : ''}</span><span>${done}/${list.length}</span></h4>${list.map((t) => taskRow(inc, t))}</section>`;
    })}</div>`;
}
A.addTask = async (f) => {
  const input = $('#task-new');
  const r = await act(api('POST', `/api/incidents/${f.dataset.id}/tasks`, { title: input.value, phase: f.phase.value, assigneeId: f.assigneeId.value || null }), 'Task added');
  if (r) { input.value = ''; reloadInc(f.dataset.id); }
};
A.taskMine = (t) => { UI.taskMine = t.checked; refresh(); };
async function patchTask(id, body, msg) { const inc = curInc(); if (await act(api('PATCH', `/api/incidents/${inc.id}/tasks/${id}`, body), msg)) reloadInc(inc.id); }
A.taskDone = (t) => patchTask(t.dataset.id, { status: t.checked ? 'done' : 'open' }, t.checked ? 'Done ✓' : 'Reopened');
A.taskStatus = (t) => patchTask(t.dataset.id, { status: t.value }, 'Updated');
A.taskAssign = (t) => patchTask(t.dataset.id, { assigneeId: t.value || null }, t.value ? `Assigned to ${userName(t.value)}` : 'Unassigned');

// ---------- legal obligations
function tabObligations(inc) {
  const L = can('legal.write');
  const obs = inc.obligations;
  const hasScope = live(inc.scope).length > 0;
  return html`
    <div class="grid g2">
      <section class="panel"><div class="panel-head"><h3>${icon('scale')} Legal determinations</h3></div><div class="panel-body"><dl class="facts">
        <dt>Discovered</dt><dd class="mono">${fmtUTC(inc.detectedAt)}</dd>
        <dt>Breach determined</dt><dd>${L ? html`<span class="editable" data-a="editFact" data-k="breachDeterminedAt">${inc.breachDeterminedAt ? fmtUTC(inc.breachDeterminedAt) : 'Not yet. Click to record'}</span>` : fmtUTC(inc.breachDeterminedAt)}<div class="tiny dim">State-law clocks run from here once set (until then, from discovery).</div></dd>
        ${S.org.publiclyTraded ? html`<dt>Materiality (SEC)</dt><dd>${L ? html`<span class="editable" data-a="editFact" data-k="materialityDeterminedAt">${inc.materialityDeterminedAt ? fmtUTC(inc.materialityDeterminedAt) : 'Not yet. Click to record'}</span>` : fmtUTC(inc.materialityDeterminedAt)}<div class="tiny dim">8-K due 4 business days after.</div></dd>` : ''}
      </dl></div></section>
      <section class="panel"><div class="panel-head"><h3>${icon('shield')} Why these appear</h3></div><div class="panel-body small muted">
        LIFEBOAT reads the <b>Scope</b> tab (data types and where people live), the incident type, and your organization profile
        (${[S.org.publiclyTraded && 'public company', S.org.hipaaCovered && 'HIPAA', S.org.nydfsRegulated && 'NYDFS', S.org.criticalInfrastructure && 'critical infrastructure'].filter(Boolean).join(', ') || 'no special regulators set'}).
        It then lists who must be told, and by when. ${!hasScope ? html`<br><br><b class="cd soon">Add affected data in Scope to unlock state, GDPR and HIPAA deadlines.</b>` : ''}</div></section>
    </div><br>
    <section class="panel">${obs.map((o) => { const done = o.status === 'done' || o.status === 'na'; return html`<div class="ob ${done ? 'done' : ''}">
      <div><div class="row wrap"><b>${o.title}</b><span class="chip lvl-${o.level}">${o.level}</span></div>
        <div class="who">${o.who}</div><div class="cite">${o.cite}</div><div class="why">${o.why}</div>
        ${o.notes ? html`<div class="small prewrap">📝 ${o.notes}</div>` : ''}
        ${L ? html`<div class="row wrap"><div class="seg">${[['pending', 'Pending'], ['in-progress', 'In progress'], ['done', 'Done'], ['na', 'Not applicable']].map(([k, l]) => html`<button type="button" class="${o.status === k ? 'on ' + k : ''}" data-a="obStatus" data-ob="${o.id}" data-s="${k}">${l}</button>`)}</div>
          <button class="btn sm ghost" data-a="obNotes" data-ob="${o.id}">${icon('edit')} Notes</button>${o.updatedBy ? html`<span class="tiny dim">${userName(o.updatedBy)} · ${ago(o.updatedAt)}</span>` : ''}</div>` : html`<div class="tiny muted">Status: ${o.status}</div>`}
      </div>
      <div class="right">${o.dueAt ? html`<div class="h2">${countdown(o.dueAt, done)}</div><div class="tiny dim mono">${fmtUTC(o.dueAt)}</div>` : html`<div class="small muted">${o.dueText || ''}</div>`}</div>
    </div>`; })}
    <div class="disclaimer">Decision support, not legal advice. Deadlines use the statutes as preloaded; confirm every obligation with counsel, check holidays and regulator-specific rules, and watch for statutory changes.</div></section>`;
}
A.obStatus = async (t) => {
  const inc = curInc();
  if (await act(api('PATCH', `/api/incidents/${inc.id}/obligations/${t.dataset.ob}`, { status: t.dataset.s }), 'Obligation updated')) reloadInc(inc.id);
};
A.obNotes = async (t) => {
  const inc = curInc();
  const o = inc.obligations.find((x) => x.id === t.dataset.ob);
  const v = await ask('Notes: ' + o.title, { type: 'textarea', value: o.notes || '', hint: 'e.g. Filed via portal, confirmation #, who approved the notice.' });
  if (v === undefined) return;
  if (await act(api('PATCH', `/api/incidents/${inc.id}/obligations/${o.id}`, { notes: v }), 'Saved')) reloadInc(inc.id);
};

// ---------- IOCs
const refang = (s) => s.replace(/hxxp/gi, 'http').replace(/\[\.\]|\(\.\)|\{\.\}/g, '.').replace(/\[@\]|\[at\]/gi, '@').replace(/\[:\]/g, ':');
const defang = (s) => s.replace(/^http/i, 'hxxp').replace(/\./g, '[.]');
function tabIocs(inc) {
  const w = can('incident.write');
  const iocs = live(inc.iocs);
  const groups = {};
  for (const i of iocs) (groups[i.type] ||= []).push(i);
  return html`
    ${w ? html`<form class="panel panel-body col" data-submit="addIocs" data-id="${inc.id}">
      <label class="field">Paste indicators <span class="hint">IPs, domains, URLs, hashes, emails, account names, one per line or comma-separated. Defanged values like hxxp://bad[.]com are fixed automatically.</span>
        <textarea id="ioc-bulk" data-keep rows="3" class="mono" placeholder="185.220.101.4&#10;update-office365[.]com&#10;e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"></textarea></label>
      <div class="row"><input id="ioc-note" data-keep placeholder="Note (optional), e.g. C2 seen in EDR alert" class="grow"><button class="btn primary">${icon('plus')} Add indicators</button></div>
    </form><br>` : ''}
    ${iocs.length ? html`<div class="row wrap">
      <button class="btn sm" data-a="iocCopy" data-mode="block">${icon('copy')} Copy blocklist (IPs + domains)</button>
      <button class="btn sm" data-a="iocCopy" data-mode="defang">${icon('copy')} Copy all, defanged (safe for email)</button>
      <button class="btn sm" data-a="iocCsv">${icon('download')} CSV</button></div><br>
    <div class="grid g2">${Object.entries(groups).map(([type, list]) => html`<section class="panel"><div class="panel-head"><h3>${type.toUpperCase()} <span class="badge">${list.length}</span></h3></div>
      ${list.map((i) => html`<div class="list-item"><span class="grow"><span class="mono small">${i.value}</span>${i.note ? html`<div class="tiny muted">${i.note}</div>` : ''}<div class="tiny dim">${userName(i.by)} · ${fmtUTC(i.at)}</div></span>
        <button class="iconbtn" data-a="copyVal" data-v="${i.value}" title="Copy">${icon('copy')}</button>${w ? html`<button class="iconbtn" data-a="strike" data-list="iocs" data-id="${i.id}" title="Strike">${icon('strike')}</button>` : ''}</div>`)}</section>`)}</div>` : html`<div class="panel empty">${icon('target')}<h3>No indicators yet</h3><p>Indicators of compromise are the attacker's fingerprints. Share them with IT, your EDR vendor and the FBI.</p></div>`}`;
}
A.addIocs = async (f) => {
  const values = refang($('#ioc-bulk').value).split(/[\n,;\s]+/).map((s) => s.trim()).filter(Boolean);
  if (!values.length) return toast('Paste at least one indicator', 'err');
  const r = await act(api('POST', `/api/incidents/${f.dataset.id}/iocs`, { values, note: $('#ioc-note').value }));
  if (r) { toast(`${r.added} indicator(s) added${values.length > r.added ? `, ${values.length - r.added} duplicates skipped` : ''}`, 'ok'); $('#ioc-bulk').value = ''; $('#ioc-note').value = ''; reloadInc(f.dataset.id); }
};
A.iocCopy = (t) => {
  const iocs = live(curInc().iocs);
  if (t.dataset.mode === 'block') copyText(iocs.filter((i) => i.type === 'ip' || i.type === 'domain').map((i) => i.value).join('\n'), 'Blocklist copied');
  else copyText(iocs.map((i) => `${i.type}\t${defang(i.value)}`).join('\n'), 'Defanged list copied');
};
A.iocCsv = () => { const inc = curInc(); downloadText(`${inc.ref}-iocs.csv`, toCsv([['type', 'value', 'note', 'added_by', 'added_utc'], ...live(inc.iocs).map((i) => [i.type, i.value, i.note, userName(i.by), i.at])]), 'text/csv'); };
A.copyVal = (t) => copyText(t.dataset.v);

// ---------- evidence
function tabEvidence(inc) {
  const w = can('incident.write');
  return html`
    ${w ? html`<div class="grid g2">
      <div class="drop" data-a="pickFile" data-drop="${inc.id}">${icon('upload')}<h3>Drop files here, or click to choose</h3><p class="small">Logs, screenshots, ransom notes, exports. Up to 50 MB each.<br>Each file is SHA-256 hashed on receipt and stored encrypted.</p></div>
      <div class="panel panel-body col"><label class="field">Note for the next upload <span class="hint">Where it came from, who collected it</span><input id="ev-note" data-keep placeholder="e.g. Exported from EDR console by J. Ruiz"></label>
        <button class="btn" data-a="evItem">${icon('box')} Log a physical item (laptop, drive, phone)</button>
        <input type="file" id="ev-file" class="hidden" multiple data-change="evFiles"></div>
    </div><br>` : ''}
    ${inc.evidence.length ? html`<div class="panel table-wrap"><table class="t"><thead><tr><th>Item</th><th>SHA-256</th><th>Collected</th><th>Chain of custody</th><th></th></tr></thead><tbody>
      ${inc.evidence.map((e) => html`<tr>
        <td><b>${e.name}</b><div class="tiny muted">${e.kind === 'file' ? `${(e.size / 1024).toFixed(e.size > 1e6 ? 0 : 1)} KB · encrypted locker` : e.location || 'Physical item'}</div>${e.note ? html`<div class="tiny dim">${e.note}</div>` : ''}</td>
        <td>${e.sha256 ? html`<span class="hash" title="${e.sha256}">${e.sha256.slice(0, 20)}…</span> <button class="iconbtn" data-a="copyVal" data-v="${e.sha256}" title="Copy full hash">${icon('copy')}</button>` : html`<span class="dim">-</span>`}</td>
        <td class="small nowrap">${userName(e.collectedBy)}<div class="tiny dim mono">${fmtUTC(e.collectedAt)}</div></td>
        <td class="small"><details id="cust-${e.id}"><summary>${e.custody.length} entr${e.custody.length > 1 ? 'ies' : 'y'} · last: ${e.custody[e.custody.length - 1].action.slice(0, 40)}</summary>
          <ul class="custody">${e.custody.map((c) => html`<li><span class="mono tiny">${fmtUTC(c.at)}</span> · <b>${userName(c.by)}</b> · ${c.action}</li>`)}</ul></details></td>
        <td class="nowrap">${e.kind === 'file' ? html`<a class="btn sm" href="/api/incidents/${inc.id}/evidence/${e.id}/file" download title="Export a copy (logged and integrity-checked)">${icon('download')}</a>` : ''}
          ${w ? html`<button class="btn sm" data-a="custody" data-id="${e.id}" title="Record a transfer">${icon('users')} Transfer</button>` : ''}</td></tr>`)}
    </tbody></table></div>` : html`<div class="panel empty">${icon('box')}<h3>Evidence locker is empty</h3><p>Preserve before you wipe. Every item gets a hash and a chain-of-custody record that will hold up later.</p></div>`}`;
}
A.pickFile = () => $('#ev-file')?.click();
A.evFiles = (t) => { uploadFiles([...t.files], curInc().id); t.value = ''; };
async function uploadFiles(files, incId) {
  const note = $('#ev-note')?.value || '';
  for (const f of files) {
    if (f.size > 50 * 1024 * 1024) { toast(`${f.name} is over 50 MB. Log it as a physical item and store it on encrypted media.`, 'err'); continue; }
    toast(`Uploading ${f.name}…`);
    const r = await act(api('POST', `/api/incidents/${incId}/evidence`, f, { headers: { 'X-Filename': encodeURIComponent(f.name), 'X-Note': encodeURIComponent(note) } }));
    if (r) toast(`${f.name} secured. SHA-256 ${r.sha256.slice(0, 16)}…`, 'ok');
  }
  if ($('#ev-note')) $('#ev-note').value = '';
  reloadInc(incId);
}
document.addEventListener('dragover', (e) => { const d = e.target.closest?.('[data-drop]'); if (d) { e.preventDefault(); d.classList.add('over'); } });
document.addEventListener('dragleave', (e) => { const d = e.target.closest?.('[data-drop]'); if (d) d.classList.remove('over'); });
document.addEventListener('drop', (e) => { const d = e.target.closest?.('[data-drop]'); if (d) { e.preventDefault(); d.classList.remove('over'); uploadFiles([...e.dataTransfer.files], d.dataset.drop); } });
A.evItem = () => {
  const inc = curInc();
  modal(html`<form id="evi-f">${mHead('Log a physical item', 'Record seized or preserved hardware so its custody can be tracked.')}
    <div class="modal-body"><label class="field">Item <input name="name" required placeholder="e.g. Dell Latitude 7440, S/N 7XK2L93 (CFO laptop)"></label>
    <label class="field">Where is it now? <input name="location" placeholder="e.g. Evidence safe, 4th floor, bag #0012"></label>
    <label class="field">Image hash (if imaged) <input name="sha256" class="mono" placeholder="SHA-256 of forensic image"></label>
    <label class="field">Notes <textarea name="note" rows="2"></textarea></label></div>
    <div class="modal-foot"><button class="btn" type="button" data-a="closeModal">Cancel</button><button class="btn primary">Log item</button></div></form>`);
  $('#evi-f').onsubmit = async (e) => {
    e.preventDefault();
    if (await act(api('POST', `/api/incidents/${inc.id}/evidence`, formData(e.target)), 'Item logged into custody')) { closeModal(); reloadInc(inc.id); }
  };
};
A.custody = async (t) => {
  const inc = curInc();
  const v = await ask('Record custody transfer', { label: 'What happened?', hint: 'e.g. Handed to DFIR examiner A. Patel (Mandiant), FedEx tracking 7712…', okLabel: 'Record' });
  if (!v) return;
  if (await act(api('POST', `/api/incidents/${inc.id}/evidence/${t.dataset.id}/custody`, { action: v }), 'Custody updated')) reloadInc(inc.id);
};

// ---------- room
function tabRoom(inc) {
  const ch = S.channels.find((c) => c.incidentId === inc.id);
  return ch ? html`<div class="comms embedded">${chatPane(ch)}</div>` : html`<div class="empty">No room for this incident.</div>`;
}

// ---------- report & SITREP
function sitrep(inc) {
  const scope = live(inc.scope);
  const total = scope.reduce((a, s) => a + (s.records || 0), 0);
  const st = {};
  for (const s of scope) st[s.status] = (st[s.status] || 0) + 1;
  const obs = openObligations(inc).filter((o) => o.dueAt).slice(0, 4);
  const open = live(inc.tasks).filter((t) => t.status !== 'done');
  const recent = live(inc.timeline).filter((e) => e.kind !== 'system' && nowMs() - new Date(e.at).getTime() < 12 * 36e5).slice(-6);
  const next = open.filter((t) => t.phase === inc.status).slice(0, 3);
  return [
    `SITREP: ${inc.ref} "${inc.codename}" · ${fmtUTC(new Date(nowMs()).toISOString())}`,
    `Severity SEV${inc.severity} (${SEV_TEXT[inc.severity]}) · Phase: ${phaseById(inc.status).label} · T+ ${elapsed(nowMs() - new Date(inc.detectedAt).getTime())}`,
    '',
    `SITUATION: ${inc.summary ? inc.summary.slice(0, 400) : inc.title}`,
    `SCOPE: ${scope.length} data set(s), ${total.toLocaleString()} records${Object.keys(st).length ? ' (' + Object.entries(st).map(([k, v]) => `${STATUS_LABEL[k][0]} ${v}`).join(', ') + ')' : ''}`,
    `DEADLINES:${obs.length ? '' : ' none running'}`,
    ...obs.map((o) => `  - ${o.title}: ${cdState(o.dueAt).text} (${fmtUTC(o.dueAt)})`),
    `TASKS: ${open.length} open${open.filter((t) => t.status === 'blocked').length ? `, ${open.filter((t) => t.status === 'blocked').length} BLOCKED` : ''}`,
    ...(recent.length ? ['LAST 12H:', ...recent.map((e) => `  - ${fmtTimeUTC(e.at)} [${e.kind}] ${e.text}`)] : []),
    ...(next.length ? ['NEXT:', ...next.map((t) => `  - ${t.title}${t.assigneeId ? ` (${userName(t.assigneeId)})` : ''}`)] : []),
  ].join('\n');
}
function tabReport(inc) {
  const scope = live(inc.scope);
  const tl = live(inc.timeline);
  const tasks = live(inc.tasks);
  return html`
    <div class="row wrap no-print">
      <button class="btn primary" data-a="print">${icon('printer')} Print / Save as PDF</button>
      <button class="btn" data-a="sitrepCopy">${icon('copy')} Copy SITREP</button>
      <button class="btn" data-a="sitrepPost">${icon('send')} Post SITREP to room</button>
      <button class="btn" data-a="exportJson">${icon('download')} Export full record (JSON)</button>
    </div><br>
    <details class="no-print panel panel-body" open id="sitrep-box"><summary><b>SITREP preview</b> <span class="small muted">· a status update you can read out on a bridge call or paste anywhere</span></summary><pre class="mono small prewrap">${sitrep(inc)}</pre></details><br>
    <article class="report">
      ${inc.privileged ? html`<div class="priv-mark">PRIVILEGED & CONFIDENTIAL · ATTORNEY-CLIENT COMMUNICATION · ATTORNEY WORK PRODUCT<br>PREPARED AT THE DIRECTION OF COUNSEL IN ANTICIPATION OF LITIGATION</div>` : ''}
      <h1>Cyber Incident Report: ${inc.ref}</h1>
      <p>${S.org.name} · Codename <b>${inc.codename}</b> · Generated ${fmtUTC(new Date(nowMs()).toISOString())} by ${S.me.displayName}</p>
      <h2>1. Summary</h2>
      <dl class="meta">
        <dt>Title</dt><dd>${inc.title}</dd><dt>Type</dt><dd>${S.categories[inc.category]}</dd>
        <dt>Severity</dt><dd>SEV${inc.severity} (${SEV_TEXT[inc.severity]})</dd><dt>Status</dt><dd>${phaseById(inc.status).label}</dd>
        <dt>Discovered</dt><dd>${fmtUTC(inc.detectedAt)}</dd><dt>First attacker activity</dt><dd>${fmtUTC(inc.occurredAt)}</dd>
        <dt>Contained</dt><dd>${fmtUTC(inc.containedAt)}</dd><dt>Closed</dt><dd>${fmtUTC(inc.closedAt)}</dd>
        <dt>Breach determined</dt><dd>${fmtUTC(inc.breachDeterminedAt)}</dd><dt>Entry point</dt><dd>${inc.attackVector || '-'}</dd>
        <dt>Affected systems</dt><dd>${inc.affectedSystems.join(', ') || '-'}</dd><dt>Incident lead</dt><dd>${userName(inc.leadId)}</dd>
      </dl>
      <p class="prewrap">${inc.summary}</p>
      <h2>2. Scope of compromised data</h2>
      ${scope.length ? html`<table><tr><th>Data set</th><th>System</th><th>Types</th><th>Records</th><th>Residents</th><th>Status</th><th>Confidence</th></tr>
        ${scope.map((s) => html`<tr><td>${s.asset}</td><td>${s.system}</td><td>${s.dataTypes.map((t) => S.dataTypes[t]).join('; ')}</td><td>${(s.records || 0).toLocaleString()}</td><td>${Object.entries(s.residents || {}).map(([k, v]) => `${k}: ${v}`).join(', ')}</td><td>${STATUS_LABEL[s.status][0]}</td><td>${s.confidence}</td></tr>`)}</table>
        <p>Total records in scope: <b>${scope.reduce((a, s) => a + (s.records || 0), 0).toLocaleString()}</b></p>` : html`<p>No data sets recorded.</p>`}
      <h2>3. Notification obligations</h2>
      <table><tr><th>Obligation</th><th>Recipient</th><th>Authority</th><th>Due (UTC)</th><th>Status</th></tr>
        ${inc.obligations.map((o) => html`<tr><td>${o.title}</td><td>${o.who}</td><td>${o.cite}</td><td>${o.dueAt ? fmtUTC(o.dueAt) : o.dueText || ''}</td><td>${o.status}${o.notes ? ' · ' + o.notes : ''}</td></tr>`)}</table>
      <h2>4. Timeline (UTC)</h2>
      <table><tr><th>Time</th><th>Type</th><th>Entry</th><th>By</th></tr>${tl.map((e) => html`<tr><td class="mono">${fmtUTC(e.at, true)}</td><td>${e.kind}</td><td>${e.text}</td><td>${userName(e.by)}</td></tr>`)}</table>
      ${inc.timeline.length > tl.length ? html`<p><i>${inc.timeline.length - tl.length} struck entr(ies) retained in the system record.</i></p>` : ''}
      <h2>5. Response actions</h2>
      <p>${tasks.filter((t) => t.status === 'done').length} of ${tasks.length} checklist actions complete.</p>
      <table><tr><th>Phase</th><th>Action</th><th>Status</th><th>Owner</th></tr>${tasks.map((t) => html`<tr><td>${phaseById(t.phase).label}</td><td>${t.title}</td><td>${t.status}${t.doneAt ? ' ' + fmtUTC(t.doneAt) : ''}</td><td>${userName(t.assigneeId || t.doneBy)}</td></tr>`)}</table>
      <h2>6. Indicators of compromise</h2>
      ${live(inc.iocs).length ? html`<table><tr><th>Type</th><th>Indicator (defanged)</th><th>Note</th></tr>${live(inc.iocs).map((i) => html`<tr><td>${i.type}</td><td class="mono">${defang(i.value)}</td><td>${i.note}</td></tr>`)}</table>` : html`<p>None recorded.</p>`}
      <h2>7. Evidence & chain of custody</h2>
      ${inc.evidence.length ? html`<table><tr><th>Item</th><th>SHA-256</th><th>Custody</th></tr>${inc.evidence.map((e) => html`<tr><td>${e.name}</td><td class="mono">${e.sha256 || '-'}</td><td>${e.custody.map((c) => `${fmtUTC(c.at)} ${userName(c.by)}: ${c.action}`).join(' → ')}</td></tr>`)}</table>` : html`<p>None recorded.</p>`}
      <p class="tiny"><br>Generated by LIFEBOAT. Source records are held in an encrypted, tamper-evident system of record.</p>
    </article>`;
}
A.print = () => window.print();
A.sitrepCopy = () => copyText(sitrep(curInc()), 'SITREP copied');
A.sitrepPost = async () => {
  const inc = curInc();
  const ch = S.channels.find((c) => c.incidentId === inc.id);
  if (ch) await act(api('POST', `/api/channels/${ch.id}/messages`, { text: sitrep(inc) }), 'SITREP posted to the incident room');
};
A.exportJson = () => { const inc = curInc(); downloadText(`${inc.ref}.json`, JSON.stringify(inc, null, 2), 'application/json'); };

// ================================================================ COMMS
function linkify(text) {
  return raw(esc(text).replace(/\bIR-\d{4}-\d{4}\b/g, (ref) => { const inc = [...S.inc.values()].find((i) => i.ref === ref); return inc ? `<a href="#/i/${esc(inc.id)}">${ref}</a>` : ref; }));
}
function channelAudience(ch) {
  const active = S.users.filter((u) => u.status === 'active');
  if (ch.members) return active.filter((u) => ch.members.includes(u.id) || u.role === 'admin');
  if (ch.incidentId) {
    const inc = S.inc.get(ch.incidentId);
    if (inc?.access === 'restricted') return active.filter((u) => u.role === 'admin' || [inc.leadId, inc.createdBy, ...(inc.members || [])].includes(u.id));
    return active.filter((u) => u.role !== undefined);
  }
  return active;
}
function msgHTML(m, cont, ch) {
  const acks = Object.keys(m.acks || {});
  const audience = channelAudience(ch).filter((u) => u.id !== m.userId);
  const missing = audience.filter((u) => !m.acks[u.id]);
  return html`<div class="msg ${cont ? 'cont' : ''} ${m.urgent ? 'urgent' : ''} ${m.userId ? '' : 'system'}">
    ${avatar(m.userId)}
    <div>${cont ? '' : html`<div class="meta"><b>${userName(m.userId)}</b><span class="tiny dim mono" title="${fmtUTC(m.at, true)}">${fmtTimeUTC(m.at)} · ${fmtLocal(m.at)}</span>${m.urgent ? html`<span class="chip st st-encrypted">URGENT</span>` : ''}</div>`}
      <div class="body">${linkify(m.text)}</div>
      ${m.urgent ? html`<div class="ack-row">${icon('check')} <b>${acks.filter((a) => a !== m.userId).length}/${audience.length}</b> acknowledged
        ${acks.filter((a) => a !== m.userId).map((a) => avatar(a, true))}
        ${missing.length ? html`<span class="dim" title="${missing.map((u) => u.displayName).join(', ')}">· waiting on ${missing.slice(0, 3).map((u) => u.displayName.split(' ')[0]).join(', ')}${missing.length > 3 ? ` +${missing.length - 3}` : ''}</span>` : html`<span class="cd ok">· everyone has seen this</span>`}
        ${m.userId !== S.me.id && !m.acks[S.me.id] ? html`<button class="btn sm primary" data-a="ack" data-id="${m.id}">${icon('check')} Acknowledge</button>` : ''}</div>` : ''}
    </div></div>`;
}
function chatPane(ch) {
  const msgs = S.msgs.get(ch.id) || [];
  let prev = null, lastDay = null;
  const items = msgs.map((m) => {
    const day = new Date(m.at).toDateString();
    const sep = day !== lastDay ? html`<div class="day-sep">${new Date(m.at).toLocaleDateString(undefined, { weekday: 'long', month: 'short', day: 'numeric' })}</div>` : '';
    const cont = !sep && prev && prev.userId === m.userId && !m.urgent && !prev.urgent && new Date(m.at) - new Date(prev.at) < 5 * 60e3;
    lastDay = day; prev = m;
    return html`${sep}${msgHTML(m, cont, ch)}`;
  });
  const inc = ch.incidentId && S.inc.get(ch.incidentId);
  const audience = channelAudience(ch);
  return html`<div class="chat">
    <div class="chat-head"><div><h3>#${ch.name}</h3><div class="tiny muted">${inc ? html`Incident room for <a href="#/i/${inc.id}">${inc.ref} · ${inc.title}</a>` : ch.members ? 'Private channel' : 'All responders'} · ${audience.length} people · ${audience.filter((u) => S.online.has(u.id)).length} online</div></div>
      <div class="online-stack">${audience.filter((u) => S.online.has(u.id)).slice(0, 8).map((u) => avatar(u.id, true))}</div></div>
    <div class="msgs" id="msgs" data-scroll="msgs-${ch.id}">${items.length ? items : html`<div class="empty small">No messages yet. Assume regular email and chat are being watched by the attacker. Talk here.</div>`}</div>
    <form class="composer" data-submit="sendMsg" data-ch="${ch.id}">
      <textarea id="composer-${ch.id}" data-keep data-composer name="text" rows="1" maxlength="4000" placeholder="Message #${ch.name}  (Enter to send · Shift+Enter new line)"></textarea>
      ${S.me.role !== 'observer' ? html`<label class="urgent-toggle" title="Everyone must tap Acknowledge. You'll see who hasn't."><input type="checkbox" name="urgent" id="urgent-${ch.id}" data-keep data-change="urgentToggle"> URGENT</label>` : ''}
      <button class="btn primary" title="Send">${icon('send')}</button>
    </form></div>`;
}
function scrollChat() { const m = $('#msgs'); if (m) m.scrollTop = m.scrollHeight; }
A.urgentToggle = (t) => t.closest('.composer').classList.toggle('is-urgent', t.checked);
A.sendMsg = async (f) => {
  const ta = $('textarea', f);
  const text = ta.value.trim();
  if (!text) return;
  const urgent = !!f.urgent?.checked;
  ta.value = '';
  const r = await act(api('POST', `/api/channels/${f.dataset.ch}/messages`, { text, urgent }));
  if (!r) { ta.value = text; return; }
  if (f.urgent) { f.urgent.checked = false; f.classList.remove('is-urgent'); }
  scrollChat();
  ta.focus();
};
A.ack = async (t) => { await act(api('POST', `/api/messages/${t.dataset.id}/ack`, {}), 'Acknowledged'); };
document.addEventListener('keydown', (e) => {
  if (e.target.matches?.('textarea[data-composer]') && e.key === 'Enter' && !e.shiftKey && !e.isComposing) { e.preventDefault(); e.target.form.requestSubmit(); }
});
document.addEventListener('input', (e) => { if (e.target.matches?.('textarea[data-composer]')) { e.target.style.height = 'auto'; e.target.style.height = Math.min(180, e.target.scrollHeight) + 'px'; } });

function CommsView(chId) {
  const pick = () => chId && S.channels.some((c) => c.id === chId) ? chId : (S.channels.find((c) => c.kind === 'general') || S.channels[0])?.id;
  return {
    flush: true,
    channelId: () => pick(),
    mount(el) { this.el = el; this.update(); scrollChat(); },
    update(what, xid) {
      if (what === 'incident') return;
      const id = pick();
      const ch = S.channels.find((c) => c.id === id);
      if (ch && document.hasFocus()) markRead(ch.id);
      const general = S.channels.filter((c) => !c.incidentId);
      const rooms = S.channels.filter((c) => c.incidentId).sort((a, b) => (isActive(S.inc.get(b.incidentId) || {}) - isActive(S.inc.get(a.incidentId) || {})));
      const chLink = (c) => { const inc = c.incidentId && S.inc.get(c.incidentId); const n = S.unread[c.id] || 0; return html`<a class="chan ${c.id === id ? 'active' : ''} ${n ? 'unread' : ''}" href="#/comms/${c.id}">${inc ? sevChip(inc.severity, false) : c.members ? icon('lock') : '#'}<span class="grow nowrap">${c.name}</span>${n ? html`<span class="badge">${n}</span>` : ''}</a>`; };
      setHTML(this.el, html`<div class="comms">
        <div class="chan-list">
          <div class="nav-label">CHANNELS</div>${general.map(chLink)}
          ${can('channel.create') ? html`<button class="btn ghost sm block" data-a="newChannel">${icon('plus')} New channel</button>` : ''}
          ${rooms.length ? html`<div class="nav-label">INCIDENT ROOMS</div>${rooms.map(chLink)}` : ''}
        </div>
        ${ch ? chatPane(ch) : html`<div class="empty">No channels.</div>`}
      </div>`);
      if (what === 'message' && xid === id) scrollChat();
    },
  };
}
A.newChannel = () => {
  const users = S.users.filter((u) => u.status === 'active' && u.id !== S.me.id);
  modal(html`<form id="nc-f">${mHead('New channel', 'Leave everyone unticked for an open channel, or pick people for a private one (e.g. #legal-privileged).')}
    <div class="modal-body"><label class="field">Name <input name="name" required maxlength="40" placeholder="e.g. legal-privileged"></label>
    <div class="type-pick">${users.map((u) => html`<label class="check"><input type="checkbox" name="m" value="${u.id}"> ${u.displayName}</label>`)}</div></div>
    <div class="modal-foot"><button class="btn" type="button" data-a="closeModal">Cancel</button><button class="btn primary">Create</button></div></form>`);
  $('#nc-f').onsubmit = async (e) => {
    e.preventDefault();
    const ch = await act(api('POST', '/api/channels', { name: e.target.name.value, members: $$('input[name=m]:checked', e.target).map((x) => x.value) }), 'Channel created');
    if (ch) { closeModal(); await resync(false); location.hash = '#/comms/' + ch.id; }
  };
};

// ================================================================ CONTACTS
const CONTACT_GROUPS = ['Leadership', 'Legal', 'Insurance', 'Forensics / DFIR', 'IT / Security', 'Law enforcement', 'Regulators', 'Banking', 'PR / Comms', 'Vendors', 'Other'];
const CONTACT_PRESETS = [
  { name: 'FBI field office (cyber squad)', group: 'Law enforcement', role: 'Report ransomware / BEC' },
  { name: 'Cyber insurance breach hotline', group: 'Insurance', role: 'First notice of loss' },
  { name: 'Outside breach counsel', group: 'Legal', role: 'Directs investigation (privilege)' },
  { name: 'DFIR / forensics firm', group: 'Forensics / DFIR', role: 'Incident response retainer' },
  { name: 'Bank fraud department', group: 'Banking', role: 'Wire recall / freeze' },
  { name: 'Crisis PR firm', group: 'PR / Comms', role: 'Media & customer statements' },
];
function ContactsView() {
  return {
    mount(el) { this.el = el; this.update(); },
    update(what) {
      if (what === 'message' || what === 'ack') return;
      const w = can('contacts.write');
      const contacts = S.org.contacts || [];
      const ins = S.org.insurance || {}, oc = S.org.outsideCounsel || {};
      const groups = CONTACT_GROUPS.map((g) => [g, contacts.filter((c) => (c.group || 'Other') === g)]).filter(([, l]) => l.length);
      const card = (c) => html`<div class="contact"><div><b>${c.name}</b><div class="small muted">${[c.role, c.org].filter(Boolean).join(' · ')}</div>${c.notes ? html`<div class="tiny dim">${c.notes}</div>` : ''}</div>
        <div class="right">${c.phone ? html`<a class="phone" href="tel:${c.phone}">${c.phone}</a>` : ''}${c.alt ? html`<div class="tiny"><a href="tel:${c.alt}">${c.alt}</a></div>` : ''}
        ${w && c.id ? html`<button class="iconbtn" data-a="editContact" data-id="${c.id}">${icon('edit')}</button>` : ''}</div></div>`;
      setHTML(this.el, html`
        <div class="page-head"><div><h1>Emergency contacts</h1><p>Assume email, Teams/Slack and the company directory are compromised. <b>Call people. Use these numbers.</b></p></div>
          <div class="row">${w ? html`<button class="btn primary" data-a="editContact">${icon('plus')} Add contact</button>` : ''}<button class="btn" data-a="print">${icon('printer')} Print phone tree</button></div></div>
        ${w && contacts.length < 4 ? html`<div class="next-up"><h3>Quick add</h3><div class="row wrap">${CONTACT_PRESETS.map((p, i) => html`<button class="btn sm" data-a="presetContact" data-i="${i}">${icon('plus')} ${p.name}</button>`)}</div></div>` : ''}
        <div class="grid g2">
          ${ins.carrier || oc.firm ? html`<section class="panel"><div class="panel-head"><h3>${icon('scale')} Insurance & counsel</h3></div>
            ${ins.carrier ? card({ name: ins.carrier, role: 'Cyber insurance · notify within ' + (ins.noticeHours || 72) + 'h', org: ins.policy ? 'Policy ' + ins.policy : '', phone: ins.hotline }) : ''}
            ${oc.firm ? card({ name: oc.contact || oc.firm, role: 'Outside breach counsel', org: oc.firm, phone: oc.phone }) : ''}</section>` : ''}
          ${groups.map(([g, l]) => html`<section class="panel"><div class="panel-head"><h3>${g}</h3><span class="badge">${l.length}</span></div>${l.map(card)}</section>`)}
          <section class="panel"><div class="panel-head"><h3>${icon('users')} Response team</h3></div>
            ${S.users.filter((u) => u.status === 'active').map((u) => html`<div class="contact"><div class="row">${avatar(u.id, true, true)}<div><b>${u.displayName}</b><div class="small muted">${S.roles[u.role]}${u.title ? ' · ' + u.title : ''}</div></div></div>
              <div class="right">${u.phone ? html`<a class="phone" href="tel:${u.phone}">${u.phone}</a>` : html`<span class="tiny dim">no phone on file</span>`}</div></div>`)}</section>
        </div>
        ${!contacts.length && !ins.carrier ? html`<div class="panel empty">${icon('phone')}<h3>No contacts yet</h3><p>Fill this in <b>before</b> an incident. It is the list you will reach for at 2 a.m.</p></div>` : ''}`);
    },
  };
}
function contactModal(c = {}) {
  modal(html`<form id="ct-f">${mHead(c.id ? 'Edit contact' : 'Add contact')}
    <div class="modal-body form-grid">
      <label class="field">Name <input name="name" required value="${c.name || ''}"></label>
      <label class="field">Group <select name="group">${CONTACT_GROUPS.map((g) => html`<option ${g === (c.group || 'Other') ? raw('selected') : ''}>${g}</option>`)}</select></label>
      <label class="field">Role <input name="role" value="${c.role || ''}" placeholder="What they do for us"></label>
      <label class="field">Organization <input name="org" value="${c.org || ''}"></label>
      <label class="field">Phone (primary) <input name="phone" value="${c.phone || ''}" inputmode="tel"></label>
      <label class="field">Phone (backup / after-hours) <input name="alt" value="${c.alt || ''}" inputmode="tel"></label>
      <label class="field full">Notes <input name="notes" value="${c.notes || ''}" placeholder="Retainer #, policy #, when to call"></label>
    </div>
    <div class="modal-foot">${c.id ? html`<button class="btn danger" type="button" id="ct-del">Remove</button><span class="grow"></span>` : ''}<button class="btn" type="button" data-a="closeModal">Cancel</button><button class="btn primary">Save</button></div></form>`, { wide: true });
  const save = async (list) => { if (await act(api('PUT', '/api/contacts', { contacts: list }), 'Contacts saved')) { closeModal(); await resync(false); } };
  $('#ct-f').onsubmit = (e) => {
    e.preventDefault();
    const d = { ...formData(e.target), id: c.id };
    const list = (S.org.contacts || []).filter((x) => x.id !== c.id);
    save([...list, d]);
  };
  const del = $('#ct-del');
  if (del) del.onclick = () => save((S.org.contacts || []).filter((x) => x.id !== c.id));
}
A.editContact = (t) => contactModal((S.org.contacts || []).find((c) => c.id === t.dataset.id) || {});
A.presetContact = (t) => contactModal({ ...CONTACT_PRESETS[Number(t.dataset.i)] });

// ================================================================ ADMIN
const ROLE_DESC = {
  admin: 'Everything, including people, settings and lockdown',
  commander: 'Runs incidents: phases, severity, access, closing',
  responder: 'Works incidents: logs, tasks, scope, evidence',
  counsel: 'Legal: deadlines, privilege, determinations, audit log',
  observer: 'Executives: read-only view, plus chat',
};
function AdminView(tab) {
  const tabs = can('admin') ? [['people', 'People', 'users'], ['sessions', 'Sessions', 'key'], ['audit', 'Audit log', 'shield'], ['org', 'Organization', 'sliders'], ['system', 'Security & system', 'lock']] : [['audit', 'Audit log', 'shield']];
  return {
    mount(el) {
      this.el = el;
      setHTML(el, html`<div class="page-head"><div><h1>${can('admin') ? 'Administration' : 'Audit log'}</h1><p>Every action here is recorded in the tamper-evident audit log.</p></div></div>
        <nav class="tabs">${tabs.map(([k, l, ic]) => html`<a class="tab ${tab === k ? 'active' : ''}" href="#/admin/${k}">${icon(ic)}${l}</a>`)}</nav><div id="admin-body"><div class="empty">Loading…</div></div>`);
      this.update('mount');
    },
    async update(what) {
      if (what === 'message' || what === 'ack' || what === 'incident') return;
      if (what === 'presence' && tab !== 'sessions') return;
      try {
        if (tab === 'people') setHTML('#admin-body', peopleHTML(await api('GET', '/api/admin/users')));
        else if (tab === 'sessions') setHTML('#admin-body', sessionsHTML(await api('GET', '/api/admin/sessions')));
        else if (tab === 'audit') { if (what === 'mount' || what === 'audit') { this.audit = await api('GET', '/api/audit?limit=1000'); } setHTML('#admin-body', auditHTML(this.audit)); }
        else if (tab === 'org') { if (what === 'mount') setHTML('#admin-body', orgHTML()); }
        else if (tab === 'system') setHTML('#admin-body', systemHTML());
      } catch (e) { setHTML('#admin-body', html`<div class="error-box">${e.message}</div>`); }
    },
  };
}

function peopleHTML(users) {
  return html`<div class="row between"><p class="muted small">New people get a one-time code. <b>Give it to them in person or by phone. Never by email</b>, which the attacker may be reading.</p>
    <button class="btn primary" data-a="invite">${icon('plus')} Invite person</button></div><br>
  <div class="panel table-wrap"><table class="t"><thead><tr><th>Person</th><th>Role</th><th>Status</th><th>Last sign-in</th><th></th></tr></thead><tbody>
  ${users.map((u) => html`<tr><td><div class="row">${avatar(u.id, true, true)}<div><b>${u.displayName}</b><div class="tiny muted mono">${u.username}${u.title ? ' · ' + u.title : ''}${u.phone ? ' · ' + u.phone : ''}</div></div></div></td>
    <td><select data-change="setRole" data-id="${u.id}" ${u.id === S.me.id ? raw('disabled') : ''}>${Object.entries(S.roles).map(([k, l]) => html`<option value="${k}" ${k === u.role ? raw('selected') : ''}>${l}</option>`)}</select></td>
    <td>${u.status === 'active' ? html`<span class="chip st st-secured">Active · MFA</span>` : u.status === 'invited' ? html`<span class="chip st st-at-risk">Invited</span><div class="tiny dim">${u.inviteExpires && u.inviteExpires < Date.now() ? 'code expired' : 'expires ' + fmtLocal(new Date(u.inviteExpires).toISOString())}</div>` : html`<span class="chip st st-encrypted">Disabled</span>`}${u.locked ? html` <span class="chip st st-encrypted">Locked out</span>` : ''}</td>
    <td class="small muted">${u.lastLogin ? fmtUTC(u.lastLogin) : 'never'}</td>
    <td class="nowrap right">${u.id !== S.me.id ? html`
      ${u.locked ? html`<button class="btn sm" data-a="userUnlock" data-id="${u.id}">Unlock</button>` : ''}
      <button class="btn sm" data-a="userReset" data-id="${u.id}" title="Lost phone or suspected compromise">${icon('key')} ${u.status === 'invited' ? 'New code' : 'Reset'}</button>
      ${u.status === 'active' ? html`<button class="btn sm danger" data-a="userDisable" data-id="${u.id}">Disable</button>` : u.status === 'disabled' ? html`<button class="btn sm" data-a="userEnable" data-id="${u.id}">Enable</button>` : ''}` : html`<span class="tiny dim">you</span>`}</td></tr>`)}
  </tbody></table></div>`;
}
function showInviteCode(r, title) {
  modal(html`${mHead(title, `For ${r.user.displayName} (${r.user.username})`)}
    <div class="modal-body"><p>Read this code to them <b>in person or by phone</b>. It works once and expires ${fmtLocal(r.expiresAt)}.</p>
      <div class="secret code-input">${r.inviteCode}</div>
      <ol class="small muted"><li>They open LIFEBOAT and choose <b>"I have an invite code"</b>.</li><li>Enter username <b class="mono">${r.user.username}</b> and this code, then choose a password.</li><li>They scan a QR code with an authenticator app. Done.</li></ol>
      <p class="tiny dim">This code is shown once and is not stored anywhere (only a hash of it).</p></div>
    <div class="modal-foot"><button class="btn" data-a="copyVal" data-v="${r.inviteCode}">${icon('copy')} Copy</button><button class="btn primary" data-a="closeModal">Done</button></div>`);
}
A.invite = () => {
  modal(html`<form id="inv-f">${mHead('Invite someone to LIFEBOAT', 'They will set their own password and two-factor sign-in.')}
    <div class="modal-body"><div class="form-grid">
      <label class="field">Full name <input name="displayName" id="inv-name" required maxlength="80" placeholder="e.g. Maria Chen"></label>
      <label class="field">Username <input name="username" id="inv-user" required maxlength="32" pattern="[a-z0-9._\\-]{2,32}" placeholder="maria.chen"></label>
      <label class="field">Job title <input name="title" maxlength="80" placeholder="e.g. IT Director"></label>
      <label class="field">Mobile phone <span class="hint">Shown in the phone tree</span><input name="phone" maxlength="60" inputmode="tel"></label></div>
      <div class="field"><span>Role</span><input type="hidden" name="role" value="responder">
        <div class="pick-grid">${Object.entries(S.roles).map(([k, l]) => html`<button type="button" class="pick ${k === 'responder' ? 'on' : ''}" data-a="pick" data-group="role" data-v="${k}">${l}<small>${ROLE_DESC[k]}</small></button>`)}</div></div>
    </div><div class="modal-foot"><button class="btn" type="button" data-a="closeModal">Cancel</button><button class="btn primary">Create invite</button></div></form>`, { wide: true });
  $('#inv-name').addEventListener('input', (e) => { const u = $('#inv-user'); if (!u.dataset.touched) u.value = e.target.value.toLowerCase().normalize('NFKD').replace(/[^\w\s.-]/g, '').trim().replace(/\s+/g, '.').slice(0, 32); });
  $('#inv-user').addEventListener('input', (e) => { e.target.dataset.touched = '1'; });
  $('#inv-f').onsubmit = async (e) => {
    e.preventDefault();
    const r = await act(api('POST', '/api/admin/users', formData(e.target)));
    if (r) { showInviteCode(r, 'Invite created'); refresh('users'); }
  };
};
A.setRole = async (t) => { if (await act(api('PATCH', '/api/admin/users/' + t.dataset.id, { role: t.value }), 'Role updated')) refresh(); };
A.userUnlock = async (t) => { if (await act(api('PATCH', '/api/admin/users/' + t.dataset.id, { unlock: true }), 'Unlocked')) refresh(); };
A.userEnable = async (t) => { if (await act(api('PATCH', '/api/admin/users/' + t.dataset.id, { status: 'active' }), 'Enabled')) refresh(); };
A.userDisable = async (t) => {
  if (!(await confirmBox('Disable this account?', 'They are signed out immediately everywhere and cannot sign in until re-enabled.', 'Disable', true))) return;
  if (await act(api('PATCH', '/api/admin/users/' + t.dataset.id, { status: 'disabled' }), 'Disabled and signed out')) refresh();
};
A.userReset = async (t) => {
  const u = userById(t.dataset.id);
  if (!(await confirmBox(`Reset ${u?.displayName || 'this person'}?`, 'Use when someone loses their phone or their account may be compromised. Their password and two-factor are wiped, they are signed out everywhere, and you get a new one-time code to give them.', 'Reset account', true))) return;
  const r = await act(api('POST', `/api/admin/users/${t.dataset.id}/reset`, {}));
  if (r) { showInviteCode(r, 'Account reset'); refresh(); }
};

function sessionsHTML(list) {
  return html`<p class="muted small">Everyone signed in right now. If you don't recognize a device or address, revoke it and reset that person's account.</p>
  <div class="panel table-wrap"><table class="t"><thead><tr><th>Person</th><th>Address</th><th>Device</th><th>Signed in</th><th>Last action</th><th></th></tr></thead><tbody>
  ${list.map((s) => html`<tr><td><div class="row">${avatar(s.user.id, true)}<b>${s.user.displayName}</b>${s.current ? html`<span class="chip">this session</span>` : ''}${s.live ? html`<span class="dot on" title="Connected now"></span>` : ''}</div></td>
    <td class="mono small">${s.ip}</td><td class="tiny muted">${s.ua.replace(/^Mozilla\/5\.0 /, '').slice(0, 70)}</td><td class="small">${fmtUTC(s.createdAt)}</td><td class="small">${ago(s.lastSeen)}</td>
    <td>${s.current ? '' : html`<button class="btn sm danger" data-a="revoke" data-id="${s.id}">Revoke</button>`}</td></tr>`)}</tbody></table></div>`;
}
A.revoke = async (t) => { if (await act(api('DELETE', '/api/admin/sessions/' + t.dataset.id), 'Session revoked')) refresh(); };

function auditHTML(data) {
  const q = UI.auditQ.toLowerCase();
  const rows = data.entries.filter((e) => !q || JSON.stringify(e).toLowerCase().includes(q));
  return html`<div class="row wrap between"><div class="row"><button class="btn primary" data-a="verifyAudit">${icon('shield')} Verify integrity</button><span id="verify-out"></span></div>
    <div class="row"><input type="search" id="audit-q" data-keep placeholder="Filter…" value="${UI.auditQ}"><button class="btn" data-a="auditCsv">${icon('download')} CSV</button></div></div><br>
    <p class="tiny muted">Each entry is cryptographically chained (HMAC-SHA256) to the one before it. Editing, deleting or reordering any record breaks the chain, and verification will point to exactly where. ${data.total.toLocaleString()} entries total.</p>
    <div class="panel table-wrap"><table class="t"><thead><tr><th>#</th><th>Time (UTC)</th><th>Who</th><th>Action</th><th>Target</th><th>Detail</th></tr></thead><tbody>
    ${rows.slice(0, 500).map((e) => html`<tr><td class="mono tiny dim">${e.seq}</td><td class="mono small nowrap">${fmtUTC(e.at, true)}</td><td class="small">${e.actor.name}</td>
      <td><span class="chip ${/fail|blocked|lockdown|reset|revoke|disable|strike/.test(e.action) ? 'lvl-required' : ''}">${e.action}</span></td><td class="small">${e.target || ''}</td><td class="mono tiny muted">${e.detail ? JSON.stringify(e.detail).slice(0, 140) : ''}</td></tr>`)}
    </tbody></table></div>`;
}
document.addEventListener('input', (e) => { if (e.target.id === 'audit-q') { UI.auditQ = e.target.value; refresh('filter'); } });
A.verifyAudit = async () => {
  const r = await act(api('GET', '/api/audit/verify'));
  if (!r) return;
  setHTML('#verify-out', r.ok ? html`<span class="chip st st-secured">${icon('check')} Chain intact · ${r.total.toLocaleString()} entries · head ${r.head.slice(0, 12)}…</span>` : html`<span class="chip st st-encrypted">TAMPERING DETECTED at entry #${r.brokenAt}</span>`);
};
A.auditCsv = () => { const d = current.audit; downloadText('lifeboat-audit.csv', toCsv([['seq', 'time_utc', 'actor', 'action', 'target', 'detail', 'hash'], ...d.entries.map((e) => [e.seq, e.at, e.actor.name, e.action, e.target, JSON.stringify(e.detail || ''), e.hash])]), 'text/csv'); };

function orgHTML() {
  const o = S.org, ins = o.insurance || {}, oc = o.outsideCounsel || {};
  const tog = (k, label, desc) => html`<label class="check"><input type="checkbox" name="${k}" ${o[k] ? raw('checked') : ''}><span><b>${label}</b><br><span class="small muted">${desc}</span></span></label>`;
  return html`<form data-submit="saveOrg" class="grid g2">
    <section class="panel"><div class="panel-head"><h3>Organization profile</h3></div><div class="panel-body col">
      <label class="field">Organization name <input name="name" required value="${o.name}"></label>
      <p class="small muted">These settings decide which legal deadlines LIFEBOAT tracks for you:</p>
      ${tog('publiclyTraded', 'Publicly traded (SEC registrant)', 'Adds the Form 8-K Item 1.05 four-business-day clock.')}
      ${tog('hipaaCovered', 'HIPAA covered entity / business associate', 'Makes HIPAA individual, HHS and media notices "required" when health data is in scope.')}
      ${tog('nydfsRegulated', 'NYDFS-regulated (23 NYCRR 500)', 'Adds the 72-hour DFS notice.')}
      ${tog('criticalInfrastructure', 'Critical infrastructure (CIRCIA)', 'Adds the 72-hour CISA report.')}
    </div></section>
    <div class="col">
      <section class="panel"><div class="panel-head"><h3>Cyber insurance</h3></div><div class="panel-body form-grid">
        <label class="field">Carrier <input name="ins.carrier" value="${ins.carrier}"></label><label class="field">Policy # <input name="ins.policy" value="${ins.policy}"></label>
        <label class="field">Breach hotline <input name="ins.hotline" value="${ins.hotline}"></label><label class="field">Notice required within (hours) <input type="number" min="1" name="ins.noticeHours" value="${ins.noticeHours || 72}"></label>
      </div></section>
      <section class="panel"><div class="panel-head"><h3>Outside breach counsel</h3></div><div class="panel-body form-grid">
        <label class="field">Firm <input name="oc.firm" value="${oc.firm}"></label><label class="field">Lead attorney <input name="oc.contact" value="${oc.contact}"></label>
        <label class="field full">Phone <input name="oc.phone" value="${oc.phone}"></label>
      </div></section>
      <button class="btn primary xl">Save organization</button>
    </div></form>`;
}
A.saveOrg = async (f) => {
  const d = formData(f);
  const body = {
    name: d.name, publiclyTraded: !!d.publiclyTraded, hipaaCovered: !!d.hipaaCovered, nydfsRegulated: !!d.nydfsRegulated, criticalInfrastructure: !!d.criticalInfrastructure,
    insurance: { carrier: d['ins.carrier'], policy: d['ins.policy'], hotline: d['ins.hotline'], noticeHours: Number(d['ins.noticeHours']) },
    outsideCounsel: { firm: d['oc.firm'], contact: d['oc.contact'], phone: d['oc.phone'] },
  };
  if (await act(api('PUT', '/api/org', body), 'Organization saved. Deadlines recalculated.')) { await resync(); setHTML('#org-name', S.org.name); }
};

function systemHTML() {
  const enrolled = S.users.filter((u) => u.status === 'active').length;
  const pending = S.users.filter((u) => u.status === 'invited').length;
  const check = (ok, label, detail) => html`<div class="list-item">${ok ? html`<span class="chip st st-secured">${icon('check')}</span>` : html`<span class="chip st st-at-risk">!</span>`}<span class="grow"><b>${label}</b><div class="tiny muted">${detail}</div></span></div>`;
  return html`<div class="grid g2">
    <section class="panel"><div class="panel-head"><h3>${icon('lock')} Lockdown (break glass)</h3>${S.lockdown.on ? html`<span class="chip st st-encrypted">ACTIVE</span>` : ''}</div><div class="panel-body col">
      <p class="small">Suspect a LIFEBOAT account has been compromised? Lockdown <b>signs out everyone except administrators instantly</b> and blocks new sign-ins until you lift it. Then reset suspect accounts and review the audit log.</p>
      ${S.lockdown.on ? html`<button class="btn xl" data-a="lockdown" data-on="0">${icon('check')} Lift lockdown</button><p class="tiny muted">Activated by ${userName(S.lockdown.by)} at ${fmtUTC(S.lockdown.at)}</p>` : html`<button class="btn danger xl" data-a="lockdown" data-on="1">${icon('lock')} Activate lockdown</button>`}
    </div></section>
    <section class="panel"><div class="panel-head"><h3>${icon('shield')} Security posture</h3></div><div class="panel-body tight">
      ${check(S.tls, 'Encrypted transport', S.tls ? 'HTTPS with TLS 1.2+, HSTS. Verify the certificate fingerprint printed at startup.' : 'Plain HTTP on loopback only. Run npm run cert before using on a network.')}
      ${check(true, 'Encrypted at rest', 'AES-256-GCM vault; key derived from a startup passphrase (scrypt) and never written to disk. Evidence files individually encrypted.')}
      ${check(true, 'Two-factor sign-in enforced', `${enrolled} active account(s), all with TOTP. ${pending} pending invite(s).`)}
      ${check(true, 'Tamper-evident audit log', 'HMAC-chained entries. Run "Verify integrity" on the Audit tab.')}
      ${check(true, `Idle sign-out after ${Math.round(S.idleMs / 60e3)} min`, '12-hour maximum session. Sessions die on server restart.')}
      ${check(true, 'Zero third-party code', 'No npm packages, CDNs, fonts or trackers. Strict Content-Security-Policy blocks all outside connections.')}
      ${check(true, 'Legal hold by design', 'Nothing can be deleted, only struck with name and time.')}
    </div></section>
    <section class="panel"><div class="panel-head"><h3>${icon('download')} Encrypted backup</h3></div><div class="panel-body col">
      <p class="small">Download the sealed vault file. It is already encrypted with your passphrase, so it is safe to carry offsite on a USB drive. Restore by placing it in the data folder and starting LIFEBOAT with the same passphrase.</p>
      <a class="btn" href="/api/admin/backup" download>${icon('download')} Download encrypted backup</a></div></section>
  </div>`;
}
A.lockdown = async (t) => {
  const on = t.dataset.on === '1';
  if (on && !(await confirmBox('Activate lockdown?', 'Everyone except administrators will be signed out immediately and blocked from signing in.', 'Activate lockdown', true))) return;
  const r = await act(api('POST', '/api/admin/lockdown', { on }), on ? 'Lockdown active' : 'Lockdown lifted');
  if (r) { S.lockdown = r; refresh('lockdown'); }
};

// ================================================================ WALLBOARD
function WallView() {
  return {
    mount(el) { this.el = el; this.update(); },
    update(what) {
      if (what === 'message' || what === 'ack') return;
      const active = allIncidents().filter(isActive);
      const ticker = active.flatMap((i) => live(i.timeline).filter((e) => e.kind !== 'system').map((e) => ({ e, i }))).sort((a, b) => b.e.at.localeCompare(a.e.at)).slice(0, 8);
      setHTML(this.el, html`<div class="wall">
        <div class="wall-head"><div class="row">${LOGO}<div><h1>LIFEBOAT · ${S.org.name}</h1><div class="muted">Situation board · updates live</div></div></div>
          <div class="right"><div class="wall-clock" id="wall-clock">${fmtTimeUTC(new Date(nowMs()).toISOString())}</div><div class="row"><span id="conn" class="conn"></span><a class="btn sm ghost" href="#/">Exit (Esc)</a></div></div></div>
        ${active.length ? html`<div class="wall-grid">${active.map((i) => { const tasks = live(i.tasks); const done = tasks.filter((t) => t.status === 'done').length; return html`<div class="wall-card s${i.severity}">
          <div class="row between">${sevChip(i.severity)}<span class="codename">${i.codename}</span></div>
          <h2>${i.title}</h2><div class="muted">${i.ref} · ${phaseById(i.status).label}</div><br>
          ${since(i.detectedAt)}<br><br>
          <div class="row">${miniPhases(i)}<span class="small muted">${done}/${tasks.length} actions</span></div><br>
          ${openObligations(i).filter((o) => o.dueAt).slice(0, 3).map((o) => html`<div class="row between small"><span>${o.title}</span>${countdown(o.dueAt)}</div>`)}
        </div>`; })}</div>` : html`<div class="empty"><h1>All clear</h1><p>No active incidents.</p></div>`}
        ${ticker.length ? html`<div class="panel wall-ticker">${ticker.map(({ e, i }) => html`<div class="list-item"><span class="mono small">${fmtTimeUTC(e.at)}</span><span class="chip k-${e.kind}">${e.kind}</span><span class="grow">${e.text}</span><span class="codename">${i.codename}</span></div>`)}</div>` : ''}
      </div>`);
      setConn(S.conn);
    },
  };
}

// ================================================================ PALETTE, HELP, KEYS
function paletteItems() {
  const items = [];
  if (can('incident.create')) items.push({ icon: 'zap', label: 'Declare an incident', hint: 'D', run: () => A.declare() });
  items.push({ icon: 'home', label: 'Command center', run: () => (location.hash = '#/') });
  items.push({ icon: 'chat', label: 'Comms', run: () => (location.hash = '#/comms') });
  items.push({ icon: 'phone', label: 'Emergency contacts', kw: 'phone call', run: () => (location.hash = '#/contacts') });
  items.push({ icon: 'tv', label: 'Wallboard (big screen)', run: () => (location.hash = '#/wall') });
  if (can('admin')) {
    items.push({ icon: 'users', label: 'Invite a person', run: () => { location.hash = '#/admin/people'; setTimeout(A.invite, 50); } });
    items.push({ icon: 'lock', label: S.lockdown.on ? 'Lift lockdown' : 'Activate lockdown', run: () => (location.hash = '#/admin/system') });
  }
  if (can('audit.read')) items.push({ icon: 'shield', label: 'Audit log', run: () => (location.hash = '#/admin/audit') });
  for (const i of allIncidents()) {
    items.push({ icon: 'alert', label: `${i.ref} · ${i.codename} · ${i.title}`, hint: phaseById(i.status).short, run: () => (location.hash = '#/i/' + i.id) });
    if (isActive(i)) for (const [k, l] of [['scope', 'Scope & Data'], ['obligations', 'Legal deadlines'], ['tasks', 'Tasks'], ['report', 'Report / SITREP'], ['room', 'Room']]) items.push({ icon: 'arrow', label: `${i.codename} → ${l}`, run: () => (location.hash = `#/i/${i.id}/${k}`) });
  }
  for (const c of S.channels) items.push({ icon: 'chat', label: '#' + c.name, run: () => (location.hash = '#/comms/' + c.id) });
  items.push({ icon: 'help', label: 'Help: how to use LIFEBOAT', hint: '?', run: () => A.help() });
  items.push({ icon: 'moon', label: 'Toggle light / dark', run: () => A.theme() });
  items.push({ icon: 'logout', label: 'Sign out', run: () => A.logout() });
  return items;
}
A.palette = () => {
  const items = paletteItems();
  let sel = 0, shown = [];
  modal(html`<input id="pal-q" placeholder="Type to search incidents, channels and actions…" autocomplete="off" aria-label="Command"><div class="items" id="pal-items"></div>`, { cls: 'palette' });
  const draw = () => {
    const q = $('#pal-q').value.toLowerCase().trim();
    shown = items.filter((i) => !q || q.split(/\s+/).every((w) => (i.label + ' ' + (i.kw || '')).toLowerCase().includes(w))).slice(0, 12);
    sel = Math.min(sel, Math.max(0, shown.length - 1));
    setHTML('#pal-items', shown.length ? shown.map((it, idx) => html`<div class="item ${idx === sel ? 'sel' : ''}" data-a="palRun" data-i="${idx}">${icon(it.icon)}<span class="grow">${it.label}</span>${it.hint ? html`<kbd>${it.hint}</kbd>` : ''}</div>`) : html`<div class="empty small">No matches</div>`);
  };
  A.palRun = (t) => { const it = shown[Number(t.dataset.i)]; closeModal(); it?.run(); };
  const q = $('#pal-q');
  q.addEventListener('input', () => { sel = 0; draw(); });
  q.addEventListener('keydown', (e) => {
    if (e.key === 'ArrowDown') { sel = Math.min(shown.length - 1, sel + 1); draw(); e.preventDefault(); }
    if (e.key === 'ArrowUp') { sel = Math.max(0, sel - 1); draw(); e.preventDefault(); }
    if (e.key === 'Enter') { const it = shown[sel]; closeModal(); it?.run(); e.preventDefault(); }
  });
  draw();
};
A.help = () => {
  modal(html`${mHead('LIFEBOAT in 60 seconds', 'You do not need to remember any of this. The screens tell you what to do next.')}
    <div class="modal-body">
      <ol class="col">
        <li><b>Something wrong? Click "Declare incident".</b> One sentence, pick a type, pick how bad. The right checklist loads automatically.</li>
        <li><b>Log as you go.</b> On an incident, type in the bar at the top and press Enter. Every entry is timestamped in UTC. This becomes your official timeline.</li>
        <li><b>Follow "Next up".</b> It shows the next steps for the current phase. Tick them off.</li>
        <li><b>Record affected data in "Scope & Data".</b> Say what data, what state (encrypted, stolen…) and where people live. Legal deadlines calculate themselves.</li>
        <li><b>Talk in the incident Room</b>, not email. Tick <b>URGENT</b> when everyone must see it; you'll see who has acknowledged.</li>
        <li><b>Call people from "Contacts"</b>. Assume the normal directory and email are compromised.</li>
      </ol>
      <div class="grid g2 small"><div><kbd>Ctrl</kbd> + <kbd>K</kbd> search & jump anywhere</div><div><kbd>D</kbd> declare incident</div><div><kbd>/</kbd> jump to the log bar</div><div><kbd>?</kbd> this help</div><div><kbd>Esc</kbd> close / exit</div><div><kbd>W</kbd> wallboard</div></div>
    </div>
    <div class="modal-foot"><button class="btn primary" data-a="closeModal">Got it</button></div>`);
};
document.addEventListener('keydown', (e) => {
  if (!S.me) return;
  const typing = e.target.closest?.('input, textarea, select, [contenteditable]');
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); if (modalOpen()) closeModal(); else A.palette(); return; }
  if (e.key === 'Escape') { if (modalOpen()) closeModal(); else if (parts()[0] === 'wall') location.hash = '#/'; return; }
  if (typing || modalOpen() || e.ctrlKey || e.metaKey || e.altKey) return;
  if (e.key === '?') { e.preventDefault(); A.help(); }
  else if (e.key === 'd' && can('incident.create')) { e.preventDefault(); A.declare(); }
  else if (e.key === 'w') { location.hash = '#/wall'; }
  else if (e.key === '/') { e.preventDefault(); const s = $('#scribe-text'); if (s) s.focus(); else A.palette(); }
});
addEventListener('focus', () => { const c = currentChannel(); if (c && S.unread[c]) { markRead(c); updateChrome(); } });

// ================================================================ BOOT
(async function boot() {
  try {
    const me = await api('GET', '/api/me', undefined, { quiet401: true });
    await startSession(me);
  } catch {
    renderAuth();
  }
})();
