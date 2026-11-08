'use strict';
/* WINDX views. Depends on core.js. */

const can = (p) => !!S.perms[p];
const UI = { tlKind: 'all', tlStruck: false, taskMine: false, incFilter: 'active', incSearch: '', auditQ: '' };
let current = null;

// Title Case for headings: capitalize each word except short joining words.
const SMALL_WORDS = new Set(['a', 'an', 'and', 'as', 'at', 'but', 'by', 'for', 'in', 'of', 'on', 'or', 'the', 'to', 'via', 'with']);
const titleCase = (t) => String(t).split(' ').map((w, i, a) => (i > 0 && i < a.length - 1 && SMALL_WORDS.has(w.toLowerCase()) ? w.toLowerCase() : w.charAt(0).toUpperCase() + w.slice(1))).join(' ');

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
          ${authState.prefill ? html`<p class="small muted">Switching to <b>${authState.prefill.name}</b>. Enter their password and 6-digit code.</p>` : ''}
          <label class="field">Username<input name="username" id="li-user" autocomplete="username" autocapitalize="none" spellcheck="false" required ${authState.prefill ? raw(`value="${esc(authState.prefill.username)}"`) : raw('autofocus')}></label>
          <label class="field">Password<input type="password" name="password" id="li-pass" autocomplete="current-password" required ${authState.prefill ? raw('autofocus') : ''}></label>
          <label class="field">6-digit code from your authenticator app<input name="totp" id="li-code" class="code-input" inputmode="numeric" autocomplete="one-time-code" maxlength="6" pattern="[0-9]{6}" required placeholder="••••••"></label>
          <div id="auth-err"></div>
          <button class="btn primary block xl">${icon('lock')} Sign in</button>
        </form>` : html`
        ${st.setupPending ? html`<p class="small muted">First time? Use the <b>administrator username and one-time code</b> printed in the WINDX server console.</p>` : html`<p class="small muted">Your administrator gave you a one-time code in person or by phone.</p>`}
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
      <div class="auth-brand">${LOGO}<h1>WINDX</h1><p>Out-of-band incident command</p></div>
      ${st.lockdown ? html`<div class="banner lockdown" >LOCKDOWN IN EFFECT: administrators only</div><br>` : ''}
      ${notice ? html`<div class="error-box">${notice}</div><br>` : ''}
      <div class="panel col">${body}</div>
      <div class="auth-foot">
        <span class="lock-icon">${icon('lock')} ${st.tls ? 'Encrypted connection' : 'Local connection'}</span> · Encrypted at rest · Every action audited<br>
        Never enter your WINDX password into any other system.
        <span class="brand-credit">Built for the Winstead PC Cyber Incident Response Dashboard challenge</span>
      </div>
    </div></div>`);
  const code = $('#li-code');
  if (code) code.addEventListener('input', () => { code.value = code.value.replace(/\D/g, ''); if (code.value.length === 6 && $('#li-user').value && $('#li-pass').value) code.form.requestSubmit(); });
  const en = $('#en-code');
  if (en) en.addEventListener('input', () => { en.value = en.value.replace(/\D/g, ''); if (en.value.length === 6) en.form.requestSubmit(); });
  const pre = authState.prefill;
  authState.prefill = null;
  if (pre && m === 'login') {
    $('#li-pass')?.focus();
    // The online demo knows every demo user's code, so it can finish the switch by itself.
    if (window.__lifeboatDemo) window.__lifeboatDemo.signIn(pre.username);
  }
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
  closeMeMenu();
  await api('POST', '/api/auth/logout', {}).catch(() => {});
  sessionEnded('You have signed out.');
};

// ---- profile menu (under your name, top right)
function closeMeMenu() {
  const m = $('#me-menu');
  if (m && !m.hidden) { m.hidden = true; $('#me-btn')?.setAttribute('aria-expanded', 'false'); }
}
function meMenuHTML() {
  return html`
    <div class="me-head">${avatar(S.me.id, false, true)}<div><b>${S.me.displayName}</b><small>${S.roles[S.me.role]} · @${S.me.username}</small></div></div>
    <a class="me-item" role="menuitem" href="#/me">${icon('users')}<span class="grow">My profile<small>Your account, role and what you can do</small></span></a>
    <a class="me-item" role="menuitem" href="#/me/history">${icon('clock')}<span class="grow">My activity<small>Everything you have done, by date</small></span></a>
    ${can('admin') ? html`<div class="me-sep"></div><div class="me-label">Administrator</div>
    <a class="me-item" role="menuitem" href="#/admin/people">${icon('users')}<span class="grow">Team &amp; Access<small>Add people, change roles, reset sign-ins</small></span></a>
    <button type="button" class="me-item lockdown-item" role="menuitem" data-a="lockdownOpen">${icon('lock')}<span class="grow">Lockdown<small>Sign everyone out right now</small></span></button>` : ''}
    <div class="me-sep"></div>
    <button type="button" class="me-item" role="menuitem" data-a="help">${icon('help')}<span class="grow">Help</span></button>
    <button type="button" class="me-item danger" role="menuitem" data-a="logout">${icon('logout')}<span class="grow">Sign out</span></button>`;
}
A.meMenu = () => {
  const m = $('#me-menu');
  if (!m) return;
  if (!m.hidden) return closeMeMenu();
  setHTML(m, meMenuHTML());
  m.hidden = false;
  $('#me-btn').setAttribute('aria-expanded', 'true');
};
document.addEventListener('click', (e) => {
  const m = $('#me-menu');
  if (!m || m.hidden) return;
  if (!e.target.closest('.me-wrap') || e.target.closest('.me-item')) closeMeMenu();
}, true);
document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeMeMenu(); });

A.switchUser = async (t) => {
  const username = t.dataset.u;
  closeMeMenu();
  await api('POST', '/api/auth/logout', {}).catch(() => {});
  authState.mode = 'login';
  authState.prefill = { username, name: t.dataset.name };
  sessionEnded(null);
};

async function startSession(me) {
  Object.assign(S, { me: me.user, csrf: me.csrf, perms: me.perms, roles: me.roles, idleMs: me.idleMinutes * 60e3, tls: me.tls });
  if (me.user.mustChangePassword) return renderPasswordChange();
  S.serverOffset = new Date(me.serverTime).getTime() - Date.now();
  lastTouch = Date.now();
  await resync();
  S.loaded = true;
  if (location.hash.startsWith('#/wall')) route(); else { renderShell(); route(); }
  connectStream();
}
// Shown once, right after someone signs in with the temporary password from their sign-in card.
function renderPasswordChange() {
  setHTML('#app', html`
    <div class="auth"><div class="auth-card">
      <div class="auth-brand">${LOGO}<h1>WINDX</h1><p>Welcome, ${S.me.displayName.split(' ')[0]}</p></div>
      <div class="panel col">
        <h2>Choose your own password</h2>
        <p class="small muted">You signed in with the temporary password from your sign-in card. Pick a new one that only you know. Use at least 12 characters; a short sentence is easy to remember and hard to guess.</p>
        <form data-submit="firstPassword" class="col">
          <label class="field">New password<input type="password" name="newPassword" id="np-1" autocomplete="new-password" minlength="12" required autofocus></label>
          <label class="field">Type it again<input type="password" name="again" id="np-2" autocomplete="new-password" minlength="12" required></label>
          <div id="auth-err"></div>
          <button class="btn primary block xl">Save password and continue</button>
        </form>
        <button type="button" class="btn ghost sm" data-a="logout">Sign out</button>
      </div>
    </div></div>`);
  setTimeout(() => $('#np-1')?.focus(), 30);
}
A.firstPassword = async (f) => {
  const d = formData(f);
  if (d.newPassword !== d.again) return authErr('The two passwords do not match.');
  if (d.newPassword.length < 12) return authErr('Use at least 12 characters.');
  const btn = $('button.primary', f); btn.disabled = true;
  try {
    await api('POST', '/api/auth/password', { newPassword: d.newPassword });
    await startSession(await api('GET', '/api/me'));
    toast('Password saved. You are signed in.', 'ok');
  } catch (e) { authErr(e.message); btn.disabled = false; }
};

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
      <a class="brand" href="#/">${LOGO}<span>WINDX<small id="org-name">${S.org.name}</small></span></a>
      <button type="button" class="searchbar" data-a="palette" aria-label="Search incidents, channels and actions (Ctrl K)">
        ${icon('search')}<span class="searchbar-text">Jump to…</span><kbd>Ctrl K</kbd>
      </button>
      <span class="grow"></span>
      <div class="clocks"><span><b id="clock-utc">--:--:--</b> UTC</span><span class="local"><b id="clock-local">--:--</b> local</span></div>
      <span id="conn" class="conn"></span>
      <div id="online" class="online-stack"></div>
      <button class="iconbtn" data-a="help" title="Help (?)">${icon('help')}</button>
      <button class="iconbtn" data-a="theme" title="Light / dark">${icon('moon')}</button>
      <div class="me-wrap">
        <button type="button" class="me-btn" id="me-btn" data-a="meMenu" aria-haspopup="menu" aria-expanded="false" title="Your profile, activity and sign out">
          <span id="me-av"></span><span class="me-name"><b>${S.me.displayName}</b></span>
          <svg class="caret" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M6 9l6 6 6-6"/></svg>
        </button>
        <div class="me-menu" id="me-menu" role="menu" hidden></div>
      </div>
    </header>
    <nav class="sidebar" id="side"></nav>
    <main class="main" id="main"><div id="banners"></div><div id="view" class="view"></div></main>
    <aside id="room-drawer" class="room-drawer" hidden aria-label="Incident room">
      <button type="button" class="room-x" data-a="toggleRoom" aria-label="Close the incident room">×</button>
      <div id="room-body" class="room-body"></div>
    </aside>
  </div>`);
  document.body.classList.toggle('nav-collapsed', !!store.get('navCollapsed', false));
  setConn(S.conn);
  updateChrome();
}

function updateChrome() {
  if (!$('#side') || !S.me) return;
  const p = parts();
  const activeIncs = allIncidents().filter(isActive);
  const unread = Object.values(S.unread).reduce((a, b) => a + b, 0);
  const nav = (href, ic, label, on, badge) => html`<a class="nav ${on ? 'active' : ''}" href="${href}" title="${label}">${icon(ic)}<span>${label}</span>${badge ? html`<span class="badge">${badge}</span>` : ''}</a>`;
  const collapsed = document.body.classList.contains('nav-collapsed');
  setHTML('#side', html`
    <button type="button" class="nav-toggle" data-a="toggleNav" aria-expanded="${collapsed ? 'false' : 'true'}" aria-label="${collapsed ? 'Expand the menu' : 'Collapse the menu'}" title="${collapsed ? 'Expand the menu' : 'Collapse the menu'}">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="${collapsed ? 'M9 18l6-6-6-6' : 'M15 18l-6-6 6-6'}"/></svg></button>
    ${nav('#/', 'home', 'Home', !p[0])}
    ${nav('#/incidents', 'alert', 'Incidents', p[0] === 'incidents', activeIncs.length || '')}
    ${nav('#/deadlines', 'scale', 'Legal Deadlines', p[0] === 'deadlines', dueSoonCount() || '')}
    ${nav('#/comms', 'chat', 'Comms', p[0] === 'comms', unread || '')}
    ${nav('#/contacts', 'phone', 'Contacts', p[0] === 'contacts')}
    ${nav('#/wall', 'tv', 'Wallboard', false)}
    ${can('admin') ? nav('#/admin', 'shield', 'Admin', p[0] === 'admin') : can('audit.read') ? nav('#/admin/audit', 'shield', 'Audit Log', p[0] === 'admin') : ''}
    ${activeIncs.length ? html`<div class="nav-sep"></div><div class="nav-label">ACTIVE INCIDENTS</div>
      ${activeIncs.map((i) => html`<a class="side-incident ${p[0] === 'i' && p[1] === i.id ? 'active' : ''}" href="#/i/${i.id}" title="${i.codename}">${sevChip(i.severity, false)}<span class="grow nowrap">${i.codename}</span></a>`)}` : ''}
    <span class="grow side-extra"></span>
    ${can('incident.create') ? html`<button class="btn primary block side-extra side-declare" data-a="declare" title="Declare incident">${icon('zap')}<span>Declare incident</span></button>` : ''}
  `);
  setHTML('#online', [...S.online].slice(0, 6).map((id) => avatar(id, true)));
  setHTML('#me-av', avatar(S.me.id, true, true));
  const urgent = urgentPending();
  setHTML('#banners', html`
    ${S.lockdown?.on ? html`<div class="banner lockdown">${icon('lock')} LOCKDOWN ACTIVE · Only administrators can use WINDX right now</div>` : ''}
    ${!S.tls ? html`<div class="banner insecure">Running without HTTPS (local only). Run <span class="mono">npm run cert</span> before use on a network.</div>` : ''}
    ${urgent.length ? html`<div class="banner urgent" data-a="goUrgent">${icon('bell')} ${urgent.length} urgent message${urgent.length > 1 ? 's' : ''} waiting for your acknowledgment. Click to view</div>` : ''}`);
  const sev1 = activeIncs.filter((i) => i.severity === 1).length;
  document.title = `${unread ? `(${unread}) ` : ''}${sev1 ? 'SEV1 · ' : ''}WINDX`;
}
A.toggleNav = () => {
  const c = !document.body.classList.contains('nav-collapsed');
  document.body.classList.toggle('nav-collapsed', c);
  store.set('navCollapsed', c);
  updateChrome();
};
A.goUrgent = () => { const m = urgentPending()[0]; if (m) location.hash = '#/comms/' + m.channelId; };
A.theme = () => applyTheme(S.theme === 'dark' ? 'light' : 'dark');

// ================================================================ ROUTER
function parts() { return location.hash.replace(/^#\/?/, '').split('/').filter(Boolean).map(decodeURIComponent); }
addEventListener('hashchange', route);

// ---- Back button: remembers the pages visited inside WINDX
const visited = [];
function trackVisit() {
  const h = location.hash || '#/';
  if (visited.length > 1 && visited[visited.length - 2] === h) visited.pop(); // came here by going back
  else if (visited[visited.length - 1] !== h) visited.push(h);
}
const atHome = () => !parts()[0];
function updateBackButton() {
  for (const b of $$('[data-a="goBack"]')) {
    const off = visited.length <= 1 && atHome();
    b.disabled = off;
    b.title = off ? 'You are on the home page' : 'Go back to the previous page';
  }
}
A.goBack = () => {
  if (visited.length > 1) history.back();
  else if (!atHome()) location.hash = '#/';
};
document.addEventListener('keydown', (e) => { if (e.altKey && e.key === 'ArrowLeft' && S.me) { e.preventDefault(); A.goBack(); } });
const backButton = () => html`<button type="button" class="back-btn" data-a="goBack" aria-label="Back">
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M15 18l-6-6 6-6"/></svg><span>Back</span></button>`;

function route() {
  if (!S.me || !S.loaded) return;
  trackVisit();
  const [a, b, c] = parts();
  if (a === 'wall') {
    current = WallView();
    current.mount($('#app'));
    updateBackButton();
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
  else if (a === 'me') v = b === 'history' ? HistoryView() : ProfileView();
  else if (a === 'deadlines') v = DeadlinesView();
  else v = { mount(el) { setHTML(el, html`<div class="empty"><h2>Page not found</h2><p><a href="#/">Back to Home</a></p></div>`); } };
  current = v;
  const wantRoom = v.incId && v.tab !== 'report' && (v.tab === 'room' || UI.roomOpen) ? v.incId : null;
  if (v.incId && v.tab === 'room') UI.roomOpen = true;
  const view = $('#view');
  view.className = 'view' + (v.flush ? ' flush' : '');
  const sameIncident = prev?.incId && prev.incId === v.incId;
  if (!sameIncident) $('#main').scrollTop = 0;
  view.innerHTML = '';
  v.mount(view);
  setRoom(wantRoom);
  updateChrome();
  updateBackButton();
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
      <div><h1>${greet}, <span class="keep-case">${S.me.displayName.split(' ')[0]}</span>.</h1>
      <p>${active.length ? html`<b>${active.length}</b> active incident${active.length > 1 ? 's' : ''}. ${overdue.length ? html`<b class="cd over">${overdue.length} deadline${overdue.length > 1 ? 's' : ''} overdue</b>` : in72.length ? `${in72.length} deadline${in72.length > 1 ? 's' : ''} in the next 72 hours.` : ''}` : 'All clear. No active incidents.'}</p></div>
      ${can('incident.create') ? html`<button class="btn primary xl" data-a="declare">${icon('zap')} Declare an incident</button>` : ''}
    </div>

    ${setupLeft.length ? html`<div class="next-up"><h3>Get ready before you need it · ${setup.length - setupLeft.length}/${setup.length} done</h3>
      <div class="row wrap">${setup.map(([l, ok, href]) => html`<a class="btn sm ${ok ? 'ghost' : ''}" href="${href}">${ok ? icon('check') : icon('arrow')} ${l}</a>`)}</div></div>` : ''}

    <div class="grid g4">
      <div class="panel stat ${active.length ? 'alert' : ''}"><div class="n">${active.length}</div><div class="l">Active Incidents</div></div>
      <div class="panel stat ${active.some((i) => i.severity === 1) ? 'alert' : ''}"><div class="n">${active.filter((i) => i.severity === 1).length}</div><div class="l">SEV1 Critical</div></div>
      <div class="panel stat ${overdue.length ? 'alert' : ''}"><div class="n">${in72.length}</div><div class="l">Legal Deadlines ≤ 72h${overdue.length ? html` · <span class="cd over">${overdue.length} overdue</span>` : ''}</div></div>
      <div class="panel stat"><div class="n">${myTasks.length}</div><div class="l">Tasks Assigned to Me</div></div>
    </div>
    <br>
    <div class="grid g-main">
      <div class="col">
        <section class="panel">
          <div class="panel-head"><h3>${icon('alert')} Active Incidents</h3><a class="small" href="#/incidents">All incidents ${icon('arrow')}</a></div>
          ${active.length ? active.map(incCard) : html`<div class="empty">${icon('shield')}<h3>All clear</h3><p>When something looks wrong, declare an incident. It takes 20 seconds and loads the right checklist automatically.</p>
            ${can('incident.create') ? html`<button class="btn primary" data-a="declare">${icon('zap')} Declare an incident</button>` : ''}</div>`}
        </section>
        <section class="panel">
          <div class="panel-head"><h3>${icon('activity')} Latest Activity</h3></div>
          <div class="panel-body tight">${activity.length ? activity.map(({ e, i }) => html`<a class="list-item click" href="#/i/${i.id}/timeline">
            <span class="mono tiny dim nowrap">${fmtTimeUTC(e.at)}</span><span class="chip k-${e.kind}">${e.kind}</span><span class="grow">${e.text}</span><span class="tiny muted nowrap">${i.codename}</span></a>`) : html`<div class="empty small">Nothing yet.</div>`}</div>
        </section>
      </div>
      <div class="col">
        <section class="panel">
          <div class="panel-head"><h3>${icon('scale')} Notification Clock</h3><span class="tiny muted">Legal & contractual deadlines</span></div>
          ${deadlines.length ? deadlines.slice(0, 8).map(({ o, i }) => deadlineRow(o, i)) : html`<div class="empty small">No running deadlines. Record compromised data in an incident's <b>Scope</b> tab and deadlines are worked out for you.</div>`}
        </section>
        <section class="panel">
          <div class="panel-head"><h3>${icon('check')} My Tasks</h3></div>
          ${myTasks.length ? myTasks.slice(0, 10).map(({ t, i }) => html`<a class="list-item click" href="#/i/${i.id}/tasks"><span class="chip">${phaseById(t.phase).short}</span><span class="grow">${t.title}</span><span class="tiny muted">${i.codename}</span></a>`) : html`<div class="empty small">Nothing assigned to you.</div>`}
        </section>
        <section class="panel">
          <div class="panel-head"><h3>${icon('users')} Response Team</h3><span class="tiny muted">${S.online.size} online</span></div>
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
      setHTML(el, html`<div class="page-head"><div><div class="title-row">${backButton()}<h1>Incidents</h1></div><p>Every incident, newest and most severe first.</p></div>
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

// Every section of an incident lives on one scrolling page; the bar at the top jumps between them.
// Only the printable report keeps its own view.
// The chat room is a panel on the right, not a section, so it stays open while you scroll the case.
const SECTIONS = TABS.filter(([k]) => k !== 'report' && k !== 'room');
const SECTION_BODY = { overview: (i) => tabOverview(i), timeline: (i) => tabTimeline(i), scope: (i) => tabScope(i), tasks: (i) => tabTasks(i), obligations: (i) => tabObligations(i), iocs: (i) => tabIocs(i), evidence: (i) => tabEvidence(i) };
function jumpTo(sec, smooth = true) {
  const el = document.getElementById('sec-' + sec);
  if (el) el.scrollIntoView({ behavior: smooth && !matchMedia('(prefers-reduced-motion: reduce)').matches ? 'smooth' : 'auto', block: 'start' });
}
A.jumpSec = (t) => jumpTo(t.dataset.sec);

// ---- incident room panel (right side)
let roomFor = null; // id of the incident whose room is open
function drawRoom() {
  const d = $('#room-drawer');
  if (!d) return;
  const ch = roomFor && S.channels.find((c) => c.incidentId === roomFor);
  if (!ch) { d.hidden = true; document.body.classList.remove('room-open'); return; }
  setHTML('#room-body', chatPane(ch));
  d.hidden = false;
  document.body.classList.add('room-open');
  if (document.hasFocus()) markRead(ch.id);
}
function setRoom(id) {
  const wasClosed = !roomFor;
  roomFor = id;
  drawRoom();
  if (id && wasClosed) { scrollChat(); setTimeout(() => $('#room-drawer textarea')?.focus(), 60); }
  const inc = current?.incId && S.inc.get(current.incId);
  if (inc && $('#inc-tabs')) setHTML('#inc-tabs', tabsHTML(inc, current.tab));
  updateChrome();
}
A.toggleRoom = () => {
  UI.roomOpen = !roomFor;
  setRoom(roomFor ? null : current?.incId || null);
};

function IncidentView(id, tab) {
  const report = tab === 'report';
  const roomOf = () => S.channels.find((c) => c.incidentId === id);
  return {
    incId: id, tab,
    channelId() { return roomFor === id ? roomOf()?.id : null; },
    mount(el) {
      this.el = el;
      this.update();
      if (!report && tab !== 'overview' && tab !== 'room') requestAnimationFrame(() => jumpTo(tab, false));
    },
    update(what, xid) {
      const ch = roomOf();
      if (what === 'message' || what === 'ack' || what === 'presence') {
        // Chat activity only redraws the room panel and the badge, so the case page stays put.
        const inc = S.inc.get(id);
        if (!inc) return;
        if (roomFor === id && (what === 'presence' || xid === ch?.id)) drawRoom();
        if ($('#inc-tabs')) setHTML('#inc-tabs', tabsHTML(inc, tab));
        return;
      }
      if (what === 'incident' && xid !== id) return;
      const inc = S.inc.get(id);
      if (!inc) { setHTML(this.el, html`<div class="empty"><h2>Incident not found</h2><p>It may be restricted to need-to-know members.</p><a href="#/">Back to Home</a></div>`); return; }
      setHTML(this.el, incidentHTML(inc, tab));
      if (roomFor === id && what === 'incident') drawRoom();
    },
  };
}

function tabsHTML(inc, tab) {
  const ch = S.channels.find((c) => c.incidentId === inc.id);
  const over = openObligations(inc).filter((o) => o.dueAt && new Date(o.dueAt).getTime() < nowMs()).length;
  const counts = {
    timeline: live(inc.timeline).length, scope: live(inc.scope).length, tasks: live(inc.tasks).filter((t) => t.status !== 'done').length,
    obligations: openObligations(inc).length, iocs: live(inc.iocs).length, evidence: inc.evidence.length, room: ch ? S.unread[ch.id] || 0 : 0,
  };
  const report = tab === 'report';
  return TABS.map(([k, l, ic]) => {
    // On the main page each item scrolls to its section; from the report view they lead back to it.
    const jump = !report && k !== 'report' && k !== 'room';
    const room = k === 'room';
    return html`<a class="tab ${(report && k === 'report') || (room && roomFor === inc.id) ? 'active' : ''}" href="#/i/${inc.id}/${k}" ${jump ? raw(`data-a="jumpSec" data-sec="${k}"`) : room ? raw(`data-a="toggleRoom" title="${roomFor === inc.id ? 'Close' : 'Open'} the incident chat"`) : ''}>${icon(ic)}${l}${counts[k] ? html`<span class="badge ${(k === 'obligations' && over) || (k === 'room' && counts.room) ? 'hot' : ''}">${counts[k]}</span>` : ''}</a>`;
  });
}

function incidentHTML(inc, tab) {
  const idx = phaseIndex(inc.status);
  const w = can('incident.write');
  const report = tab === 'report';
  return html`
    ${inc.privileged ? html`<div class="banner priv">${icon('scale')} PRIVILEGED & CONFIDENTIAL · ATTORNEY-CLIENT COMMUNICATION / ATTORNEY WORK PRODUCT · PREPARED AT THE DIRECTION OF COUNSEL</div>` : ''}
    <div class="inc-head">
      <div class="grow">
        <div class="row wrap">${sevChip(inc.severity)}<span class="mono">${inc.ref}</span><span class="codename">${inc.codename}</span><span class="chip">${S.categories[inc.category]}</span>
          ${inc.access === 'restricted' ? html`<span class="chip" title="Need-to-know">${icon('lock')} Need-to-know</span>` : ''}${inc.status === 'closed' ? html`<span class="chip">CLOSED</span>` : ''}</div>
        <div class="title-row">${backButton()}<h1 ${w ? raw('data-a="editFact" data-k="title"') : ''} title="${w ? 'Click to rename' : ''}">${inc.title}</h1></div>
        <div class="small muted">Lead ${userName(inc.leadId)} · Detected ${fmtUTC(inc.detectedAt)} · Updated ${ago(inc.updatedAt)}</div>
      </div>
      <div class="big-clock">${since(inc.detectedAt, inc.closedAt)}<div class="small muted">${inc.closedAt ? 'total duration' : 'since detection'}</div></div>
    </div>
    <div class="phases">${S.phases.slice(0, 5).map((p, i) => html`<button type="button" class="phase ${i < idx || inc.status === 'closed' ? 'done' : i === idx ? 'cur' : ''}" ${w ? raw(`data-a="setPhase" data-phase="${p.id}"`) : ''} title="${p.hint}">
      <div class="n">${i < idx || inc.status === 'closed' ? '✓ ' : ''}STEP ${i + 1}</div><div class="t">${p.label}</div><div class="h">${p.hint}</div></button>`)}
      ${can('incident.manage') ? (inc.status === 'closed' ? html`<button type="button" class="btn" data-a="setPhase" data-phase="post">Reopen</button>` : html`<button type="button" class="btn" data-a="setPhase" data-phase="closed">${icon('check')} Close</button>`) : ''}
    </div>
    <div class="inc-sticky">
    ${w && inc.status !== 'closed' && !report ? html`<form class="scribe" data-submit="scribe" data-id="${inc.id}">
      <div class="kinds">${['action', 'finding', 'decision'].map((k) => html`<button type="button" class="k-${k} ${S.scribeKind === k ? 'on' : ''}" data-a="scribeKind" data-k="${k}">${k[0].toUpperCase() + k.slice(1)}</button>`)}</div>
      <input type="text" id="scribe-text" data-keep autocomplete="off" maxlength="4000" placeholder="What just happened? Type and press Enter. It is timestamped for you.">
      <input type="datetime-local" id="scribe-at" data-keep class="${UI.backdate ? '' : 'hidden'}" title="When it happened (local time)">
      <button type="button" class="iconbtn" data-a="backdate" title="Log at a different time">${icon('clock')}</button>
      <button class="btn primary sm">Log</button>
    </form>` : ''}
    <nav class="tabs" id="inc-tabs">${tabsHTML(inc, tab)}</nav>
    </div>
    ${report
      ? html`<div class="row no-print"><a class="btn sm ghost" href="#/i/${inc.id}">← Back to the incident</a></div><br><div id="tab-body">${tabReport(inc)}</div>`
      : html`<div class="inc-sections">${SECTIONS.map(([k, l, ic]) => html`<section class="inc-sec" id="sec-${k}">
          <h2 class="sec-title">${icon(ic)} ${l}</h2><div id="sec-${k}-body">${SECTION_BODY[k](inc)}</div></section>`)}</div>`}`;
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
  const fact = (k, label, val, editable = w) => html`<dt>${label}</dt><dd>${editable ? html`<span class="editable" data-a="editFact" data-k="${k}">${val || html`<span class="dim">Not set (click to add)</span>`}</span>` : val || html`<span class="dim">-</span>`}</dd>`;
  return html`
    ${inc.status !== 'closed' ? html`<div class="next-up">
      <h3>Next up · ${phase.label}: ${phase.hint}</h3>
      ${phaseTasks.length ? phaseTasks.slice(0, 4).map((t) => taskRow(inc, t, true)) : html`<p class="muted small">Checklist for this phase is complete.</p>`}
      <div class="row wrap"><a class="btn sm ghost" href="#/i/${inc.id}/tasks" data-a="jumpSec" data-sec="tasks">See full checklist ${icon('arrow')}</a><span class="grow"></span>
      ${w && nextPhase && nextPhase.id !== 'closed' ? html`<button class="btn sm ${phaseTasks.length ? '' : 'primary'}" data-a="setPhase" data-phase="${nextPhase.id}">Move to ${nextPhase.label} ${icon('arrow')}</button>` : ''}</div>
    </div>` : ''}
    <div class="grid g-main">
      <div class="col">
        <section class="panel"><div class="panel-head"><h3>${icon('file')} Situation</h3>${w ? html`<button class="btn sm ghost" data-a="editFact" data-k="summary">${icon('edit')} Edit</button>` : ''}</div>
          <div class="panel-body prewrap">${inc.summary || html`<span class="dim">No summary yet. Write 2-3 sentences anyone could understand: what happened, what's affected, what we're doing.</span>`}</div></section>
        <section class="panel"><div class="panel-head"><h3>${icon('list')} Key Facts</h3><span class="tiny muted">Click any value to update</span></div>
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
      </div>
      <div class="col">
        <section class="panel"><div class="panel-head"><h3>${icon('users')} Who Can See This</h3>${can('incident.manage') ? html`<button class="btn sm ghost" data-a="manageAccess">${icon('lock')} Manage</button>` : ''}</div>
          <div class="panel-body small">${inc.access === 'restricted' ? html`<p><b>Need-to-know.</b> Only these people (plus administrators):</p><div class="row wrap">${[...new Set([inc.leadId, inc.createdBy, ...(inc.members || [])])].map((id) => html`<span class="row">${avatar(id, true, true)} ${userName(id)}</span>`)}</div>` : inc.privileged ? html`<p><b>Privileged &amp; Confidential.</b> Visible to Administrators, Incident Commanders and Legal Counsel, plus:</p><div class="row wrap">${[...new Set([inc.leadId, inc.createdBy, ...(inc.members || [])])].filter(Boolean).map((id) => html`<span class="row">${avatar(id, true, true)} ${userName(id)}</span>`)}</div>` : html`<p class="muted">Everyone with a WINDX account can see this incident.</p>`}</div></section>
      </div>
    </div>`;
}

A.manageAccess = () => {
  const inc = curInc();
  const users = S.users.filter((u) => u.status === 'active');
  modal(html`<form id="acc-f">${mHead('Who can see this incident?', 'Restrict when the attacker could be an insider, or the matter is especially sensitive.')}
    <div class="modal-body">
      <label class="check"><input type="radio" name="access" value="all" ${inc.access !== 'restricted' ? raw('checked') : ''}><span><b>Everyone on WINDX</b></span></label>
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
    if (added.length) toast(`Legal: ${added.length} new notification obligation${added.length > 1 ? 's' : ''} triggered: ${added.map((o) => o.title).join('; ')}. Click to review.`, 'urgent', () => (location.hash = `#/i/${inc.id}/obligations`));
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
    if (added.length) toast(`Legal: new obligation triggered: ${added.map((o) => o.title).join('; ')}`, 'urgent', () => (location.hash = `#/i/${inc.id}/obligations`));
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
A.taskDone = (t) => patchTask(t.dataset.id, { status: t.checked ? 'done' : 'open' }, t.checked ? 'Marked done' : 'Reopened');
A.taskStatus = (t) => patchTask(t.dataset.id, { status: t.value }, 'Updated');
A.taskAssign = (t) => patchTask(t.dataset.id, { assigneeId: t.value || null }, t.value ? `Assigned to ${userName(t.value)}` : 'Unassigned');

// ---------- legal obligations
function tabObligations(inc) {
  const L = can('legal.write');
  const obs = inc.obligations;
  const hasScope = live(inc.scope).length > 0;
  return html`
    <div class="grid g2">
      <section class="panel"><div class="panel-head"><h3>${icon('scale')} Legal Determinations</h3></div><div class="panel-body"><dl class="facts">
        <dt>Discovered</dt><dd class="mono">${fmtUTC(inc.detectedAt)}</dd>
        <dt>Breach determined</dt><dd>${L ? html`<span class="editable" data-a="editFact" data-k="breachDeterminedAt">${inc.breachDeterminedAt ? fmtUTC(inc.breachDeterminedAt) : 'Not yet. Click to record'}</span>` : fmtUTC(inc.breachDeterminedAt)}<div class="tiny dim">State-law clocks run from here once set (until then, from discovery).</div></dd>
        ${S.org.publiclyTraded ? html`<dt>Materiality (SEC)</dt><dd>${L ? html`<span class="editable" data-a="editFact" data-k="materialityDeterminedAt">${inc.materialityDeterminedAt ? fmtUTC(inc.materialityDeterminedAt) : 'Not yet. Click to record'}</span>` : fmtUTC(inc.materialityDeterminedAt)}<div class="tiny dim">8-K due 4 business days after.</div></dd>` : ''}
      </dl></div></section>
      <section class="panel"><div class="panel-head"><h3>${icon('shield')} Why These Appear</h3></div><div class="panel-body small muted">
        WINDX reads the <b>Scope</b> tab (data types and where people live), the incident type, and your organization profile
        (${[S.org.publiclyTraded && 'public company', S.org.hipaaCovered && 'HIPAA', S.org.nydfsRegulated && 'NYDFS', S.org.criticalInfrastructure && 'critical infrastructure'].filter(Boolean).join(', ') || 'no special regulators set'}).
        It then lists who must be told, and by when. ${!hasScope ? html`<br><br><b class="cd soon">Add affected data in Scope to unlock state, GDPR and HIPAA deadlines.</b>` : ''}</div></section>
    </div><br>
    <section class="panel">${obs.map((o) => { const done = o.status === 'done' || o.status === 'na'; return html`<div class="ob ${done ? 'done' : ''}">
      <div><div class="row wrap"><b>${o.title}</b><span class="chip lvl-${o.level}">${o.level}</span></div>
        <div class="who">${o.who}</div><div class="cite">${o.cite}</div><div class="why">${o.why}</div>
        ${o.notes ? html`<div class="small prewrap"><b>Notes:</b> ${o.notes}</div>` : ''}
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
      <p class="tiny"><br>Generated by WINDX. Source records are held in an encrypted, tamper-evident system of record.</p>
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
        ${w && contacts.length < 4 ? html`<div class="next-up"><h3>Quick Add</h3><div class="row wrap">${CONTACT_PRESETS.map((p, i) => html`<button class="btn sm" data-a="presetContact" data-i="${i}">${icon('plus')} ${p.name}</button>`)}</div></div>` : ''}
        <div class="grid g2">
          ${ins.carrier || oc.firm ? html`<section class="panel"><div class="panel-head"><h3>${icon('scale')} Insurance & Counsel</h3></div>
            ${ins.carrier ? card({ name: ins.carrier, role: 'Cyber insurance · notify within ' + (ins.noticeHours || 72) + 'h', org: ins.policy ? 'Policy ' + ins.policy : '', phone: ins.hotline }) : ''}
            ${oc.firm ? card({ name: oc.contact || oc.firm, role: 'Outside breach counsel', org: oc.firm, phone: oc.phone }) : ''}</section>` : ''}
          ${groups.map(([g, l]) => html`<section class="panel"><div class="panel-head"><h3>${titleCase(g)}</h3><span class="badge">${l.length}</span></div>${l.map(card)}</section>`)}
          <section class="panel"><div class="panel-head"><h3>${icon('users')} Response Team</h3></div>
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
  const tabs = can('admin') ? [['people', 'Team & Access', 'users'], ['sessions', 'Sessions', 'key'], ['audit', 'Audit Log', 'shield'], ['org', 'Organization', 'sliders'], ['system', 'Security & System', 'lock']] : [['audit', 'Audit Log', 'shield']];
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
  const status = (u) => u.status === 'active' ? html`<span class="chip st st-secured">Active</span>`
    : u.status === 'invited' ? html`<span class="chip st st-at-risk">Invited</span><div class="tiny dim">${u.mustChangePassword ? 'Has not set a password yet' : 'Has not finished setup'}</div>`
    : html`<span class="chip st st-encrypted">Disabled</span>`;
  return html`<div class="team-head">
      <div><h2>Team &amp; Access</h2><p class="muted small">Each new person gets a one-time <b>sign-in card</b>. Hand it over in person. Never send it by email or chat, which the attacker may be reading.</p></div>
      <button class="btn primary xl" data-a="invite">${icon('plus')} Add a person</button>
    </div>
    <div class="panel table-wrap"><table class="t team-table"><thead><tr><th>Name</th><th>Username</th><th>Role</th><th>Status</th><th>Last sign-in</th><th class="right">Actions</th></tr></thead><tbody>
    ${users.map((u) => { const me = u.id === S.me.id; return html`<tr>
      <td><div class="row">${avatar(u.id, true, true)}<div><b>${u.displayName}</b>${u.title ? html`<div class="tiny muted">${u.title}</div>` : ''}</div></div></td>
      <td class="mono small">${u.username}</td>
      <td><select class="role-select" data-change="setRole" data-id="${u.id}" data-was="${u.role}" aria-label="Role for ${u.displayName}" ${me ? raw('disabled title="You cannot change your own role"') : ''}>${Object.entries(S.roles).map(([k, l]) => html`<option value="${k}" ${k === u.role ? raw('selected') : ''}>${l}</option>`)}</select></td>
      <td>${status(u)}${u.locked ? html` <span class="chip st st-encrypted">Locked 15 min</span>` : ''}</td>
      <td class="small muted nowrap">${u.lastLogin ? fmtUTC(u.lastLogin) : 'Never'}</td>
      <td class="nowrap right">${me ? html`<span class="tiny dim">This is you</span>` : html`
        ${u.locked ? html`<button class="btn sm" data-a="userUnlock" data-id="${u.id}">Unlock</button>` : ''}
        <button class="btn sm" data-a="userReset" data-id="${u.id}" title="Lost phone or suspected compromise">${icon('key')} Reset sign-in</button>
        ${u.status === 'disabled' ? html`<button class="btn sm" data-a="userEnable" data-id="${u.id}">Enable</button>` : html`<button class="btn sm danger" data-a="userDisable" data-id="${u.id}">Disable</button>`}`}</td></tr>`; })}
    </tbody></table></div>
    <p class="tiny dim">Disabling someone, resetting their sign-in, or making someone an Administrator needs a fresh 6-digit code from your authenticator app.</p>`;
}

// Ask for a fresh authenticator code before a dangerous action. The server checks it; the dialog
// stays open on a wrong code so the admin can wait for the next one and try again.
function stepUpModal({ title, intro, okLabel, confirmWord = null, run }) {
  return new Promise((resolve) => {
    let done = false;
    const finish = (v) => { if (!done) { done = true; resolve(v); } };
    modal(html`<form id="su-f" autocomplete="off">${mHead(title)}
      <div class="modal-body">
        <div class="su-intro">${intro}</div>
        ${confirmWord ? html`<label class="field"><span>Type <b class="mono">${confirmWord}</b> to confirm</span><input id="su-word" class="su-word mono" autocomplete="off" autocapitalize="characters" spellcheck="false" placeholder="${confirmWord}"></label>` : ''}
        <label class="field">6-digit code from Microsoft Authenticator
          <span class="hint">Open the app and type the code shown for WINDX. Use a fresh code, not the one you signed in with.</span>
          <input id="su-code" class="code-input su-code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" pattern="[0-9]{6}" placeholder="••••••" ${confirmWord ? '' : raw('autofocus')}></label>
        <div id="su-err" aria-live="assertive"></div>
      </div>
      <div class="modal-foot"><button class="btn" type="button" data-a="closeModal">Cancel</button><button class="btn danger-solid xl" id="su-ok" disabled>${okLabel}</button></div></form>`, { onClose: () => finish(undefined) });
    const code = $('#su-code'), word = $('#su-word'), ok = $('#su-ok');
    const check = () => { code.value = code.value.replace(/\D/g, '').slice(0, 6); ok.disabled = !(/^\d{6}$/.test(code.value) && (!confirmWord || word.value.trim() === confirmWord)); };
    code.addEventListener('input', check);
    word?.addEventListener('input', check);
    if (word) setTimeout(() => word.focus(), 30);
    $('#su-f').onsubmit = async (e) => {
      e.preventDefault();
      if (ok.disabled) return;
      ok.disabled = true; const label = ok.textContent; ok.textContent = 'Checking…';
      try {
        const r = await run(code.value, word?.value.trim());
        finish(r); closeModal();
      } catch (err) {
        setHTML('#su-err', html`<div class="error-box">${err.message}</div>`);
        code.value = ''; ok.textContent = label; check(); code.focus();
      }
    };
  });
}

// The one-time sign-in card: username, temporary password, authenticator QR and key.
function showSignInCard(card, title) {
  const keyGroups = card.secret.match(/.{1,4}/g).join(' ');
  modal(html`${mHead(title, `For ${card.displayName}`)}
    <div class="modal-body">
      <div class="signin-card" id="signin-card">
        <div class="sc-top"><b>WINDX sign-in card</b><span>${card.displayName} · ${S.roles[card.role] || card.role}</span></div>
        <div class="sc-grid">
          <div class="col">
            <div><div class="sc-label">Username</div><div class="sc-value mono">${card.username}</div></div>
            <div><div class="sc-label">Temporary password</div><div class="sc-value mono">${card.tempPassword}</div></div>
            <ol class="sc-steps">
              <li>Open <b>Microsoft Authenticator</b> (or Google Authenticator), tap <b>+</b>, choose <b>Other account</b>, and scan this code.</li>
              <li>Sign in to WINDX with the username, temporary password and the 6-digit code from the app.</li>
              <li>Choose your own password (12+ characters). The temporary one stops working.</li>
            </ol>
          </div>
          <div class="sc-qr-wrap">
            <svg class="qr" viewBox="0 0 ${card.qr.size} ${card.qr.size}" shape-rendering="crispEdges" role="img" aria-label="Authenticator QR code"><rect width="100%" height="100%" fill="#fff"/><path d="${card.qr.path}" fill="#000"/></svg>
            <div class="sc-label">Can't scan? Enter this key</div><div class="sc-key mono">${keyGroups}</div>
          </div>
        </div>
      </div>
      <div class="error-box"><b>Shown only once.</b> Print it or hand it over now. WINDX does not keep the temporary password or this QR code. Give it in person, never by email or chat.</div>
    </div>
    <div class="modal-foot"><button class="btn" type="button" data-a="printCard">${icon('printer')} Print</button><button class="btn primary" type="button" data-a="cardDone">Done, I've handed it over</button></div>`, { wide: true });
}
A.printCard = () => { document.body.classList.add('printing-card'); window.print(); setTimeout(() => document.body.classList.remove('printing-card'), 500); };
A.cardDone = () => closeModal();

A.invite = () => {
  modal(html`<form id="inv-f">${mHead('Add a person', 'They get a one-time sign-in card with a temporary password and an authenticator code.')}
    <div class="modal-body"><div class="form-grid">
      <label class="field">Full name <input name="displayName" id="inv-name" required maxlength="80" placeholder="e.g. Maria Chen" autofocus></label>
      <label class="field">Username <span class="hint">Filled in from the name. You can change it.</span><input name="username" id="inv-user" required maxlength="32" pattern="[a-z0-9._\-]{2,32}" placeholder="maria.chen"></label>
      <label class="field">Job title <span class="hint">Optional</span><input name="title" maxlength="80" placeholder="e.g. IT Director"></label>
      <label class="field">Mobile phone <span class="hint">Optional. Shown in the phone tree</span><input name="phone" maxlength="60" inputmode="tel"></label></div>
      <div class="field"><span>What should they be able to do?</span><input type="hidden" name="role" value="responder">
        <div class="pick-grid">${Object.entries(S.roles).map(([k, l]) => html`<button type="button" class="pick ${k === 'responder' ? 'on' : ''}" data-a="pick" data-group="role" data-v="${k}">${l}<small>${ROLE_DESC[k]}</small></button>`)}</div></div>
    </div><div class="modal-foot"><button class="btn" type="button" data-a="closeModal">Cancel</button><button class="btn primary xl">Create sign-in card</button></div></form>`, { wide: true });
  $('#inv-name').addEventListener('input', (e) => { const u = $('#inv-user'); if (!u.dataset.touched) u.value = e.target.value.toLowerCase().normalize('NFKD').replace(/[\u0300-\u036f]/g, '').replace(/[^a-z0-9\s.-]/g, '').trim().replace(/\s+/g, '.').slice(0, 32); });
  $('#inv-user').addEventListener('input', (e) => { e.target.dataset.touched = '1'; });
  $('#inv-f').onsubmit = async (e) => {
    e.preventDefault();
    const d = formData(e.target);
    let r;
    if (d.role === 'admin') {
      closeModal();
      r = await stepUpModal({ title: `Make ${d.displayName} an Administrator?`, intro: html`<p>Administrators can add and remove people, change everyone's access and lock everyone out. Confirm with your authenticator.</p>`, okLabel: 'Create Administrator', run: (code) => api('POST', '/api/admin/users', { ...d, code }) });
    } else r = await act(api('POST', '/api/admin/users', d));
    if (r) { showSignInCard(r.card, 'Sign-in card created'); toast(`${r.user.displayName} added`, 'ok'); refresh('users'); }
  };
};
const firstName = (id) => (userById(id)?.displayName || 'They').split(' ')[0];
A.setRole = async (t) => {
  const id = t.dataset.id, role = t.value, label = S.roles[role];
  const u = userById(id);
  let r;
  if (role === 'admin') {
    r = await stepUpModal({ title: `Make ${u?.displayName || 'this person'} an Administrator?`, intro: html`<p>Administrators can add and remove people, change everyone's access and lock everyone out. Confirm with your authenticator.</p>`, okLabel: 'Make Administrator', run: (code) => api('PATCH', '/api/admin/users/' + id, { role, code }) });
  } else r = await act(api('PATCH', '/api/admin/users/' + id, { role }));
  if (r) toast(`Role updated: ${firstName(id)} is now ${label}`, 'ok');
  else t.value = t.dataset.was; // cancelled or refused: put the old role back
  refresh();
};
A.userUnlock = async (t) => { if (await act(api('PATCH', '/api/admin/users/' + t.dataset.id, { unlock: true }), `${firstName(t.dataset.id)} unlocked`)) refresh(); };
A.userEnable = async (t) => { if (await act(api('PATCH', '/api/admin/users/' + t.dataset.id, { status: 'active' }), `${firstName(t.dataset.id)} re-enabled`)) refresh(); };
A.userDisable = async (t) => {
  const id = t.dataset.id, u = userById(id);
  const r = await stepUpModal({ title: `Disable ${u?.displayName || 'this person'}?`, intro: html`<p>They are <b>signed out on every device right away</b>, and cannot sign in again until you enable them.</p>`, okLabel: 'Disable and sign out', run: (code) => api('PATCH', '/api/admin/users/' + id, { status: 'disabled', code }) });
  if (r) { toast(`${firstName(id)} disabled and signed out`, 'ok'); refresh(); }
};
A.userReset = async (t) => {
  const id = t.dataset.id, u = userById(id);
  const r = await stepUpModal({ title: `Reset ${u?.displayName || 'this person'}'s sign-in?`, intro: html`<p>Use this if they lost their phone or their account may be stolen. They get a <b>new temporary password and a new authenticator code</b>, and are signed out everywhere. The old ones stop working.</p>`, okLabel: 'Reset sign-in', run: (code) => api('POST', `/api/admin/users/${id}/reset`, { code }) });
  if (r) { showSignInCard(r.card, 'New sign-in card'); toast(`${firstName(id)}'s sign-in was reset`, 'ok'); refresh(); }
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
A.auditCsv = () => { const d = current.audit; downloadText('windx-audit.csv', toCsv([['seq', 'time_utc', 'actor', 'action', 'target', 'detail', 'hash'], ...d.entries.map((e) => [e.seq, e.at, e.actor.name, e.action, e.target, JSON.stringify(e.detail || ''), e.hash])]), 'text/csv'); };

function orgHTML() {
  const o = S.org, ins = o.insurance || {}, oc = o.outsideCounsel || {};
  const tog = (k, label, desc) => html`<label class="check"><input type="checkbox" name="${k}" ${o[k] ? raw('checked') : ''}><span><b>${label}</b><br><span class="small muted">${desc}</span></span></label>`;
  return html`<form data-submit="saveOrg" class="grid g2">
    <section class="panel"><div class="panel-head"><h3>Organization Profile</h3></div><div class="panel-body col">
      <label class="field">Organization name <input name="name" required value="${o.name}"></label>
      <p class="small muted">These settings decide which legal deadlines WINDX tracks for you:</p>
      ${tog('publiclyTraded', 'Publicly traded (SEC registrant)', 'Adds the Form 8-K Item 1.05 four-business-day clock.')}
      ${tog('hipaaCovered', 'HIPAA covered entity / business associate', 'Makes HIPAA individual, HHS and media notices "required" when health data is in scope.')}
      ${tog('nydfsRegulated', 'NYDFS-regulated (23 NYCRR 500)', 'Adds the 72-hour DFS notice.')}
      ${tog('criticalInfrastructure', 'Critical infrastructure (CIRCIA)', 'Adds the 72-hour CISA report.')}
    </div></section>
    <div class="col">
      <section class="panel"><div class="panel-head"><h3>Cyber Insurance</h3></div><div class="panel-body form-grid">
        <label class="field">Carrier <input name="ins.carrier" value="${ins.carrier}"></label><label class="field">Policy # <input name="ins.policy" value="${ins.policy}"></label>
        <label class="field">Breach hotline <input name="ins.hotline" value="${ins.hotline}"></label><label class="field">Notice required within (hours) <input type="number" min="1" name="ins.noticeHours" value="${ins.noticeHours || 72}"></label>
      </div></section>
      <section class="panel"><div class="panel-head"><h3>Outside Breach Counsel</h3></div><div class="panel-body form-grid">
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
    <section class="panel"><div class="panel-head"><h3>${icon('lock')} Lockdown (Break Glass)</h3>${S.lockdown.on ? html`<span class="chip st st-encrypted">ACTIVE</span>` : ''}</div><div class="panel-body col">
      <p class="small">Suspect a WINDX account has been stolen? Lockdown <b>signs out everyone, including you</b>, closes every open screen, and lets only administrators sign back in until you lift it. Then reset suspect accounts and review the audit log.</p>
      ${S.lockdown.on ? html`<button class="btn xl" data-a="lockdown" data-on="0">${icon('check')} Lift lockdown</button><p class="tiny muted">Activated by ${userName(S.lockdown.by)} at ${fmtUTC(S.lockdown.at)}</p>` : html`<button class="btn danger-solid xl" data-a="lockdownOpen">${icon('lock')} Lockdown</button>`}
    </div></section>
    <section class="panel"><div class="panel-head"><h3>${icon('shield')} Security Posture</h3></div><div class="panel-body tight">
      ${check(S.tls, 'Encrypted transport', S.tls ? 'HTTPS with TLS 1.2+, HSTS. Verify the certificate fingerprint printed at startup.' : 'Plain HTTP on loopback only. Run npm run cert before using on a network.')}
      ${check(true, 'Encrypted at rest', 'AES-256-GCM vault; key derived from a startup passphrase (scrypt) and never written to disk. Evidence files individually encrypted.')}
      ${check(true, 'Two-factor sign-in enforced', `${enrolled} active account(s), all with TOTP. ${pending} pending invite(s).`)}
      ${check(true, 'Tamper-evident audit log', 'HMAC-chained entries. Run "Verify integrity" on the Audit tab.')}
      ${check(true, `Idle sign-out after ${Math.round(S.idleMs / 60e3)} min`, '8-hour maximum session. Sessions die on server restart.')}
      ${check(true, 'Zero third-party code', 'No npm packages, CDNs, fonts or trackers. Strict Content-Security-Policy blocks all outside connections.')}
      ${check(true, 'Legal hold by design', 'Nothing can be deleted, only struck with name and time.')}
    </div></section>
    <section class="panel"><div class="panel-head"><h3>${icon('download')} Encrypted Backup</h3></div><div class="panel-body col">
      <p class="small">Download the sealed vault file. It is already encrypted with your passphrase, so it is safe to carry offsite on a USB drive. Restore by placing it in the data folder and starting WINDX with the same passphrase.</p>
      <a class="btn" href="/api/admin/backup" download>${icon('download')} Download encrypted backup</a></div></section>
  </div>`;
}
// Lifting a lockdown lets non-admins sign in again.
A.lockdown = async () => {
  const r = await act(api('POST', '/api/admin/lockdown', { on: false }), 'Lockdown lifted. Everyone can sign in again.');
  if (r) { S.lockdown = r; refresh('lockdown'); }
};
// Lockdown: typed confirmation plus a fresh authenticator code, both checked by the server.
A.lockdownOpen = async () => {
  closeMeMenu();
  if (!can('admin')) return;
  const r = await stepUpModal({
    title: 'Lockdown: sign everyone out',
    intro: html`<p>Use this if you think a WINDX account has been stolen. When you confirm:</p>
      <ul><li><b>Everyone is signed out right now, including you.</b></li><li>Every open WINDX screen closes and goes back to the sign-in page.</li><li>Until an administrator signs back in and lifts it, <b>only administrators can sign in</b>.</li></ul>`,
    confirmWord: 'LOCKDOWN',
    okLabel: 'Sign everyone out now',
    run: (code, word) => api('POST', '/api/admin/lockdown', { on: true, confirm: word, code }),
  });
  if (r) sessionEnded('An administrator ended all sessions (Lockdown).');
};

// ================================================================ LEGAL DEADLINES (ALL CASES)
// Deadlines that need attention: open and either overdue or due within 72 hours. Drives the menu badge.
function dueSoonCount() {
  const limit = nowMs() + 72 * 36e5;
  return allIncidents().filter(isActive).reduce((n, i) => n + openObligations(i).filter((o) => o.dueAt && new Date(o.dueAt).getTime() < limit).length, 0);
}
const OB_STATUS = [['pending', 'Pending'], ['in-progress', 'In progress'], ['done', 'Done'], ['na', 'Not applicable']];
function DeadlinesView() {
  return {
    mount(el) { this.el = el; UI.dlShow ||= 'open'; this.update(); },
    update(what) {
      if (what === 'message' || what === 'ack' || what === 'presence') return;
      const L = can('legal.write');
      const cases = allIncidents().filter((i) => UI.dlShow === 'all' || isActive(i));
      const now = nowMs();
      const isDone = (o) => o.status === 'done' || o.status === 'na';
      const groups = cases.map((inc) => {
        const obs = inc.obligations.filter((o) => UI.dlShow === 'all' || !isDone(o))
          .sort((a, b) => (isDone(a) - isDone(b)) || ((a.dueAt ? 0 : 1) - (b.dueAt ? 0 : 1)) || String(a.dueAt).localeCompare(String(b.dueAt)));
        const next = obs.find((o) => o.dueAt && !isDone(o));
        return { inc, obs, next };
      }).filter((g) => g.obs.length)
        .sort((a, b) => (a.next ? 0 : 1) - (b.next ? 0 : 1) || String(a.next?.dueAt).localeCompare(String(b.next?.dueAt)));
      const open = cases.flatMap((i) => openObligations(i));
      const overdue = open.filter((o) => o.dueAt && new Date(o.dueAt).getTime() < now).length;
      const soon = open.filter((o) => o.dueAt && new Date(o.dueAt).getTime() >= now && new Date(o.dueAt).getTime() < now + 72 * 36e5).length;
      const done = cases.flatMap((i) => i.obligations).filter(isDone).length;
      setHTML(this.el, html`
        <div class="page-head"><div><h1>Legal Deadlines</h1><p>Every notification deadline from every case, grouped by case, soonest first.</p></div>
          <div class="seg">${[['open', 'Open only'], ['all', 'Include done & closed cases']].map(([k, l]) => html`<button type="button" class="${UI.dlShow === k ? 'on' : ''}" data-a="dlShow" data-k="${k}">${l}</button>`)}</div></div>
        <div class="grid g4">
          <div class="panel stat ${overdue ? 'alert' : ''}"><div class="n">${overdue}</div><div class="l">Overdue</div></div>
          <div class="panel stat ${soon ? 'alert' : ''}"><div class="n">${soon}</div><div class="l">Due in the Next 72 Hours</div></div>
          <div class="panel stat"><div class="n">${open.length}</div><div class="l">Open Obligations</div></div>
          <div class="panel stat"><div class="n">${done}</div><div class="l">Done or Not Applicable</div></div>
        </div><br>
        ${groups.length ? groups.map(({ inc, obs, next }) => html`
          <section class="panel dl-case s${inc.severity}">
            <div class="panel-head">
              <div class="row wrap">${sevChip(inc.severity, false)}<a class="dl-case-name" href="#/i/${inc.id}/obligations">${inc.codename}</a><span class="mono small muted">${inc.ref}</span><span class="small muted">${inc.title}</span>${isActive(inc) ? '' : html`<span class="chip">CLOSED</span>`}</div>
              <span class="small nowrap">${next ? html`Next: ${countdown(next.dueAt)}` : html`<span class="dim">No timed deadline</span>`}</span>
            </div>
            ${obs.map((o) => { const d = isDone(o); return html`<div class="dl-row ${d ? 'done' : ''}">
              <div class="grow"><div class="row wrap"><b>${o.title}</b><span class="chip lvl-${o.level}">${o.level}</span></div>
                <div class="small muted">${o.who} · <span class="mono">${o.cite}</span></div>
                ${L ? html`<div class="seg dl-seg">${OB_STATUS.map(([k, l]) => html`<button type="button" class="${o.status === k ? 'on ' + k : ''}" data-a="dlStatus" data-inc="${inc.id}" data-ob="${o.id}" data-s="${k}">${l}</button>`)}</div>` : html`<div class="tiny muted">Status: ${(OB_STATUS.find((x) => x[0] === o.status) || [null, o.status])[1]}</div>`}</div>
              <div class="right dl-when">${o.dueAt ? html`${countdown(o.dueAt, d)}<div class="tiny dim mono">${fmtUTC(o.dueAt)}</div>` : html`<div class="small muted">${o.dueText || ''}</div>`}</div>
            </div>`; })}
          </section>`) : html`<div class="panel empty">${icon('scale')}<h3>No deadlines to show</h3><p>Deadlines appear when a case records affected data in its Scope & Data section.</p></div>`}
        <p class="tiny dim">Decision support, not legal advice. Confirm every obligation with counsel.</p>`);
    },
  };
}
A.dlShow = (t) => { UI.dlShow = t.dataset.k; refresh(); };
A.dlStatus = async (t) => {
  const id = t.dataset.inc;
  if (await act(api('PATCH', `/api/incidents/${id}/obligations/${t.dataset.ob}`, { status: t.dataset.s }), 'Obligation updated')) reloadInc(id);
};

// ================================================================ MY PROFILE & MY ACTIVITY
const meTabs = (active) => html`<nav class="tabs">
  <a class="tab ${active === 'profile' ? 'active' : ''}" href="#/me">My profile</a>
  <a class="tab ${active === 'history' ? 'active' : ''}" href="#/me/history">My activity</a></nav><br>`;

// Every audit action, in plain words, grouped for filtering.
const ACTIONS = {
  'auth.login': ['Signed in', 'signin'], 'auth.logout': ['Signed out', 'signin'], 'auth.login.failed': ['Failed sign-in attempt on your account', 'signin'],
  'auth.login.blocked_lockdown': ['Sign-in blocked by lockdown', 'signin'], 'user.enrolled': ['Activated your account', 'signin'],
  'incident.create': ['Declared an incident', 'incident'], 'incident.update': ['Updated an incident', 'incident'], 'timeline.add': ['Logged a timeline entry', 'incident'],
  'timeline.strike': ['Struck a timeline entry', 'incident'], 'task.add': ['Added a task', 'incident'], 'task.update': ['Updated a task', 'incident'], 'tasks.strike': ['Removed a task', 'incident'],
  'ioc.add': ['Added indicators', 'incident'], 'iocs.strike': ['Struck an indicator', 'incident'], 'scope.add': ['Recorded affected data', 'incident'],
  'scope.update': ['Updated affected data', 'incident'], 'scope.strike': ['Struck a data set', 'incident'], 'obligation.update': ['Updated a legal obligation', 'incident'],
  'evidence.add': ['Logged evidence', 'incident'], 'evidence.custody': ['Recorded a custody transfer', 'incident'], 'evidence.export': ['Exported evidence', 'incident'],
  'message.post': ['Sent a message', 'comms'], 'message.urgent': ['Sent an URGENT message', 'comms'], 'channel.create': ['Created a channel', 'comms'],
  'org.update': ['Updated the organization profile', 'admin'], 'contacts.update': ['Updated emergency contacts', 'admin'], 'user.invite': ['Invited a person', 'admin'],
  'user.update': ["Changed a person's account", 'admin'], 'user.reset': ['Reset an account', 'admin'], 'session.revoke': ["Ended someone's session", 'admin'],
  'lockdown.on': ['Turned lockdown on', 'admin'], 'lockdown.off': ['Lifted lockdown', 'admin'], 'audit.verify': ['Verified the audit log', 'admin'],
  'vault.backup': ['Downloaded an encrypted backup', 'admin'],
};
const ACTION_GROUPS = [['all', 'Everything'], ['incident', 'Incident work'], ['comms', 'Messages'], ['signin', 'Sign-ins'], ['admin', 'Admin']];
const RANGES = [['week', 'Past week'], ['month', 'Past month'], ['6months', 'Past 6 months'], ['year', 'Past year'], ['all', 'All time']];

function describeAction(e) {
  const d = e.detail || {};
  let label = (ACTIONS[e.action] || [e.action])[0];
  if (e.action === 'task.update' && d.status === 'done') label = 'Completed a task';
  const bits = [];
  if (d.title) bits.push(`"${d.title}"`);
  if (d.asset) bits.push(`"${d.asset}"${d.status ? ' as ' + d.status : ''}`);
  if (d.name) bits.push(`"${d.name}"`);
  if (d.kind) bits.push(`(${d.kind})`);
  if (e.action === 'obligation.update' && d.id) bits.push(`${d.id} marked ${d.status}`);
  if (e.action === 'incident.update') bits.push(Object.keys(d).map((k) => ({ breachDeterminedAt: 'breach determination', materialityDeterminedAt: 'materiality determination', status: 'phase', leadId: 'incident lead' }[k] || k)).join(', '));
  if (e.action === 'ioc.add' && d.count != null) bits.push(`${d.count} added`);
  if (d.role && e.action === 'user.invite') bits.push(`as ${S.roles[d.role] || d.role}`);
  if (d.ip) bits.push(`from ${d.ip}`);
  if (e.action === 'auth.login.failed') bits.push(d.why === 'mfa' ? 'right password, wrong 6-digit code' : 'wrong password');
  return { label, group: (ACTIONS[e.action] || [null, 'admin'])[1], info: bits.join(' ') };
}
function targetLink(target) {
  if (!target) return '';
  const inc = [...S.inc.values()].find((i) => i.ref === target);
  if (inc) return html`<a href="#/i/${inc.id}">${inc.ref} · ${inc.codename}</a>`;
  const ch = S.channels.find((c) => c.name === target);
  if (ch) return html`<a href="#/comms/${ch.id}">#${ch.name}</a>`;
  return html`<span class="mono">${target}</span>`;
}

function HistoryView() {
  return {
    mount(el) {
      this.el = el;
      UI.histRange ||= 'month';
      UI.histType ||= 'all';
      setHTML(el, html`<div class="page-head"><div><h1>My activity</h1><p>Every action you have taken in WINDX, from the tamper-proof audit log.</p></div></div>${meTabs('history')}<div id="hist-body"><div class="empty">Loading…</div></div>`);
      this.load();
    },
    async load() {
      try { this.data = await api('GET', '/api/me/history?range=' + UI.histRange); } catch (e) { setHTML('#hist-body', html`<div class="error-box">${e.message}</div>`); return; }
      this.draw();
    },
    update(what) { if (what === 'all' || what === 'users') this.draw(); },
    draw() {
      const d = this.data;
      if (!d) return;
      const items = d.entries.map((e) => ({ ...e, ...describeAction(e) })); // keeps e.detail (raw) and adds label, group, info
      const counts = { all: items.length };
      for (const i of items) counts[i.group] = (counts[i.group] || 0) + 1;
      const shown = items.filter((i) => UI.histType === 'all' || i.group === UI.histType);
      const failed = items.filter((i) => i.action === 'auth.login.failed');
      let lastDay = null;
      const rows = shown.map((i) => {
        const day = new Date(i.at).toLocaleDateString(undefined, { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' });
        const head = day !== lastDay ? html`<div class="hist-day">${day}</div>` : '';
        lastDay = day;
        return html`${head}<div class="hist-row g-${i.group} ${i.action === 'auth.login.failed' ? 'warn' : ''}">
          <div class="hist-time"><b>${new Date(i.at).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })}</b><span class="mono">${fmtTimeUTC(i.at)}</span></div>
          <div class="grow"><b>${i.label}</b> ${i.info ? html`<span class="muted">${i.info}</span>` : ''}${i.target && !/^auth|user\.enrolled/.test(i.action) ? html`<div class="small">${targetLink(i.target)}</div>` : ''}</div></div>`;
      });
      setHTML('#hist-body', html`
        <div class="row wrap between">
          <div class="seg" role="group" aria-label="Time range">${RANGES.map(([k, l]) => html`<button type="button" class="${UI.histRange === k ? 'on' : ''}" data-a="histRange" data-r="${k}">${l}</button>`)}</div>
          <button class="btn sm" data-a="histCsv" ${shown.length ? '' : raw('disabled')}>${icon('download')} Download (CSV)</button>
        </div><br>
        <div class="grid g4">
          <div class="panel stat"><div class="n">${counts.all}</div><div class="l">Actions · ${RANGES.find((r) => r[0] === UI.histRange)[1].replace(/\b\w/g, (c) => c.toUpperCase())}</div></div>
          <div class="panel stat"><div class="n">${counts.incident || 0}</div><div class="l">Incident Updates</div></div>
          <div class="panel stat"><div class="n">${counts.comms || 0}</div><div class="l">Messages Sent</div></div>
          <div class="panel stat ${failed.length ? 'alert' : ''}"><div class="n">${failed.length}</div><div class="l">Failed Sign-ins on Your Account</div></div>
        </div>
        ${failed.length ? html`<br><div class="banner urgent hist-alert">${icon('alert')} Someone tried to sign in to your account ${failed.length} time${failed.length > 1 ? 's' : ''} without the right code (most recently from ${failed[0].detail?.ip || 'an unknown address'}). If this was not you, tell an administrator.</div>` : ''}
        <br><div class="row wrap">${ACTION_GROUPS.map(([k, l]) => html`<button type="button" class="chip click ${UI.histType === k ? 'on' : ''}" data-a="histType" data-t="${k}">${l} <span class="dim">${counts[k] || 0}</span></button>`)}</div><br>
        <section class="panel hist">${shown.length ? rows : html`<div class="empty">${icon('clock')}<h3>Nothing here</h3><p>No ${UI.histType === 'all' ? '' : ACTION_GROUPS.find((g) => g[0] === UI.histType)[1].toLowerCase() + ' '}activity in this time range. Try a longer range.</p></div>`}</section>
        ${d.total > d.entries.length ? html`<p class="tiny dim">Showing the latest ${d.entries.length} of ${d.total} actions.</p>` : ''}`);
      this.shown = shown;
    },
  };
}
A.histRange = (t) => { UI.histRange = t.dataset.r; current.load?.(); };
A.histType = (t) => { UI.histType = t.dataset.t; current.draw?.(); };
A.histCsv = () => {
  const rows = current.shown || [];
  downloadText(`windx-activity-${S.me.username}-${UI.histRange}.csv`, toCsv([['time_utc', 'action', 'details', 'target', 'audit_seq'], ...rows.map((i) => [i.at, i.label, i.info, i.target || '', i.seq])]), 'text/csv');
};

A.changePassword = () => {
  modal(html`<form id="cp-f">${mHead('Change your password', 'At least 12 characters. A short sentence works well.')}
    <div class="modal-body">
      <label class="field">Current password<input type="password" name="currentPassword" autocomplete="current-password" required autofocus></label>
      <label class="field">New password<input type="password" name="newPassword" autocomplete="new-password" minlength="12" required></label>
      <label class="field">Type it again<input type="password" name="again" autocomplete="new-password" minlength="12" required></label>
      <div id="cp-err"></div>
    </div><div class="modal-foot"><button class="btn" type="button" data-a="closeModal">Cancel</button><button class="btn primary">Change password</button></div></form>`);
  $('#cp-f').onsubmit = async (e) => {
    e.preventDefault();
    const d = formData(e.target);
    if (d.newPassword !== d.again) return setHTML('#cp-err', html`<div class="error-box">The two new passwords do not match.</div>`);
    try { await api('POST', '/api/auth/password', { currentPassword: d.currentPassword, newPassword: d.newPassword }); closeModal(); toast('Password changed. Your other sessions were signed out.', 'ok'); }
    catch (err) { setHTML('#cp-err', html`<div class="error-box">${err.message}</div>`); }
  };
};

const CAPABILITIES = [
  [() => true, 'View incidents, timelines and deadlines'],
  [() => can('incident.create'), 'Declare new incidents'],
  [() => can('incident.write'), 'Update incidents: log events, tasks, scope, evidence'],
  [() => can('incident.manage'), 'Close incidents, lower severity, control who can see them'],
  [() => can('legal.write'), 'Make legal determinations and mark notifications done'],
  [() => S.me.role !== 'observer', 'Send URGENT messages that need acknowledgment'],
  [() => can('channel.create'), 'Create chat channels'],
  [() => can('contacts.write'), 'Edit the emergency contact list'],
  [() => can('audit.read'), 'View the full audit log'],
  [() => can('privileged.read'), 'See all Privileged & Confidential incidents'],
  [() => can('admin'), 'Manage people, organization settings, sessions and lockdown'],
];
function ProfileView() {
  return {
    async mount(el) {
      this.el = el;
      this.draw();
      try {
        const [me, hist] = await Promise.all([api('GET', '/api/me'), api('GET', '/api/me/history?range=month')]);
        this.me = me; this.month = hist.total; this.failed = hist.entries.filter((e) => e.action === 'auth.login.failed').length;
        this.draw();
      } catch { /* keep the basic view */ }
    },
    update(what) { if (what === 'all' || what === 'users' || what === 'incident') this.draw(); },
    draw() {
      const u = this.me?.user || S.me;
      const sess = this.me?.session;
      const leading = allIncidents().filter((i) => i.leadId === u.id && isActive(i));
      const myTasks = allIncidents().filter(isActive).flatMap((i) => live(i.tasks).filter((t) => t.assigneeId === u.id && t.status !== 'done').map((t) => ({ t, i })));
      const admins = S.users.filter((x) => x.role === 'admin' && x.status === 'active' && x.id !== u.id);
      const fact = (label, value) => html`<dt>${label}</dt><dd>${value || html`<span class="dim">Not set</span>`}</dd>`;
      setHTML(this.el, html`
        <div class="page-head"><div class="row">${avatar(u.id)}<div><h1 class="keep-case">${u.displayName}</h1><p>@${u.username} · ${S.roles[u.role]}${u.title ? ' · ' + u.title : ''}</p></div></div></div>
        ${meTabs('profile')}
        <div class="grid g-main">
          <div class="col">
            <section class="panel"><div class="panel-head"><h3>${icon('users')} Account</h3></div><div class="panel-body"><dl class="facts">
              ${fact('Full name', u.displayName)}
              ${fact('Username', html`<span class="mono">${u.username}</span>`)}
              ${fact('Role', html`<b>${S.roles[u.role]}</b><div class="small muted">${ROLE_DESC[u.role] || ''}</div>`)}
              ${fact('Job title', u.title)}
              ${fact('Mobile phone', u.phone && html`<span class="mono">${u.phone}</span>`)}
              ${fact('Account status', html`<span class="chip st st-secured">Active</span>`)}
              ${fact('Two-factor sign-in', u.mfa === false ? html`<span class="chip st st-encrypted">Off</span>` : html`<span class="chip st st-secured">On</span> <span class="small muted">6-digit code from your authenticator app</span>`)}
              ${fact('Account created', u.createdAt && fmtUTC(u.createdAt))}
              ${fact('Last sign-in', u.lastLogin && fmtUTC(u.lastLogin))}
            </dl></div></section>
            <section class="panel"><div class="panel-head"><h3>${icon('lock')} This Session</h3><div class="row"><button class="btn sm" data-a="changePassword">${icon('key')} Change password</button><button class="btn sm danger" data-a="logout">Sign out</button></div></div><div class="panel-body"><dl class="facts">
              ${fact('Signed in', sess && fmtUTC(sess.createdAt))}
              ${fact('From', sess && html`<span class="mono">${sess.ip}</span>`)}
              ${fact('Connection', S.tls ? 'Encrypted (HTTPS)' : 'Local only')}
              ${fact('Automatic sign-out', `After ${Math.round(S.idleMs / 60e3)} minutes without activity, and after ${sess?.maxHours || 12} hours at most`)}
            </dl></div></section>
            <section class="panel"><div class="panel-head"><h3>${icon('key')} Need a Change?</h3></div><div class="panel-body small">
              <p>For security, only an administrator can change your role or phone number, or reset your password and two-factor (for example if you lose your phone).</p>
              ${admins.length ? html`<p>Administrators: ${admins.map((a, n) => html`${n ? ', ' : ''}<b>${a.displayName}</b>${a.phone ? html` <span class="mono">${a.phone}</span>` : ''}`)}</p>` : can('admin') ? html`<p>You are an administrator. Manage accounts on the <a href="#/admin/people">People</a> page.</p>` : ''}
            </div></section>
          </div>
          <div class="col">
            <section class="panel"><div class="panel-head"><h3>${icon('shield')} What You Can Do</h3><span class="tiny muted">Set by your role</span></div><div class="panel-body tight">
              ${CAPABILITIES.map(([ok, label]) => { const yes = ok(); return html`<div class="list-item cap ${yes ? 'yes' : 'no'}">${yes ? icon('check') : icon('x')}<span class="grow">${label}</span><span class="tiny ${yes ? '' : 'dim'}">${yes ? 'Allowed' : 'Not allowed'}</span></div>`; })}
            </div></section>
            <section class="panel"><div class="panel-head"><h3>${icon('activity')} Your Work</h3><a class="small" href="#/me/history">My activity ${icon('arrow')}</a></div><div class="panel-body col">
              <div class="row between"><span>Actions in the past month</span><b class="mono">${this.month ?? '…'}</b></div>
              ${this.failed ? html`<div class="row between"><span class="cd urgent">Failed sign-ins on your account (past month)</span><b class="mono cd urgent">${this.failed}</b></div>` : ''}
              <div><b>Incidents you lead</b>${leading.length ? html`<ul class="plain">${leading.map((i) => html`<li>${sevChip(i.severity, false)} <a href="#/i/${i.id}">${i.codename}</a> <span class="muted small">${phaseById(i.status).label}</span></li>`)}</ul>` : html`<div class="small muted">None right now.</div>`}</div>
              <div><b>Open tasks assigned to you</b>${myTasks.length ? html`<ul class="plain">${myTasks.slice(0, 6).map(({ t, i }) => html`<li><a href="#/i/${i.id}/tasks">${t.title}</a> <span class="muted small">${i.codename}</span></li>`)}</ul>` : html`<div class="small muted">None right now.</div>`}</div>
            </div></section>
          </div>
        </div>`);
    },
  };
}

// ================================================================ WALLBOARD
function WallView() {
  return {
    mount(el) { this.el = el; this.update(); },
    update(what) {
      if (what === 'message' || what === 'ack') return;
      const active = allIncidents().filter(isActive);
      const ticker = active.flatMap((i) => live(i.timeline).filter((e) => e.kind !== 'system').map((e) => ({ e, i }))).sort((a, b) => b.e.at.localeCompare(a.e.at)).slice(0, 8);
      setHTML(this.el, html`<div class="wall">
        <div class="wall-head"><div class="row">${backButton()}${LOGO}<div><h1>WINDX · ${S.org.name}</h1><div class="muted">Situation Board</div></div></div>
          <div class="right"><div class="wall-clock" id="wall-clock">${fmtTimeUTC(new Date(nowMs()).toISOString())}</div><div class="wall-live"><span id="conn" class="conn"></span></div></div></div>
        ${window.AttackReplay ? html`<div class="replay-slot">${window.AttackReplay.markup()}</div>` : ''}
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
      window.AttackReplay?.mount($('.replay', this.el));
    },
  };
}

// ================================================================ PALETTE, HELP, KEYS
function paletteItems() {
  const items = [];
  if (can('incident.create')) items.push({ icon: 'zap', label: 'Declare an incident', hint: 'D', run: () => A.declare() });
  items.push({ icon: 'home', label: 'Home', run: () => (location.hash = '#/') });
  items.push({ icon: 'scale', label: 'Legal deadlines (all cases)', kw: 'notify notification law', run: () => (location.hash = '#/deadlines') });
  items.push({ icon: 'chat', label: 'Comms', run: () => (location.hash = '#/comms') });
  items.push({ icon: 'phone', label: 'Emergency contacts', kw: 'phone call', run: () => (location.hash = '#/contacts') });
  items.push({ icon: 'tv', label: 'Wallboard (big screen)', run: () => (location.hash = '#/wall') });
  if (can('admin')) {
    items.push({ icon: 'users', label: 'Invite a person', run: () => { location.hash = '#/admin/people'; setTimeout(A.invite, 50); } });
    items.push({ icon: 'users', label: 'Team & Access', kw: 'people users roles invite', run: () => (location.hash = '#/admin/people') });
    items.push({ icon: 'lock', label: S.lockdown.on ? 'Lift lockdown' : 'Lockdown (sign everyone out)', run: () => (S.lockdown.on ? (location.hash = '#/admin/system') : A.lockdownOpen()) });
  }
  if (can('audit.read')) items.push({ icon: 'shield', label: 'Audit Log', run: () => (location.hash = '#/admin/audit') });
  for (const i of allIncidents()) {
    items.push({ icon: 'alert', label: `${i.ref} · ${i.codename} · ${i.title}`, hint: phaseById(i.status).short, run: () => (location.hash = '#/i/' + i.id) });
    if (isActive(i)) for (const [k, l] of [['scope', 'Scope & Data'], ['obligations', 'Legal deadlines'], ['tasks', 'Tasks'], ['report', 'Report / SITREP'], ['room', 'Room']]) items.push({ icon: 'arrow', label: `${i.codename} → ${l}`, run: () => (location.hash = `#/i/${i.id}/${k}`) });
  }
  for (const c of S.channels) items.push({ icon: 'chat', label: '#' + c.name, run: () => (location.hash = '#/comms/' + c.id) });
  items.push({ icon: 'help', label: 'Help: how to use WINDX', hint: '?', run: () => A.help() });
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
  modal(html`${mHead('WINDX in 60 seconds', 'You do not need to remember any of this. The screens tell you what to do next.')}
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
