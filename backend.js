'use strict';
/* WINDX online demo: the server's API, running inside the browser.
   The real product runs server.js on an isolated laptop; this lets anyone click through it from a link. */
(function () {
  const enc = new TextEncoder();
  const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
  const sha256 = async (d) => hex(await crypto.subtle.digest('SHA-256', typeof d === 'string' ? enc.encode(d) : d));
  const ALPH = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-';
  const rid = (p = '') => p + Array.from(crypto.getRandomValues(new Uint8Array(9)), (b) => ALPH[b & 63]).join('');
  const now = () => new Date().toISOString();

  // ---------- TOTP (same algorithm as the real server) ----------
  const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  function b32enc(bytes) { let bits = 0, v = 0, o = ''; for (const b of bytes) { v = (v << 8) | b; bits += 8; while (bits >= 5) { o += B32[(v >>> (bits - 5)) & 31]; bits -= 5; } } if (bits) o += B32[(v << (5 - bits)) & 31]; return o; }
  function b32dec(s) { let bits = 0, v = 0; const o = []; for (const c of s.toUpperCase().replace(/[^A-Z2-7]/g, '')) { v = (v << 5) | B32.indexOf(c); bits += 5; if (bits >= 8) { o.push((v >>> (bits - 8)) & 255); bits -= 8; } } return new Uint8Array(o); }
  const keyCache = new Map();
  async function totpAt(secret, step) {
    let key = keyCache.get(secret);
    if (!key) { key = await crypto.subtle.importKey('raw', b32dec(secret), { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']); keyCache.set(secret, key); }
    const msg = new Uint8Array(8); let s = step; for (let i = 7; i >= 0; i--) { msg[i] = s & 255; s = Math.floor(s / 256); }
    const h = new Uint8Array(await crypto.subtle.sign('HMAC', key, msg));
    const off = h[h.length - 1] & 15;
    const bin = ((h[off] & 127) << 24) | (h[off + 1] << 16) | (h[off + 2] << 8) | h[off + 3];
    return String(bin % 1e6).padStart(6, '0');
  }
  const curStep = () => Math.floor(Date.now() / 30000);
  async function verifyTotp(secret, code, last = -1) {
    code = String(code || '').replace(/\s/g, '');
    if (!/^\d{6}$/.test(code)) return -1;
    for (const s of [curStep(), curStep() - 1, curStep() + 1]) if (s > last && (await totpAt(secret, s)) === code) return s;
    return -1;
  }
  async function demoSecret(u) { return b32enc(new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode('lifeboat-demo:' + u))).slice(0, 20)); }

  // ---------- shared modules from the real app ----------
  const PB = __LIB.playbooks, REG = __LIB.regulations, QR = __LIB.qr;

  // ---------- state ----------
  const KEY = 'lifeboat-demo-state-v3';
  let S;
  function shiftTimes(o, off) {
    if (Array.isArray(o)) return o.map((x) => shiftTimes(x, off));
    if (o && typeof o === 'object') { const r = {}; for (const [k, v] of Object.entries(o)) r[k] = k === 'inviteExpires' && typeof v === 'number' ? v + off : shiftTimes(v, off); return r; }
    if (typeof o === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z$/.test(o)) return new Date(new Date(o).getTime() + off).toISOString();
    return o;
  }
  function freshState() { const off = Date.now() - new Date(__SEED.meta.seededAt).getTime(); return shiftTimes(JSON.parse(JSON.stringify(__SEED)), off); }
  function loadState() { try { const s = localStorage.getItem(KEY); if (s) return JSON.parse(s); } catch { /* storage blocked */ } return null; }
  S = loadState() || freshState();
  let saveTimer = null;
  function saveNow() { clearTimeout(saveTimer); try { localStorage.setItem(KEY, JSON.stringify(S)); } catch { /* ignore */ } }
  function save() { clearTimeout(saveTimer); saveTimer = setTimeout(saveNow, 100); }

  // tamper-evident audit chain (HMAC with a per-browser key)
  let auditKey;
  const auditReady = (async () => {
    auditKey = await crypto.subtle.importKey('raw', enc.encode('lifeboat-demo-audit-key'), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    if (!S.audit.length || !S.audit[0].hash) { let prev = 'GENESIS'; for (const e of S.audit) { e.prev = prev; e.hash = await auditHash(prev, e); prev = e.hash; } save(); }
  })();
  async function auditHash(prev, e) { return hex(await crypto.subtle.sign('HMAC', auditKey, enc.encode(prev + JSON.stringify([e.seq, e.at, e.actor, e.action, e.target, e.detail])))); }
  let auditQ = Promise.resolve();
  function audit(actor, action, target = null, detail = null) {
    auditQ = auditQ.then(async () => {
      await auditReady;
      const prev = S.audit.length ? S.audit[S.audit.length - 1].hash : 'GENESIS';
      const e = { seq: S.audit.length + 1, at: now(), actor: actor ? { id: actor.id, name: actor.displayName } : { id: null, name: 'system' }, action, target, detail, prev };
      e.hash = await auditHash(prev, e);
      const fresh = loadState(); if (fresh) S = fresh; // another tab may have written meanwhile
      e.seq = S.audit.length + 1; e.prev = S.audit.length ? S.audit[S.audit.length - 1].hash : 'GENESIS'; e.hash = await auditHash(e.prev, e);
      S.audit.push(e); saveNow();
    });
  }

  // ---------- helpers mirrored from server.js ----------
  class HE extends Error { constructor(s, m) { super(m); this.status = s; } }
  const bad = (m) => new HE(400, m);
  function str(v, max = 500, { required = false, name = 'field' } = {}) {
    if (v == null) v = '';
    if (typeof v !== 'string' && typeof v !== 'number') throw bad(`${name} must be text`);
    const s = String(v).trim();
    if (required && !s) throw bad(`${name} is required`);
    if (s.length > max) throw bad(`${name} is too long (max ${max})`);
    return s;
  }
  const oneOf = (v, list, n) => { if (!list.includes(v)) throw bad('Invalid ' + n); return v; };
  const date = (v) => { if (v == null || v === '') return null; const t = new Date(v); if (isNaN(t)) throw bad('Invalid date'); return t.toISOString(); };
  const int = (v, a = 0, b = 1e12) => Math.max(a, Math.min(b, Math.round(Number(v) || 0)));
  const ROLES = {
    admin: { label: 'Administrator', perms: ['*'] },
    commander: { label: 'Incident Commander', perms: ['incident.read', 'incident.write', 'incident.create', 'incident.manage', 'privileged.read', 'legal.write', 'contacts.write', 'audit.read', 'channel.create'] },
    responder: { label: 'Responder', perms: ['incident.read', 'incident.write', 'incident.create'] },
    counsel: { label: 'Legal Counsel', perms: ['incident.read', 'incident.write', 'privileged.read', 'legal.write', 'audit.read', 'channel.create'] },
    observer: { label: 'Executive (read-only)', perms: ['incident.read'] },
  };
  const can = (u, p) => !!u && (ROLES[u.role]?.perms.includes('*') || ROLES[u.role]?.perms.includes(p));
  const findUser = (id) => S.users.find((u) => u.id === id);
  const findInc = (id) => S.incidents.find((i) => i.id === id);
  function canSee(u, inc) {
    if (!inc || !can(u, 'incident.read')) return false;
    const named = u.role === 'admin' || inc.leadId === u.id || inc.createdBy === u.id || (inc.members || []).includes(u.id);
    if (inc.access === 'restricted') return named;
    if (inc.privileged && !can(u, 'privileged.read')) return named;
    return true;
  }
  function canSeeChannel(u, ch) { if (!ch) return false; if (ch.incidentId) return canSee(u, findInc(ch.incidentId)); if (ch.members) return u.role === 'admin' || ch.members.includes(u.id); return true; }
  function publicUser(u, full = false) {
    const o = { id: u.id, username: u.username, displayName: u.displayName, role: u.role, title: u.title || '', phone: u.phone || '', status: u.status, mustChangePassword: !!u.mustChangePassword };
    if (full) Object.assign(o, { createdAt: u.createdAt, lastLogin: u.lastLogin || null, mfa: !!u.totpSecret, locked: (u.lockedUntil || 0) > Date.now(), inviteExpires: u.inviteExpires || null });
    return o;
  }
  const full = (inc) => ({ ...inc, obligations: REG.compute(inc, S.org) });
  function addTimeline(inc, u, text, kind = 'system', at = null) {
    const e = { id: rid('t_'), at: at || now(), loggedAt: now(), by: u?.id || null, kind, text };
    inc.timeline.push(e); inc.timeline.sort((a, b) => a.at.localeCompare(b.at)); return e;
  }

  // ---------- realtime: in-page stream + other tabs via BroadcastChannel ----------
  const streams = new Set();
  let bc = null; try { bc = new BroadcastChannel('lifeboat-demo'); } catch { /* unsupported */ }
  function visible(u, scope) {
    if (!u || !scope) return true;
    if (scope.inc) return canSee(u, findInc(scope.inc));
    if (scope.ch) return canSeeChannel(u, S.channels.find((c) => c.id === scope.ch));
    if (scope.user) return u.id === scope.user;
    return true;
  }
  function emitLocal(type, data, scope) { const u = me(); for (const s of streams) if (visible(u, scope)) s._emit(type, data); }
  function broadcast(type, data, scope = null) { saveNow(); emitLocal(type, data, scope); try { bc && bc.postMessage({ type, data, scope }); } catch { /* ignore */ } }
  const peers = new Map();
  if (bc) bc.onmessage = (ev) => {
    const m = ev.data || {};
    if (m.presence) { peers.set(m.tab, { userId: m.presence, at: Date.now() }); emitPresence(); return; }
    if (m.bye) { peers.delete(m.tab); emitPresence(); return; }
    const fresh = loadState(); if (fresh) S = fresh;
    if (m.type === 'logout') return;
    if (m.kick) { const u = session && findUser(session.userId); if (session && !me()) { setSession(null); emitLocal('logout', { reason: m.kick }); } return; }
    emitLocal(m.type, m.data, m.scope);
  };
  const TAB = rid('tab_');
  // End sessions: bump an epoch so old sessions stop working, then tell every open tab.
  function endSessions(userId, reason) {
    if (userId) { const u = findUser(userId); u.sessionEpoch = (u.sessionEpoch || 0) + 1; } else S.sessionEpoch = (S.sessionEpoch || 0) + 1;
    saveNow();
    try { bc && bc.postMessage({ kick: reason }); } catch { /* ignore */ }
  }
  const stepFails = new Map();
  async function stepUp(u, code, action) {
    const t = Date.now(), st = stepFails.get(u.id) || { fails: [], blockedUntil: 0 };
    if (st.blockedUntil > t) throw new HE(429, `Too many wrong codes. For safety, wait ${Math.ceil((st.blockedUntil - t) / 60e3)} minutes before trying again.`);
    const step = await verifyTotp(u.totpSecret, code, u.lastTotpStep ?? -1);
    if (step < 0) {
      st.fails = st.fails.filter((x) => t - x < 5 * 60e3).concat(t);
      if (st.fails.length >= 3) { st.blockedUntil = t + 5 * 60e3; st.fails = []; }
      stepFails.set(u.id, st);
      audit(u, action + '.mfa_fail', null, { blocked: st.blockedUntil > t });
      throw new HE(403, "That code didn't work. Wait for the next code and try again.");
    }
    u.lastTotpStep = step; stepFails.delete(u.id); save();
  }
  async function newSignInCard(u) {
    const a = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789', b = crypto.getRandomValues(new Uint8Array(16));
    let pw = ''; for (const x of b) pw += a[x % a.length];
    pw = pw.match(/.{4}/g).join('-');
    const secret = b32enc(crypto.getRandomValues(new Uint8Array(20)));
    Object.assign(u, { passHash: await sha256(u.id + ':' + pw), tempHash: await sha256(u.id + ':' + pw), totpSecret: secret, lastTotpStep: -1, mustChangePassword: true, status: 'invited', inviteHash: null, inviteExpires: null, failed: 0, lockedUntil: 0 });
    delete u.demoPassword;
    const uri = `otpauth://totp/WINDX:${encodeURIComponent(u.username)}?secret=${secret}&issuer=WINDX&algorithm=SHA1&digits=6&period=30`;
    return { username: u.username, displayName: u.displayName, role: u.role, tempPassword: pw, secret, uri, qr: QR.svgPath(uri) };
  }
  function online() {
    const ids = new Set(['SIM']);
    const u = me(); if (u) ids.add(u.id);
    for (const p of peers.values()) if (Date.now() - p.at < 25000) ids.add(p.userId);
    ids.delete('SIM');
    for (const name of ['sam', 'dana']) { const x = S.users.find((y) => y.username === name); if (x) ids.add(x.id); }
    return [...ids];
  }
  function emitPresence() { emitLocal('presence', { online: online() }); }
  setInterval(() => { const u = me(); try { bc && u && bc.postMessage({ presence: u.id, tab: TAB }); } catch { /* ignore */ } }, 8000);
  addEventListener('pagehide', () => { try { bc && bc.postMessage({ bye: true, tab: TAB }); } catch { /* ignore */ } });

  class DemoEventSource {
    constructor() { this.readyState = 1; this.l = {}; streams.add(this); setTimeout(() => { this._emit('hello', { serverTime: now() }); emitPresence(); }, 30); }
    addEventListener(t, f) { (this.l[t] ||= []).push(f); }
    close() { this.readyState = 2; streams.delete(this); }
    _emit(t, d) { for (const f of this.l[t] || []) f({ data: JSON.stringify(d) }); }
  }
  window.EventSource = DemoEventSource;

  // ---------- session (one per browser tab) ----------
  const SKEY = 'lifeboat-demo-session';
  let session = null;
  try { session = JSON.parse(sessionStorage.getItem(SKEY) || 'null'); } catch { /* ignore */ }
  function setSession(s) { session = s; try { s ? sessionStorage.setItem(SKEY, JSON.stringify(s)) : sessionStorage.removeItem(SKEY); } catch { /* ignore */ } }
  function me() {
    if (!session) return null;
    const u = findUser(session.userId);
    const usable = u && (u.status === 'active' || (u.status === 'invited' && u.mustChangePassword));
    if (!usable || (S.lockdown.on && u.role !== 'admin')) return null;
    if ((session.epoch ?? 0) !== (S.sessionEpoch || 0) || (session.uepoch ?? 0) !== (u.sessionEpoch || 0)) return null;
    if (Date.now() - new Date(session.createdAt).getTime() > 8 * 3600e3) return null;
    return u;
  }

  function touch(inc, u, what) { inc.updatedAt = now(); inc.version = (inc.version || 0) + 1; broadcast('incident', { id: inc.id, by: u?.id, what }, { inc: inc.id }); }
  function postMessage(u, ch, text, urgent = false, ackedBy = null) {
    const m = { id: rid('m_'), channelId: ch.id, userId: u?.id || null, text, at: now(), urgent: !!urgent, acks: {} };
    if (u && urgent) m.acks[u.id] = m.at;
    if (ackedBy) m.acks[ackedBy.id] = m.at;
    S.messages.push(m);
    broadcast('message', m, { ch: ch.id });
    return m;
  }
  function softDelete(u, inc, list, id) {
    const item = inc[list].find((x) => x.id === id);
    if (!item) throw new HE(404, 'Not found');
    if (item.by !== u.id && item.createdBy !== u.id && !can(u, 'incident.manage')) throw new HE(403, 'You can only strike your own entries.');
    item.deleted = { by: u.id, at: now() };
    audit(u, list + '.strike', inc.ref, { id }); touch(inc, u, list);
    return { ok: true };
  }
  function guessIoc(v) {
    if (/^\d{1,3}(\.\d{1,3}){3}(\/\d+)?$/.test(v)) return 'ip';
    if (/^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i.test(v)) return 'hash';
    if (/^https?:\/\//i.test(v)) return 'url';
    if (/^[^@\s]+@[^@\s]+\.[a-z]{2,}$/i.test(v)) return 'email';
    if (/^([a-z0-9-]+\.)+[a-z]{2,}$/i.test(v)) return 'domain';
    if (/\.(exe|dll|ps1|bat|js|vbs|msi|zip|iso|lnk)$/i.test(v)) return 'file';
    return 'other';
  }
  const SCOPE_STATUS = ['encrypted', 'exfiltrated', 'accessed', 'deleted', 'corrupted', 'at-risk', 'secured', 'restored'];
  function scopeFields(b, row = {}) {
    if ('asset' in b || !row.asset) row.asset = str(b.asset, 200, { required: true, name: 'Data set' });
    if ('system' in b) row.system = str(b.system, 200);
    if ('dataTypes' in b) row.dataTypes = (b.dataTypes || []).filter((t) => REG.DATA_TYPES[t]);
    row.dataTypes ||= [];
    if ('records' in b) row.records = int(b.records);
    if ('residents' in b) { const r = {}; for (const [k, v] of Object.entries(b.residents || {})) { const c = String(k).toUpperCase().slice(0, 4); if (/^[A-Z]{2,4}$/.test(c) && Number(v) > 0) r[c] = int(v); } row.residents = r; }
    row.residents ||= {};
    if ('status' in b) row.status = oneOf(b.status, SCOPE_STATUS, 'status');
    row.status ||= 'at-risk';
    if ('confidence' in b) row.confidence = oneOf(b.confidence, ['confirmed', 'suspected', 'ruled-out'], 'confidence');
    row.confidence ||= 'suspected';
    if ('notes' in b) row.notes = str(b.notes, 2000);
    return row;
  }
  function incFor(u, id) { const inc = findInc(id); if (!canSee(u, inc)) throw new HE(404, 'Incident not found'); return inc; }
  const enrollments = new Map();

  // ---------- routes ----------
  const routes = [];
  const route = (method, pattern, opts, fn) => { const keys = []; const re = new RegExp('^' + pattern.replace(/:(\w+)/g, (_, k) => (keys.push(k), '([A-Za-z0-9_-]+)')) + '$'); routes.push({ method, re, keys, opts, fn }); };

  route('GET', '/api/auth/status', { public: true }, () => ({ setupPending: false, lockdown: S.lockdown.on, tls: true }));
  route('POST', '/api/auth/login', { public: true }, async ({ body }) => {
    const user = S.users.find((u) => u.username === String(body.username || '').toLowerCase().trim());
    const fail = () => new HE(401, 'Sign-in failed. Check your username, password and 6-digit code.');
    if (user && (user.lockedUntil || 0) > Date.now()) throw new HE(423, 'This account is temporarily locked after repeated failed attempts. Wait 15 minutes or ask an administrator.');
    const pwOk = user && (user.status === 'active' || (user.status === 'invited' && user.mustChangePassword)) && (user.demoPassword ? body.password === 'lifeboat-demo-2026' : user.passHash === await sha256(user.id + ':' + body.password));
    const strike = () => { if (user) { user.failed = (user.failed || 0) + 1; if (user.failed >= 5) { user.lockedUntil = Date.now() + 15 * 60e3; user.failed = 0; } save(); } };
    if (!pwOk) { strike(); audit(user || null, 'auth.login.failed', body.username, { why: 'password' }); throw fail(); }
    const step = await verifyTotp(user.totpSecret, body.totp, user.lastTotpStep ?? -1);
    if (step < 0) { strike(); audit(user, 'auth.login.failed', user.username, { why: 'mfa' }); throw fail(); }
    if (S.lockdown.on && user.role !== 'admin') throw new HE(403, 'WINDX is in lockdown. Only administrators can sign in right now.');
    Object.assign(user, { lastTotpStep: step, failed: 0, lastLogin: now() });
    setSession({ id: rid('s_'), userId: user.id, csrf: rid(), createdAt: now(), epoch: S.sessionEpoch || 0, uepoch: user.sessionEpoch || 0 });
    audit(user, 'auth.login', user.username, user.mustChangePassword ? { firstSignIn: true } : null); save();
    startSimulation();
    return { ok: true, mustChangePassword: !!user.mustChangePassword };
  });
  route('POST', '/api/auth/password', {}, async ({ u, body }) => {
    const pw = String(body.newPassword || '');
    if (!u.mustChangePassword) {
      const cur = String(body.currentPassword || '');
      const ok = u.demoPassword ? cur === 'lifeboat-demo-2026' : u.passHash === await sha256(u.id + ':' + cur);
      if (!ok) throw bad('Your current password is not right.');
    }
    if (pw.length < 12) throw bad('Use at least 12 characters. A short sentence works well.');
    if (pw.length > 200) throw bad('That password is too long.');
    if (pw.toLowerCase().includes(u.username)) throw bad('Your password cannot contain your username.');
    const h = await sha256(u.id + ':' + pw);
    if (u.mustChangePassword && h === u.tempHash) throw bad('Choose a new password, not the temporary one.');
    const first = !!u.mustChangePassword;
    Object.assign(u, { passHash: h, mustChangePassword: false, tempHash: null, status: 'active' });
    delete u.demoPassword;
    u.sessionEpoch = (u.sessionEpoch || 0) + 1; session.uepoch = u.sessionEpoch; setSession(session);
    try { bc && bc.postMessage({ kick: 'revoked' }); } catch { /* ignore */ }
    audit(u, 'auth.password_change', u.username, first ? { firstSignIn: true } : null); broadcast('users', {});
    return { ok: true };
  });
  route('POST', '/api/auth/logout', { public: true }, () => { const u = me(); if (u) audit(u, 'auth.logout', u.username); setSession(null); return { ok: true }; });
  route('POST', '/api/auth/enroll', { public: true }, async ({ body }) => {
    const username = String(body.username || '').toLowerCase().trim();
    const code = String(body.code || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
    const user = S.users.find((u) => u.username === username && u.status === 'invited');
    if (!user || user.inviteExpires < Date.now() || (await sha256(code)) !== user.inviteHash) throw new HE(401, 'That invite code is not valid or has expired. Ask your administrator for a new one.');
    const pw = String(body.password || '');
    if (pw.length < 12) throw bad('Password must be at least 12 characters. A short sentence works well.');
    const secret = b32enc(crypto.getRandomValues(new Uint8Array(20)));
    const token = rid('en_');
    enrollments.set(token, { userId: user.id, pw, secret });
    const uri = `otpauth://totp/WINDX:${encodeURIComponent(user.username)}?secret=${secret}&issuer=WINDX&algorithm=SHA1&digits=6&period=30`;
    return { enrollToken: token, secret, uri, qr: QR.svgPath(uri) };
  });
  route('POST', '/api/auth/enroll/confirm', { public: true }, async ({ body }) => {
    const e = enrollments.get(String(body.enrollToken || ''));
    if (!e) throw new HE(401, 'Enrollment expired. Start again with your invite code.');
    const user = findUser(e.userId);
    const step = await verifyTotp(e.secret, body.totp);
    if (step < 0) throw bad('That code did not match. Check the time on your phone is correct, and enter the newest code.');
    enrollments.delete(String(body.enrollToken));
    Object.assign(user, { passHash: await sha256(user.id + ':' + e.pw), totpSecret: e.secret, lastTotpStep: step, status: 'active', inviteHash: null, inviteExpires: null, lastLogin: now() });
    delete user.demoPassword;
    setSession({ id: rid('s_'), userId: user.id, csrf: rid(), createdAt: now(), epoch: S.sessionEpoch || 0, uepoch: user.sessionEpoch || 0 });
    audit(user, 'user.enrolled', user.username);
    broadcast('users', {});
    return { ok: true };
  });

  route('GET', '/api/me', {}, ({ u }) => ({
    user: publicUser(u, true), csrf: session.csrf,
    roles: Object.fromEntries(Object.entries(ROLES).map(([k, v]) => [k, v.label])),
    perms: Object.fromEntries(['incident.write', 'incident.create', 'incident.manage', 'privileged.read', 'legal.write', 'contacts.write', 'audit.read', 'channel.create', 'admin'].map((p) => [p, can(u, p)])),
    serverTime: now(), idleMinutes: 15, tls: true,
    session: { createdAt: session.createdAt, ip: 'this browser', maxHours: 8 },
  }));
  const RANGES = { week: 7, month: 30, '6months': 182, year: 365, all: null };
  route('GET', '/api/me/history', {}, async ({ u, url }) => {
    await auditQ;
    const range = url.searchParams.get('range') || 'month';
    if (!(range in RANGES)) throw bad('Unknown time range');
    const since = RANGES[range] ? Date.now() - RANGES[range] * 864e5 : 0;
    const mine = S.audit.filter((e) => e.actor?.id === u.id && new Date(e.at).getTime() >= since);
    return { range, since: since ? new Date(since).toISOString() : null, total: mine.length, entries: mine.slice(-3000).reverse().map(({ seq, at, action, target, detail }) => ({ seq, at, action, target, detail })) };
  });
  route('POST', '/api/ping', {}, () => ({ ok: true }));
  route('GET', '/api/bootstrap', {}, ({ u }) => ({
    org: S.org, lockdown: S.lockdown, users: S.users.map((x) => publicUser(x)),
    incidents: S.incidents.filter((i) => canSee(u, i)).map((i) => ({ id: i.id })),
    channels: S.channels.filter((c) => canSeeChannel(u, c)).map((c) => ({ ...c })),
    phases: PB.PHASES, categories: PB.CATEGORIES, dataTypes: REG.DATA_TYPES,
    states: Object.fromEntries(Object.entries(REG.STATES).map(([k, v]) => [k, v.name])), online: online(),
  }));

  route('GET', '/api/incidents/:id', {}, ({ u, p }) => full(incFor(u, p.id)));
  route('POST', '/api/incidents', { perm: 'incident.create' }, ({ u, body }) => {
    S.meta.incidentSeq = (S.meta.incidentSeq || 0) + 1;
    const category = oneOf(body.category || 'other', Object.keys(PB.CATEGORIES), 'category');
    const inc = {
      id: rid('i_'), ref: `IR-${new Date().getUTCFullYear()}-${String(S.meta.incidentSeq).padStart(4, '0')}`, codename: PB.codename(),
      title: str(body.title, 200, { required: true, name: 'Title' }), summary: str(body.summary, 8000), severity: int(body.severity || 2, 1, 4), category,
      status: 'triage', privileged: body.privileged !== false, access: body.restricted ? 'restricted' : 'all', members: body.restricted ? [u.id] : [],
      detectedAt: date(body.detectedAt) || now(), occurredAt: null, breachDeterminedAt: null, materialityDeterminedAt: null,
      leadId: u.id, createdBy: u.id, createdAt: now(), updatedAt: now(), affectedSystems: [], attackVector: '',
      timeline: [], tasks: [], iocs: [], scope: [], evidence: [], notifications: {}, version: 1,
    };
    addTimeline(inc, u, `Incident declared by ${u.displayName}: ${inc.title}`);
    for (const t of PB.tasksFor(category)) inc.tasks.push({ id: rid('k_'), title: t.title, phase: t.phase, status: 'open', assigneeId: null, due: null, createdBy: null, createdAt: now(), playbook: true });
    S.incidents.push(inc);
    const ch = { id: rid('c_'), name: inc.codename.toLowerCase().replace(/\s+/g, '-'), kind: 'incident', incidentId: inc.id, createdAt: now() };
    S.channels.push(ch);
    postMessage(null, ch, `${inc.ref} "${inc.codename}" declared at SEV${inc.severity} by ${u.displayName}. This is the incident room.`, true, u);
    audit(u, 'incident.create', inc.ref, { title: inc.title });
    touch(inc, u, 'created');
    broadcast('channels', {});
    return full(inc);
  });
  const LEGAL = new Set(['breachDeterminedAt', 'materialityDeterminedAt', 'privileged']);
  route('PATCH', '/api/incidents/:id', { perm: 'incident.write' }, ({ u, p, body }) => {
    const inc = incFor(u, p.id);
    const ch = {};
    const set = (k, v) => { if (JSON.stringify(inc[k]) !== JSON.stringify(v)) { ch[k] = v; inc[k] = v; } };
    for (const k of Object.keys(body)) {
      if (LEGAL.has(k) && !can(u, 'legal.write')) throw new HE(403, 'Only counsel or incident commanders can change legal determinations.');
      if (k === 'title') set(k, str(body[k], 200, { required: true, name: 'Title' }));
      else if (k === 'summary') set(k, str(body[k], 8000));
      else if (k === 'attackVector') set(k, str(body[k], 1000));
      else if (k === 'severity') { const v = int(body[k], 1, 4); if (!can(u, 'incident.manage') && v > inc.severity) throw new HE(403, 'Only incident commanders can downgrade severity.'); set(k, v); }
      else if (k === 'category') set(k, oneOf(body[k], Object.keys(PB.CATEGORIES), 'category'));
      else if (k === 'status') {
        const v = oneOf(body[k], PB.PHASES.map((x) => x.id), 'status');
        if ((v === 'closed' || inc.status === 'closed') && !can(u, 'incident.manage')) throw new HE(403, 'Only incident commanders can close or reopen incidents.');
        set(k, v); if (v === 'eradication' && !inc.containedAt) inc.containedAt = now(); if (v === 'closed') inc.closedAt = now(); else if (inc.closedAt) inc.closedAt = null;
      } else if (['detectedAt', 'occurredAt', 'containedAt', 'breachDeterminedAt', 'materialityDeterminedAt'].includes(k)) set(k, date(body[k]));
      else if (k === 'privileged') set(k, !!body[k]);
      else if (k === 'leadId') set(k, body[k] && findUser(body[k]) ? body[k] : null);
      else if (k === 'affectedSystems') set(k, (body[k] || []).map((x) => str(x, 200)).filter(Boolean));
      else if (k === 'access' || k === 'members') {
        if (!can(u, 'incident.manage')) throw new HE(403, 'Only incident commanders can change who can see an incident.');
        set(k, k === 'access' ? oneOf(body[k], ['all', 'restricted'], 'access') : [...new Set((body[k] || []).filter(findUser))]);
      } else throw bad(`Field "${k}" cannot be changed`);
    }
    const label = { status: 'Phase', severity: 'Severity', leadId: 'Incident lead', breachDeterminedAt: 'Breach determination', materialityDeterminedAt: 'Materiality determination', access: 'Visibility', privileged: 'Privilege marking' };
    for (const [k, to] of Object.entries(ch)) {
      if (!label[k]) continue;
      let v = to;
      if (k === 'status') v = PB.PHASES.find((x) => x.id === to).label;
      if (k === 'severity') v = 'SEV' + to;
      if (k === 'leadId') v = findUser(to)?.displayName || 'nobody';
      if (k.endsWith('At')) v = to ? new Date(to).toUTCString() : 'cleared';
      if (k === 'privileged') v = to ? 'privileged & confidential' : 'not privileged';
      addTimeline(inc, u, `${label[k]} set to ${v}`);
    }
    if (Object.keys(ch).length) { audit(u, 'incident.update', inc.ref, Object.keys(ch)); if (ch.access || ch.members) broadcast('channels', {}); touch(inc, u, Object.keys(ch).join(',')); }
    return full(inc);
  });
  route('POST', '/api/incidents/:id/timeline', { perm: 'incident.write' }, ({ u, p, body }) => {
    const inc = incFor(u, p.id);
    const e = addTimeline(inc, u, str(body.text, 4000, { required: true, name: 'Entry' }), oneOf(body.kind || 'note', ['note', 'action', 'finding', 'decision', 'comms'], 'kind'), date(body.at));
    audit(u, 'timeline.add', inc.ref, { kind: e.kind }); touch(inc, u, 'timeline'); return e;
  });
  for (const list of ['timeline', 'tasks', 'iocs', 'scope']) route('DELETE', `/api/incidents/:id/${list}/:eid`, { perm: 'incident.write' }, ({ u, p }) => softDelete(u, incFor(u, p.id), list, p.eid));
  route('POST', '/api/incidents/:id/tasks', { perm: 'incident.write' }, ({ u, p, body }) => {
    const inc = incFor(u, p.id);
    const t = { id: rid('k_'), title: str(body.title, 300, { required: true, name: 'Task' }), phase: oneOf(body.phase || (inc.status === 'closed' ? 'post' : inc.status), PB.PHASES.map((x) => x.id), 'phase'), status: 'open', assigneeId: body.assigneeId && findUser(body.assigneeId) ? body.assigneeId : null, due: date(body.due), createdBy: u.id, createdAt: now() };
    inc.tasks.push(t); audit(u, 'task.add', inc.ref, { title: t.title }); touch(inc, u, 'tasks');
    if (t.assigneeId) broadcast('notify', { text: `${u.displayName} assigned you a task in ${inc.ref}: ${t.title}`, incidentId: inc.id }, { user: t.assigneeId });
    return t;
  });
  route('PATCH', '/api/incidents/:id/tasks/:eid', { perm: 'incident.write' }, ({ u, p, body }) => {
    const inc = incFor(u, p.id);
    const t = inc.tasks.find((x) => x.id === p.eid); if (!t) throw new HE(404, 'Task not found');
    if ('status' in body) { t.status = oneOf(body.status, ['open', 'doing', 'blocked', 'done'], 'status'); if (t.status === 'done') { t.doneAt = now(); t.doneBy = u.id; addTimeline(inc, u, `Task completed: ${t.title}`, 'action'); } else t.doneAt = null; }
    if ('assigneeId' in body) { t.assigneeId = body.assigneeId && findUser(body.assigneeId) ? body.assigneeId : null; if (t.assigneeId && t.assigneeId !== u.id) broadcast('notify', { text: `${u.displayName} assigned you a task in ${inc.ref}: ${t.title}`, incidentId: inc.id }, { user: t.assigneeId }); }
    if ('title' in body) t.title = str(body.title, 300, { required: true, name: 'Task' });
    if ('due' in body) t.due = date(body.due);
    if ('phase' in body) t.phase = oneOf(body.phase, PB.PHASES.map((x) => x.id), 'phase');
    audit(u, 'task.update', inc.ref, body); touch(inc, u, 'tasks'); return t;
  });
  route('POST', '/api/incidents/:id/iocs', { perm: 'incident.write' }, ({ u, p, body }) => {
    const inc = incFor(u, p.id);
    const vals = (Array.isArray(body.values) ? body.values : [body.value]).map((v) => str(v, 2000)).filter(Boolean).slice(0, 500);
    if (!vals.length) throw bad('Enter at least one indicator');
    let added = 0;
    for (const value of vals) { if (inc.iocs.some((i) => !i.deleted && i.value === value)) continue; inc.iocs.push({ id: rid('o_'), type: guessIoc(value), value, note: str(body.note, 500), by: u.id, at: now() }); added++; }
    audit(u, 'ioc.add', inc.ref, { count: added }); touch(inc, u, 'iocs'); return { added };
  });
  route('POST', '/api/incidents/:id/scope', { perm: 'incident.write' }, ({ u, p, body }) => {
    const inc = incFor(u, p.id);
    const row = scopeFields(body, { id: rid('d_'), createdBy: u.id, createdAt: now() });
    Object.assign(row, { updatedBy: u.id, updatedAt: now(), history: [{ at: now(), by: u.id, status: row.status, confidence: row.confidence }] });
    inc.scope.push(row);
    addTimeline(inc, u, `Scope: "${row.asset}" recorded as ${row.status.toUpperCase()} (${row.confidence}), ${row.records.toLocaleString()} records`, 'finding');
    audit(u, 'scope.add', inc.ref, { asset: row.asset }); touch(inc, u, 'scope'); return row;
  });
  route('PATCH', '/api/incidents/:id/scope/:eid', { perm: 'incident.write' }, ({ u, p, body }) => {
    const inc = incFor(u, p.id);
    const row = inc.scope.find((x) => x.id === p.eid); if (!row) throw new HE(404, 'Not found');
    const before = row.status + '/' + row.confidence;
    scopeFields(body, row); row.updatedBy = u.id; row.updatedAt = now();
    if (row.status + '/' + row.confidence !== before) { row.history = [...(row.history || []), { at: now(), by: u.id, status: row.status, confidence: row.confidence }]; addTimeline(inc, u, `Scope: "${row.asset}" changed to ${row.status.toUpperCase()} (${row.confidence})`, 'finding'); }
    audit(u, 'scope.update', inc.ref, { id: row.id }); touch(inc, u, 'scope'); return row;
  });
  route('PATCH', '/api/incidents/:id/obligations/:eid', { perm: 'legal.write' }, ({ u, p, body }) => {
    const inc = incFor(u, p.id);
    const cur = inc.notifications[p.eid] || {};
    const status = oneOf(body.status || cur.status || 'pending', ['pending', 'in-progress', 'done', 'na'], 'status');
    inc.notifications[p.eid] = { status, notes: 'notes' in body ? str(body.notes, 2000) : cur.notes || '', updatedBy: u.id, updatedAt: now(), doneAt: status === 'done' ? cur.doneAt || now() : null };
    if (status !== cur.status) addTimeline(inc, u, `Obligation "${p.eid}" marked ${status === 'na' ? 'NOT APPLICABLE' : status.toUpperCase()}`, 'decision');
    audit(u, 'obligation.update', inc.ref, { id: p.eid, status }); touch(inc, u, 'obligations'); return inc.notifications[p.eid];
  });
  route('POST', '/api/incidents/:id/evidence', { perm: 'incident.write' }, async ({ u, p, body, raw, headers }) => {
    const inc = incFor(u, p.id);
    let ev;
    if (raw) {
      const buf = await raw.arrayBuffer();
      const name = decodeURIComponent(headers['X-Filename'] || 'evidence.bin').replace(/[\\/]/g, '_');
      const h = await sha256(buf);
      ev = { id: rid('e_'), kind: 'file', name, size: buf.byteLength, sha256: h, note: decodeURIComponent(headers['X-Note'] || ''), location: 'Hash recorded (online demo does not store files)' };
    } else ev = { id: rid('e_'), kind: 'item', name: str(body.name, 200, { required: true, name: 'Item' }), size: null, sha256: body.sha256 ? str(body.sha256, 128) : null, note: str(body.note, 1000), location: str(body.location, 300) };
    Object.assign(ev, { collectedBy: u.id, collectedAt: now(), custody: [{ at: now(), by: u.id, action: raw ? `Uploaded & hashed (SHA-256 ${ev.sha256.slice(0, 16)}…)` : `Logged into custody${ev.location ? ' at ' + ev.location : ''}` }] });
    inc.evidence.push(ev); addTimeline(inc, u, `Evidence collected: ${ev.name}`, 'action');
    audit(u, 'evidence.add', inc.ref, { name: ev.name, sha256: ev.sha256 }); touch(inc, u, 'evidence'); return ev;
  });
  route('POST', '/api/incidents/:id/evidence/:eid/custody', { perm: 'incident.write' }, ({ u, p, body }) => {
    const inc = incFor(u, p.id);
    const ev = inc.evidence.find((x) => x.id === p.eid); if (!ev) throw new HE(404, 'Not found');
    ev.custody.push({ at: now(), by: u.id, action: str(body.action, 500, { required: true, name: 'Custody action' }) });
    audit(u, 'evidence.custody', inc.ref); touch(inc, u, 'evidence'); return ev;
  });

  route('GET', '/api/channels/:id/messages', {}, ({ u, p }) => { const ch = S.channels.find((c) => c.id === p.id); if (!canSeeChannel(u, ch)) throw new HE(404, 'Channel not found'); return S.messages.filter((m) => m.channelId === ch.id).slice(-500); });
  route('POST', '/api/channels/:id/messages', {}, ({ u, p, body }) => {
    const ch = S.channels.find((c) => c.id === p.id); if (!canSeeChannel(u, ch)) throw new HE(404, 'Channel not found');
    const urgent = !!body.urgent && u.role !== 'observer';
    const m = postMessage(u, ch, str(body.text, 4000, { required: true, name: 'Message' }), urgent);
    audit(u, urgent ? 'message.urgent' : 'message.post', ch.name); return m;
  });
  route('POST', '/api/messages/:id/ack', {}, ({ u, p }) => {
    const m = S.messages.find((x) => x.id === p.id); const ch = m && S.channels.find((c) => c.id === m.channelId);
    if (!m || !canSeeChannel(u, ch)) throw new HE(404, 'Not found');
    if (!m.acks[u.id]) { m.acks[u.id] = now(); broadcast('ack', { id: m.id, channelId: m.channelId, userId: u.id, at: m.acks[u.id] }, { ch: ch.id }); }
    return { ok: true };
  });
  route('POST', '/api/channels', { perm: 'channel.create' }, ({ u, body }) => {
    const name = str(body.name, 40, { required: true, name: 'Channel name' }).toLowerCase().replace(/[^a-z0-9-]+/g, '-');
    const members = Array.isArray(body.members) && body.members.length ? [...new Set([u.id, ...body.members.filter(findUser)])] : null;
    const ch = { id: rid('c_'), name, kind: 'custom', members, createdBy: u.id, createdAt: now() };
    S.channels.push(ch); audit(u, 'channel.create', name); broadcast('channels', {}); return ch;
  });
  route('PUT', '/api/org', { perm: 'admin' }, ({ u, body }) => {
    const o = S.org;
    o.name = str(body.name ?? o.name, 120, { required: true, name: 'Organization name' });
    for (const k of ['publiclyTraded', 'hipaaCovered', 'nydfsRegulated', 'criticalInfrastructure']) if (k in body) o[k] = !!body[k];
    if (body.insurance) o.insurance = { carrier: str(body.insurance.carrier, 120), policy: str(body.insurance.policy, 80), hotline: str(body.insurance.hotline, 80), noticeHours: int(body.insurance.noticeHours || 72, 1, 8760) };
    if (body.outsideCounsel) o.outsideCounsel = { firm: str(body.outsideCounsel.firm, 120), contact: str(body.outsideCounsel.contact, 120), phone: str(body.outsideCounsel.phone, 80) };
    audit(u, 'org.update', o.name); broadcast('org', {}); return o;
  });
  route('PUT', '/api/contacts', { perm: 'contacts.write' }, ({ u, body }) => {
    S.org.contacts = (body.contacts || []).slice(0, 200).map((c) => ({ id: c.id || rid('p_'), name: str(c.name, 120, { required: true, name: 'Name' }), role: str(c.role, 120), org: str(c.org, 120), phone: str(c.phone, 60), alt: str(c.alt, 60), notes: str(c.notes, 500), group: str(c.group, 60) }));
    audit(u, 'contacts.update'); broadcast('org', {}); return S.org.contacts;
  });
  function inviteCode() { const a = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; const b = crypto.getRandomValues(new Uint8Array(15)); let s = ''; for (const x of b) s += a[x % 32]; return `${s.slice(0, 5)}-${s.slice(5, 10)}-${s.slice(10)}`; }
  route('GET', '/api/admin/users', { perm: 'admin' }, () => S.users.map((x) => publicUser(x, true)));
  route('POST', '/api/admin/users', { perm: 'admin' }, async ({ u, body }) => {
    const username = str(body.username, 32, { required: true, name: 'Username' }).toLowerCase();
    if (!/^[a-z0-9._-]{2,32}$/.test(username)) throw bad('Username: 2-32 characters, letters, numbers, dot, dash or underscore');
    if (S.users.some((x) => x.username === username)) throw new HE(409, 'That username is taken');
    const nu = { id: rid('u_'), username, displayName: str(body.displayName, 80, { required: true, name: 'Full name' }), role: oneOf(body.role || 'responder', Object.keys(ROLES), 'role'), title: str(body.title, 80), phone: str(body.phone, 60), createdAt: now() };
    if (nu.role === 'admin') await stepUp(u, body.code, 'user.create_admin');
    const card = await newSignInCard(nu);
    S.users.push(nu); audit(u, 'user.create', username, { role: nu.role, ...(nu.role === 'admin' ? { mfa: 'verified' } : {}) }); broadcast('users', {});
    return { user: publicUser(nu, true), card };
  });
  route('PATCH', '/api/admin/users/:id', { perm: 'admin' }, async ({ u, p, body }) => {
    const x = findUser(p.id); if (!x) throw new HE(404, 'User not found');
    if (x.id === u.id && ((body.role && body.role !== 'admin') || body.status === 'disabled')) throw bad('You cannot remove your own admin role or disable yourself. Ask another administrator.');
    const role = 'role' in body ? oneOf(body.role, Object.keys(ROLES), 'role') : x.role;
    const status = 'status' in body ? oneOf(body.status, ['active', 'disabled'], 'status') : null;
    if (role === 'admin' && x.role !== 'admin') await stepUp(u, body.code, 'user.make_admin');
    else if (status === 'disabled' && x.status !== 'disabled') await stepUp(u, body.code, 'user.disable');
    const changes = {};
    if (role !== x.role) { changes.role = { from: x.role, to: role }; x.role = role; }
    if (status && status !== x.status) {
      if (status === 'active') x.status = x.mustChangePassword ? 'invited' : 'active';
      else { x.status = 'disabled'; endSessions(x.id, 'disabled'); }
      changes.status = status;
    }
    if (body.unlock) { x.lockedUntil = 0; x.failed = 0; changes.unlocked = true; }
    audit(u, status === 'disabled' ? 'user.disable' : 'user.update', x.username, { ...changes, ...(status === 'disabled' || changes.role?.to === 'admin' ? { mfa: 'verified' } : {}) });
    broadcast('users', {}); return publicUser(x, true);
  });
  route('POST', '/api/admin/users/:id/reset', { perm: 'admin' }, async ({ u, p, body }) => {
    const x = findUser(p.id); if (!x) throw new HE(404, 'User not found');
    if (x.id === u.id) throw bad('Ask another administrator to reset your own account.');
    await stepUp(u, body.code, 'user.reset');
    const card = await newSignInCard(x);
    endSessions(x.id, 'revoked');
    audit(u, 'user.reset', x.username, { mfa: 'verified' }); broadcast('users', {});
    return { user: publicUser(x, true), card };
  });
  route('GET', '/api/admin/sessions', { perm: 'admin' }, ({ u }) => [{ id: session.id, user: publicUser(u), ip: 'this browser', ua: navigator.userAgent, createdAt: session.createdAt, lastSeen: now(), current: true, live: true }]);
  route('DELETE', '/api/admin/sessions/:id', { perm: 'admin' }, () => ({ ok: true }));
  route('POST', '/api/admin/lockdown', { perm: 'admin' }, async ({ u, body }) => {
    if (!body.on) { S.lockdown = { on: false, by: u.id, at: now() }; audit(u, 'lockdown.off'); broadcast('lockdown', S.lockdown); return S.lockdown; }
    if (body.confirm !== 'LOCKDOWN') throw bad('Type LOCKDOWN to confirm.');
    await stepUp(u, body.code, 'lockdown');
    const killed = 1 + [...peers.values()].filter((x) => Date.now() - x.at < 25000).length;
    S.lockdown = { on: true, by: u.id, at: now() };
    audit(u, 'LOCKDOWN', null, { mfa: 'verified', killed });
    endSessions(null, 'lockdown'); setSession(null);
    return { ok: true, killed };
  });
  route('GET', '/api/audit', { perm: 'audit.read' }, async () => { await auditQ; return { entries: S.audit.slice(-1000).reverse(), total: S.audit.length }; });
  route('GET', '/api/audit/verify', { perm: 'audit.read' }, async ({ u }) => {
    await auditQ; await auditReady;
    let prev = 'GENESIS';
    for (const e of S.audit) { if (e.prev !== prev || e.hash !== (await auditHash(prev, e))) return { ok: false, brokenAt: e.seq, total: S.audit.length }; prev = e.hash; }
    audit(u, 'audit.verify', null, { ok: true });
    return { ok: true, total: S.audit.length, head: prev };
  });

  // ---------- fetch interception ----------
  const json = (s, o) => new Response(JSON.stringify(o), { status: s, headers: { 'Content-Type': 'application/json' } });
  const realFetch = window.fetch.bind(window);
  window.fetch = async (input, init = {}) => {
    const url = typeof input === 'string' ? input : input.url;
    if (!url.startsWith('/api/')) return realFetch(input, init);
    await new Promise((r) => setTimeout(r, 40)); // feel like a network
    const u0 = new URL(url, 'https://lifeboat.demo');
    const method = (init.method || 'GET').toUpperCase();
    const headers = init.headers || {};
    let body = {}, raw = null;
    if (init.body instanceof Blob) raw = init.body; else if (init.body) { try { body = JSON.parse(init.body); } catch { return json(400, { error: 'Malformed JSON' }); } }
    try {
      let m, params = {};
      const r = routes.find((x) => x.method === method && (m = u0.pathname.match(x.re)));
      if (!r) throw new HE(404, 'Not available in the online demo');
      r.keys.forEach((k, i) => (params[k] = m[i + 1]));
      if (method !== 'GET') { const fresh = loadState(); if (fresh) S = fresh; } // pick up other tabs' changes first
      const u = me();
      if (!r.opts.public) {
        if (!u) throw new HE(401, 'Not signed in');
        if (method !== 'GET' && headers['X-CSRF-Token'] !== session.csrf) throw new HE(403, 'Security token mismatch. Reload the page.');
        if (r.opts.perm && !can(u, r.opts.perm)) throw new HE(403, 'Your role does not allow this.');
        if (u.mustChangePassword && !['/api/me', '/api/auth/password', '/api/ping'].includes(u0.pathname)) throw new HE(403, 'Choose a new password before continuing.');
      }
      const out = await r.fn({ u, p: params, body, raw, headers, url: u0 });
      if (method !== 'GET') saveNow();
      return json(200, out ?? { ok: true });
    } catch (e) {
      if (e instanceof HE) return json(e.status, { error: e.message });
      console.error(e);
      return json(500, { error: 'Internal error' });
    }
  };

  // Downloads and printing are blocked inside an embedded page, so explain instead of failing silently.
  document.addEventListener('click', (e) => {
    const a = e.target.closest && e.target.closest('a[href^="/api/"]');
    if (a) { e.preventDefault(); e.stopPropagation(); window.toast && window.toast('File downloads are turned off in the online demo. The full app supports them.', 'err'); }
  }, true);
  // Inside Claude's viewer printing is blocked, so explain instead. On a normal website, printing works.
  if (window.claude) window.print = () => window.toast && window.toast('Printing is turned off in this view. In the full app this prints a court-ready report.', 'err');

  // ---------- simulated teammates, so the live updates are visible ----------
  function startSimulation() {
    try { if (sessionStorage.getItem('lifeboat-demo-sim')) return; sessionStorage.setItem('lifeboat-demo-sim', '1'); } catch { /* ignore */ }
    const inc = S.incidents.find((i) => i.codename === 'BLACK HERON');
    const sam = S.users.find((x) => x.username === 'sam');
    const dana = S.users.find((x) => x.username === 'dana');
    if (!inc || !sam || !dana) return;
    const room = S.channels.find((c) => c.incidentId === inc.id);
    const steps = [
      [25e3, () => { if (me()?.id !== sam.id && room) postMessage(sam, room, 'Northgate confirms the encryptor matches BlackSuit v2. No free decryptor available.'); }],
      [55e3, () => { addTimeline(inc, sam, 'Northgate confirmed encryptor is BlackSuit v2; no public decryptor exists', 'finding'); touch(inc, sam, 'timeline'); }],
      [90e3, () => { if (!inc.notifications.fbi || inc.notifications.fbi.status !== 'done') { inc.notifications.fbi = { status: 'done', notes: 'Spoke with SA Bell; IC3 complaint filed', updatedBy: dana.id, updatedAt: now(), doneAt: now() }; addTimeline(inc, dana, 'Obligation "fbi" marked DONE', 'decision'); touch(inc, dana, 'obligations'); } }],
    ];
    for (const [ms, fn] of steps) setTimeout(() => { try { fn(); } catch (e) { console.error(e); } }, ms);
  }

  // ---------- demo helper card ----------
  const USERS = [['jordan', 'Incident Commander'], ['dana', 'Legal Counsel'], ['sam', 'Responder'], ['alex', 'Administrator'], ['morgan', 'Executive (read-only)']];
  window.__lifeboatDemo = {
    reset() { try { localStorage.removeItem(KEY); sessionStorage.clear(); } catch { /* ignore */ } location.reload(); },
    async codes() {
      const out = [];
      for (const [u, r] of USERS) { const x = S.users.find((y) => y.username === u); let st = curStep(); if (x && (x.lastTotpStep ?? -1) >= st) st += 1; out.push([u, r, x?.totpSecret ? await totpAt(x.totpSecret, st) : '------']); }
      return out;
    },
    async signIn(username) {
      const user = S.users.find((x) => x.username === username);
      let step = curStep();
      if (user && (user.lastTotpStep ?? -1) >= step) step += 1; // this code was already used: take the next one
      const code = await totpAt(await demoSecret(username), step);
      let f = null;
      for (let i = 0; i < 40 && !f; i++) {
        f = document.querySelector('form[data-submit="login"]');
        if (!f) { const tab = document.querySelector('[data-a="authMode"][data-m="login"]'); if (tab) tab.click(); await new Promise((r) => setTimeout(r, 100)); }
      }
      if (!f) return false;
      f.username.value = username; f.password.value = 'lifeboat-demo-2026'; f.totp.value = code;
      f.requestSubmit(); return true;
    },
  };
})();
