#!/usr/bin/env node
'use strict';
/*
 * LIFEBOAT: out-of-band cyber incident command center.
 * Zero third-party dependencies. Node.js standard library only.
 */
const http = require('node:http');
const https = require('node:https');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const C = require('./lib/crypto');
const { Vault } = require('./lib/store');
const REG = require('./lib/regulations');
const PB = require('./lib/playbooks');
const QR = require('./lib/qr');

// ---------------------------------------------------------------- config
const ROOT = __dirname;
const DATA_DIR = path.resolve(process.env.LIFEBOAT_DATA || path.join(ROOT, 'data'));
const HOST = process.env.LIFEBOAT_HOST || '127.0.0.1';
const PORT = Number(process.env.LIFEBOAT_PORT || 8443);
const TLS_CERT = process.env.LIFEBOAT_TLS_CERT || path.join(DATA_DIR, 'tls', 'cert.pem');
const TLS_KEY = process.env.LIFEBOAT_TLS_KEY || path.join(DATA_DIR, 'tls', 'key.pem');
const IDLE_MS = Number(process.env.LIFEBOAT_IDLE_MIN || 30) * 60e3;
const ABSOLUTE_MS = 12 * 3600e3;
const INVITE_TTL = 72 * 3600e3;
const MAX_EVIDENCE = 50 * 1024 * 1024;
const LOGIN_RATE = Number(process.env.LIFEBOAT_LOGIN_RATE || 20); // sign-in attempts per IP per 15 min

const ROLES = {
  admin: { label: 'Administrator', perms: ['*'] },
  commander: { label: 'Incident Commander', perms: ['incident.read', 'incident.write', 'incident.create', 'incident.manage', 'legal.write', 'contacts.write', 'audit.read', 'channel.create'] },
  responder: { label: 'Responder', perms: ['incident.read', 'incident.write', 'incident.create'] },
  counsel: { label: 'Legal Counsel', perms: ['incident.read', 'incident.write', 'legal.write', 'audit.read', 'channel.create'] },
  observer: { label: 'Executive (read-only)', perms: ['incident.read'] },
};
const can = (u, p) => !!u && (ROLES[u.role]?.perms.includes('*') || ROLES[u.role]?.perms.includes(p));

// ---------------------------------------------------------------- helpers
class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}
const bad = (m) => new HttpError(400, m);
const now = () => new Date().toISOString();

function str(v, max = 500, { required = false, name = 'field' } = {}) {
  if (v === undefined || v === null) v = '';
  if (typeof v !== 'string' && typeof v !== 'number') throw bad(`${name} must be text`);
  const s = String(v).replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '').trim();
  if (required && !s) throw bad(`${name} is required`);
  if (s.length > max) throw bad(`${name} is too long (max ${max})`);
  return s;
}
function oneOf(v, list, name) {
  if (!list.includes(v)) throw bad(`Invalid ${name}`);
  return v;
}
function date(v, name = 'date') {
  if (v === null || v === '' || v === undefined) return null;
  const t = new Date(v);
  if (isNaN(t)) throw bad(`Invalid ${name}`);
  return t.toISOString();
}
function int(v, min = 0, max = 1e10) {
  const n = Math.round(Number(v) || 0);
  return Math.max(min, Math.min(max, n));
}

// ---------------------------------------------------------------- vault
const vault = new Vault(DATA_DIR);
const S = () => vault.state;
const findUser = (id) => S().users.find((u) => u.id === id);
const findIncident = (id) => S().incidents.find((i) => i.id === id);

function publicUser(u, full = false) {
  const o = { id: u.id, username: u.username, displayName: u.displayName, role: u.role, title: u.title || '', phone: u.phone || '', status: u.status };
  if (full) Object.assign(o, { createdAt: u.createdAt, lastLogin: u.lastLogin || null, mfa: !!u.totpSecret, locked: (u.lockedUntil || 0) > Date.now(), inviteExpires: u.inviteExpires || null });
  return o;
}

function canSee(user, inc) {
  if (!inc || !can(user, 'incident.read')) return false;
  if (inc.access !== 'restricted') return true;
  return user.role === 'admin' || inc.leadId === user.id || inc.createdBy === user.id || (inc.members || []).includes(user.id);
}
function canSeeChannel(user, ch) {
  if (!ch) return false;
  if (ch.incidentId) return canSee(user, findIncident(ch.incidentId));
  if (ch.members) return user.role === 'admin' || ch.members.includes(user.id);
  return true;
}

// ---------------------------------------------------------------- sessions
const sessions = new Map(); // sha256(token) -> session
const enrollments = new Map(); // enrollToken -> pending enrollment
const limits = new Map();

function rateLimit(key, max, windowMs) {
  const t = Date.now();
  let e = limits.get(key);
  if (!e || e.reset < t) { e = { n: 0, reset: t + windowMs }; limits.set(key, e); }
  e.n++;
  if (e.n > max) throw new HttpError(429, 'Too many attempts. Wait a few minutes and try again.');
}

let useTls = false;
const cookieName = () => (useTls ? '__Host-lb' : 'lb_sid');

function createSession(user, req, res) {
  const token = C.randomToken(32);
  const s = {
    id: C.randomId('s_'), userId: user.id, csrf: C.randomToken(24),
    createdAt: Date.now(), lastSeen: Date.now(), ip: clientIp(req), ua: str(req.headers['user-agent'] || '', 300),
  };
  sessions.set(C.sha256(token), s);
  res.setHeader('Set-Cookie', `${cookieName()}=${token}; Path=/; HttpOnly; SameSite=Strict${useTls ? '; Secure' : ''}; Max-Age=${ABSOLUTE_MS / 1000}`);
  return s;
}

function getSession(req) {
  const cookie = req.headers.cookie || '';
  const m = cookie.match(new RegExp(`(?:^|;\\s*)${cookieName().replace(/[-_]/g, '\\$&')}=([A-Za-z0-9_-]+)`));
  if (!m) return null;
  const key = C.sha256(m[1]);
  const s = sessions.get(key);
  if (!s) return null;
  const t = Date.now();
  const user = findUser(s.userId);
  if (!user || user.status !== 'active' || t - s.lastSeen > IDLE_MS || t - s.createdAt > ABSOLUTE_MS || (S().lockdown.on && user.role !== 'admin')) {
    killSession(key, 'expired');
    return null;
  }
  return { key, s, user };
}

function killSession(key, reason = 'revoked') {
  const s = sessions.get(key);
  if (!s) return;
  sessions.delete(key);
  for (const c of streams) if (c.sessionKey === key) { sendEvent(c, 'logout', { reason }); c.res.end(); }
}
function killUserSessions(userId, exceptKey) {
  for (const [k, s] of sessions) if (s.userId === userId && k !== exceptKey) killSession(k);
}

setInterval(() => {
  const t = Date.now();
  for (const [k, s] of sessions) if (t - s.lastSeen > IDLE_MS || t - s.createdAt > ABSOLUTE_MS) killSession(k, 'expired');
  for (const [k, e] of enrollments) if (e.expires < t) enrollments.delete(k);
  for (const [k, e] of limits) if (e.reset < t) limits.delete(k);
}, 30e3).unref();

function clientIp(req) {
  return req.socket.remoteAddress || '?';
}

// ---------------------------------------------------------------- realtime (SSE)
const streams = new Set();
function sendEvent(c, type, data) {
  c.res.write(`event: ${type}\ndata: ${JSON.stringify(data)}\n\n`);
}
function broadcast(type, data, filter = () => true) {
  for (const c of streams) {
    const u = findUser(c.userId);
    if (u && filter(u)) sendEvent(c, type, data);
  }
}
function presence() {
  const online = [...new Set([...streams].map((c) => c.userId))];
  broadcast('presence', { online });
}
setInterval(() => { for (const c of streams) c.res.write(': hb\n\n'); }, 20e3).unref();

function touchIncident(inc, user, what) {
  inc.updatedAt = now();
  inc.version = (inc.version || 0) + 1;
  vault.save();
  broadcast('incident', { id: inc.id, by: user?.id, what }, (u) => canSee(u, inc));
}

// ---------------------------------------------------------------- incident shaping
function incidentSummary(inc) {
  const tasks = inc.tasks.filter((t) => !t.deleted);
  const obligations = REG.compute(inc, S().org);
  const nextDeadline = obligations.find((o) => o.dueAt && o.status !== 'done' && o.status !== 'na');
  return {
    id: inc.id, ref: inc.ref, codename: inc.codename, title: inc.title, severity: inc.severity, category: inc.category,
    status: inc.status, privileged: inc.privileged, access: inc.access, detectedAt: inc.detectedAt, createdAt: inc.createdAt,
    updatedAt: inc.updatedAt, closedAt: inc.closedAt || null, leadId: inc.leadId,
    tasksOpen: tasks.filter((t) => t.status !== 'done').length, tasksDone: tasks.filter((t) => t.status === 'done').length,
    scopeRecords: inc.scope.filter((s) => !s.deleted).reduce((a, s) => a + (s.records || 0), 0),
    nextDeadline: nextDeadline ? { title: nextDeadline.title, dueAt: nextDeadline.dueAt } : null,
    obligationsOpen: obligations.filter((o) => o.status !== 'done' && o.status !== 'na').length,
    lastEvent: inc.timeline.filter((e) => !e.deleted).slice(-1)[0] || null,
  };
}
function incidentFull(inc) {
  return { ...inc, obligations: REG.compute(inc, S().org) };
}

function addTimeline(inc, user, text, kind = 'system', at = null) {
  const e = { id: C.randomId('t_'), at: at || now(), loggedAt: now(), by: user?.id || null, kind, text };
  inc.timeline.push(e);
  inc.timeline.sort((a, b) => a.at.localeCompare(b.at));
  return e;
}

// ---------------------------------------------------------------- routes
const routes = [];
const route = (method, pattern, opts, handler) => {
  const keys = [];
  const re = new RegExp('^' + pattern.replace(/:(\w+)/g, (_, k) => (keys.push(k), '([A-Za-z0-9_-]+)')) + '$');
  routes.push({ method, re, keys, opts, handler });
};

// ---- public / auth
route('GET', '/api/auth/status', { public: true }, () => ({
  setupPending: !S().users.some((u) => u.status === 'active'),
  lockdown: S().lockdown.on,
  tls: useTls,
}));

route('POST', '/api/auth/login', { public: true }, async ({ body, req, res }) => {
  rateLimit('login-ip:' + clientIp(req), LOGIN_RATE, 15 * 60e3);
  const username = str(body.username, 64).toLowerCase();
  const user = S().users.find((u) => u.username === username);
  const fail = (why) => {
    vault.audit(user || null, 'auth.login.failed', username, { ip: clientIp(req), why });
    return new HttpError(401, 'Sign-in failed. Check your username, password and 6-digit code.');
  };
  if (user && (user.lockedUntil || 0) > Date.now()) {
    C.verifyPassword(String(body.password || ''), null);
    throw new HttpError(423, 'This account is temporarily locked after repeated failed attempts. Wait 15 minutes or ask an administrator.');
  }
  const pwOk = C.verifyPassword(String(body.password || ''), user?.status === 'active' ? user.passHash : null);
  if (!user || user.status !== 'active' || !pwOk) {
    if (user) { user.failed = (user.failed || 0) + 1; if (user.failed >= 5) { user.lockedUntil = Date.now() + 15 * 60e3; user.failed = 0; } }
    throw fail('password');
  }
  const step = C.verifyTotp(user.totpSecret, body.totp, user.lastTotpStep ?? -1);
  if (step < 0) {
    user.failed = (user.failed || 0) + 1;
    if (user.failed >= 5) { user.lockedUntil = Date.now() + 15 * 60e3; user.failed = 0; }
    throw fail('mfa');
  }
  if (S().lockdown.on && user.role !== 'admin') {
    vault.audit(user, 'auth.login.blocked_lockdown', user.username, { ip: clientIp(req) });
    throw new HttpError(403, 'LIFEBOAT is in lockdown. Only administrators can sign in right now.');
  }
  user.lastTotpStep = step;
  user.failed = 0;
  user.lastLogin = now();
  const s = createSession(user, req, res);
  vault.audit(user, 'auth.login', user.username, { ip: s.ip });
  return { ok: true };
});

route('POST', '/api/auth/logout', { public: true }, ({ ctx, res }) => {
  if (ctx) { vault.audit(ctx.user, 'auth.logout', ctx.user.username); killSession(ctx.key, 'logout'); }
  res.setHeader('Set-Cookie', `${cookieName()}=; Path=/; HttpOnly; SameSite=Strict${useTls ? '; Secure' : ''}; Max-Age=0`);
  return { ok: true };
});

// Step 1 of joining: prove you hold the one-time invite code, choose a password, receive an MFA secret.
route('POST', '/api/auth/enroll', { public: true }, ({ body, req }) => {
  rateLimit('enroll-ip:' + clientIp(req), 10, 15 * 60e3);
  const username = str(body.username, 64).toLowerCase();
  const code = str(body.code, 40).toUpperCase().replace(/[^A-Z0-9]/g, '');
  const password = String(body.password || '');
  const user = S().users.find((u) => u.username === username && u.status === 'invited');
  const ok = user && user.inviteHash && user.inviteExpires > Date.now() && C.safeEqual(C.sha256(code), user.inviteHash);
  if (!ok) {
    vault.audit(null, 'auth.enroll.failed', username, { ip: clientIp(req) });
    throw new HttpError(401, 'That invite code is not valid or has expired. Ask your administrator for a new one.');
  }
  if (password.length < 12) throw bad('Password must be at least 12 characters. A short sentence works well.');
  if (password.length > 200) throw bad('Password is too long.');
  if (password.toLowerCase().includes(username)) throw bad('Password must not contain your username.');
  const secret = C.newTotpSecret();
  const token = C.randomToken(24);
  enrollments.set(token, { userId: user.id, passHash: C.hashPassword(password), secret, expires: Date.now() + 15 * 60e3, tries: 0 });
  const uri = `otpauth://totp/LIFEBOAT:${encodeURIComponent(user.username)}?secret=${secret}&issuer=LIFEBOAT&algorithm=SHA1&digits=6&period=30`;
  return { enrollToken: token, secret, uri, qr: QR.svgPath(uri) };
});

// Step 2: prove the authenticator app works, then the account goes live.
route('POST', '/api/auth/enroll/confirm', { public: true }, ({ body, req, res }) => {
  const e = enrollments.get(String(body.enrollToken || ''));
  if (!e || e.expires < Date.now()) throw new HttpError(401, 'Enrollment expired. Start again with your invite code.');
  const user = findUser(e.userId);
  if (!user || user.status !== 'invited') throw new HttpError(401, 'Enrollment is no longer valid.');
  const step = C.verifyTotp(e.secret, body.totp);
  if (step < 0) {
    if (++e.tries >= 5) enrollments.delete(String(body.enrollToken));
    throw bad('That code did not match. Check the time on your phone is correct, and enter the newest code.');
  }
  enrollments.delete(String(body.enrollToken));
  Object.assign(user, { passHash: e.passHash, totpSecret: e.secret, lastTotpStep: step, status: 'active', inviteHash: null, inviteExpires: null, lastLogin: now() });
  vault.audit(user, 'user.enrolled', user.username, { ip: clientIp(req) });
  createSession(user, req, res);
  broadcast('users', {});
  return { ok: true };
});

// ---- session
route('GET', '/api/me', {}, ({ ctx }) => ({
  user: publicUser(ctx.user, true),
  csrf: ctx.s.csrf,
  roles: Object.fromEntries(Object.entries(ROLES).map(([k, v]) => [k, v.label])),
  perms: Object.fromEntries(['incident.write', 'incident.create', 'incident.manage', 'legal.write', 'contacts.write', 'audit.read', 'channel.create', 'admin'].map((p) => [p, can(ctx.user, p)])),
  serverTime: now(),
  idleMinutes: IDLE_MS / 60e3,
  tls: useTls,
}));

route('POST', '/api/ping', {}, () => ({ ok: true }));

route('GET', '/api/bootstrap', {}, ({ ctx }) => {
  const u = ctx.user;
  return {
    org: S().org,
    lockdown: S().lockdown,
    users: S().users.filter((x) => x.status !== 'deleted').map((x) => publicUser(x)),
    incidents: S().incidents.filter((i) => canSee(u, i)).map(incidentSummary),
    channels: S().channels.filter((c) => canSeeChannel(u, c)).map((c) => ({ ...c, last: lastMessage(c.id) })),
    phases: PB.PHASES,
    categories: PB.CATEGORIES,
    dataTypes: REG.DATA_TYPES,
    states: Object.fromEntries(Object.entries(REG.STATES).map(([k, v]) => [k, v.name])),
    online: [...new Set([...streams].map((c) => c.userId))],
  };
});

function lastMessage(channelId) {
  const msgs = S().messages;
  for (let i = msgs.length - 1; i >= 0; i--) if (msgs[i].channelId === channelId) return { at: msgs[i].at, id: msgs[i].id };
  return null;
}

// ---- incidents
route('GET', '/api/incidents/:id', {}, ({ ctx, params }) => {
  const inc = findIncident(params.id);
  if (!canSee(ctx.user, inc)) throw new HttpError(404, 'Incident not found');
  return incidentFull(inc);
});

route('POST', '/api/incidents', { perm: 'incident.create' }, ({ ctx, body }) => {
  const u = ctx.user;
  const st = S();
  const year = new Date().getUTCFullYear();
  st.meta.incidentSeq = (st.meta.incidentSeq || 0) + 1;
  const category = oneOf(body.category || 'other', Object.keys(PB.CATEGORIES), 'category');
  const inc = {
    id: C.randomId('i_'),
    ref: `IR-${year}-${String(st.meta.incidentSeq).padStart(4, '0')}`,
    codename: PB.codename(),
    title: str(body.title, 200, { required: true, name: 'Title' }),
    summary: str(body.summary, 8000),
    severity: int(body.severity || 2, 1, 4),
    category,
    status: 'triage',
    privileged: body.privileged !== false,
    access: body.restricted ? 'restricted' : 'all',
    members: body.restricted ? [u.id] : [],
    detectedAt: date(body.detectedAt) || now(),
    occurredAt: date(body.occurredAt),
    breachDeterminedAt: null,
    materialityDeterminedAt: null,
    leadId: u.id,
    createdBy: u.id,
    createdAt: now(),
    updatedAt: now(),
    affectedSystems: [],
    attackVector: '',
    timeline: [], tasks: [], iocs: [], scope: [], evidence: [], notifications: {},
    version: 1,
  };
  addTimeline(inc, u, `Incident declared by ${u.displayName}: ${inc.title}`, 'system');
  for (const t of PB.tasksFor(category)) {
    inc.tasks.push({ id: C.randomId('k_'), title: t.title, phase: t.phase, status: 'open', assigneeId: null, due: null, createdBy: null, createdAt: now(), playbook: true });
  }
  st.incidents.push(inc);
  const ch = { id: C.randomId('c_'), name: inc.codename.toLowerCase().replace(/\s+/g, '-'), kind: 'incident', incidentId: inc.id, createdAt: now() };
  st.channels.push(ch);
  postMessage(null, ch, `🚨 ${inc.ref} "${inc.codename}" declared at SEV${inc.severity} by ${u.displayName}. This is the incident room.`, true, u);
  vault.audit(u, 'incident.create', inc.ref, { title: inc.title, severity: inc.severity, category });
  touchIncident(inc, u, 'created');
  broadcast('channels', {}, (x) => canSee(x, inc));
  return incidentFull(inc);
});

const LEGAL_FIELDS = new Set(['breachDeterminedAt', 'materialityDeterminedAt', 'privileged']);
route('PATCH', '/api/incidents/:id', { perm: 'incident.write' }, ({ ctx, params, body }) => {
  const u = ctx.user;
  const inc = findIncident(params.id);
  if (!canSee(u, inc)) throw new HttpError(404, 'Incident not found');
  const changes = {};
  const set = (k, v) => { if (JSON.stringify(inc[k]) !== JSON.stringify(v)) { changes[k] = { from: inc[k], to: v }; inc[k] = v; } };
  for (const k of Object.keys(body)) {
    if (LEGAL_FIELDS.has(k) && !can(u, 'legal.write')) throw new HttpError(403, 'Only counsel or incident commanders can change legal determinations.');
    switch (k) {
      case 'title': set(k, str(body[k], 200, { required: true, name: 'Title' })); break;
      case 'summary': set(k, str(body[k], 8000)); break;
      case 'attackVector': set(k, str(body[k], 1000)); break;
      case 'severity': {
        if (!can(u, 'incident.manage') && int(body[k], 1, 4) > inc.severity) throw new HttpError(403, 'Only incident commanders can downgrade severity.');
        set(k, int(body[k], 1, 4)); break;
      }
      case 'category': set(k, oneOf(body[k], Object.keys(PB.CATEGORIES), 'category')); break;
      case 'status': {
        const v = oneOf(body[k], PB.PHASES.map((p) => p.id), 'status');
        if ((v === 'closed' || inc.status === 'closed') && !can(u, 'incident.manage')) throw new HttpError(403, 'Only incident commanders can close or reopen incidents.');
        set(k, v);
        if (v === 'eradication' && !inc.containedAt) inc.containedAt = now();
        if (v === 'closed') inc.closedAt = now();
        break;
      }
      case 'detectedAt': case 'occurredAt': case 'containedAt': case 'breachDeterminedAt': case 'materialityDeterminedAt':
        set(k, date(body[k], k)); break;
      case 'privileged': set(k, !!body[k]); break;
      case 'leadId': if (body[k] && !findUser(body[k])) throw bad('Unknown user'); set(k, body[k] || null); break;
      case 'affectedSystems':
        if (!Array.isArray(body[k])) throw bad('affectedSystems must be a list');
        set(k, body[k].slice(0, 200).map((x) => str(x, 200)).filter(Boolean)); break;
      case 'access': {
        if (!can(u, 'incident.manage')) throw new HttpError(403, 'Only incident commanders can change who can see an incident.');
        set(k, oneOf(body[k], ['all', 'restricted'], 'access'));
        break;
      }
      case 'members': {
        if (!can(u, 'incident.manage')) throw new HttpError(403, 'Only incident commanders can change membership.');
        if (!Array.isArray(body[k])) throw bad('members must be a list');
        set(k, [...new Set(body[k].filter((id) => findUser(id)))]);
        break;
      }
      default: throw bad(`Field "${k}" cannot be changed`);
    }
  }
  if (!Object.keys(changes).length) return incidentFull(inc);
  const label = { status: 'Phase', severity: 'Severity', leadId: 'Incident lead', breachDeterminedAt: 'Breach determination', materialityDeterminedAt: 'Materiality determination', access: 'Visibility', privileged: 'Privilege marking' };
  for (const [k, { to }] of Object.entries(changes)) {
    if (!label[k]) continue;
    let v = to;
    if (k === 'status') v = PB.PHASES.find((p) => p.id === to).label;
    if (k === 'severity') v = 'SEV' + to;
    if (k === 'leadId') v = findUser(to)?.displayName || 'nobody';
    if (k.endsWith('At')) v = to ? new Date(to).toUTCString() : 'cleared';
    if (k === 'privileged') v = to ? 'privileged & confidential' : 'not privileged';
    addTimeline(inc, u, `${label[k]} set to ${v}`, 'system');
  }
  vault.audit(u, 'incident.update', inc.ref, Object.fromEntries(Object.entries(changes).map(([k, c]) => [k, k === 'summary' ? '(edited)' : c.to])));
  if (changes.access || changes.members) broadcast('channels', {});
  touchIncident(inc, u, Object.keys(changes).join(','));
  return incidentFull(inc);
});

function incidentForWrite(ctx, id) {
  const inc = findIncident(id);
  if (!canSee(ctx.user, inc)) throw new HttpError(404, 'Incident not found');
  return inc;
}

// timeline
route('POST', '/api/incidents/:id/timeline', { perm: 'incident.write' }, ({ ctx, params, body }) => {
  const inc = incidentForWrite(ctx, params.id);
  const e = addTimeline(inc, ctx.user, str(body.text, 4000, { required: true, name: 'Entry' }), oneOf(body.kind || 'note', ['note', 'action', 'finding', 'decision', 'comms'], 'kind'), date(body.at));
  vault.audit(ctx.user, 'timeline.add', inc.ref, { id: e.id, kind: e.kind });
  touchIncident(inc, ctx.user, 'timeline');
  return e;
});
route('DELETE', '/api/incidents/:id/timeline/:eid', { perm: 'incident.write' }, ({ ctx, params }) => softDelete(ctx, params, 'timeline'));

function softDelete(ctx, params, list) {
  const inc = incidentForWrite(ctx, params.id);
  const item = inc[list].find((x) => x.id === params.eid);
  if (!item) throw new HttpError(404, 'Not found');
  if (item.by !== ctx.user.id && item.createdBy !== ctx.user.id && !can(ctx.user, 'incident.manage')) throw new HttpError(403, 'You can only strike your own entries.');
  // Legal hold: nothing is ever destroyed, only marked struck with who and when.
  item.deleted = { by: ctx.user.id, at: now() };
  vault.audit(ctx.user, `${list}.strike`, inc.ref, { id: item.id });
  touchIncident(inc, ctx.user, list);
  return { ok: true };
}

// tasks
route('POST', '/api/incidents/:id/tasks', { perm: 'incident.write' }, ({ ctx, params, body }) => {
  const inc = incidentForWrite(ctx, params.id);
  const t = {
    id: C.randomId('k_'), title: str(body.title, 300, { required: true, name: 'Task' }),
    phase: oneOf(body.phase || (inc.status === 'closed' ? 'post' : inc.status), PB.PHASES.map((p) => p.id), 'phase'),
    status: 'open', assigneeId: body.assigneeId && findUser(body.assigneeId) ? body.assigneeId : null,
    due: date(body.due), createdBy: ctx.user.id, createdAt: now(),
  };
  inc.tasks.push(t);
  vault.audit(ctx.user, 'task.add', inc.ref, { id: t.id, title: t.title });
  touchIncident(inc, ctx.user, 'tasks');
  if (t.assigneeId) notifyUser(t.assigneeId, `${ctx.user.displayName} assigned you a task in ${inc.ref}: ${t.title}`, inc.id);
  return t;
});
route('PATCH', '/api/incidents/:id/tasks/:eid', { perm: 'incident.write' }, ({ ctx, params, body }) => {
  const inc = incidentForWrite(ctx, params.id);
  const t = inc.tasks.find((x) => x.id === params.eid);
  if (!t) throw new HttpError(404, 'Task not found');
  if ('status' in body) {
    t.status = oneOf(body.status, ['open', 'doing', 'blocked', 'done'], 'status');
    if (t.status === 'done') { t.doneAt = now(); t.doneBy = ctx.user.id; addTimeline(inc, ctx.user, `Task completed: ${t.title}`, 'action'); } else { t.doneAt = null; }
  }
  if ('assigneeId' in body) {
    t.assigneeId = body.assigneeId && findUser(body.assigneeId) ? body.assigneeId : null;
    if (t.assigneeId && t.assigneeId !== ctx.user.id) notifyUser(t.assigneeId, `${ctx.user.displayName} assigned you a task in ${inc.ref}: ${t.title}`, inc.id);
  }
  if ('title' in body) t.title = str(body.title, 300, { required: true, name: 'Task' });
  if ('due' in body) t.due = date(body.due);
  if ('phase' in body) t.phase = oneOf(body.phase, PB.PHASES.map((p) => p.id), 'phase');
  vault.audit(ctx.user, 'task.update', inc.ref, { id: t.id, ...body });
  touchIncident(inc, ctx.user, 'tasks');
  return t;
});
route('DELETE', '/api/incidents/:id/tasks/:eid', { perm: 'incident.write' }, ({ ctx, params }) => softDelete(ctx, params, 'tasks'));

// indicators of compromise
const IOC_TYPES = ['ip', 'domain', 'url', 'hash', 'email', 'account', 'file', 'other'];
route('POST', '/api/incidents/:id/iocs', { perm: 'incident.write' }, ({ ctx, params, body }) => {
  const inc = incidentForWrite(ctx, params.id);
  const values = (Array.isArray(body.values) ? body.values : [body.value]).map((v) => str(v, 2000)).filter(Boolean).slice(0, 500);
  if (!values.length) throw bad('Enter at least one indicator');
  const added = [];
  for (const value of values) {
    if (inc.iocs.some((i) => !i.deleted && i.value === value)) continue;
    const i = { id: C.randomId('o_'), type: body.type && IOC_TYPES.includes(body.type) ? body.type : guessIoc(value), value, note: str(body.note, 500), by: ctx.user.id, at: now() };
    inc.iocs.push(i);
    added.push(i);
  }
  vault.audit(ctx.user, 'ioc.add', inc.ref, { count: added.length });
  touchIncident(inc, ctx.user, 'iocs');
  return { added: added.length };
});
route('DELETE', '/api/incidents/:id/iocs/:eid', { perm: 'incident.write' }, ({ ctx, params }) => softDelete(ctx, params, 'iocs'));

function guessIoc(v) {
  if (/^\d{1,3}(\.\d{1,3}){3}(\/\d+)?$/.test(v) || /^[0-9a-f:]+:[0-9a-f:]+$/i.test(v)) return 'ip';
  if (/^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i.test(v)) return 'hash';
  if (/^https?:\/\//i.test(v)) return 'url';
  if (/^[^@\s]+@[^@\s]+\.[a-z]{2,}$/i.test(v)) return 'email';
  if (/^([a-z0-9-]+\.)+[a-z]{2,}$/i.test(v)) return 'domain';
  if (/\.(exe|dll|ps1|bat|js|vbs|msi|zip|iso|lnk)$/i.test(v)) return 'file';
  return 'other';
}

// scope of compromised data
const SCOPE_STATUS = ['encrypted', 'exfiltrated', 'accessed', 'deleted', 'corrupted', 'at-risk', 'secured', 'restored'];
function scopeFields(body, row = {}) {
  if ('asset' in body || !row.asset) row.asset = str(body.asset, 200, { required: true, name: 'Data set' });
  if ('system' in body) row.system = str(body.system, 200);
  if ('dataTypes' in body) {
    if (!Array.isArray(body.dataTypes)) throw bad('dataTypes must be a list');
    row.dataTypes = body.dataTypes.filter((t) => REG.DATA_TYPES[t]);
  }
  row.dataTypes ||= [];
  if ('records' in body) row.records = int(body.records, 0, 1e12);
  if ('residents' in body) {
    const r = {};
    for (const [k, v] of Object.entries(body.residents || {})) {
      const code = String(k).toUpperCase().slice(0, 4);
      if (/^[A-Z]{2,4}$/.test(code) && Number(v) > 0) r[code] = int(v, 0, 1e12);
    }
    row.residents = r;
  }
  row.residents ||= {};
  if ('status' in body) row.status = oneOf(body.status, SCOPE_STATUS, 'status');
  row.status ||= 'at-risk';
  if ('confidence' in body) row.confidence = oneOf(body.confidence, ['confirmed', 'suspected', 'ruled-out'], 'confidence');
  row.confidence ||= 'suspected';
  if ('notes' in body) row.notes = str(body.notes, 2000);
  return row;
}
route('POST', '/api/incidents/:id/scope', { perm: 'incident.write' }, ({ ctx, params, body }) => {
  const inc = incidentForWrite(ctx, params.id);
  const row = scopeFields(body, { id: C.randomId('d_'), createdBy: ctx.user.id, createdAt: now() });
  row.updatedBy = ctx.user.id;
  row.updatedAt = now();
  row.history = [{ at: now(), by: ctx.user.id, status: row.status, confidence: row.confidence }];
  inc.scope.push(row);
  addTimeline(inc, ctx.user, `Scope: "${row.asset}" recorded as ${row.status.toUpperCase()} (${row.confidence}), ${row.records.toLocaleString()} records`, 'finding');
  vault.audit(ctx.user, 'scope.add', inc.ref, { id: row.id, asset: row.asset, status: row.status });
  touchIncident(inc, ctx.user, 'scope');
  return row;
});
route('PATCH', '/api/incidents/:id/scope/:eid', { perm: 'incident.write' }, ({ ctx, params, body }) => {
  const inc = incidentForWrite(ctx, params.id);
  const row = inc.scope.find((x) => x.id === params.eid);
  if (!row) throw new HttpError(404, 'Not found');
  const before = `${row.status}/${row.confidence}`;
  scopeFields(body, row);
  row.updatedBy = ctx.user.id;
  row.updatedAt = now();
  if (`${row.status}/${row.confidence}` !== before) {
    row.history = [...(row.history || []), { at: now(), by: ctx.user.id, status: row.status, confidence: row.confidence }];
    addTimeline(inc, ctx.user, `Scope: "${row.asset}" changed to ${row.status.toUpperCase()} (${row.confidence})`, 'finding');
  }
  vault.audit(ctx.user, 'scope.update', inc.ref, { id: row.id, status: row.status, confidence: row.confidence });
  touchIncident(inc, ctx.user, 'scope');
  return row;
});
route('DELETE', '/api/incidents/:id/scope/:eid', { perm: 'incident.write' }, ({ ctx, params }) => softDelete(ctx, params, 'scope'));

// notification obligations
route('PATCH', '/api/incidents/:id/obligations/:eid', { perm: 'legal.write' }, ({ ctx, params, body }) => {
  const inc = incidentForWrite(ctx, params.id);
  const id = String(params.eid);
  const cur = inc.notifications[id] || {};
  const status = oneOf(body.status || cur.status || 'pending', ['pending', 'in-progress', 'done', 'na'], 'status');
  inc.notifications[id] = { status, notes: 'notes' in body ? str(body.notes, 2000) : cur.notes || '', updatedBy: ctx.user.id, updatedAt: now(), doneAt: status === 'done' ? cur.doneAt || now() : null };
  if (status !== cur.status) addTimeline(inc, ctx.user, `Obligation "${id}" marked ${status === 'na' ? 'NOT APPLICABLE' : status.toUpperCase()}`, 'decision');
  vault.audit(ctx.user, 'obligation.update', inc.ref, { id, status });
  touchIncident(inc, ctx.user, 'obligations');
  return inc.notifications[id];
});

// evidence locker with chain of custody
route('POST', '/api/incidents/:id/evidence', { perm: 'incident.write', raw: true }, async ({ ctx, params, req, rawBody }) => {
  const inc = incidentForWrite(ctx, params.id);
  const isFile = (req.headers['content-type'] || '').startsWith('application/octet-stream');
  let ev;
  if (isFile) {
    const name = str(decodeURIComponent(String(req.headers['x-filename'] || 'evidence.bin')), 200).replace(/[\\/]/g, '_') || 'evidence.bin';
    const note = str(decodeURIComponent(String(req.headers['x-note'] || '')), 1000);
    ev = { id: C.randomId('e_'), kind: 'file', name, size: rawBody.length, sha256: C.sha256(rawBody), note, location: 'LIFEBOAT encrypted locker' };
    vault.writeEvidence(ev.id, rawBody);
  } else {
    const body = JSON.parse(rawBody.toString('utf8') || '{}');
    ev = { id: C.randomId('e_'), kind: 'item', name: str(body.name, 200, { required: true, name: 'Item' }), size: null, sha256: body.sha256 ? str(body.sha256, 128) : null, note: str(body.note, 1000), location: str(body.location, 300) };
  }
  Object.assign(ev, { collectedBy: ctx.user.id, collectedAt: now(), custody: [{ at: now(), by: ctx.user.id, action: isFile ? `Uploaded & hashed (SHA-256 ${ev.sha256.slice(0, 16)}…)` : `Logged into custody${ev.location ? ' at ' + ev.location : ''}` }] });
  inc.evidence.push(ev);
  addTimeline(inc, ctx.user, `Evidence collected: ${ev.name}`, 'action');
  vault.audit(ctx.user, 'evidence.add', inc.ref, { id: ev.id, name: ev.name, sha256: ev.sha256 });
  touchIncident(inc, ctx.user, 'evidence');
  return ev;
});
route('POST', '/api/incidents/:id/evidence/:eid/custody', { perm: 'incident.write' }, ({ ctx, params, body }) => {
  const inc = incidentForWrite(ctx, params.id);
  const ev = inc.evidence.find((x) => x.id === params.eid);
  if (!ev) throw new HttpError(404, 'Not found');
  ev.custody.push({ at: now(), by: ctx.user.id, action: str(body.action, 500, { required: true, name: 'Custody action' }) });
  vault.audit(ctx.user, 'evidence.custody', inc.ref, { id: ev.id });
  touchIncident(inc, ctx.user, 'evidence');
  return ev;
});
route('GET', '/api/incidents/:id/evidence/:eid/file', {}, ({ ctx, params, res }) => {
  const inc = incidentForWrite(ctx, params.id);
  const ev = inc.evidence.find((x) => x.id === params.eid && x.kind === 'file');
  if (!ev) throw new HttpError(404, 'Not found');
  const buf = vault.readEvidence(ev.id);
  const intact = C.sha256(buf) === ev.sha256;
  ev.custody.push({ at: now(), by: ctx.user.id, action: `Copy exported (integrity ${intact ? 'VERIFIED' : 'MISMATCH!'})` });
  vault.audit(ctx.user, 'evidence.export', inc.ref, { id: ev.id, intact });
  touchIncident(inc, ctx.user, 'evidence');
  res.writeHead(200, {
    'Content-Type': 'application/octet-stream',
    'Content-Disposition': `attachment; filename="${ev.name.replace(/[^\w.\- ]/g, '_')}"`,
    'X-Integrity': intact ? 'verified' : 'MISMATCH',
    'Content-Length': buf.length,
  });
  res.end(buf);
  return undefined;
});

// ---- comms
function postMessage(user, ch, text, urgent = false, ackedBy = null) {
  const m = { id: C.randomId('m_'), channelId: ch.id, userId: user?.id || null, text, at: now(), urgent: !!urgent, acks: {} };
  if (user && urgent) m.acks[user.id] = m.at;
  if (ackedBy) m.acks[ackedBy.id] = m.at;
  S().messages.push(m);
  vault.save();
  broadcast('message', m, (u) => canSeeChannel(u, ch));
  return m;
}
function notifyUser(userId, text, incidentId) {
  broadcast('notify', { text, incidentId }, (u) => u.id === userId);
}

route('GET', '/api/channels/:id/messages', {}, ({ ctx, params }) => {
  const ch = S().channels.find((c) => c.id === params.id);
  if (!canSeeChannel(ctx.user, ch)) throw new HttpError(404, 'Channel not found');
  return S().messages.filter((m) => m.channelId === ch.id).slice(-500);
});
route('POST', '/api/channels/:id/messages', {}, ({ ctx, params, body }) => {
  const ch = S().channels.find((c) => c.id === params.id);
  if (!canSeeChannel(ctx.user, ch)) throw new HttpError(404, 'Channel not found');
  rateLimit('msg:' + ctx.user.id, 60, 60e3);
  const urgent = !!body.urgent && ctx.user.role !== 'observer';
  const m = postMessage(ctx.user, ch, str(body.text, 4000, { required: true, name: 'Message' }), urgent);
  vault.audit(ctx.user, urgent ? 'message.urgent' : 'message.post', ch.name, { id: m.id });
  return m;
});
route('POST', '/api/messages/:id/ack', {}, ({ ctx, params }) => {
  const m = S().messages.find((x) => x.id === params.id);
  const ch = m && S().channels.find((c) => c.id === m.channelId);
  if (!m || !canSeeChannel(ctx.user, ch)) throw new HttpError(404, 'Not found');
  if (!m.acks[ctx.user.id]) {
    m.acks[ctx.user.id] = now();
    vault.save();
    broadcast('ack', { id: m.id, channelId: m.channelId, userId: ctx.user.id, at: m.acks[ctx.user.id] }, (u) => canSeeChannel(u, ch));
  }
  return { ok: true };
});
route('POST', '/api/channels', { perm: 'channel.create' }, ({ ctx, body }) => {
  const name = str(body.name, 40, { required: true, name: 'Channel name' }).toLowerCase().replace(/[^a-z0-9-]+/g, '-');
  const members = Array.isArray(body.members) && body.members.length ? [...new Set([ctx.user.id, ...body.members.filter((id) => findUser(id))])] : null;
  const ch = { id: C.randomId('c_'), name, kind: 'custom', members, createdBy: ctx.user.id, createdAt: now() };
  S().channels.push(ch);
  vault.audit(ctx.user, 'channel.create', name, { private: !!members });
  vault.save();
  broadcast('channels', {}, (u) => canSeeChannel(u, ch));
  return ch;
});

// ---- org profile & out-of-band contacts
route('PUT', '/api/org', { perm: 'admin' }, ({ ctx, body }) => {
  const o = S().org;
  o.name = str(body.name ?? o.name, 120, { required: true, name: 'Organization name' });
  for (const k of ['publiclyTraded', 'hipaaCovered', 'nydfsRegulated', 'criticalInfrastructure']) if (k in body) o[k] = !!body[k];
  if (body.insurance) o.insurance = { carrier: str(body.insurance.carrier, 120), policy: str(body.insurance.policy, 80), hotline: str(body.insurance.hotline, 80), noticeHours: int(body.insurance.noticeHours || 72, 1, 24 * 365) };
  if (body.outsideCounsel) o.outsideCounsel = { firm: str(body.outsideCounsel.firm, 120), contact: str(body.outsideCounsel.contact, 120), phone: str(body.outsideCounsel.phone, 80) };
  vault.audit(ctx.user, 'org.update', o.name);
  vault.save();
  broadcast('org', {});
  for (const inc of S().incidents) broadcast('incident', { id: inc.id, what: 'org' }, (u) => canSee(u, inc));
  return o;
});
route('PUT', '/api/contacts', { perm: 'contacts.write' }, ({ ctx, body }) => {
  if (!Array.isArray(body.contacts)) throw bad('contacts must be a list');
  S().org.contacts = body.contacts.slice(0, 200).map((c) => ({
    id: c.id && /^[\w-]+$/.test(c.id) ? c.id : C.randomId('p_'),
    name: str(c.name, 120, { required: true, name: 'Name' }), role: str(c.role, 120), org: str(c.org, 120),
    phone: str(c.phone, 60), alt: str(c.alt, 60), notes: str(c.notes, 500), group: str(c.group, 60),
  }));
  vault.audit(ctx.user, 'contacts.update', null, { count: S().org.contacts.length });
  vault.save();
  broadcast('org', {});
  return S().org.contacts;
});

// ---- administration
route('GET', '/api/admin/users', { perm: 'admin' }, () => S().users.map((u) => publicUser(u, true)));

route('POST', '/api/admin/users', { perm: 'admin' }, ({ ctx, body }) => {
  const username = str(body.username, 32, { required: true, name: 'Username' }).toLowerCase();
  if (!/^[a-z0-9._-]{2,32}$/.test(username)) throw bad('Username: 2-32 characters, letters, numbers, dot, dash or underscore');
  if (S().users.some((u) => u.username === username)) throw new HttpError(409, 'That username is taken');
  const code = C.inviteCode();
  const u = {
    id: C.randomId('u_'), username, displayName: str(body.displayName, 80, { required: true, name: 'Full name' }),
    role: oneOf(body.role || 'responder', Object.keys(ROLES), 'role'), title: str(body.title, 80), phone: str(body.phone, 60),
    status: 'invited', inviteHash: C.sha256(code.replace(/-/g, '')), inviteExpires: Date.now() + INVITE_TTL,
    createdAt: now(), createdBy: ctx.user.id,
  };
  S().users.push(u);
  vault.audit(ctx.user, 'user.invite', username, { role: u.role });
  broadcast('users', {});
  return { user: publicUser(u, true), inviteCode: code, expiresAt: new Date(u.inviteExpires).toISOString() };
});

route('PATCH', '/api/admin/users/:id', { perm: 'admin' }, ({ ctx, params, body }) => {
  const u = findUser(params.id);
  if (!u) throw new HttpError(404, 'User not found');
  if (u.id === ctx.user.id && (body.role && body.role !== 'admin' || body.status === 'disabled')) throw bad('You cannot demote or disable yourself. Ask another administrator.');
  if ('displayName' in body) u.displayName = str(body.displayName, 80, { required: true, name: 'Full name' });
  if ('title' in body) u.title = str(body.title, 80);
  if ('phone' in body) u.phone = str(body.phone, 60);
  if ('role' in body) u.role = oneOf(body.role, Object.keys(ROLES), 'role');
  if ('status' in body) {
    const st = oneOf(body.status, ['active', 'disabled'], 'status');
    if (st === 'active' && !u.passHash) throw bad('This user has not finished enrolling yet.');
    u.status = st;
    if (st === 'disabled') killUserSessions(u.id);
  }
  if (body.unlock) { u.lockedUntil = 0; u.failed = 0; }
  vault.audit(ctx.user, 'user.update', u.username, body);
  broadcast('users', {});
  return publicUser(u, true);
});

// Lost phone or suspected compromise: wipe credentials and MFA, issue a new invite.
route('POST', '/api/admin/users/:id/reset', { perm: 'admin' }, ({ ctx, params }) => {
  const u = findUser(params.id);
  if (!u) throw new HttpError(404, 'User not found');
  if (u.id === ctx.user.id) throw bad('Ask another administrator to reset your own account.');
  const code = C.inviteCode();
  Object.assign(u, { status: 'invited', passHash: null, totpSecret: null, lastTotpStep: -1, inviteHash: C.sha256(code.replace(/-/g, '')), inviteExpires: Date.now() + INVITE_TTL, failed: 0, lockedUntil: 0 });
  killUserSessions(u.id);
  vault.audit(ctx.user, 'user.reset', u.username);
  broadcast('users', {});
  return { user: publicUser(u, true), inviteCode: code, expiresAt: new Date(u.inviteExpires).toISOString() };
});

route('GET', '/api/admin/sessions', { perm: 'admin' }, ({ ctx }) => [...sessions.entries()].map(([k, s]) => ({
  id: s.id, user: publicUser(findUser(s.userId) || { id: s.userId, username: '?', displayName: '?' }), ip: s.ip, ua: s.ua,
  createdAt: new Date(s.createdAt).toISOString(), lastSeen: new Date(s.lastSeen).toISOString(), current: k === ctx.key,
  live: [...streams].some((c) => c.sessionKey === k),
})));
route('DELETE', '/api/admin/sessions/:id', { perm: 'admin' }, ({ ctx, params }) => {
  for (const [k, s] of sessions) if (s.id === params.id) { vault.audit(ctx.user, 'session.revoke', findUser(s.userId)?.username, { ip: s.ip }); killSession(k); }
  return { ok: true };
});

// Break glass: kick everyone except administrators. Use when a responder account may be compromised.
route('POST', '/api/admin/lockdown', { perm: 'admin' }, ({ ctx, body }) => {
  const on = !!body.on;
  S().lockdown = { on, by: ctx.user.id, at: now() };
  if (on) for (const [k, s] of sessions) { const u = findUser(s.userId); if (!u || u.role !== 'admin') killSession(k, 'lockdown'); }
  vault.audit(ctx.user, on ? 'lockdown.on' : 'lockdown.off');
  broadcast('lockdown', S().lockdown);
  return S().lockdown;
});

route('GET', '/api/audit', { perm: 'audit.read' }, ({ url }) => {
  const limit = int(url.searchParams.get('limit') || 300, 1, 5000);
  return { entries: S().audit.slice(-limit).reverse(), total: S().audit.length };
});
route('GET', '/api/audit/verify', { perm: 'audit.read' }, ({ ctx }) => {
  const r = vault.verifyAudit();
  vault.audit(ctx.user, 'audit.verify', null, { ok: r.ok });
  return r;
});

// Encrypted backup: the vault is already ciphertext, so the file is safe to carry offsite.
route('GET', '/api/admin/backup', { perm: 'admin' }, ({ ctx, res }) => {
  vault.audit(ctx.user, 'vault.backup');
  vault.flush();
  const buf = fs.readFileSync(vault.file);
  res.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Content-Disposition': `attachment; filename="lifeboat-${new Date().toISOString().slice(0, 10)}.lbv"`, 'Content-Length': buf.length });
  res.end(buf);
});

// ---- realtime stream
function openStream(req, res, ctx) {
  res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-store', Connection: 'keep-alive', 'X-Accel-Buffering': 'no' });
  res.write('retry: 3000\n\n');
  const c = { res, userId: ctx.user.id, sessionKey: ctx.key };
  streams.add(c);
  sendEvent(c, 'hello', { serverTime: now() });
  presence();
  req.on('close', () => { streams.delete(c); presence(); });
}

// ---------------------------------------------------------------- HTTP plumbing
const STATIC = new Map();
function loadStatic() {
  const types = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon' };
  const dir = path.join(ROOT, 'public');
  // The single-file build embeds the web app; otherwise it is read from ./public.
  const embedded = global.__LIFEBOAT_STATIC;
  for (const f of embedded ? Object.keys(embedded) : fs.readdirSync(dir)) {
    const ext = path.extname(f);
    if (!types[ext]) continue;
    const body = embedded ? Buffer.from(embedded[f], 'base64') : fs.readFileSync(path.join(dir, f));
    STATIC.set('/' + f, { body, type: types[ext], etag: '"' + C.sha256(body).slice(0, 16) + '"' });
  }
  STATIC.set('/', STATIC.get('/index.html'));
}

function securityHeaders(res) {
  res.setHeader('Content-Security-Policy', "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'");
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=()');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Embedder-Policy', 'require-corp');
  if (useTls) res.setHeader('Strict-Transport-Security', 'max-age=31536000');
  res.setHeader('Server', 'lifeboat');
}

function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > limit) { reject(new HttpError(413, 'Upload too large')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(body);
}

async function handle(req, res) {
  securityHeaders(res);
  const url = new URL(req.url, 'http://x');
  const p = url.pathname;

  if (!p.startsWith('/api/')) {
    if (req.method !== 'GET' && req.method !== 'HEAD') return sendJson(res, 405, { error: 'Method not allowed' });
    const f = STATIC.get(p);
    if (!f) return sendJson(res, 404, { error: 'Not found' });
    if (req.headers['if-none-match'] === f.etag) { res.writeHead(304); return res.end(); }
    res.writeHead(200, { 'Content-Type': f.type, ETag: f.etag, 'Cache-Control': 'no-cache' });
    return res.end(req.method === 'HEAD' ? undefined : f.body);
  }

  try {
    const ctx = getSession(req);
    if (p === '/api/stream' && req.method === 'GET') {
      if (!ctx) throw new HttpError(401, 'Not signed in');
      return openStream(req, res, ctx);
    }
    let match, params = {};
    const r = routes.find((x) => x.method === req.method && (match = p.match(x.re)));
    if (!r) throw new HttpError(404, 'Not found');
    r.keys.forEach((k, i) => (params[k] = match[i + 1]));

    if (req.method !== 'GET') {
      // CSRF defence in depth: SameSite=Strict cookie + same-origin check + per-session token header.
      const origin = req.headers.origin;
      if (origin && new URL(origin).host !== req.headers.host) throw new HttpError(403, 'Cross-origin request blocked');
      if (!r.opts.public && (!ctx || !C.safeEqual(req.headers['x-csrf-token'] || '', ctx.s.csrf))) throw new HttpError(ctx ? 403 : 401, ctx ? 'Security token mismatch. Reload the page.' : 'Not signed in');
    }
    if (!r.opts.public) {
      if (!ctx) throw new HttpError(401, 'Not signed in');
      if (r.opts.perm && !can(ctx.user, r.opts.perm)) throw new HttpError(403, 'Your role does not allow this.');
      // Idle timer: only real user actions count (writes, or the client's activity ping).
      // Background refreshes triggered by other people's updates do not keep a session alive.
      if (req.method !== 'GET') ctx.s.lastSeen = Date.now();
    }

    let body = {}, rawBody = null;
    if (req.method === 'POST' || req.method === 'PATCH' || req.method === 'PUT') {
      if (r.opts.raw) rawBody = await readBody(req, MAX_EVIDENCE);
      else {
        const ct = req.headers['content-type'] || '';
        if (!ct.startsWith('application/json')) throw new HttpError(415, 'Expected JSON');
        const buf = await readBody(req, 1024 * 1024);
        try { body = buf.length ? JSON.parse(buf.toString('utf8')) : {}; } catch { throw bad('Malformed JSON'); }
        if (typeof body !== 'object' || body === null || Array.isArray(body)) throw bad('Expected a JSON object');
      }
    }
    const out = await r.handler({ req, res, url, params, body, rawBody, ctx });
    if (!res.headersSent) sendJson(res, 200, out ?? { ok: true });
  } catch (err) {
    if (res.headersSent) return res.end();
    if (err instanceof HttpError) return sendJson(res, err.status, { error: err.message });
    console.error('[error]', err);
    sendJson(res, 500, { error: 'Internal error' });
  }
}

// ---------------------------------------------------------------- startup
async function askPassphrase() {
  if (process.env.LIFEBOAT_PASSPHRASE) {
    const p = process.env.LIFEBOAT_PASSPHRASE;
    delete process.env.LIFEBOAT_PASSPHRASE; // keep it out of child processes / crash dumps
    return p;
  }
  if (!process.stdin.isTTY) throw new Error('Set LIFEBOAT_PASSPHRASE or run in a terminal to enter the vault passphrase.');
  const readline = require('node:readline');
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
  const fresh = !vault.exists();
  const ask = (q) => new Promise((res) => {
    rl.output.write(q);
    rl._writeToOutput = () => {};
    rl.question('', (a) => { rl.output.write('\n'); res(a); });
  });
  let p = await ask(fresh ? 'Create vault passphrase (12+ chars, write it down offline): ' : 'Vault passphrase: ');
  if (fresh) {
    const again = await ask('Confirm passphrase: ');
    if (again !== p) { rl.close(); throw new Error('Passphrases did not match.'); }
  }
  rl.close();
  return p;
}

function ensureAdminInvite(forceUser) {
  const st = S();
  const hasActiveAdmin = st.users.some((u) => u.role === 'admin' && u.status === 'active');
  if (hasActiveAdmin && !forceUser) return;
  const username = (forceUser || process.env.LIFEBOAT_ADMIN || 'admin').toLowerCase();
  let u = st.users.find((x) => x.username === username);
  const code = C.inviteCode();
  if (!u) {
    u = { id: C.randomId('u_'), username, displayName: 'Administrator', role: 'admin', title: '', phone: '', createdAt: now(), createdBy: null };
    st.users.push(u);
  }
  Object.assign(u, { role: 'admin', status: 'invited', passHash: null, totpSecret: null, lastTotpStep: -1, inviteHash: C.sha256(code.replace(/-/g, '')), inviteExpires: Date.now() + INVITE_TTL });
  vault.audit(null, 'user.bootstrap_invite', username);
  if (!st.channels.some((c) => c.kind === 'general')) st.channels.push({ id: C.randomId('c_'), name: 'command', kind: 'general', createdAt: now() });
  vault.flush();
  console.log('\n  ┌──────────────────────────────────────────────────────────┐');
  console.log('  │  ADMINISTRATOR ENROLLMENT                                │');
  console.log(`  │  Username:  ${username.padEnd(45)}│`);
  console.log(`  │  One-time code:  ${code.padEnd(40)}│`);
  console.log('  │  Open LIFEBOAT and choose "I have an invite code".       │');
  console.log('  │  Code expires in 72 hours and works once.               │');
  console.log('  └──────────────────────────────────────────────────────────┘\n');
}

async function main() {
  const args = process.argv.slice(2);
  const passphrase = await askPassphrase();
  process.stdout.write('Unlocking vault… ');
  vault.open(passphrase);
  console.log('ok');
  const ri = args.indexOf('--reset-admin');
  ensureAdminInvite(ri >= 0 ? args[ri + 1] || 'admin' : null);
  vault.audit(null, 'system.start', null, { host: HOST, port: PORT });
  loadStatic();

  let server;
  if (fs.existsSync(TLS_CERT) && fs.existsSync(TLS_KEY)) {
    useTls = true;
    const cert = fs.readFileSync(TLS_CERT);
    server = https.createServer({ cert, key: fs.readFileSync(TLS_KEY), minVersion: 'TLSv1.2' }, handle);
    const fp = new crypto.X509Certificate(cert).fingerprint256;
    console.log(`TLS certificate SHA-256 fingerprint (verify this in your browser):\n  ${fp}`);
  } else {
    const loopback = ['127.0.0.1', 'localhost', '::1'].includes(HOST);
    if (!loopback && process.env.LIFEBOAT_ALLOW_HTTP !== '1') {
      console.error('Refusing to serve plain HTTP on a network interface. Run `npm run cert` first (or set LIFEBOAT_ALLOW_HTTP=1 for a lab).');
      process.exit(1);
    }
    console.warn('⚠  No TLS certificate found. Serving HTTP on loopback only. Run `npm run cert` to enable HTTPS.');
    server = http.createServer(handle);
  }
  server.headersTimeout = 20e3;
  server.requestTimeout = 120e3;
  server.listen(PORT, HOST, () => console.log(`\nLIFEBOAT is up: ${useTls ? 'https' : 'http'}://${HOST === '0.0.0.0' ? 'localhost' : HOST}:${PORT}\n`));

  const shutdown = () => { console.log('\nSealing vault…'); vault.audit(null, 'system.stop'); vault.flush(); process.exit(0); };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

if (require.main === module) {
  main().catch((e) => { console.error('\n✖ ' + e.message); process.exit(1); });
}

module.exports = { handle, vault, routes, main };
