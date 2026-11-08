'use strict';
// Security & behaviour tests. Run: npm test
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');

const DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'lifeboat-test-'));
process.env.LIFEBOAT_DATA = DIR;
process.env.LIFEBOAT_LOGIN_RATE = '500'; // the suite signs in many times from one IP
const C = require('../lib/crypto');
const REG = require('../lib/regulations');
const { handle, vault } = require('../server');

const PASS = 'test-vault-passphrase-123';
const PW = 'a long enough password!';
let server, base;
const users = {};

function mkUser(username, role) {
  const u = { id: C.randomId('u_'), username, displayName: username.toUpperCase(), role, status: 'active', passHash: C.hashPassword(PW), totpSecret: C.newTotpSecret(), lastTotpStep: -1, createdAt: new Date().toISOString() };
  vault.state.users.push(u);
  users[username] = u;
  return u;
}

async function req(method, p, { body, cookie, csrf, headers = {} } = {}) {
  const h = { ...headers };
  if (body !== undefined && !(body instanceof Buffer)) h['content-type'] = 'application/json';
  if (cookie) h.cookie = cookie;
  if (csrf) h['x-csrf-token'] = csrf;
  const res = await fetch(base + p, { method, headers: h, body: body === undefined ? undefined : body instanceof Buffer ? body : JSON.stringify(body) });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* not json */ }
  return { status: res.status, json, text, headers: res.headers };
}

// Each login burns a TOTP time step (replay protection), so tests use a fake clock step by resetting lastTotpStep.
async function login(username) {
  const u = users[username];
  u.lastTotpStep = -1;
  const r = await req('POST', '/api/auth/login', { body: { username, password: PW, totp: C.totpAt(u.totpSecret, C.currentStep()) } });
  assert.equal(r.status, 200, `login ${username}: ${r.text}`);
  const cookie = r.headers.get('set-cookie').split(';')[0];
  const me = await req('GET', '/api/me', { cookie });
  return { cookie, csrf: me.json.csrf };
}

before(async () => {
  vault.open(PASS);
  vault.state.channels.push({ id: 'c_general', name: 'command', kind: 'general' });
  mkUser('admin1', 'admin');
  mkUser('cmdr', 'commander');
  mkUser('resp', 'responder');
  mkUser('exec', 'observer');
  server = http.createServer(handle);
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${server.address().port}`;
});
after(() => { server.close(); vault.flush(); fs.rmSync(DIR, { recursive: true, force: true }); });

test('API refuses unauthenticated requests', async () => {
  assert.equal((await req('GET', '/api/bootstrap')).status, 401);
  assert.equal((await req('GET', '/api/admin/users')).status, 401);
});

test('security headers: strict CSP, no framing, no sniffing', async () => {
  const r = await req('GET', '/api/auth/status');
  assert.match(r.headers.get('content-security-policy'), /default-src 'none'; script-src 'self'/);
  assert.equal(r.headers.get('x-frame-options'), 'DENY');
  assert.equal(r.headers.get('x-content-type-options'), 'nosniff');
});

test('login requires password AND a valid TOTP code', async () => {
  const u = users.resp;
  u.lastTotpStep = -1;
  const noCode = await req('POST', '/api/auth/login', { body: { username: 'resp', password: PW, totp: '000000' } });
  assert.equal(noCode.status, 401);
  const wrongPw = await req('POST', '/api/auth/login', { body: { username: 'resp', password: 'nope-nope-nope', totp: C.totpAt(u.totpSecret, C.currentStep()) } });
  assert.equal(wrongPw.status, 401);
  assert.equal(noCode.json.error, wrongPw.json.error, 'error messages must not reveal which factor failed');
  u.failed = 0;
});

test('a TOTP code cannot be replayed', async () => {
  const u = users.cmdr;
  u.lastTotpStep = -1;
  const code = C.totpAt(u.totpSecret, C.currentStep());
  const first = await req('POST', '/api/auth/login', { body: { username: 'cmdr', password: PW, totp: code } });
  assert.equal(first.status, 200);
  const replay = await req('POST', '/api/auth/login', { body: { username: 'cmdr', password: PW, totp: code } });
  assert.equal(replay.status, 401);
  u.failed = 0;
});

test('account locks after 5 failed attempts', async () => {
  const u = mkUser('victim', 'responder');
  for (let i = 0; i < 5; i++) await req('POST', '/api/auth/login', { body: { username: 'victim', password: 'wrong-wrong-wrong', totp: '123456' } });
  u.lastTotpStep = -1;
  const r = await req('POST', '/api/auth/login', { body: { username: 'victim', password: PW, totp: C.totpAt(u.totpSecret, C.currentStep()) } });
  assert.equal(r.status, 423);
});

test('state-changing requests need the CSRF token and same origin', async () => {
  const { cookie, csrf } = await login('resp');
  const noToken = await req('POST', '/api/incidents', { cookie, body: { title: 'x' } });
  assert.equal(noToken.status, 403);
  const crossOrigin = await req('POST', '/api/incidents', { cookie, csrf, body: { title: 'x' }, headers: { origin: 'https://evil.example' } });
  assert.equal(crossOrigin.status, 403);
});

test('role permissions: observers are read-only, responders cannot administer', async () => {
  const ex = await login('exec');
  assert.equal((await req('POST', '/api/incidents', { ...ex, body: { title: 'should fail' } })).status, 403);
  const rs = await login('resp');
  assert.equal((await req('GET', '/api/admin/users', rs)).status, 403);
  assert.equal((await req('POST', '/api/admin/lockdown', { ...rs, body: { on: true } })).status, 403);
});

test('declaring an incident loads a playbook, opens a room, and is audited', async () => {
  const s = await login('resp');
  const r = await req('POST', '/api/incidents', { ...s, body: { title: 'Files encrypted', category: 'ransomware', severity: 1 } });
  assert.equal(r.status, 200);
  assert.match(r.json.ref, /^IR-\d{4}-\d{4}$/);
  assert.ok(r.json.tasks.length > 10);
  assert.ok(r.json.obligations.some((o) => o.id === 'ofac'), 'ransomware triggers OFAC check');
  assert.ok(vault.state.channels.some((c) => c.incidentId === r.json.id));
  assert.ok(vault.state.audit.some((a) => a.action === 'incident.create' && a.target === r.json.ref));
});

test('need-to-know incidents are invisible to non-members', async () => {
  const c = await login('cmdr');
  const inc = (await req('POST', '/api/incidents', { ...c, body: { title: 'Insider matter', category: 'insider', restricted: true } })).json;
  const r = await login('resp');
  assert.equal((await req('GET', '/api/incidents/' + inc.id, r)).status, 404);
  const boot = (await req('GET', '/api/bootstrap', r)).json;
  assert.ok(!boot.incidents.some((i) => i.id === inc.id));
  assert.ok(!boot.channels.some((ch) => ch.incidentId === inc.id), 'incident room hidden too');
  const a = await login('admin1');
  assert.equal((await req('GET', '/api/incidents/' + inc.id, a)).status, 200);
});

test('scope drives legal deadlines (Texas AG, GDPR, HIPAA)', async () => {
  const s = await login('resp');
  const inc = (await req('POST', '/api/incidents', { ...s, body: { title: 'Exfil', category: 'exfiltration' } })).json;
  const r = await req('POST', `/api/incidents/${inc.id}/scope`, { ...s, body: { asset: 'Patient DB', dataTypes: ['phi', 'pii'], records: 1200, residents: { TX: 900, EU: 40 }, status: 'exfiltrated', confidence: 'confirmed' } });
  assert.equal(r.status, 200);
  const full = (await req('GET', '/api/incidents/' + inc.id, s)).json;
  const ids = full.obligations.map((o) => o.id);
  for (const id of ['state-TX', 'state-TX-ag', 'gdpr', 'hipaa-ind', 'hipaa-hhs']) assert.ok(ids.includes(id), 'missing ' + id);
  const ag = full.obligations.find((o) => o.id === 'state-TX-ag');
  const days = (new Date(ag.dueAt) - new Date(full.detectedAt)) / 864e5;
  assert.equal(Math.round(days), 30);
});

test('regulation engine: SEC 8-K skips weekends', () => {
  const fri = new Date('2026-11-06T15:00:00Z'); // a Friday
  assert.equal(REG.addBusinessDays(fri, 4).toISOString().slice(0, 10), '2026-11-12');
});

test('deletions are soft (legal hold): struck items stay on record', async () => {
  const s = await login('resp');
  const inc = (await req('POST', '/api/incidents', { ...s, body: { title: 'Hold test' } })).json;
  const e = (await req('POST', `/api/incidents/${inc.id}/timeline`, { ...s, body: { text: 'oops', kind: 'note' } })).json;
  assert.equal((await req('DELETE', `/api/incidents/${inc.id}/timeline/${e.id}`, s)).status, 200);
  const full = (await req('GET', '/api/incidents/' + inc.id, s)).json;
  const kept = full.timeline.find((x) => x.id === e.id);
  assert.ok(kept && kept.deleted && kept.text === 'oops');
});

test('evidence is hashed on receipt and encrypted on disk', async () => {
  const s = await login('resp');
  const inc = (await req('POST', '/api/incidents', { ...s, body: { title: 'Evidence test' } })).json;
  const secret = Buffer.from('SECRET-RANSOM-NOTE-CONTENTS-' + Date.now());
  const ev = (await req('POST', `/api/incidents/${inc.id}/evidence`, { ...s, body: secret, headers: { 'content-type': 'application/octet-stream', 'x-filename': 'note.txt' } })).json;
  assert.equal(ev.sha256, C.sha256(secret));
  const onDisk = fs.readFileSync(path.join(DIR, 'evidence', ev.id + '.bin'));
  assert.ok(!onDisk.includes(secret), 'evidence must not be stored in plaintext');
  const dl = await fetch(`${base}/api/incidents/${inc.id}/evidence/${ev.id}/file`, { headers: { cookie: s.cookie } });
  assert.equal(dl.headers.get('x-integrity'), 'verified');
  assert.deepEqual(Buffer.from(await dl.arrayBuffer()), secret);
});

// A fresh authenticator code for step-up checks (tests reset the replay guard instead of waiting 30 s).
function freshCode(username) { const u = users[username]; u.lastTotpStep = -1; return C.totpAt(u.totpSecret, C.currentStep()); }

test('Team & Access: sign-in card, forced password change, then normal access', async () => {
  const a = await login('admin1');
  const r = await req('POST', '/api/admin/users', { ...a, body: { username: 'newbie', displayName: 'New Person', role: 'responder' } });
  assert.equal(r.status, 200, r.text);
  const card = r.json.card;
  assert.match(card.tempPassword, /^[A-Z2-9]{4}(-[A-Z2-9]{4}){3}$/);
  assert.match(card.uri, /^otpauth:\/\/totp\/WINDX:newbie\?secret=[A-Z2-7]+&issuer=WINDX&algorithm=SHA1&digits=6&period=30$/);
  assert.ok(card.qr.path.length > 100);
  const stored = vault.state.users.find((u) => u.username === 'newbie');
  assert.ok(!JSON.stringify(stored).includes(card.tempPassword), 'temporary password is never stored in plain text');
  assert.equal(stored.status, 'invited');

  const li = await req('POST', '/api/auth/login', { body: { username: 'newbie', password: card.tempPassword, totp: C.totpAt(card.secret, C.currentStep()) } });
  assert.equal(li.status, 200, li.text);
  assert.equal(li.json.mustChangePassword, true);
  const cookie = li.headers.get('set-cookie').split(';')[0];
  const csrf = (await req('GET', '/api/me', { cookie })).json.csrf;
  assert.equal((await req('GET', '/api/bootstrap', { cookie, csrf })).status, 403, 'nothing else works until the password is changed');
  assert.equal((await req('POST', '/api/auth/password', { cookie, csrf, body: { newPassword: 'short' } })).status, 400);
  assert.equal((await req('POST', '/api/auth/password', { cookie, csrf, body: { newPassword: card.tempPassword } })).status, 400, 'cannot reuse the temporary password');
  assert.equal((await req('POST', '/api/auth/password', { cookie, csrf, body: { newPassword: 'correct horse battery staple' } })).status, 200);
  assert.equal((await req('GET', '/api/bootstrap', { cookie, csrf })).status, 200);
  assert.equal(stored.status, 'active');
});

test('making someone an Administrator needs a fresh authenticator code', async () => {
  const a = await login('admin1');
  const target = mkUser('promote', 'responder');
  assert.equal((await req('PATCH', '/api/admin/users/' + target.id, { ...a, body: { role: 'admin' } })).status, 403);
  assert.equal(target.role, 'responder');
  const ok = await req('PATCH', '/api/admin/users/' + target.id, { ...a, body: { role: 'admin', code: freshCode('admin1') } });
  assert.equal(ok.status, 200, ok.text);
  assert.equal(target.role, 'admin');
  const self = await req('PATCH', '/api/admin/users/' + users.admin1.id, { ...a, body: { role: 'responder' } });
  assert.equal(self.status, 400, 'admins cannot demote themselves');
});

test('disabling a user needs a code and signs them out everywhere', async () => {
  const v = mkUser('leaver', 'responder');
  const vs = await login('leaver');
  const a = await login('admin1');
  assert.equal((await req('PATCH', '/api/admin/users/' + v.id, { ...a, body: { status: 'disabled', code: '000000' } })).status, 403);
  assert.equal((await req('GET', '/api/bootstrap', vs)).status, 200, 'wrong code changes nothing');
  assert.ok(vault.state.audit.some((e) => e.action === 'user.disable.mfa_fail'));
  const ok = await req('PATCH', '/api/admin/users/' + v.id, { ...a, body: { status: 'disabled', code: freshCode('admin1') } });
  assert.equal(ok.status, 200, ok.text);
  assert.equal((await req('GET', '/api/bootstrap', vs)).status, 401, 'their session is gone');
  const last = vault.state.audit.filter((e) => e.action === 'user.disable').pop();
  assert.ok(!JSON.stringify(last).includes('"code"'), 'the code itself is never logged');
});

test('reset sign-in issues a new card and kills sessions', async () => {
  const v = mkUser('lostphone', 'responder');
  const vs = await login('lostphone');
  const a = await login('admin1');
  const r = await req('POST', `/api/admin/users/${v.id}/reset`, { ...a, body: { code: freshCode('admin1') } });
  assert.equal(r.status, 200, r.text);
  assert.ok(r.json.card.tempPassword && r.json.card.secret);
  assert.equal((await req('GET', '/api/bootstrap', vs)).status, 401);
  v.lastTotpStep = -1;
  const old = await req('POST', '/api/auth/login', { body: { username: 'lostphone', password: PW, totp: C.totpAt(v.totpSecret, C.currentStep()) } });
  assert.equal(old.status, 401, 'old password no longer works');
});

test('three wrong step-up codes block step-up for 5 minutes', async () => {
  mkUser('admin2', 'admin');
  const a = await login('admin2');
  for (let i = 0; i < 3; i++) assert.equal((await req('POST', '/api/admin/lockdown', { ...a, body: { on: true, confirm: 'LOCKDOWN', code: '000000' } })).status, 403);
  const blocked = await req('POST', '/api/admin/lockdown', { ...a, body: { on: true, confirm: 'LOCKDOWN', code: freshCode('admin2') } });
  assert.equal(blocked.status, 429, 'even a correct code is refused while blocked');
  assert.equal(vault.state.lockdown?.on || false, false);
});

test('privileged incidents are hidden from roles not cleared for them', async () => {
  const c = await login('cmdr');
  const inc = (await req('POST', '/api/incidents', { ...c, body: { title: 'Privileged matter', severity: 2, category: 'other' } })).json;
  const e = await login('exec');
  assert.equal((await req('GET', '/api/incidents/' + inc.id, e)).status, 404);
  const cmdr = await login('cmdr');
  const pub = await req('POST', '/api/incidents', { ...cmdr, body: { title: 'Open matter', severity: 3, category: 'other', privileged: false } });
  const e2 = await login('exec');
  assert.equal((await req('GET', '/api/incidents/' + pub.json.id, e2)).status, 200);
});

test('lockdown needs LOCKDOWN typed and a code, then ends every session including the admin', async () => {
  const r = await login('resp');
  const a = await login('admin1');
  assert.equal((await req('POST', '/api/admin/lockdown', { ...a, body: { on: true, code: freshCode('admin1') } })).status, 400, 'must type LOCKDOWN');
  assert.equal((await req('POST', '/api/admin/lockdown', { ...a, body: { on: true, confirm: 'LOCKDOWN', code: '123456' } })).status, 403);
  assert.ok(vault.state.audit.some((x) => x.action === 'lockdown.mfa_fail'));
  assert.equal((await req('GET', '/api/bootstrap', r)).status, 200, 'wrong code: no lockdown');
  const ok = await req('POST', '/api/admin/lockdown', { ...a, body: { on: true, confirm: 'LOCKDOWN', code: freshCode('admin1') } });
  assert.equal(ok.status, 200, ok.text);
  assert.ok(ok.json.killed >= 2);
  assert.equal((await req('GET', '/api/bootstrap', r)).status, 401);
  assert.equal((await req('GET', '/api/bootstrap', a)).status, 401, 'the admin is signed out too');
  const entry = vault.state.audit.filter((x) => x.action === 'LOCKDOWN').pop();
  assert.equal(entry.detail.mfa, 'verified');
  const u = users.resp; u.lastTotpStep = -1;
  const again = await req('POST', '/api/auth/login', { body: { username: 'resp', password: PW, totp: C.totpAt(u.totpSecret, C.currentStep()) } });
  assert.equal(again.status, 403, 'non-admins stay out until it is lifted');
  const a2 = await login('admin1');
  assert.equal((await req('POST', '/api/admin/lockdown', { ...a2, body: { on: false } })).status, 200);
  await login('resp');
});

test('audit chain detects tampering', async () => {
  assert.equal(vault.verifyAudit().ok, true);
  const entry = vault.state.audit[3];
  const original = entry.actor.name;
  entry.actor.name = 'someone-else';
  const r = vault.verifyAudit();
  assert.equal(r.ok, false);
  assert.equal(r.brokenAt, 4);
  entry.actor.name = original;
  assert.equal(vault.verifyAudit().ok, true);
});

test('vault on disk is ciphertext and rejects the wrong passphrase', () => {
  vault.flush();
  const raw = fs.readFileSync(path.join(DIR, 'vault.lbv'));
  assert.ok(!raw.includes(Buffer.from('Files encrypted')), 'no plaintext incident data on disk');
  assert.ok(!raw.includes(Buffer.from('admin1')), 'no plaintext usernames on disk');
  const { Vault } = require('../lib/store');
  assert.throws(() => new Vault(DIR).open('the-wrong-passphrase'), /Wrong passphrase/);
});

test('QR encoder produces a valid-size symbol for an otpauth URI', () => {
  const m = require('../lib/qr').encode('otpauth://totp/WINDX:someone?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=WINDX&algorithm=SHA1&digits=6&period=30');
  assert.equal((m.length - 17) % 4, 0);
});
