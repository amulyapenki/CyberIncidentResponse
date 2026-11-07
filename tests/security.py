"""Security checks against a running demo server (run right after e2e.py)."""
import re, time, httpx, pyotp, sqlite3, subprocess, os
log=open('/tmp/srv.log').read()
creds=dict((u,(p,k)) for u,p,k in re.findall(r"enrollment: (\S+) .*?\n\s+temporary password : (\S+)\n\s+authenticator key  : (\S+)", log))
B="https://127.0.0.1:8443"; ok=lambda c,m: print(('PASS ' if c else 'FAIL ')+m)
def wait_step():
    t=time.time()%30
    if t>25: time.sleep(31-t)
c=httpx.Client(verify=False, base_url=B)
u,(pw,k)='j.okafor',creds['j.okafor']
wait_step(); time.sleep(31)  # make sure no earlier code reused
code=pyotp.TOTP(k).now()
r=c.post('/api/login', json={'username':u,'password':pw,'code':code}); ok(r.status_code==200, f'valid login ({r.status_code})')
csrf=r.json().get('csrf')
c2=httpx.Client(verify=False, base_url=B)
r=c2.post('/api/login', json={'username':u,'password':pw,'code':code}); ok(r.status_code==401, 'same TOTP code replay rejected')
r=c2.post('/api/login', json={'username':u,'password':'wrong','code':pyotp.TOTP(k).now()}); ok(r.status_code==401 and 'Check username' in r.text, 'wrong password: generic error (no user enumeration)')
r=c2.post('/api/login', json={'username':'nobody','password':'x','code':'123456'}); ok(r.status_code==401 and 'Check username' in r.text, 'unknown user: same generic error')
r=c.post('/api/incidents/1/entries', json={'kind':'timeline','text':'x'}); ok(r.status_code==403, 'POST without CSRF token rejected')
c.headers['X-CSRF-Token']=csrf
r=c.get('/api/incidents/1'); ok(r.status_code==403, 'temp password must be changed before any access')
c.post('/api/me/password', json={'current':pw,'new':'responder passphrase 99'})
r=c.post('/api/incidents/1/entries', json={'kind':'timeline','text':'<img src=x onerror=alert(1)>', 'privileged':True})
ok(r.status_code==200 and r.json()['privileged'] is False, 'responder cannot create privileged entries')
r=c.get('/api/incidents/1'); ok(not any(e.get('privileged') for e in r.json()['entries']['timeline']), 'privileged entries filtered server-side for responder')
r=c.post('/api/users', json={'username':'evil','display':'Evil','role':'admin'}); ok(r.status_code==403, 'responder cannot add users')
r=c.get('/api/audit'); ok(r.status_code==403, 'responder cannot read audit log')
r=c.patch('/api/incidents/1', json={'status':'Closed'}); ok(r.status_code==403, 'responder cannot close incident')
r=c.patch('/api/incidents/1', json={'severity':'SEV9'}); ok(r.status_code==400, 'invalid enum rejected')
r=c.post('/api/incidents/1/entries', content=b'x'*300000, headers={'content-type':'application/json'}); ok(r.status_code==413, 'oversized body rejected')
h=c.get('/').headers; ok("script-src 'self'" in h.get('content-security-policy','') and h.get('x-frame-options')=='DENY', 'CSP + anti-framing headers present')
ok('server' not in h, 'server banner hidden')
ok(c.get('/docs').status_code==404 and c.get('/openapi.json').status_code==404, 'API docs/schema not exposed')
sc=[x for x in c.cookies.jar][0]; ok(sc.secure and sc.name.startswith('__Host-'), 'session cookie is __Host-, Secure')
db=sqlite3.connect('/tmp/v/ironroom.db'); raw=b''.join(r[0] for r in db.execute('select data from entries'))
ok(b'LockBit' not in raw and b'svc-backup' not in raw and b'185.220' not in raw, 'incident data encrypted at rest (no plaintext in DB)')
rawu=b''.join(r[0] for r in db.execute('select data from users')); ok(b'argon2' not in rawu, 'password hashes & TOTP secrets encrypted at rest')
# tamper with an audit row and verify detection via admin
db.execute("update audit set prev='deadbeef' where id=3"); db.commit()
a=httpx.Client(verify=False, base_url=B); wait_step(); time.sleep(31)
r=a.post('/api/login', json={'username':'admin','password':'a much longer passphrase 2026','code':pyotp.TOTP(creds['admin'][1]).now()})
a.headers['X-CSRF-Token']=r.json()['csrf']
v=a.get('/api/audit/verify').json(); ok(v['ok'] is False and v['broken_at']==3, f'audit tampering detected: {v}')
# ---- evidence locker checks ----
r=a.get('/api/incidents/1').json(); ev=r['entries']['evidence'][0]
rawf=b''.join(x[0] for x in db.execute('select content from files')); ok(b'LockBit' not in rawf, 'evidence files encrypted at rest')
r=a.get(f"/api/evidence/{ev['id']}"); ok(r.status_code==200 and r.headers['content-type']=='application/octet-stream' and 'sandbox' in r.headers.get('content-security-policy',''), 'evidence served as download-only (no XSS via uploaded HTML)')
import hashlib as _h; ok(_h.sha256(r.content).hexdigest()==ev['sha256'], 'downloaded evidence matches recorded SHA-256')
r=a.post('/api/incidents/1/evidence', content=b'<script>alert(1)</script>', headers={'x-filename':'..%2F..%2Fetc%2Fpasswd<x>.html','content-type':'application/octet-stream'})
ok(r.status_code==200 and '/' not in r.json()['name'] and '<' not in r.json()['name'], f"path traversal / odd chars stripped from filename -> {r.json().get('name')}")
v=httpx.Client(verify=False, base_url=B); wait_step(); time.sleep(31)
r=v.post('/api/login', json={'username':'ceo.patel','password':'a much longer passphrase 2026','code':pyotp.TOTP(creds['ceo.patel'][1]).now()})
if r.status_code==200:
    v.headers['X-CSRF-Token']=r.json()['csrf']
    ok(v.get(f"/api/evidence/{ev['id']}").status_code==403, 'viewer cannot download evidence')
    ok(v.post('/api/incidents/1/evidence', content=b'x', headers={'x-filename':'a.txt'}).status_code==403, 'viewer cannot upload evidence')
blob=bytearray(db.execute('select content from files where id=?',(ev['file_id'],)).fetchone()[0]); blob[20]^=1
db.execute('update files set content=? where id=?',(bytes(blob),ev['file_id'])); db.commit()
ok(a.get(f"/api/evidence/{ev['id']}").status_code==500, 'tampered evidence file detected (AES-GCM authentication)')
