"""
IRONROOM - Cyber Incident Response Command Center
==================================================
A self-contained, out-of-band incident response dashboard designed to run on an
isolated laptop / hotspot while the corporate network is assumed compromised.

Security model (summary - see README.md for full threat model):
  * Zero dependency on corporate infra: no AD/SSO, no corporate DNS, no CDN, no cloud.
  * Everything at rest is AES-256-GCM encrypted. The key is derived (scrypt) from a
    passphrase typed at startup and is NEVER written to disk.
  * Passwords: Argon2id. MFA: TOTP is mandatory for every account (with replay protection).
  * Sessions live in RAM only, are bound to client IP, expire on idle (15 min) and
    absolute (8 h) timeouts, and can all be killed instantly with "Lockdown".
  * HTTPS only (self-signed cert generated locally; fingerprint printed for verification).
  * Network allowlist (CIDR) - only devices on the out-of-band network can connect.
  * Strict CSP, no inline script, all user data rendered via textContent (no XSS sinks).
  * CSRF token on every state-changing request; WebSocket Origin check.
  * Tamper-evident, HMAC hash-chained audit log of every action.
"""
import argparse
import asyncio
import base64
import datetime as dt
import getpass
import hashlib
import hmac
import io
import ipaddress
import json
import os
import secrets
import socket
import sqlite3
import sys
import threading
import time

import pyotp
import qrcode
import uvicorn
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError
from cryptography import x509
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.x509.oid import NameOID
from fastapi import FastAPI, HTTPException, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

BASE = os.path.dirname(os.path.abspath(__file__))
STATIC = os.path.join(BASE, "static")

# ----------------------------------------------------------------------------
# Domain constants
# ----------------------------------------------------------------------------
PHASES = ["Detection", "Analysis", "Containment", "Eradication", "Recovery", "Post-Incident"]
SEVERITIES = ["SEV1", "SEV2", "SEV3", "SEV4"]
STATUSES = ["Active", "Monitoring", "Closed"]
CATEGORIES = ["Ransomware", "Business Email Compromise", "Data Exfiltration", "Malware",
              "Unauthorized Access", "Phishing", "Insider Threat", "Denial of Service",
              "Lost/Stolen Device", "Other"]
DATA_TYPES = ["PII", "PHI (health)", "PCI (card data)", "Financial", "Credentials",
              "Trade secrets / IP", "Attorney-client privileged", "Employee / HR",
              "Customer data", "Source code", "Other"]
SCOPE_STATUSES = ["Unknown", "Accessed", "Exfiltrated", "Encrypted (ransomware)",
                  "Deleted", "Modified", "Contained", "Restored"]
CONFIDENCE = ["Suspected", "Likely", "Confirmed"]
IOC_TYPES = ["IP address", "Domain", "URL", "File hash", "Email address", "User account",
             "Hostname", "File name", "Other"]

ROLES = {
    "admin":     {"users", "audit", "lockdown", "incident.create", "incident.edit",
                  "incident.close", "entry.write", "read.priv", "chat"},
    "commander": {"audit", "incident.create", "incident.edit", "incident.close",
                  "entry.write", "read.priv", "chat"},
    "responder": {"incident.create", "incident.edit", "entry.write", "chat"},
    "legal":     {"incident.edit", "entry.write", "read.priv", "chat"},
    "viewer":    {"chat"},
}
ROLE_LABELS = {"admin": "Administrator", "commander": "Incident Commander",
               "responder": "Responder", "legal": "Legal / Counsel", "viewer": "Executive / Viewer"}

PLAYBOOK_COMMON = {
    "Detection": ["Confirm the alert is a real incident (not a false positive)",
                  "Assign an Incident Commander",
                  "Move team communications OFF corporate email/chat to this system"],
    "Analysis": ["Identify affected systems and accounts",
                 "Record indicators of compromise (IOCs)",
                 "Determine what data may be involved (Scope tab)",
                 "Engage outside counsel (preserves privilege)",
                 "Notify cyber insurance carrier"],
    "Containment": ["Isolate affected hosts from the network",
                    "Disable/reset compromised accounts",
                    "Preserve evidence: memory images, logs, disk images"],
    "Eradication": ["Remove attacker persistence (tasks, services, accounts)",
                    "Patch/close the initial access vector"],
    "Recovery": ["Restore from known-good backups",
                 "Monitor restored systems for re-infection",
                 "Complete legal/regulatory notifications"],
    "Post-Incident": ["Hold lessons-learned review",
                      "Finalize incident report",
                      "Update playbooks and controls"],
}
PLAYBOOK_EXTRA = {
    "Ransomware": {
        "Analysis": ["Photograph/save the ransom note (do NOT contact attacker without counsel)",
                     "Identify ransomware strain",
                     "Check OFAC sanctions exposure before any payment discussion"],
        "Containment": ["Verify offline/immutable backups are intact and isolated",
                        "Block known C2 domains/IPs at the perimeter"],
    },
    "Business Email Compromise": {
        "Containment": ["Revoke mailbox sessions and OAuth tokens",
                        "Remove malicious inbox forwarding rules",
                        "Call bank to recall/freeze any fraudulent wire (verify by phone)"],
    },
    "Data Exfiltration": {
        "Analysis": ["Identify exfiltration channel and volume",
                     "Check leak sites / dark web for posted data"],
    },
}

# Default notification reminders. NOT legal advice - confirm with counsel.
VERIFY_WORDS = ("amber anchor apple arrow aspen atlas badge banjo basil beacon birch bison "
                "blaze bolt brick brook cabin cactus canyon cedar chalk cobalt comet coral "
                "cosmo crane delta dune eagle ember falcon fern flint forge frost garnet "
                "glacier granite harbor hazel heron indigo iris jade jasper juniper kayak "
                "kestrel lagoon lantern lemon lotus maple marble meadow mesa nectar nova "
                "oak oasis onyx orbit otter pebble pepper pine plum prism quartz raven reef "
                "ridge river saffron sage sierra slate sparrow spruce summit tango thistle "
                "timber topaz tulip tundra velvet violet walnut willow zephyr").split()

# ----------------------------------------------------------------------------
# Vault: key derivation + authenticated encryption
# ----------------------------------------------------------------------------
class Vault:
    def __init__(self, passphrase: str, salt: bytes):
        master = Scrypt(salt=salt, length=32, n=2 ** 15, r=8, p=1).derive(passphrase.encode())
        self.enc_key = HKDF(hashes.SHA256(), 32, None, b"ironroom-enc-v1").derive(master)
        self.mac_key = HKDF(hashes.SHA256(), 32, None, b"ironroom-mac-v1").derive(master)
        self.aead = AESGCM(self.enc_key)

    def seal(self, obj, aad: str) -> bytes:
        nonce = os.urandom(12)
        return nonce + self.aead.encrypt(nonce, json.dumps(obj).encode(), aad.encode())

    def open(self, blob: bytes, aad: str):
        return json.loads(self.aead.decrypt(blob[:12], blob[12:], aad.encode()))

    def mac(self, data: str) -> str:
        return hmac.new(self.mac_key, data.encode(), hashlib.sha256).hexdigest()


# ----------------------------------------------------------------------------
# Storage (SQLite; every payload column is ciphertext)
# ----------------------------------------------------------------------------
class Store:
    def __init__(self, path: str):
        self.db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA secure_delete=ON")
        self.lock = threading.RLock()
        with self.lock:
            self.db.executescript("""
            CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v BLOB);
            CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE, data BLOB);
            CREATE TABLE IF NOT EXISTS incidents(id INTEGER PRIMARY KEY, created REAL, data BLOB);
            CREATE TABLE IF NOT EXISTS entries(id INTEGER PRIMARY KEY, incident_id INTEGER,
                kind TEXT, created REAL, data BLOB);
            CREATE INDEX IF NOT EXISTS ix_entries ON entries(incident_id, kind);
            CREATE TABLE IF NOT EXISTS files(id INTEGER PRIMARY KEY, incident_id INTEGER, content BLOB);
            CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, ts REAL, prev TEXT, hash TEXT, data BLOB);
            """)

    def meta_get(self, k):
        r = self.db.execute("SELECT v FROM meta WHERE k=?", (k,)).fetchone()
        return r[0] if r else None

    def meta_set(self, k, v):
        with self.lock:
            self.db.execute("INSERT OR REPLACE INTO meta VALUES(?,?)", (k, v))


V: Vault = None
S: Store = None
PH = PasswordHasher()  # argon2id defaults
DUMMY_HASH = PH.hash(secrets.token_hex(16))

# ---- users ----
def user_get(uid):
    r = S.db.execute("SELECT id, username, data FROM users WHERE id=?", (uid,)).fetchone()
    if not r:
        return None
    d = V.open(r[2], "users")
    d.update(id=r[0], username=r[1])
    return d

def user_by_name(name):
    r = S.db.execute("SELECT id FROM users WHERE username=?", (name.lower().strip(),)).fetchone()
    return user_get(r[0]) if r else None

def user_save(u):
    d = {k: v for k, v in u.items() if k not in ("id", "username")}
    with S.lock:
        if u.get("id"):
            S.db.execute("UPDATE users SET data=? WHERE id=?", (V.seal(d, "users"), u["id"]))
        else:
            cur = S.db.execute("INSERT INTO users(username, data) VALUES(?,?)",
                               (u["username"], V.seal(d, "users")))
            u["id"] = cur.lastrowid
    return u

def users_all():
    return [user_get(r[0]) for r in S.db.execute("SELECT id FROM users ORDER BY id")]

def public_user(u):
    return {"id": u["id"], "username": u["username"], "display": u["display"], "role": u["role"],
            "role_label": ROLE_LABELS[u["role"]], "active": u["active"],
            "perms": sorted(ROLES[u["role"]]), "must_change": u.get("must_change", False),
            "last_login": u.get("last_login")}

# ---- incidents / entries ----
def inc_get(iid):
    r = S.db.execute("SELECT id, created, data FROM incidents WHERE id=?", (iid,)).fetchone()
    if not r:
        return None
    d = V.open(r[2], "incidents")
    d.update(id=r[0], created=r[1])
    return d

def inc_save(inc):
    d = {k: v for k, v in inc.items() if k not in ("id", "created")}
    with S.lock:
        if inc.get("id"):
            S.db.execute("UPDATE incidents SET data=? WHERE id=?", (V.seal(d, "incidents"), inc["id"]))
        else:
            inc["created"] = time.time()
            cur = S.db.execute("INSERT INTO incidents(created, data) VALUES(?,?)",
                               (inc["created"], V.seal(d, "incidents")))
            inc["id"] = cur.lastrowid
    return inc

def entry_get(eid):
    r = S.db.execute("SELECT id, incident_id, kind, created, data FROM entries WHERE id=?", (eid,)).fetchone()
    if not r:
        return None
    d = V.open(r[4], "entries:" + r[2])
    d.update(id=r[0], incident_id=r[1], kind=r[2], created=r[3])
    return d

def entry_save(e):
    d = {k: v for k, v in e.items() if k not in ("id", "incident_id", "kind", "created")}
    with S.lock:
        if e.get("id"):
            S.db.execute("UPDATE entries SET data=? WHERE id=?", (V.seal(d, "entries:" + e["kind"]), e["id"]))
        else:
            e["created"] = e.get("created") or time.time()
            cur = S.db.execute("INSERT INTO entries(incident_id, kind, created, data) VALUES(?,?,?,?)",
                               (e["incident_id"], e["kind"], e["created"], V.seal(d, "entries:" + e["kind"])))
            e["id"] = cur.lastrowid
    return e

def entries_for(iid, kind=None, limit=None):
    sql = "SELECT id FROM entries WHERE incident_id=?"
    args = [iid]
    if kind:
        sql += " AND kind=?"
        args.append(kind)
    sql += " ORDER BY id"
    rows = S.db.execute(sql, args).fetchall()
    if limit:
        rows = rows[-limit:]
    return [entry_get(r[0]) for r in rows]

# ---- audit ----
def audit(actor, action, target="", detail=None, ip=""):
    with S.lock:
        r = S.db.execute("SELECT hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
        prev = r[0] if r else "GENESIS"
        rec = {"ts": time.time(), "actor": actor, "action": action, "target": str(target),
               "detail": detail, "ip": ip}
        h = V.mac(prev + json.dumps(rec, sort_keys=True))
        S.db.execute("INSERT INTO audit(ts, prev, hash, data) VALUES(?,?,?,?)",
                     (rec["ts"], prev, h, V.seal(rec, "audit")))

def audit_verify():
    prev = "GENESIS"
    n = 0
    for rid, p, h, blob in S.db.execute("SELECT id, prev, hash, data FROM audit ORDER BY id"):
        try:
            rec = V.open(blob, "audit")
        except InvalidTag:
            return {"ok": False, "checked": n, "broken_at": rid, "reason": "ciphertext tampered"}
        if p != prev or not hmac.compare_digest(h, V.mac(prev + json.dumps(rec, sort_keys=True))):
            return {"ok": False, "checked": n, "broken_at": rid, "reason": "hash chain mismatch"}
        prev = h
        n += 1
    return {"ok": True, "checked": n, "head": prev}

# ----------------------------------------------------------------------------
# Input validation (whitelist every field)
# ----------------------------------------------------------------------------
def _str(n):
    def f(v):
        if not isinstance(v, str):
            raise ValueError("must be text")
        v = v.strip()
        if len(v) > n:
            raise ValueError(f"max {n} characters")
        return v
    return f

def _enum(opts):
    def f(v):
        if v not in opts:
            raise ValueError("invalid choice")
        return v
    return f

def _bool(v):
    if not isinstance(v, bool):
        raise ValueError("must be true/false")
    return v

def _int(lo, hi):
    def f(v):
        if v in ("", None):
            return None
        v = int(v)
        if not lo <= v <= hi:
            raise ValueError("out of range")
        return v
    return f

def _list(item, maxn):
    def f(v):
        if not isinstance(v, list) or len(v) > maxn:
            raise ValueError("invalid list")
        return [item(x) for x in v]
    return f

INCIDENT_SCHEMA = {
    "title": _str(200), "category": _enum(CATEGORIES), "severity": _enum(SEVERITIES),
    "phase": _enum(PHASES), "status": _enum(STATUSES),
    "discovered_at": _str(40), "occurred_at": _str(40), "materiality_at": _str(40),
    "detection_source": _str(300), "reported_by": _str(200), "summary": _str(8000),
    "business_impact": _str(4000), "attack_vector": _str(500), "threat_actor": _str(300),
    "affected_systems": _str(4000), "ransom_demand": _str(300), "external_refs": _str(2000),
    "counsel_engaged": _bool, "insurer_notified": _bool, "le_notified": _bool,
    "forensics_engaged": _bool, "backups_verified": _bool, "regulators_notified": _bool,
    "notices_done": _list(_str(80), 40),
}
ENTRY_SCHEMAS = {
    "timeline": {"at": _str(40), "text": _str(4000), "privileged": _bool, "source": _str(200)},
    "task": {"title": _str(300), "phase": _enum(PHASES), "assignee": _str(200), "done": _bool},
    "scope": {"name": _str(300), "system": _str(300), "data_types": _list(_enum(DATA_TYPES), 12),
              "records": _int(0, 10 ** 11), "status": _enum(SCOPE_STATUSES),
              "confidence": _enum(CONFIDENCE), "jurisdictions": _list(_str(40), 30),
              "notes": _str(3000)},
    "ioc": {"type": _enum(IOC_TYPES), "value": _str(600), "note": _str(600)},
    "message": {"text": _str(4000), "urgent": _bool, "privileged": _bool},
}

def clean(data, schema, partial=True):
    if not isinstance(data, dict):
        raise HTTPException(400, "Expected an object")
    out = {}
    for k, v in data.items():
        if k not in schema:
            continue  # silently drop unknown fields
        try:
            out[k] = schema[k](v)
        except (ValueError, TypeError) as e:
            raise HTTPException(400, f"Field '{k}': {e}")
    return out

# ----------------------------------------------------------------------------
# Sessions (RAM only), rate limiting
# ----------------------------------------------------------------------------
IDLE_TIMEOUT = 15 * 60
ABS_TIMEOUT = 8 * 3600
SESSIONS = {}          # sha256(token) -> {uid, created, last, csrf, ip}
FAILS_IP = {}          # ip -> [timestamps]
COOKIE = "__Host-ironroom"

def _th(tok):
    return hashlib.sha256(tok.encode()).hexdigest()

def client_ip(conn):
    return conn.client.host if conn.client else "?"

def session_from(conn, require_csrf=False):
    tok = conn.cookies.get(COOKIE)
    if not tok:
        raise HTTPException(401, "Not signed in")
    th = _th(tok)
    s = SESSIONS.get(th)
    now = time.time()
    if not s:
        raise HTTPException(401, "Session expired - please sign in again")
    if now - s["last"] > IDLE_TIMEOUT or now - s["created"] > ABS_TIMEOUT:
        SESSIONS.pop(th, None)
        raise HTTPException(401, "Session timed out - please sign in again")
    if s["ip"] != client_ip(conn):
        SESSIONS.pop(th, None)
        raise HTTPException(401, "Session moved to a different device - signed out")
    u = user_get(s["uid"])
    if not u or not u["active"]:
        SESSIONS.pop(th, None)
        raise HTTPException(401, "Account disabled")
    if require_csrf:
        hdr = conn.headers.get("x-csrf-token", "")
        if not hmac.compare_digest(hdr, s["csrf"]):
            raise HTTPException(403, "Security token mismatch - reload the page")
    s["last"] = now
    return u, s, th

def auth(request: Request, perm=None, allow_must_change=False):
    u, s, th = session_from(request, require_csrf=request.method not in ("GET", "HEAD"))
    if u.get("must_change") and not allow_must_change:
        raise HTTPException(403, "You must set a new password first")
    if perm and perm not in ROLES[u["role"]]:
        raise HTTPException(403, f"Your role ({ROLE_LABELS[u['role']]}) can't do that")
    request.state.user = u
    return u

def can(u, perm):
    return perm in ROLES[u["role"]]

def kill_sessions(uid=None):
    for th in [t for t, s in SESSIONS.items() if uid is None or s["uid"] == uid]:
        SESSIONS.pop(th, None)

# ----------------------------------------------------------------------------
# Real-time hub (server -> client push only; all writes go through CSRF'd REST)
# ----------------------------------------------------------------------------
class Hub:
    def __init__(self):
        self.conns = {}  # ws -> (uid, session_hash)

    def presence(self):
        seen = {}
        for uid, _ in self.conns.values():
            u = user_get(uid)
            if u:
                seen[uid] = {"id": uid, "display": u["display"], "role": ROLE_LABELS[u["role"]]}
        return list(seen.values())

    async def send(self, event, privileged=False):
        dead = []
        for ws, (uid, th) in list(self.conns.items()):
            if th not in SESSIONS:
                dead.append(ws)
                continue
            u = user_get(uid)
            if not u or not u["active"]:
                dead.append(ws)
                continue
            if privileged and not can(u, "read.priv"):
                continue
            try:
                await ws.send_text(json.dumps(event))
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.conns.pop(ws, None)
            try:
                await ws.close(code=4001)
            except Exception:
                pass

    async def close_all(self, uid=None):
        for ws, (u, _) in list(self.conns.items()):
            if uid is None or u == uid:
                self.conns.pop(ws, None)
                try:
                    await ws.send_text(json.dumps({"type": "signed_out"}))
                    await ws.close(code=4001)
                except Exception:
                    pass

HUB = Hub()

# ----------------------------------------------------------------------------
# ASGI guard: network allowlist, body size cap, security headers
# ----------------------------------------------------------------------------
ALLOW_NETS = []
SEC_HEADERS = [
    (b"content-security-policy", b"default-src 'none'; script-src 'self'; style-src 'self'; "
                                 b"img-src 'self' data:; connect-src 'self'; font-src 'self'; "
                                 b"base-uri 'none'; form-action 'self'; frame-ancestors 'none'"),
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"referrer-policy", b"no-referrer"),
    (b"strict-transport-security", b"max-age=31536000"),
    (b"cross-origin-opener-policy", b"same-origin"),
    (b"cross-origin-resource-policy", b"same-origin"),
    (b"permissions-policy", b"camera=(), microphone=(), geolocation=(), usb=(), payment=()"),
]
MAX_BODY = 256 * 1024
MAX_UPLOAD = 25 * 1024 * 1024

def ip_allowed(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in ALLOW_NETS)

class Guard:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] not in ("http", "websocket"):
            return await self.app(scope, receive, send)
        ip = (scope.get("client") or ("?", 0))[0]
        if not ip_allowed(ip):
            if scope["type"] == "http":
                await send({"type": "http.response.start", "status": 403,
                            "headers": [(b"content-type", b"text/plain")]})
                await send({"type": "http.response.body", "body": b"Forbidden network"})
            else:
                await receive()
                await send({"type": "websocket.close", "code": 1008})
            return
        if scope["type"] == "websocket":
            return await self.app(scope, receive, send)
        limit = MAX_UPLOAD + 4096 if scope.get("path", "").endswith("/evidence") else MAX_BODY
        for k, v in scope.get("headers", []):
            if k == b"content-length" and v.isdigit() and int(v) > limit:
                await send({"type": "http.response.start", "status": 413, "headers": []})
                await send({"type": "http.response.body", "body": b"Too large"})
                return
        path = scope.get("path", "")
        seen = 0
        orig_receive = receive

        async def receive():  # enforce limit on streamed/chunked bodies too
            nonlocal seen
            msg = await orig_receive()
            if msg["type"] == "http.request":
                seen += len(msg.get("body", b""))
                if seen > limit:
                    return {"type": "http.disconnect"}
            return msg

        async def send2(msg):
            if msg["type"] == "http.response.start":
                h = [x for x in msg.get("headers", []) if x[0].lower() != b"server"] + SEC_HEADERS
                if path.startswith("/api"):
                    h.append((b"cache-control", b"no-store"))
                msg["headers"] = h
            await send(msg)
        return await self.app(scope, receive, send2)

# ----------------------------------------------------------------------------
# App + API
# ----------------------------------------------------------------------------
api = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

@api.exception_handler(HTTPException)
async def http_err(request, exc):
    return JSONResponse({"error": exc.detail}, status_code=exc.status_code)

def now_iso():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")

def qr_data_uri(text):
    img = qrcode.make(text, box_size=6, border=2)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()

def gen_password():
    words = secrets.SystemRandom().sample(VERIFY_WORDS, 3)
    return "-".join(words) + "-" + str(secrets.randbelow(9000) + 1000)

def enrollment(u, password):
    uri = pyotp.TOTP(u["totp"]).provisioning_uri(name=u["username"], issuer_name="IRONROOM")
    return {"username": u["username"], "temp_password": password, "totp_secret": u["totp"],
            "totp_uri": uri, "qr": qr_data_uri(uri)}

def new_user(username, display, role, password=None):
    password = password or gen_password()
    u = {"username": username, "display": display, "role": role, "active": True,
         "pw": PH.hash(password), "totp": pyotp.random_base32(), "last_step": 0,
         "fails": 0, "locked_until": 0, "must_change": True, "created": now_iso()}
    return user_save(u), password

@api.get("/")
async def index():
    return FileResponse(os.path.join(STATIC, "index.html"))

@api.get("/api/meta")
async def meta():
    return {"phases": PHASES, "severities": SEVERITIES, "statuses": STATUSES,
            "categories": CATEGORIES, "data_types": DATA_TYPES, "scope_statuses": SCOPE_STATUSES,
            "confidence": CONFIDENCE, "ioc_types": IOC_TYPES, "roles": ROLE_LABELS,
            "idle_timeout": IDLE_TIMEOUT, "fingerprint": CERT_FP, "server_time": time.time(),
            "max_upload": MAX_UPLOAD}


@api.get("/api/time")
async def server_time():
    return {"server_time": time.time()}

# ---- authentication ----
@api.post("/api/login")
async def login(request: Request, response: Response):
    ip = client_ip(request)
    now = time.time()
    FAILS_IP[ip] = [t for t in FAILS_IP.get(ip, []) if now - t < 600]
    if len(FAILS_IP[ip]) >= 10:
        raise HTTPException(429, "Too many failed attempts from this device. Wait 10 minutes.")
    body = await request.json()
    username = str(body.get("username", ""))[:64].lower().strip()
    password = str(body.get("password", ""))[:256]
    code = "".join(ch for ch in str(body.get("code", "")) if ch.isdigit())[:6]
    u = user_by_name(username) if username else None
    generic = "Sign-in failed. Check username, password and 6-digit code."

    def fail(reason):
        FAILS_IP[ip].append(now)
        if u:
            u["fails"] = u.get("fails", 0) + 1
            if u["fails"] >= 5:
                u["locked_until"] = now + 900
                u["fails"] = 0
            user_save(u)
        audit(username or "?", "login.fail", username, {"reason": reason}, ip)
        raise HTTPException(401, generic)

    if not u:
        try:
            PH.verify(DUMMY_HASH, password)  # constant-ish time
        except Exception:
            pass
        fail("unknown user")
    if not u["active"]:
        fail("disabled")
    if u.get("locked_until", 0) > now:
        audit(username, "login.locked", username, None, ip)
        raise HTTPException(423, "Account temporarily locked after failed attempts. Try again in 15 minutes.")
    try:
        PH.verify(u["pw"], password)
    except (VerifyMismatchError, InvalidHashError):
        fail("bad password")
    totp = pyotp.TOTP(u["totp"])
    step = None
    for off in (-1, 0, 1):  # allow 30 s clock drift
        t = now + off * 30
        if hmac.compare_digest(totp.at(t), code.ljust(6, "x")):
            step = int(t // 30)
    if step is None:
        fail("bad mfa code")
    if step <= u.get("last_step", 0):
        fail("mfa code replay")
    u.update(last_step=step, fails=0, locked_until=0, last_login=now_iso())
    user_save(u)
    tok = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(32)
    SESSIONS[_th(tok)] = {"uid": u["id"], "created": now, "last": now, "csrf": csrf, "ip": ip}
    response.set_cookie(COOKIE, tok, httponly=True, secure=True, samesite="strict", path="/")
    audit(u["username"], "login.ok", u["username"], None, ip)
    return {"user": public_user(u), "csrf": csrf}

@api.post("/api/logout")
async def logout(request: Request, response: Response):
    try:
        u, s, th = session_from(request, require_csrf=True)
        SESSIONS.pop(th, None)
        audit(u["username"], "logout", u["username"], None, client_ip(request))
    except HTTPException:
        pass
    response.delete_cookie(COOKIE, path="/")
    return {"ok": True}

@api.get("/api/session")
async def session(request: Request):
    u, s, _ = session_from(request)
    return {"user": public_user(u), "csrf": s["csrf"]}

@api.post("/api/me/password")
async def change_pw(request: Request):
    u = auth(request, allow_must_change=True)
    body = await request.json()
    cur, new = str(body.get("current", "")), str(body.get("new", ""))
    try:
        PH.verify(u["pw"], cur)
    except Exception:
        raise HTTPException(400, "Current password is wrong")
    if len(new) < 12:
        raise HTTPException(400, "New password must be at least 12 characters")
    if new == cur:
        raise HTTPException(400, "New password must be different")
    u["pw"] = PH.hash(new)
    u["must_change"] = False
    user_save(u)
    audit(u["username"], "password.change", u["username"], None, client_ip(request))
    return {"user": public_user(u)}

# ---- administration ----
@api.get("/api/users")
async def list_users(request: Request):
    auth(request)  # everyone sees the roster (who's on the team); details limited
    online = {p["id"] for p in HUB.presence()}
    return [dict(public_user(u), online=u["id"] in online) for u in users_all()]

@api.post("/api/users")
async def add_user(request: Request):
    me = auth(request, "users")
    b = await request.json()
    username = str(b.get("username", "")).lower().strip()
    display = str(b.get("display", "")).strip()[:80]
    role = b.get("role")
    if not username.replace(".", "").replace("_", "").replace("-", "").isalnum() or not 2 <= len(username) <= 32:
        raise HTTPException(400, "Username: 2-32 letters, numbers, . _ -")
    if not display:
        raise HTTPException(400, "Enter the person's full name")
    if role not in ROLES:
        raise HTTPException(400, "Pick a role")
    if user_by_name(username):
        raise HTTPException(409, "That username already exists")
    u, pw = new_user(username, display, role)
    audit(me["username"], "user.create", username, {"role": role}, client_ip(request))
    await HUB.send({"type": "users"})
    return {"user": public_user(u), "enrollment": enrollment(u, pw)}

@api.patch("/api/users/{uid}")
async def edit_user(uid: int, request: Request):
    me = auth(request, "users")
    u = user_get(uid)
    if not u:
        raise HTTPException(404, "No such user")
    b = await request.json()
    changes = {}
    if "role" in b:
        if b["role"] not in ROLES:
            raise HTTPException(400, "Bad role")
        if u["id"] == me["id"] and b["role"] != "admin":
            raise HTTPException(400, "You can't remove your own admin role")
        u["role"] = changes["role"] = b["role"]
    if "active" in b:
        if u["id"] == me["id"]:
            raise HTTPException(400, "You can't disable yourself")
        u["active"] = changes["active"] = bool(b["active"])
    user_save(u)
    if not u["active"]:
        kill_sessions(uid)
        await HUB.close_all(uid)
    audit(me["username"], "user.update", u["username"], changes, client_ip(request))
    await HUB.send({"type": "users"})
    return public_user(u)

@api.post("/api/users/{uid}/reset")
async def reset_user(uid: int, request: Request):
    me = auth(request, "users")
    u = user_get(uid)
    if not u:
        raise HTTPException(404, "No such user")
    pw = gen_password()
    u.update(pw=PH.hash(pw), totp=pyotp.random_base32(), last_step=0, must_change=True,
             fails=0, locked_until=0)
    user_save(u)
    kill_sessions(uid)
    await HUB.close_all(uid)
    audit(me["username"], "user.reset", u["username"], None, client_ip(request))
    return {"enrollment": enrollment(u, pw)}

@api.post("/api/admin/lockdown")
async def lockdown(request: Request):
    me = auth(request, "lockdown")
    n = len(SESSIONS)
    audit(me["username"], "LOCKDOWN", "all sessions", {"killed": n}, client_ip(request))
    await HUB.close_all()
    kill_sessions()
    return {"killed": n}

@api.get("/api/audit")
async def get_audit(request: Request, limit: int = 300):
    auth(request, "audit")
    rows = S.db.execute("SELECT id, hash, data FROM audit ORDER BY id DESC LIMIT ?", (min(limit, 2000),)).fetchall()
    out = []
    for rid, h, blob in rows:
        rec = V.open(blob, "audit")
        rec.update(id=rid, hash=h[:16])
        out.append(rec)
    return out

@api.get("/api/audit/verify")
async def verify_audit(request: Request):
    me = auth(request, "audit")
    res = audit_verify()
    audit(me["username"], "audit.verify", "", {"ok": res["ok"]}, client_ip(request))
    return res

# ---- incidents ----
def incident_summary(inc):
    scope = entries_for(inc["id"], "scope")
    tasks = entries_for(inc["id"], "task")
    return {k: inc.get(k) for k in ("id", "ref", "title", "category", "severity", "phase",
                                    "status", "discovered_at", "created", "updated")} | {
        "scope_count": len(scope),
        "records": sum((s.get("records") or 0) for s in scope),
        "exfil": any(s.get("status") == "Exfiltrated" for s in scope),
        "encrypted": any(s.get("status") == "Encrypted (ransomware)" for s in scope),
        "tasks_done": sum(1 for t in tasks if t.get("done")), "tasks_total": len(tasks)}

def verify_phrase(iid):
    hour = int(time.time() // 3600)
    d = V.mac(f"phrase|{iid}|{hour}")
    words = [VERIFY_WORDS[int(d[i:i + 4], 16) % len(VERIFY_WORDS)] for i in (0, 4, 8)]
    return {"phrase": " ".join(words), "expires": (hour + 1) * 3600}

def visible(u, e):
    return not e.get("privileged") or can(u, "read.priv")

async def push_entry(e, action="entry"):
    await HUB.send({"type": action, "incident_id": e["incident_id"], "kind": e["kind"],
                    "entry": e}, privileged=bool(e.get("privileged")))

async def system_note(iid, text, who):
    e = entry_save({"incident_id": iid, "kind": "timeline", "at": now_iso(), "text": text,
                    "privileged": False, "source": "System", "author": who, "is_system": True})
    await push_entry(e)

@api.get("/api/incidents")
async def list_incidents(request: Request):
    auth(request)
    rows = S.db.execute("SELECT id FROM incidents ORDER BY id DESC").fetchall()
    return [incident_summary(inc_get(r[0])) for r in rows]

@api.post("/api/incidents")
async def create_incident(request: Request):
    me = auth(request, "incident.create")
    b = clean(await request.json(), INCIDENT_SCHEMA)
    if not b.get("title"):
        raise HTTPException(400, "Give the incident a short title")
    inc = {"title": b["title"], "category": b.get("category", "Other"),
           "severity": b.get("severity", "SEV2"), "phase": "Detection", "status": "Active",
           "discovered_at": b.get("discovered_at") or now_iso(), "commander": me["display"],
           "created_by": me["username"], "updated": time.time(), "updated_by": me["display"],
           "history": [{"field": "phase", "from": None, "to": "Detection", "at": now_iso(), "by": me["display"]},
                       {"field": "severity", "from": None, "to": b.get("severity", "SEV2"), "at": now_iso(), "by": me["display"]},
                       {"field": "status", "from": None, "to": "Active", "at": now_iso(), "by": me["display"]}]}
    inc.update({k: v for k, v in b.items() if k not in inc})
    inc = inc_save(inc)
    inc["ref"] = f"IR-{dt.date.today().year}-{inc['id']:03d}"
    inc_save(inc)
    # seed playbook
    for ph in PHASES:
        items = PLAYBOOK_COMMON.get(ph, []) + PLAYBOOK_EXTRA.get(inc["category"], {}).get(ph, [])
        for t in items:
            entry_save({"incident_id": inc["id"], "kind": "task", "title": t, "phase": ph,
                        "assignee": "", "done": False, "author": "Playbook"})
    await system_note(inc["id"], f"Incident declared by {me['display']} ({inc['severity']}, {inc['category']})",
                      me["display"])
    audit(me["username"], "incident.create", inc["ref"], {"title": inc["title"]}, client_ip(request))
    await HUB.send({"type": "incidents"})
    return incident_summary(inc)

@api.get("/api/incidents/{iid}")
async def get_incident(iid: int, request: Request):
    me = auth(request)
    inc = inc_get(iid)
    if not inc:
        raise HTTPException(404, "No such incident")
    ents = [e for e in entries_for(iid) if visible(me, e)]
    by = {k: [] for k in list(ENTRY_SCHEMAS) + ["evidence"]}
    for e in ents:
        by[e["kind"]].append(e)
    by["message"] = by["message"][-300:]
    return {"incident": inc, "entries": by, "phrase": verify_phrase(iid)}

@api.patch("/api/incidents/{iid}")
async def patch_incident(iid: int, request: Request):
    me = auth(request, "incident.edit")
    inc = inc_get(iid)
    if not inc:
        raise HTTPException(404, "No such incident")
    b = clean(await request.json(), INCIDENT_SCHEMA)
    if b.get("status") == "Closed" and not can(me, "incident.close"):
        raise HTTPException(403, "Only the Incident Commander can close an incident")
    notes = []
    labels = {"phase": "Phase", "status": "Status", "severity": "Severity"}
    hist = inc.setdefault("history", [])
    for k, lbl in labels.items():
        if k in b and b[k] != inc.get(k):
            notes.append(f"{lbl}: {inc.get(k)} → {b[k]}")
            hist.append({"field": k, "from": inc.get(k), "to": b[k], "at": now_iso(), "by": me["display"]})
    flag_labels = {"counsel_engaged": "Outside counsel engaged", "insurer_notified": "Insurer notified",
                   "le_notified": "Law enforcement notified", "forensics_engaged": "Forensics firm engaged",
                   "backups_verified": "Backups verified", "regulators_notified": "Regulators notified"}
    for k, lbl in flag_labels.items():
        if k in b and b[k] != bool(inc.get(k)):
            notes.append(f"{lbl}: {'YES' if b[k] else 'no'}")
    inc.update(b)
    inc["updated"] = time.time()
    inc["updated_by"] = me["display"]
    inc_save(inc)
    for n in notes:
        await system_note(iid, f"{n} (by {me['display']})", me["display"])
    audit(me["username"], "incident.update", inc["ref"], {"fields": sorted(b)}, client_ip(request))
    await HUB.send({"type": "incident", "incident_id": iid})
    await HUB.send({"type": "incidents"})
    return inc

@api.post("/api/incidents/{iid}/entries")
async def add_entry(iid: int, request: Request):
    body = await request.json()
    kind = body.get("kind")
    if kind not in ENTRY_SCHEMAS:
        raise HTTPException(400, "Unknown entry type")
    me = auth(request, "chat" if kind == "message" else "entry.write")
    if iid != 0 and not inc_get(iid):
        raise HTTPException(404, "No such incident")
    if iid == 0 and kind != "message":
        raise HTTPException(400, "Only messages go to the team-wide channel")
    d = clean(body, ENTRY_SCHEMAS[kind])
    if d.get("privileged") and not can(me, "read.priv"):
        d["privileged"] = False
    required = {"timeline": "text", "task": "title", "scope": "name", "ioc": "value", "message": "text"}[kind]
    if not d.get(required):
        raise HTTPException(400, f"'{required}' is required")
    defaults = {"timeline": {"at": now_iso(), "privileged": False},
                "task": {"phase": "Detection", "done": False, "assignee": ""},
                "scope": {"status": "Unknown", "confidence": "Suspected", "data_types": [], "jurisdictions": []},
                "ioc": {"type": "Other"}, "message": {"urgent": False, "privileged": False}}[kind]
    e = {**defaults, **d, "incident_id": iid, "kind": kind, "author": me["display"],
         "author_id": me["id"], "author_role": ROLE_LABELS[me["role"]], "logged_at": now_iso()}
    if kind == "scope":
        e["status_history"] = [{"status": e["status"], "confidence": e["confidence"], "at": now_iso(), "by": me["display"]}]
    e = entry_save(e)
    audit(me["username"], f"{kind}.add", f"incident:{iid}", {"entry": e["id"]}, client_ip(request))
    await push_entry(e)
    if kind == "scope":
        await system_note(iid, f"Affected data added: {e['name']} — {e['status']} ({e['confidence']})", me["display"])
    if kind in ("scope", "task"):
        await HUB.send({"type": "incidents"})
    return e

@api.patch("/api/entries/{eid}")
async def patch_entry(eid: int, request: Request):
    e = entry_get(eid)
    if not e:
        raise HTTPException(404, "Not found")
    me = auth(request, "entry.write")
    if not visible(me, e):
        raise HTTPException(404, "Not found")
    if e["kind"] == "message":
        raise HTTPException(400, "Chat messages can't be edited (they're part of the record)")
    if e.get("is_system"):
        raise HTTPException(400, "System entries can't be edited")
    if e["kind"] == "evidence":
        raise HTTPException(400, "Evidence is immutable once logged")
    d = clean(await request.json(), ENTRY_SCHEMAS[e["kind"]])
    if e["kind"] == "scope" and "status" in d and d["status"] != e.get("status"):
        await system_note(e["incident_id"], f"Data '{e['name']}' status: {e.get('status')} → {d['status']} "
                                            f"(by {me['display']})", me["display"])
    if e["kind"] == "scope" and (d.get("status", e.get("status")) != e.get("status")
                                 or d.get("confidence", e.get("confidence")) != e.get("confidence")):
        e.setdefault("status_history", []).append({"status": d.get("status", e.get("status")),
                                                   "confidence": d.get("confidence", e.get("confidence")),
                                                   "at": now_iso(), "by": me["display"]})
    if e["kind"] == "task" and d.get("done") and not e.get("done"):
        d["done_by"] = me["display"]
        d["done_at"] = now_iso()
    if e["kind"] == "task" and d.get("done") is False:
        d["done_by"] = ""
        d["done_at"] = ""
    e.update(d)
    e["edited_by"] = me["display"]
    e["edited_at"] = now_iso()
    entry_save(e)
    audit(me["username"], f"{e['kind']}.update", f"entry:{eid}", {"fields": sorted(d)}, client_ip(request))
    await push_entry(e, "entry_update")
    await HUB.send({"type": "incidents"})
    return e

@api.get("/api/channel")
async def team_channel(request: Request):
    me = auth(request)
    return [e for e in entries_for(0, "message", 300) if visible(me, e)]

@api.get("/api/incidents/{iid}/export")
async def export_incident(iid: int, request: Request):
    me = auth(request)
    data = await get_incident(iid, request)
    audit(me["username"], "incident.export", data["incident"]["ref"], None, client_ip(request))
    data["exported_at"] = now_iso()
    data["exported_by"] = me["display"]
    data["audit_chain"] = audit_verify()
    return JSONResponse(data, headers={"content-disposition": f'attachment; filename="{data["incident"]["ref"]}.json"'})

# ---- evidence locker (encrypted files + chain of custody) ----
def safe_name(n):
    from urllib.parse import unquote
    n = unquote(n or "")[:200]
    n = "".join(ch for ch in n if ch.isalnum() or ch in " ._-()[]")
    return n.strip(" .") or "evidence.bin"

@api.post("/api/incidents/{iid}/evidence")
async def upload_evidence(iid: int, request: Request):
    me = auth(request, "entry.write")
    if not inc_get(iid):
        raise HTTPException(404, "No such incident")
    data = await request.body()
    if not data:
        raise HTTPException(400, "Empty file")
    if len(data) > MAX_UPLOAD:
        raise HTTPException(413, f"File too large (max {MAX_UPLOAD // 1024 // 1024} MB)")
    from urllib.parse import unquote
    name = safe_name(request.headers.get("x-filename"))
    desc = unquote(request.headers.get("x-description", ""))[:1000]
    collected = unquote(request.headers.get("x-collected-at", ""))[:40]
    digest = hashlib.sha256(data).hexdigest()
    nonce = os.urandom(12)
    sealed = nonce + V.aead.encrypt(nonce, data, f"file:{iid}:{digest}".encode())
    with S.lock:
        fid = S.db.execute("INSERT INTO files(incident_id, content) VALUES(?,?)", (iid, sealed)).lastrowid
    ip = client_ip(request)
    e = entry_save({"incident_id": iid, "kind": "evidence", "file_id": fid, "name": name, "size": len(data),
                    "sha256": digest, "description": desc, "collected_at": collected or None,
                    "author": me["display"], "author_id": me["id"], "logged_at": now_iso(),
                    "custody": [{"action": "Collected & sealed (SHA-256 recorded)", "by": me["display"],
                                 "at": now_iso(), "ip": ip}]})
    audit(me["username"], "evidence.upload", f"incident:{iid}", {"file": name, "sha256": digest}, ip)
    await push_entry(e)
    await system_note(iid, f"Evidence logged: {name} ({len(data):,} bytes, SHA-256 {digest[:16]}…)", me["display"])
    return e

@api.get("/api/evidence/{eid}")
async def download_evidence(eid: int, request: Request):
    me = auth(request, "entry.write")
    e = entry_get(eid)
    if not e or e["kind"] != "evidence":
        raise HTTPException(404, "Not found")
    r = S.db.execute("SELECT content FROM files WHERE id=?", (e["file_id"],)).fetchone()
    try:
        data = V.aead.decrypt(r[0][:12], r[0][12:], f"file:{e['incident_id']}:{e['sha256']}".encode())
    except (InvalidTag, TypeError):
        raise HTTPException(500, "Evidence integrity failure - stored file was altered")
    ok = hashlib.sha256(data).hexdigest() == e["sha256"]
    e["custody"].append({"action": "Downloaded" + (" - hash verified" if ok else " - HASH MISMATCH"),
                         "by": me["display"], "at": now_iso(), "ip": client_ip(request)})
    entry_save(e)
    audit(me["username"], "evidence.download", f"entry:{eid}", {"verified": ok}, client_ip(request))
    await push_entry(e, "entry_update")
    return Response(data, media_type="application/octet-stream", headers={
        "content-disposition": f'attachment; filename="{e["name"]}"',
        "content-security-policy": "sandbox; default-src 'none'", "x-sha256": e["sha256"]})

# ---- websocket ----
@api.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    origin = ws.headers.get("origin", "")
    host = ws.headers.get("host", "")
    if origin not in (f"https://{host}",):
        await ws.close(code=1008)
        return
    try:
        u, s, th = session_from(ws)
    except HTTPException:
        await ws.close(code=4001)
        return
    await ws.accept()
    HUB.conns[ws] = (u["id"], th)
    await HUB.send({"type": "presence", "online": HUB.presence()})
    try:
        while True:
            msg = await ws.receive_text()  # client only sends keep-alive pings
            if th not in SESSIONS:
                break
            if msg == "ping":
                await ws.send_text('{"type":"pong"}')
    except WebSocketDisconnect:
        pass
    finally:
        HUB.conns.pop(ws, None)
        await HUB.send({"type": "presence", "online": HUB.presence()})

api.mount("/static", StaticFiles(directory=STATIC), name="static")
app = Guard(api)

# ----------------------------------------------------------------------------
# TLS + bootstrap
# ----------------------------------------------------------------------------
CERT_FP = ""

def ensure_cert(d):
    global CERT_FP
    key_p, crt_p = os.path.join(d, "tls.key"), os.path.join(d, "tls.crt")
    if not os.path.exists(crt_p):
        key = ec.generate_private_key(ec.SECP384R1())
        names = [x509.DNSName("localhost"), x509.DNSName(socket.gethostname())]
        ips = {"127.0.0.1"}
        try:
            ips.add(socket.gethostbyname(socket.gethostname()))
        except OSError:
            pass
        names += [x509.IPAddress(ipaddress.ip_address(i)) for i in ips]
        subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "IRONROOM")])
        now = dt.datetime.now(dt.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(subj).issuer_name(subj)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=90))
                .add_extension(x509.SubjectAlternativeName(names), critical=False)
                .sign(key, hashes.SHA384()))
        fd = os.open(key_p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()))
        with open(crt_p, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
    cert = x509.load_pem_x509_certificate(open(crt_p, "rb").read())
    fp = cert.fingerprint(hashes.SHA256()).hex().upper()
    CERT_FP = ":".join(fp[i:i + 2] for i in range(0, len(fp), 2))
    return key_p, crt_p

def bootstrap(data_dir, passphrase, demo=False):
    global V, S
    os.makedirs(data_dir, mode=0o700, exist_ok=True)
    S = Store(os.path.join(data_dir, "ironroom.db"))
    salt = S.meta_get("salt")
    first = salt is None
    if first:
        salt = os.urandom(16)
        S.meta_set("salt", salt)
    V = Vault(passphrase, salt)
    chk = S.meta_get("check")
    if chk is None:
        S.meta_set("check", V.seal({"ok": 1}, "check"))
    else:
        try:
            V.open(chk, "check")
        except InvalidTag:
            sys.exit("\n[!] Wrong passphrase - the vault cannot be decrypted.\n")
    creds = []
    if not users_all():
        u, pw = new_user("admin", "Platform Administrator", "admin")
        creds.append((u, pw))
        audit("system", "bootstrap", "admin")
        if demo:
            for un, dn, role in [("ic.rivera", "Dana Rivera", "commander"),
                                 ("j.okafor", "James Okafor", "responder"),
                                 ("counsel.lee", "Morgan Lee (Outside Counsel)", "legal"),
                                 ("ceo.patel", "Priya Patel (CEO)", "viewer")]:
                creds.append(new_user(un, dn, role))
            seed_demo(creds[1][0])
    return creds

def seed_demo(ic):
    def ts_ago(h):
        return time.time() - h * 3600

    def ago(h):
        return (dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=h)).isoformat(timespec="seconds")
    inc = inc_save({"title": "Ransomware on file servers - Dallas office", "category": "Ransomware",
                    "severity": "SEV1", "phase": "Containment", "status": "Active",
                    "discovered_at": ago(30), "occurred_at": ago(52), "commander": ic["display"],
                    "created_by": ic["username"], "detection_source": "Help desk tickets: files renamed .lockbit",
                    "reported_by": "IT Help Desk", "attack_vector": "Suspected compromised VPN account (no MFA)",
                    "threat_actor": "Unknown - note claims LockBit affiliate",
                    "affected_systems": "FS01, FS02 (file servers), HR-APP01, ~40 workstations in Dallas office",
                    "summary": "Users reported encrypted files and ransom notes on shared drives. "
                               "Domain admin credentials likely compromised.",
                    "business_impact": "Dallas office cannot access client files. Billing system offline.",
                    "ransom_demand": "45 BTC, 7-day deadline", "counsel_engaged": True,
                    "insurer_notified": True, "updated": time.time(), "updated_by": ic["display"],
                    "history": [{"field": "phase", "from": None, "to": "Detection", "at": ago(29.5), "by": ic["display"]},
                                {"field": "severity", "from": None, "to": "SEV2", "at": ago(29.5), "by": ic["display"]},
                                {"field": "status", "from": None, "to": "Active", "at": ago(29.5), "by": ic["display"]},
                                {"field": "phase", "from": "Detection", "to": "Analysis", "at": ago(28), "by": ic["display"]},
                                {"field": "severity", "from": "SEV2", "to": "SEV1", "at": ago(27.2), "by": ic["display"]},
                                {"field": "phase", "from": "Analysis", "to": "Containment", "at": ago(26.5), "by": ic["display"]}]})
    inc["ref"] = f"IR-{dt.date.today().year}-{inc['id']:03d}"
    inc_save(inc)
    S.db.execute("UPDATE incidents SET created=? WHERE id=?", (time.time() - 29.5 * 3600, inc["id"]))
    done_phases = {"Detection", "Analysis"}
    for ph in PHASES:
        for i, t in enumerate(PLAYBOOK_COMMON.get(ph, []) + PLAYBOOK_EXTRA["Ransomware"].get(ph, [])):
            done = ph in done_phases and i < 4
            entry_save({"incident_id": inc["id"], "kind": "task", "title": t, "phase": ph,
                        "assignee": "James Okafor" if ph == "Containment" else "", "done": done,
                        "done_by": ic["display"] if done else "", "done_at": ago(29 - i - (2 if ph == "Analysis" else 0)) if done else "",
                        "author": "Playbook"})
    for h, txt, src, priv in [(52, "Earliest suspicious VPN login from 185.220.101.4 (user: svc-backup)", "VPN logs", False),
                              (30, "Help desk receives 12 tickets: files renamed with .lockbit extension", "Help desk", False),
                              (29, "Incident declared. Team moved to IRONROOM out-of-band system.", "IC", False),
                              (26, "FS01/FS02 disconnected from network", "J. Okafor", False),
                              (20, "Counsel engaged; forensics firm retained through counsel to preserve privilege", "Counsel", True)]:
        entry_save({"incident_id": inc["id"], "kind": "timeline", "at": ago(h), "text": txt,
                    "source": src, "privileged": priv, "author": ic["display"], "created": ts_ago(min(h, 29) - 0.05),
                    "logged_at": ago(min(h, 29) - 0.05)})
    for n, sysn, types, rec, st, conf, jur in [
        ("Client matter files", "FS01 \\\\clients", ["Customer data", "Attorney-client privileged"], 180000,
         "Encrypted (ransomware)", "Confirmed", ["TX", "CA"]),
        ("HR personnel records", "HR-APP01 database", ["PII", "Employee / HR", "Financial"], 2400,
         "Exfiltrated", "Likely", ["TX", "OK"]),
        ("Benefits enrollment exports", "FS02 \\\\hr\\benefits", ["PHI (health)", "PII"], 1900,
         "Accessed", "Suspected", ["TX"]),
        ("Billing system", "BILL-DB01", ["Financial", "PCI (card data)"], None, "Unknown", "Suspected", []),
    ]:
        hist = [{"status": "Unknown", "confidence": "Suspected", "at": ago(27), "by": ic["display"]}]
        if st != "Unknown":
            hist.append({"status": st, "confidence": conf, "at": ago(22 if st != "Exfiltrated" else 9), "by": "James Okafor"})
        entry_save({"incident_id": inc["id"], "kind": "scope", "name": n, "system": sysn,
                    "data_types": types, "records": rec, "status": st, "confidence": conf,
                    "jurisdictions": jur, "notes": "", "author": ic["display"], "logged_at": ago(27),
                    "status_history": hist})
    for t, v, note in [("IP address", "185.220.101.4", "VPN login source"),
                       ("File hash", "a3f5c9e1b2d4f6a8c0e2b4d6f8a0c2e4b6d8f0a2c4e6b8d0f2a4c6e8b0d2f4a6", "Encryptor binary (SHA-256)"),
                       ("User account", "svc-backup", "Compromised service account")]:
        entry_save({"incident_id": inc["id"], "kind": "ioc", "type": t, "value": v, "note": note,
                    "author": ic["display"], "created": ts_ago(27)})
    note = (b"~~~ LockBit 3.0 ~~~ Your data are stolen and encrypted.\n"
            b"[DEMO SAMPLE - not a real ransom note]\n")
    nonce = os.urandom(12)
    dg = hashlib.sha256(note).hexdigest()
    with S.lock:
        fid = S.db.execute("INSERT INTO files(incident_id, content) VALUES(?,?)",
                           (inc["id"], nonce + V.aead.encrypt(nonce, note, f"file:{inc['id']}:{dg}".encode()))).lastrowid
    entry_save({"incident_id": inc["id"], "kind": "evidence", "file_id": fid, "name": "ransom-note-FS01.txt",
                "size": len(note), "sha256": dg, "description": "Ransom note copied from \\\\FS01\\clients root",
                "collected_at": ago(29), "author": "James Okafor", "logged_at": ago(28.8),
                "custody": [{"action": "Collected & sealed (SHA-256 recorded)", "by": "James Okafor", "at": ago(28.8), "ip": "10.42.0.12"}]})
    for txt, urg, hh in [("All: do NOT use Teams or corporate email for anything about this incident.", True, 29.2),
                         ("FS01 and FS02 are isolated. Starting memory capture on HR-APP01.", False, 26)]:
        entry_save({"incident_id": inc["id"], "kind": "message", "text": txt, "urgent": urg, "created": ts_ago(hh),
                    "privileged": False, "author": ic["display"], "author_role": "Incident Commander"})


def main():
    global ALLOW_NETS
    ap = argparse.ArgumentParser(description="IRONROOM incident response command center")
    ap.add_argument("--host", default=os.environ.get("IRONROOM_HOST", "0.0.0.0"))
    ap.add_argument("--port", type=int, default=int(os.environ.get("IRONROOM_PORT", "8443")))
    ap.add_argument("--data", default=os.environ.get("IRONROOM_DATA", os.path.join(BASE, "vault")))
    ap.add_argument("--allow", default=os.environ.get("IRONROOM_ALLOW",
                    "127.0.0.0/8,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"),
                    help="Comma-separated CIDRs allowed to connect (lock to your out-of-band subnet)")
    ap.add_argument("--demo", action="store_true", help="Seed demo users + a sample ransomware incident")
    a = ap.parse_args()
    ALLOW_NETS = [ipaddress.ip_network(x.strip(), strict=False) for x in a.allow.split(",") if x.strip()]
    pp = os.environ.pop("IRONROOM_PASSPHRASE", None) or getpass.getpass("Vault passphrase: ")
    if len(pp) < 12:
        sys.exit("Passphrase must be at least 12 characters.")
    creds = bootstrap(a.data, pp, a.demo)
    del pp
    key_p, crt_p = ensure_cert(a.data)
    print("\n  IRONROOM  ·  out-of-band incident command center")
    print(f"  https://<this-machine>:{a.port}   (allowed networks: {a.allow})")
    print(f"  TLS fingerprint (verify in browser): \n  {CERT_FP}\n")
    for u, pw in creds:
        print(f"  ── first-run enrollment: {u['username']} ({ROLE_LABELS[u['role']]})")
        print(f"     temporary password : {pw}")
        print(f"     authenticator key  : {u['totp']}")
        if u["username"] == "admin":
            q = qrcode.QRCode(border=1)
            q.add_data(pyotp.TOTP(u["totp"]).provisioning_uri(u["username"], issuer_name="IRONROOM"))
            q.print_ascii(invert=True)
    if creds:
        print("  These are shown ONCE and are not stored in plain text anywhere.\n")
    uvicorn.run(app, host=a.host, port=a.port, ssl_keyfile=key_p, ssl_certfile=crt_p,
                server_header=False, log_level="warning", ws_ping_interval=20)


if __name__ == "__main__":
    main()
