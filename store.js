'use strict';
// Encrypted vault: the whole database lives in memory and is written to disk
// only as AES-256-GCM ciphertext. The key comes from a passphrase given at
// startup and is never stored. If someone takes the disk, they get noise.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const C = require('./crypto');

const MAGIC = Buffer.from('LBV1');

function emptyState() {
  return {
    meta: { createdAt: new Date().toISOString(), schema: 1, incidentSeq: 0 },
    org: {
      name: 'Your Organization',
      publiclyTraded: false,
      hipaaCovered: false,
      nydfsRegulated: false,
      criticalInfrastructure: false,
      insurance: { carrier: '', policy: '', hotline: '', noticeHours: 72 },
      outsideCounsel: { firm: '', contact: '', phone: '' },
      contacts: [],
    },
    lockdown: { on: false, by: null, at: null },
    users: [],
    incidents: [],
    channels: [],
    messages: [],
    audit: [],
  };
}

class Vault {
  constructor(dir) {
    this.dir = dir;
    this.file = path.join(dir, 'vault.lbv');
    this.evidenceDir = path.join(dir, 'evidence');
    this.state = null;
    this.key = null;
    this._timer = null;
  }

  exists() {
    return fs.existsSync(this.file);
  }

  open(passphrase) {
    if (!passphrase || passphrase.length < 12) throw new Error('Vault passphrase must be at least 12 characters.');
    fs.mkdirSync(this.evidenceDir, { recursive: true, mode: 0o700 });
    if (this.exists()) {
      const raw = fs.readFileSync(this.file);
      if (!raw.subarray(0, 4).equals(MAGIC)) throw new Error('Not a Lifeboat vault file.');
      const salt = raw.subarray(4, 20);
      this.salt = salt;
      this.key = C.deriveVaultKey(passphrase, salt);
      let plain;
      try {
        plain = C.decrypt(C.subKey(this.key, 'vault'), raw.subarray(20), MAGIC);
      } catch {
        this.key = null;
        throw new Error('Wrong passphrase, or the vault file has been tampered with.');
      }
      this.state = JSON.parse(plain.toString('utf8'));
    } else {
      this.salt = crypto.randomBytes(16);
      this.key = C.deriveVaultKey(passphrase, this.salt);
      this.state = emptyState();
      this.flush();
    }
    this.auditKey = C.subKey(this.key, 'audit');
    this.evidenceKey = C.subKey(this.key, 'evidence');
    return this;
  }

  /** Atomic write: encrypt -> temp file -> fsync -> rename. Never leaves a half-written vault. */
  flush() {
    clearTimeout(this._timer);
    this._timer = null;
    const plain = Buffer.from(JSON.stringify(this.state));
    const blob = Buffer.concat([MAGIC, this.salt, C.encrypt(C.subKey(this.key, 'vault'), plain, MAGIC)]);
    const tmp = this.file + '.tmp';
    const fd = fs.openSync(tmp, 'w', 0o600);
    fs.writeSync(fd, blob);
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fs.renameSync(tmp, this.file);
  }

  save() {
    if (!this._timer) this._timer = setTimeout(() => this.flush(), 150);
  }

  // ---------- Tamper-evident audit chain ----------
  // Each entry is HMAC'd together with the previous entry's hash. Editing,
  // deleting or reordering any record breaks every hash after it.
  audit(actor, action, target = null, detail = null) {
    const log = this.state.audit;
    const prev = log.length ? log[log.length - 1].hash : 'GENESIS';
    const entry = {
      seq: log.length + 1,
      at: new Date().toISOString(),
      actor: actor ? { id: actor.id, name: actor.displayName || actor.username } : { id: null, name: 'system' },
      action,
      target,
      detail,
      prev,
    };
    entry.hash = C.hmac(this.auditKey, prev + JSON.stringify([entry.seq, entry.at, entry.actor, entry.action, entry.target, entry.detail]));
    log.push(entry);
    this.save();
    return entry;
  }

  verifyAudit() {
    let prev = 'GENESIS';
    for (const e of this.state.audit) {
      const expect = C.hmac(this.auditKey, prev + JSON.stringify([e.seq, e.at, e.actor, e.action, e.target, e.detail]));
      if (e.prev !== prev || e.hash !== expect) return { ok: false, brokenAt: e.seq, total: this.state.audit.length };
      prev = e.hash;
    }
    return { ok: true, total: this.state.audit.length, head: prev };
  }

  // ---------- Evidence locker (each file encrypted separately) ----------
  writeEvidence(id, buf) {
    const blob = C.encrypt(this.evidenceKey, buf, id);
    fs.writeFileSync(path.join(this.evidenceDir, id + '.bin'), blob, { mode: 0o600 });
  }

  readEvidence(id) {
    if (!/^[A-Za-z0-9_-]+$/.test(id)) throw new Error('bad id');
    const blob = fs.readFileSync(path.join(this.evidenceDir, id + '.bin'));
    return C.decrypt(this.evidenceKey, blob, id);
  }
}

module.exports = { Vault };
