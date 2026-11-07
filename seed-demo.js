#!/usr/bin/env node
'use strict';
// Builds a realistic demo vault: a Texas medical group mid-way through a ransomware attack.
// Usage: LIFEBOAT_PASSPHRASE='…' node scripts/seed-demo.js [--force]
const fs = require('node:fs');
const path = require('node:path');
const C = require('../lib/crypto');
const { Vault } = require('../lib/store');
const PB = require('../lib/playbooks');

const DATA_DIR = path.resolve(process.env.LIFEBOAT_DATA || path.join(__dirname, '..', 'data'));
const pass = process.env.LIFEBOAT_PASSPHRASE;
if (!pass) { console.error('Set LIFEBOAT_PASSPHRASE first (12+ characters).'); process.exit(1); }
const vaultFile = path.join(DATA_DIR, 'vault.lbv');
if (fs.existsSync(vaultFile)) {
  if (!process.argv.includes('--force')) { console.error(`A vault already exists at ${vaultFile}. Re-run with --force to replace it.`); process.exit(1); }
  fs.rmSync(vaultFile);
  fs.rmSync(path.join(DATA_DIR, 'evidence'), { recursive: true, force: true });
}

const v = new Vault(DATA_DIR).open(pass);
const st = v.state;
const T = Date.now();
const ago = (h) => new Date(T - h * 3600e3).toISOString();
const id = C.randomId;

// ---------- people
const DEMO_PASSWORD = 'lifeboat-demo-2026';
const people = [
  ['alex', 'Alex Rivera', 'admin', 'IT Director', '(512) 555-0142'],
  ['jordan', 'Jordan Patel', 'commander', 'CISO', '(512) 555-0117'],
  ['sam', 'Sam Okafor', 'responder', 'Sr. Security Engineer', '(512) 555-0188'],
  ['dana', 'Dana Whitfield', 'counsel', 'General Counsel', '(512) 555-0163'],
  ['morgan', 'Morgan Lee', 'observer', 'Chief Executive Officer', '(512) 555-0101'],
];
const passHash = C.hashPassword(DEMO_PASSWORD);
const U = {};
for (const [username, displayName, role, title, phone] of people) {
  const totpSecret = C.base32Encode(Buffer.from(C.sha256('lifeboat-demo:' + username), 'hex').subarray(0, 20));
  U[username] = { id: id('u_'), username, displayName, role, title, phone, status: 'active', passHash, totpSecret, lastTotpStep: -1, createdAt: ago(24 * 40), lastLogin: ago(2) };
  st.users.push(U[username]);
}
st.users.push({ id: id('u_'), username: 'priya', displayName: 'Priya Shah', role: 'responder', title: 'Network Engineer', phone: '', status: 'invited', inviteHash: C.sha256('DEMOINVITECODE1'), inviteExpires: T + 48 * 3600e3, createdAt: ago(3) });

// ---------- organization
Object.assign(st.org, {
  name: 'Brazos Valley Medical Group',
  publiclyTraded: false, hipaaCovered: true, nydfsRegulated: false, criticalInfrastructure: false,
  insurance: { carrier: 'Lone Star Mutual Cyber', policy: 'CYB-2209-4471', hotline: '(800) 555-0199', noticeHours: 48 },
  outsideCounsel: { firm: 'Hale & Ridley LLP', contact: 'Catherine Hale', phone: '(214) 555-0130' },
  contacts: [
    { id: id('p_'), name: 'SA Marcus Bell', group: 'Law enforcement', role: 'FBI San Antonio, cyber squad', org: 'FBI', phone: '(210) 555-0170', alt: '', notes: 'Met at InfraGard. Call for ransomware/BEC.' },
    { id: id('p_'), name: 'Northgate DFIR hotline', group: 'Forensics / DFIR', role: '24/7 incident response retainer', org: 'Northgate Forensics', phone: '(888) 555-0110', alt: '', notes: 'Retainer #NG-55-1192. Carrier-approved panel vendor.' },
    { id: id('p_'), name: 'Frost Regional Bank fraud desk', group: 'Banking', role: 'Wire recall / account freeze', org: 'Frost Regional', phone: '(800) 555-0155', alt: '', notes: 'Ask for treasury fraud. Have wire reference ready.' },
    { id: id('p_'), name: 'Elena Ortiz', group: 'PR / Comms', role: 'Crisis communications', org: 'Bluebonnet Strategies', phone: '(512) 555-0124', alt: '(512) 555-0125', notes: 'No statements before counsel review.' },
    { id: id('p_'), name: 'Dr. Ruth Alvarez', group: 'Leadership', role: 'Chief Medical Officer', org: 'BVMG', phone: '(979) 555-0148', alt: '', notes: 'Patient-care impact decisions' },
  ],
});

// ---------- general channel
const general = { id: id('c_'), name: 'command', kind: 'general', createdAt: ago(24 * 40) };
const legal = { id: id('c_'), name: 'legal-privileged', kind: 'custom', members: [U.dana.id, U.jordan.id, U.morgan.id], createdBy: U.dana.id, createdAt: ago(20) };
st.channels.push(general, legal);

function incident(o) {
  st.meta.incidentSeq++;
  const inc = {
    id: id('i_'), ref: `IR-2026-${String(st.meta.incidentSeq).padStart(4, '0')}`, privileged: true, access: 'all', members: [],
    occurredAt: null, containedAt: null, breachDeterminedAt: null, materialityDeterminedAt: null, affectedSystems: [], attackVector: '',
    timeline: [], tasks: [], iocs: [], scope: [], evidence: [], notifications: {}, version: 1, createdAt: o.detectedAt, updatedAt: ago(0.2), ...o,
  };
  for (const t of PB.tasksFor(inc.category)) inc.tasks.push({ id: id('k_'), title: t.title, phase: t.phase, status: 'open', assigneeId: null, due: null, createdBy: null, createdAt: inc.createdAt, playbook: true });
  const ch = { id: id('c_'), name: inc.codename.toLowerCase().replace(/\s+/g, '-'), kind: 'incident', incidentId: inc.id, createdAt: inc.createdAt };
  st.channels.push(ch);
  st.incidents.push(inc);
  inc._ch = ch;
  return inc;
}
const tl = (inc, h, by, kind, text) => inc.tasks && inc.timeline.push({ id: id('t_'), at: ago(h), loggedAt: ago(Math.max(0, h - 0.05)), by: by?.id || null, kind, text });
const done = (inc, match, by, h, assignee) => { const t = inc.tasks.find((x) => x.title.startsWith(match)); if (t) Object.assign(t, h == null ? { assigneeId: (assignee || by).id } : { status: 'done', doneAt: ago(h), doneBy: by.id, assigneeId: by.id }); };
const msg = (ch, h, by, text, urgent = false, acks = []) => st.messages.push({ id: id('m_'), channelId: ch.id, userId: by?.id || null, text, at: ago(h), urgent, acks: Object.fromEntries((urgent && by ? [by, ...acks] : acks).map((u) => [u.id, ago(h - 0.1)])) });

// ======================= INCIDENT 1: ransomware, SEV1
const r = incident({
  codename: 'BLACK HERON', title: 'Ransomware encrypted EHR file servers; ransom note on clinic workstations', severity: 1, category: 'ransomware', status: 'containment',
  detectedAt: ago(26), occurredAt: ago(26 + 24 * 6), leadId: U.jordan.id, createdBy: U.sam.id,
  summary: 'At 02:10 local, night staff at the College Station clinic reported workstations showing a ransom note ("BlackSuit"). File servers FS01/FS02 hosting scanned patient records and billing exports are encrypted. The threat actor claims 400 GB was exfiltrated and has posted a sample on their leak site. Clinics are on paper downtime procedures. EHR (cloud-hosted) is unaffected so far.',
  attackVector: 'Compromised VPN account (former contractor, no MFA) → RDP lateral movement',
  affectedSystems: ['FS01 (file server)', 'FS02 (file server)', 'BKUP-01 (backup server)', '41 clinic workstations', 'DC02 (domain controller)'],
  breachDeterminedAt: ago(5),
});
tl(r, 26, U.sam, 'finding', 'Night charge nurse called IT on-call: ransom note on 6 workstations at College Station clinic');
tl(r, 25.9, U.sam, 'system', 'Incident declared by Sam Okafor: Ransomware encrypted EHR file servers');
tl(r, 25.6, U.sam, 'action', 'Disconnected College Station and Bryan clinic switches from WAN');
tl(r, 25.2, U.jordan, 'decision', 'Jordan Patel assumed Incident Commander. All response comms moved to LIFEBOAT; corporate email treated as compromised');
tl(r, 24.8, U.alex, 'action', 'Disabled all VPN accounts except break-glass; forced global password reset queued');
tl(r, 24.1, U.dana, 'decision', 'Engaged Hale & Ridley LLP as breach counsel; Northgate DFIR retained through counsel to preserve privilege');
tl(r, 23.5, U.dana, 'comms', 'Notified Lone Star Mutual Cyber (claim #LSM-88412). Carrier approved Northgate as panel vendor');
tl(r, 22.0, U.sam, 'finding', 'Ransom note identifies BlackSuit. Encrypted extension .blacksuit. Leak-site post claims 400 GB including "patients" folder');
tl(r, 19.4, U.sam, 'finding', 'EDR shows initial VPN login from 185.220.101.4 using account c.martin (contractor, offboarded in June, never disabled)');
tl(r, 16.0, U.alex, 'action', 'Backups on BKUP-01 partially encrypted; offline tape set from Oct 31 confirmed intact');
tl(r, 12.5, U.sam, 'finding', 'Rclone transfer logs found on FS02: ~380 GB uploaded to mega[.]nz between Nov 3 and Nov 5');
tl(r, 9.0, U.jordan, 'action', 'Blocked C2 domains and IPs at the firewall (see Indicators)');
tl(r, 5.0, U.dana, 'decision', 'Counsel determination: reportable breach of PHI. HIPAA and Texas notification clocks confirmed');
tl(r, 3.0, U.morgan, 'decision', 'CEO: no contact with threat actor; ransom payment not authorized pending OFAC review and counsel advice');
tl(r, 1.2, U.sam, 'action', 'Northgate began imaging DC02 and FS02 memory');
for (const [m, by, h] of [['Assign an Incident Commander', U.jordan, 25], ['Engage legal counsel', U.dana, 24], ['Move all response communications', U.jordan, 25], ['Notify cyber insurance', U.dana, 23.5],
  ['Photograph the ransom note', U.sam, 25.5], ['Identify the ransomware strain', U.sam, 22], ['Check whether data was exfiltrated', U.sam, 12.5], ['Record first-known indicators', U.sam, 19],
  ['Isolate infected hosts', U.alex, 25.6], ['Block known C2', U.jordan, 9]]) done(r, m, by, h);
done(r, 'Disable or segment backups', U.alex, null);
done(r, 'Preserve volatile evidence', U.sam, null);
done(r, 'Reset credentials', U.alex, null);
const rb = r.tasks.find((t) => t.title.startsWith('Reset credentials')); if (rb) rb.status = 'doing';
const pv = r.tasks.find((t) => t.title.startsWith('Preserve volatile')); if (pv) pv.status = 'doing';
r.tasks.push({ id: id('k_'), title: 'Confirm whether cloud EHR (Epic hosted) sessions were accessed from compromised hosts', phase: 'containment', status: 'blocked', assigneeId: U.sam.id, due: ago(-6), createdBy: U.jordan.id, createdAt: ago(8) });
r.tasks.push({ id: id('k_'), title: 'Draft patient notification letter for counsel review', phase: 'post', status: 'open', assigneeId: U.dana.id, due: ago(-24 * 5), createdBy: U.dana.id, createdAt: ago(4) });

const scope = (o) => ({ id: id('d_'), createdBy: U.sam.id, createdAt: ago(o.h || 10), updatedBy: o.by?.id || U.sam.id, updatedAt: ago(o.u ?? 3), history: [{ at: ago(o.h || 10), by: U.sam.id, status: o.status, confidence: o.confidence }], notes: '', system: '', ...o, h: undefined, u: undefined, by: undefined });
r.scope.push(
  scope({ asset: 'Scanned patient intake forms & records', system: 'FS02 \\\\clinical\\scans', dataTypes: ['phi', 'pii'], records: 18400, residents: { TX: 18110, LA: 214, OK: 61, EU: 15 }, status: 'exfiltrated', confidence: 'confirmed', notes: 'Rclone logs + leak-site sample matches. Includes DOB, SSN on ~40% of forms.', h: 12 }),
  scope({ asset: 'Billing exports (claims, insurance IDs)', system: 'FS01 \\\\finance\\billing', dataTypes: ['phi', 'financial'], records: 9200, residents: { TX: 9050, LA: 150 }, status: 'encrypted', confidence: 'confirmed', notes: 'Exfil not yet confirmed. Northgate reviewing egress logs.', h: 20 }),
  scope({ asset: 'Employee HR files', system: 'FS01 \\\\hr', dataTypes: ['employee', 'pii'], records: 312, residents: { TX: 312 }, status: 'accessed', confidence: 'suspected', h: 9 }),
  scope({ asset: 'Backup catalog (BKUP-01)', system: 'BKUP-01', dataTypes: ['operational'], records: 0, residents: {}, status: 'restored', confidence: 'confirmed', notes: 'Offline tapes from Oct 31 verified', h: 16, by: U.alex }),
);
r.iocs.push(...[
  ['ip', '185.220.101.4', 'Initial VPN login (Tor exit)'], ['ip', '45.153.160.140', 'Cobalt Strike beacon C2'], ['domain', 'update-msedge-cdn.com', 'C2 domain'],
  ['domain', 'mega.nz', 'Exfiltration destination (rclone)'], ['hash', 'a3f5c1b2e4d6f7890123456789abcdef0123456789abcdef0123456789abcdef', 'Encryptor binary (svchost32.exe)'],
  ['file', 'svchost32.exe', 'Dropped in C:\\ProgramData'], ['account', 'c.martin', 'Compromised contractor VPN account'], ['email', 'blacksuit_support@onionmail.org', 'Contact address in ransom note'],
].map(([type, value, note]) => ({ id: id('o_'), type, value, note, by: U.sam.id, at: ago(18) })));

const note = Buffer.from('YOUR NETWORK HAS BEEN COMPROMISED\n\nAll your files are encrypted. We have downloaded 400GB of your data.\nContact us at blacksuit_support@onionmail.org within 72 hours.\n(Demo artifact for LIFEBOAT. Not a real ransom note.)\n');
const evId = id('e_');
v.writeEvidence(evId, note);
r.evidence.push({ id: evId, kind: 'file', name: 'ransom_note_COLLEGE-STN-WS14.txt', size: note.length, sha256: C.sha256(note), note: 'Copied from desktop of WS14 by S. Okafor', location: 'LIFEBOAT encrypted locker', collectedBy: U.sam.id, collectedAt: ago(25.4), custody: [{ at: ago(25.4), by: U.sam.id, action: `Uploaded & hashed (SHA-256 ${C.sha256(note).slice(0, 16)}…)` }] });
r.evidence.push({ id: id('e_'), kind: 'item', name: 'DC02 domain controller: forensic image (2 TB)', size: null, sha256: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08', note: 'Imaged with FTK Imager 4.7', location: 'Evidence safe, IT room 2B, bag #0007', collectedBy: U.alex.id, collectedAt: ago(10), custody: [
  { at: ago(10), by: U.alex.id, action: 'Logged into custody at Evidence safe, IT room 2B, bag #0007' },
  { at: ago(1.2), by: U.sam.id, action: 'Released to Northgate examiner R. Kim for analysis (signed form NG-CoC-118)' },
] });
r.notifications.insurance = { status: 'done', notes: 'Claim #LSM-88412, adjuster T. Burns', updatedBy: U.dana.id, updatedAt: ago(23.5), doneAt: ago(23.5) };
r.notifications.fbi = { status: 'in-progress', notes: 'Left voicemail for SA Bell; IC3 complaint drafted', updatedBy: U.jordan.id, updatedAt: ago(6) };

msg(r._ch, 25.9, null, `🚨 ${r.ref} "${r.codename}" declared at SEV1. This is the incident room.`, true);
msg(r._ch, 25.5, U.sam, 'Isolating College Station + Bryan now. Do NOT power anything off. Leave machines on for memory capture.');
msg(r._ch, 25.1, U.jordan, 'I have command. Assume email and Teams are compromised. Everything goes through LIFEBOAT or phone from here.', true, [U.sam, U.alex, U.dana, U.morgan]);
msg(r._ch, 24.0, U.dana, 'Hale & Ridley engaged. Northgate will be retained through counsel. Please mark analysis "prepared at direction of counsel".');
msg(r._ch, 12.4, U.sam, 'Confirmed exfil: rclone to mega.nz, ~380GB, Nov 3-5. Adding to Scope now.');
msg(r._ch, 4.8, U.dana, 'Breach determination recorded. Texas AG notice is due within 30 days (>250 Texans). LIFEBOAT has the clock running.');
msg(r._ch, 0.6, U.jordan, 'All hands: 15:00 UTC bridge call is cancelled. Updates in this room only. Acknowledge please.', true, [U.sam]);

msg(general, 30, U.alex, 'Quarterly LIFEBOAT drill complete. Everyone confirmed MFA works. Thanks all.');
msg(general, 25.8, null, 'BLACK HERON (SEV1) has been declared. Responders join #black-heron.');
msg(legal, 4.5, U.dana, 'Morgan: per OFAC guidance we cannot evaluate any payment until attribution is confirmed against the SDN list. Recommend no contact with the actor.');
msg(legal, 3.1, U.morgan, 'Understood. No contact, no payment. Please prep a board briefing for tomorrow 9am.');

// ======================= INCIDENT 2: BEC, SEV2
const b = incident({
  codename: 'SILVER SPARROW', title: 'Vendor email compromise: $184,500 wire sent to fraudulent account', severity: 2, category: 'bec', status: 'triage',
  detectedAt: ago(3.2), leadId: U.jordan.id, createdBy: U.jordan.id, access: 'restricted', members: [U.dana.id, U.alex.id],
  summary: 'Accounts payable paid a "new bank details" invoice from our medical-supply vendor. Vendor confirmed by phone they never changed accounts. Need-to-know restricted: AP mailbox may be compromised internally.',
  attackVector: 'Lookalike domain medsupp1y-tx.com spoofing vendor; possible AP mailbox rule',
});
tl(b, 3.2, U.jordan, 'system', 'Incident declared by Jordan Patel: Vendor email compromise, $184,500 wire');
tl(b, 3.0, U.jordan, 'action', 'Called Frost Regional fraud desk. Recall request #FR-22981 filed');
tl(b, 2.4, U.alex, 'finding', 'Inbox rule on ap@ mailbox forwarding "invoice" emails to external Gmail address');
done(b, 'Call the bank fraud line', U.jordan, 3);
done(b, 'File IC3 complaint', U.jordan, null);
b.iocs.push({ id: id('o_'), type: 'domain', value: 'medsupp1y-tx.com', note: 'Lookalike vendor domain', by: U.alex.id, at: ago(2.5) });
b.iocs.push({ id: id('o_'), type: 'email', value: 'ap.forward.archive@gmail.com', note: 'Forwarding rule destination', by: U.alex.id, at: ago(2.4) });
msg(b._ch, 3.2, null, `🚨 ${b.ref} "${b.codename}" declared at SEV2. This is the incident room.`, true);
msg(b._ch, 2.9, U.jordan, 'Recall filed with Frost. They say first 72h matter most. Dana, can you loop in Hale & Ridley?');

// ======================= INCIDENT 3: closed phishing
const p = incident({
  codename: 'COPPER LANTERN', title: 'Phishing click: credential harvest page (no compromise)', severity: 4, category: 'malware', status: 'closed',
  detectedAt: ago(24 * 19), closedAt: ago(24 * 18), containedAt: ago(24 * 19 - 2), leadId: U.sam.id, createdBy: U.sam.id, privileged: false,
  summary: 'Two staff clicked a fake Microsoft 365 login link. One entered credentials; MFA blocked the sign-in. Password reset, domain blocked.',
});
tl(p, 24 * 19, U.sam, 'system', 'Incident declared by Sam Okafor');
tl(p, 24 * 19 - 1, U.sam, 'action', 'Reset password for affected user; MFA logs show blocked sign-in from 102.88.x.x');
tl(p, 24 * 18, U.sam, 'decision', 'Closed: no compromise. Lesson: report-phish button adoption');
for (const t of p.tasks) Object.assign(t, { status: 'done', doneAt: ago(24 * 18), doneBy: U.sam.id });

for (const inc of st.incidents) { inc.timeline.sort((a, b2) => a.at.localeCompare(b2.at)); delete inc._ch; }
st.messages.sort((a, b2) => a.at.localeCompare(b2.at));

v.audit(null, 'system.seed_demo', null, { incidents: st.incidents.length });
for (const inc of st.incidents) v.audit({ id: inc.createdBy, displayName: st.users.find((x) => x.id === inc.createdBy).displayName }, 'incident.create', inc.ref, { title: inc.title });
v.flush();

if (require.main === module || process.argv[1]?.endsWith('lifeboat.js') && !process.env.LIFEBOAT_QUIET) {
console.log('\nDemo vault created: Brazos Valley Medical Group\n');
console.log(`All demo accounts use the password:  ${DEMO_PASSWORD}\n`);
console.log('  username   role                    TOTP secret (add to an authenticator app, or run: node lifeboat.js totp SECRET)');
for (const [username, , role] of people) console.log(`  ${username.padEnd(10)} ${role.padEnd(23)} ${U[username].totpSecret}`);
console.log('\nStart the server with the same passphrase: node lifeboat.js  (or npm start)\n');
}
