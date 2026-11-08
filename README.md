# WINDX: Out-of-Band Cyber Incident Command

> When the attacker is inside your network, you don't run the response from inside it. You move to WINDX.

WINDX is a self-contained command center for running a cyber incident while the attacker is still inside your network. It runs on one isolated machine, needs nothing from your corporate IT (no Active Directory, no email, no cloud, no internet), and is built so a stressed team can use it with zero training.

**Zero third-party dependencies.** No npm packages, no CDNs, no web fonts, no analytics. About 4,000 lines of code you can audit in an afternoon, running on the Node.js standard library.

---

## Quick start (2 minutes)

Requires **Node.js 20+** and OpenSSL (for the HTTPS certificate).

```bash
cd WINDX
npm run cert            # creates a TLS certificate and prints its fingerprint
npm start               # asks you to create a vault passphrase, prints an admin invite code
```

Open **https://localhost:8443**, choose **"I have an invite code"**, and enter the username `admin` and the code from the console. Pick a password, scan the QR code with any authenticator app, and you're in.

### Demo mode (pre-loaded scenario)

Fastest way: `npm run quickstart`, then open http://127.0.0.1:8443. It loads the demo, prints each person's 6-digit code every 30 seconds, and starts the server.

Or step by step:

```bash
LIFEBOAT_PASSPHRASE='correct horse battery staple' npm run demo -- --force
LIFEBOAT_PASSPHRASE='correct horse battery staple' npm start
```

This loads **Brazos Valley Medical Group** in the middle of a BlackSuit ransomware attack: patient data exfiltrated, Texas AG / HIPAA / GDPR clocks running, a parallel wire-fraud incident restricted to need-to-know, evidence in custody, and live chat. All demo users share the password `lifeboat-demo-2026`. The seeder prints each user's TOTP secret: add it to an authenticator app, or get the current code with `npm run totp -- <SECRET>`.

| user | role | try this |
|---|---|---|
| `jordan` | Incident Commander | Run the incident, move phases, close it |
| `sam` | Responder | Log, scope, evidence, tasks |
| `dana` | Legal Counsel | Mark notifications done, breach determination |
| `morgan` | Executive (read-only) | See the wallboard; cannot change anything |
| `alex` | Administrator | Invite people, lockdown, audit verification |

Run the test suite with `npm test` (18 security and behaviour tests).

---

## How it maps to the challenge

### 1. Highly secure, isolated system
| Threat (attacker owns the internal network) | WINDX's answer |
|---|---|
| Attacker reads email / Teams / Slack | All response comms happen inside WINDX. Invite codes are given **in person or by phone**, never email. |
| Attacker controls Active Directory / SSO | WINDX has its own accounts: **scrypt** password hashing plus **mandatory TOTP two-factor** for every user. No AD, no SSO, no LDAP. |
| Attacker sniffs or MITMs the network | HTTPS only on any network interface (the server **refuses** to start plain HTTP off-loopback). The cert fingerprint is printed at startup so the team can verify it. |
| Attacker steals the laptop or disk | All data is in an **AES-256-GCM encrypted vault**. The key is derived (scrypt, N=2^17) from a passphrase typed at startup and **never written to disk**. Each evidence file is encrypted separately. |
| Attacker compromises a responder's account | **Lockdown** button kicks every non-admin out instantly. Admins see every **live session with its IP and device** and can revoke it. Accounts lock after 5 failed attempts. Sessions expire after 30 min idle and 12 h total. |
| Attacker tampers with the record to cover tracks | **HMAC-chained audit log**. Change, delete or reorder any entry and "Verify integrity" names the exact entry that was altered. |
| Insider threat | **Need-to-know incidents**: invisible (404) to everyone except named members, including their chat room. |
| Supply-chain attack via a library | There are **no libraries**. Even the QR-code generator for MFA enrollment is written in-house. |
| XSS, CSRF, clickjacking | Strict CSP (`script-src 'self'`, no inline code), auto-escaping templates, SameSite=Strict cookies + per-session CSRF token + origin check, `frame-ancestors 'none'`. |
| Spoliation claims | **Legal hold by design**: nothing is ever deleted, only "struck" with name and time. |

**Recommended deployment:** a dedicated laptop or mini-PC that is *not* domain-joined, on its own LTE/5G hotspot. Responders connect from phones or clean devices. Keep a printed card with the URL, the cert fingerprint and the emergency phone tree. Take an encrypted backup (Admin → Security & system) offsite.

### 2. Access control
- Admin invites people with a **one-time, 72-hour, single-use code** (only its hash is stored).
- Five roles: **Administrator, Incident Commander, Responder, Legal Counsel, Executive (read-only)**. Permissions are enforced server-side on every request.
- Lost phone? **Reset** wipes password + MFA, kills all their sessions and issues a new code.

### 3. Incident documentation (NIST SP 800-61 aligned)
- **Declare in 20 seconds**: one sentence, pick a type, pick severity. The matching **playbook checklist** loads automatically (ransomware, BEC, exfiltration, insider, DDoS, lost device…).
- **Five-phase lifecycle**: Detect & Analyze → Contain → Eradicate → Recover → Post-Incident, with a "Next up" panel that always shows what to do now.
- **Scribe bar**: type what happened and press Enter. It is timestamped in UTC, categorized (action / finding / decision / comms) and can be backdated. This becomes the forensic timeline.
- Key facts (discovery, first attacker activity, containment, entry point, affected systems), **indicators of compromise** (paste a messy list; it auto-classifies and fixes defanged values), and an **evidence locker** with SHA-256 hashing and **chain of custody**.
- **Real-time**: every screen updates live over Server-Sent Events. A T+ clock runs from detection.

### 4. Scope definitions
For every affected data set record **what** it is, **where** it lives, **what kinds of data** (PII, PHI, card, credentials, privileged…), **how many records**, **where the people live**, and its **state**:
`Encrypted (ransomware) · Exfiltrated · Accessed · Deleted · Altered · At risk · Secured · Restored`, each with confidence `Confirmed / Suspected / Ruled out` and a full change history.

### 5. Communications
- A general channel, an automatic **incident room** per incident, and private channels (e.g. `#legal-privileged`).
- **URGENT messages need an acknowledgment**: you see who has seen it and who hasn't ("waiting on Sam, Dana"). Unacknowledged alerts follow you on every screen.
- **Presence**: see who is online right now.
- **Emergency contacts / phone tree**: the out-of-band list you need at 2 a.m. (FBI, insurer hotline, DFIR firm, bank fraud desk), printable.

---

## Beyond the brief (creativity)

- **Breach-notification deadline engine.** From the scope data and org profile, WINDX works out who must be notified and **counts down every deadline**: Texas AG (30 days, 250+ Texans), Texas/Florida/NY/CO/WA/CA residents, GDPR 72 h, HIPAA individuals/HHS/media, SEC 8-K (4 business days after materiality), NYDFS 72 h, CIRCIA, PCI, cyber-insurance notice, OFAC screening before any ransom payment, and ABA Op. 483 for law firms. Adding a data set that crosses a threshold pops up **"3 new notification obligations triggered."**
- **Attorney-client privilege by default.** Incidents are marked *Privileged & Confidential, prepared at the direction of counsel*, and the banner carries through to every screen and the printed report.
- **Codenames** ("BLACK HERON") so conversations don't reveal the target if anyone is listening.
- **One-click SITREP**: a status update you can read out on a bridge call or post to the room.
- **Court-ready incident report**: summary, scope, obligations, timeline, IOCs, evidence and custody, ready to print or save as PDF.
- **Wallboard mode** for the war-room TV with big clocks and live deadlines.
- ⌨**Ctrl+K command palette**, keyboard shortcuts (`D` declare, `/` log, `?` help), light/dark theme, works on a phone.
- **Security posture page** that shows the controls in place, for auditors and judges.

---

## Architecture

```
server.js            HTTP(S) server, routing, auth, permissions, realtime (SSE)
lib/crypto.js        scrypt, TOTP (RFC 6238), AES-256-GCM, HKDF, invite codes
lib/store.js         encrypted vault, atomic writes, HMAC audit chain, evidence locker
lib/regulations.js   notification obligation engine
lib/playbooks.js     phases, incident types, checklists, codenames
lib/qr.js            QR-code encoder for MFA enrollment (no dependency)
public/              single-page app: vanilla JS, safe templating, no build step
  core.js            safe HTML templating, API client, live updates, shared UI pieces
  app.js             every screen: incidents, legal deadlines, comms, Team & Access, Lockdown
  assistant.js       Response Assistant (offline help chat)
  replay.js          Attack Replay chart on the Wallboard
test/                security & behaviour tests (node --test)
scripts/             quickstart, TLS cert generator, demo seeder, TOTP helper, single-file build
deploy/vercel/       the online demo as one static page (what the Vercel site serves)
deploy/online-demo/  source for that page: an in-browser copy of the API so the demo runs with no server
```

Rebuild the online demo after changing `public/` or `lib/`: `python3 deploy/online-demo/assemble.py`.

Configuration (environment variables): `LIFEBOAT_HOST` (default `127.0.0.1`; use `0.0.0.0` to serve the hotspot), `LIFEBOAT_PORT` (8443), `LIFEBOAT_DATA` (./data), `LIFEBOAT_PASSPHRASE` (otherwise prompted), `LIFEBOAT_IDLE_MIN` (15; sessions also end after 8 hours), `LIFEBOAT_ADMIN` (admin), `LIFEBOAT_LOGIN_RATE` (20 sign-in attempts per IP per 15 min). Forgot the admin login? Restart with `node server.js --reset-admin admin` to issue a new code.

*The notification engine is decision support, not legal advice. Statutes change; counsel confirms every obligation.*
