# WINDX: 5-minute demo script

**Setup before you present**
1. `LIFEBOAT_PASSPHRASE='correct horse battery staple' npm run demo -- --force`
2. Add the TOTP secrets for `jordan`, `dana` and `alex` to a phone authenticator app (or use `npm run totp -- SECRET`).
3. `LIFEBOAT_PASSPHRASE='correct horse battery staple' npm start`
4. Open two browser windows side by side: **Jordan** (commander) and **Dana** (counsel). Put a third on the projector as the **Wallboard** (press `W`).

---

### 0:00 · The problem (30 s)
"It's 2 a.m. Ransomware just hit. Your email is compromised, Active Directory is owned, and the attacker is reading your Teams chat. Where do you run the response? Most companies open a Google Doc and a group text. **WINDX is the way out**: a hardened, self-contained command center on one laptop with its own hotspot. It trusts nothing inside the building."

### 0:30 · Security first (60 s)
- Show the **login**: password **plus** a 6-digit code. No SSO, no Active Directory. "If the attacker owns AD, they still can't get in."
- Mention: "**Zero third-party dependencies.** Not one npm package. Even the QR code is ours. There's nothing to poison in the supply chain."
- Admin → **Security & system**: encrypted vault (AES-256-GCM, key never on disk), audit chain, lockdown.
- Admin → **Audit log** → **Verify integrity** → green. "Every action is cryptographically chained. Change one line and it tells you exactly where."
- Optional punch: run `strings data/vault.lbv | grep -i brazos` → nothing. "Steal the laptop, get noise."

### 1:30 · Ease of use under stress (90 s)
- Jordan's dashboard: "Two incidents, one SEV1, legal deadlines counting down. No training needed: it tells you what's next."
- Press **D** → declare an incident: one sentence, pick a type, pick severity → **Declare**. "20 seconds. The ransomware playbook loaded itself, an incident room opened, and it got a codename so nobody says 'payroll server' out loud."
- Open **BLACK HERON**: the **Next up** box, phase stepper, T+ clock.
- Type in the **scribe bar**: `Isolated VLAN 40` → Enter. "Timestamped in UTC. That's your forensic timeline, written as you work."

### 3:00 · Scope → legal deadlines (60 s): the lawyer moment
- **Scope & Data**: data sets with status *Encrypted / Exfiltrated / Accessed*, records, where people live.
- **Add affected data**: "HR payroll export", Exfiltrated, PII + financial, `TX:600, FL:40` → save. The toast fires: **"3 new notification obligations triggered."**
- **Legal Deadlines** tab: Texas AG in 30 days (250+ Texans), HIPAA 60 days, GDPR 72 h, insurer notice, OFAC check before any ransom payment, all with live countdowns and citations.
- In Dana's window, mark one **Done** and watch Jordan's update live.
- Point at the purple banner: "Privileged & Confidential, prepared at the direction of counsel, by default."

### 4:00 · Communications (40 s)
- Jordan opens **Room**, ticks **URGENT**: "Do not power off any servers." Send.
- Dana's screen gets a red banner and a beep. Jordan sees "**0/4 acknowledged · waiting on Sam, Dana…**". Dana clicks **Acknowledge** and the count updates live.
- **Contacts**: "The phone tree you need at 2 a.m.: FBI, insurer, forensics, bank fraud desk. Because email is compromised."

### 4:40 · Close (20 s)
- **Report** tab → **Print**: a court-ready report with timeline, scope, obligations and chain of custody.
- Wallboard on the projector: "And this is what's on the war-room TV."
- "Secure because it trusts nothing. Simple because the screen always tells you the next step. **WINDX.**"

---

**Likely judge questions**
- *What if the WINDX laptop itself is compromised?* It is never domain-joined, has its own network, and its data is encrypted at rest. Sessions are visible and revocable, there's lockdown, and the audit chain makes tampering evident. Keep an encrypted backup offsite.
- *Why not just use Signal / a SaaS tool?* No structured documentation, no legal deadlines, no chain of custody, and SaaS means trusting someone else's cloud with privileged material. WINDX can run fully air-gapped.
- *How do new people get access if email is down?* The admin reads them a one-time code in person or by phone. It is single-use, expires in 72 h, and only its hash is stored.
- *Is the legal engine accurate?* It is decision support with citations for each rule. Counsel confirms. Rules live in one file (`lib/regulations.js`) and are easy to extend.
