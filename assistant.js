'use strict';
/* Cyberattack Response Assistant.
   Works fully offline: it recognizes common situations and walks the person through
   what to do right now, what not to do, and who to call. In the online demo it can
   also ask Claude about questions the built-in guide does not cover. */
(function () {
  // ---------------------------------------------------------------- knowledge
  const SCENARIOS = [
    {
      id: 'ransomware', label: 'Files are locked / ransom note', category: 'ransomware', severity: 1,
      match: /ransom|encrypt|locked (files|my files)|files (are|got|were) locked|can'?t open (my |any )?files|bitcoin|lockbit|blacksuit|\.locked/i,
      title: 'Ransomware: act fast, but do not shut anything down.',
      now: [
        'Unplug the network cable and turn off Wi-Fi on the affected computer. Leave it powered on.',
        'Take a photo of the ransom note with your phone.',
        'Call your IT or security lead right away. Use the phone, not email.',
        'Check whether other computers or shared drives show the same thing.',
        'Do not contact the attackers and do not pay anything.',
      ],
      next: [
        'Declare an incident in WINDX so the team gets the ransomware checklist.',
        'Call your cyber insurance hotline before hiring outside help. Many policies require it.',
        'Bring in legal counsel early so the investigation stays privileged.',
        'Protect your backups: disconnect them so they do not get encrypted too.',
        'Find out whether data was copied out before it was locked. That decides who you must notify.',
      ],
      dont: [
        'Do not pay or reply to the attackers without counsel. Paying a sanctioned group can bring federal penalties (OFAC).',
        'Do not turn off, restart or wipe infected computers. Memory holds evidence.',
        'Do not restore from backups until you know how they got in.',
        'Do not discuss the attack over company email or chat. Assume the attacker can read it.',
      ],
      call: ['IT / Security', 'Insurance', 'Legal', 'Forensics / DFIR', 'Law enforcement'],
    },
    {
      id: 'phishing', label: 'I clicked a bad link or email', category: 'intrusion', severity: 3,
      match: /phish|clicked|click(ed)? (on )?(a|the) link|suspicious (link|email|attachment)|fake (login|email|page)|entered my password|opened (an|the) attachment|weird email/i,
      title: 'Clicked a suspicious link or attachment.',
      now: [
        'If you opened a file or downloaded something, disconnect that computer from the network.',
        'From a different, trusted device, change the password you typed in.',
        'Sign out of all sessions for that account and make sure two-factor login is on.',
        'Report the email to IT. Do not forward it to coworkers.',
      ],
      next: [
        'IT checks the mailbox for new forwarding rules and sign-ins from unknown places.',
        'Scan the computer with your antivirus or EDR tool.',
        'Block the sender and the link for the whole company.',
        'If the account sent emails you did not write, warn the people who got them, by phone.',
        'Declare an incident if a password was entered or a file was opened.',
      ],
      dont: [
        'Do not delete the email. IT needs it as evidence.',
        'Do not click the link again to check it.',
        'Do not reuse the old password anywhere.',
      ],
      call: ['IT / Security'],
    },
    {
      id: 'account', label: 'My account was hacked', category: 'intrusion', severity: 2,
      match: /hack(ed)? (my|our|the)? ?(account|email|login)|account (was |got |is )?(hacked|compromised|taken over)|someone (else )?(logged|signed) in|can'?t (log|sign) in|password (was |got )?(stolen|changed)|unknown (login|sign.?in)|(mfa|2fa|two.factor) (prompt|request|code)s?/i,
      title: 'A hacked account: lock it down from a clean device.',
      now: [
        'From a different, trusted device, reset the password.',
        'Sign out of all active sessions for that account.',
        'Turn on or reset two-factor login. Deny any login prompt you did not start.',
        'Check the account for forwarding rules and changed recovery email or phone.',
        'Tell IT so they can check what the attacker accessed.',
      ],
      next: [
        'IT reviews sign-in logs to see when and from where the attacker got in.',
        'Change passwords on any other account that used the same password.',
        'Look for emails sent, files shared or settings changed by the attacker.',
        'Declare an incident if business data or other people may be affected.',
      ],
      dont: [
        'Do not reset the password from the computer that may be infected.',
        'Do not approve two-factor prompts you did not request. Someone has your password.',
      ],
      call: ['IT / Security'],
    },
    {
      id: 'bec', label: 'Money was sent to a scammer', category: 'bec', severity: 2,
      match: /wire|bank (details|account)|fake invoice|invoice|payment (was )?(sent|made)|fraudulent (transfer|payment)|sent money|gift cards?|\bach\b|ceo (email|asked)/i,
      title: 'Payment fraud: call the bank now. The first hours matter most.',
      now: [
        "Call your bank's fraud line right now and ask them to recall or freeze the transfer.",
        'File a complaint at ic3.gov and ask the FBI for help recovering the money.',
        'Call the real vendor or person using a phone number you already had, not one from the email.',
        'Save every email and invoice involved. Do not delete anything.',
        'Tell IT the mailbox that received or sent the request may be compromised.',
      ],
      next: [
        'Declare an incident. WINDX loads the wire-fraud checklist.',
        'IT checks the mailbox for forwarding rules and unknown sign-ins.',
        'Notify your cyber insurer. Many policies cover this kind of fraud.',
        'Warn your finance team to verify all bank-detail changes by phone.',
      ],
      dont: [
        'Do not reply to the scam email or use any contact details from it.',
        'Do not wait to see if the payment clears. Recalls get harder every hour.',
      ],
      call: ['Banking', 'Law enforcement', 'Insurance', 'IT / Security'],
    },
    {
      id: 'breach', label: 'Data was stolen or leaked', category: 'exfiltration', severity: 1,
      match: /data (was |got |has been )?(stolen|leaked|exposed|breached|taken)|exfiltrat|leak site|(customer|client|patient|employee) (data|records|information)|\bssn\b|social security|database (was )?(accessed|dumped)|downloaded our data/i,
      title: 'Stolen data: stop the leak and get legal help early.',
      now: [
        'Cut off access to the system or account the data came from.',
        'Save the logs that show what was accessed. Do not delete anything.',
        'Call legal counsel. Breach laws have strict deadlines.',
        'Notify your cyber insurance carrier.',
        'Start a list of what data was involved and whose it was.',
      ],
      next: [
        'Declare an incident and record each data set in the Scope & Data section.',
        'WINDX then works out the legal deadlines, for example the Texas Attorney General within 30 days when 250 or more Texans are affected.',
        'Work with counsel on letters to the affected people and regulators.',
        'Find and close the way the attacker got in.',
      ],
      dont: [
        'Do not announce anything publicly before counsel reviews it.',
        'Do not put guesses about numbers in writing. Mark them as suspected until confirmed.',
        'Do not delete logs or wipe systems.',
      ],
      call: ['Legal', 'Insurance', 'Forensics / DFIR', 'Law enforcement'],
    },
    {
      id: 'malware', label: 'Virus or strange pop-ups', category: 'malware', severity: 3,
      match: /virus|malware|pop.?ups?|slow computer|strange (program|app|software)|antivirus (alert|warning)|trojan|keylogger|spyware|computer (is )?acting (weird|strange)/i,
      title: 'Possible malware: isolate the computer and tell IT.',
      now: [
        'Disconnect the computer from the network.',
        'Do not log in to anything else from that computer.',
        'Write down what you saw: the alert text, file names and the time.',
        'Tell IT so they can scan or quarantine it with your security tools.',
      ],
      next: [
        'IT checks whether other computers show the same signs.',
        'Change passwords that were used on that computer, from another device.',
        'Declare an incident if the malware spread or touched sensitive data.',
      ],
      dont: [
        'Do not run random cleanup tools from the internet.',
        'Do not plug USB drives from that computer into other machines.',
      ],
      call: ['IT / Security'],
    },
    {
      id: 'device', label: 'Lost or stolen laptop or phone', category: 'device', severity: 3,
      match: /lost (my|a|the|our)|stolen (laptop|phone|device|computer)|(laptop|phone|device|computer) (was |got )?(stolen|lost|missing)|left my (laptop|phone)|stole my/i,
      title: 'Lost or stolen device: lock it remotely.',
      now: [
        'Report it to IT now so they can lock or wipe it remotely.',
        'Change passwords for accounts saved on the device.',
        'File a police report if it was stolen.',
        'Write down when and where you last had it.',
      ],
      next: [
        'IT confirms whether the device was encrypted. That decides if this counts as a data breach.',
        'Declare an incident if it held sensitive data and was not encrypted.',
      ],
      dont: ['Do not wait to see if it turns up before reporting it.'],
      call: ['IT / Security', 'Law enforcement'],
    },
    {
      id: 'ddos', label: 'Our website is down / flooded', category: 'ddos', severity: 2,
      match: /ddos|denial of service|website (is )?(down|offline|slow)|site (is )?(down|offline)|traffic (spike|flood)|can'?t reach (our|the) (site|website)/i,
      title: 'Website flooded or down.',
      now: [
        "Check your hosting provider's status page to rule out a normal outage.",
        'Call your hosting or internet provider, or your DDoS protection service.',
        'Turn on rate limiting or an "under attack" mode if your provider has one.',
        'Post updates on a status page so customers know you are working on it.',
      ],
      next: [
        'Capture a sample of the traffic for the provider and law enforcement.',
        'Watch for a second attack hiding behind the noise, like a login attempt or data theft.',
        'Declare an incident if it lasts or comes with a ransom demand.',
      ],
      dont: ['Do not pay anyone who demands money to stop the attack.'],
      call: ['IT / Security', 'Vendors'],
    },
    {
      id: 'insider', label: 'An employee may be stealing data', category: 'insider', severity: 2,
      match: /employee (is |was )?(stealing|took|copying|downloading)|insider|former employee|disgruntled|coworker (is |was )?(stealing|downloading|copying)/i,
      title: 'Possible insider: move quietly and involve HR and legal.',
      now: [
        'Do not confront the person.',
        'Tell HR and legal counsel privately, by phone or in person.',
        'Mark the incident as need-to-know in WINDX so only the right people can see it.',
        "Preserve the person's account activity, email and devices.",
      ],
      next: [
        'Plan when to remove access together with HR.',
        'Review what data the person accessed or copied.',
      ],
      dont: ['Do not discuss it in shared channels or with their team.'],
      call: ['Legal', 'IT / Security'],
    },
  ];

  const QA = [
    { match: /pay(ing)?( the)? ransom|should (we|i) pay|negotiat/i, text: 'Do not pay or contact the attackers without legal counsel. Paying a group on the U.S. sanctions list can bring federal penalties (OFAC), and paying does not guarantee you get your files back or that stolen data is deleted. Check nomoreransom.org for free decryption tools, and speak with your insurer and counsel first.' },
    { match: /turn (it )?off|shut ?(it )?down|power (it )?off|restart|reboot/i, text: 'Disconnect it from the network (unplug the cable and turn off Wi-Fi), but leave it powered on. Shutting down erases evidence in memory and can make recovery harder.' },
    { match: /police|fbi|law enforcement|ic3|report (it|this)/i, text: 'Report it to the FBI through your local field office or at ic3.gov. Early reports help with recovering money in wire fraud cases and can give access to decryption help. It also shows regulators you acted responsibly.' },
    { match: /insurance|insurer|carrier|claim|policy/i, text: 'Call your cyber insurance hotline early, ideally in the first day. Late notice is a common reason claims get denied. Ask which law firm and forensics firm they approve before hiring anyone.' },
    { match: /lawyer|legal|counsel|attorney|privilege/i, text: 'Bring in a breach lawyer early. When counsel directs the investigation, the findings are more likely to stay privileged. Counsel also decides which notification laws apply.' },
    { match: /notify|tell (our )?(customers|clients|patients)|disclos|deadline|attorney general|hipaa|gdpr|regulator/i, text: 'Who you must notify depends on what data was taken and where the affected people live. In WINDX, record it in the Scope & Data section and the Legal Deadlines section counts down each deadline. For example, Texas requires notice to the Attorney General within 30 days when 250 or more Texans are affected.' },
    { match: /backup|restore|recover/i, text: 'Disconnect your backups so they stay safe. Only restore after you know how the attacker got in, and check that the backup itself is clean. Otherwise they can get right back in.' },
    { match: /password|reset/i, text: 'Reset passwords from a clean, trusted device, starting with admin accounts and the accounts involved. Turn on two-factor login and sign out all sessions.' },
    { match: /evidence|logs?|preserve|screenshot/i, text: 'Keep everything. Take photos of screens, save logs, and do not wipe or rebuild machines yet. In WINDX, log each item in the Evidence section so its chain of custody is recorded.' },
    { match: /email|teams|slack|chat|text message/i, text: 'Assume company email and chat may be watched by the attacker. Talk by phone or inside WINDX, which runs separately from your normal systems.' },
  ];

  const GREETING = "Hi, I'm the Response Assistant. Tell me what is happening and I'll walk you through what to do next. You can type in your own words, for example \"My computer has ransomware\", or pick one below.";

  // ---------------------------------------------------------------- state
  let open = false, scenario = null, lastUserText = '', busy = false, sample = null, aiTried = false;
  const log = []; // {from: 'bot'|'user', parts}
  const turns = []; // for the online AI: plain text history

  if (window.claude && window.claude.use) window.claude.use('sample').then((s) => { sample = s; setMode(); }).catch(() => {});
  function setMode() { const m = document.querySelector('.assist-mode'); if (m) { m.textContent = sample ? 'AI on (online demo) · type any question' : 'Built-in guide (works offline)'; m.classList.toggle('ai', !!sample); } }
  const signedIn = () => typeof S !== 'undefined' && !!S.me;
  const canDeclare = () => signedIn() && typeof can === 'function' && can('incident.create');

  // ---------------------------------------------------------------- DOM
  const launcher = document.createElement('button');
  launcher.type = 'button';
  launcher.className = 'assist-launch';
  launcher.setAttribute('aria-expanded', 'false');
  // The button is the WINDX logo with a small question-mark badge in its corner.
  launcher.setAttribute('aria-label', 'Get help from the Response Assistant');
  launcher.title = 'Get help: Response Assistant';
  launcher.innerHTML = (typeof LOGO !== 'undefined' ? String(LOGO) : '') + '<span class="assist-badge" aria-hidden="true">?</span>';
  const panel = document.createElement('section');
  panel.className = 'assist';
  panel.hidden = true;
  panel.setAttribute('aria-label', 'Cyberattack Response Assistant');
  panel.innerHTML = `
    <header class="assist-head"><div><b>Response Assistant</b><small>Step-by-step help during a cyberattack</small><span class="assist-mode">Built-in guide (works offline)</span></div>
      <button type="button" class="assist-x" aria-label="Close">×</button></header>
    <div class="assist-log" aria-live="polite"></div>
    <div class="assist-chips"></div>
    <form class="assist-form"><input type="text" class="assist-input" maxlength="500" autocomplete="off" placeholder="Type what is happening, or ask any question…" aria-label="Your message"><button class="assist-send">Send</button></form>`;
  document.body.append(panel, launcher);
  const logEl = panel.querySelector('.assist-log');
  setMode();
  const chipsEl = panel.querySelector('.assist-chips');
  const input = panel.querySelector('.assist-input');

  function setOpen(v) {
    open = v;
    panel.hidden = !v;
    launcher.setAttribute('aria-expanded', String(v));
    launcher.classList.toggle('is-open', v);
    if (v) {
      if (!log.length) bot({ text: GREETING }, startChips());
      setTimeout(() => input.focus(), 30);
    }
  }
  launcher.addEventListener('click', () => setOpen(!open));
  panel.querySelector('.assist-x').addEventListener('click', () => setOpen(false));
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && open && !document.querySelector('#modal-root .modal')) setOpen(false); });

  // ---------------------------------------------------------------- rendering (text only, never HTML)
  function el(tag, cls, text) { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; }
  function renderMsg(m) {
    const wrap = el('div', 'assist-msg ' + m.from);
    const b = el('div', 'assist-bubble');
    const p = m.parts;
    if (p.title) b.append(el('div', 'assist-title', p.title));
    if (p.label) b.append(el('div', 'assist-label', p.label));
    if (p.text) b.append(el('p', null, p.text));
    if (p.steps) { const ol = el('ol'); for (const s of p.steps) ol.append(el('li', null, s)); b.append(ol); }
    if (p.bullets) { const ul = el('ul'); for (const s of p.bullets) ul.append(el('li', null, s)); b.append(ul); }
    if (p.contacts) {
      const ul = el('ul', 'assist-contacts');
      for (const c of p.contacts) { const li = el('li'); li.append(el('b', null, c.name)); if (c.detail) li.append(el('span', null, ' · ' + c.detail)); if (c.phone) li.append(el('span', 'assist-phone', c.phone)); ul.append(li); }
      b.append(ul);
    }
    if (p.note) b.append(el('div', 'assist-note', p.note));
    wrap.append(b);
    return wrap;
  }
  function draw() {
    logEl.replaceChildren(...log.map(renderMsg));
    logEl.scrollTop = logEl.scrollHeight;
  }
  function chips(list) {
    chipsEl.replaceChildren(...list.map(([label, fn, primary]) => {
      const b = el('button', 'assist-chip' + (primary ? ' primary' : ''), label);
      b.type = 'button';
      b.addEventListener('click', fn);
      return b;
    }));
  }
  function bot(parts, nextChips) { log.push({ from: 'bot', parts }); turns.push({ role: 'assistant', content: partsToText(parts) }); draw(); if (nextChips) chips(nextChips); }
  function user(text) { log.push({ from: 'user', parts: { text } }); turns.push({ role: 'user', content: text }); draw(); }
  function partsToText(p) { return [p.title, p.text, ...(p.steps || []).map((s, i) => `${i + 1}. ${s}`), ...(p.bullets || []).map((s) => '- ' + s), p.note].filter(Boolean).join('\n'); }

  // ---------------------------------------------------------------- flows
  function startChips() {
    return SCENARIOS.map((s) => [s.label, () => { user(s.label); lastUserText = s.label; pickScenario(s); }]);
  }
  function followChips() {
    const list = [
      ['What next?', () => { user('What next?'); showNext(); }],
      ['What should I NOT do?', () => { user('What should I not do?'); showDont(); }],
      ['Who do I call?', () => { user('Who do I call?'); showCall(); }],
    ];
    if (canDeclare()) list.unshift(['Declare an incident', declare, true]);
    list.push(['Something else', () => { scenario = null; user('Something else'); bot({ text: 'OK. What else is going on?' }, startChips()); }]);
    return list;
  }
  function pickScenario(s) {
    scenario = s;
    bot({ title: s.title, label: 'Do this right now', steps: s.now, note: canDeclare() ? 'When the urgent steps are done, declare an incident so your team gets the full checklist.' : signedIn() ? '' : 'Sign in to WINDX to declare an incident and bring in your team.' }, followChips());
  }
  function showNext() {
    if (!scenario) return bot({ text: 'Tell me what happened first, and I will tell you the next steps.' }, startChips());
    bot({ label: 'Next steps', steps: scenario.next }, followChips());
  }
  function showDont() {
    if (!scenario) return bot({ label: 'In almost every attack', bullets: ['Do not pay or contact attackers without counsel.', 'Do not turn off or wipe affected computers. Disconnect them instead.', 'Do not use company email to discuss the attack.', 'Do not delete emails, files or logs.'] }, startChips());
    bot({ label: 'Do NOT do this', bullets: scenario.dont }, followChips());
  }
  function showCall() {
    const groups = scenario ? scenario.call : ['IT / Security', 'Insurance', 'Legal', 'Law enforcement'];
    const out = [];
    if (signedIn()) {
      const org = S.org || {};
      if (groups.includes('Insurance') && org.insurance?.carrier) out.push({ name: org.insurance.carrier, detail: 'Cyber insurance hotline' + (org.insurance.policy ? `, policy ${org.insurance.policy}` : ''), phone: org.insurance.hotline });
      if (groups.includes('Legal') && org.outsideCounsel?.firm) out.push({ name: org.outsideCounsel.contact || org.outsideCounsel.firm, detail: 'Breach counsel, ' + org.outsideCounsel.firm, phone: org.outsideCounsel.phone });
      for (const c of org.contacts || []) if (groups.includes(c.group)) out.push({ name: c.name, detail: c.role || c.group, phone: c.phone });
      if (groups.includes('IT / Security')) {
        const lead = (S.users || []).find((u) => u.status === 'active' && (u.role === 'commander' || u.role === 'admin') && u.phone && u.id !== S.me.id);
        if (lead) out.push({ name: lead.displayName, detail: lead.title || 'Incident response lead', phone: lead.phone });
      }
    }
    if (!out.length) {
      const generic = { 'IT / Security': 'Your IT or security lead', Insurance: 'Your cyber insurance hotline', Legal: 'A breach lawyer', 'Forensics / DFIR': 'A digital forensics firm', 'Law enforcement': 'The FBI (local field office or ic3.gov)', Banking: "Your bank's fraud line", Vendors: 'Your hosting or internet provider' };
      for (const g of groups) if (generic[g]) out.push({ name: generic[g] });
    }
    bot({ label: 'Call these people (by phone, not email)', contacts: out, note: signedIn() ? 'The full phone tree is on the Contacts page.' : '' }, scenario ? followChips() : startChips());
  }
  function declare() {
    const s = scenario;
    setOpen(false);
    if (typeof A === 'undefined' || !A.declare) return;
    A.declare();
    setTimeout(() => {
      const t = document.querySelector('#modal-root input[name=title]');
      if (t) t.value = (lastUserText && lastUserText !== s?.label ? lastUserText : s?.title || '').slice(0, 200);
      if (s) {
        document.querySelector(`#modal-root [data-group=category][data-v="${s.category}"]`)?.click();
        document.querySelector(`#modal-root [data-group=severity][data-v="${s.severity}"]`)?.click();
      }
      const sum = document.querySelector('#modal-root textarea[name=summary]');
      if (sum && s) sum.value = 'Started from the Response Assistant. Urgent steps suggested: ' + s.now.slice(0, 3).join(' ');
    }, 40);
  }

  // Built-in (offline) answer for a typed message. Returns true when it handled it.
  function offlineAnswer(text, s, q) {
    if (s && s !== scenario) { pickScenario(s); if (q && text.includes('?')) bot({ text: q.text }, followChips()); return true; }
    if (q) { bot({ text: q.text }, scenario ? followChips() : startChips()); return true; }
    if (s) { pickScenario(s); return true; }
    return false;
  }

  async function handle(text) {
    lastUserText = text;
    user(text);
    if (/^(hi|hello|hey|help)\b\W*$/i.test(text)) return bot({ text: 'What is happening right now? Describe it in a few words.' }, startChips());
    if (/^(something else|start over|new problem)\W*$/i.test(text)) { scenario = null; return bot({ text: 'OK. What else is going on?' }, startChips()); }
    if (/who (do|should) (i|we) call|who to (call|contact)|phone number/i.test(text)) return showCall();
    if (/^(declare|declare an incident|open an incident|start an incident)\W*$/i.test(text)) { if (canDeclare()) return declare(); return bot({ text: 'Sign in to WINDX to declare an incident.' }, startChips()); }
    const s = SCENARIOS.find((x) => x.match.test(text));
    const q = QA.find((x) => x.match.test(text));
    if (s) scenario = s; // keep the buttons (What next, Who do I call, Declare) in step with the conversation
    // Online demo: every typed message goes to the AI, grounded in the built-in guide.
    if (sample) return askAI(text, s, q);
    if (/what('?s| is)? next|next steps?|then what|after that/i.test(text)) return showNext();
    if (/what (not|shouldn'?t)|don'?t do|avoid/i.test(text)) return showDont();
    if (s) scenario = null; // let offlineAnswer show the full guide for a newly described situation
    if (offlineAnswer(text, s, q)) return;
    bot({ text: "I'm not sure I understood. Pick the closest match below, or describe what you see, for example \"files are locked\", \"I clicked a link\" or \"money went to the wrong account\"." }, startChips());
  }

  // Online demo only: typed messages are answered by Claude, using the built-in guide as its reference.
  const RULES = `You are the Response Assistant inside WINDX, a cyber incident response app. A stressed, possibly non-technical person is asking what to do during or after a cyberattack.
Reply in plain, calm language. Give at most 5 short numbered steps, most urgent first. Then, only if useful, one short line starting with "Do not". Keep it under 130 words.
Use plain text only: no emoji, no em dashes, no markdown headings, no bold.
Always follow these rules: disconnect infected machines from the network but do not power them off; never pay or contact attackers without legal counsel (OFAC sanctions risk); call the cyber insurance hotline early; talk by phone or in WINDX, not company email.
If the question is not about cybersecurity or responding to an incident, say in one sentence that you can only help with cyberattack response.
You give decision support, not legal advice.`;
  function guideFor(s, q) {
    const g = [];
    if (s) g.push(`Built-in guide for "${s.label}":\nRight now: ${s.now.join(' ')}\nNext: ${s.next.join(' ')}\nDo not: ${s.dont.join(' ')}`);
    if (q) g.push('Built-in answer on this topic: ' + q.text);
    return g.length ? '\n\nUse this reference from the app (stay consistent with it):\n' + g.join('\n') : '';
  }
  async function askAI(text, s, q) {
    busy = true;
    const pending = { from: 'bot', parts: { label: 'AI assistant', text: 'Thinking…' } };
    log.push(pending); draw(); chips([]);
    try {
      const history = turns.slice(-8);
      while (history.length && history[0].role !== 'user') history.shift();
      history[history.length - 1] = { role: 'user', content: text + guideFor(s, q) };
      const { text: answer } = await sample([{ role: 'user', content: RULES }, ...history], {
        modelTier: 'quick', cache: false,
        onText: ({ text: t }) => { pending.parts.text = t; draw(); },
      });
      pending.parts.text = answer;
      pending.parts.note = 'AI answer (online demo). The offline WINDX uses its built-in guide.';
      turns.push({ role: 'assistant', content: answer });
    } catch (e) {
      const off = e && ['not_granted', 'sampling_disabled', 'capability_disabled', 'not_declared', 'capability_removed'].includes(e.code);
      if (off) { sample = null; setMode(); }
      log.pop();
      const why = off ? 'AI is not available here, so here is the built-in guide.' : e && e.code === 'rate_limited' ? 'The AI is busy right now. Here is the built-in guide.' : 'The AI did not answer. Here is the built-in guide.';
      bot({ note: why });
      const wasScenario = scenario; if (s) scenario = null;
      if (!offlineAnswer(text, s, q)) { scenario = wasScenario; bot({ text: "I'm not sure I understood. Pick the closest match below, or describe what you see." }, startChips()); }
      busy = false;
      return;
    }
    busy = false;
    draw();
    chips(scenario ? followChips() : startChips());
  }

  panel.querySelector('.assist-form').addEventListener('submit', (e) => {
    e.preventDefault();
    const text = input.value.trim();
    if (!text || busy) return;
    input.value = '';
    handle(text);
  });

  // Small public hook so other parts of the page could open the assistant.
  window.__assistant = { open: () => setOpen(true) };
})();
