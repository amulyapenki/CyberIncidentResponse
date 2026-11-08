'use strict';
// Notification obligation engine. Looks at what data was compromised, whose
// data it was, and the org profile, then works out who must be told and by when.
// Decision support only: counsel confirms every obligation.

const H = 3600e3;
const D = 24 * H;

// Data types that trigger US state breach-notification laws.
const STATE_TRIGGER = new Set(['pii', 'phi', 'pci', 'financial', 'credentials', 'biometric']);
const PERSONAL = new Set(['pii', 'phi', 'pci', 'financial', 'credentials', 'biometric', 'employee']);

const DATA_TYPES = {
  pii: 'Personal info (SSN, DL, passport)',
  phi: 'Health info (PHI)',
  pci: 'Payment cards',
  financial: 'Bank / financial accounts',
  credentials: 'Usernames & passwords',
  biometric: 'Biometric data',
  employee: 'Employee / HR records',
  privileged: 'Attorney-client privileged',
  ip: 'Trade secrets / IP',
  operational: 'Operational / business data',
};

const STATES = {
  TX: { name: 'Texas', days: 60, agThreshold: 250, agDays: 30, cite: 'Tex. Bus. & Com. Code §521.053', ag: 'Texas Attorney General (online form)' },
  CA: { name: 'California', days: null, agThreshold: 501, agDays: null, cite: 'Cal. Civ. Code §1798.82', ag: 'California AG (submit sample notice)' },
  FL: { name: 'Florida', days: 30, agThreshold: 500, agDays: 30, cite: 'Fla. Stat. §501.171', ag: 'Florida Dept. of Legal Affairs' },
  NY: { name: 'New York', days: 30, agThreshold: 1, agDays: null, cite: 'N.Y. Gen. Bus. Law §899-aa', ag: 'NY AG, Dept. of State & State Police' },
  CO: { name: 'Colorado', days: 30, agThreshold: 500, agDays: 30, cite: 'C.R.S. §6-1-716', ag: 'Colorado Attorney General' },
  WA: { name: 'Washington', days: 30, agThreshold: 501, agDays: 30, cite: 'RCW 19.255.010', ag: 'Washington Attorney General' },
};
const EU_LIKE = { EU: 'EU / EEA', UK: 'United Kingdom' };

function addBusinessDays(date, n) {
  const d = new Date(date);
  let added = 0;
  while (added < n) {
    d.setUTCDate(d.getUTCDate() + 1);
    const wd = d.getUTCDay();
    if (wd !== 0 && wd !== 6) added++;
  }
  return d;
}

function iso(t) {
  return t ? new Date(t).toISOString() : null;
}

/** Totals residents per jurisdiction across live scope rows that hold the given kinds of data. */
function residents(incident, filter) {
  const out = {};
  for (const s of incident.scope || []) {
    if (s.deleted) continue;
    if (s.status === 'secured' && s.confidence === 'ruled-out') continue;
    if (!s.dataTypes.some((t) => filter.has(t))) continue;
    for (const [j, n] of Object.entries(s.residents || {})) out[j] = (out[j] || 0) + (Number(n) || 0);
  }
  return out;
}

function hasType(incident, type) {
  return (incident.scope || []).some((s) => !s.deleted && s.dataTypes.includes(type));
}

function compute(incident, org) {
  const ob = [];
  const aware = new Date(incident.detectedAt || incident.createdAt).getTime();
  const determined = incident.breachDeterminedAt ? new Date(incident.breachDeterminedAt).getTime() : null;
  const stateClock = determined || aware;
  const add = (o) => ob.push({ status: 'pending', notes: '', ...o, ...(incident.notifications?.[o.id] || {}) });

  // Cyber insurance: late notice is one of the most common reasons claims get denied.
  const ins = org.insurance || {};
  add({
    id: 'insurance',
    title: 'Notify cyber insurance carrier',
    who: ins.carrier ? `${ins.carrier}${ins.hotline ? ' · ' + ins.hotline : ''}` : 'Your cyber insurance carrier',
    cite: ins.policy ? `Policy ${ins.policy}` : 'Policy notice provision',
    level: 'required',
    dueAt: iso(aware + (Number(ins.noticeHours) || 72) * H),
    why: 'Late notice is a leading cause of denied cyber claims. Use the carrier\'s panel counsel and vendors where required.',
  });

  if (incident.category === 'ransomware' || incident.category === 'extortion') {
    add({
      id: 'ofac',
      title: 'OFAC sanctions screening before any ransom payment',
      who: 'Counsel + U.S. Treasury OFAC',
      cite: 'OFAC Advisory (Sept. 2021); 31 C.F.R. Ch. V',
      level: 'required',
      dueAt: null,
      dueText: 'Before any payment decision',
      why: 'Paying a sanctioned actor can trigger strict-liability civil penalties.',
    });
  }
  if (['ransomware', 'extortion', 'bec', 'exfiltration', 'intrusion'].includes(incident.category)) {
    add({
      id: 'fbi',
      title: 'Report to law enforcement (FBI field office / IC3)',
      who: 'FBI · ic3.gov',
      cite: 'Recommended',
      level: 'recommended',
      dueAt: null,
      dueText: 'As early as possible',
      why: 'Early reporting can enable fund recovery (BEC) and access to decryptors. It is also a mitigating factor for regulators.',
    });
  }

  const personal = residents(incident, PERSONAL);
  const euCount = (personal.EU || 0) + (personal.UK || 0);
  if (euCount > 0) {
    add({
      id: 'gdpr',
      title: 'Notify supervisory authority (GDPR / UK GDPR)',
      who: 'Lead data protection authority (ICO for UK)',
      cite: 'GDPR Art. 33 (individuals: Art. 34)',
      level: 'required',
      dueAt: iso(aware + 72 * H),
      why: `${euCount.toLocaleString()} EU/UK data subjects in scope. Report within 72h of becoming aware, unless the breach is unlikely to create risk.`,
    });
  }

  if (org.publiclyTraded) {
    const mat = incident.materialityDeterminedAt;
    add({
      id: 'sec',
      title: 'SEC Form 8-K, Item 1.05 (material incident)',
      who: 'SEC via EDGAR',
      cite: '17 C.F.R. §229.106; Form 8-K Item 1.05',
      level: mat ? 'required' : 'conditional',
      dueAt: mat ? iso(addBusinessDays(mat, 4)) : null,
      dueText: mat ? null : 'Determine materiality without unreasonable delay. Clock starts at that decision.',
      why: '4 business days after the materiality determination. Weekends are skipped; check federal holidays manually.',
    });
  }

  if (hasType(incident, 'phi')) {
    const phi = residents(incident, new Set(['phi']));
    const total = Object.values(phi).reduce((a, b) => a + b, 0);
    add({
      id: 'hipaa-ind',
      title: 'HIPAA notice to affected individuals',
      who: 'Affected individuals (first-class mail)',
      cite: '45 C.F.R. §164.404',
      level: org.hipaaCovered ? 'required' : 'conditional',
      dueAt: iso(aware + 60 * D),
      why: 'Without unreasonable delay, and no later than 60 days after discovery.' + (org.hipaaCovered ? '' : ' Applies if you are a covered entity, or a business associate notifying the covered entity.'),
    });
    add({
      id: 'hipaa-hhs',
      title: total >= 500 ? 'HIPAA notice to HHS (500+ individuals)' : 'Log breach for annual HHS report (<500)',
      who: 'HHS Office for Civil Rights',
      cite: '45 C.F.R. §164.408',
      level: org.hipaaCovered ? 'required' : 'conditional',
      dueAt: total >= 500 ? iso(aware + 60 * D) : null,
      dueText: total >= 500 ? null : 'Within 60 days after end of calendar year',
      why: `${total.toLocaleString()} individuals with PHI currently in scope.`,
    });
    const bigState = Object.entries(phi).filter(([, n]) => n > 500);
    if (bigState.length) {
      add({
        id: 'hipaa-media',
        title: 'HIPAA media notice',
        who: `Prominent media outlets in ${bigState.map(([s]) => s).join(', ')}`,
        cite: '45 C.F.R. §164.406',
        level: org.hipaaCovered ? 'required' : 'conditional',
        dueAt: iso(aware + 60 * D),
        why: 'More than 500 residents of one state or jurisdiction.',
      });
    }
  }

  if (org.nydfsRegulated) {
    add({
      id: 'nydfs',
      title: 'NYDFS cybersecurity incident notice',
      who: 'NY Dept. of Financial Services portal',
      cite: '23 NYCRR §500.17(a)',
      level: 'required',
      dueAt: iso(aware + 72 * H),
      why: '72 hours from determining a cybersecurity incident occurred. Any extortion payment needs separate notice within 24h of payment (§500.17(c)).',
    });
  }

  if (org.criticalInfrastructure) {
    add({
      id: 'circia',
      title: 'CISA report (CIRCIA covered entity)',
      who: 'CISA',
      cite: '6 U.S.C. §681b',
      level: 'conditional',
      dueAt: iso(aware + 72 * H),
      why: 'Covered cyber incidents: 72h. Ransom payments: 24h. Confirm the final rule is in effect and that you are a covered entity.',
    });
  }

  const us = residents(incident, STATE_TRIGGER);
  for (const [code, count] of Object.entries(us)) {
    const st = STATES[code];
    if (EU_LIKE[code] || !count) continue;
    if (!st) {
      add({
        id: `state-${code}`,
        title: `${code} residents: check state breach statute`,
        who: `Affected ${code} residents (and regulator, if required)`,
        cite: `${code} breach notification law`,
        level: 'required',
        dueAt: null,
        dueText: 'Varies by state, often 30 to 60 days or "most expedient time"',
        why: `${count.toLocaleString()} residents in scope. All 50 states have breach laws; this one is not preloaded.`,
      });
      continue;
    }
    add({
      id: `state-${code}`,
      title: `Notify ${st.name} residents`,
      who: `${count.toLocaleString()} affected ${st.name} residents`,
      cite: st.cite,
      level: 'required',
      dueAt: st.days ? iso(stateClock + st.days * D) : null,
      dueText: st.days ? null : 'Most expedient time possible, without unreasonable delay',
      why: (st.days ? `Within ${st.days} days` : 'No fixed day count') + (determined ? ' of breach determination.' : '. Clock assumed from detection until a breach determination is recorded.'),
    });
    if (count >= st.agThreshold) {
      add({
        id: `state-${code}-ag`,
        title: `Notify ${st.ag}`,
        who: st.ag,
        cite: st.cite,
        level: 'required',
        dueAt: st.agDays ? iso(stateClock + st.agDays * D) : null,
        dueText: st.agDays ? null : 'At the time individuals are notified',
        why: `${count.toLocaleString()} residents meets the ${st.agThreshold}+ regulator threshold.`,
      });
    }
  }

  if (hasType(incident, 'privileged')) {
    add({
      id: 'privileged',
      title: 'Assess ethical duties for compromised client data',
      who: 'General counsel / ethics counsel; affected clients',
      cite: 'ABA Formal Op. 483; Model Rules 1.1, 1.4, 1.6(c)',
      level: 'required',
      dueAt: null,
      dueText: 'Promptly',
      why: 'Lawyers must notify current clients of a data breach involving material client confidential information.',
    });
  }

  if (hasType(incident, 'pci')) {
    add({
      id: 'pci',
      title: 'Notify acquiring bank / card brands',
      who: 'Acquirer & payment brands',
      cite: 'PCI DSS / merchant agreement',
      level: 'required',
      dueAt: iso(aware + 72 * H),
      why: 'Card-brand rules usually demand immediate notice. Check your merchant agreement (often 24 to 72h).',
    });
  }

  const rank = (o) => (o.status === 'done' || o.status === 'na' ? 2 : o.dueAt ? 0 : 1);
  ob.sort((a, b) => rank(a) - rank(b) || (a.dueAt && b.dueAt ? a.dueAt.localeCompare(b.dueAt) : 0));
  return ob;
}

module.exports = { compute, DATA_TYPES, STATES, addBusinessDays };
