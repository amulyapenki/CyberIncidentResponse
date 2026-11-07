'use strict';
// Playbooks: plain-language checklists that load into an incident's task list
// when it is declared. People under stress follow the list; they don't need to remember it.

const PHASES = [
  { id: 'triage', label: 'Detect & Analyze', short: 'Triage', hint: 'What happened? How bad? Who needs to know?' },
  { id: 'containment', label: 'Contain', short: 'Contain', hint: 'Stop the spread. Preserve evidence.' },
  { id: 'eradication', label: 'Eradicate', short: 'Eradicate', hint: 'Remove the attacker and the way they got in.' },
  { id: 'recovery', label: 'Recover', short: 'Recover', hint: 'Restore safely and watch for return.' },
  { id: 'post', label: 'Post-Incident', short: 'Lessons', hint: 'Notify, document, learn.' },
  { id: 'closed', label: 'Closed', short: 'Closed', hint: 'Incident closed.' },
];

const CATEGORIES = {
  ransomware: 'Ransomware',
  extortion: 'Data extortion (no encryption)',
  bec: 'Business email compromise / wire fraud',
  exfiltration: 'Data theft / exfiltration',
  intrusion: 'Unauthorized access / intrusion',
  malware: 'Malware infection',
  insider: 'Insider threat',
  ddos: 'Denial of service',
  device: 'Lost or stolen device',
  other: 'Other / unknown',
};

const COMMON = {
  triage: [
    'Assign an Incident Commander and a scribe',
    'Engage legal counsel and direct the investigation through counsel (privilege)',
    'Move all response communications to Lifeboat. Assume email and chat are compromised',
    'Notify cyber insurance carrier and confirm panel vendors',
    'Record first-known indicators (IPs, hashes, accounts) in IOCs',
  ],
  containment: [
    'Preserve volatile evidence (memory, logs) before wiping or rebooting',
    'Reset credentials for affected and privileged accounts from a clean device',
  ],
  eradication: ['Identify initial access vector and close it', 'Sweep the environment for persistence using IOCs'],
  recovery: ['Restore from known-clean backups and verify integrity', 'Heightened monitoring for 30 days for re-entry'],
  post: [
    'Finalize scope of compromised data with counsel',
    'Complete all regulatory and contractual notifications (see Obligations)',
    'Hold lessons-learned review within 2 weeks',
  ],
};

const SPECIFIC = {
  ransomware: {
    triage: ['Photograph the ransom note. Do NOT contact the threat actor without counsel', 'Identify the ransomware strain (note, file extension)', 'Check whether data was exfiltrated before encryption (double extortion)'],
    containment: ['Isolate infected hosts from the network (unplug, do not power off)', 'Disable or segment backups so they are not encrypted', 'Block known C2 domains and IPs at the firewall'],
    eradication: ['Rebuild domain controllers or rotate KRBTGT twice', 'Check nomoreransom.org for a free decryptor'],
    recovery: ['Restore critical systems in priority order agreed with business owners'],
    post: ['OFAC sanctions check documented before any payment decision'],
  },
  extortion: {
    triage: ['Preserve the extortion message and any leak-site posting', 'Validate the sample data the attacker claims to have'],
    containment: ['Find and cut the exfiltration channel'],
  },
  bec: {
    triage: ['Call the bank fraud line NOW to recall or freeze the wire (first 24-72h matter)', 'File IC3 complaint and request Financial Fraud Kill Chain'],
    containment: ['Reset the compromised mailbox password and revoke all sessions and tokens', 'Remove malicious inbox / forwarding rules', 'Check OAuth app grants on the mailbox'],
    eradication: ['Review mailbox audit logs for what the attacker read or sent'],
    recovery: ['Warn affected clients and vendors by phone using known-good numbers'],
  },
  exfiltration: {
    triage: ['Determine what data left, how much, and from which systems'],
    containment: ['Block exfil destinations; revoke cloud sharing links and keys'],
    post: ['Build the affected-individual list by state for notification'],
  },
  intrusion: {
    triage: ['Determine attacker dwell time and accounts used'],
    containment: ['Disable compromised accounts; force MFA re-registration'],
  },
  malware: {
    triage: ['Collect a sample hash and submit to EDR / sandbox'],
    containment: ['Quarantine infected endpoints via EDR'],
  },
  insider: {
    triage: ['Restrict this incident to need-to-know members only', 'Coordinate with HR and counsel before any contact with the subject'],
    containment: ['Preserve the subject\'s mailbox, devices and logs under legal hold', 'Disable access in coordination with HR timing'],
  },
  ddos: {
    triage: ['Confirm attack vs. outage; capture traffic samples'],
    containment: ['Engage ISP / DDoS mitigation provider', 'Enable rate limiting and geo-blocking where safe'],
  },
  device: {
    triage: ['Confirm whether the device was encrypted and when it was last seen', 'File a police report'],
    containment: ['Remote-wipe or lock the device', 'Reset credentials cached on the device'],
  },
};

function tasksFor(category) {
  const out = [];
  for (const phase of ['triage', 'containment', 'eradication', 'recovery', 'post']) {
    const titles = [...(SPECIFIC[category]?.[phase] || []), ...COMMON[phase]];
    for (const title of titles) out.push({ phase, title });
  }
  return out;
}

// Codenames keep the real target out of conversation in case anyone is listening.
const ADJ = ['AMBER', 'BLACK', 'COBALT', 'CRIMSON', 'GRANITE', 'IRON', 'SILENT', 'SILVER', 'COPPER', 'NORTHERN', 'HOLLOW', 'MIDNIGHT', 'STONE', 'ARCTIC', 'EMBER', 'JADE'];
const NOUN = ['HERON', 'FALCON', 'LANTERN', 'HARBOR', 'MERIDIAN', 'ORCHARD', 'SPARROW', 'TIDE', 'ANVIL', 'BEACON', 'CANYON', 'KESTREL', 'GLACIER', 'COMPASS', 'RAVEN', 'SUMMIT'];
function codename() {
  const c = require('node:crypto');
  return `${ADJ[c.randomInt(ADJ.length)]} ${NOUN[c.randomInt(NOUN.length)]}`;
}

module.exports = { PHASES, CATEGORIES, tasksFor, codename };
