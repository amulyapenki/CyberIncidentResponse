#!/usr/bin/env node
'use strict';
// One command to run the demo: npm run quickstart
// Loads the demo data the first time, prints sign-in codes, and starts the server.
const fs = require('node:fs');
const path = require('node:path');

process.env.LIFEBOAT_PASSPHRASE = process.env.LIFEBOAT_PASSPHRASE || 'lifeboat-demo-passphrase';
const pass = process.env.LIFEBOAT_PASSPHRASE;
const dataDir = path.resolve(process.env.LIFEBOAT_DATA || path.join(__dirname, '..', 'data'));
if (!fs.existsSync(path.join(dataDir, 'vault.lbv'))) require('./seed-demo');
process.env.LIFEBOAT_PASSPHRASE = pass;

const C = require('../lib/crypto');
function codes() {
  console.log('\n  Demo sign-in  ·  password for everyone: lifeboat-demo-2026');
  console.log('  username   role         6-digit code right now');
  for (const [u, role] of [['alex', 'admin'], ['jordan', 'commander'], ['sam', 'responder'], ['dana', 'counsel'], ['morgan', 'observer']]) {
    const secret = C.base32Encode(Buffer.from(C.sha256('lifeboat-demo:' + u), 'hex').subarray(0, 20));
    console.log('  ' + u.padEnd(10) + ' ' + role.padEnd(12) + ' ' + C.totpAt(secret, C.currentStep()));
  }
  console.log('  (new codes print every 30 seconds)\n');
}
codes();
setInterval(codes, 30000).unref();
require('../server').main().catch((e) => { console.error('\n✖ ' + e.message); process.exit(1); });
