#!/usr/bin/env node
'use strict';
// Packs the whole app (server, libraries, web app, demo seeder) into one file: dist/lifeboat.js
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const MODULES = ['server.js', 'lib/crypto.js', 'lib/store.js', 'lib/regulations.js', 'lib/playbooks.js', 'lib/qr.js', 'scripts/seed-demo.js', 'scripts/totp.js'];
const PUBLIC = fs.readdirSync(path.join(ROOT, 'public')).sort();

const mods = MODULES.map((m) => {
  const src = fs.readFileSync(path.join(ROOT, m), 'utf8').replace(/^#!.*\n/, '');
  return `  ${JSON.stringify(m)}: function (module, exports, require, __filename, __dirname) {\n${src}\n  },`;
}).join('\n');
const statics = PUBLIC.map((f) => `  ${JSON.stringify(f)}: ${JSON.stringify(fs.readFileSync(path.join(ROOT, 'public', f)).toString('base64'))},`).join('\n');

const out = `#!/usr/bin/env node
/*
 * WINDX: out-of-band cyber incident command center. Single-file edition.
 * Needs only Node.js 20+. No npm install, no other files.
 *
 *   node lifeboat.js quickstart      EASIEST: loads the demo, starts the server, prints sign-in codes
 *   node lifeboat.js codes           print fresh 6-digit sign-in codes for all demo users
 *   node lifeboat.js                 start the server (asks for a vault passphrase)
 *   node lifeboat.js demo --force    load the demo scenario (Brazos Valley Medical Group)
 *   node lifeboat.js totp SECRET     print the current 6-digit sign-in code for a demo user
 *   node lifeboat.js cert            create an HTTPS certificate (needs OpenSSL installed)
 *
 * Data is stored in a "data" folder next to this file.
 */
'use strict';
const __path = require('node:path');
const __BASE = __dirname;

global.__LIFEBOAT_STATIC = {
${statics}
};

const __MODULES = {
${mods}
};

const __cache = {};
function __load(name) {
  if (__cache[name]) return __cache[name].exports;
  const module = { exports: {} };
  __cache[name] = module;
  const dir = __path.dirname(name);
  const req = (spec) => {
    if (!spec.startsWith('.')) return require(spec);
    let r = __path.posix.normalize(__path.posix.join(dir, spec));
    if (!r.endsWith('.js')) r += '.js';
    if (!__MODULES[r]) throw new Error('Module not bundled: ' + r);
    return __load(r);
  };
  __MODULES[name].call(module.exports, module, module.exports, req, __path.join(__BASE, name), __path.join(__BASE, dir));
  return module.exports;
}

let cmd = process.argv[2];
// Uploaded to a hosting site (no terminal, no passphrase set)? Run the demo automatically.
if (!cmd && !process.env.LIFEBOAT_PASSPHRASE && !process.stdin.isTTY) cmd = 'quickstart';

const DEMO_SECRETS = { alex: 'admin', jordan: 'commander', sam: 'responder', dana: 'counsel', morgan: 'observer' };
function demoCodes() {
  const C = __load('lib/crypto.js');
  console.log('\\n  Demo sign-in  ·  password for everyone: lifeboat-demo-2026');
  console.log('  username   role         6-digit code right now');
  for (const [u, role] of Object.entries(DEMO_SECRETS)) {
    const secret = C.base32Encode(Buffer.from(C.sha256('lifeboat-demo:' + u), 'hex').subarray(0, 20));
    console.log('  ' + u.padEnd(10) + ' ' + role.padEnd(12) + ' ' + C.totpAt(secret, C.currentStep()));
  }
  const left = 30 - (Math.floor(Date.now() / 1000) % 30);
  console.log('  (codes change every 30 s, this set is valid ' + left + 's more; run "node lifeboat.js codes" for fresh ones)\\n');
}

if (cmd === 'codes') {
  demoCodes();
} else if (cmd === 'quickstart') {
  process.argv.splice(2, 1);
  process.env.LIFEBOAT_PASSPHRASE = process.env.LIFEBOAT_PASSPHRASE || 'lifeboat-demo-passphrase';
  if (process.env.PORT) {
    // Hosting platforms (Replit, Render, Glitch…) give us a PORT and put HTTPS in front of us.
    process.env.LIFEBOAT_PORT = process.env.PORT;
    process.env.LIFEBOAT_HOST = '0.0.0.0';
    process.env.LIFEBOAT_ALLOW_HTTP = '1';
  }
  const fs = require('node:fs');
  const vaultFile = __path.join(process.env.LIFEBOAT_DATA || __path.join(__BASE, 'data'), 'vault.lbv');
  const pass = process.env.LIFEBOAT_PASSPHRASE;
  if (!fs.existsSync(vaultFile)) __load('scripts/seed-demo.js');
  process.env.LIFEBOAT_PASSPHRASE = pass;
  demoCodes();
  setInterval(demoCodes, 30000).unref();
  __load('server.js').main().catch((e) => { console.error('\\n✖ ' + e.message); process.exit(1); });
} else if (cmd === 'demo') {
  process.argv.splice(2, 1);
  __load('scripts/seed-demo.js');
} else if (cmd === 'totp') {
  process.argv.splice(2, 1);
  __load('scripts/totp.js');
} else if (cmd === 'cert') {
  const fs = require('node:fs');
  const dir = __path.join(process.env.LIFEBOAT_DATA || __path.join(__BASE, 'data'), 'tls');
  fs.mkdirSync(dir, { recursive: true });
  const { spawnSync } = require('node:child_process');
  const r = spawnSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes', '-days', '365',
    '-keyout', __path.join(dir, 'key.pem'), '-out', __path.join(dir, 'cert.pem'), '-subj', '/CN=windx.local/O=WINDX',
    '-addext', 'subjectAltName=DNS:windx.local,DNS:localhost,IP:127.0.0.1'], { stdio: 'ignore' });
  if (r.error || r.status !== 0) {
    console.error('OpenSSL is not installed, so no certificate was made. WINDX will still run on this computer over plain HTTP.');
    process.exit(1);
  }
  const fp = new (require('node:crypto').X509Certificate)(fs.readFileSync(__path.join(dir, 'cert.pem'))).fingerprint256;
  console.log('Certificate written to ' + dir + '\\nSHA-256 fingerprint (give this to your team):\\n  ' + fp);
} else {
  const server = __load('server.js');
  server.main().catch((e) => { console.error('\\n✖ ' + e.message); process.exit(1); });
}
`;
fs.mkdirSync(path.join(ROOT, 'dist'), { recursive: true });
fs.writeFileSync(path.join(ROOT, 'dist', 'lifeboat.js'), out);
console.log(`dist/lifeboat.js written (${(out.length / 1024).toFixed(0)} KB)`);
