// Demo helper: prints the current 6-digit code for a TOTP secret.
// For rehearsals only. Real users use an authenticator app on their phone.
const C = require('../lib/crypto');
const secret = process.argv[2];
if (!secret) { console.error('usage: npm run totp -- <SECRET>'); process.exit(1); }
const left = 30 - (Math.floor(Date.now() / 1000) % 30);
console.log(`${C.totpAt(secret, C.currentStep())}  (valid ${left}s more)`);
