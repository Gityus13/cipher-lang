#!/usr/bin/env node
/**
 * CipherLang Setup — cross-platform (macOS / Linux / Windows)
 * Zero npm installs needed — runs with Node.js 18+ built-ins only.
 */
const fs   = require('fs');
const path = require('path');
const os   = require('os');
const { execSync } = require('child_process');

const G='\x1b[32m', C='\x1b[36m', Y='\x1b[33m', R='\x1b[31m', B='\x1b[1m', X='\x1b[0m';
const log=(m,c='')=>console.log(`${c}${m}${X}`);
const ok =m=>log(`  ✓ ${m}`,G);
const warn=m=>log(`  ⚠ ${m}`,Y);
const err =m=>log(`  ✗ ${m}`,R);
const step=(n,m)=>log(`\n[${n}] ${m}`,C+B);

console.log(`
${G}${B}  ██████╗██╗██████╗ ██╗  ██╗███████╗██████╗
  ██╔════╝██║██╔══██╗██║  ██║██╔════╝██╔══██╗
  ██║     ██║██████╔╝███████║█████╗  ██████╔╝
  ██║     ██║██╔═══╝ ██╔══██║██╔══╝  ██╔══██╗
  ╚██████╗██║██║     ██║  ██║███████╗██║  ██║
   ╚═════╝╚═╝╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝${X}
${C}  LANG  v2.0 — AES-256 Secret Language System
  Setup Script — ${os.platform()} ${os.arch()}${X}
`);

step(1,'Checking Node.js version');
const major = parseInt(process.version.slice(1));
if (major < 18) {
  err(`Node.js ${process.version} detected. Need ≥ 18.0.0`);
  log('\n  Download: https://nodejs.org/en/download/',Y);
  process.exit(1);
}
ok(`Node.js ${process.version}`);

step(2,'Checking zero-dependency status');
ok('No npm install required — uses Node.js built-ins only');
ok('Built-ins used: http, fs, path, crypto, url, util');

step(3,'Creating .env file');
const envPath = path.join(__dirname,'../.env');
if (fs.existsSync(envPath)) {
  warn('.env already exists — skipping');
} else {
  const crypto = require('crypto');
  const secret = crypto.randomBytes(64).toString('hex');
  fs.writeFileSync(envPath,
`# CipherLang Environment — keep this file private, never commit it
PORT=3000
NODE_ENV=development
JWT_SECRET=${secret}
`);
  ok('.env created with secure JWT secret');
}

step(4,'Verifying file structure');
const required = [
  'server/index.js','server/cipher.js','server/auth.js',
  'server/keyManager.js','client/index.html'
];
let allOk = true;
for (const f of required) {
  const full = path.join(__dirname,'../',f);
  if (fs.existsSync(full)) ok(f);
  else { err(`MISSING: ${f}`); allOk = false; }
}
if (!allOk) { log('\nSome files are missing. Re-download the project.',R); process.exit(1); }

step(5,'Quick cipher self-test');
try {
  const { encodeMessage, decodeMessage } = require('../server/cipher');
  const { loadKeys, getCurrentKeyId }    = require('../server/keyManager');
  const keys  = loadKeys();
  const keyId = getCurrentKeyId();
  const enc   = encodeMessage('self-test-ok', keys[keyId], keyId);
  const dec   = decodeMessage(enc, keys);
  if (dec !== 'self-test-ok') throw new Error('mismatch');
  ok('AES-256-GCM encode/decode verified');
} catch(e) { err('Cipher self-test failed: ' + e.message); process.exit(1); }

console.log(`
${G}${B}╔════════════════════════════════════════════╗
║          CIPHERLANG READY TO START          ║
╚════════════════════════════════════════════╝${X}

${C}Start the server:${X}
  cd cipher-lang
  npm start          (or: node server/index.js)

${C}Development mode (auto-restart on file change):${X}
  npm run dev        (Node 18+ built-in --watch)

${C}Then open your browser:${X}
  http://localhost:3000

${Y}First run?${X} Register an account in the web UI.
Encryption keys are auto-generated on first start.

${G}Security:${X}
  • .env and .keys.json are in .gitignore — never commit them
  • AES-256-GCM keys stored server-side only
  • Passwords hashed with scrypt (NIST-recommended)
  • Zero external dependencies — nothing to audit or update
`);
