/**
 * CipherLang Auth Module
 * JWT session tokens + scrypt password hashing (built-in Node.js crypto)
 * In production, bcrypt is also excellent — install with: npm install bcrypt
 */

const crypto = require('crypto');
const { promisify } = require('util');

const scrypt = promisify(crypto.scrypt);

const TOKEN_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const TOKEN_EXPIRY = 24 * 60 * 60 * 1000; // 24 hours

// Simple self-contained HMAC-SHA256 signed token
function generateToken(payload) {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'CL1' })).toString('base64url');
  const body = Buffer.from(JSON.stringify({ ...payload, exp: Date.now() + TOKEN_EXPIRY, iat: Date.now() })).toString('base64url');
  const signature = crypto.createHmac('sha256', TOKEN_SECRET).update(`${header}.${body}`).digest('base64url');
  return `${header}.${body}.${signature}`;
}

function verifyToken(token) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;

    const [header, body, sig] = parts;
    const expectedSig = crypto.createHmac('sha256', TOKEN_SECRET).update(`${header}.${body}`).digest('base64url');

    const sigBuf = Buffer.from(sig + '='.repeat((4 - sig.length % 4) % 4), 'base64');
    const expBuf = Buffer.from(expectedSig + '='.repeat((4 - expectedSig.length % 4) % 4), 'base64');

    if (sigBuf.length !== expBuf.length) return null;
    if (!crypto.timingSafeEqual(sigBuf, expBuf)) return null;

    const payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    if (Date.now() > payload.exp) return null;

    return payload;
  } catch {
    return null;
  }
}

// scrypt password hashing (built-in, no external deps needed)
// Cost factor: N=16384 (2^14), r=8, p=1 — NIST-recommended minimum
async function hashPassword(password) {
  const salt = crypto.randomBytes(32).toString('hex');
  const keyLen = 64;
  const hash = await scrypt(password, salt, keyLen, { N: 16384, r: 8, p: 1 });
  return `scrypt$${salt}$${hash.toString('hex')}`;
}

async function verifyPassword(password, storedHash) {
  try {
    const [algo, salt, hashHex] = storedHash.split('$');
    if (algo !== 'scrypt') throw new Error('Unknown algorithm');
    const keyLen = 64;
    const hash = await scrypt(password, salt, keyLen, { N: 16384, r: 8, p: 1 });
    const storedBuf = Buffer.from(hashHex, 'hex');
    // Constant-time comparison
    if (hash.length !== storedBuf.length) return false;
    return crypto.timingSafeEqual(hash, storedBuf);
  } catch {
    return false;
  }
}

module.exports = { generateToken, verifyToken, hashPassword, verifyPassword };
