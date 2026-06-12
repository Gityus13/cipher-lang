/**
 * CipherLang Server — zero external dependencies
 * Uses only Node.js built-ins: http, fs, path, crypto, url
 */

const http  = require('http');
const fs    = require('fs');
const path  = require('path');
const { encodeMessage, decodeMessage } = require('./cipher');
const { generateToken, verifyToken, hashPassword, verifyPassword } = require('./auth');
const { loadKeys, rotateKey, getCurrentKeyId } = require('./keyManager');

const PORT = parseInt(process.env.PORT || '3000', 10);

// ─── In-memory stores (survive process lifetime) ──────────────────────────────
const users    = new Map(); // username → { hash, createdAt }
const messages = [];        // { id, owner, label, encoded, isPublic, createdAt }
let   msgIdSeq = 1;

// ─── Rate limiter (simple token-bucket per IP) ────────────────────────────────
const rateBuckets = new Map();
function rateLimit(ip, max, windowMs) {
  const now = Date.now();
  let b = rateBuckets.get(ip);
  if (!b || now - b.ts > windowMs) { b = { ts: now, count: 0 }; rateBuckets.set(ip, b); }
  b.count++;
  return b.count <= max;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────
function json(res, code, data) {
  const body = JSON.stringify(data);
  res.writeHead(code, {
    'Content-Type':  'application/json',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com"
  });
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', chunk => { data += chunk; if (data.length > 50000) reject(new Error('Body too large')); });
    req.on('end', () => {
      try { resolve(JSON.parse(data || '{}')); }
      catch { reject(new Error('Invalid JSON')); }
    });
    req.on('error', reject);
  });
}

function getToken(req) {
  const h = req.headers['authorization'] || '';
  return h.startsWith('Bearer ') ? h.slice(7) : null;
}

function auth(req) {
  const t = getToken(req);
  if (!t) return null;
  return verifyToken(t);
}

function serveStatic(res, filePath) {
  const ext = path.extname(filePath).toLowerCase();
  const mime = { '.html':'text/html;charset=utf-8', '.css':'text/css', '.js':'text/javascript', '.png':'image/png', '.ico':'image/x-icon' };
  fs.readFile(filePath, (err, data) => {
    if (err) { res.writeHead(404); res.end('Not found'); return; }
    res.writeHead(200, { 'Content-Type': mime[ext] || 'text/plain', 'X-Frame-Options': 'DENY' });
    res.end(data);
  });
}

// ─── Router ───────────────────────────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  const ip  = req.socket.remoteAddress || 'unknown';
  const url = new URL(req.url, `http://localhost:${PORT}`);
  const pathname = url.pathname;
  const method   = req.method.toUpperCase();

  // ── Static files ──────────────────────────────────────────────────────────
  if (!pathname.startsWith('/api/')) {
    const clientDir = path.join(__dirname, '../client');
    const target = pathname === '/' ? 'index.html' : pathname.slice(1);
    return serveStatic(res, path.join(clientDir, target));
  }

  // ── API ───────────────────────────────────────────────────────────────────
  if (method === 'OPTIONS') {
    res.writeHead(204); res.end(); return;
  }

  try {
    // POST /api/register
    if (pathname === '/api/register' && method === 'POST') {
      if (!rateLimit(ip, 10, 15 * 60 * 1000)) return json(res, 429, { error: 'Too many attempts. Wait 15 minutes.' });
      const { username, password } = await readBody(req);
      if (!username || !password) return json(res, 400, { error: 'Username and password required' });
      if (typeof username !== 'string' || username.length < 3 || username.length > 32)
        return json(res, 400, { error: 'Username must be 3–32 characters' });
      if (typeof password !== 'string' || password.length < 6)
        return json(res, 400, { error: 'Password must be at least 6 characters' });
      if (users.has(username.toLowerCase()))
        return json(res, 409, { error: 'Username already taken' });

      const hash = await hashPassword(password);
      users.set(username.toLowerCase(), { hash, displayName: username, createdAt: Date.now() });
      const token = generateToken({ username: username.toLowerCase(), display: username });
      return json(res, 200, { token, username: username.toLowerCase(), display: username });
    }

    // POST /api/login
    if (pathname === '/api/login' && method === 'POST') {
      if (!rateLimit(ip, 15, 15 * 60 * 1000)) return json(res, 429, { error: 'Too many attempts. Wait 15 minutes.' });
      const { username, password } = await readBody(req);
      if (!username || !password) return json(res, 400, { error: 'Username and password required' });

      const user = users.get(username.toLowerCase());
      if (!user) return json(res, 401, { error: 'Invalid username or password' });

      const valid = await verifyPassword(password, user.hash);
      if (!valid) return json(res, 401, { error: 'Invalid username or password' });

      const token = generateToken({ username: username.toLowerCase(), display: user.displayName });
      return json(res, 200, { token, username: username.toLowerCase(), display: user.displayName });
    }

    // ── All routes below require auth ──────────────────────────────────────
    const user = auth(req);
    if (!user && pathname !== '/api/register' && pathname !== '/api/login') {
      return json(res, 401, { error: 'Login required' });
    }

    // GET /api/status
    if (pathname === '/api/status' && method === 'GET') {
      const keys = loadKeys();
      return json(res, 200, {
        username: user.username,
        display:  user.display,
        activeKeyId: getCurrentKeyId(),
        totalKeys: Object.keys(keys).length,
        totalMessages: messages.length,
        myMessages: messages.filter(m => m.owner === user.username).length,
        serverTime: new Date().toISOString()
      });
    }

    // POST /api/encode
    if (pathname === '/api/encode' && method === 'POST') {
      if (!rateLimit(ip, 60, 60 * 1000)) return json(res, 429, { error: 'Slow down — 60 encodes/min max' });
      const { message, label, isPublic } = await readBody(req);
      if (!message || typeof message !== 'string') return json(res, 400, { error: 'message is required' });
      if (message.length > 10000) return json(res, 400, { error: 'Message too long (max 10 000 chars)' });

      const keys    = loadKeys();
      const keyId   = getCurrentKeyId();
      const encoded = encodeMessage(message, keys[keyId], keyId);

      const entry = {
        id:        msgIdSeq++,
        owner:     user.username,
        display:   user.display,
        label:     (typeof label === 'string' && label.trim()) ? label.trim().slice(0, 80) : 'Untitled',
        encoded,
        isPublic:  isPublic === true,
        createdAt: Date.now()
      };
      messages.push(entry);

      return json(res, 200, { encoded, id: entry.id, isPublic: entry.isPublic });
    }

    // POST /api/decode
    if (pathname === '/api/decode' && method === 'POST') {
      if (!rateLimit(ip, 60, 60 * 1000)) return json(res, 429, { error: 'Slow down' });
      const { encoded } = await readBody(req);
      if (!encoded || typeof encoded !== 'string') return json(res, 400, { error: 'encoded is required' });

      const keys   = loadKeys();
      const decoded = decodeMessage(encoded, keys);
      return json(res, 200, { message: decoded });
    }

    // GET /api/messages  — returns public ones + my own private ones
    if (pathname === '/api/messages' && method === 'GET') {
      const visible = messages
        .filter(m => m.isPublic || m.owner === user.username)
        .sort((a, b) => b.createdAt - a.createdAt)
        .map(m => ({
          id:        m.id,
          owner:     m.display,
          label:     m.label,
          encoded:   m.encoded,
          isPublic:  m.isPublic,
          mine:      m.owner === user.username,
          createdAt: m.createdAt
        }));
      return json(res, 200, { messages: visible });
    }

    // DELETE /api/messages/:id — owner only
    if (pathname.startsWith('/api/messages/') && method === 'DELETE') {
      const id  = parseInt(pathname.split('/').pop(), 10);
      const idx = messages.findIndex(m => m.id === id && m.owner === user.username);
      if (idx === -1) return json(res, 404, { error: 'Not found or not yours' });
      messages.splice(idx, 1);
      return json(res, 200, { ok: true });
    }

    // POST /api/rotate-key
    if (pathname === '/api/rotate-key' && method === 'POST') {
      const newKeyId = rotateKey();
      return json(res, 200, { ok: true, newKeyId });
    }

    return json(res, 404, { error: 'Not found' });

  } catch (err) {
    console.error('[Server error]', err.message);
    return json(res, 500, { error: 'Internal server error' });
  }
});

server.listen(PORT, () => {
  loadKeys(); // bootstrap if needed
  console.log(`\n╔══════════════════════════════════════╗`);
  console.log(`║     CIPHERLANG SERVER STARTED        ║`);
  console.log(`╠══════════════════════════════════════╣`);
  console.log(`║  URL  : http://localhost:${PORT}         ║`);
  console.log(`║  Deps : zero (pure Node.js built-ins)║`);
  console.log(`╚══════════════════════════════════════╝\n`);
});
