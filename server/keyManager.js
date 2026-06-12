/**
 * CipherLang Key Manager
 * Handles secure key generation, storage, and rotation
 * Keys are stored in a local JSON file (in production, use a proper KMS)
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const KEYS_FILE = path.join(__dirname, '../.keys.json');
const CURRENT_KEY_FILE = path.join(__dirname, '../.current_key');

// Generate a cryptographically secure 256-bit key
function generateKey() {
  return crypto.randomBytes(32).toString('hex');
}

// Generate a unique key ID
function generateKeyId() {
  return crypto.randomBytes(4).toString('hex').toUpperCase();
}

// Load all keys from disk
function loadKeys() {
  if (!fs.existsSync(KEYS_FILE)) {
    // Bootstrap: create the first key
    const keyId = generateKeyId();
    const key = generateKey();
    const keys = { [keyId]: key };
    fs.writeFileSync(KEYS_FILE, JSON.stringify(keys, null, 2), { mode: 0o600 });
    fs.writeFileSync(CURRENT_KEY_FILE, keyId, { mode: 0o600 });
    console.log(`[KeyManager] Bootstrapped new key: ${keyId}`);
    return keys;
  }

  try {
    const raw = fs.readFileSync(KEYS_FILE, 'utf8');
    return JSON.parse(raw);
  } catch (err) {
    throw new Error('Failed to load keys: ' + err.message);
  }
}

// Get the currently active key ID
function getCurrentKeyId() {
  if (!fs.existsSync(CURRENT_KEY_FILE)) {
    const keys = loadKeys();
    return Object.keys(keys)[0];
  }
  return fs.readFileSync(CURRENT_KEY_FILE, 'utf8').trim();
}

// Rotate: generate a new key, keep old ones for decryption
function rotateKey() {
  const keys = loadKeys();
  const newKeyId = generateKeyId();
  const newKey = generateKey();

  keys[newKeyId] = newKey;

  // Prune to last 10 keys max (retain old ones for decoding)
  const keyIds = Object.keys(keys);
  if (keyIds.length > 10) {
    const toRemove = keyIds.slice(0, keyIds.length - 10);
    for (const id of toRemove) delete keys[id];
    console.log(`[KeyManager] Pruned ${toRemove.length} old key(s)`);
  }

  fs.writeFileSync(KEYS_FILE, JSON.stringify(keys, null, 2), { mode: 0o600 });
  fs.writeFileSync(CURRENT_KEY_FILE, newKeyId, { mode: 0o600 });

  console.log(`[KeyManager] Rotated to new key: ${newKeyId}`);
  return newKeyId;
}

module.exports = { loadKeys, getCurrentKeyId, rotateKey, generateKey, generateKeyId };
