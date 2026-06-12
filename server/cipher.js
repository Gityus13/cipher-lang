/**
 * CipherLang Core Engine
 *
 * Layer 1: AES-256-GCM (real cryptography)
 * Layer 2: Custom symbolic "secret language" format
 *
 * Security relies on AES-256-GCM, NOT on the symbol encoding.
 * The symbol layer is purely aesthetic — obscurity on top of real crypto.
 */

const crypto = require('crypto');

// ─── Symbol Alphabet ─────────────────────────────────────────────────────────
// 256 unique multi-char symbols, one per byte value (0-255)
// Built algorithmically from character pools
const GREEK = ['α','β','γ','δ','ε','ζ','η','θ','ι','κ','λ','μ','ν','ξ','ο','π','ρ','σ','τ','υ','φ','χ','ψ','ω'];
const CYRILLIC = ['Ж','Щ','Ф','Ю','Я','Э','Ъ','Ь','Ш','Ч','Ц','Х','Й'];
const DIGITS = ['0','1','2','3','4','5','6','7','8','9'];
const ARROWS = ['→','←','↑','↓','↗','↘','↙','↖','⇒','⇐','⇑','⇓'];
const MATH = ['∑','∏','∆','∇','∂','∞','∅','∈','∉','⊕','⊗','⊙','⊚'];
const GEOMETRIC = ['◆','◇','●','○','■','□','▲','△','▼','▽','◉','◎','⬟','⬠','⬡'];
const RUNES = ['ᚠ','ᚢ','ᚦ','ᚨ','ᚱ','ᚲ','ᚷ','ᚹ','ᚺ','ᚾ','ᛁ','ᛃ','ᛇ','ᛈ','ᛉ','ᛊ','ᛏ','ᛒ','ᛖ','ᛗ','ᛚ','ᛜ','ᛞ','ᛟ'];

// Build a 256-entry symbol table deterministically
function buildSymbolTable() {
  const table = [];
  const prefixes = ['Δ','Ω','Λ','Σ','Ψ','Θ','Ξ','Γ'];

  // Each symbol: prefix + 1-2 alphanumeric chars, ensuring uniqueness
  for (let i = 0; i < 256; i++) {
    const prefix = prefixes[i % prefixes.length];
    const hi = Math.floor(i / 16).toString(16).toUpperCase();
    const lo = (i % 16).toString(16).toUpperCase();
    table.push(`${prefix}${hi}${lo}`);
  }
  return table;
}

const SYMBOL_TABLE = buildSymbolTable();
const SYMBOL_MAP = new Map(SYMBOL_TABLE.map((sym, i) => [sym, i]));

// Separator between tokens (not a valid symbol char)
const TOKEN_SEP = '·';
// Segment separator (between IV, auth tag, ciphertext sections)
const SEGMENT_SEP = '::';
// Message envelope markers
const ENVELOPE_START = '⟦';
const ENVELOPE_END = '⟧';
// Key ID prefix
const KEYID_PREFIX = 'KID';

// ─── Noise System ──────────────────────────────────────────────────────────
// Adds random "noise tokens" at random positions so same input ≠ same output
// Noise tokens are prefixed with a distinct marker not in SYMBOL_TABLE

const NOISE_MARKER = 'N';
const NOISE_CHARS = 'ABCDEFGHJKLMNPQRSTUVWXYZ2345679';

function generateNoiseToken() {
  const len = 2 + Math.floor(Math.random() * 2);
  let s = NOISE_MARKER;
  for (let i = 0; i < len; i++) s += NOISE_CHARS[Math.floor(Math.random() * NOISE_CHARS.length)];
  return s;
}

function isNoiseToken(token) {
  return token.startsWith(NOISE_MARKER) && !token.startsWith('NA') === false
    ? token[0] === NOISE_MARKER && NOISE_CHARS.includes(token[1])
    : false;
}

// Better check: noise tokens start with 'N' followed by NOISE_CHARS
function isNoise(token) {
  if (!token.startsWith(NOISE_MARKER)) return false;
  if (token.length < 3) return false;
  return [...token.slice(1)].every(c => NOISE_CHARS.includes(c));
}

// Insert noise every N real tokens (non-deterministic positions)
function injectNoise(tokens) {
  const result = [];
  const noiseFreq = 3 + Math.floor(Math.random() * 3); // every 3-5 tokens
  for (let i = 0; i < tokens.length; i++) {
    result.push(tokens[i]);
    if ((i + 1) % noiseFreq === 0) {
      result.push(generateNoiseToken());
    }
  }
  // Random trailing noise
  if (Math.random() > 0.5) result.push(generateNoiseToken());
  return result;
}

function stripNoise(tokens) {
  return tokens.filter(t => !isNoise(t));
}

// ─── Byte ↔ Symbol Conversion ───────────────────────────────────────────────

function bytesToSymbols(buffer) {
  return Array.from(buffer).map(byte => SYMBOL_TABLE[byte]);
}

function symbolsToBytes(symbols) {
  const bytes = [];
  for (const sym of symbols) {
    if (!SYMBOL_MAP.has(sym)) throw new Error(`Unknown symbol: ${sym}`);
    bytes.push(SYMBOL_MAP.get(sym));
  }
  return Buffer.from(bytes);
}

// ─── AES-256-GCM Encryption ─────────────────────────────────────────────────

const IV_LENGTH = 12;  // 96 bits for GCM
const TAG_LENGTH = 16; // 128-bit auth tag
const KEY_LENGTH = 32; // 256-bit key

function normalizeKey(key) {
  // Always produce a 32-byte key from whatever string/buffer is given
  return crypto.createHash('sha256').update(key).digest();
}

function encrypt(plaintext, keyMaterial) {
  const key = normalizeKey(keyMaterial);
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

  const encrypted = Buffer.concat([
    cipher.update(plaintext, 'utf8'),
    cipher.final()
  ]);
  const tag = cipher.getAuthTag();

  return { iv, tag, ciphertext: encrypted };
}

function decrypt(iv, tag, ciphertext, keyMaterial) {
  const key = normalizeKey(keyMaterial);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);

  const decrypted = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final()
  ]);
  return decrypted.toString('utf8');
}

// ─── Encode: plaintext → secret language ────────────────────────────────────

function encodeMessage(plaintext, keyMaterial, keyId) {
  // Step 1: AES-256-GCM encrypt
  const { iv, tag, ciphertext } = encrypt(plaintext, keyMaterial);

  // Step 2: Convert each buffer to symbol arrays
  const ivSymbols = bytesToSymbols(iv);
  const tagSymbols = bytesToSymbols(tag);
  const ctSymbols = bytesToSymbols(ciphertext);

  // Step 3: Inject noise into ciphertext symbols only (IV/tag must stay clean)
  const noisyCt = injectNoise(ctSymbols);

  // Step 4: Format as secret language string
  // Format: ⟦KID<keyId>::<iv_tokens>::<tag_tokens>::<noisy_ct_tokens>⟧
  const ivPart = ivSymbols.join(TOKEN_SEP);
  const tagPart = tagSymbols.join(TOKEN_SEP);
  const ctPart = noisyCt.join(TOKEN_SEP);

  return `${ENVELOPE_START}${KEYID_PREFIX}${keyId}${SEGMENT_SEP}${ivPart}${SEGMENT_SEP}${tagPart}${SEGMENT_SEP}${ctPart}${ENVELOPE_END}`;
}

// ─── Decode: secret language → plaintext ────────────────────────────────────

function decodeMessage(encoded, keys) {
  // Unwrap envelope
  if (!encoded.startsWith(ENVELOPE_START) || !encoded.endsWith(ENVELOPE_END)) {
    throw new Error('Invalid cipher format: missing envelope markers');
  }

  const inner = encoded.slice(ENVELOPE_START.length, -ENVELOPE_END.length);
  const segments = inner.split(SEGMENT_SEP);

  if (segments.length !== 4) {
    throw new Error(`Invalid cipher format: expected 4 segments, got ${segments.length}`);
  }

  const [kidSegment, ivSegment, tagSegment, ctSegment] = segments;

  // Extract key ID
  if (!kidSegment.startsWith(KEYID_PREFIX)) throw new Error('Missing key ID');
  const keyId = kidSegment.slice(KEYID_PREFIX.length);

  if (!keys[keyId]) throw new Error(`Unknown key ID: ${keyId}`);
  const keyMaterial = keys[keyId];

  // Parse tokens
  const ivTokens = ivSegment.split(TOKEN_SEP).filter(Boolean);
  const tagTokens = tagSegment.split(TOKEN_SEP).filter(Boolean);
  const ctTokensNoisy = ctSegment.split(TOKEN_SEP).filter(Boolean);
  const ctTokens = stripNoise(ctTokensNoisy);

  // Convert back to buffers
  const iv = symbolsToBytes(ivTokens);
  const tag = symbolsToBytes(tagTokens);
  const ciphertext = symbolsToBytes(ctTokens);

  // Decrypt
  return decrypt(iv, tag, ciphertext, keyMaterial);
}

module.exports = { encodeMessage, decodeMessage, SYMBOL_TABLE };
