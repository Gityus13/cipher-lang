# 🔐 CipherLang v2.0

**AES-256-GCM encrypted secret language system.** Messages are encrypted with real cryptography, then encoded into a custom symbolic format. A message vault lets you save messages as public (visible to all users) or private (visible only to you).

```
⟦KID2B1C::Ξ5E·ΩC1·Θ65::Λ0A·Δ90·Σ5B::ΓF2·NQR·Δ1A·Ω3F·...⟧
```

---

## 🚀 Quick Start (all platforms)

### Requirements
- **Node.js 18+** — https://nodejs.org/en/download/
- **Zero npm dependencies** — everything uses Node.js built-ins

### Install & Run

```bash
# 1. Unzip
unzip cipher-lang.zip
cd cipher-lang

# 2. Setup (checks Node version, creates .env, runs self-test)
node scripts/setup.js

# 3. Start
npm start
```

Open **http://localhost:3000** — register an account and start encoding.

### Windows (PowerShell or CMD)
```powershell
cd cipher-lang
node scripts/setup.js
npm start
```

### Development mode (auto-restart)
```bash
npm run dev
```

---

## 📁 Project Structure

```
cipher-lang/
├── server/
│   ├── index.js        ← HTTP server, all API routes (zero deps)
│   ├── cipher.js       ← AES-256-GCM + symbol encoding engine
│   ├── auth.js         ← scrypt password hashing + HMAC-SHA256 tokens
│   ├── keyManager.js   ← Key generation, file storage, rotation
│   └── package.json    ← Zero dependencies
├── client/
│   └── index.html      ← Full dark UI (single file, no build step)
├── scripts/
│   └── setup.js        ← Cross-platform setup + self-test
├── .env.example        ← Copy to .env before starting
├── .gitignore          ← Excludes .env, .keys.json, node_modules
└── README.md
```

---

## 🌐 API Reference

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/api/register` | — | Create account |
| POST | `/api/login` | — | Get session token |
| GET  | `/api/status` | ✓ | Server & key info |
| POST | `/api/encode` | ✓ | Encrypt → CipherLang, save to vault |
| POST | `/api/decode` | ✓ | Decode CipherLang → plaintext |
| GET  | `/api/messages` | ✓ | List vault (public + your private) |
| DELETE | `/api/messages/:id` | ✓ | Delete your own message |
| POST | `/api/rotate-key` | ✓ | Generate new AES key |

### Encode payload
```json
{
  "message":  "your secret text",
  "label":    "Note for Alice",
  "isPublic": true
}
```

---

## 🔒 Security Architecture

### Layer 1 — Cryptography (real security)
1. Plaintext → **AES-256-GCM** with a fresh random **96-bit IV** per message
2. GCM generates a **128-bit authentication tag** (tamper detection)
3. Encryption key lives **server-side only** — never touches the browser
4. Passwords hashed with **scrypt** (memory-hard, NIST SP 800-132)
5. Sessions signed with **HMAC-SHA256**, 24 h expiry

### Layer 2 — Secret language (aesthetic)
6. Every byte mapped to a unique 3-char symbol: `Δ00`…`ΓFF` (8 prefix chars × 256 combos)
7. Random **noise tokens** (`NXX`) injected at random intervals → same plaintext ≠ same output
8. Envelope: `⟦KID<id>::iv_symbols::authtag_symbols::ciphertext+noise⟧`

### Visibility system
- **Public** — ciphertext saved to vault, visible to all logged-in users; still AES-encrypted, decoding requires this server
- **Private** — saved to vault, only the owner can see or decode it

---

## ⚙️ Configuration

```env
PORT=3000
NODE_ENV=development
JWT_SECRET=your-64-char-random-secret
```

Keys are auto-bootstrapped in `.keys.json` on first start. Up to 10 keys retained for backward decoding.

---

## 🖥️ Production Notes

```bash
NODE_ENV=production PORT=8080 JWT_SECRET=<long-secret> npm start
```

Recommendations for production:
- Reverse proxy (nginx / Caddy) with TLS/HTTPS
- Process manager: `pm2 start server/index.js --name cipherlang`
- Replace in-memory user store with SQLite or PostgreSQL
- Replace file-based key store with AWS KMS / HashiCorp Vault

---

> Security note: the symbol encoding is purely aesthetic on top of AES-256-GCM.
> The cryptography — not the symbols — is what makes messages secure.
