/**
 * shared/crypto.mjs
 * Shared cryptographic utilities — no external deps, pure Node built-ins.
 */

import crypto from 'crypto';

// ── Base58 (inline, no bs58 dependency) ──────────────────────────────────────
const B58_ALPHA = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

export function b58enc(buf) {
  const bytes = buf instanceof Buffer ? buf : Buffer.from(buf);
  let digits = [0];
  for (let i = 0; i < bytes.length; i++) {
    let carry = bytes[i];
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j] << 8;
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) { digits.push(carry % 58); carry = (carry / 58) | 0; }
  }
  for (let i = 0; i < bytes.length && bytes[i] === 0; i++) digits.push(0);
  return digits.reverse().map(d => B58_ALPHA[d]).join('');
}

// ── Key generation ────────────────────────────────────────────────────────────
// Format: incognito_v1_{keyId}_{Base58(entropy)}_{Base58(sig)}
// Sig = HMAC-SHA256(v1 + keyId + entropy, KEY_PEPPER) truncated to 12 bytes

export function getPepper() {
  const p = Netlify.env.get('KEY_PEPPER');
  if (!p) throw new Error('KEY_PEPPER env var is not set');
  return p;
}

export function deriveSignature(keyId, entropy) {
  const pepper = getPepper();
  const msg = Buffer.concat([
    Buffer.from('v1', 'utf8'),
    Buffer.from(keyId, 'utf8'),
    entropy,
  ]);
  return crypto.createHmac('sha256', pepper).update(msg).digest().slice(0, 12);
}

export function generateKey(keyId) {
  const entropy = crypto.randomBytes(16);
  const sig = deriveSignature(keyId, entropy);
  return `incognito_v1_${keyId}_${b58enc(entropy)}_${b58enc(sig)}`;
}

export function verifyKeySignature(rawKey) {
  try {
    const parts = rawKey.split('_');
    // incognito _ v1 _ keyId _ b58entropy _ b58sig
    if (parts.length !== 5 || parts[0] !== 'incognito' || parts[1] !== 'v1') return { ok: false };
    const [, , keyId, b58entropy, b58sig] = parts;

    // Decode Base58 entropy + sig
    const entropyBuf = b58decBuf(b58entropy);
    const sigBuf     = b58decBuf(b58sig);
    if (!entropyBuf || !sigBuf) return { ok: false };

    const expected = deriveSignature(keyId, entropyBuf);
    if (sigBuf.length !== expected.length) return { ok: false };

    const match = crypto.timingSafeEqual(sigBuf, expected);
    return { ok: match, keyId: match ? keyId : undefined };
  } catch { return { ok: false }; }
}

function b58decBuf(str) {
  try {
    const alphabet = B58_ALPHA;
    let decoded = BigInt(0);
    let base = BigInt(1);
    for (let i = str.length - 1; i >= 0; i--) {
      const idx = alphabet.indexOf(str[i]);
      if (idx < 0) return null;
      decoded += base * BigInt(idx);
      base *= BigInt(58);
    }
    const hex = decoded.toString(16).padStart(2, '0');
    const padded = hex.length % 2 ? '0' + hex : hex;
    return Buffer.from(padded, 'hex');
  } catch { return null; }
}

// ── HWID hashing ──────────────────────────────────────────────────────────────
export function hashHwid(hwidHex) {
  return crypto.createHmac('sha256', getPepper()).update(hwidHex).digest('hex');
}

// ── Session token signing (verifies cookie/param wasn't tampered with) ────────
export function signToken(data) {
  const pepper = getPepper();
  const payload = JSON.stringify(data);
  const mac = crypto.createHmac('sha256', pepper).update(payload).digest('hex').slice(0, 16);
  return Buffer.from(payload).toString('base64url') + '.' + mac;
}

export function verifyToken(token) {
  try {
    const pepper = getPepper();
    const [b64, mac] = token.split('.');
    if (!b64 || !mac) return null;
    const payload = Buffer.from(b64, 'base64url').toString('utf8');
    const expected = crypto.createHmac('sha256', pepper).update(payload).digest('hex').slice(0, 16);
    if (!crypto.timingSafeEqual(Buffer.from(mac, 'utf8'), Buffer.from(expected, 'utf8'))) return null;
    return JSON.parse(payload);
  } catch { return null; }
}

// ── AES-256-GCM payload encryption for executor verify responses ──────────────
export function encryptPayload(obj, sessionSaltHex) {
  const masterKey = Netlify.env.get('AES_MASTER_KEY');
  if (!masterKey) throw new Error('AES_MASTER_KEY not set');
  const salt = Buffer.from(sessionSaltHex, 'hex');
  const key  = crypto.hkdfSync('sha256', Buffer.from(masterKey, 'hex'), salt, Buffer.from('incognito-v1'), 32);
  const iv   = crypto.randomBytes(12);
  const c    = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct   = Buffer.concat([c.update(JSON.stringify(obj), 'utf8'), c.final()]);
  const tag  = c.getAuthTag();
  return { iv: iv.toString('hex'), salt: sessionSaltHex, tag: tag.toString('hex'), ct: ct.toString('hex') };
}
