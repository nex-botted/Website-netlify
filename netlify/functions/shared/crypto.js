/**
 * shared/crypto.js
 * CommonJS version (Netlify-compatible)
 */

const crypto = require('crypto');

// ── Base58 ─────────────────────────────────────────────
const B58_ALPHA = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function b58enc(buf) {
  const bytes = buf instanceof Buffer ? buf : Buffer.from(buf);
  let digits = [0];

  for (let i = 0; i < bytes.length; i++) {
    let carry = bytes[i];
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j] << 8;
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }

  for (let i = 0; i < bytes.length && bytes[i] === 0; i++) {
    digits.push(0);
  }

  return digits.reverse().map(d => B58_ALPHA[d]).join('');
}

function b58decBuf(str) {
  try {
    let decoded = BigInt(0);
    let base = BigInt(1);

    for (let i = str.length - 1; i >= 0; i--) {
      const idx = B58_ALPHA.indexOf(str[i]);
      if (idx < 0) return null;
      decoded += base * BigInt(idx);
      base *= BigInt(58);
    }

    let hex = decoded.toString(16);
    if (hex.length % 2) hex = '0' + hex;

    return Buffer.from(hex, 'hex');
  } catch {
    return null;
  }
}

// ── Env helpers ────────────────────────────────────────
function getPepper() {
  const p = process.env.KEY_PEPPER;
  if (!p) throw new Error('KEY_PEPPER env var is not set');
  return p;
}

// ── Key generation ─────────────────────────────────────
function deriveSignature(keyId, entropy) {
  const msg = Buffer.concat([
    Buffer.from('v1', 'utf8'),
    Buffer.from(keyId, 'utf8'),
    entropy,
  ]);

  return crypto
    .createHmac('sha256', getPepper())
    .update(msg)
    .digest()
    .slice(0, 12);
}

function generateKey(keyId) {
  const entropy = crypto.randomBytes(16);
  const sig = deriveSignature(keyId, entropy);

  return `incognito_v1_${keyId}_${b58enc(entropy)}_${b58enc(sig)}`;
}

function verifyKeySignature(rawKey) {
  try {
    const parts = rawKey.split('_');

    if (
      parts.length !== 5 ||
      parts[0] !== 'incognito' ||
      parts[1] !== 'v1'
    ) {
      return { ok: false };
    }

    const [, , keyId, b58entropy, b58sig] = parts;

    const entropyBuf = b58decBuf(b58entropy);
    const sigBuf = b58decBuf(b58sig);

    if (!entropyBuf || !sigBuf) return { ok: false };

    const expected = deriveSignature(keyId, entropyBuf);

    if (sigBuf.length !== expected.length) return { ok: false };

    const match = crypto.timingSafeEqual(sigBuf, expected);

    return { ok: match, keyId: match ? keyId : undefined };
  } catch {
    return { ok: false };
  }
}

// ── HWID hashing ───────────────────────────────────────
function hashHwid(hwidHex) {
  return crypto
    .createHmac('sha256', getPepper())
    .update(hwidHex)
    .digest('hex');
}

// ── Token signing ──────────────────────────────────────
function signToken(data) {
  const payload = JSON.stringify(data);

  const mac = crypto
    .createHmac('sha256', getPepper())
    .update(payload)
    .digest('hex')
    .slice(0, 16);

  return Buffer.from(payload).toString('base64url') + '.' + mac;
}

function verifyToken(token) {
  try {
    const [b64, mac] = token.split('.');
    if (!b64 || !mac) return null;

    const payload = Buffer.from(b64, 'base64url').toString('utf8');

    const expected = crypto
      .createHmac('sha256', getPepper())
      .update(payload)
      .digest('hex')
      .slice(0, 16);

    if (mac.length !== expected.length) return null;

    if (
      !crypto.timingSafeEqual(
        Buffer.from(mac),
        Buffer.from(expected)
      )
    ) {
      return null;
    }

    return JSON.parse(payload);
  } catch {
    return null;
  }
}

// ── AES encryption ─────────────────────────────────────
function encryptPayload(obj, sessionSaltHex) {
  const masterKey = process.env.AES_MASTER_KEY;
  if (!masterKey) throw new Error('AES_MASTER_KEY not set');

  const salt = Buffer.from(sessionSaltHex, 'hex');

  const key = crypto.hkdfSync(
    'sha256',
    Buffer.from(masterKey, 'hex'),
    salt,
    Buffer.from('incognito-v1'),
    32
  );

  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

  const ct = Buffer.concat([
    cipher.update(JSON.stringify(obj), 'utf8'),
    cipher.final()
  ]);

  const tag = cipher.getAuthTag();

  return {
    iv: iv.toString('hex'),
    salt: sessionSaltHex,
    tag: tag.toString('hex'),
    ct: ct.toString('hex')
  };
}

// ── EXPORTS ────────────────────────────────────────────
module.exports = {
  b58enc,
  getPepper,
  deriveSignature,
  generateKey,
  verifyKeySignature,
  hashHwid,
  signToken,
  verifyToken,
  encryptPayload
};
