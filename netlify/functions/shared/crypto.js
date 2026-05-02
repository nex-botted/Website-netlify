/**
 * shared/crypto.js
 * CommonJS version (Netlify-compatible)
 */

const crypto = require('crypto');

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

function getPepper() {
  const p = process.env.KEY_PEPPER;
  if (!p) throw new Error('KEY_PEPPER env var is not set');
  return p;
}

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

function hashHwid(hwidHex) {
  return crypto
    .createHmac('sha256', getPepper())
    .update(hwidHex)
    .digest('hex');
}

function signToken(data) {
  const now = Date.now();
  const payloadObj = {
    ...data,
    iat: data.iat || now,
    nbf: data.nbf || now - 5000,
    jti: data.jti || crypto.randomBytes(16).toString('hex')
  };
  const payload = JSON.stringify(payloadObj);
  const iv = crypto.randomBytes(12);
  const encKey = crypto
    .createHash('sha256')
    .update(String(process.env.TOKEN_ENC_KEY || getPepper()))
    .digest();
  const cipher = crypto.createCipheriv('aes-256-gcm', encKey, iv);
  const ciphertext = Buffer.concat([cipher.update(payload, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  const body = Buffer.concat([iv, tag, ciphertext]).toString('base64url');
  const mac = crypto.createHmac('sha256', getPepper()).update(body).digest('hex').slice(0, 32);
  return `${body}.${mac}`;
}

function verifyToken(token) {
  try {
    const [body, mac] = token.split('.');
    if (!body || !mac) return null;
    const expected = crypto.createHmac('sha256', getPepper()).update(body).digest('hex').slice(0, 32);

    if (mac.length !== expected.length) return null;

    if (
      !crypto.timingSafeEqual(
        Buffer.from(mac),
        Buffer.from(expected)
      )
    ) {
      return null;
    }
    const packed = Buffer.from(body, 'base64url');
    if (packed.length < 29) return null;
    const iv = packed.subarray(0, 12);
    const tag = packed.subarray(12, 28);
    const ciphertext = packed.subarray(28);
    const encKey = crypto
      .createHash('sha256')
      .update(String(process.env.TOKEN_ENC_KEY || getPepper()))
      .digest();
    const decipher = crypto.createDecipheriv('aes-256-gcm', encKey, iv);
    decipher.setAuthTag(tag);
    const payload = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
    const data = JSON.parse(payload);
    const now = Date.now();
    if (typeof data.nbf === 'number' && data.nbf > now + 5000) return null;
    if (typeof data.exp === 'number' && data.exp < now) return null;
    return data;
  } catch {
    return null;
  }
}

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
