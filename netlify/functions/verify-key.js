const { getStore } = require('@netlify/blobs');
const crypto = require('crypto');
const {
  verifyKeySignature,
  verifySignedLicenseKey,
  hashHwid,
  encryptPayload,
  decryptAtRest,
  verifyToken
} = require('./shared/crypto');

function json(data, status = 200) {
  return {
    statusCode: status,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff'
    },
    body: JSON.stringify(data)
  };
}

function getClientIp(event) {
  return (
    event.headers?.['x-forwarded-for']?.split(',')[0]?.trim() ||
    event.headers?.['client-ip'] ||
    '0.0.0.0'
  );
}

function hasTrustedOrigin(event) {
  const origin = event.headers?.origin;
  if (!origin) return true;
  try {
    const reqUrl = new URL(event.rawUrl);
    const o = new URL(origin);
    return reqUrl.host === o.host && reqUrl.protocol === o.protocol;
  } catch {
    return false;
  }
}

const IP_WINDOW_MS = 5 * 60 * 1000;
const IP_MAX_REQUESTS = 30;
const BLOCKED_UA_PATTERNS = [
  /sqlmap/i, /nikto/i, /acunetix/i, /nessus/i, /openvas/i, /burpsuite/i, /zap/i, /nmap/i
];

function isSuspiciousRequest(event) {
  const ua = String(event.headers?.['user-agent'] || '');
  const probeHeaders = [
    'x-zap-scan', 'x-attack-proxy', 'x-sqlmap', 'x-pentest-tool'
  ];
  return BLOCKED_UA_PATTERNS.some((rx) => rx.test(ua)) ||
    probeHeaders.some((h) => event.headers?.[h]);
}

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') {
    return json({ ok: false, error: 'Method not allowed' }, 405);
  }
  if (isSuspiciousRequest(event)) {
    return json({ ok: false, error: 'forbidden_client' }, 403);
  }

  if (!hasTrustedOrigin(event)) {
    return json({ ok: false, error: 'forbidden_origin' }, 403);
  }

  let body;
  try {
    body = event.body ? JSON.parse(event.body) : {};
  } catch {
    return json({ ok: false, error: 'Invalid JSON body' }, 400);
  }

  const { key, hwid, sid } = body;
  const st = String(body?.st || '');
  const nonce = String(body?.nonce || event.headers?.['x-inc-nonce'] || '');

  if (!key || !hwid || !sid) {
    return json({ ok: false, error: 'Missing parameters' }, 400);
  }

  if (!/^[a-f0-9]{32}$/i.test(sid)) {
    return json({ ok: false, error: 'Invalid session' }, 400);
  }

  if (!/^[0-9a-f]{128}$/i.test(hwid)) {
    return json({ ok: false, error: 'Invalid HWID format' }, 400);
  }
  const ip = getClientIp(event);
  const uaHash = crypto
    .createHash('sha256')
    .update(String(event.headers?.['user-agent'] || ''))
    .digest('hex')
    .slice(0, 16);
  const tokenData = verifyToken(st);
  if (!tokenData || tokenData.sid !== sid || tokenData.ip !== ip || tokenData.ua !== uaHash) {
    return json({ ok: false, error: 'Invalid session token' }, 403);
  }

  const sigCheck = key.startsWith('incognito_v2_')
    ? verifySignedLicenseKey(key)
    : verifyKeySignature(key);
  if (!sigCheck.ok) {
    return json({ ok: false, error: 'Invalid key' }, 403);
  }

  const revoked = (process.env.REVOKED_KEY_IDS || '')
    .split(',')
    .map(v => v.trim())
    .filter(Boolean);
  if (sigCheck.keyId && revoked.includes(sigCheck.keyId)) {
    return json({ ok: false, error: 'revoked_key' }, 403);
  }

  const store = getStore({
    name: 'incognito-sessions',
    consistency: 'strong',
    siteID: process.env.NETLIFY_SITE_ID,
    token: process.env.NETLIFY_AUTH_TOKEN
  });

  const session = await store.get(`session:${sid}`, { type: 'json' });
  if (!session) return json({ ok: false, error: 'Invalid session' }, 404);
  if (!/^[a-f0-9]{32}$/i.test(nonce) || !session.nonce || nonce !== session.nonce) {
    return json({ ok: false, error: 'invalid_nonce' }, 403);
  }

  const now = Date.now();
  const ipRateKey = `rl:verify:ip:${ip}`;
  const ipRateRaw = await store.get(ipRateKey, { type: 'json' });
  const ipRecent = ((ipRateRaw?.timestamps) || []).filter(ts => ts > now - IP_WINDOW_MS);
  if (ipRecent.length >= IP_MAX_REQUESTS) {
    return json({ ok: false, error: 'rate_limited' }, 429);
  }
  ipRecent.push(now);
  await store.setJSON(ipRateKey, { timestamps: ipRecent });
  if (session.expiresAt < now) {
    return json({ ok: false, error: 'Session expired' }, 410);
  }

  if (session.ip && session.ip !== ip) {
    return json({ ok: false, error: 'ip_mismatch' }, 403);
  }

  const hwidHash = hashHwid(hwid);
  if (session.hwidHash !== hwidHash) {
    return json({ ok: false, error: 'HWID mismatch' }, 403);
  }

  if (!session.key || typeof session.key !== 'string') {
    return json({ ok: false, error: 'Key mismatch' }, 403);
  }

  const decryptedKey = decryptAtRest(session.key);
  if (!decryptedKey) {
    return json({ ok: false, error: 'Key unavailable' }, 500);
  }

  const providedKey = Buffer.from(String(key));
  const storedKey = Buffer.from(decryptedKey);
  if (providedKey.length !== storedKey.length || !crypto.timingSafeEqual(providedKey, storedKey)) {
    return json({ ok: false, error: 'Key mismatch' }, 403);
  }

  if (!session.key || !session.keyExpiresAt || session.keyExpiresAt < now) {
    return json({ ok: false, error: 'key_expired' }, 410);
  }

  const payload = encryptPayload(
    { success: true, ts: now },
    session.sessionId.slice(0, 32)
  );
  await store.setJSON(`session:${sid}`, { ...session, nonce: crypto.randomBytes(16).toString('hex') });

  return json({ ok: true, payload });
};

exports.config = { path: '/api/verify-key' };
