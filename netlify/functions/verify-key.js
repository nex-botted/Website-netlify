const { getStore } = require('@netlify/blobs');
const crypto = require('crypto');
const {
  verifyKeySignature,
  hashHwid,
  encryptPayload
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
    event.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
    event.headers['client-ip'] ||
    '0.0.0.0'
  );
}

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') {
    return json({ ok: false, error: 'Method not allowed' }, 405);
  }

  let body;
  try {
    body = event.body ? JSON.parse(event.body) : {};
  } catch {
    return json({ ok: false, error: 'Invalid JSON body' }, 400);
  }

  const { key, hwid, sid } = body;

  if (!key || !hwid || !sid) {
    return json({ ok: false, error: 'Missing parameters' }, 400);
  }

  if (!/^[a-f0-9]{32}$/i.test(sid)) {
    return json({ ok: false, error: 'Invalid session' }, 400);
  }

  if (!/^[0-9a-f]{128}$/i.test(hwid)) {
    return json({ ok: false, error: 'Invalid HWID format' }, 400);
  }

  const sigCheck = verifyKeySignature(key);
  if (!sigCheck.ok) {
    return json({ ok: false, error: 'Invalid key' }, 403);
  }

  const store = getStore({
    name: 'incognito-sessions',
    consistency: 'strong',
    siteID: process.env.NETLIFY_SITE_ID,
    token: process.env.NETLIFY_AUTH_TOKEN
  });

  const session = await store.get(`session:${sid}`, { type: 'json' });
  if (!session) return json({ ok: false, error: 'Invalid session' }, 404);

  const now = Date.now();
  const ip = getClientIp(event);
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

  const providedKey = Buffer.from(String(key));
  const storedKey = Buffer.from(session.key);
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

  return json({ ok: true, payload });
};

exports.config = { path: '/api/verify-key' };
