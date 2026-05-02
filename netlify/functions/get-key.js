const { getStore } = require('@netlify/blobs');
const crypto = require('crypto');
const { verifyToken } = require('./shared/crypto');

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

const IP_WINDOW_MS = 5 * 60 * 1000;
const IP_MAX_REQUESTS = 20;
function hashUa(ua) {
  return crypto.createHash('sha256').update(String(ua || '')).digest('hex').slice(0, 16);
}

exports.handler = async (event) => {
  if (event.httpMethod !== 'GET') {
    return json({ ok: false, error: 'Method not allowed' }, 405);
  }

  const sessionId = event.queryStringParameters?.sid;
  const st = event.queryStringParameters?.st;
  if (typeof sessionId !== 'string' || !/^[a-f0-9]{32}$/i.test(sessionId)) {
    return json({ ok: false, error: 'Invalid session' }, 400);
  }

  const ip = getClientIp(event);
  const uaHash = hashUa(event.headers?.['user-agent'] || '');
  const tokenData = verifyToken(String(st || ''));
  if (!tokenData || tokenData.sid !== sessionId || tokenData.ip !== ip || tokenData.ua !== uaHash) {
    return json({ ok: false, error: 'Invalid session token' }, 403);
  }
  const clientNonce = String(event.headers?.['x-inc-nonce'] || '');
  if (!/^[a-f0-9]{32}$/i.test(clientNonce)) {
    return json({ ok: false, error: 'invalid_nonce' }, 400);
  }

  const store = getStore({
    name: 'incognito-sessions',
    consistency: 'strong',
    siteID: process.env.NETLIFY_SITE_ID,
    token: process.env.NETLIFY_AUTH_TOKEN
  });

  const session = await store.get(`session:${sessionId}`, { type: 'json' });
  if (!session) return json({ ok: false, error: 'Invalid session' }, 404);
  if (!session.nonce || session.nonce !== clientNonce) {
    return json({ ok: false, error: 'invalid_nonce' }, 403);
  }

  const now = Date.now();
  const ipRateKey = `rl:getkey:ip:${ip}`;
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

  if (session.step < 4) {
    return json({ ok: false, error: 'Key not ready yet' }, 403);
  }

  if (!session.key || !session.keyExpiresAt || session.keyExpiresAt < now) {
    return json({ ok: false, error: 'key_expired' }, 410);
  }

  return json({ ok: true, key: session.key });
};

exports.config = { path: '/api/get-key' };
