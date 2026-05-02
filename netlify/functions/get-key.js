const { getStore } = require('@netlify/blobs');

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
  if (event.httpMethod !== 'GET') {
    return json({ ok: false, error: 'Method not allowed' }, 405);
  }

  const sessionId = event.queryStringParameters?.sid;
  if (typeof sessionId !== 'string' || !/^[a-f0-9]{32}$/i.test(sessionId)) {
    return json({ ok: false, error: 'Invalid session' }, 400);
  }

  const store = getStore({
    name: 'incognito-sessions',
    consistency: 'strong',
    siteID: process.env.NETLIFY_SITE_ID,
    token: process.env.NETLIFY_AUTH_TOKEN
  });

  const session = await store.get(`session:${sessionId}`, { type: 'json' });
  if (!session) return json({ ok: false, error: 'Invalid session' }, 404);

  const now = Date.now();
  const ip = getClientIp(event);
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
