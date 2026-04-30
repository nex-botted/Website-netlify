const { getStore } = require('@netlify/blobs');
const { generateKey } = require('./shared/crypto');

function json(data, status = 200) {
  return {
    statusCode: status,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data)
  };
}

exports.handler = async (event) => {
  if (event.httpMethod !== 'GET') {
    return json({ ok: false, error: 'Method not allowed' }, 405);
  }

  const sessionId = event.queryStringParameters?.sid;
  if (!sessionId) {
    return json({ ok: false, error: 'Missing session ID' }, 400);
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
  if (session.expiresAt < now) {
    return json({ ok: false, error: 'Session expired' }, 410);
  }

  if (session.step < 4) {
    return json({ ok: false, error: 'Key not ready yet' }, 403);
  }

  if (!session.key) {
    session.key = generateKey(session.sessionId);
    await store.setJSON(`session:${sessionId}`, session);
  }

  return json({ ok: true, key: session.key });
};

exports.config = { path: '/api/get-key' };
