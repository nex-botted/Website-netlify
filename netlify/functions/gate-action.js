const { getStore } = require('@netlify/blobs');

function json(data, status = 200) {
  return {
    statusCode: status,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data)
  };
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

  const { sid, step } = body;
  if (!sid || typeof step !== 'number') {
    return json({ ok: false, error: 'Invalid parameters' }, 400);
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
  if (session.expiresAt < now) {
    return json({ ok: false, error: 'Session expired' }, 410);
  }

  if (step !== session.step + 1) {
    return json({ ok: false, error: 'Invalid step progression' }, 400);
  }

  session.step = step;
  session.stepTimestamps = session.stepTimestamps || {};
  session.stepTimestamps[`step${step}`] = now;

  await store.setJSON(`session:${sid}`, session);

  return json({ ok: true, step });
};

exports.config = { path: '/api/gate-action' };
