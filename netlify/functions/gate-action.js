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
    body = JSON.parse(event.body || '{}');
  } catch {
    return json({ ok: false, error: 'Invalid JSON' }, 400);
  }

  const { sessionId, action } = body;

  if (!sessionId || !action) {
    return json({ ok: false, error: 'Missing params' }, 400);
  }

  const store = getStore({
    name: 'incognito-sessions',
    consistency: 'strong',
  });

  const key = `session:${sessionId}`;
  let session = await store.get(key, { type: 'json' });

  if (!session) {
    return json({ ok: false, error: 'Invalid session' }, 404);
  }

  const now = Date.now();

  if (session.expiresAt && session.expiresAt < now) {
    return json({ ok: false, error: 'Session expired' }, 410);
  }

  // initialize
  session.step = session.step || 0;
  session.timestamps = session.timestamps || {};

  // ---- ACTION HANDLING ----
  if (action === 'start_1') {
    session.step = 1;
    session.timestamps.step1 = now;
  }

  else if (action === 'complete_1') {
    if (session.step < 1) {
      return json({ ok: false, error: 'Step 1 not started' });
    }

    const diff = now - session.timestamps.step1;
    if (diff < 5000) {
      return json({ ok: false, waitMs: 5000 - diff });
    }

    session.step = 2;
    session.timestamps.step2 = now;
  }

  else if (action === 'complete_2') {
    if (session.step < 2) {
      return json({ ok: false, error: 'Step 2 not ready' });
    }

    const diff = now - session.timestamps.step2;
    if (diff < 5000) {
      return json({ ok: false, waitMs: 5000 - diff });
    }

    session.step = 3;
    session.timestamps.step3 = now;
  }

  else if (action === 'complete_3') {
    if (session.step < 3) {
      return json({ ok: false, error: 'Step 3 not ready' });
    }

    const diff = now - session.timestamps.step3;
    if (diff < 5000) {
      return json({ ok: false, waitMs: 5000 - diff });
    }

    session.step = 4;

    // generate key
    const keyValue = Math.random().toString(36).slice(2, 12).toUpperCase();
    session.key = keyValue;

    await store.setJSON(key, session);

    return json({ ok: true, key: keyValue });
  }

  else {
    return json({ ok: false, error: 'Invalid action' });
  }

  await store.setJSON(key, session);

  return json({ ok: true });
};

exports.config = { path: '/api/gate-action' };
