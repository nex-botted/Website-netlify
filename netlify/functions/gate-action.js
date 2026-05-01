const { getStore } = require('@netlify/blobs');
const crypto = require('crypto');

const ALLOWED_ACTIONS = new Set(['start_1', 'complete_1', 'complete_2', 'complete_3']);
const STEP_DELAY_MS = 5000;
const KEY_TTL_MS = 24 * 60 * 60 * 1000;

function json(data, status = 200) {
  return {
    statusCode: status,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  };
}

function invalid() {
  return json({ ok: false, error: 'Invalid session' }, 400);
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

  const { sessionId, action } = body || {};

  if (typeof sessionId !== 'string' || !/^[a-f0-9]{32}$/i.test(sessionId)) {
    return invalid();
  }

  if (typeof action !== 'string' || !ALLOWED_ACTIONS.has(action)) {
    return json({ ok: false, error: 'Invalid action' }, 400);
  }

  const store = getStore({
    name: 'incognito-sessions',
    consistency: 'strong',
  });

  const storeKey = `session:${sessionId}`;
  const session = await store.get(storeKey, { type: 'json' });

  if (!session || session.sessionId !== sessionId) {
    return invalid();
  }

  const now = Date.now();

  if (typeof session.expiresAt !== 'number' || session.expiresAt <= now) {
    return json({ ok: false, error: 'Session expired' }, 410);
  }

  const step = Number.isInteger(session.step) ? session.step : 0;
  const stepTimestamps = session.stepTimestamps && typeof session.stepTimestamps === 'object'
    ? session.stepTimestamps
    : {};

  if (step >= 4) {
    return json({ ok: false, error: 'already_completed' }, 409);
  }

  const expectedActionByStep = {
    0: 'start_1',
    1: 'complete_1',
    2: 'complete_2',
    3: 'complete_3',
  };

  if (action !== expectedActionByStep[step]) {
    return json({ ok: false, error: 'step_order' }, 409);
  }

  if (step > 0) {
    const prevStepKey = `step${step}`;
    const prevTs = stepTimestamps[prevStepKey];

    if (typeof prevTs !== 'number') {
      return json({ ok: false, error: 'step_order' }, 409);
    }

    if (now - prevTs < STEP_DELAY_MS) {
      return json({ ok: false, error: 'rate_limited' }, 429);
    }
  }

  const nextStep = step + 1;
  const nextTimestamps = {
    ...stepTimestamps,
    [`step${nextStep}`]: now,
  };

  const nextSession = {
    ...session,
    step: nextStep,
    stepTimestamps: nextTimestamps,
  };

  if (nextStep === 4) {
    nextSession.key = crypto.randomBytes(32).toString('hex').toUpperCase();
    nextSession.keyExpiresAt = now + KEY_TTL_MS;
  }

  await store.setJSON(storeKey, nextSession);

  if (nextStep === 4) {
    return json({ ok: true, key: nextSession.key });
  }

  return json({ ok: true });
};

exports.config = { path: '/api/gate-action' };
