const { getStore } = require('@netlify/blobs');
const crypto = require('crypto');
const { verifyToken } = require('./shared/crypto');

const ALLOWED_ACTIONS = new Set(['start_1', 'complete_1', 'complete_2', 'complete_3']);
const STEP_DELAY_MS = 5000;
const KEY_TTL_MS = 24 * 60 * 60 * 1000;
const IP_WINDOW_MS = 5 * 60 * 1000;
const IP_MAX_REQUESTS = 60;

function json(data, status = 200) {
  return {
    statusCode: status,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff'
    },
    body: JSON.stringify(data),
  };
}

function invalid() {
  return json({ ok: false, error: 'Invalid session' }, 400);
}

function getClientIp(event) {
  return (
    event.headers?.['x-forwarded-for']?.split(',')[0]?.trim() ||
    event.headers?.['client-ip'] ||
    '0.0.0.0'
  );
}
function hashUa(ua) {
  return crypto.createHash('sha256').update(String(ua || '')).digest('hex').slice(0, 16);
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

exports.handler = async (event) => {
  if (event.httpMethod !== 'POST') {
    return json({ ok: false, error: 'Method not allowed' }, 405);
  }

  if (!hasTrustedOrigin(event)) {
    return json({ ok: false, error: 'forbidden_origin' }, 403);
  }

  let body;
  try {
    body = JSON.parse(event.body || '{}');
  } catch {
    return json({ ok: false, error: 'Invalid JSON' }, 400);
  }

  const { sessionId, action, st } = body || {};

  if (typeof sessionId !== 'string' || !/^[a-f0-9]{32}$/i.test(sessionId)) {
    return invalid();
  }

  if (typeof action !== 'string' || !ALLOWED_ACTIONS.has(action)) {
    return json({ ok: false, error: 'Invalid action' }, 400);
  }

  const ip = getClientIp(event);
  const uaHash = hashUa(event.headers?.['user-agent'] || '');
  const tokenData = verifyToken(String(st || ''));
  if (!tokenData || tokenData.sid !== sessionId || tokenData.ip !== ip || tokenData.ua !== uaHash) {
    return json({ ok: false, error: 'Invalid session token' }, 403);
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

  const ipRateKey = `rl:gate:ip:${ip}`;
  const ipRateRaw = await store.get(ipRateKey, { type: 'json' });
  const ipRecent = ((ipRateRaw?.timestamps) || []).filter(ts => ts > now - IP_WINDOW_MS);
  if (ipRecent.length >= IP_MAX_REQUESTS) {
    return json({ ok: false, error: 'rate_limited' }, 429);
  }
  ipRecent.push(now);
  await store.setJSON(ipRateKey, { timestamps: ipRecent });

  if (typeof session.expiresAt !== 'number' || session.expiresAt <= now) {
    return json({ ok: false, error: 'Session expired' }, 410);
  }

  if (session.ip && session.ip !== ip) {
    return json({ ok: false, error: 'ip_mismatch' }, 403);
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

  if (nextStep === 4) return json({ ok: true });

  return json({ ok: true });
};

exports.config = { path: '/api/gate-action' };
