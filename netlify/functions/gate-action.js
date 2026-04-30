/**
 * POST /api/gate-action
 * 
 * Handles progression through Linkvertise steps.
 * 
 * Body: { sid: string, step: number }
 */

import { getStore } from '@netlify/blobs';

function json(data, status = 200) {
  return {
    statusCode: status,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data)
  };
}

export async function handler(event, context) {
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
    return json({ ok: false, error: 'Missing or invalid parameters' }, 400);
  }

  const store = getStore({ name: 'incognito-sessions', consistency: 'strong' });

  const session = await store.get(`session:${sid}`, { type: 'json' });

  if (!session) {
    return json({ ok: false, error: 'Invalid session' }, 404);
  }

  const now = Date.now();

  if (session.expiresAt < now) {
    return json({ ok: false, error: 'Session expired' }, 410);
  }

  // Prevent skipping steps
  if (step !== session.step + 1) {
    return json({ ok: false, error: 'Invalid step progression' }, 400);
  }

  // Update session step
  session.step = step;
  session.stepTimestamps = session.stepTimestamps || {};
  session.stepTimestamps[`step${step}`] = now;

  await store.setJSON(`session:${sid}`, session);

  return json({
    ok: true,
    step: session.step
  });
}

export const config = { path: '/api/gate-action' };
