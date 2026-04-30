/**
 * GET /api/get-key?sid=<sessionId>
 * 
 * Called after completing all linkvertise steps.
 * Returns the generated key tied to the session.
 */

import { getStore } from '@netlify/blobs';
import { generateKey } from './shared/crypto.js';

function json(data, status = 200) {
  return {
    statusCode: status,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data)
  };
}

export async function handler(event, context) {
  if (event.httpMethod !== 'GET') {
    return json({ ok: false, error: 'Method not allowed' }, 405);
  }

  const params = event.queryStringParameters || {};
  const sessionId = params.sid;

  if (!sessionId) {
    return json({ ok: false, error: 'Missing session ID' }, 400);
  }

  const store = getStore({ name: 'incognito-sessions', consistency: 'strong' });

  const session = await store.get(`session:${sessionId}`, { type: 'json' });

  if (!session) {
    return json({ ok: false, error: 'Invalid session' }, 404);
  }

  const now = Date.now();

  if (session.expiresAt < now) {
    return json({ ok: false, error: 'Session expired' }, 410);
  }

  // Must complete all steps before getting key
  if (session.step < 4) {
    return json({ ok: false, error: 'Key not ready yet' }, 403);
  }

  // If key doesn't exist yet → generate it
  if (!session.key) {
    session.key = generateKey(session.sessionId);
    await store.setJSON(`session:${sessionId}`, session);
  }

  return json({
    ok: true,
    key: session.key
  });
}

export const config = { path: '/api/get-key' };
