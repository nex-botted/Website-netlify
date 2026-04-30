/**
 * GET /api/get-key?sid=SESSION_ID
 *
 * Called by key.html to retrieve the generated key for display.
 * Also can be polled by the executor to get the key automatically.
 *
 * Returns: { ok, key, expiresAt }
 */

import { getStore } from '@netlify/blobs';

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

export default async (req) => {
  const url = new URL(req.url);
  const sid = url.searchParams.get('sid');

  if (!sid || !/^[0-9a-f]{32}$/.test(sid)) {
    return json({ ok: false, error: 'Invalid session ID' }, 400);
  }

  const store   = getStore({ name: 'incognito-sessions', consistency: 'strong' });
  const session = await store.get(`session:${sid}`, { type: 'json' });

  if (!session) return json({ ok: false, error: 'Session not found' }, 404);
  if (Date.now() > session.expiresAt) return json({ ok: false, error: 'Session expired' }, 403);

  if (session.step < 4 || !session.key) {
    return json({ ok: false, error: 'Key not yet generated', step: session.step }, 202);
  }

  return json({
    ok: true,
    key: session.key,
    expiresAt: new Date(session.stepTimestamps.keyGeneratedAt + 24 * 3600_000).toISOString(),
  });
};

export const config = { path: '/api/get-key' };
