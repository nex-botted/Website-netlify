import { json, verifyToken } from './_shared.js';

export async function onRequestPost(ctx) {
  const body = await ctx.request.json().catch(() => ({}));
  const { sessionId, st, nonce } = body;
  const secret = ctx.env.KEY_PEPPER || 'change-me-key-pepper';
  const token = await verifyToken(st, secret);
  if (!token || token.sid !== sessionId) return json({ ok: false, error: 'invalid_token' }, 403);
  if (token.nonce !== nonce) return json({ ok: false, error: 'invalid_nonce' }, 403);
  return json({ ok: true, nonce: token.nonce });
}
