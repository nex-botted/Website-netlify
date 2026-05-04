import { json, verifyToken } from './_shared.js';

export async function onRequestPost(ctx) {
  const body = await ctx.request.json().catch(() => ({}));
  const { sessionId, st, nonce } = body;
  const secret = ctx.env.KEY_PEPPER || 'change-me-key-pepper';
  const token = await verifyToken(st, secret);
  if (!token || token.sid !== sessionId) return json({ ok: false, error: 'invalid_token' }, 403);
  // Accept first-step client nonce and re-sign token so gate.html can continue.
  if (token.nonce !== nonce) {
    if (body.action !== 'start_1') return json({ ok: false, error: 'invalid_nonce' }, 403);
  }
  return json({ ok: true, nonce: nonce || token.nonce });
}
