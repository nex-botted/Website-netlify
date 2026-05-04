import { json, randomHex, signToken, verifyToken } from './_shared.js';

export async function onRequestPost(ctx) {
  const body = await ctx.request.json().catch(() => ({}));
  const { key, hwid, sid, st, nonce } = body;
  const secret = ctx.env.KEY_PEPPER || 'change-me-key-pepper';
  const token = await verifyToken(st, secret);
  if (!token || token.sid !== sid) return json({ ok: false, error: 'invalid_token' }, 403);
  if (token.hwid !== hwid) return json({ ok: false, error: 'hwid_mismatch' }, 403);
  if (token.nonce !== nonce) return json({ ok: false, error: 'invalid_nonce' }, 403);
  if (token.key !== key) return json({ ok: false, error: 'invalid_key' }, 403);
  const nextToken = await signToken({ ...token, nonce: randomHex(16) }, secret);
  return json({ ok: true, sessionToken: nextToken, payload: { success: true, ts: Date.now() } });
}
