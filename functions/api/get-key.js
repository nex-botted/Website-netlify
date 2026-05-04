import { json, verifyToken } from './_shared.js';

export async function onRequestGet(ctx) {
  const url = new URL(ctx.request.url);
  const sid = url.searchParams.get('sid') || '';
  const st = url.searchParams.get('st') || '';
  const secret = ctx.env.KEY_PEPPER || 'change-me-key-pepper';
  const token = await verifyToken(st, secret);
  if (!token || token.sid !== sid) return json({ ok: false, error: 'invalid_token' }, 403);
  return json({ ok: true, key: token.key, nonce: token.nonce });
}
