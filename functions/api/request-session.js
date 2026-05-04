import { json, randomHex, signToken } from './_shared.js';

export async function onRequestPost(ctx) {
  const body = await ctx.request.json().catch(() => ({}));
  const hwid = String(body.hwid || '');
  if (!/^[0-9a-f]{128}$/i.test(hwid)) return json({ ok: false, error: 'invalid_hwid' }, 400);

  const sid = randomHex(16);
  const nonce = randomHex(16);
  const exp = Date.now() + 30 * 60 * 1000;
  const secret = ctx.env.KEY_PEPPER || 'change-me-key-pepper';
  const key = `incognito_v2_${randomHex(20).toUpperCase()}`;
  const sessionToken = await signToken({ sid, hwid, nonce, key, exp }, secret);
  const base = new URL(ctx.request.url).origin;

  return json({
    ok: true,
    sessionId: sid,
    sessionToken,
    gateUrl: `${base}/gate?step=1&sid=${sid}&st=${encodeURIComponent(sessionToken)}`,
    expiresIn: 1800
  }, 201);
}
