/**
 * POST /api/verify-key
 *
 * Three-phase key verification for the Incognito executor.
 *
 * Phase 1: Timing-safe HMAC signature check (no DB hit)
 * Phase 2: DB check — HWID binding, expiry
 * Phase 3: Return AES-256-GCM encrypted payload
 *
 * Body: { key, hwid, sessionSalt }
 * Returns: { ok, payload: { iv, salt, tag, ct } }
 */

import { getStore } from '@netlify/blobs';
import crypto from 'crypto';
import { verifyKeySignature, hashHwid, encryptPayload } from './shared/crypto.mjs';

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

export default async (req, context) => {
  if (req.method !== 'POST') return json({ ok: false }, 405);

  let body;
  try { body = await req.json(); }
  catch { return json({ ok: false, error: 'Invalid JSON' }, 400); }

  const { key, hwid, sessionSalt } = body;

  if (typeof key !== 'string' || !key.startsWith('incognito_'))
    return json({ ok: false, error: 'Invalid key format' }, 400);
  if (typeof hwid !== 'string' || !/^[0-9a-f]{128}$/i.test(hwid))
    return json({ ok: false, error: 'Invalid HWID' }, 400);
  if (typeof sessionSalt !== 'string' || !/^[0-9a-f]{32,64}$/.test(sessionSalt))
    return json({ ok: false, error: 'Invalid sessionSalt' }, 400);

  const store = getStore({ name: 'incognito-sessions', consistency: 'strong' });

  // ── Brute-force protection on verify-key ────────────────────────────────
  const ip = context.ip || '0.0.0.0';
  const bfKey = `rl:verify:${ip}`;
  const bfRaw = await store.get(bfKey, { type: 'json' });
  const now   = Date.now();
  const bfTs  = ((bfRaw?.timestamps) || []).filter(ts => ts > now - 60_000);

  if (bfTs.length >= 20) {
    return json({ ok: false, error: 'Rate limit exceeded' }, 429);
  }
  bfTs.push(now);
  await store.setJSON(bfKey, { timestamps: bfTs });

  // ════════════════════════════════════════════════════════════════════════
  // PHASE 1: Timing-safe HMAC signature verification
  // ════════════════════════════════════════════════════════════════════════
  let sigResult;
  try { sigResult = verifyKeySignature(key); }
  catch { return json({ ok: false, error: 'Server error' }, 500); }

  if (!sigResult.ok) {
    // Increment sig-fail counter (stricter limit)
    const sfKey = `rl:sigfail:${ip}`;
    const sfRaw = await store.get(sfKey, { type: 'json' });
    const sfTs  = ((sfRaw?.timestamps) || []).filter(ts => ts > now - 300_000); // 5 min window
    sfTs.push(now);
    await store.setJSON(sfKey, { timestamps: sfTs });
    if (sfTs.length >= 5) {
      return json({ ok: false, error: 'Too many invalid keys. Temporarily blocked.' }, 429);
    }
    return json({ ok: false, error: 'Invalid key' }, 401);
  }

  const { keyId } = sigResult;

  // ════════════════════════════════════════════════════════════════════════
  // PHASE 2: Database check — expiry + HWID binding
  // ════════════════════════════════════════════════════════════════════════
  let hwidHash;
  try { hwidHash = hashHwid(hwid); }
  catch { return json({ ok: false, error: 'Server error' }, 500); }

  const keyRecord = await store.get(`key:${keyId}`, { type: 'json' });

  if (!keyRecord) return json({ ok: false, error: 'Key not found or expired' }, 401);
  if (Date.now() > keyRecord.expiresAt) return json({ ok: false, error: 'Key expired' }, 401);

  // HWID binding: first use binds the key to this machine
  if (!keyRecord.hwidHash || keyRecord.hwidHash === keyRecord.hwidHash) {
    if (!keyRecord.boundHwid) {
      keyRecord.boundHwid = hwidHash;
      await store.setJSON(`key:${keyId}`, keyRecord);
    } else if (keyRecord.boundHwid !== hwidHash) {
      return json({ ok: false, error: 'Key is bound to a different machine' }, 403);
    }
  }

  // ════════════════════════════════════════════════════════════════════════
  // PHASE 3: Encrypt and return the script payload
  // ════════════════════════════════════════════════════════════════════════
  const payload = {
    authorized:  true,
    keyId,
    isLifetime:  keyRecord.isLifetime || false,
    expiresAt:   new Date(keyRecord.expiresAt).toISOString(),
    issuedAt:    new Date().toISOString(),
    nonce:       crypto.randomBytes(16).toString('hex'),
    unlock: {
      remoteSpyEnabled:   true,
      multiClientEnabled: true,
      maxSyncEnabled:     true,
      coreFeatures:       true,
    },
  };

  let encrypted;
  try { encrypted = encryptPayload(payload, sessionSalt); }
  catch (e) {
    console.error('Encryption error:', e.message);
    return json({ ok: false, error: 'Encryption failed' }, 500);
  }

  return json({ ok: true, payload: encrypted });
};

export const config = { path: '/api/verify-key' };
