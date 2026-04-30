/**
 * POST /api/request-session
 * 
 * Called by the Incognito executor to begin the key gate flow.
 * 
 * Body:  { hwid: "<128-char hex SHA-512>" }
 * Returns: { ok, sessionId, gateUrl, expiresIn }
 */

import { getStore } from '@netlify/blobs';
import crypto from 'crypto';
import { hashHwid } from './shared/crypto.mjs';

const SESSION_TTL_MS  = 30 * 60 * 1000;   // 30 minutes
const HWID_RATE_LIMIT = 3;                 // max new sessions per HWID per hour

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

  const { hwid } = body;

  // Validate HWID
  if (typeof hwid !== 'string' || !/^[0-9a-f]{128}$/i.test(hwid)) {
    return json({
      ok: false,
      error: 'HWID must be a 128-char hex-encoded SHA-512 hash.'
    }, 400);
  }

  let hwidHash;
  try {
    hwidHash = hashHwid(hwid);
  } catch {
    return json({ ok: false, error: 'Server configuration error.' }, 500);
  }

  const store = getStore({ name: 'incognito-sessions', consistency: 'strong' });

  const now = Date.now();

  // ── Per-HWID rate limiting ──
  const rlKey = `rl:hwid:${hwidHash}`;
  const rlRaw = await store.get(rlKey, { type: 'json' });

  const cutoff = now - 3600_000;
  const recent = ((rlRaw?.timestamps) || []).filter(ts => ts > cutoff);

  if (recent.length >= HWID_RATE_LIMIT) {
    const retryAfter = Math.ceil((recent[0] + 3600_000 - now) / 1000);
    return json({
      ok: false,
      error: 'Too many key requests from this machine. Try again later.',
      retryAfter
    }, 429);
  }

  recent.push(now);
  await store.setJSON(rlKey, { timestamps: recent });

  // ── IP rate limiting ──
  const ip =
    event.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
    event.headers['client-ip'] ||
    '0.0.0.0';

  const ipKey = `rl:ip:${ip}`;
  const ipRaw = await store.get(ipKey, { type: 'json' });

  const ipRecent = ((ipRaw?.timestamps) || []).filter(ts => ts > now - 600_000);

  if (ipRecent.length >= 10) {
    return json({ ok: false, error: 'Rate limit exceeded. Please wait.' }, 429);
  }

  ipRecent.push(now);
  await store.setJSON(ipKey, { timestamps: ipRecent });

  // ── Create session ──
  const sessionId = crypto.randomUUID().replace(/-/g, '');

  const session = {
    sessionId,
    hwidHash,
    ip,
    step: 0,
    stepTimestamps: {},
    key: null,
    createdAt: now,
    expiresAt: now + SESSION_TTL_MS,
  };

  await store.setJSON(`session:${sessionId}`, session);

  // Build base URL correctly
  const reqUrl = new URL(event.rawUrl);
  const baseUrl = `${reqUrl.protocol}//${reqUrl.host}`;

  return json({
    ok: true,
    sessionId,
    gateUrl: `${baseUrl}/gate?step=1&sid=${sessionId}`,
    expiresIn: SESSION_TTL_MS / 1000,
  }, 201);
}

export const config = { path: '/api/request-session' };
