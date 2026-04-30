/**
 * POST /api/gate-action
 *
 * Called by gate.html at each step transition.
 *
 * Body:  { sessionId, action }
 * Actions:
 *   "start_1"    — record that user is about to do LV1 (sets step→1)
 *   "complete_1" — user returned from LV1, validate timing (sets step→2)
 *   "start_2"    — record user is about to do LV2 (sets step→3)  [combined in gate, rarely called standalone]
 *   "complete_2" — user returned from LV2, validate timing (sets step→4)
 *   "complete_3" — user returned from LV3, generate key (sets step→5)
 *
 * In practice gate.html calls:
 *   step=1 page  → "start_1"    then redirects to LV1
 *   step=2 page  → "complete_1" then "start_2" then redirects to LV2
 *   step=3 page  → "complete_2" then "start_3" then redirects to LV3
 *   step=done    → "complete_3" returns key
 *
 * Returns: { ok, key? (only on complete_3) }
 */

import { getStore } from '@netlify/blobs';
import { generateKey } from './shared/crypto.mjs';

// Minimum milliseconds the user must spend on each Linkvertise step
// (protects against automated bypass tools — real LV takes 15-30 seconds)
const MIN_STEP_MS = 20_000;   // 20 seconds

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

const VALID_ACTIONS = new Set(['start_1', 'complete_1', 'complete_2', 'complete_3']);

export default async (req, context) => {
  if (req.method !== 'POST') return json({ ok: false }, 405);

  // ── Only accept requests from our own origin (anti-bypass) ──────────────
  const origin  = req.headers.get('origin') || '';
  const referer = req.headers.get('referer') || '';
  const host    = new URL(req.url).host;
  const fromUs  = origin.includes(host) || referer.includes(host);
  if (!fromUs) return json({ ok: false, error: 'Forbidden' }, 403);

  let body;
  try { body = await req.json(); }
  catch { return json({ ok: false, error: 'Bad request' }, 400); }

  const { sessionId, action } = body;

  if (!sessionId || !action || !VALID_ACTIONS.has(action)) {
    return json({ ok: false, error: 'Invalid parameters' }, 400);
  }

  if (!/^[0-9a-f]{32}$/.test(sessionId)) {
    return json({ ok: false, error: 'Invalid session ID' }, 400);
  }

  const store = getStore({ name: 'incognito-sessions', consistency: 'strong' });
  const session = await store.get(`session:${sessionId}`, { type: 'json' });

  if (!session) return json({ ok: false, error: 'Session not found' }, 404);
  if (Date.now() > session.expiresAt) return json({ ok: false, error: 'Session expired' }, 403);
  if (session.key) return json({ ok: false, error: 'Session already completed' }, 409);

  const now = Date.now();
  const ts = session.stepTimestamps;

  switch (action) {
    // ── User is about to open LV1 ──────────────────────────────────────────
    case 'start_1': {
      if (session.step !== 0) return json({ ok: false, error: 'Invalid step sequence' }, 403);
      session.step = 1;
      ts.step1Start = now;
      await store.setJSON(`session:${sessionId}`, session);
      return json({ ok: true });
    }

    // ── User returned from LV1 ─────────────────────────────────────────────
    case 'complete_1': {
      if (session.step !== 1) return json({ ok: false, error: 'Step 1 not started' }, 403);
      if (!ts.step1Start) return json({ ok: false, error: 'Invalid state' }, 403);

      const elapsed = now - ts.step1Start;
      if (elapsed < MIN_STEP_MS) {
        // Too fast — bypass attempt
        return json({
          ok: false,
          error: 'Bypass detected: completed too fast.',
          waitMs: MIN_STEP_MS - elapsed,
        }, 403);
      }

      session.step = 2;
      ts.step1Done = now;
      ts.step2Start = now;   // immediately start step 2 timer
      await store.setJSON(`session:${sessionId}`, session);
      return json({ ok: true });
    }

    // ── User returned from LV2 ─────────────────────────────────────────────
    case 'complete_2': {
      if (session.step !== 2) return json({ ok: false, error: 'Step 2 not started' }, 403);
      if (!ts.step2Start) return json({ ok: false, error: 'Invalid state' }, 403);

      const elapsed = now - ts.step2Start;
      if (elapsed < MIN_STEP_MS) {
        return json({
          ok: false,
          error: 'Bypass detected: completed too fast.',
          waitMs: MIN_STEP_MS - elapsed,
        }, 403);
      }

      session.step = 3;
      ts.step2Done = now;
      ts.step3Start = now;
      await store.setJSON(`session:${sessionId}`, session);
      return json({ ok: true });
    }

    // ── User returned from LV3 — generate key ─────────────────────────────
    case 'complete_3': {
      if (session.step !== 3) return json({ ok: false, error: 'Step 3 not started' }, 403);
      if (!ts.step3Start) return json({ ok: false, error: 'Invalid state' }, 403);

      const elapsed = now - ts.step3Start;
      if (elapsed < MIN_STEP_MS) {
        return json({
          ok: false,
          error: 'Bypass detected: completed too fast.',
          waitMs: MIN_STEP_MS - elapsed,
        }, 403);
      }

      // ── Generate the key ────────────────────────────────────────────────
      let key;
      try {
        key = generateKey(sessionId.slice(0, 16));
      } catch (e) {
        console.error('Key generation failed:', e.message);
        return json({ ok: false, error: 'Key generation failed. Contact support.' }, 500);
      }

      session.step = 4;
      session.key = key;
      ts.step3Done = now;
      ts.keyGeneratedAt = now;

      await store.setJSON(`session:${sessionId}`, session);

      // Also store by key for verify-key lookups
      await store.setJSON(`key:${sessionId.slice(0, 16)}`, {
        hwidHash:    session.hwidHash,
        generatedAt: now,
        expiresAt:   now + 24 * 3600_000,   // key valid for 24h
        isLifetime:  false,
      });

      return json({ ok: true, key });
    }
  }
};

export const config = { path: '/api/gate-action' };
