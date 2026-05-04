const enc = new TextEncoder();

function b64urlEncode(bytes) {
  let bin = '';
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  for (let i = 0; i < arr.length; i++) bin += String.fromCharCode(arr[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function b64urlDecode(str) {
  const base64 = str.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((str.length + 3) % 4);
  const bin = atob(base64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function hmac(data, secret) {
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, enc.encode(data)));
}

export async function signToken(payload, secret) {
  const body = b64urlEncode(enc.encode(JSON.stringify(payload)));
  const sig = b64urlEncode((await hmac(body, secret)).slice(0, 24));
  return `${body}.${sig}`;
}

export async function verifyToken(token, secret) {
  const [body, sig] = String(token || '').split('.');
  if (!body || !sig) return null;
  const expected = b64urlEncode((await hmac(body, secret)).slice(0, 24));
  if (expected !== sig) return null;
  const payload = JSON.parse(new TextDecoder().decode(b64urlDecode(body)));
  if (typeof payload.exp === 'number' && payload.exp < Date.now()) return null;
  return payload;
}

export function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json', 'cache-control': 'no-store' }
  });
}

export function randomHex(bytes = 16) {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
}
