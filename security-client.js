(function () {
  const enc = new TextEncoder();
  const dec = new TextDecoder();
  const NS = '__incog_secure_v1__';

  function b64(buf) {
    return btoa(String.fromCharCode(...new Uint8Array(buf)));
  }

  function unb64(str) {
    return Uint8Array.from(atob(str), c => c.charCodeAt(0));
  }

  async function getKey() {
    let salt = sessionStorage.getItem(NS + ':salt');
    if (!salt) {
      const raw = crypto.getRandomValues(new Uint8Array(16));
      salt = b64(raw);
      sessionStorage.setItem(NS + ':salt', salt);
    }

    const material = await crypto.subtle.importKey(
      'raw',
      enc.encode(location.origin + '|' + navigator.userAgent),
      'PBKDF2',
      false,
      ['deriveKey']
    );

    return crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: unb64(salt),
        iterations: 250000,
        hash: 'SHA-256'
      },
      material,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  async function encrypt(value) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await getKey();
    const cipher = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(JSON.stringify(value)));
    return b64(iv) + '.' + b64(cipher);
  }

  async function decrypt(payload) {
    const [ivB64, dataB64] = (payload || '').split('.');
    if (!ivB64 || !dataB64) return null;
    const key = await getKey();
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(ivB64) }, key, unb64(dataB64));
    return JSON.parse(dec.decode(plain));
  }

  window.secureStore = {
    async set(name, value) {
      const blob = await encrypt(value);
      sessionStorage.setItem(NS + ':' + name, blob);
    },
    async get(name) {
      const blob = sessionStorage.getItem(NS + ':' + name);
      return blob ? decrypt(blob) : null;
    },
    del(name) {
      sessionStorage.removeItem(NS + ':' + name);
    }
  };

  (async function protectUrlParams() {
    if (!location.search) return;
    const params = Object.fromEntries(new URLSearchParams(location.search).entries());
    if (!Object.keys(params).length) return;
    await window.secureStore.set('url_params:' + location.pathname, params);
    history.replaceState({}, '', location.pathname + location.hash);
  })().catch(() => {});
})();
