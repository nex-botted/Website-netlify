exports.handler = async (event) => {
  const sourcePath = event.path || '/unknown';
  const ip = event.headers['x-forwarded-for'] || 'unknown';
  const userAgent = event.headers['user-agent'] || 'unknown';

  console.warn('[SECURITY_BLOCKED_REQUEST]', {
    at: new Date().toISOString(),
    path: sourcePath,
    method: event.httpMethod,
    ip,
    userAgent
  });

  return {
    statusCode: 403,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store, no-cache, must-revalidate'
    },
    body: '<!doctype html><html><head><meta charset="utf-8"><title>403</title></head><body>403 Forbidden</body></html>'
  };
};
