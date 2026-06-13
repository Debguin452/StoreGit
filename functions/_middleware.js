'use strict';

// ── Security headers applied to every response ──────────────────────────────
const GLOBAL_SEC = {
  'X-Content-Type-Options':    'nosniff',
  'X-Frame-Options':           'DENY',
  'Referrer-Policy':           'no-referrer',
  'X-Permitted-Cross-Domain-Policies': 'none',
  'Cross-Origin-Opener-Policy':  'same-origin',
  'Cross-Origin-Embedder-Policy': 'require-corp',
  'Cross-Origin-Resource-Policy': 'same-origin',
  'Permissions-Policy':
    'camera=(), microphone=(), geolocation=(), payment=(), usb=(), ' +
    'display-capture=(), clipboard-read=(), clipboard-write=(), ' +
    'screen-wake-lock=(), accelerometer=(), gyroscope=(), magnetometer=()',
  'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload',
};

// CSP for the main HTML pages (app, login, etc.)
const PAGE_CSP =
  "default-src 'none'; " +
  "script-src 'self'; " +
  "style-src 'self'; " +
  "img-src 'self' data: blob:; " +
  "media-src 'self' data: blob:; " +
  "connect-src 'self' https://api.github.com; " +
  "frame-ancestors 'none'; " +
  "form-action 'none'; " +
  "base-uri 'none'; " +
  "upgrade-insecure-requests;";

// Blocked user-agent patterns (bots, scanners, exploit frameworks)
const BLOCKED_UA_RE = /(?:sqlmap|nikto|nmap|masscan|zgrab|go-http-client\/1\.1|python-requests\/[01]\.|curl\/[0-6]\.|dirbuster|dirb|wfuzz|nuclei|acunetix|nessus|openvas|burpsuite|w3af|joomscan|wpscan|havij|pangolin|darkstat)/i;

// IP-based brute-force memory (in-process; also backed by KV via the API worker)
const _mwRate = new Map();
const MW_RATE_WINDOW = 60_000;
const MW_RATE_MAX    = 600;   // requests per minute per IP before throttling

function getIP(req) {
  return req.headers.get('CF-Connecting-IP') ||
    req.headers.get('X-Forwarded-For')?.split(',')[0].trim() || 'unknown';
}

function isRateLimited(ip) {
  const now = Date.now();
  let r = _mwRate.get(ip);
  if (!r || now > r.resetAt) {
    _mwRate.set(ip, { count: 1, resetAt: now + MW_RATE_WINDOW });
    if (_mwRate.size > 50_000) {
      for (const [k, v] of _mwRate) if (now > v.resetAt) _mwRate.delete(k);
    }
    return false;
  }
  r.count++;
  return r.count > MW_RATE_MAX;
}

function deny(status, msg) {
  return new Response(JSON.stringify({ error: msg }), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store',
      ...GLOBAL_SEC,
    },
  });
}

export async function onRequest({ request, next, env }) {
  const method = request.method.toUpperCase();
  const url    = new URL(request.url);
  const path   = url.pathname;

  // ── 1. HTTPS enforcement ─────────────────────────────────────────────────
  if (url.protocol === 'http:' && !url.hostname.includes('localhost')) {
    const httpsUrl = new URL(request.url);
    httpsUrl.protocol = 'https:';
    return Response.redirect(httpsUrl.toString(), 301);
  }

  // ── 2. Block malicious user-agents ────────────────────────────────────────
  const ua = request.headers.get('User-Agent') || '';
  if (BLOCKED_UA_RE.test(ua)) return deny(403, 'Forbidden');

  // ── 3. Global rate limiting ───────────────────────────────────────────────
  const ip = getIP(request);
  if (isRateLimited(ip)) return deny(429, 'Too many requests');

  // ── 4. Block bad methods ──────────────────────────────────────────────────
  const ALLOWED_METHODS = new Set(['GET','POST','PUT','DELETE','OPTIONS','HEAD']);
  if (!ALLOWED_METHODS.has(method)) return deny(405, 'Method not allowed');

  // ── 5. Block path traversal & null bytes ─────────────────────────────────
  if (path.includes('..') || path.includes('\0') || path.includes('%00')) {
    return deny(400, 'Bad request');
  }

  // ── 6. Block obvious scanner probes ──────────────────────────────────────
  const SCAN_PATHS = [
    '/wp-admin', '/wp-login', '/phpmyadmin', '/.env', '/.git',
    '/xmlrpc', '/cgi-bin', '/admin.php', '/shell', '/etc/passwd',
  ];
  if (SCAN_PATHS.some(p => path.toLowerCase().startsWith(p))) {
    return deny(404, 'Not found');
  }

  // ── 7. Enforce max request body size (10 MB hard limit) ───────────────────
  // Only upload-related API routes are allowed to exceed the 10 MB limit.
  const LARGE_BODY_ALLOWED = new Set(['/api/upload', '/api/upload-chunk', '/api/finalize-upload']);
  const contentLength = parseInt(request.headers.get('Content-Length') || '0', 10);
  if (contentLength > 10 * 1024 * 1024 && !LARGE_BODY_ALLOWED.has(path)) {
    return deny(413, 'Payload too large');
  }

  // ── 8. Forward to next handler ────────────────────────────────────────────
  const response = await next();

  // ── 9. Attach security headers to every response ──────────────────────────
  const headers = new Headers(response.headers);
  for (const [k, v] of Object.entries(GLOBAL_SEC)) {
    // For API routes the worker sets Cross-Origin-Resource-Policy itself
    // (cross-origin for API key requests, same-origin otherwise).
    // Skip here so we don't overwrite the worker's intentional choice.
    if (k === 'Cross-Origin-Resource-Policy' && path.startsWith('/api/')) continue;
    if (!headers.has(k)) headers.set(k, v);
  }

  // Add page-level CSP for HTML responses
  const ct = response.headers.get('Content-Type') || '';
  if (ct.includes('text/html') && !headers.has('Content-Security-Policy')) {
    headers.set('Content-Security-Policy', PAGE_CSP);
  }

  // Remove information-leaking headers
  headers.delete('Server');
  headers.delete('X-Powered-By');
  headers.delete('X-AspNet-Version');
  headers.delete('X-AspNetMvc-Version');

  return new Response(response.body, {
    status:     response.status,
    statusText: response.statusText,
    headers,
  });
}
