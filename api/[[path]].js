/**
 * Vercel Serverless Function (Node.js runtime) adapter for StoreGit's
 * Cloudflare Pages API handler.
 *
 * WHY NOT EDGE RUNTIME:
 *   Vercel Edge Functions have a hard 4 MB request-body limit, which would
 *   block chunk uploads (each chunk can be up to ~14 MB base64). The Node.js
 *   runtime supports larger bodies when bodyParser is configured accordingly.
 *
 * KV NOTE:
 *   Cloudflare KV (env.RATE_LIMIT_KV) is not available on Vercel.
 *   The handler degrades gracefully (null KV) — rate-limit counters fall
 *   back to in-process memory, session cache is skipped, share-link short
 *   IDs are unavailable. All upload/download/auth features work normally.
 *
 * ENVIRONMENT VARIABLES (set in Vercel project settings):
 *   TOKEN_SECRET              — random secret for JWT / share-token HMAC
 *   REGISTRY_GITHUB_TOKEN     — GitHub PAT for the registry repo
 *   REGISTRY_GITHUB_OWNER     — GitHub owner of the registry repo
 *   REGISTRY_GITHUB_REPO      — GitHub repo name of the registry
 */

// Increase body-parser limit to 20 MB to accommodate base64-encoded chunks.
export const config = {
  api: {
    bodyParser: {
      sizeLimit: '20mb',
    },
  },
};

import { onRequest as cfOnRequest } from '../functions/api/[[path]].js';

export default async function handler(req, res) {
  // Reconstruct a Web API Request from the Node.js IncomingMessage so the
  // Cloudflare-style handler can consume it with request.json() etc.
  const url    = new URL(req.url, `https://${req.headers.host || 'localhost'}`);
  const method = req.method?.toUpperCase() ?? 'GET';

  // Vercel's bodyParser already parsed the body into req.body. Re-serialise it
  // so the handler can call request.json() on a real Request object.
  let bodyInit;
  if (req.body !== undefined && method !== 'GET' && method !== 'HEAD') {
    bodyInit = typeof req.body === 'string' ? req.body : JSON.stringify(req.body);
  }

  const headers = new Headers();
  for (const [k, v] of Object.entries(req.headers)) {
    if (v == null) continue;
    if (Array.isArray(v)) v.forEach(val => headers.append(k, val));
    else headers.set(k, v);
  }

  const webRequest = new Request(url.toString(), {
    method,
    headers,
    body:   bodyInit ?? undefined,
    // Required for Request to accept a body in newer runtimes
    duplex: 'half',
  });

  const env = {
    TOKEN_SECRET:          process.env.TOKEN_SECRET          ?? '',
    REGISTRY_GITHUB_TOKEN: process.env.REGISTRY_GITHUB_TOKEN ?? '',
    REGISTRY_GITHUB_OWNER: process.env.REGISTRY_GITHUB_OWNER ?? '',
    REGISTRY_GITHUB_REPO:  process.env.REGISTRY_GITHUB_REPO  ?? '',
    RATE_LIMIT_KV:         null, // Cloudflare KV — not available on Vercel
  };

  // Build params.path from the URL (mirrors CF Pages path matching)
  const segments = url.pathname.replace(/^\/api\/?/, '').split('/').filter(Boolean);
  const params   = { path: segments };

  let webResponse;
  try {
    webResponse = await cfOnRequest({ request: webRequest, env, params });
  } catch (err) {
    console.error('[StoreGit/Vercel] Unhandled error:', err);
    res.status(500).json({ error: 'An unexpected server error occurred.' });
    return;
  }

  // Forward status + headers
  res.status(webResponse.status);
  webResponse.headers.forEach((value, key) => {
    // Vercel sets its own transfer-encoding; skip to avoid conflicts
    if (key.toLowerCase() === 'transfer-encoding') return;
    res.setHeader(key, value);
  });

  // Stream the response body
  const body = await webResponse.arrayBuffer();
  res.end(Buffer.from(body));
}
