export const config = { api: { bodyParser: false } };

import { onRequestGet as cfOnRequestGet } from '../functions/[id].js';

export default async function handler(req, res) {
  const url    = new URL(req.url, `https://${req.headers.host || 'localhost'}`);
  const id     = req.query?.id ?? url.pathname.split('/').filter(Boolean).pop() ?? '';

  const headers = new Headers();
  for (const [k, v] of Object.entries(req.headers)) {
    if (v == null) continue;
    if (Array.isArray(v)) v.forEach(val => headers.append(k, val));
    else headers.set(k, v);
  }

  const webRequest = new Request(url.toString(), { method: 'GET', headers });
  const env        = { RATE_LIMIT_KV: null, ASSETS: null };
  const params     = { id };

  let webResponse;
  try {
    webResponse = await cfOnRequestGet({ env, params, request: webRequest });
  } catch (err) {
    console.error('[StoreGit/Vercel] Share-link error:', err);
    res.status(503).send('<html><body><h2>Link unavailable</h2></body></html>');
    return;
  }

  res.status(webResponse.status);
  webResponse.headers.forEach((value, key) => {
    if (key.toLowerCase() === 'transfer-encoding') return;
    res.setHeader(key, value);
  });
  const body = await webResponse.arrayBuffer();
  res.end(Buffer.from(body));
}
