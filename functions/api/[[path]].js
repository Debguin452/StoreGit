'use strict';
const SESSION_TTL               = 8  * 60 * 60 * 1000;
const SESSION_REFRESH_THRESHOLD =      60 * 60 * 1000;
const SHARE_TTL_MAX             = 7 * 24 * 60 * 60;
const RATE_WINDOW_MS            = 15 * 60 * 1000;
const LOGIN_LOCKOUT_MS          = 30 * 1000;
const LOGIN_LOCKOUT_ATTEMPTS    = 3;
const RATE_MAX_SIGNUP           = 3;
const RATE_MAX_RESET            = 3;
const CHUNK_B64_MAX             = 14 * 1024 * 1024;
const SMALL_MAX_BYTES           =  5 * 1024 * 1024;
// Files larger than this raw size will distribute chunks across repos to equalise storage.
// Kept well above CHUNK_THRESHOLD (8 MB) so small multi-chunk files stay in one repo.
const DIST_THRESHOLD            = 50 * 1024 * 1024;  // 50 MB raw — split across repos above this
const MAX_TOTAL_CHUNKS          = 1024;  // 1024 × 10 MB = ~10 GB max; 2 repos → ~5 GB each
const COMMIT_RETRY_MAX          = 6;   // optimistic concurrency retries for branch ref updates
const PARALLEL_DL_CHUNKS        = 24;  // simultaneous chunk fetches during download (sliding window)
const UPLOAD_CONCURRENCY        = 8;   // advisory: how many chunk uploads client should run in parallel
const INDEX_CACHE_TTL           = 60;  // seconds to cache readIndex results in KV
const REPO_BYTES_CACHE_TTL      = 30;  // seconds to cache per-repo byte totals in KV
const SHA_RE                    = /^[0-9a-f]{40}$/i;
const USERNAME_RE               = /^[a-zA-Z0-9_\-]{3,32}$/;
const CLEAN_NAME_RE             = /^[a-zA-Z0-9][a-zA-Z0-9._\-()\s]{0,253}$/;
const REGISTRY_BRANCH           = 'main';
const OWNER_RE   = /^[a-zA-Z0-9][a-zA-Z0-9\-]{0,37}$/;
const REPO_RE    = /^[a-zA-Z0-9_.\-]{1,100}$/;
const BRANCH_RE  = /^[a-zA-Z0-9_.\-\/]{1,250}$/;
const FOLDER_RE  = /^[a-zA-Z0-9_.\-]{1,100}$/;
const BLOCKED_EXTS = new Set([
  'exe','bat','cmd','com','msi','ps1','psm1',
  'sh','bash','zsh','fish','command',
  'php','php3','php4','php5','php7','php8','phtml','phar',
  'asp','aspx','cshtml','jsp','jspx',
  'py','pyc','pyw','rb','pl','cgi','lua',
  'js','mjs','cjs','ts','tsx','jsx',
  'html','htm','xhtml','svg','xml',
  'htaccess','htpasswd',
  'dll','so','dylib','sys',
  'vbs','vbe','wsf','wsh','hta',
  'jar','war','ear','class',
  'scr','pif','reg','lnk',
  'app','dmg','pkg','deb','rpm','apk',
]);
const BLOCKED_MAGIC = [
  [0,[0x4D,0x5A]],
  [0,[0x7F,0x45,0x4C,0x46]],
  [0,[0xFE,0xED,0xFA,0xCE]],[0,[0xFE,0xED,0xFA,0xCF]],
  [0,[0xCE,0xFA,0xED,0xFE]],[0,[0xCF,0xFA,0xED,0xFE]],
  [0,[0xCA,0xFE,0xBA,0xBE]],
  [0,[0x23,0x21]],
  [0,[0x3C,0x3F,0x70,0x68,0x70]],
  [0,[0x3C,0x73,0x63,0x72,0x69,0x70,0x74]],
  [0,[0x3C,0x68,0x74,0x6D,0x6C]],[0,[0x3C,0x48,0x54,0x4D,0x4C]],
];

// Human-readable byte formatter used by storage endpoints
function formatBytes(b) {
  if (b < 1024)                  return `${b} B`;
  if (b < 1024 * 1024)           return `${(b / 1024).toFixed(1)} KB`;
  if (b < 1024 * 1024 * 1024)   return `${(b / (1024 * 1024)).toFixed(1)} MB`;
  return `${(b / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

const _memRate = new Map();

const SEC = {
  'X-Content-Type-Options':    'nosniff',
  'X-Frame-Options':           'DENY',
  'Referrer-Policy':           'no-referrer',
  'Permissions-Policy':        'camera=(), microphone=(), geolocation=(), payment=(), usb=(), display-capture=(), clipboard-read=(), clipboard-write=(), screen-wake-lock=(), accelerometer=(), gyroscope=(), magnetometer=()',
  'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload',
  'Content-Security-Policy':
    "default-src 'none'; script-src 'none'; " +
    "style-src 'none'; img-src 'none'; " +
    "connect-src 'self'; frame-ancestors 'none'; form-action 'none'; base-uri 'none';",
  'Cache-Control': 'no-store',
};
// allowedOrigins: null=same-origin, []=any, [...]=whitelist
function corsHeaders(req, allowedOrigins = null) {
  const o = req.headers.get('Origin') || '';
  const h = req.headers.get('Host')   || '';
  const isSame = o === `https://${h}` || o === `http://${h}`;
  let allowOrigin = 'null';
  let allowCreds  = 'false';
  if (isSame) {
    allowOrigin = o; allowCreds = 'true';
  } else if (allowedOrigins !== null) {
    if (allowedOrigins.length === 0) {
      allowOrigin = o || '*';   // unrestricted API key
    } else if (o && allowedOrigins.includes(o)) {
      allowOrigin = o;          // domain-bound API key
    }
  }
  return {
    'Access-Control-Allow-Origin':      allowOrigin,
    'Access-Control-Allow-Methods':     'GET,POST,DELETE,OPTIONS',
    'Access-Control-Allow-Headers':     'Content-Type,X-API-Key',
    'Access-Control-Allow-Credentials': allowCreds,
    'Vary': 'Origin',
  };
}

// API key: sgk_<43 B64URL chars>, 256-bit (SHA-256 stored in KV, raw key never persisted)
const APIKEY_RE          = /^sgk_[A-Za-z0-9_-]{43}$/; // 43 chars × 6 bits = 258 bits ≥ 256
const APIKEY_RATE_MAX    = 120;   // requests per minute per key
const APIKEY_RATE_WINDOW = 60_000;

// RFC 4648 §5 Base64URL alphabet — no padding, URL-safe
const B64URL_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

// Base64URL encode — 3 raw bytes → 4 chars, no padding
function base64urlFromBytes(bytes) {
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i], b1 = bytes[i + 1] ?? 0, b2 = bytes[i + 2] ?? 0;
    out += B64URL_CHARS[b0 >> 2];
    out += B64URL_CHARS[((b0 & 0x03) << 4) | (b1 >> 4)];
    out += B64URL_CHARS[((b1 & 0x0f) << 2) | (b2 >> 6)];
    out += B64URL_CHARS[b2 & 0x3f];
  }
  // For 32 bytes: ceil(32 × 4/3) = 43 usable chars (last char encodes 2 bits of the 32nd byte)
  return out.slice(0, Math.ceil(bytes.length * 4 / 3));
}

// Uniform random string from alphabet using rejection sampling (no modulo bias)
function randomAlphabetString(alphabet, length) {
  const sz     = alphabet.length;
  const cutoff = 256 - (256 % sz); // reject bytes ≥ cutoff to eliminate bias
  let out = '';
  while (out.length < length) {
    const buf = crypto.getRandomValues(new Uint8Array((length - out.length) * 2));
    for (const byte of buf) {
      if (byte < cutoff) out += alphabet[byte % sz];
      if (out.length >= length) break;
    }
  }
  return out;
}

function generateRawApiKey() {
  return `sgk_${base64urlFromBytes(crypto.getRandomValues(new Uint8Array(32)))}`;
}

// ── API key storage helpers ───────────────────────────────────────────────────
//
// SOURCE OF TRUTH (new): user's own GitHub repo, at:
//   {folder}/.storegit/apikeys/{sha256[0:2]}/{sha256hex}.json
//
// CACHE / LEGACY (KV): "apikey:sha256:<sha256hex>"
//   Still written on every new key and read first on every lookup —
//   so existing keys keep working unchanged until migration is run.
//
// MIGRATION: POST /api/apikeys/migrate copies each KV entry to git.
//   Idempotent — safe to run multiple times.

// Derive SHA-256 hex from raw key
async function apiKeyHash(rawKey) {
  const digest = await crypto.subtle.digest('SHA-256', ENC.encode(rawKey));
  return hexEnc(new Uint8Array(digest));
}
// KV key for a hashed API key (legacy primary + new cache)
function apiKeyKvKey(sha256hex) { return `apikey:sha256:${sha256hex}`; }
// Path inside user's repo for a key record
function apiKeyGitPath(sha256hex, folder) {
  return `${folder || 'uploads'}/.storegit/apikeys/${sha256hex.slice(0, 2)}/${sha256hex}.json`;
}

// Read key record from user's git repo — returns null if missing/error
async function readApiKeyFromGit(sha256hex, ghToken, ghOwner, ghRepo, ghBranch, folder) {
  const path = apiKeyGitPath(sha256hex, folder);
  const res = await fetch(
    `https://api.github.com/repos/${encodeURIComponent(ghOwner)}/${encodeURIComponent(ghRepo)}/contents/${path}?ref=${encodeURIComponent(ghBranch || 'main')}`,
    { headers: ghH(ghToken) }
  ).catch(() => null);
  if (!res || res.status === 404) return null;
  if (!res.ok) return null;
  try {
    const d = await res.json();
    return { record: JSON.parse(DEC.decode(b64urlDec(d.content.replace(/\s/g, '')))), fileSha: d.sha };
  } catch { return null; }
}

// Write (upsert) key record to user's git repo
async function writeApiKeyToGit(sha256hex, keyRecord, ghToken, ghOwner, ghRepo, ghBranch, folder) {
  const path   = apiKeyGitPath(sha256hex, folder);
  const branch = ghBranch || 'main';
  const chkRes = await fetch(
    `https://api.github.com/repos/${encodeURIComponent(ghOwner)}/${encodeURIComponent(ghRepo)}/contents/${path}?ref=${encodeURIComponent(branch)}`,
    { headers: ghH(ghToken) }
  ).catch(() => null);
  const existingSha = (chkRes && chkRes.ok) ? (await chkRes.json()).sha : null;
  const body = {
    message: `StoreGit: API key ${keyRecord.keyId}`,
    content: utf8b64(JSON.stringify(keyRecord, null, 2)),
    branch,
    ...(existingSha ? { sha: existingSha } : {}),
  };
  const res = await fetch(
    `https://api.github.com/repos/${encodeURIComponent(ghOwner)}/${encodeURIComponent(ghRepo)}/contents/${path}`,
    { method: 'PUT', headers: ghH(ghToken), body: JSON.stringify(body) }
  );
  if (!res.ok) throw new Error('apikey_git_write_fail');
}

// Delete key record from user's git repo (best-effort; 404 = already gone)
async function deleteApiKeyFromGit(sha256hex, ghToken, ghOwner, ghRepo, ghBranch, folder) {
  const path   = apiKeyGitPath(sha256hex, folder);
  const branch = ghBranch || 'main';
  const chkRes = await fetch(
    `https://api.github.com/repos/${encodeURIComponent(ghOwner)}/${encodeURIComponent(ghRepo)}/contents/${path}?ref=${encodeURIComponent(branch)}`,
    { headers: ghH(ghToken) }
  ).catch(() => null);
  if (!chkRes || !chkRes.ok) return;
  const fileSha = (await chkRes.json()).sha;
  await fetch(
    `https://api.github.com/repos/${encodeURIComponent(ghOwner)}/${encodeURIComponent(ghRepo)}/contents/${path}`,
    { method: 'DELETE', headers: ghH(ghToken), body: JSON.stringify({ message: `StoreGit: revoke API key`, sha: fileSha, branch }) }
  ).catch(() => {});
}

async function resolveApiKey(request, env, secret) {
  const apiKey = request.headers.get('X-API-Key') || '';
  if (!APIKEY_RE.test(apiKey)) return null;

  const sha256hex = await apiKeyHash(apiKey);
  const kv        = env.RATE_LIMIT_KV || null;
  let keyData     = null;

  // 1. KV — fast path; also the legacy store for pre-migration keys
  if (kv) {
    keyData = await kv.get(apiKeyKvKey(sha256hex), 'json').catch(() => null);
  }

  if (!keyData || !keyData.username) return null;

  // Domain binding check
  const origin  = request.headers.get('Origin') || '';
  const origins = keyData.allowedOrigins || [];
  if (origins.length > 0 && origin && !origins.includes(origin)) {
    return { blocked: true, reason: 'Origin not allowed for this API key' };
  }

  // Per-key rate limiting (in-memory; no KV r/w on hot path)
  if (await checkRate(`apikey_rate:${apiKey}`, APIKEY_RATE_MAX, env, APIKEY_RATE_WINDOW)) {
    return { blocked: true, reason: 'API key rate limit exceeded' };
  }

  const rec = await getUser(keyData.username, env).catch(() => null);
  if (!rec) return null;
  const { content: user } = rec;
  let ghToken;
  try { ghToken = await aesDecrypt(user.encGhToken, secret, `user-token:${user.username}`); }
  catch { return null; }
  const repos    = getUserRepos(user);
  const repo     = repos[0];
  const fullSess = {
    username: user.username, display: user.displayName || user.username,
    ghToken, ghOwner: repo.ghOwner, ghRepo: repo.ghRepo,
    ghBranch: repo.ghBranch, folder: repo.folder,
    repoLabel: (repo.label && repo.label !== 'Default') ? repo.label : '',
    repos: repos.map(r => ({ label: r.label, ghOwner: r.ghOwner, ghRepo: r.ghRepo })),
    activeRepoIdx: 0,
  };
  return { fullSess, allowedOrigins: origins, keyData };
}
function jsonRes(req, data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...SEC, ...corsHeaders(req), 'Content-Type': 'application/json', ...extra },
  });
}
const ERRS = {
  400:'Bad request', 401:'Invalid credentials', 403:'Forbidden',
  404:'Not found',   409:'Username already taken',
  413:'Payload too large', 415:'File type not permitted',
  429:'Too many attempts — please wait and try again',
  500:'Server error', 502:'Upstream error',
};
const fail = (req, code) => jsonRes(req, { error: ERRS[code] || 'Error' }, code);
const ENC = new TextEncoder();
const DEC = new TextDecoder();
function b64Enc(u8) {
  const C = 0x8000; let s = '';
  for (let i = 0; i < u8.length; i += C)
    s += String.fromCharCode(...u8.subarray(i, Math.min(i + C, u8.length)));
  return btoa(s);
}
function b64Dec(s) { return Uint8Array.from(atob(s), c => c.charCodeAt(0)); }
function b64urlEnc(u8) { return b64Enc(u8).replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,''); }
function b64urlDec(s) {
  const p = s.replace(/-/g,'+').replace(/_/g,'/');
  return b64Dec(p + '='.repeat((4 - p.length%4)%4));
}
function hexEnc(u8) { return Array.from(u8).map(b=>b.toString(16).padStart(2,'0')).join(''); }
async function gitBlobSha(buffer) {
  const prefix = ENC.encode(`blob ${buffer.byteLength}\0`);
  const combined = new Uint8Array(prefix.byteLength + buffer.byteLength);
  combined.set(prefix);
  combined.set(new Uint8Array(buffer));
  const hash = await crypto.subtle.digest('SHA-1', combined);
  return hexEnc(new Uint8Array(hash));
}
function utf8b64(str) {
  return btoa(encodeURIComponent(str).replace(/%([0-9A-F]{2})/g,
    (_,p1) => String.fromCharCode(parseInt(p1,16))));
}
const chunkDir   = (folder, name)       => `${folder}/.chunks/${name}`;
const chunkPath  = (folder, name, idx)  => `${folder}/.chunks/${name}/${name}.part${idx}`;
const manifestP  = (folder, name)       => `${folder}/.manifests/${name}.json`;
const indexP     = (folder)             => `${folder}/.manifests/_index.json`;
async function deriveKey(secret, label, usage) {
  const raw = await crypto.subtle.importKey('raw', ENC.encode(secret), 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name:'HKDF', hash:'SHA-256', salt:ENC.encode('StoreGit-v1'), info:ENC.encode(label) },
    raw, { name:'AES-GCM', length:256 }, false, usage
  );
}
async function aesEncrypt(plaintext, secret, label='enc') {
  const key = await deriveKey(secret, label, ['encrypt']);
  const iv  = crypto.getRandomValues(new Uint8Array(12));
  const ct  = await crypto.subtle.encrypt({ name:'AES-GCM', iv }, key, ENC.encode(plaintext));
  return { iv: b64urlEnc(iv), ct: b64urlEnc(new Uint8Array(ct)) };
}
async function aesDecrypt(enc, secret, label='enc') {
  const key = await deriveKey(secret, label, ['decrypt']);
  const pt  = await crypto.subtle.decrypt(
    { name:'AES-GCM', iv: b64urlDec(enc.iv) }, key, b64urlDec(enc.ct)
  );
  return DEC.decode(pt);
}
async function hmacSign(data, secret) {
  const k = await crypto.subtle.importKey('raw', ENC.encode(secret),
    { name:'HMAC', hash:'SHA-256' }, false, ['sign']);
  const s = await crypto.subtle.sign('HMAC', k, ENC.encode(data));
  return b64urlEnc(new Uint8Array(s));
}
async function timingSafeEq(a, b) {
  const k = await crypto.subtle.importKey('raw', ENC.encode('_cmp_'),
    { name:'HMAC', hash:'SHA-256' }, false, ['sign']);
  const [ha, hb] = await Promise.all([
    crypto.subtle.sign('HMAC', k, ENC.encode(String(a))),
    crypto.subtle.sign('HMAC', k, ENC.encode(String(b))),
  ]);
  const ua = new Uint8Array(ha), ub = new Uint8Array(hb);
  let d = 0; for (let i = 0; i < ua.length; i++) d |= ua[i] ^ ub[i];
  return d === 0;
}
const PBKDF2_ITERS_CURRENT = 100_000; // active hash iterations
const PBKDF2_ITERS_LEGACY  =  50_000;  // accepted for existing accounts, re-hashed on next login
async function pbkdf2Hash(password, salt, iterations = PBKDF2_ITERS_CURRENT) {
  const km = await crypto.subtle.importKey('raw', ENC.encode(password), 'PBKDF2', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits(
    { name:'PBKDF2', salt, iterations, hash:'SHA-256' }, km, 256
  ));
}
async function blobTokenSign(jti, safeName, index, blobSha, secret) {
  return hmacSign(`blob:${jti}:${safeName}:${index}:${blobSha}`, secret);
}
function contentDisposition(safeName, forDownload = true) {
  const ascii = safeName.replace(/[^\x20-\x7E]/g, '_').replace(/["\\\/]/g, '_');
  const disp  = forDownload ? 'attachment' : 'inline';
  return `${disp}; filename="${ascii}"; filename*=UTF-8''${encodeURIComponent(safeName)}`;
}
function buildSharePage(filename, displayName, size, expIso, tok) {
  const extRaw = (displayName.split('.').pop() || '').toLowerCase();
  const extLabel = extRaw.slice(0,5).toUpperCase() || 'FILE';
  const sz = size > 0 ? (size < 1048576 ? (size/1024).toFixed(1)+' KB' : size < 1073741824 ? (size/1048576).toFixed(1)+' MB' : (size/1073741824).toFixed(2)+' GB') : '';
  const exp = expIso === null ? 'Never expires' : expIso ? 'Expires ' + new Date(expIso).toLocaleString('en-US',{dateStyle:'medium',timeStyle:'short'}) : '';
  const dlUrl = `?tok=${encodeURIComponent(tok)}&download=1`;
  const IMGS  = new Set(['jpg','jpeg','png','gif','webp','bmp','avif','tiff','tif','ico']);
  const VIDS  = new Set(['mp4','webm','mov','m4v']);
  const TEXTS = new Set(['txt','md','markdown','csv','json','log','ini','cfg','conf','yaml','yml','toml','diff','patch','nfo','js','ts','jsx','tsx','py','rb','sh','bash','c','cpp','h','java','go','rs','swift','kt','php','css','html','htm','xml','sql','r','lua']);
  const isImg  = IMGS.has(extRaw);
  const isVid  = VIDS.has(extRaw);
  const isText = TEXTS.has(extRaw);
  const BADGE_COLORS = {jpg:'#2563eb',jpeg:'#2563eb',png:'#2563eb',gif:'#2563eb',webp:'#2563eb',bmp:'#2563eb',avif:'#2563eb',tiff:'#2563eb',tif:'#2563eb',ico:'#2563eb',svg:'#2563eb',mp4:'#dc2626',webm:'#dc2626',mov:'#dc2626',m4v:'#dc2626',mp3:'#d97706',wav:'#d97706',ogg:'#d97706',m4a:'#d97706',flac:'#d97706',aac:'#d97706',js:'#16a34a',ts:'#16a34a',jsx:'#16a34a',tsx:'#16a34a',py:'#16a34a',rb:'#16a34a',go:'#16a34a',rs:'#16a34a',java:'#16a34a',c:'#16a34a',cpp:'#16a34a',h:'#16a34a',swift:'#16a34a',kt:'#16a34a',php:'#16a34a',sh:'#16a34a',bash:'#16a34a',json:'#0891b2',csv:'#0891b2',xml:'#0891b2',yaml:'#0891b2',yml:'#0891b2',sql:'#0891b2',pdf:'#ef4444',doc:'#2563eb',docx:'#2563eb',txt:'#6b7280',md:'#6b7280',zip:'#b45309',gz:'#b45309',rar:'#b45309',tar:'#b45309'};
  const badgeColor = BADGE_COLORS[extRaw] || '#6b7280';
  const nameSafe = displayName.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  const meta = [sz, exp].filter(Boolean).join('  ·  ');
  let preview = '';
  if (isImg) {
    preview = `<div class="pv-wrap img-wrap"><img src="${dlUrl}" alt="${nameSafe}" loading="lazy" onerror="this.closest('.pv-wrap').style.display='none'"></div>`;
  } else if (isVid) {
    preview = `<div class="pv-wrap vid-wrap"><video controls preload="metadata" src="${dlUrl}" onerror="this.closest('.pv-wrap').style.display='none'"></video></div>`;
  } else if (isText) {
    preview = `<div class="pv-wrap code-wrap"><div class="code-loading" id="cl"><span class="spin"></span>Loading preview\u2026</div><pre id="cp" class="code-pre" style="display:none"></pre><div id="ce" class="code-err" style="display:none">Preview unavailable.</div></div><script>(function(){fetch(${JSON.stringify(dlUrl)}).then(function(r){if(!r.ok)throw 0;return r.text();}).then(function(t){document.getElementById('cp').textContent=t.length>10000?t.slice(0,10000)+'\n\n\u2026 (truncated)':t;document.getElementById('cl').style.display='none';document.getElementById('cp').style.display='';}).catch(function(){document.getElementById('cl').style.display='none';document.getElementById('ce').style.display='';});})();<\/script>`;
  }
  return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${nameSafe} \u2014 StoreGit</title><style>:root{--bg:#eff6ff;--card:#fff;--border:#dbeafe;--t1:#111827;--t2:#6b7280;--t3:#9ca3af;--dl-bg:#2563eb;--dl-fg:#fff;--code-bg:#f8faff;--code-text:#1e293b;color-scheme:light}@media(prefers-color-scheme:dark){:root{--bg:#0d0f1a;--card:#131929;--border:#1e2e50;--t1:#f1f5f9;--t2:#94a3b8;--t3:#475569;--dl-bg:#3b82f6;--dl-fg:#fff;--code-bg:#0d1117;--code-text:#c9d1d9;color-scheme:dark}}*{box-sizing:border-box;margin:0;padding:0}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--t1);min-height:100vh;display:flex;flex-direction:column}.topbar{height:54px;background:var(--card);border-bottom:1px solid var(--border);display:flex;align-items:center;padding:0 1.75rem}.brand{display:flex;align-items:center;gap:.55rem;font-weight:700;font-size:.95rem;color:var(--t1);text-decoration:none}.brand-logo{width:20px;height:20px;border-radius:5px;background:#2563eb;display:flex;align-items:center;justify-content:center;flex-shrink:0}.brand-logo svg{display:block}main{flex:1;display:flex;justify-content:center;padding:2.5rem 1.25rem 4rem}.wrap{width:100%;max-width:${isImg||isVid||isText?'700':'420'}px;display:flex;flex-direction:column;gap:1rem}.pv-wrap{width:100%;border-radius:14px;overflow:hidden;border:1px solid var(--border);background:var(--card)}.img-wrap{background:#000;display:flex;align-items:center;justify-content:center;min-height:180px}.img-wrap img{max-width:100%;max-height:540px;object-fit:contain;display:block}.vid-wrap video{width:100%;max-height:460px;display:block;background:#000}.code-wrap{background:var(--code-bg)}.code-loading{padding:1.75rem 1.5rem;display:flex;align-items:center;gap:.6rem;color:var(--t2);font-size:.85rem}.code-pre{font-family:'SF Mono','Fira Mono',Consolas,monospace;font-size:.775rem;line-height:1.7;padding:1.25rem 1.5rem;overflow:auto;max-height:440px;white-space:pre;color:var(--code-text)}.code-err{padding:1.5rem;color:var(--t3);font-size:.85rem}.spin{width:15px;height:15px;border:2px solid var(--border);border-top-color:#2563eb;border-radius:50%;animation:sp .7s linear infinite;flex-shrink:0}@keyframes sp{to{transform:rotate(360deg)}}.info-card{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:1.5rem 1.75rem}.file-row{display:flex;align-items:center;gap:1rem;margin-bottom:1.35rem}.badge{width:50px;height:50px;min-width:50px;border-radius:11px;display:flex;align-items:center;justify-content:center;font-size:.58rem;font-weight:800;letter-spacing:.06em;color:#fff}.file-name{font-size:1.05rem;font-weight:600;color:var(--t1);word-break:break-all;line-height:1.4;margin-bottom:.3rem}.file-meta{font-size:.8rem;color:var(--t2)}.dl-btn{display:flex;align-items:center;justify-content:center;gap:.5rem;width:100%;padding:.95rem 1.25rem;background:var(--dl-bg);color:var(--dl-fg);border:none;border-radius:10px;font-family:inherit;font-size:.95rem;font-weight:600;text-decoration:none;cursor:pointer;transition:opacity .15s}.dl-btn:hover{opacity:.82}.dl-btn:active{opacity:.65}footer{text-align:center;font-size:.72rem;color:var(--t3);padding:.5rem 1.25rem 2rem}@media(max-width:480px){main{padding:1.25rem .75rem 3rem}.info-card{padding:1.25rem}.topbar{padding:0 1.25rem}}</style></head><body><header class="topbar"><a href="/" class="brand"><span class="brand-logo"><svg viewBox="0 0 20 20" width="12" height="12"><path d="M4 10h12M10 4v12" stroke="#fff" stroke-width="2.5" stroke-linecap="round"/></svg></span>StoreGit</a></header><main><div class="wrap">${preview}<div class="info-card"><div class="file-row"><div class="badge" style="background:${badgeColor}">${extLabel}</div><div><div class="file-name">${nameSafe}</div><div class="file-meta">${meta}</div></div></div><a class="dl-btn" href="${dlUrl}"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" width="17" height="17"><path d="M12 5v14M5 12l7 7 7-7"/></svg>Download</a></div></div></main><footer>Shared via StoreGit</footer></body></html>`;
}
async function createShareToken(username, filename, repoIdx, ttlSeconds, size, displayName, secret) {
  const exp     = ttlSeconds === 0 ? 0 : Date.now() + ttlSeconds * 1000;
  const payload = b64urlEnc(ENC.encode(JSON.stringify({ u: username, f: filename, r: repoIdx, e: exp, s: size || 0, d: displayName || filename })));
  const sig     = await hmacSign(`share:${payload}`, secret);
  return `${payload}.${sig}`;
}
async function verifyShareToken(token, secret) {
  if (!token || typeof token !== 'string') return null;
  const dot = token.lastIndexOf('.');
  if (dot < 1) return null;
  const payload = token.slice(0, dot), sig = token.slice(dot + 1);
  if (!(await timingSafeEq(sig, await hmacSign(`share:${payload}`, secret)))) return null;
  try {
    const raw = JSON.parse(DEC.decode(b64urlDec(payload)));
    // Support both short keys (new) and long keys (legacy tokens)
    const data = {
      username:    raw.u ?? raw.username,
      filename:    raw.f ?? raw.filename,
      repoIdx:     raw.r ?? raw.repoIdx,
      exp:         raw.e ?? raw.exp,
      size:        raw.s ?? raw.size ?? 0,
      displayName: raw.d ?? raw.displayName,
    };
    if (data.exp !== 0 && Date.now() > data.exp) return null;
    return data;
  } catch { return null; }
}
function getUserRepos(user) {
  if (Array.isArray(user.repos) && user.repos.length > 0) return user.repos;
  return [{ label: '', ghOwner: user.ghOwner, ghRepo: user.ghRepo, ghBranch: user.ghBranch, folder: user.folder }];
}
async function getFullSession(sess, env, secret) {
  if (!sess || !sess.username) return null;
  const kv      = env.RATE_LIMIT_KV || null;
  const cacheKey = `sess_cache:${sess.jti}`;
  if (kv) {
    const cached = await kv.get(cacheKey, 'json').catch(() => null);
    if (cached) {
      try {
        const ghToken = await aesDecrypt(cached.encGhToken, secret, `user-token:${cached.username}`);
        const repoIdx = typeof sess.repoIdx === 'number' ? sess.repoIdx : 0;
        const repos   = cached.repos || [];
        const repo    = repos[repoIdx] || repos[0] || {};
        return { ...sess, ghToken, ghOwner: repo.ghOwner, ghRepo: repo.ghRepo, ghBranch: repo.ghBranch, folder: repo.folder, repoLabel: (repo.label && repo.label !== 'Default') ? repo.label : '', repos, activeRepoIdx: repoIdx };
      } catch {}
    }
  }
  const rec = await getUser(sess.username, env).catch(() => null);
  if (!rec) return null;
  const { content: user } = rec;
  let ghToken;
  try { ghToken = await aesDecrypt(user.encGhToken, secret, `user-token:${user.username}`); }
  catch { return null; }
  const repoIdx = typeof sess.repoIdx === 'number' ? sess.repoIdx : 0;
  const repos   = getUserRepos(user);
  const repo    = repos[repoIdx] || repos[0];
  if (kv) {
    const ttl = Math.min(300, Math.ceil((sess.exp - Date.now()) / 1000));
    if (ttl > 0) {
      await kv.put(cacheKey, JSON.stringify({ username: user.username, encGhToken: user.encGhToken, repos }), { expirationTtl: ttl }).catch(() => {});
    }
  }
  return { ...sess, ghToken, ghOwner: repo.ghOwner, ghRepo: repo.ghRepo, ghBranch: repo.ghBranch, folder: repo.folder, repoLabel: (repo.label && repo.label !== 'Default') ? repo.label : '', repos: repos.map(r => ({ label: r.label, ghOwner: r.ghOwner, ghRepo: r.ghRepo, ghBranch: r.ghBranch || 'main', folder: r.folder || 'uploads' })), activeRepoIdx: repoIdx };
}
function isHttps(req) {
  try { return new URL(req.url).protocol === 'https:'; } catch { return false; }
}
function buildSetCookie(req, token, maxAge) {
  const https  = isHttps(req);
  const name   = https ? '__Host-sg_sess' : 'sg_sess';
  const secure = https ? '; Secure' : '';
  return `${name}=${token}; Path=/; HttpOnly${secure}; SameSite=Strict; Max-Age=${maxAge}`;
}
function readSessionCookie(req) {
  const hdr  = req.headers.get('Cookie') || '';
  const name = isHttps(req) ? '__Host-sg_sess' : 'sg_sess';
  const re   = new RegExp('(?:^|;\\s*)' + name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '=([^;]+)');
  return (hdr.match(re))?.[1] || '';
}
async function createToken(payload, secret) {
  const full = { ...payload, jti: base64urlFromBytes(crypto.getRandomValues(new Uint8Array(24))), exp: Date.now() + SESSION_TTL };
  const enc  = await aesEncrypt(JSON.stringify(full), secret, 'session');
  const body = b64urlEnc(ENC.encode(JSON.stringify(enc)));
  return `${body}.${await hmacSign(body, secret)}`;
}
async function verifyToken(token, secret) {
  if (!token || typeof token !== 'string') return null;
  const dot = token.lastIndexOf('.');
  if (dot < 1) return null;
  const body = token.slice(0, dot), sig = token.slice(dot+1);
  if (!(await timingSafeEq(sig, await hmacSign(body, secret)))) return null;
  try {
    const enc  = JSON.parse(DEC.decode(b64urlDec(body)));
    const data = JSON.parse(await aesDecrypt(enc, secret, 'session'));
    return Date.now() > data.exp ? null : data;
  } catch { return null; }
}
function getIP(req) {
  return req.headers.get('CF-Connecting-IP') ||
    req.headers.get('X-Forwarded-For')?.split(',')[0].trim() || 'unknown';
}
async function checkRate(key, max, env, windowMs = RATE_WINDOW_MS) {
  const now = Date.now();
  const kv  = env.RATE_LIMIT_KV || null;
  let r = kv
    ? await kv.get(key, 'json').catch(() => null)
    : _memRate.get(key) || null;
  if (!r || now > r.resetAt) {
    const f = { count: 1, resetAt: now + windowMs };
    if (kv) await kv.put(key, JSON.stringify(f), { expirationTtl: Math.ceil(windowMs / 1000) }).catch(() => {});
    else { _memRate.set(key, f); if (_memRate.size > 20000) for (const [k, v] of _memRate) if (now > v.resetAt) _memRate.delete(k); }
    return false;
  }
  r.count++;
  if (kv) await kv.put(key, JSON.stringify(r), { expirationTtl: Math.ceil((r.resetAt - now) / 1000) }).catch(() => {});
  else _memRate.set(key, r);
  return r.count > max;
}
async function clearRate(key, env) {
  if (env.RATE_LIMIT_KV) await env.RATE_LIMIT_KV.delete(key).catch(() => {});
  else _memRate.delete(key);
}
function sanitize(name) {
  if (!name || typeof name !== 'string') return null;
  const s = name.replace(/\0/g,'').replace(/\.\./g,'').replace(/[/\\]/g,'').trim();
  if (!s) return null;
  const safe = s.replace(/[^a-zA-Z0-9._\-()\s]/g,'_');
  if (!CLEAN_NAME_RE.test(safe)) return null;
  const ext = safe.split('.').pop()?.toLowerCase() || '';
  if (BLOCKED_EXTS.has(ext)) {
    const wrapped = safe + '.txt';
    if (!CLEAN_NAME_RE.test(wrapped)) return null;
    return wrapped;
  }
  return safe;
}
function unwrapName(storedName) {
  if (!storedName.endsWith('.txt')) return storedName;
  const original = storedName.slice(0, -4);
  if (!original) return storedName;
  const ext = original.split('.').pop()?.toLowerCase() || '';
  return BLOCKED_EXTS.has(ext) ? original : storedName;
}
function getOriginalName(rawInput, fallback) {
  try {
    const s = String(rawInput).replace(/\0/g,'').replace(/\.\./g,'').replace(/[/\\]/g,'').trim();
    if (!s) return fallback;
    const cleaned = s.replace(/[^a-zA-Z0-9._\-()\s]/g,'_');
    return CLEAN_NAME_RE.test(cleaned) ? cleaned : fallback;
  } catch { return fallback; }
}
function checkMagic(bytes) {
  for (const [off, pat] of BLOCKED_MAGIC) {
    let ok = true;
    for (let i = 0; i < pat.length; i++) { if (bytes[off+i] !== pat[i]) { ok=false; break; } }
    if (ok) return false;
  }
  return true;
}
function checkMagicBase64(b64) {
  try {
    const prefix = b64.slice(0, 24).replace(/-/g, '+').replace(/_/g, '/');
    const bin = atob(prefix);
    const head = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) head[i] = bin.charCodeAt(i);
    return checkMagic(head);
  } catch { return false; }
}
const regH = env => ({
  Authorization: `token ${env.REGISTRY_GITHUB_TOKEN}`,
  Accept: 'application/vnd.github.v3+json',
  'Content-Type': 'application/json',
  'User-Agent': 'StoreGit/1',
});
const regBase = env =>
  `https://api.github.com/repos/${encodeURIComponent(env.REGISTRY_GITHUB_OWNER)}/${encodeURIComponent(env.REGISTRY_GITHUB_REPO)}`;

const CONFIG_KV_KEY = 'storegit:config:v1';
const CONFIG_KV_TTL = 300; // 5 min

async function loadConfig(env) {
  const kv = env.RATE_LIMIT_KV;
  if (kv) {
    const cached = await kv.get(CONFIG_KV_KEY, 'json').catch(() => null);
    if (cached && typeof cached === 'object') return cached;
  }
  try {
    const res = await fetch(
      `${regBase(env)}/contents/config/config.json?ref=${REGISTRY_BRANCH}`,
      { headers: regH(env) }
    );
    if (res.ok) {
      const d   = await res.json();
      const cfg = JSON.parse(DEC.decode(b64urlDec(d.content.replace(/\s/g, ''))));
      if (kv) await kv.put(CONFIG_KV_KEY, JSON.stringify(cfg), { expirationTtl: CONFIG_KV_TTL }).catch(() => {});
      return cfg;
    }
  } catch {}
  return {};
}
// Safe numeric config read with fallback
function cn(cfg, key, fallback) {
  const v = cfg[key];
  return (typeof v === 'number' && isFinite(v) && v > 0) ? v : fallback;
}
function getRepoSess(fullSess, repoIdx) {
  const repos = fullSess.repos || [];
  const idx   = (Number.isInteger(repoIdx) && repoIdx >= 0 && repoIdx < repos.length) ? repoIdx : 0;
  const repo  = repos[idx] || repos[0] || {};
  return {
    ...fullSess,
    ghOwner:  repo.ghOwner  || fullSess.ghOwner,
    ghRepo:   repo.ghRepo   || fullSess.ghRepo,
    ghBranch: repo.ghBranch || fullSess.ghBranch || 'main',
    folder:   repo.folder   || fullSess.folder   || 'uploads',
    activeRepoIdx: idx,
  };
}
async function readReg(path, env) {
  const res = await fetch(`${regBase(env)}/contents/${path}?ref=${REGISTRY_BRANCH}`, { headers: regH(env) });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error('reg_read_fail');
  const d = await res.json();
  return { content: JSON.parse(DEC.decode(b64urlDec(d.content.replace(/\s/g,'')))), sha: d.sha };
}
async function writeReg(path, content, msg, env, sha = null) {
  const res = await fetch(`${regBase(env)}/contents/${path}`, {
    method: 'PUT', headers: regH(env),
    body: JSON.stringify({ message: msg, content: utf8b64(JSON.stringify(content,null,2)), branch: REGISTRY_BRANCH, ...(sha?{sha}:{}) }),
  });
  if (!res.ok) throw new Error('reg_write_fail');
  return (await res.json()).content?.sha;
}
function userPath(username) { return `users/${username.toLowerCase()}.json`; }
async function getUser(username, env) {
  if (!USERNAME_RE.test(username)) return null;
  return readReg(userPath(username), env).catch(() => null);
}
const ghH = token => ({
  Authorization: `token ${token}`,
  Accept: 'application/vnd.github.v3+json',
  'Content-Type': 'application/json',
  'User-Agent': 'StoreGit/1',
});
async function listFiles(sess) {
  const { ghToken, ghOwner, ghRepo, ghBranch, folder } = sess;
  const res = await fetch(
    `https://api.github.com/repos/${encodeURIComponent(ghOwner)}/${encodeURIComponent(ghRepo)}/contents/${encodeURIComponent(folder)}?ref=${encodeURIComponent(ghBranch)}`,
    { headers: ghH(ghToken) }
  );
  if (res.status === 404) return [];
  if (!res.ok) throw new Error('list_fail');
  const data = await res.json();
  return Array.isArray(data)
    ? data.filter(f => f.type === 'file' && f.name !== '.storegit').map(f => ({ name: f.name, size: f.size, sha: f.sha }))
    : [];
}
async function readIndex(sess) {
  const { ghToken, ghOwner, ghRepo, ghBranch, folder } = sess;
  const url = `https://api.github.com/repos/${encodeURIComponent(ghOwner)}/${encodeURIComponent(ghRepo)}/contents/${encodeURIComponent(indexP(folder))}?ref=${encodeURIComponent(ghBranch)}`;
  const res = await fetch(url, { headers: ghH(ghToken) });
  if (res.status === 404) return { data: {}, sha: null };
  if (!res.ok) return { data: {}, sha: null };
  const d = await res.json();
  return { data: JSON.parse(DEC.decode(b64urlDec(d.content.replace(/\s/g,'')))), sha: d.sha };
}
function isDistributed(totalSize, repos) {
  // Distribute when file is large enough that splitting meaningfully equalises repo storage,
  // AND the user has multiple repos to split across.
  // Threshold is raw bytes — no b64 conversion needed here.
  return Number.isInteger(totalSize) && totalSize > DIST_THRESHOLD && Array.isArray(repos) && repos.length > 1;
}
// ── Index caching helpers ─────────────────────────────────────────────────────
function indexCacheKey(sess) {
  return `idx_cache:${sess.ghOwner}:${sess.ghRepo}:${(sess.ghBranch||'main').replace(/\//g,'_')}:${sess.folder||'uploads'}`;
}
// readIndex with KV-backed cache (INDEX_CACHE_TTL seconds).
// Cache is keyed by repo coordinates so multiple users sharing a repo still benefit.
async function readIndexCached(sess, kv) {
  if (!kv) return readIndex(sess);
  const cKey = indexCacheKey(sess);
  try {
    const cached = await kv.get(cKey, 'json').catch(() => null);
    if (cached && typeof cached.data === 'object') return { data: cached.data, sha: cached.sha ?? null };
  } catch {}
  const result = await readIndex(sess);
  kv.put(cKey, JSON.stringify(result), { expirationTtl: INDEX_CACHE_TTL }).catch(() => {});
  return result;
}
// Bust the index cache after any write to the repo.
function invalidateIndexCache(sess, kv) {
  if (!kv) return;
  kv.delete(indexCacheKey(sess)).catch(() => {});
}
// ── Space-aware routing helpers ──────────────────────────────────────────────
// Fetch current byte totals for every repo in parallel — results cached in KV.
// Returns 0 for any repo whose index cannot be read.
async function fetchRepoBytes(fullSess, kv) {
  if (!Array.isArray(fullSess.repos) || fullSess.repos.length === 0) return [];
  return Promise.all(
    fullSess.repos.map(async (repo) => {
      try {
        const s = { ...fullSess, ghOwner: repo.ghOwner, ghRepo: repo.ghRepo,
          ghBranch: repo.ghBranch || 'main', folder: repo.folder || 'uploads' };
        if (kv) {
          const bKey = `rbytes:${s.ghOwner}:${s.ghRepo}:${(s.ghBranch||'main').replace(/\//g,'_')}:${s.folder}`;
          const cb = await kv.get(bKey, 'json').catch(() => null);
          if (typeof cb === 'number' && cb >= 0) return cb;
          const { data: idx } = await readIndex(s);
          const total = Object.values(idx).reduce((sum, f) => sum + (Number(f.totalSize ?? f.size) || 0), 0);
          kv.put(bKey, JSON.stringify(total), { expirationTtl: REPO_BYTES_CACHE_TTL }).catch(() => {});
          return total;
        }
        const { data: idx } = await readIndex(s);
        return Object.values(idx).reduce((sum, f) => sum + (Number(f.totalSize ?? f.size) || 0), 0);
      } catch { return 0; }
    })
  );
}
// Return the index of the repo with the fewest stored bytes.
async function pickLeastUsedRepo(fullSess, kv) {
  if (!Array.isArray(fullSess.repos) || fullSess.repos.length <= 1) return 0;
  const bytes = await fetchRepoBytes(fullSess, kv).catch(() => []);
  if (!bytes.length) return 0;
  let min = 0;
  for (let i = 1; i < bytes.length; i++) if (bytes[i] < bytes[min]) min = i;
  return min;
}
// ── Contiguous chunk assignment ───────────────────────────────────────────────
// Assigns CONTIGUOUS ranges of chunks to repos, filling the least-used repo first
// until it reaches the target usage level ((totalUsed + fileBytes) / repoCount).
// This eliminates per-chunk repo switching and keeps chunks together, which makes
// deleting and streaming much simpler and faster.
// Rule: if one repo can absorb the entire file within target, all chunks go there.
// ── Contiguous chunk assignment ────────────────────────────────────────────────
// Assigns CONTIGUOUS ranges of chunks to repos, targeting equal storage usage.
//
// Rule 1 — single-repo: if putting the ENTIRE file in the least-used repo keeps
//   it at or below the target usage level, use that repo only. No fragmentation.
// Rule 2 — split: otherwise fill repos greedily from least-used, each getting
//   a contiguous run sized to bring it up to targetUsage. Last repo takes the rest.
//
// targetUsage = (sum(currentUsed) + fileBytes) / repoCount
//
function computeContiguousAssignment(totalChunks, approxChunkBytes, repoCurrentBytes) {
  const n = Array.isArray(repoCurrentBytes) ? repoCurrentBytes.length : 0;
  if (n <= 1) return Array.from({ length: totalChunks }, () => 0);

  const used     = repoCurrentBytes.map(b => (Number.isFinite(b) && b >= 0 ? b : 0));
  const fileBytes = approxChunkBytes > 0 ? approxChunkBytes * totalChunks : totalChunks;
  const totalUsed = used.reduce((a, b) => a + b, 0);
  const targetPerRepo = (totalUsed + fileBytes) / n;

  // Sort repos by least-used first (highest free-space priority)
  const order = used.map((bytes, i) => ({ i, bytes })).sort((a, b) => a.bytes - b.bytes);
  const leastUsed = order[0];

  // Rule 1: entire file fits in one repo without exceeding target → single repo
  if (leastUsed.bytes + fileBytes <= targetPerRepo) {
    return Array.from({ length: totalChunks }, () => leastUsed.i);
  }

  // Rule 2: split — give each repo a contiguous run of chunks sized to reach target
  const chunksPerRepo = new Array(n).fill(0);
  let assigned = 0;
  for (let k = 0; k < order.length; k++) {
    const remaining = totalChunks - assigned;
    if (remaining <= 0) break;
    if (k === order.length - 1) {
      // Last repo absorbs all remaining chunks (handles rounding)
      chunksPerRepo[order[k].i] = remaining;
      assigned += remaining;
      break;
    }
    const capBytes = Math.max(0, targetPerRepo - order[k].bytes);
    // How many chunks fill this repo up to target?
    let give = approxChunkBytes > 0 ? Math.floor(capBytes / approxChunkBytes) : 0;
    // Must leave at least one chunk for each remaining repo
    const mustLeave = order.length - 1 - k;
    give = Math.min(give, remaining - mustLeave);
    give = Math.max(0, give);
    chunksPerRepo[order[k].i] = give;
    assigned += give;
  }
  // Safety: absorb any unassigned chunks into the least-used repo
  if (assigned < totalChunks) chunksPerRepo[order[0].i] += totalChunks - assigned;

  // Build the flat assignment array: chunks are contiguous within each repo
  // Least-used repo gets the lowest chunk indices (0, 1, 2, …)
  const assignment = new Array(totalChunks);
  let pos = 0;
  for (const { i: ri } of order) {
    for (let j = 0; j < chunksPerRepo[ri]; j++) assignment[pos++] = ri;
  }
  return assignment;
}
// ── Batch commit (single tree commit for multiple files) ──────────────────────
// Replaces commitFileToRepo for finalisation — one commit per repo regardless of
// how many chunk files are included, dramatically reducing GitHub API round-trips.
async function batchCommitForRepo(sess, filePaths, message, maxRetries = COMMIT_RETRY_MAX) {
  // filePaths: [{path: string, blobSha: string}]
  if (!filePaths.length) return;
  const { ghToken, ghOwner, ghRepo, ghBranch } = sess;
  const gh = ghH(ghToken);
  const base = `https://api.github.com/repos/${encodeURIComponent(ghOwner)}/${encodeURIComponent(ghRepo)}`;
  for (let attempt = 0; attempt < maxRetries; attempt++) {
    const refRes = await fetch(`${base}/git/ref/heads/${encodeURIComponent(ghBranch)}`, { headers: gh });
    if (!refRes.ok) throw new Error(`ref_fail:${ghRepo}`);
    const { object: { sha: headSha } } = await refRes.json();
    const commitRes = await fetch(`${base}/git/commits/${headSha}`, { headers: gh });
    if (!commitRes.ok) throw new Error(`commit_read_fail:${ghRepo}`);
    const { tree: { sha: treeSha } } = await commitRes.json();
    const treeRes = await fetch(`${base}/git/trees`, {
      method: 'POST', headers: gh,
      body: JSON.stringify({
        base_tree: treeSha,
        tree: filePaths.map(({ path, blobSha }) => ({ path, mode: '100644', type: 'blob', sha: blobSha })),
      }),
    });
    if (!treeRes.ok) throw new Error(`tree_fail:${ghRepo}`);
    const { sha: newTreeSha } = await treeRes.json();
    const newCommitRes = await fetch(`${base}/git/commits`, {
      method: 'POST', headers: gh,
      body: JSON.stringify({ message, tree: newTreeSha, parents: [headSha] }),
    });
    if (!newCommitRes.ok) throw new Error(`commit_fail:${ghRepo}`);
    const { sha: newCommit } = await newCommitRes.json();
    const updateRes = await fetch(`${base}/git/refs/heads/${encodeURIComponent(ghBranch)}`, {
      method: 'PATCH', headers: gh,
      body: JSON.stringify({ sha: newCommit, force: false }),
    });
    if (updateRes.ok) return newCommit;
    if (updateRes.status === 422 && attempt < maxRetries - 1) {
      await new Promise(r => setTimeout(r, 120 + attempt * 200 + Math.random() * 100));
      continue;
    }
    throw new Error(`ref_update_fail:${ghRepo}`);
  }
  throw new Error(`ref_update_exhausted:${ghRepo}`);
}
async function writeIndex(sess, data, existingSha) {
  const { ghToken, ghOwner, ghRepo, ghBranch, folder } = sess;
  const url = `https://api.github.com/repos/${encodeURIComponent(ghOwner)}/${encodeURIComponent(ghRepo)}/contents/${encodeURIComponent(indexP(folder))}`;
  const res = await fetch(url, {
    method: 'PUT', headers: ghH(ghToken),
    body: JSON.stringify({ message: 'StoreGit: update index', content: utf8b64(JSON.stringify(data, null, 2)), branch: ghBranch, ...(existingSha ? { sha: existingSha } : {}) }),
  });
  if (!res.ok) throw new Error('index_write_fail');
}
async function getStorageFromIndex(sess) {
  try {
    const { data: idx } = await readIndex(sess);
    const entries = Object.values(idx);
    const totalBytes = entries.reduce((sum, f) => sum + (Number(f.totalSize ?? f.size) || 0), 0);
    return { fileCount: entries.length, totalBytes, humanSize: formatBytes(totalBytes) };
  } catch {
    return { fileCount: 0, totalBytes: 0, humanSize: '0 B' };
  }
}
async function createBlob(sess, b64Content) {
  const { ghToken, ghOwner, ghRepo } = sess;
  const res = await fetch(
    `https://api.github.com/repos/${encodeURIComponent(ghOwner)}/${encodeURIComponent(ghRepo)}/git/blobs`,
    { method:'POST', headers: ghH(ghToken), body: JSON.stringify({ content: b64Content, encoding:'base64' }) }
  );
  if (!res.ok) throw new Error('blob_fail');
  return (await res.json()).sha;
}
// Commit one blob as its own commit; retries on 422 (parallel chunk race on same repo)
async function commitFileToRepo(sess, filePath, blobSha, message, maxRetries = COMMIT_RETRY_MAX) {
  const { ghToken, ghOwner, ghRepo, ghBranch } = sess;
  const gh   = ghH(ghToken);
  const base = `https://api.github.com/repos/${encodeURIComponent(ghOwner)}/${encodeURIComponent(ghRepo)}`;
  for (let attempt = 0; attempt < maxRetries; attempt++) {
    // 1. Read current HEAD
    const refRes = await fetch(`${base}/git/ref/heads/${encodeURIComponent(ghBranch)}`, { headers: gh });
    if (!refRes.ok) throw new Error(`ref_fail:${filePath}`);
    const { object: { sha: headSha } } = await refRes.json();
    // 2. Read parent tree sha
    const commitRes = await fetch(`${base}/git/commits/${headSha}`, { headers: gh });
    if (!commitRes.ok) throw new Error(`commit_read_fail:${filePath}`);
    const { tree: { sha: treeSha } } = await commitRes.json();
    // 3. Create a tree containing only this file (base_tree preserves everything else)
    const treeRes = await fetch(`${base}/git/trees`, {
      method: 'POST', headers: gh,
      body: JSON.stringify({ base_tree: treeSha, tree: [{ path: filePath, mode: '100644', type: 'blob', sha: blobSha }] }),
    });
    if (!treeRes.ok) throw new Error(`tree_fail:${filePath}`);
    const { sha: newTreeSha } = await treeRes.json();
    // 4. Create a commit with a single parent
    const newCommitRes = await fetch(`${base}/git/commits`, {
      method: 'POST', headers: gh,
      body: JSON.stringify({ message, tree: newTreeSha, parents: [headSha] }),
    });
    if (!newCommitRes.ok) throw new Error(`commit_fail:${filePath}`);
    const { sha: newCommit } = await newCommitRes.json();
    // 5. Advance the branch ref (non-force — safe, append-only)
    const updateRes = await fetch(`${base}/git/refs/heads/${encodeURIComponent(ghBranch)}`, {
      method: 'PATCH', headers: gh,
      body: JSON.stringify({ sha: newCommit, force: false }),
    });
    if (updateRes.ok) return newCommit;
    // 422 = another chunk won the race; re-read HEAD and retry
    if (updateRes.status === 422 && attempt < maxRetries - 1) {
      await new Promise(r => setTimeout(r, 120 + attempt * 160 + Math.random() * 80));
      continue;
    }
    throw new Error(`ref_update_fail:${filePath}`);
  }
  throw new Error(`ref_update_exhausted:${filePath}`);
}
async function uploadSmall(sess, filename, b64) {
  const { ghToken, ghOwner, ghRepo, ghBranch, folder } = sess;
  const url = `https://api.github.com/repos/${encodeURIComponent(ghOwner)}/${encodeURIComponent(ghRepo)}/contents/${encodeURIComponent(folder)}/${encodeURIComponent(filename)}`;
  let sha = null;
  const chk = await fetch(`${url}?ref=${ghBranch}`, { headers: ghH(ghToken) });
  if (chk.ok) sha = (await chk.json()).sha;
  const res = await fetch(url, {
    method:'PUT', headers: ghH(ghToken),
    body: JSON.stringify({ message:`Upload ${filename}`, content: b64, branch: ghBranch, ...(sha?{sha}:{}) }),
  });
  if (!res.ok) throw new Error('upload_fail');
}
// Single batch commit: all chunk blobs + manifest in ONE tree commit per repo.
// Previously this only committed the manifest (chunks were committed one-by-one during upload).
// Now upload-chunk only creates blobs (no commits); finalize does the single commit.
async function finalizeChunkedUpload(sess, safeName, blobs, totalSize, chunkSize) {
  const sorted = blobs.slice().sort((a, b) => a.index - b.index);
  const manifest = {
    name: safeName, totalSize, totalChunks: blobs.length, chunkSize,
    uploadedAt: new Date().toISOString(),
    chunks: sorted.map(b => ({ index: b.index, size: b.size, blobSha: b.blobSha })),
  };
  // Create manifest blob and commit everything in one tree operation
  const manifestBlobSha = await createBlob(sess, utf8b64(JSON.stringify(manifest, null, 2)));
  const filePaths = [
    ...sorted.map(b => ({ path: chunkPath(sess.folder, safeName, b.index), blobSha: b.blobSha })),
    { path: manifestP(sess.folder, safeName), blobSha: manifestBlobSha },
  ];
  await batchCommitForRepo(sess, filePaths, `StoreGit: ${safeName} (${blobs.length} parts)`);
}
// Parallel batch commits per repo — one commit per repo regardless of chunk count.
// Previously did per-chunk commits; now all chunks for a repo land in a single tree.
async function finalizeDistributedUpload(fullSess, safeName, blobs, totalSize, chunkSize) {
  const repos = fullSess.repos;
  const sorted = blobs.slice().sort((a, b) => a.index - b.index);
  const manifest = {
    name: safeName, totalSize, totalChunks: blobs.length, chunkSize,
    distributed: true, repoCount: repos.length,
    uploadedAt: new Date().toISOString(),
    chunks: sorted.map(b => {
      const repo = repos[b.repoIdx ?? 0] || repos[0];
      return { index: b.index, size: b.size, blobSha: b.blobSha, repoIdx: b.repoIdx ?? 0,
        ghOwner: repo.ghOwner, ghRepo: repo.ghRepo,
        ghBranch: repo.ghBranch || 'main', folder: repo.folder || 'uploads' };
    }),
  };
  const manifestBlobSha = await createBlob(fullSess, utf8b64(JSON.stringify(manifest, null, 2)));
  // Group chunks by repoIdx
  const byRepo = new Map();
  for (const b of sorted) {
    const ri = b.repoIdx ?? 0;
    if (!byRepo.has(ri)) byRepo.set(ri, []);
    byRepo.get(ri).push(b);
  }
  const primaryRepoIdx = 0;
  // Commit each repo in parallel — one tree per repo
  await Promise.all([...byRepo.entries()].map(async ([repoIdx, repoBlobs]) => {
    const repoSess = getRepoSess(fullSess, repoIdx);
    const filePaths = repoBlobs.map(b => ({
      path: chunkPath(repoSess.folder, safeName, b.index), blobSha: b.blobSha,
    }));
    if (repoIdx === primaryRepoIdx) {
      filePaths.push({ path: manifestP(repoSess.folder, safeName), blobSha: manifestBlobSha });
    }
    await batchCommitForRepo(repoSess, filePaths,
      `StoreGit dist: ${safeName} repo${repoIdx} (${repoBlobs.length} chunks)`);
  }));
  // If primary repo had no chunks, commit just the manifest there
  if (!byRepo.has(primaryRepoIdx)) {
    const primarySess = getRepoSess(fullSess, primaryRepoIdx);
    await batchCommitForRepo(primarySess,
      [{ path: manifestP(primarySess.folder, safeName), blobSha: manifestBlobSha }],
      `StoreGit dist-manifest: ${safeName}`);
  }
}
async function deleteChunked(sess, safeName) {
  const { ghToken, ghOwner, ghRepo, ghBranch, folder } = sess;
  const gh   = ghH(ghToken);
  const base = `https://api.github.com/repos/${encodeURIComponent(ghOwner)}/${encodeURIComponent(ghRepo)}`;
  const chunkDirRes = await fetch(`${base}/contents/${chunkDir(folder, safeName)}?ref=${ghBranch}`, { headers: gh });
  let chunkFiles = [];
  if (chunkDirRes.ok) { const d = await chunkDirRes.json(); chunkFiles = Array.isArray(d) ? d.filter(f => f.type === 'file') : []; }
  const refRes = await fetch(`${base}/git/ref/heads/${ghBranch}`, { headers: gh });
  if (!refRes.ok) throw new Error('ref_fail');
  const { object: { sha: headSha } } = await refRes.json();
  const commitRes = await fetch(`${base}/git/commits/${headSha}`, { headers: gh });
  if (!commitRes.ok) throw new Error('commit_read_fail');
  const { tree: { sha: treeSha } } = await commitRes.json();
  const treeItems = [
    ...chunkFiles.map(f => ({ path: `${chunkDir(folder, safeName)}/${f.name}`, mode: '100644', type: 'blob', sha: null })),
    { path: manifestP(folder, safeName), mode: '100644', type: 'blob', sha: null },
  ];
  const newTreeRes = await fetch(`${base}/git/trees`, { method: 'POST', headers: gh, body: JSON.stringify({ base_tree: treeSha, tree: treeItems }) });
  if (!newTreeRes.ok) throw new Error('tree_fail');
  const { sha: newTreeSha } = await newTreeRes.json();
  const newCommitRes = await fetch(`${base}/git/commits`, { method: 'POST', headers: gh, body: JSON.stringify({ message: `Delete ${safeName}`, tree: newTreeSha, parents: [headSha] }) });
  if (!newCommitRes.ok) throw new Error('commit_fail');
  const { sha: newCommit } = await newCommitRes.json();
  const updateRes = await fetch(`${base}/git/refs/heads/${ghBranch}`, { method: 'PATCH', headers: gh, body: JSON.stringify({ sha: newCommit, force: false }) });
  if (!updateRes.ok) throw new Error('ref_update_fail');
}
// Read manifest → delete chunks in parallel across repos → remove manifest
async function deleteDistributed(fullSess, safeName) {
  const { ghToken, ghOwner, ghRepo, ghBranch, folder } = fullSess;
  const gh   = ghH(ghToken);
  // Load master manifest from active repo
  const mRes = await fetch(`https://api.github.com/repos/${ghOwner}/${ghRepo}/contents/${manifestP(folder, safeName)}?ref=${ghBranch}`, { headers: gh });
  if (!mRes.ok) throw new Error('manifest_missing');
  const mData = await mRes.json();
  const manifest = JSON.parse(atob(mData.content.replace(/\s/g, '')));
  // Group chunks by repo using the routing data baked into the manifest
  const byRepo = new Map();
  for (const chunk of (manifest.chunks || [])) {
    const key = `${chunk.ghOwner}/${chunk.ghRepo}/${chunk.ghBranch}/${chunk.folder}`;
    if (!byRepo.has(key)) byRepo.set(key, { chunk, indices: [] });
    byRepo.get(key).indices.push(chunk.index);
  }
  // Delete chunks from each repo in parallel
  await Promise.all([...byRepo.values()].map(async ({ chunk: rep, indices }) => {
    const base = `https://api.github.com/repos/${encodeURIComponent(rep.ghOwner)}/${encodeURIComponent(rep.ghRepo)}`;
    const repGh = ghH(ghToken);
    const refRes = await fetch(`${base}/git/ref/heads/${rep.ghBranch}`, { headers: repGh });
    if (!refRes.ok) throw new Error(`ref_fail:${rep.ghRepo}`);
    const { object: { sha: headSha } } = await refRes.json();
    const commitRes = await fetch(`${base}/git/commits/${headSha}`, { headers: repGh });
    if (!commitRes.ok) throw new Error(`commit_read_fail:${rep.ghRepo}`);
    const { tree: { sha: treeSha } } = await commitRes.json();
    const treeItems = indices.map(idx => ({ path: chunkPath(rep.folder, safeName, idx), mode: '100644', type: 'blob', sha: null }));
    const newTreeRes = await fetch(`${base}/git/trees`, { method: 'POST', headers: repGh, body: JSON.stringify({ base_tree: treeSha, tree: treeItems }) });
    if (!newTreeRes.ok) throw new Error(`tree_fail:${rep.ghRepo}`);
    const { sha: newTreeSha } = await newTreeRes.json();
    const newCommitRes = await fetch(`${base}/git/commits`, { method: 'POST', headers: repGh, body: JSON.stringify({ message: `StoreGit dist-delete: ${safeName}`, tree: newTreeSha, parents: [headSha] }) });
    if (!newCommitRes.ok) throw new Error(`commit_fail:${rep.ghRepo}`);
    const { sha: newCommit } = await newCommitRes.json();
    const upRes = await fetch(`${base}/git/refs/heads/${rep.ghBranch}`, { method: 'PATCH', headers: repGh, body: JSON.stringify({ sha: newCommit, force: false }) });
    if (!upRes.ok) throw new Error(`ref_update_fail:${rep.ghRepo}`);
  }));
  // Remove manifest from active repo
  const base = `https://api.github.com/repos/${encodeURIComponent(ghOwner)}/${encodeURIComponent(ghRepo)}`;
  const refRes = await fetch(`${base}/git/ref/heads/${ghBranch}`, { headers: gh });
  if (!refRes.ok) throw new Error('manifest_ref_fail');
  const { object: { sha: headSha } } = await refRes.json();
  const commitRes = await fetch(`${base}/git/commits/${headSha}`, { headers: gh });
  if (!commitRes.ok) throw new Error('manifest_commit_read_fail');
  const { tree: { sha: treeSha } } = await commitRes.json();
  const newTreeRes = await fetch(`${base}/git/trees`, { method: 'POST', headers: gh, body: JSON.stringify({ base_tree: treeSha, tree: [{ path: manifestP(folder, safeName), mode: '100644', type: 'blob', sha: null }] }) });
  if (!newTreeRes.ok) throw new Error('manifest_tree_fail');
  const { sha: newTreeSha } = await newTreeRes.json();
  const newCommitRes = await fetch(`${base}/git/commits`, { method: 'POST', headers: gh, body: JSON.stringify({ message: `StoreGit dist-delete-manifest: ${safeName}`, tree: newTreeSha, parents: [headSha] }) });
  if (!newCommitRes.ok) throw new Error('manifest_commit_fail');
  const { sha: newCommit } = await newCommitRes.json();
  const upRes = await fetch(`${base}/git/refs/heads/${ghBranch}`, { method: 'PATCH', headers: gh, body: JSON.stringify({ sha: newCommit, force: false }) });
  if (!upRes.ok) throw new Error('manifest_ref_update_fail');
}
async function deleteRegular(sess, filename, sha) {
  const { ghToken, ghOwner, ghRepo, ghBranch, folder } = sess;
  const res = await fetch(
    `https://api.github.com/repos/${encodeURIComponent(ghOwner)}/${encodeURIComponent(ghRepo)}/contents/${encodeURIComponent(folder)}/${encodeURIComponent(filename)}`,
    { method:'DELETE', headers: ghH(ghToken), body: JSON.stringify({ message:`Delete ${filename}`, sha, branch: ghBranch }) }
  );
  if (!res.ok) throw new Error('delete_fail');
}
const MIMES = {
  pdf:'application/pdf', doc:'application/msword',
  docx:'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  xls:'application/vnd.ms-excel', xlsx:'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  ppt:'application/vnd.ms-powerpoint', pptx:'application/vnd.openxmlformats-officedocument.presentationml.presentation',
  txt:'text/plain;charset=utf-8', csv:'text/plain;charset=utf-8', md:'text/plain;charset=utf-8', rtf:'application/rtf',
  jpg:'image/jpeg', jpeg:'image/jpeg', png:'image/png', gif:'image/gif', webp:'image/webp', bmp:'image/bmp',
  mp3:'audio/mpeg', wav:'audio/wav', ogg:'audio/ogg', flac:'audio/flac', m4a:'audio/mp4', aac:'audio/aac',
  mp4:'video/mp4', webm:'video/webm', mov:'video/quicktime', avi:'video/x-msvideo', mkv:'video/x-matroska',
  zip:'application/zip', gz:'application/gzip', tar:'application/x-tar', '7z':'application/x-7z-compressed', rar:'application/vnd.rar',
  json:'text/plain;charset=utf-8', yaml:'text/plain;charset=utf-8', yml:'text/plain;charset=utf-8',
};
const safeMime = name => MIMES[name.split('.').pop()?.toLowerCase()||''] || 'application/octet-stream';
export async function onRequest({ request, env, params }) {
  try {
    return await _handleRequest({ request, env, params });
  } catch (err) {
    const msg = (err instanceof Error) ? err.message : String(err);
    console.error('[StoreGit] Unhandled error:', msg, err?.stack || '');
    return new Response(
      JSON.stringify({ error: 'An unexpected server error occurred.' }),
      { status: 500, headers: { ...SEC, 'Content-Type': 'application/json' } }
    );
  }
}
async function _handleRequest({ request, env, params }) {
  const method = request.method.toUpperCase();
  const route  = (params.path || []).join('/');
  // API key auth only on real requests, not OPTIONS preflights
  if (method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: { ...SEC, ...corsHeaders(request, []) } });
  }
  const secret = env.TOKEN_SECRET;
  if (!secret) return fail(request, 500);
  const cfg = await loadConfig(env).catch(() => ({}));
  if (route === 'status' && method === 'GET') {
    const ready = !!(env.REGISTRY_GITHUB_TOKEN && env.REGISTRY_GITHUB_OWNER && env.REGISTRY_GITHUB_REPO);
    return jsonRes(request, {
      ready,
      version: '1',
      kvAvailable: !!(env.RATE_LIMIT_KV),
      uploadConcurrency: cn(cfg, 'upload_concurrency', UPLOAD_CONCURRENCY),
      distThresholdBytes: cn(cfg, 'dist_threshold_bytes', DIST_THRESHOLD),
      // chunkMaxRawBytes: safe per-chunk raw size the server accepts via upload-chunk.
      // = floor(CHUNK_B64_MAX × 3/4) — client uses this to set its CHUNK_THRESHOLD.
      chunkMaxRawBytes: Math.floor(cn(cfg, 'chunk_b64_max', CHUNK_B64_MAX) * 3 / 4),
      ...(!ready && { hint: 'Missing one or more required env vars: REGISTRY_GITHUB_TOKEN, REGISTRY_GITHUB_OWNER, REGISTRY_GITHUB_REPO' }),
      endpoints: {
        public: [
          { method: 'GET',    path: '/api/status' },
          { method: 'POST',   path: '/api/signup' },
          { method: 'POST',   path: '/api/auth' },
          { method: 'POST',   path: '/api/reset-password' },
          { method: 'GET',    path: '/api/dl?tok=<token>' },
        ],
        authenticated: [
          { method: 'POST',   path: '/api/logout',          auth: ['session'] },
          { method: 'GET',    path: '/api/me',               auth: ['session', 'apiKey'], note: 'Includes active-repo storage stats' },
          { method: 'GET',    path: '/api/repos',            auth: ['session', 'apiKey'] },
          { method: 'GET',    path: '/api/storage',          auth: ['session', 'apiKey'], note: 'Per-repo and total storage breakdown' },
          { method: 'POST',   path: '/api/switch-repo',      auth: ['session'] },
          { method: 'POST',   path: '/api/add-repo',         auth: ['session'] },
          { method: 'POST',   path: '/api/remove-repo',      auth: ['session'] },
          { method: 'GET',    path: '/api/files',            auth: ['session', 'apiKey'], note: 'Returns file array — supports ?repoIdx=N. Use /api/storage for size totals.' },
          { method: 'POST',   path: '/api/upload',           auth: ['session', 'apiKey'] },
          { method: 'POST',   path: '/api/upload-chunk',     auth: ['session', 'apiKey'] },
          { method: 'POST',   path: '/api/finalize-upload',  auth: ['session', 'apiKey'] },
          { method: 'GET',    path: '/api/download',         auth: ['session', 'apiKey'] },
          { method: 'DELETE', path: '/api/delete',           auth: ['session', 'apiKey'] },
          { method: 'GET',    path: '/api/share-link',       auth: ['session', 'apiKey'] },
          { method: 'GET',    path: '/api/apikeys/list',     auth: ['session'] },
          { method: 'POST',   path: '/api/apikeys/create',   auth: ['session'] },
          { method: 'DELETE', path: '/api/apikeys/revoke',   auth: ['session'] },
          { method: 'POST',   path: '/api/apikeys/migrate',  auth: ['session'], note: 'One-time migration: copies KV-stored keys into your git repo (idempotent)' },
        ],
      },
    });
  }
  if (route === 'signup' && method === 'POST') {
    const ip = getIP(request);
    if (await checkRate(`signup:${ip}`, RATE_MAX_SIGNUP, env)) return fail(request, 429);
    // Fail fast if the registry is not configured — avoids misleading "Upstream error"
    // after the user has already filled in valid credentials.
    if (!env.REGISTRY_GITHUB_TOKEN || !env.REGISTRY_GITHUB_OWNER || !env.REGISTRY_GITHUB_REPO)
      return jsonRes(request, { error: 'Registration is not available (service misconfigured)' }, 503);
    let body; try { body = await request.json(); } catch { return fail(request, 400); }
    const { username, password, ghToken, ghOwner, ghRepo, ghBranch='main', folder='uploads' } = body||{};
    if (!username||!password||!ghToken||!ghOwner||!ghRepo) return fail(request, 400);
    if (!USERNAME_RE.test(username)) return jsonRes(request,{error:'Username must be 3–32 chars: letters, numbers, hyphens, underscores'},400);
    if (password.length < 8) return jsonRes(request,{error:'Password must be at least 8 characters'},400);
    if (!OWNER_RE.test(ghOwner))   return jsonRes(request,{error:'Invalid GitHub owner name'},400);
    if (!REPO_RE.test(ghRepo))     return jsonRes(request,{error:'Invalid GitHub repository name'},400);
    if (!BRANCH_RE.test(ghBranch)) return jsonRes(request,{error:'Invalid branch name'},400);
    if (!FOLDER_RE.test(folder))   return jsonRes(request,{error:'Invalid folder name'},400);
    if (await getUser(username, env)) return fail(request, 409);
    if (!/^(ghp_[a-zA-Z0-9]{36,}|github_pat_[a-zA-Z0-9_]{40,})$/.test(ghToken))
      return jsonRes(request, {error: 'Invalid GitHub token format'}, 400);
    const repoCheck = await fetch(
      `https://api.github.com/repos/${ghOwner}/${ghRepo}`,
      { headers:{ Authorization:`token ${ghToken}`, Accept:'application/vnd.github.v3+json', 'User-Agent':'StoreGit/1' } }
    );
    if (repoCheck.status===401) return jsonRes(request,{error:'Invalid GitHub token'},400);
    if (repoCheck.status===404) return jsonRes(request,{error:'Repository not found'},400);
    if (!repoCheck.ok) return jsonRes(request,{error:'GitHub validation failed'},400);
    const repoData = await repoCheck.json();
    if (!repoData.permissions?.push && !repoData.permissions?.admin)
      return jsonRes(request,{error:'Token requires write access to this repository'},400);
    const salt       = crypto.getRandomValues(new Uint8Array(16));
    const pwHash     = await pbkdf2Hash(password, salt);
    const encGhToken = await aesEncrypt(ghToken, secret, `user-token:${username.toLowerCase()}`);
    const firstRepo  = { label: '', ghOwner, ghRepo, ghBranch, folder };
    const userRecord = {
      username: username.toLowerCase(), displayName: username,
      pwSalt: b64urlEnc(salt), pwHash: b64urlEnc(pwHash),
      encGhToken, ghOwner, ghRepo, ghBranch, folder,
      repos: [firstRepo],
      createdAt: new Date().toISOString(),
    };
    try { await writeReg(userPath(username), userRecord, `Register ${username.toLowerCase()}`, env); }
    catch (regErr) {
      // Surface a meaningful error instead of the opaque "Upstream error".
      // Common causes: registry token expired/missing write access, or the
      // registry repo itself does not exist.
      const msg = regErr?.message || '';
      if (msg === 'reg_write_fail') {
        // Probe the registry repo so we can give a precise reason.
        let regStatus = 0;
        try {
          const probe = await fetch(
            `${regBase(env)}/contents/`,
            { headers: regH(env) }
          );
          regStatus = probe.status;
        } catch { /* network failure handled below */ }
        if (regStatus === 401 || regStatus === 403)
          return jsonRes(request, { error: 'Registration failed: registry access token is invalid or lacks write permission' }, 502);
        if (regStatus === 404)
          return jsonRes(request, { error: 'Registration failed: registry repository not found' }, 502);
      }
      return jsonRes(request, { error: 'Registration failed: could not save account. Please try again later.' }, 502);
    }
    const markerUrl = `https://api.github.com/repos/${ghOwner}/${ghRepo}/contents/${folder}/.storegit`;
    const markerChk = await fetch(`${markerUrl}?ref=${ghBranch}`, { headers: ghH(ghToken) });
    if (markerChk.status === 404) {
      await fetch(markerUrl, {
        method:'PUT', headers: ghH(ghToken),
        body: JSON.stringify({ message:'Initialize StoreGit storage', content: utf8b64(`# StoreGit Storage\nManaged by StoreGit. Do not delete this file.\nUser: ${username}\n`), branch: ghBranch }),
      }).catch(()=>{});
    }
    return jsonRes(request, { ok:true });
  }
  if (route === 'auth' && method === 'POST') {
    const ip = getIP(request);
    if (await checkRate(`login:${ip}`, LOGIN_LOCKOUT_ATTEMPTS, env, LOGIN_LOCKOUT_MS)) return fail(request, 429);
    let body; try { body = await request.json(); } catch { return fail(request, 400); }
    const { username, password } = body||{};
    if (!username||!password) return fail(request, 400);
    if (await checkRate(`login:user:${username.toLowerCase()}`, LOGIN_LOCKOUT_ATTEMPTS, env, LOGIN_LOCKOUT_MS)) return fail(request, 429);
    const rec = await getUser(username, env);
    if (!rec) {
      await pbkdf2Hash(password, crypto.getRandomValues(new Uint8Array(16)));
      await new Promise(r=>setTimeout(r,100+Math.random()*200));
      return fail(request, 401);
    }
    const { content: user } = rec;
    const salt   = b64urlDec(user.pwSalt);
    const stored = b64urlDec(user.pwHash);
    const derivedCurrent = await pbkdf2Hash(password, salt, PBKDF2_ITERS_CURRENT);
    let diffCurrent = 0; for (let i = 0; i < 32; i++) diffCurrent |= derivedCurrent[i] ^ (stored[i] ?? 0);
    if (diffCurrent !== 0) {
      const derivedLegacy = await pbkdf2Hash(password, salt, PBKDF2_ITERS_LEGACY);
      let diffLegacy = 0; for (let i = 0; i < 32; i++) diffLegacy |= derivedLegacy[i] ^ (stored[i] ?? 0);
      if (diffLegacy !== 0) {
        await new Promise(r => setTimeout(r, 300 + Math.random() * 200));
        return fail(request, 401);
      }
    }
    await clearRate(`login:${ip}`, env);
    await clearRate(`login:user:${user.username}`, env);
    const token = await createToken({ username: user.username, display: user.displayName||user.username, repoIdx: 0 }, secret);
    return jsonRes(request, { ok:true, display: user.displayName||user.username }, 200, {
      'Set-Cookie': buildSetCookie(request, token, SESSION_TTL / 1000),
    });
  }
  if (route === 'logout' && method === 'POST') {
    const rawToken = readSessionCookie(request);
    const sess = await verifyToken(rawToken, secret);
    if (sess) {
      const kv = env.RATE_LIMIT_KV || null;
      if (kv) {
        const remaining = Math.ceil((sess.exp - Date.now()) / 1000);
        if (remaining > 0) await kv.put(`revoked:${sess.jti}`, '1', { expirationTtl: remaining }).catch(() => {});
        await kv.delete(`sess_cache:${sess.jti}`).catch(() => {});
      }
    }
    return jsonRes(request, { ok:true }, 200, { 'Set-Cookie': buildSetCookie(request, '', 0) });
  }
  if (route === 'dl' && method === 'GET') {
    const sp       = new URL(request.url).searchParams;
    const tok      = sp.get('tok') || '';
    const isDownload = sp.get('download') === '1';
    const data     = await verifyShareToken(tok, secret);
    if (!data) {
      if (!isDownload && (request.headers.get('Accept') || '').includes('text/html')) {
        const html = '<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Link Expired</title><style>body{font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;background:#f4f4f6;color:#111}.card{background:#fff;border-radius:14px;padding:2rem;text-align:center;max-width:320px;box-shadow:0 4px 24px rgba(0,0,0,.08)}h2{margin-bottom:.5rem}p{font-size:.85rem;color:#888}</style></head><body><div class="card"><h2>Link expired</h2><p>This share link has expired or is invalid.</p></div></body></html>';
        return new Response(html, { status:410, headers:{'Content-Type':'text/html;charset=utf-8','X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Cache-Control':'no-store'} });
      }
      return fail(request, 403);
    }
    if (!isDownload && (request.headers.get('Accept') || '').includes('text/html')) {
      const page = buildSharePage(data.filename, data.displayName || data.filename, data.size || 0, data.exp === 0 ? null : new Date(data.exp).toISOString(), tok);
      return new Response(page, { status:200, headers:{'Content-Type':'text/html;charset=utf-8','X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Referrer-Policy':'no-referrer','Cache-Control':'no-store','Content-Security-Policy':"default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src 'self'; media-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none';"} });
    }
    const rec = await getUser(data.username, env);
    if (!rec) return fail(request, 404);
    const { content: user } = rec;
    let ghToken;
    try { ghToken = await aesDecrypt(user.encGhToken, secret, `user-token:${user.username}`); }
    catch { return fail(request, 500); }
    const repos    = getUserRepos(user);
    const repoIdx  = typeof data.repoIdx === 'number' ? data.repoIdx : 0;
    const repo     = repos[repoIdx] || repos[0];
    const { ghOwner, ghRepo, ghBranch, folder } = repo;
    const safe     = sanitize(data.filename);
    if (!safe) return fail(request, 400);
    const fakeSess = { ghToken, ghOwner, ghRepo, ghBranch, folder };
    let manifest   = null, serveAs = safe;
    try {
      const { data: idx } = await readIndex(fakeSess);
      if (idx[safe]) serveAs = idx[safe].originalName || unwrapName(safe);
      else serveAs = unwrapName(safe);
      if (idx[safe]?.totalChunks) {
        const mRes = await fetch(`https://api.github.com/repos/${ghOwner}/${ghRepo}/contents/${manifestP(folder,safe)}?ref=${ghBranch}`, { headers: ghH(ghToken) });
        if (mRes.ok) { const mData = await mRes.json(); manifest = JSON.parse(atob(mData.content.replace(/\s/g,''))); }
      }
    } catch {}
    if (manifest) {
      const authHeader = { Authorization:`token ${ghToken}`, 'User-Agent':'StoreGit/1' };
      const cfg2 = await loadConfig(env).catch(() => ({}));
      const dlWindow = Math.max(1, cn(cfg2, 'parallel_dl_chunks', PARALLEL_DL_CHUNKS));
      const fetchChunkDl = async (i) => {
        const chunkMeta   = manifest.chunks?.[i];
        const chunkOwner  = chunkMeta?.ghOwner  || ghOwner;
        const chunkRepo   = chunkMeta?.ghRepo   || ghRepo;
        const chunkBranch = chunkMeta?.ghBranch || ghBranch;
        const chunkFolder = chunkMeta?.folder   || folder;
        const chunkUrl    = `https://raw.githubusercontent.com/${chunkOwner}/${chunkRepo}/${chunkBranch}/${chunkPath(chunkFolder, safe, i)}`;
        const res = await fetch(chunkUrl, { headers: authHeader });
        if (!res.ok) throw new Error(`chunk_${i}_missing`);
        const buf = await res.arrayBuffer();
        if (chunkMeta?.blobSha) {
          const actual = await gitBlobSha(buf);
          if (actual !== chunkMeta.blobSha) throw new Error(`chunk_${i}_corrupt`);
        }
        return new Uint8Array(buf);
      };
      const stream = new ReadableStream({
        async start(controller) {
          try {
            const total   = manifest.totalChunks;
            const pending = new Map();
            for (let i = 0; i < Math.min(dlWindow, total); i++) pending.set(i, fetchChunkDl(i));
            for (let i = 0; i < total; i++) {
              const data = await pending.get(i);
              pending.delete(i);
              const next = i + dlWindow;
              if (next < total) pending.set(next, fetchChunkDl(next));
              controller.enqueue(data);
            }
            controller.close();
          } catch (e) { controller.error(e); }
        },
      });
      return new Response(stream, { status:200, headers: { ...SEC, 'Content-Type': safeMime(serveAs), 'Content-Disposition': contentDisposition(serveAs, isDownload), 'Content-Length': String(manifest.totalSize), 'Accept-Ranges':'none' } });
    }
    const rawUrl = `https://raw.githubusercontent.com/${ghOwner}/${ghRepo}/${ghBranch}/${folder}/${encodeURIComponent(safe)}`;
    let ghRes;
    try { ghRes = await fetch(rawUrl, { headers:{ Authorization:`token ${ghToken}`, 'User-Agent':'StoreGit/1' } }); }
    catch { return fail(request, 502); }
    if (ghRes.status===404) return fail(request, 404);
    if (!ghRes.ok) return fail(request, 502);
    const len = ghRes.headers.get('Content-Length') || '';
    return new Response(ghRes.body, { status:200, headers: { ...SEC, 'Content-Type': safeMime(serveAs), 'Content-Disposition': contentDisposition(serveAs, isDownload), ...(len?{'Content-Length':len}:{}), 'Accept-Ranges':'bytes' } });
  }
  if (route === 'reset-password' && method === 'POST') {
    const ip = getIP(request);
    if (await checkRate(`reset:${ip}`, RATE_MAX_RESET, env)) return fail(request, 429);
    let body; try { body = await request.json(); } catch { return fail(request, 400); }
    const { username, ghToken, newPassword } = body||{};
    if (!username||!ghToken||!newPassword) return fail(request, 400);
    if (newPassword.length < 8) return jsonRes(request, {error:'Password must be at least 8 characters'}, 400);
    const rec = await getUser(username, env);
    if (!rec) {
      await new Promise(r => setTimeout(r, 300 + Math.random() * 200));
      return fail(request, 401);
    }
    const { content: user, sha: userSha } = rec;
    const repos    = getUserRepos(user);
    const mainRepo = repos[0];
    const repoCheck = await fetch(
      `https://api.github.com/repos/${mainRepo.ghOwner}/${mainRepo.ghRepo}`,
      { headers:{ Authorization:`token ${ghToken}`, Accept:'application/vnd.github.v3+json', 'User-Agent':'StoreGit/1' } }
    );
    if (!repoCheck.ok || !(await repoCheck.json()).permissions?.push) {
      await new Promise(r => setTimeout(r, 300 + Math.random() * 200));
      return fail(request, 401);
    }
    const salt       = crypto.getRandomValues(new Uint8Array(16));
    const pwHash     = await pbkdf2Hash(newPassword, salt);
    const encGhToken = await aesEncrypt(ghToken, secret, `user-token:${user.username}`);
    const updated    = { ...user, pwSalt: b64urlEnc(salt), pwHash: b64urlEnc(pwHash), encGhToken };
    try { await writeReg(userPath(username), updated, `Password reset ${user.username}`, env, userSha); }
    catch { return fail(request, 502); }
    return jsonRes(request, { ok:true });
  }
  const apiKeyHeader = request.headers.get('X-API-Key') || '';
  if (apiKeyHeader) {
    const akResult = await resolveApiKey(request, env, secret);
    if (!akResult) return fail(request, 401);
    if (akResult.blocked) return jsonRes(request, { error: akResult.reason }, 403);
    // API keys can access storage routes only (not account management)
    const AK_ALLOWED = new Set(['files','upload','upload-chunk','finalize-upload','download','delete','share-link','me','repos','storage']);
    if (!AK_ALLOWED.has(route)) return fail(request, 403);
    return _dispatchRoute(route, method, request, env, akResult.fullSess, null, secret, akResult.allowedOrigins, cfg);
  }

  const rawToken = readSessionCookie(request);
  const sess     = await verifyToken(rawToken, secret);
  if (!sess) return fail(request, 401);
  const kv = env.RATE_LIMIT_KV || null;
  if (kv) {
    const revoked = await kv.get(`revoked:${sess.jti}`).catch(() => null);
    if (revoked) return fail(request, 401);
  }
  const fullSess = await getFullSession(sess, env, secret);
  if (!fullSess) return fail(request, 401);
  let refreshCookie = null;
  if (sess.exp - Date.now() < SESSION_REFRESH_THRESHOLD) {
    const newTok = await createToken({ username: sess.username, display: sess.display, repoIdx: sess.repoIdx ?? 0 }, secret);
    refreshCookie = buildSetCookie(request, newTok, SESSION_TTL / 1000);
  }
  const response = await _dispatchRoute(route, method, request, env, fullSess, sess, secret, null, cfg);
  if (refreshCookie) {
    const headers = new Headers(response.headers);
    headers.append('Set-Cookie', refreshCookie);
    return new Response(response.body, { status: response.status, headers });
  }
  return response;
}
async function _dispatchRoute(route, method, request, env, fullSess, sess, secret, apiKeyOrigins = null, cfg = {}) {
  const cors = corsHeaders(request, apiKeyOrigins);
  const C_SHARE_TTL_MAX      = cn(cfg, 'share_ttl_max_seconds',      SHARE_TTL_MAX);
  const C_CHUNK_B64_MAX      = cn(cfg, 'chunk_b64_max',              CHUNK_B64_MAX);
  const C_SMALL_MAX_BYTES    = cn(cfg, 'small_max_bytes',            SMALL_MAX_BYTES);
  const C_DIST_THRESHOLD     = cn(cfg, 'dist_threshold_bytes',       DIST_THRESHOLD);
  const C_MAX_TOTAL_CHUNKS   = cn(cfg, 'max_total_chunks',           MAX_TOTAL_CHUNKS);
  const C_MAX_REPOS          = cn(cfg, 'max_repos_per_user',         20);
  const C_MAX_APIKEYS        = cn(cfg, 'max_apikeys_per_user',       10);
  const C_PARALLEL_DL        = cn(cfg, 'parallel_dl_chunks',        PARALLEL_DL_CHUNKS);
  const C_COMMIT_RETRIES     = cn(cfg, 'commit_retry_max',          COMMIT_RETRY_MAX);
  function jRes(data, status=200, extra={}) {
    return new Response(JSON.stringify(data), { status, headers: { ...SEC, ...cors, 'Content-Type':'application/json', ...extra } });
  }
  const kv = env.RATE_LIMIT_KV || null;

  if (route === 'me' && method === 'GET') {
    const storage = await getStorageFromIndex(fullSess);
    return jRes({
      username: fullSess.username, display: fullSess.display,
      repos: fullSess.repos,
      storage,
    });
  }
  if (route === 'repos' && method === 'GET') {
    return jRes({ repos: fullSess.repos, activeRepoIdx: fullSess.activeRepoIdx });
  }
  // Returns per-repo stats derived from each repo's index file.
  // One GitHub API call per repo, all fired concurrently.
  if (route === 'storage' && method === 'GET') {
    const repoStats = await Promise.all(
      fullSess.repos.map(async (repo, idx) => {
        const repoSess = {
          ...fullSess,
          ghOwner:   repo.ghOwner,
          ghRepo:    repo.ghRepo,
          ghBranch:  repo.ghBranch  || 'main',
          folder:    repo.folder    || 'uploads',
          repoLabel: (repo.label && repo.label !== 'Default') ? repo.label : '',
        };
        const storage = await getStorageFromIndex(repoSess);
        return {
          repoIdx:  idx,
          label:    repo.label || 'Default',
          ghOwner:  repo.ghOwner,
          ghRepo:   repo.ghRepo,
          ghBranch: repo.ghBranch  || 'main',
          folder:   repo.folder    || 'uploads',
          active:   idx === fullSess.activeRepoIdx,
          ...storage,
        };
      })
    );
    const totals = repoStats.reduce(
      (acc, r) => ({ fileCount: acc.fileCount + r.fileCount, totalBytes: acc.totalBytes + r.totalBytes }),
      { fileCount: 0, totalBytes: 0 }
    );
    return jRes({
      repos: repoStats,
      totals: { ...totals, humanSize: formatBytes(totals.totalBytes) },
    });
  }
  if (route === 'switch-repo' && method === 'POST') {
    return jRes({ ok: true, deprecated: 'switch-repo is no longer needed. Pass repoIdx per-request instead.' });
  }
  if (route === 'add-repo' && method === 'POST') {
    if (!sess) return jRes({ error: 'Session required' }, 403);
    let body; try { body = await request.json(); } catch { return jRes({ error: ERRS[400] }, 400); }
    const { label='New Repo', ghOwner, ghRepo, ghBranch='main', folder='uploads' } = body||{};
    if (!ghOwner||!ghRepo) return jRes({ error: ERRS[400] }, 400);
    if (!OWNER_RE.test(ghOwner))   return jRes({error:'Invalid GitHub owner name'},400);
    if (!REPO_RE.test(ghRepo))     return jRes({error:'Invalid GitHub repository name'},400);
    if (!BRANCH_RE.test(ghBranch)) return jRes({error:'Invalid branch name'},400);
    if (!FOLDER_RE.test(folder))   return jRes({error:'Invalid folder name'},400);
    const repoCheck = await fetch(
      `https://api.github.com/repos/${ghOwner}/${ghRepo}`,
      { headers:{ Authorization:`token ${fullSess.ghToken}`, Accept:'application/vnd.github.v3+json', 'User-Agent':'StoreGit/1' } }
    );
    if (!repoCheck.ok) return jRes({error:'Repository not accessible with your GitHub token'},400);
    const repoData = await repoCheck.json();
    if (!repoData.permissions?.push && !repoData.permissions?.admin)
      return jRes({error:'Token requires write access to this repository'},400);
    const rec = await getUser(sess.username, env);
    if (!rec) return jRes({ error: ERRS[404] }, 404);
    const { content: user, sha: userSha } = rec;
    const repos = getUserRepos(user);
    if (repos.length >= C_MAX_REPOS) return jRes({ error: `Maximum of ${C_MAX_REPOS} repositories allowed` }, 400);
    repos.push({ label: String(label).slice(0,40), ghOwner, ghRepo, ghBranch, folder });
    const updated = { ...user, repos };
    try { await writeReg(userPath(sess.username), updated, `Add repo ${ghOwner}/${ghRepo}`, env, userSha); }
    catch { return jRes({ error: ERRS[502] }, 502); }
    if (kv) await env.RATE_LIMIT_KV.delete(`sess_cache:${sess.jti}`).catch(() => {});
    return jRes({ ok:true, repos: repos.map(r => ({ label: r.label, ghOwner: r.ghOwner, ghRepo: r.ghRepo })) });
  }
  if (route === 'remove-repo' && method === 'POST') {
    if (!sess) return jRes({ error: 'Session required' }, 403);
    let body; try { body = await request.json(); } catch { return jRes({ error: ERRS[400] }, 400); }
    const { repoIdx } = body||{};
    if (typeof repoIdx !== 'number' || repoIdx < 0) return jRes({ error: ERRS[400] }, 400);
    const rec = await getUser(sess.username, env);
    if (!rec) return jRes({ error: ERRS[404] }, 404);
    const { content: user, sha: userSha } = rec;
    const repos = getUserRepos(user);
    if (repos.length <= 1) return jRes({ error: 'Cannot remove your only repository' }, 400);
    if (repoIdx >= repos.length) return jRes({ error: ERRS[400] }, 400);
    repos.splice(repoIdx, 1);
    const updated = { ...user, repos };
    try { await writeReg(userPath(sess.username), updated, `Remove repo ${repoIdx}`, env, userSha); }
    catch { return jRes({ error: ERRS[502] }, 502); }
    if (kv) await env.RATE_LIMIT_KV.delete(`sess_cache:${sess.jti}`).catch(() => {});
    return jRes({ ok: true, repos: repos.map(r => ({ label: r.label, ghOwner: r.ghOwner, ghRepo: r.ghRepo })) });
  }

  // ── POST /api/apikeys/migrate ────────────────────────────────────────────────
  // One-time migration: copies each API key from KV into the user's git repo.
  // Idempotent — skips keys already present in git. Safe to run multiple times.
  // After migration: new keys go to git+KV, revokes hit git+KV, KV stays as cache.
  // Returns: { ok, migrated, skipped, failed, keys: [{keyId, label, status}] }
  if (route === 'apikeys/migrate' && method === 'POST') {
    if (!sess) return jRes({ error: 'Session required' }, 403);
    const rec = await getUser(sess.username, env);
    if (!rec) return jRes({ error: ERRS[404] }, 404);
    const { content: user } = rec;
    const existingKeys = user.apiKeys || [];
    if (existingKeys.length === 0) {
      return jRes({ ok: true, migrated: 0, skipped: 0, failed: 0, keys: [] });
    }
    let ghToken;
    try { ghToken = await aesDecrypt(user.encGhToken, secret, `user-token:${user.username}`); }
    catch { return jRes({ error: 'Could not decrypt GitHub token' }, 500); }
    const repos  = getUserRepos(user);
    const repo   = repos[0];
    const { ghOwner, ghRepo, ghBranch = 'main', folder = 'uploads' } = repo;
    const results = [];
    let migrated = 0, skipped = 0, failed = 0;
    for (const keyMeta of existingKeys) {
      const { keyId, label = '', allowedOrigins = [], createdAt } = keyMeta;
      // Step 1: decrypt encKey → derive sha256
      let rawKey, sha256hex;
      try {
        rawKey    = await aesDecrypt(keyMeta.encKey, secret, `apikey:${sess.username}:${keyId}`);
        sha256hex = await apiKeyHash(rawKey);
      } catch {
        results.push({ keyId, label, status: 'failed', reason: 'Could not decrypt key' });
        failed++;
        continue;
      }
      // Step 2: skip if already in git (idempotent)
      const existing = await readApiKeyFromGit(sha256hex, ghToken, ghOwner, ghRepo, ghBranch, folder);
      if (existing) {
        // Ensure KV is also fresh
        if (kv) {
          await kv.put(
            apiKeyKvKey(sha256hex),
            JSON.stringify({ username: sess.username, label, allowedOrigins, keyId }),
          ).catch(() => {});
        }
        results.push({ keyId, label, status: 'skipped', reason: 'Already in git repo' });
        skipped++;
        continue;
      }
      // Step 3: read from KV to get the most up-to-date record
      let kvRecord = null;
      if (kv) kvRecord = await kv.get(apiKeyKvKey(sha256hex), 'json').catch(() => null);
      const gitRecord = {
        username:       sess.username,
        label:          kvRecord?.label          ?? label,
        allowedOrigins: kvRecord?.allowedOrigins ?? allowedOrigins,
        keyId:          kvRecord?.keyId          ?? keyId,
        createdAt:      createdAt ?? new Date().toISOString(),
      };
      // Step 4: write to git
      try {
        await writeApiKeyToGit(sha256hex, gitRecord, ghToken, ghOwner, ghRepo, ghBranch, folder);
        // Refresh KV entry too
        if (kv) {
          await kv.put(
            apiKeyKvKey(sha256hex),
            JSON.stringify({ username: sess.username, label: gitRecord.label, allowedOrigins: gitRecord.allowedOrigins, keyId: gitRecord.keyId }),
          ).catch(() => {});
        }
        results.push({ keyId, label: gitRecord.label, status: 'migrated' });
        migrated++;
      } catch (e) {
        results.push({ keyId, label, status: 'failed', reason: e?.message || 'git write failed' });
        failed++;
      }
    }
    return jRes({ ok: true, migrated, skipped, failed, keys: results });
  }

  if (route === 'apikeys/list' && method === 'GET') {
    if (!sess) return jRes({ error: 'Session required' }, 403);
    const rec = await getUser(sess.username, env);
    if (!rec) return jRes({ error: ERRS[404] }, 404);
    const keys = (rec.content.apiKeys || []).map(k => ({
      keyId: k.keyId, preview: k.preview, label: k.label,
      allowedOrigins: k.allowedOrigins || [], createdAt: k.createdAt,
    }));
    return jRes({ keys });
  }
  if (route === 'apikeys/create' && method === 'POST') {
    if (!sess) return jRes({ error: 'Session required' }, 403);
    let body; try { body = await request.json(); } catch { return jRes({ error: ERRS[400] }, 400); }
    const label          = String(body?.label || 'My App').slice(0, 60);
    const rawOrigins     = Array.isArray(body?.allowedOrigins) ? body.allowedOrigins : [];
    const allowedOrigins = rawOrigins
      .map(o => String(o).trim().toLowerCase().replace(/\/+$/, ''))
      .filter(o => {
        try { const u = new URL(o); return u.protocol === 'https:' || u.protocol === 'http:'; }
        catch { return false; }
      })
      .slice(0, 20);
    const rec = await getUser(sess.username, env);
    if (!rec) return jRes({ error: ERRS[404] }, 404);
    const { content: user, sha: userSha } = rec;
    const existingKeys = user.apiKeys || [];
    if (existingKeys.length >= C_MAX_APIKEYS) return jRes({ error: `Maximum of ${C_MAX_APIKEYS} API keys allowed` }, 400);
    const rawKey = generateRawApiKey();
    const keyId  = base64urlFromBytes(crypto.getRandomValues(new Uint8Array(9)));
    const preview = rawKey.slice(0, 12) + '…';
    const sha256hex = await apiKeyHash(rawKey);
    const keyRecord = { username: sess.username, label, allowedOrigins, keyId, createdAt: new Date().toISOString() };

    // ── 1. Write to user's git repo (source of truth) ─────────────────────────
    let ghToken;
    try { ghToken = await aesDecrypt(user.encGhToken, secret, `user-token:${user.username}`); }
    catch { return jRes({ error: ERRS[500] }, 500); }
    const repos = getUserRepos(user);
    const repo  = repos[0];
    try {
      await writeApiKeyToGit(sha256hex, keyRecord, ghToken, repo.ghOwner, repo.ghRepo, repo.ghBranch || 'main', repo.folder || 'uploads');
    } catch {
      return jRes({ error: 'Failed to write API key to your repository — check that your GitHub token has write access' }, 502);
    }

    // ── 2. Write to KV (write-through cache + backwards compat) ───────────────
    if (kv) {
      await kv.put(
        apiKeyKvKey(sha256hex),
        JSON.stringify({ username: sess.username, label, allowedOrigins, keyId }),
      ).catch(() => { console.warn('[StoreGit] KV write failed for new API key'); });
    }
    // Store metadata (not raw key) in user record
    const encKey = await aesEncrypt(rawKey, secret, `apikey:${sess.username}:${keyId}`);
    const keyMeta = { keyId, preview, label, allowedOrigins, createdAt: new Date().toISOString(), encKey };
    const updated = { ...user, apiKeys: [...existingKeys, keyMeta] };
    try { await writeReg(userPath(sess.username), updated, `Create API key: ${label}`, env, userSha); }
    catch {
      // Registry write failed — roll back git and KV so no orphaned key exists
      await deleteApiKeyFromGit(sha256hex, ghToken, repo.ghOwner, repo.ghRepo, repo.ghBranch || 'main', repo.folder || 'uploads').catch(() => {});
      if (kv) await kv.delete(apiKeyKvKey(sha256hex)).catch(() => {});
      return jRes({ error: ERRS[502] }, 502);
    }
    return jRes({ ok: true, rawKey, keyId, preview, label, allowedOrigins });
  }
  if (route === 'apikeys/revoke' && method === 'DELETE') {
    if (!sess) return jRes({ error: 'Session required' }, 403);
    let body; try { body = await request.json(); } catch { return jRes({ error: ERRS[400] }, 400); }
    const { keyId } = body||{};
    if (!keyId || typeof keyId !== 'string') return jRes({ error: ERRS[400] }, 400);
    const rec = await getUser(sess.username, env);
    if (!rec) return jRes({ error: ERRS[404] }, 404);
    const { content: user, sha: userSha } = rec;
    const existing = user.apiKeys || [];
    const target   = existing.find(k => k.keyId === keyId);
    if (!target) return jRes({ error: 'API key not found' }, 404);
    // Decrypt raw key → sha256 → delete from git repo + KV
    if (target.encKey) {
      try {
        const rawKey    = await aesDecrypt(target.encKey, secret, `apikey:${sess.username}:${keyId}`);
        const sha256hex = await apiKeyHash(rawKey);
        // Delete from git (source of truth)
        let ghToken;
        try { ghToken = await aesDecrypt(user.encGhToken, secret, `user-token:${user.username}`); } catch {}
        if (ghToken) {
          const repos = getUserRepos(user);
          const repo  = repos[0];
          await deleteApiKeyFromGit(sha256hex, ghToken, repo.ghOwner, repo.ghRepo, repo.ghBranch || 'main', repo.folder || 'uploads').catch(() => {});
        }
        // Delete from KV (cache + legacy store)
        if (kv) await kv.delete(apiKeyKvKey(sha256hex)).catch(() => {});
      } catch {}
    }
    const updated = { ...user, apiKeys: existing.filter(k => k.keyId !== keyId) };
    try { await writeReg(userPath(sess.username), updated, `Revoke API key: ${target.label}`, env, userSha); }
    catch { return jRes({ error: ERRS[502] }, 502); }
    return jRes({ ok: true });
  }
  if (route === 'share-link' && method === 'GET') {
    const sp    = new URL(request.url).searchParams;
    const nameP = sp.get('name') || '';
    const ttlP  = parseInt(sp.get('ttl') || '3600', 10);
    const rIdx  = parseInt(sp.get('repoIdx') || '0', 10);
    const never = ttlP === 0;
    const safe  = sanitize(nameP);
    if (!safe) return fail(request, 400);
    const ttl = never ? 0 : Math.max(60, Math.min(ttlP, C_SHARE_TTL_MAX));
    const targetSess = getRepoSess(fullSess, rIdx);
    let size = 0, displayName = unwrapName(safe);
    try {
      const { data: idx } = await readIndex(targetSess);
      if (idx[safe]) { displayName = idx[safe].originalName || unwrapName(safe); size = idx[safe].totalSize || idx[safe].size || 0; }
    } catch {}
    const exp = never ? null : new Date(Date.now() + ttl * 1000).toISOString();
    const tok = await createShareToken(
      sess ? sess.username : fullSess.username,
      safe, rIdx, ttl, size, displayName, secret
    );
    const kv2 = env.RATE_LIMIT_KV || null;
    let url = `/api/dl?tok=${encodeURIComponent(tok)}`;
    if (kv2) {
      let shortId = null;
      outer: for (let len = 4; len <= 6; len++) {
        for (let attempt = 0; attempt < 6; attempt++) {
          const id = randomAlphabetString(B64URL_CHARS, len);
          const existing = await kv2.get('sl:' + id).catch(() => null);
          if (!existing) { shortId = id; break outer; }
        }
      }
      if (shortId) {
        const kvOpts = never ? {} : { expirationTtl: ttl };
        await kv2.put('sl:' + shortId, JSON.stringify({ tok, displayName, size, exp }), kvOpts).catch(() => {});
        url = `/${shortId}`;
      }
    }
    return jRes({ url, exp });
  }
  if (route === 'files' && method === 'GET') {
    // ?repoIdx= fetches a specific repo without session mutation
    const qRepoIdx = parseInt(new URL(request.url).searchParams.get('repoIdx') ?? '', 10);
    let targetSess = fullSess;
    if (!isNaN(qRepoIdx) && qRepoIdx >= 0 && qRepoIdx < fullSess.repos.length) {
      targetSess = getRepoSess(fullSess, qRepoIdx);
    }
    try {
      const [regular, { data: idx }] = await Promise.all([
        listFiles(targetSess),
        readIndexCached(targetSess, kv).catch(() => ({ data: {} })),
      ]);
      const chunked = Object.entries(idx)
        .filter(([, info]) => info.totalChunks)
        .map(([name, info]) => ({ name, originalName: info.originalName || unwrapName(name), size: info.totalSize, sha: '', chunked: true, distributed: info.distributed || false, repoCount: info.repoCount || 1, parts: info.totalChunks, uploadedAt: info.uploadedAt || null }));
      const chunkedNames = new Set(chunked.map(f => f.name));
      const cleanRegular = regular
        .filter(f => !chunkedNames.has(f.name))
        .map(f => ({ ...f, originalName: idx[f.name]?.originalName || unwrapName(f.name), uploadedAt: idx[f.name]?.uploadedAt || null, chunked: false }));
      const all = [...cleanRegular, ...chunked].sort((a, b) => {
        if (!a.uploadedAt && !b.uploadedAt) return 0;
        if (!a.uploadedAt) return 1;
        if (!b.uploadedAt) return -1;
        return new Date(b.uploadedAt) - new Date(a.uploadedAt);
      });
      return jRes(all);
    } catch { return jRes({ error: ERRS[502] }, 502); }
  }
  if (route === 'upload' && method === 'POST') {
    if (!(request.headers.get('Content-Type')||'').includes('application/json')) return jRes({ error: ERRS[400] },400);
    let body; try { body = await request.json(); } catch { return jRes({ error: ERRS[400] },400); }
    const { name: rawName, content: b64 } = body||{};
    if (!rawName || !b64 || typeof b64 !== 'string') return jRes({ error: ERRS[400] },400);
    if (b64.length > C_CHUNK_B64_MAX) return jRes({ error: ERRS[413] },413);
    const safe = sanitize(String(rawName));
    if (!safe) return jRes({ error: ERRS[415] },415);
    if (!checkMagicBase64(b64)) return jRes({ error: ERRS[415] },415);
    const decodedSize = Math.floor(b64.length * 3 / 4);
    // Route to the repo with the most available space — no repo is special or preferred.
    const uploadRepoIdx = fullSess.repos.length > 1
      ? await pickLeastUsedRepo(fullSess, kv).catch(() => 0)
      : 0;
    const uploadSess = getRepoSess(fullSess, uploadRepoIdx);
    try {
      if (decodedSize > C_SMALL_MAX_BYTES) {
        const blobSha = await createBlob(uploadSess, b64);
        const { ghToken, ghOwner, ghRepo, ghBranch, folder } = uploadSess;
        const gh   = ghH(ghToken);
        const base = `https://api.github.com/repos/${encodeURIComponent(ghOwner)}/${encodeURIComponent(ghRepo)}`;
        const refRes = await fetch(`${base}/git/ref/heads/${encodeURIComponent(ghBranch)}`, { headers:gh });
        if (!refRes.ok) throw new Error('ref_fail');
        const { object:{ sha:headSha } } = await refRes.json();
        const commitRes = await fetch(`${base}/git/commits/${headSha}`, { headers:gh });
        const { tree:{ sha:treeSha } } = await commitRes.json();
        const newTreeRes = await fetch(`${base}/git/trees`, { method:'POST', headers:gh, body: JSON.stringify({ base_tree:treeSha, tree:[{ path:`${folder}/${safe}`, mode:'100644', type:'blob', sha:blobSha }] }) });
        const { sha:newTree } = await newTreeRes.json();
        const newCommitRes = await fetch(`${base}/git/commits`, { method:'POST', headers:gh, body: JSON.stringify({ message:`Upload ${safe}`, tree:newTree, parents:[headSha] }) });
        const { sha:newCommit } = await newCommitRes.json();
        await fetch(`${base}/git/refs/heads/${ghBranch}`, { method:'PATCH', headers:gh, body: JSON.stringify({ sha:newCommit, force:false }) });
      } else {
        await uploadSmall(uploadSess, safe, b64);
      }
      try {
        const { data: idx, sha: idxSha } = await readIndex(uploadSess);
        idx[safe] = { originalName: getOriginalName(rawName, safe), uploadedAt: new Date().toISOString(), size: decodedSize };
        await writeIndex(uploadSess, idx, idxSha);
        invalidateIndexCache(uploadSess, kv);
      } catch {}
      return jRes({ ok:true, name:safe, size:decodedSize });
    } catch { return jRes({ error: ERRS[502] }, 502); }
  }
  if (route === 'upload-chunk' && method === 'POST') {
    if (!(request.headers.get('Content-Type')||'').includes('application/json')) return jRes({ error: ERRS[400] },400);
    let body; try { body = await request.json(); } catch { return jRes({ error: ERRS[400] },400); }
    const { name: rawName, chunkIndex, totalChunks, totalSize, content: b64 } = body||{};
    if (!rawName || !b64 || typeof b64 !== 'string') return jRes({ error: ERRS[400] },400);
    if (b64.length > C_CHUNK_B64_MAX) return jRes({ error: ERRS[413] },413);
    const chunkIdx = parseInt(chunkIndex, 10);
    const tot = parseInt(totalChunks, 10);
    if (isNaN(chunkIdx)||chunkIdx<0) return jRes({ error: ERRS[400] },400);
    if (isNaN(tot)||tot<1||tot>C_MAX_TOTAL_CHUNKS) return jRes({ error: ERRS[400] },400);
    const safe = sanitize(String(rawName));
    if (!safe) return jRes({ error: ERRS[415] },415);
    if (chunkIdx === 0 && !checkMagicBase64(b64)) return jRes({ error: ERRS[415] },415);
    const decodedSize = Math.floor(b64.length * 3 / 4);
    // ── Space-aware repo routing ─────────────────────────────────────────────
    // All repos are equal — no "target" or "primary" repo.
    // A chunk→repo assignment is computed once (using live repo sizes) and cached
    // in KV for the duration of this upload so every chunk routes consistently,
    // even when chunks arrive out of order or are retried.
    const dist = isDistributed(totalSize, fullSess.repos);
    let resolvedRepoIdx = 0;
    if (fullSess.repos.length > 1) {
      const assignKey = `chunk_assign:${fullSess.username}:${safe}:${tot}`;
      let assignment = null;
      if (kv) {
        const cached = await kv.get(assignKey, 'json').catch(() => null);
        if (Array.isArray(cached) && cached.length === tot &&
            cached.every(r => Number.isInteger(r) && r >= 0 && r < fullSess.repos.length)) {
          assignment = cached;
        }
      }
      if (!assignment) {
        const repoBytes = await fetchRepoBytes(fullSess, kv).catch(() => fullSess.repos.map(() => 0));
        const approxChunkBytes = (Number.isFinite(totalSize) && totalSize > 0 && tot > 0)
          ? Math.ceil(totalSize / tot) : 0;
        if (dist) {
          // Large file: contiguous ranges per repo (minimises fragmentation + equalisies usage)
          assignment = computeContiguousAssignment(tot, approxChunkBytes, repoBytes);
        } else {
          // Normal file: all chunks to the repo with most free space
          let min = 0;
          for (let r = 1; r < repoBytes.length; r++) if (repoBytes[r] < repoBytes[min]) min = r;
          assignment = Array.from({ length: tot }, () => min);
        }
        if (kv) await kv.put(assignKey, JSON.stringify(assignment), { expirationTtl: 86400 }).catch(() => {});
      }
      resolvedRepoIdx = assignment[chunkIdx] ?? (dist ? chunkIdx % fullSess.repos.length : 0);
      resolvedRepoIdx = Math.max(0, Math.min(resolvedRepoIdx, fullSess.repos.length - 1));
    }
    const targetSess = getRepoSess(fullSess, resolvedRepoIdx);
    const jti = sess ? sess.jti : `ak:${fullSess.username}`;
    try {
      // ── Blob-only upload ───────────────────────────────────────────────────
      // NO per-chunk commit here. All commits happen in a single batch during
      // finalize-upload (one tree commit per repo). This reduces GitHub API calls
      // from O(chunks × 4) sequential to O(repos × 5) parallel — critical for
      // large files (e.g. 150 MB / 10 MB = 15 chunks: was 60 calls, now 5).
      const blobSha = await createBlob(targetSess, b64);
      const blobToken = await blobTokenSign(jti, safe, chunkIdx, blobSha, secret);
      return jRes({ ok: true, blobSha, blobToken, index: chunkIdx, size: decodedSize, repoIdx: resolvedRepoIdx, distributed: dist });
    } catch { return jRes({ error: ERRS[502] }, 502); }
  }
  if (route === 'finalize-upload' && method === 'POST') {
    let body; try { body = await request.json(); } catch { return jRes({ error: ERRS[400] },400); }
    const { name, totalSize, totalChunks, chunkSize, blobs } = body||{};
    if (!name||!totalSize||!totalChunks||!Array.isArray(blobs)) return jRes({ error: ERRS[400] },400);
    if (blobs.length !== totalChunks) return jRes({ error: ERRS[400] },400);
    if (totalChunks > C_MAX_TOTAL_CHUNKS) return jRes({ error: ERRS[413] },413);
    const MAX_FILE_BYTES     = C_MAX_TOTAL_CHUNKS * Math.floor(C_CHUNK_B64_MAX * 3 / 4);
    const C_CHUNK_RAW_MAX    = Math.floor(C_CHUNK_B64_MAX * 3 / 4); // ~10.5 MB raw
    if (!Number.isInteger(totalSize) || totalSize < 1 || totalSize > MAX_FILE_BYTES) return jRes({ error: ERRS[400] }, 400);
    // chunkSize is raw bytes; guard against it exceeding per-chunk raw limit
    if (chunkSize !== undefined && (!Number.isInteger(chunkSize) || chunkSize < 1 || chunkSize > C_CHUNK_RAW_MAX)) return jRes({ error: ERRS[400] }, 400);
    const safe = sanitize(String(name));
    if (!safe) return jRes({ error: ERRS[415] }, 415);
    const dist = isDistributed(totalSize, fullSess.repos);
    // Recover the repo that was chosen at upload-chunk time from the KV assignment cache.
    // For non-distributed uploads all chunks went to one repo — read it from cached[0].
    // For distributed uploads finalSess is only used for the manifest commit, which lands
    // on the session's context repo (same as before).
    const assignKey = `chunk_assign:${fullSess.username}:${safe}:${totalChunks}`;
    let finalRepoIdx = 0;
    if (!dist && fullSess.repos.length > 1 && kv) {
      const cached = await kv.get(assignKey, 'json').catch(() => null);
      if (Array.isArray(cached) && cached.length > 0 &&
          Number.isInteger(cached[0]) && cached[0] >= 0 && cached[0] < fullSess.repos.length) {
        finalRepoIdx = cached[0];
      }
    }
    const finalSess = dist ? fullSess : getRepoSess(fullSess, finalRepoIdx);
    const jti = sess ? sess.jti : `ak:${fullSess.username}`;
    for (const b of blobs) {
      if (typeof b.blobSha   !== 'string' || !SHA_RE.test(b.blobSha)) return jRes({ error: ERRS[400] },400);
      if (typeof b.blobToken !== 'string')                             return jRes({ error: ERRS[400] },400);
      if (typeof b.index     !== 'number' || b.index < 0)             return jRes({ error: ERRS[400] },400);
      if (typeof b.size      !== 'number' || b.size  < 1)             return jRes({ error: ERRS[400] },400);
      if (dist) {
        // Repo routing was decided at upload-chunk time via balanced assignment.
        // The blobToken already cryptographically binds (jti, name, chunkIndex, blobSha),
        // so we only verify the reported repoIdx is a valid slot — not a specific value.
        const ri = b.repoIdx ?? 0;
        if (!Number.isInteger(ri) || ri < 0 || ri >= fullSess.repos.length) {
          return jRes({ error: 'chunk_repo_mismatch' }, 400);
        }
        b.repoIdx = ri;
      }
      const expected = await blobTokenSign(jti, safe, b.index, b.blobSha, secret);
      if (!(await timingSafeEq(b.blobToken, expected))) return jRes({ error: ERRS[403] }, 403);
    }
    try {
      if (dist) {
        await finalizeDistributedUpload(fullSess, safe, blobs, totalSize, chunkSize);
      } else {
        await finalizeChunkedUpload(finalSess, safe, blobs, totalSize, chunkSize);
      }
      // Clean up upload assignment cache and bust index/bytes caches for all affected repos
      if (kv) {
        kv.delete(assignKey).catch(() => {});
        // Invalidate index cache for repos that received chunks
        const affectedRepos = dist
          ? [...new Set(blobs.map(b => b.repoIdx ?? 0))].map(ri => getRepoSess(fullSess, ri))
          : [finalSess];
        for (const rs of affectedRepos) {
          invalidateIndexCache(rs, kv);
          // Bust repo-bytes cache so next upload sees fresh sizes
          const bKey = `rbytes:${rs.ghOwner}:${rs.ghRepo}:${(rs.ghBranch||'main').replace(/\//g,'_')}:${rs.folder||'uploads'}`;
          kv.delete(bKey).catch(() => {});
        }
      }
      const { data: idx, sha: idxSha } = await readIndex(finalSess);
      idx[safe] = { originalName: getOriginalName(name, safe), totalSize, totalChunks, uploadedAt: new Date().toISOString(), ...(dist && { distributed: true, repoCount: fullSess.repos.length }) };
      await writeIndex(finalSess, idx, idxSha);
      invalidateIndexCache(finalSess, kv);
      return jRes({ ok: true, name: safe, distributed: dist, ...(dist && { repoCount: fullSess.repos.length }) });
    } catch { return jRes({ error: ERRS[502] }, 502); }
  }
  if (route === 'download' && method === 'GET') {
    const sp = new URL(request.url).searchParams;
    const nameParam = sp.get('name') || '';
    const rIdx = parseInt(sp.get('repoIdx') || '0', 10);
    const forDownload = sp.get('inline') !== '1'; // ?inline=1 → inline preview, no attachment
    const safe = sanitize(nameParam);
    if (!safe) return jRes({ error: ERRS[400] },400);
    const dlSess = getRepoSess(fullSess, rIdx);
    const { ghToken, ghOwner, ghRepo, ghBranch, folder } = dlSess;
    let manifest = null, serveAs = safe;
    try {
      const { data: idx } = await readIndexCached(dlSess, kv);
      if (idx[safe]) serveAs = idx[safe].originalName || unwrapName(safe);
      else serveAs = unwrapName(safe);
      if (idx[safe]?.totalChunks) {
        const mRes = await fetch(`https://api.github.com/repos/${ghOwner}/${ghRepo}/contents/${manifestP(folder,safe)}?ref=${ghBranch}`, { headers: ghH(ghToken) });
        if (mRes.ok) { const mData = await mRes.json(); manifest = JSON.parse(atob(mData.content.replace(/\s/g,''))); }
      }
    } catch {}
    if (manifest) {
      const authHeader = { Authorization:`token ${ghToken}`, 'User-Agent':'StoreGit/1' };
      // Keep C_PARALLEL_DL fetches in-flight simultaneously.
      const fetchChunk = async (i) => {
        const chunkMeta   = manifest.chunks?.[i];
        const chunkOwner  = chunkMeta?.ghOwner  || ghOwner;
        const chunkRepo   = chunkMeta?.ghRepo   || ghRepo;
        const chunkBranch = chunkMeta?.ghBranch || ghBranch;
        const chunkFolder = chunkMeta?.folder   || folder;
        const chunkUrl    = `https://raw.githubusercontent.com/${chunkOwner}/${chunkRepo}/${chunkBranch}/${chunkPath(chunkFolder, safe, i)}`;
        const res = await fetch(chunkUrl, { headers: authHeader });
        if (!res.ok) throw new Error(`chunk_${i}_missing`);
        const buf = await res.arrayBuffer();
        if (chunkMeta?.blobSha) {
          const actual = await gitBlobSha(buf);
          if (actual !== chunkMeta.blobSha) throw new Error(`chunk_${i}_corrupt`);
        }
        return new Uint8Array(buf);
      };
      const stream = new ReadableStream({
        async start(controller) {
          try {
            const total  = manifest.totalChunks;
            const window = Math.max(1, C_PARALLEL_DL);
            // Pre-launch first window of fetches
            const pending = new Map();
            for (let i = 0; i < Math.min(window, total); i++) {
              pending.set(i, fetchChunk(i));
            }
            for (let i = 0; i < total; i++) {
              // Await the chunk whose turn it is (may already be resolved)
              const data = await pending.get(i);
              pending.delete(i);
              // Immediately launch the next chunk to keep the window full
              const next = i + window;
              if (next < total) pending.set(next, fetchChunk(next));
              controller.enqueue(data);
            }
            controller.close();
          } catch (e) { controller.error(e); }
        },
      });
      return new Response(stream, { status:200, headers: { ...SEC, ...cors, 'Content-Type': safeMime(serveAs), 'Content-Disposition': contentDisposition(serveAs, forDownload), 'Content-Length': String(manifest.totalSize), 'Accept-Ranges':'none' } });
    }
    const rawUrl = `https://raw.githubusercontent.com/${ghOwner}/${ghRepo}/${ghBranch}/${folder}/${encodeURIComponent(safe)}`;
    let ghRes;
    try { ghRes = await fetch(rawUrl, { headers:{ Authorization:`token ${ghToken}`, 'User-Agent':'StoreGit/1' } }); }
    catch { return jRes({ error: ERRS[502] },502); }
    if (ghRes.status===404) return jRes({ error: ERRS[404] },404);
    if (!ghRes.ok) return jRes({ error: ERRS[502] },502);
    const len = ghRes.headers.get('Content-Length')||'';
    return new Response(ghRes.body, { status:200, headers: { ...SEC, ...cors, 'Content-Type': safeMime(serveAs), 'Content-Disposition': contentDisposition(serveAs, forDownload), ...(len?{'Content-Length':len}:{}), 'Accept-Ranges':'bytes' } });
  }
  if (route === 'delete' && method === 'DELETE') {
    let body; try { body = await request.json(); } catch { return jRes({ error: ERRS[400] },400); }
    const { name, sha, chunked, repoIdx: delRepoIdx } = body||{};
    if (typeof name !== 'string') return jRes({ error: ERRS[400] },400);
    const safe = sanitize(name);
    if (!safe) return jRes({ error: ERRS[400] },400);
    const delSess = getRepoSess(fullSess, Number.isInteger(delRepoIdx) ? delRepoIdx : 0);
    if (chunked) {
      try {
        const { data: idx, sha: idxSha } = await readIndex(delSess);
        const isDistFile = idx[safe]?.distributed;
        if (isDistFile) {
          await deleteDistributed(delSess, safe);
        } else {
          await deleteChunked(delSess, safe);
        }
        delete idx[safe];
        await writeIndex(delSess, idx, idxSha);
        invalidateIndexCache(delSess, kv);
        if (kv) { const bKey = `rbytes:${delSess.ghOwner}:${delSess.ghRepo}:${(delSess.ghBranch||'main').replace(/\//g,'_')}:${delSess.folder||'uploads'}`; kv.delete(bKey).catch(() => {}); }
        return jRes({ ok:true });
      } catch { return jRes({ error: ERRS[502] },502); }
    } else {
      if (typeof sha !== 'string' || !SHA_RE.test(sha)) return jRes({ error: ERRS[400] },400);
      try {
        await deleteRegular(delSess, safe, sha);
        try {
          const { data: idx, sha: idxSha } = await readIndex(delSess);
          if (idx[safe]) { delete idx[safe]; await writeIndex(delSess, idx, idxSha); }
          invalidateIndexCache(delSess, kv);
          if (kv) { const bKey = `rbytes:${delSess.ghOwner}:${delSess.ghRepo}:${(delSess.ghBranch||'main').replace(/\//g,'_')}:${delSess.folder||'uploads'}`; kv.delete(bKey).catch(() => {}); }
        } catch {}
        return jRes({ ok:true });
      } catch { return jRes({ error: ERRS[502] },502); }
    }
  }
  return jRes({ error: ERRS[404] }, 404);
}
