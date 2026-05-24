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
const MAX_TOTAL_CHUNKS          = 512;
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
// allowedOrigins: null = same-origin only, [] = any origin, [...] = whitelist
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

// ── API key — production-grade entropy design ────────────────────────────────
//
//  Format : sgk_<43 Base64URL chars>
//  Entropy: 32 bytes = 256 bits  (6 bits per char, no modulo bias)
//  Storage: KV key = "apikey:sha256:<SHA-256 hex of raw key>"
//           Raw key NEVER persisted — only its SHA-256 digest used as KV key.
//           If KV is fully dumped, raw keys remain safe.
//
//  Why Base64URL over hex:
//    hex   : 16 bytes → 32 chars → 4.0 bits/char  (128-bit key)
//    B64URL: 32 bytes → 43 chars → 5.95 bits/char (256-bit key, smaller footprint)
//
const APIKEY_RE          = /^sgk_[A-Za-z0-9_-]{43}$/; // 43 chars × 6 bits = 258 bits ≥ 256
const APIKEY_RATE_MAX    = 120;   // requests per minute per key
const APIKEY_RATE_WINDOW = 60_000;

// Standard RFC 4648 §5 Base64URL alphabet (URL-safe, no padding)
const B64URL_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

// Bias-free Base64URL encoder — no modulo of 256 by a non-power-of-two.
// Processes bytes in groups of 3 → 4 chars (exactly 6 bits per output char).
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

// Bias-free random string for any alphabet using rejection sampling.
// Ensures uniform distribution even when alphabetSize doesn't divide 256.
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
  // 32 bytes (256 bits) of CSPRNG → 43 Base64URL chars
  return `sgk_${base64urlFromBytes(crypto.getRandomValues(new Uint8Array(32)))}`;
}

// Store metadata under SHA-256(rawKey) so the actual key is never a KV key.
// Compromise of KV reveals usernames/labels/origins but NOT the signing secret.
async function apiKeyKvKey(rawKey) {
  const digest = await crypto.subtle.digest('SHA-256', ENC.encode(rawKey));
  return `apikey:sha256:${hexEnc(new Uint8Array(digest))}`;
}

async function resolveApiKey(request, env, secret) {
  const apiKey = request.headers.get('X-API-Key') || '';
  if (!APIKEY_RE.test(apiKey)) return null;
  const kv = env.RATE_LIMIT_KV;
  if (!kv) return null;

  const kvKey   = await apiKeyKvKey(apiKey);
  const keyData = await kv.get(kvKey, 'json').catch(() => null);
  if (!keyData || !keyData.username) return null;

  // Domain binding check
  const origin = request.headers.get('Origin') || '';
  const origins = keyData.allowedOrigins || [];
  if (origins.length > 0 && origin && !origins.includes(origin)) {
    return { blocked: true, reason: 'Origin not allowed for this API key' };
  }

  // Per-key rate limiting
  if (await checkRate(`apikey_rate:${apiKey}`, APIKEY_RATE_MAX, env, APIKEY_RATE_WINDOW)) {
    return { blocked: true, reason: 'API key rate limit exceeded' };
  }

  // Load full session for this user
  const rec = await getUser(keyData.username, env).catch(() => null);
  if (!rec) return null;
  const { content: user } = rec;
  let ghToken;
  try { ghToken = await aesDecrypt(user.encGhToken, secret, `user-token:${user.username}`); }
  catch { return null; }
  const repos   = getUserRepos(user);
  const repo    = repos[0];
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
function ab2b64(buf) { return b64Enc(new Uint8Array(buf)); }
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
const PBKDF2_ITERS_CURRENT = 100_000;
const PBKDF2_ITERS_LEGACY  =  50_000;
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
  return { ...sess, ghToken, ghOwner: repo.ghOwner, ghRepo: repo.ghRepo, ghBranch: repo.ghBranch, folder: repo.folder, repoLabel: (repo.label && repo.label !== 'Default') ? repo.label : '', repos: repos.map(r => ({ label: r.label, ghOwner: r.ghOwner, ghRepo: r.ghRepo })), activeRepoIdx: repoIdx };
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
    body: JSON.stringify({ message: msg, content: b64urlEnc(ENC.encode(JSON.stringify(content,null,2))), branch: REGISTRY_BRANCH, ...(sha?{sha}:{}) }),
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
async function writeIndex(sess, data, existingSha) {
  const { ghToken, ghOwner, ghRepo, ghBranch, folder } = sess;
  const url = `https://api.github.com/repos/${encodeURIComponent(ghOwner)}/${encodeURIComponent(ghRepo)}/contents/${encodeURIComponent(indexP(folder))}`;
  const res = await fetch(url, {
    method: 'PUT', headers: ghH(ghToken),
    body: JSON.stringify({ message: 'StoreGit: update index', content: utf8b64(JSON.stringify(data, null, 2)), branch: ghBranch, ...(existingSha ? { sha: existingSha } : {}) }),
  });
  if (!res.ok) throw new Error('index_write_fail');
}
// Compute storage stats from a pre-fetched file list (used by /api/files).
function computeStorageStats(files) {
  const totalBytes = files.reduce((sum, f) => sum + (Number(f.size) || 0), 0);
  return { fileCount: files.length, totalBytes, humanSize: formatBytes(totalBytes) };
}
// Cheap single-call storage probe: reads only the index JSON (no directory listing).
// Used by /api/me and /api/storage where we want per-repo stats without a full listing.
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
async function finalizeChunkedUpload(sess, safeName, blobs, totalSize, chunkSize) {
  const { ghToken, ghOwner, ghRepo, ghBranch, folder } = sess;
  const gh   = ghH(ghToken);
  const base = `https://api.github.com/repos/${encodeURIComponent(ghOwner)}/${encodeURIComponent(ghRepo)}`;
  const manifest = { name: safeName, totalSize, totalChunks: blobs.length, chunkSize, uploadedAt: new Date().toISOString(), chunks: blobs.map(b => ({ index: b.index, size: b.size, blobSha: b.blobSha })) };
  const manifestBlobSha = await createBlob(sess, utf8b64(JSON.stringify(manifest, null, 2)));
  const refRes = await fetch(`${base}/git/ref/heads/${ghBranch}`, { headers: gh });
  if (!refRes.ok) throw new Error('ref_fail');
  const { object: { sha: headSha } } = await refRes.json();
  const commitRes = await fetch(`${base}/git/commits/${headSha}`, { headers: gh });
  if (!commitRes.ok) throw new Error('commit_read_fail');
  const { tree: { sha: treeSha } } = await commitRes.json();
  const treeItems = blobs.map(b => ({ path: chunkPath(folder, safeName, b.index), mode: '100644', type: 'blob', sha: b.blobSha }));
  treeItems.push({ path: manifestP(folder, safeName), mode: '100644', type: 'blob', sha: manifestBlobSha });
  const newTreeRes = await fetch(`${base}/git/trees`, { method: 'POST', headers: gh, body: JSON.stringify({ base_tree: treeSha, tree: treeItems }) });
  if (!newTreeRes.ok) throw new Error('tree_fail');
  const { sha: newTreeSha } = await newTreeRes.json();
  const newCommitRes = await fetch(`${base}/git/commits`, { method: 'POST', headers: gh, body: JSON.stringify({ message: `Upload ${safeName} (${blobs.length} parts)`, tree: newTreeSha, parents: [headSha] }) });
  if (!newCommitRes.ok) throw new Error('commit_fail');
  const { sha: newCommit } = await newCommitRes.json();
  const updateRes = await fetch(`${base}/git/refs/heads/${ghBranch}`, { method: 'PATCH', headers: gh, body: JSON.stringify({ sha: newCommit, force: false }) });
  if (!updateRes.ok) throw new Error('ref_update_fail');
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
  // Browsers never send X-API-Key values in preflight — only the header *name*
  // appears in Access-Control-Request-Headers. Enforce auth on the real request.
  if (method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: { ...SEC, ...corsHeaders(request, []) } });
  }
  const secret = env.TOKEN_SECRET;
  if (!secret) return fail(request, 500);
  if (route === 'status' && method === 'GET') {
    const ready = !!(env.REGISTRY_GITHUB_TOKEN && env.REGISTRY_GITHUB_OWNER && env.REGISTRY_GITHUB_REPO);
    return jsonRes(request, {
      ready,
      version: '1',
      kvAvailable: !!(env.RATE_LIMIT_KV),
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
          { method: 'GET',    path: '/api/files',            auth: ['session', 'apiKey'], note: 'Returns { files, storage } — supports ?repoIdx=N' },
          { method: 'POST',   path: '/api/upload',           auth: ['session', 'apiKey'] },
          { method: 'POST',   path: '/api/upload-chunk',     auth: ['session', 'apiKey'] },
          { method: 'POST',   path: '/api/finalize-upload',  auth: ['session', 'apiKey'] },
          { method: 'GET',    path: '/api/download',         auth: ['session', 'apiKey'] },
          { method: 'DELETE', path: '/api/delete',           auth: ['session', 'apiKey'] },
          { method: 'GET',    path: '/api/share-link',       auth: ['session', 'apiKey'] },
          { method: 'GET',    path: '/api/apikeys/list',     auth: ['session'] },
          { method: 'POST',   path: '/api/apikeys/create',   auth: ['session'] },
          { method: 'DELETE', path: '/api/apikeys/revoke',   auth: ['session'] },
        ],
      },
    });
  }
  if (route === 'signup' && method === 'POST') {
    const ip = getIP(request);
    if (await checkRate(`signup:${ip}`, RATE_MAX_SIGNUP, env)) return fail(request, 429);
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
    catch { return fail(request, 502); }
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
      const rawBase    = `https://raw.githubusercontent.com/${ghOwner}/${ghRepo}/${ghBranch}`;
      const authHeader = { Authorization:`token ${ghToken}`, 'User-Agent':'StoreGit/1' };
      const stream = new ReadableStream({
        async start(controller) {
          try {
            for (let i = 0; i < manifest.totalChunks; i++) {
              const res = await fetch(`${rawBase}/${chunkPath(folder, safe, i)}`, { headers: authHeader });
              if (!res.ok) { controller.error(new Error(`chunk_${i}_missing`)); return; }
              const buf = await res.arrayBuffer();
              const expected = manifest.chunks?.[i]?.blobSha;
              if (expected) { const actual = await gitBlobSha(buf); if (actual !== expected) { controller.error(new Error(`chunk_${i}_corrupt`)); return; } }
              controller.enqueue(new Uint8Array(buf));
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
  // ── Try API key auth first ────────────────────────────────────────────────
  const apiKeyHeader = request.headers.get('X-API-Key') || '';
  if (apiKeyHeader) {
    const akResult = await resolveApiKey(request, env, secret);
    if (!akResult) return fail(request, 401);
    if (akResult.blocked) return jsonRes(request, { error: akResult.reason }, 403);
    // API keys can access storage routes only (not account management)
    const AK_ALLOWED = new Set(['files','upload','upload-chunk','finalize-upload','download','delete','share-link','me','repos','storage']);
    if (!AK_ALLOWED.has(route)) return fail(request, 403);
    return _dispatchRoute(route, method, request, env, akResult.fullSess, null, secret, akResult.allowedOrigins);
  }

  // ── Session cookie auth ───────────────────────────────────────────────────
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
  const response = await _dispatchRoute(route, method, request, env, fullSess, sess, secret, null);
  if (refreshCookie) {
    const headers = new Headers(response.headers);
    headers.append('Set-Cookie', refreshCookie);
    return new Response(response.body, { status: response.status, headers });
  }
  return response;
}
async function _dispatchRoute(route, method, request, env, fullSess, sess, secret, apiKeyOrigins = null) {
  const cors = corsHeaders(request, apiKeyOrigins);
  function jRes(data, status=200, extra={}) {
    return new Response(JSON.stringify(data), { status, headers: { ...SEC, ...cors, 'Content-Type':'application/json', ...extra } });
  }
  const kv = env.RATE_LIMIT_KV || null;

  if (route === 'me' && method === 'GET') {
    const storage = await getStorageFromIndex(fullSess);
    return jRes({
      username: fullSess.username, display: fullSess.display,
      repo: `${fullSess.ghOwner}/${fullSess.ghRepo}`,
      repoLabel: fullSess.repoLabel, folder: fullSess.folder,
      repos: fullSess.repos, activeRepoIdx: fullSess.activeRepoIdx,
      storage,
    });
  }
  if (route === 'repos' && method === 'GET') {
    return jRes({ repos: fullSess.repos, activeRepoIdx: fullSess.activeRepoIdx });
  }
  // ── Storage breakdown — all repos in parallel ──────────────────────────────
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
    if (!sess) return jRes({ error: 'Session required' }, 403);
    let body; try { body = await request.json(); } catch { return jRes({ error: ERRS[400] }, 400); }
    const { repoIdx } = body||{};
    if (typeof repoIdx !== 'number' || repoIdx < 0 || repoIdx >= fullSess.repos.length) return jRes({ error: ERRS[400] }, 400);
    const newToken = await createToken({ username: sess.username, display: sess.display, repoIdx }, secret);
    return jRes({ ok:true, repoIdx }, 200, { 'Set-Cookie': buildSetCookie(request, newToken, SESSION_TTL / 1000) });
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
    if (repoIdx === 0) return jRes({ error: 'Cannot remove the primary repository' }, 400);
    if (repoIdx >= repos.length) return jRes({ error: ERRS[400] }, 400);
    repos.splice(repoIdx, 1);
    const updated = { ...user, repos };
    try { await writeReg(userPath(sess.username), updated, `Remove repo ${repoIdx}`, env, userSha); }
    catch { return jRes({ error: ERRS[502] }, 502); }
    if (kv) await env.RATE_LIMIT_KV.delete(`sess_cache:${sess.jti}`).catch(() => {});
    return jRes({ ok:true });
  }

  // ── API Key management (session only) ─────────────────────────────────────
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
    if (existingKeys.length >= 10) return jRes({ error: 'Maximum of 10 API keys allowed' }, 400);
    const rawKey = generateRawApiKey();
    const keyId  = base64urlFromBytes(crypto.getRandomValues(new Uint8Array(9))); // 9 bytes → 12 B64URL chars, URL-safe unique ID
    const preview = rawKey.slice(0, 12) + '…';
    // Store in KV for fast lookup
    if (!kv) return jRes({ error: 'KV binding required for API keys' }, 500);
    const kvKey  = await apiKeyKvKey(rawKey);
    await kv.put(kvKey, JSON.stringify({
      username: sess.username, label, allowedOrigins, keyId,
    })).catch(() => {});
    // Store metadata (not raw key) in user record
    const encKey = await aesEncrypt(rawKey, secret, `apikey:${sess.username}:${keyId}`);
    const keyMeta = { keyId, preview, label, allowedOrigins, createdAt: new Date().toISOString(), encKey };
    const updated = { ...user, apiKeys: [...existingKeys, keyMeta] };
    try { await writeReg(userPath(sess.username), updated, `Create API key: ${label}`, env, userSha); }
    catch { const _k = await apiKeyKvKey(rawKey); await kv.delete(_k).catch(() => {}); return jRes({ error: ERRS[502] }, 502); }
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
    // Decrypt to get raw key so we can delete from KV
    if (kv && target.encKey) {
      try {
        const rawKey  = await aesDecrypt(target.encKey, secret, `apikey:${sess.username}:${keyId}`);
        const rkvKey = await apiKeyKvKey(rawKey);
        await kv.delete(rkvKey).catch(() => {});
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
    const never = ttlP === 0;
    const safe  = sanitize(nameP);
    if (!safe) return fail(request, 400);
    const ttl = never ? 0 : Math.max(60, Math.min(ttlP, SHARE_TTL_MAX));
    let size = 0, displayName = unwrapName(safe);
    try {
      const { data: idx } = await readIndex(fullSess);
      if (idx[safe]) { displayName = idx[safe].originalName || unwrapName(safe); size = idx[safe].totalSize || idx[safe].size || 0; }
    } catch {}
    const exp = never ? null : new Date(Date.now() + ttl * 1000).toISOString();
    const tok = await createShareToken(
      sess ? sess.username : fullSess.username,
      safe, fullSess.activeRepoIdx, ttl, size, displayName, secret
    );
    const kv2 = env.RATE_LIMIT_KV || null;
    let url = `/api/dl?tok=${encodeURIComponent(tok)}`;
    if (kv2) {
      // Use bias-free randomAlphabetString with the shared B64URL_CHARS (64-char alphabet;
      // 256 % 64 === 0 so there is zero modulo bias, but randomAlphabetString is
      // still used here for consistency and future-proofing if the alphabet changes.)
      let shortId = null;
      outer: for (let len = 4; len <= 6; len++) {   // start at 4: 64^4 = 16M slots
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
    // Optional ?repoIdx= param lets callers fetch a specific repo without switching session
    const qRepoIdx = parseInt(new URL(request.url).searchParams.get('repoIdx') ?? '', 10);
    if (!isNaN(qRepoIdx) && qRepoIdx >= 0 && qRepoIdx < fullSess.repos.length && qRepoIdx !== fullSess.activeRepoIdx) {
      // Build a one-off session for this repo index without mutating the session
      const targetRepo = fullSess.repos[qRepoIdx];
      fullSess = {
        ...fullSess,
        ghOwner: targetRepo.ghOwner, ghRepo: targetRepo.ghRepo,
        ghBranch: targetRepo.ghBranch || 'main',
        folder: targetRepo.folder || 'uploads',
        repoLabel: (targetRepo.label && targetRepo.label !== 'Default') ? targetRepo.label : '',
        activeRepoIdx: qRepoIdx,
      };
    }
    try {
      const [regular, { data: idx }] = await Promise.all([
        listFiles(fullSess),
        readIndex(fullSess).catch(() => ({ data: {} })),
      ]);
      const chunked = Object.entries(idx)
        .filter(([, info]) => info.totalChunks)
        .map(([name, info]) => ({ name, originalName: info.originalName || unwrapName(name), size: info.totalSize, sha: '', chunked: true, parts: info.totalChunks, uploadedAt: info.uploadedAt || null }));
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
      return jRes({ files: all, storage: computeStorageStats(all) });
    } catch { return jRes({ error: ERRS[502] }, 502); }
  }
  if (route === 'upload' && method === 'POST') {
    if (!(request.headers.get('Content-Type')||'').includes('application/json')) return jRes({ error: ERRS[400] },400);
    let body; try { body = await request.json(); } catch { return jRes({ error: ERRS[400] },400); }
    const { name: rawName, content: b64 } = body||{};
    if (!rawName || !b64 || typeof b64 !== 'string') return jRes({ error: ERRS[400] },400);
    if (b64.length > CHUNK_B64_MAX) return jRes({ error: ERRS[413] },413);
    const safe = sanitize(String(rawName));
    if (!safe) return jRes({ error: ERRS[415] },415);
    if (!checkMagicBase64(b64)) return jRes({ error: ERRS[415] },415);
    const decodedSize = Math.floor(b64.length * 3 / 4);
    try {
      if (decodedSize > SMALL_MAX_BYTES) {
        const blobSha = await createBlob(fullSess, b64);
        const { ghToken, ghOwner, ghRepo, ghBranch, folder } = fullSess;
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
        await uploadSmall(fullSess, safe, b64);
      }
      try {
        const { data: idx, sha: idxSha } = await readIndex(fullSess);
        idx[safe] = { originalName: getOriginalName(rawName, safe), uploadedAt: new Date().toISOString(), size: decodedSize };
        await writeIndex(fullSess, idx, idxSha);
      } catch {}
      return jRes({ ok:true, name:safe, size:decodedSize });
    } catch { return jRes({ error: ERRS[502] }, 502); }
  }
  if (route === 'upload-chunk' && method === 'POST') {
    if (!(request.headers.get('Content-Type')||'').includes('application/json')) return jRes({ error: ERRS[400] },400);
    let body; try { body = await request.json(); } catch { return jRes({ error: ERRS[400] },400); }
    const { name: rawName, chunkIndex, totalChunks, content: b64 } = body||{};
    if (!rawName || !b64 || typeof b64 !== 'string') return jRes({ error: ERRS[400] },400);
    if (b64.length > CHUNK_B64_MAX) return jRes({ error: ERRS[413] },413);
    const chunkIdx = parseInt(chunkIndex, 10);
    const tot = parseInt(totalChunks, 10);
    if (isNaN(chunkIdx)||chunkIdx<0) return jRes({ error: ERRS[400] },400);
    if (isNaN(tot)||tot<1||tot>MAX_TOTAL_CHUNKS) return jRes({ error: ERRS[400] },400);
    const safe = sanitize(String(rawName));
    if (!safe) return jRes({ error: ERRS[415] },415);
    if (chunkIdx === 0 && !checkMagicBase64(b64)) return jRes({ error: ERRS[415] },415);
    const decodedSize = Math.floor(b64.length * 3 / 4);
    // For API key sessions, use a synthetic jti
    const jti = sess ? sess.jti : `ak:${fullSess.username}`;
    try {
      const blobSha   = await createBlob(fullSess, b64);
      const blobToken = await blobTokenSign(jti, safe, chunkIdx, blobSha, secret);
      return jRes({ ok:true, blobSha, blobToken, index: chunkIdx, size: decodedSize });
    } catch { return jRes({ error: ERRS[502] }, 502); }
  }
  if (route === 'finalize-upload' && method === 'POST') {
    let body; try { body = await request.json(); } catch { return jRes({ error: ERRS[400] },400); }
    const { name, totalSize, totalChunks, chunkSize, blobs } = body||{};
    if (!name||!totalSize||!totalChunks||!Array.isArray(blobs)) return jRes({ error: ERRS[400] },400);
    if (blobs.length !== totalChunks) return jRes({ error: ERRS[400] },400);
    if (totalChunks > MAX_TOTAL_CHUNKS) return jRes({ error: ERRS[413] },413);
    const MAX_FILE_BYTES = MAX_TOTAL_CHUNKS * CHUNK_B64_MAX;
    if (!Number.isInteger(totalSize) || totalSize < 1 || totalSize > MAX_FILE_BYTES) return jRes({ error: ERRS[400] }, 400);
    if (chunkSize !== undefined && (!Number.isInteger(chunkSize) || chunkSize < 1 || chunkSize > CHUNK_B64_MAX)) return jRes({ error: ERRS[400] }, 400);
    const safe = sanitize(String(name));
    if (!safe) return jRes({ error: ERRS[415] }, 415);
    const jti = sess ? sess.jti : `ak:${fullSess.username}`;
    for (const b of blobs) {
      if (typeof b.blobSha   !== 'string' || !SHA_RE.test(b.blobSha)) return jRes({ error: ERRS[400] },400);
      if (typeof b.blobToken !== 'string')                             return jRes({ error: ERRS[400] },400);
      if (typeof b.index     !== 'number' || b.index < 0)             return jRes({ error: ERRS[400] },400);
      if (typeof b.size      !== 'number' || b.size  < 1)             return jRes({ error: ERRS[400] },400);
      const expected = await blobTokenSign(jti, safe, b.index, b.blobSha, secret);
      if (!(await timingSafeEq(b.blobToken, expected))) return jRes({ error: ERRS[403] }, 403);
    }
    try {
      await finalizeChunkedUpload(fullSess, safe, blobs, totalSize, chunkSize);
      const { data: idx, sha: idxSha } = await readIndex(fullSess);
      idx[safe] = { originalName: getOriginalName(name, safe), totalSize, totalChunks, uploadedAt: new Date().toISOString() };
      await writeIndex(fullSess, idx, idxSha);
      return jRes({ ok:true, name:safe });
    } catch { return jRes({ error: ERRS[502] }, 502); }
  }
  if (route === 'download' && method === 'GET') {
    const nameParam = new URL(request.url).searchParams.get('name') || '';
    const safe = sanitize(nameParam);
    if (!safe) return jRes({ error: ERRS[400] },400);
    const { ghToken, ghOwner, ghRepo, ghBranch, folder } = fullSess;
    let manifest = null, serveAs = safe;
    try {
      const { data: idx } = await readIndex(fullSess);
      if (idx[safe]) serveAs = idx[safe].originalName || unwrapName(safe);
      else serveAs = unwrapName(safe);
      if (idx[safe]?.totalChunks) {
        const mRes = await fetch(`https://api.github.com/repos/${ghOwner}/${ghRepo}/contents/${manifestP(folder,safe)}?ref=${ghBranch}`, { headers: ghH(ghToken) });
        if (mRes.ok) { const mData = await mRes.json(); manifest = JSON.parse(atob(mData.content.replace(/\s/g,''))); }
      }
    } catch {}
    if (manifest) {
      const rawBase    = `https://raw.githubusercontent.com/${ghOwner}/${ghRepo}/${ghBranch}`;
      const authHeader = { Authorization:`token ${ghToken}`, 'User-Agent':'StoreGit/1' };
      const stream = new ReadableStream({
        async start(controller) {
          try {
            for (let i = 0; i < manifest.totalChunks; i++) {
              const res = await fetch(`${rawBase}/${chunkPath(folder, safe, i)}`, { headers: authHeader });
              if (!res.ok) { controller.error(new Error(`chunk_${i}_missing`)); return; }
              const buf = await res.arrayBuffer();
              const expected = manifest.chunks?.[i]?.blobSha;
              if (expected) { const actual = await gitBlobSha(buf); if (actual !== expected) { controller.error(new Error(`chunk_${i}_corrupt`)); return; } }
              controller.enqueue(new Uint8Array(buf));
            }
            controller.close();
          } catch (e) { controller.error(e); }
        },
      });
      return new Response(stream, { status:200, headers: { ...SEC, ...cors, 'Content-Type': safeMime(serveAs), 'Content-Disposition': contentDisposition(serveAs), 'Content-Length': String(manifest.totalSize), 'Accept-Ranges':'none' } });
    }
    const rawUrl = `https://raw.githubusercontent.com/${ghOwner}/${ghRepo}/${ghBranch}/${folder}/${encodeURIComponent(safe)}`;
    let ghRes;
    try { ghRes = await fetch(rawUrl, { headers:{ Authorization:`token ${ghToken}`, 'User-Agent':'StoreGit/1' } }); }
    catch { return jRes({ error: ERRS[502] },502); }
    if (ghRes.status===404) return jRes({ error: ERRS[404] },404);
    if (!ghRes.ok) return jRes({ error: ERRS[502] },502);
    const len = ghRes.headers.get('Content-Length')||'';
    return new Response(ghRes.body, { status:200, headers: { ...SEC, ...cors, 'Content-Type': safeMime(serveAs), 'Content-Disposition': contentDisposition(serveAs), ...(len?{'Content-Length':len}:{}), 'Accept-Ranges':'bytes' } });
  }
  if (route === 'delete' && method === 'DELETE') {
    let body; try { body = await request.json(); } catch { return jRes({ error: ERRS[400] },400); }
    const { name, sha, chunked } = body||{};
    if (typeof name !== 'string') return jRes({ error: ERRS[400] },400);
    const safe = sanitize(name);
    if (!safe) return jRes({ error: ERRS[400] },400);
    if (chunked) {
      try {
        await deleteChunked(fullSess, safe);
        const { data: idx, sha: idxSha } = await readIndex(fullSess);
        delete idx[safe];
        await writeIndex(fullSess, idx, idxSha);
        return jRes({ ok:true });
      } catch { return jRes({ error: ERRS[502] },502); }
    } else {
      if (typeof sha !== 'string' || !SHA_RE.test(sha)) return jRes({ error: ERRS[400] },400);
      try {
        await deleteRegular(fullSess, safe, sha);
        try {
          const { data: idx, sha: idxSha } = await readIndex(fullSess);
          if (idx[safe]) { delete idx[safe]; await writeIndex(fullSess, idx, idxSha); }
        } catch {}
        return jRes({ ok:true });
      } catch { return jRes({ error: ERRS[502] },502); }
    }
  }
  return jRes({ error: ERRS[404] }, 404);
}
