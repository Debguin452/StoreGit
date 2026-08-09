import { createRequire } from 'module';
import { getServer, getCookie, parseCookie, saveSession, getUsername } from './auth.js';

const _require = createRequire(import.meta.url);
const _pkg     = _require('../package.json');
const UA       = `storegit-cli/${_pkg.version}`;

const MAX_RETRIES   = 3;
const RETRY_BASE_MS = 600;

// ── MIME from extension ───────────────────────────────────────────────────────
const MIME_MAP = {
  pdf:'application/pdf', png:'image/png', jpg:'image/jpeg', jpeg:'image/jpeg',
  gif:'image/gif', webp:'image/webp', svg:'image/svg+xml',
  mp4:'video/mp4', webm:'video/webm', mp3:'audio/mpeg', wav:'audio/wav',
  zip:'application/zip', tar:'application/x-tar', gz:'application/gzip',
  txt:'text/plain', md:'text/markdown', html:'text/html', css:'text/css',
  js:'text/javascript', mjs:'text/javascript', ts:'text/typescript',
  json:'application/json', xml:'application/xml', yaml:'text/yaml', yml:'text/yaml',
  csv:'text/csv', py:'text/x-python', sh:'text/x-shellscript',
  c:'text/x-csrc', cpp:'text/x-c++src', go:'text/x-go', rs:'text/x-rust',
  java:'text/x-java', rb:'text/x-ruby', php:'text/x-php', sql:'text/x-sql',
  doc:'application/msword',
  docx:'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  xls:'application/vnd.ms-excel',
  xlsx:'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  pptx:'application/vnd.openxmlformats-officedocument.presentationml.presentation',
};
const TEXT_EXTS  = new Set(['txt','md','markdown','json','js','mjs','cjs','ts','tsx','jsx',
  'c','cpp','h','hpp','cs','java','go','rs','py','rb','php','sh','bash','zsh',
  'lua','r','swift','kt','css','html','htm','xml','yaml','yml','toml','ini',
  'cfg','conf','log','csv','sql','diff','patch','env','gitignore','dockerfile','makefile']);
const IMAGE_EXTS = new Set(['png','jpg','jpeg','gif','webp','svg','bmp','ico','avif']);
const MEDIA_EXTS = new Set(['mp4','webm','mp3','wav','ogg','flac','aac','m4a','mov']);

export function mimeFromName(name) {
  const ext = (name||'').split('.').pop().toLowerCase();
  return MIME_MAP[ext] || 'application/octet-stream';
}
export function isText(name)  { return TEXT_EXTS.has((name||'').split('.').pop().toLowerCase()); }
export function isImage(name) { return IMAGE_EXTS.has((name||'').split('.').pop().toLowerCase()); }
export function isMedia(name) { return MEDIA_EXTS.has((name||'').split('.').pop().toLowerCase()); }

// ── Normalise every server file entry into a consistent shape ─────────────────
export function normaliseFile(f, repoIdx = 0) {
  const name     = f.name || '';
  const origName = f.originalName || name;
  const mime     = mimeFromName(origName);
  const chunked  = !!(f.chunked || f.totalChunks);
  return {
    name,
    originalName: origName,
    size:         f.size         ?? null,
    shareUrl:     f.shareUrl     ?? null,
    type:         chunked ? `${mime} (chunked)` : mime,
    sha:          f.sha          ?? null,
    uploadedAt:   f.uploadedAt   ?? null,
    modifiedAt:   f.modifiedAt   ?? f.uploadedAt ?? null,
    repo:         f.repoIdx      ?? repoIdx,
    chunked,
    parts:        chunked ? (f.totalChunks ?? f.parts ?? null) : null,
    distributed:  f.distributed  ?? false,
    repoCount:    f.repoCount    ?? 1,
  };
}

// ── Core fetch ────────────────────────────────────────────────────────────────
async function request(method, path, { body, server, stream = false } = {}) {
  const base    = (server || getServer()).replace(/\/+$/, '');
  const url     = `${base}/api/${path}`;
  const headers = { 'Cookie': getCookie(), 'User-Agent': UA };
  if (body !== undefined) headers['Content-Type'] = 'application/json';

  let attempt = 0;
  while (true) {
    attempt++;
    let res;
    try {
      res = await fetch(url, { method, headers,
        body: body !== undefined ? JSON.stringify(body) : undefined });
    } catch (e) {
      if (attempt > MAX_RETRIES) throw new Error(`Network error: ${e.message}`);
      await sleep(RETRY_BASE_MS * 2 ** (attempt - 1)); continue;
    }
    const setCookie = res.headers.get('set-cookie');
    const fresh     = parseCookie(setCookie);
    if (fresh && fresh !== getCookie()) {
      saveSession({ cookie: fresh, username: getUsername() });
      headers['Cookie'] = fresh;
    }
    if (res.status === 429 && attempt <= MAX_RETRIES) {
      await sleep(Math.min(parseInt(res.headers.get('retry-after')||'10',10)*1000, 60_000));
      continue;
    }
    if (res.status >= 500 && attempt <= MAX_RETRIES) {
      await sleep(RETRY_BASE_MS * 2 ** (attempt - 1)); continue;
    }
    if (stream) return res;
    const text = await res.text();
    let data;
    try { data = JSON.parse(text); } catch { data = { error: text || `HTTP ${res.status}` }; }
    if (!res.ok) { const e = new Error(data?.error||`HTTP ${res.status}`); e.status=res.status; throw e; }
    return data;
  }
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
const get  = (path, o)    => request('GET',    path, o);
const post = (path, b, o) => request('POST',   path, { body: b, ...o });
const del  = (path, b, o) => request('DELETE', path, { body: b, ...o });

// ── Auth ──────────────────────────────────────────────────────────────────────
export async function login({ server, username, password }) {
  const res = await fetch(`${(server||getServer()).replace(/\/+$/,'')}/api/login`, {
    method:'POST', headers:{'Content-Type':'application/json','User-Agent':UA},
    body: JSON.stringify({ username, password }),
  });
  const data = await res.json().catch(()=>({}));
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  const setCookies = typeof res.headers.getSetCookie==='function'
    ? res.headers.getSetCookie()
    : (res.headers.get('set-cookie')||'').split(/,(?=\s*(?:__Host|sg_sess|session))/);
  let cookie = null;
  for (const sc of setCookies) { cookie = parseCookie(sc); if (cookie) break; }
  if (!cookie) throw new Error('Server did not return a session cookie');
  return { cookie, data };
}
export async function signup({ server, username, password, displayName, ghToken, ghOwner, ghRepo, ghBranch, folder }) {
  const base = (server||getServer()).replace(/\/+$/,'');
  const res  = await fetch(`${base}/api/signup`, {
    method:'POST', headers:{'Content-Type':'application/json','User-Agent':UA},
    body: JSON.stringify({ username, password, displayName, ghToken, ghOwner, ghRepo,
                           ghBranch:ghBranch||'main', folder:folder||'uploads' }),
  });
  const data = await res.json().catch(()=>({}));
  if (!res.ok) throw new Error(data.error||`HTTP ${res.status}`);
  return data;
}
export async function logout()  { return post('logout',{}).catch(()=>{}); }
export async function me()      { return get('me'); }
export async function status(s) { return get('status',{server:s}); }

// ── Files ─────────────────────────────────────────────────────────────────────
export async function listFiles(repoIdx=0) {
  const raw = await get(`files${repoIdx>0?`?repoIdx=${repoIdx}`:''}`);
  const arr = Array.isArray(raw) ? raw : (raw.files||[]);
  return arr.map(f => normaliseFile(f, repoIdx));
}
export async function uploadSmall(name, b64Content) { return post('upload',{name,content:b64Content}); }
export async function uploadChunk({ name, chunkIndex, totalChunks, totalSize, content, targetRepoIdx }) {
  return post('upload-chunk',{ name, chunkIndex, totalChunks, totalSize, content, targetRepoIdx });
}
export async function finalizeUpload({ name, totalSize, totalChunks, chunkSize, blobs, targetRepoIdx }) {
  return post('finalize-upload',{ name, totalSize, totalChunks, chunkSize, blobs, targetRepoIdx });
}
export async function downloadFile(name, repoIdx=0) {
  return get(`download?name=${encodeURIComponent(name)}${repoIdx>0?`&repoIdx=${repoIdx}`:''}`, { stream:true });
}
export async function deleteFile({ name, sha, chunked, repoIdx }) {
  return del('delete',{ name, sha, chunked:!!chunked, repoIdx:repoIdx||0 });
}

// ── Share link — uses server's share-link endpoint ────────────────────────────
export async function createShare({ name, repoIdx=0, ttl=3600 }) {
  const qs = `name=${encodeURIComponent(name)}&repoIdx=${repoIdx}&ttl=${ttl}`;
  return get(`share-link?${qs}`);
}

// ── Repos — add / remove / list only (no switch/default concept) ──────────────
export async function addRepo({ label, ghOwner, ghRepo, ghBranch, folder, ghToken }) {
  return post('add-repo',{ label, ghOwner, ghRepo, ghBranch:ghBranch||'main',
                           folder:folder||'uploads', ghToken });
}
export async function removeRepo(repoIdx) { return post('remove-repo',{ repoIdx }); }

// ── API keys ──────────────────────────────────────────────────────────────────
export async function listApiKeys()  { return get('apikeys/list'); }
export async function createApiKey({ label, allowedOrigins }) {
  return post('apikeys/create',{ label, allowedOrigins:allowedOrigins||[] });
}
export async function revokeApiKey(keyId) { return del('apikeys/revoke',{ keyId }); }

// ── Folders (server endpoints added in this update) ───────────────────────────
export async function mkdirFolder({ path: p, repoIdx=0 }) {
  return post('mkdir',{ path:p, repoIdx });
}
export async function rmdirFolder({ path: p, repoIdx=0 }) {
  return del('rmdir',{ path:p, repoIdx });
}
export async function moveFile({ name, destName, srcRepoIdx=0, destRepoIdx=0 }) {
  return post('move',{ name, destName, srcRepoIdx, destRepoIdx });
}
