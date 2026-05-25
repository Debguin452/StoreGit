# StoreGit

A serverless file-storage platform built on **Cloudflare Pages Functions** and the **GitHub Contents / Git Data APIs**. Each user connects their own GitHub repository as storage. You deploy one Cloudflare Pages project; users bring their own GitHub repo and personal access token.

---

## Table of Contents

1. [Architecture](#architecture)
2. [Features](#features)
3. [Security Model](#security-model)
4. [API Key System](#api-key-system)
5. [REST API Reference](#rest-api-reference)
6. [Deployment](#deployment)
7. [Environment Variables](#environment-variables)
8. [KV Namespace](#kv-namespace)
9. [Using StoreGit from Any App](#using-storegit-from-any-app)
10. [Changelog](#changelog)

---

## Architecture

```
Browser / External App
        │
        │  HTTPS  (X-API-Key header  OR  session cookie)
        ▼
Cloudflare Pages (CDN edge)
        │
        ├─ functions/_middleware.js     ← Security headers, rate-limit, bot-block (runs first on every request)
        ├─ functions/api/[[path]].js    ← All API routes
        └─ functions/[id].js            ← Short share-link resolver  (e.g. /aBcD)
        │
        │  GitHub REST API + Git Data API
        ▼
GitHub Repository  (one per user — the actual file store)
```

File content never touches Cloudflare KV. KV stores only:

| KV key | Value |
|---|---|
| `apikey:sha256:<hex>` | `{ username, label, allowedOrigins, keyId }` |
| `sess_cache:<jti>` | Cached full session payload |
| `revoked:<jti>` | Revoked session marker |
| `rate:<scope>:<window>` | Rate-limit counters |
| `sl:<shortId>` | Share-link metadata `{ tok, displayName, size, exp }` |

---

## Features

- **Upload / download / delete** — GitHub Contents API for files up to ~50 MB; Git Data API (chunked) for files up to ~5 GB
- **Multiple repositories** per account — connect as many GitHub repos as you like; all files appear in a single unified list
- **Shareable links** — signed tokens with configurable expiry (1 hr / 24 hr / 7 days / never), shortened to 3–5 character IDs stored in KV
- **Inline previews** on share pages — images, video, audio, and code/text files all render before the download button
- **API keys** — generate in-app, optionally restrict to specific origins, revoke instantly; keys are SHA-256 hashed in KV (raw key never stored)
- **Hamburger drawer** — repository management and API key management in a slide-in panel; main canvas stays clean
- **Security middleware** — CSP, HSTS, CORS, bot-blocking, and rate-limiting on every edge request, before any route handler runs
- **Dark mode** — follows `prefers-color-scheme` with no JavaScript
- **Resilient upload queue** — survives page refresh; pauses and resumes mid-batch

---

## Security Model

### Global middleware (`functions/_middleware.js`)

Every request — HTML pages, API calls, static assets — passes through `_middleware.js` before any route handler runs.

| Check | Detail |
|---|---|
| **HTTPS redirect** | HTTP → HTTPS 301 in production |
| **Bad user-agent block** | sqlmap, nikto, nmap, masscan, dirbuster, nuclei, burpsuite, and others |
| **Global rate limit** | 600 req/min per IP (sliding window, in-process Map) |
| **Method allowlist** | `GET POST DELETE OPTIONS HEAD` — all others → 405 |
| **Path traversal** | Rejects `..`, null bytes, `%00` in path |
| **Scanner probe block** | `/wp-admin`, `/.env`, `/.git`, `/phpmyadmin`, `/xmlrpc` → 404 |
| **Security headers** | See table below |
| **Information stripping** | Removes `Server`, `X-Powered-By`, `X-AspNet-Version` |

**Security headers set on every response:**

```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: no-referrer
X-Permitted-Cross-Domain-Policies: none
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
Cross-Origin-Resource-Policy: same-origin
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), …
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
Content-Security-Policy: (HTML pages — strict default-src 'none')
```

### Session security

- HMAC-SHA-256 signed JWTs stored in `HttpOnly; Secure; SameSite=Strict` cookies
- JTI is 24 bytes of CSPRNG encoded as Base64URL (192-bit entropy — unguessable)
- Sessions refresh automatically when within 1 hour of expiry
- Revoked sessions are marked in KV and rejected immediately on every subsequent request

---

## API Key System

### Key format

```
sgk_<43 Base64URL characters>
```

| Property | Value |
|---|---|
| Entropy | 32 bytes = 256 bits of CSPRNG |
| Alphabet | Base64URL — `A-Z a-z 0-9 - _` (64 chars, 6 bits/char) |
| Encoding | RFC 4648 §5, bias-free rejection sampling |
| Total length | `sgk_` + 43 = **47 characters** |

### Storage — hashed keys, never raw

Raw keys are **never stored anywhere**. Only their SHA-256 digest is used as the KV lookup key:

```
KV key:   "apikey:sha256:<SHA-256(rawKey) as hex>"
KV value: { username, label, allowedOrigins, keyId }
```

Even if KV were fully compromised, no raw keys could be reconstructed.

The `encKey` field in the user record stores the raw key encrypted with AES-GCM (keyed from `APP_SECRET`) so that revocation can recompute the hash and clean up the KV entry.

### Origin binding

When creating a key you may restrict it to specific origins:

```json
{ "label": "My Blog", "allowedOrigins": ["https://myblog.com"] }
```

- Empty `allowedOrigins` → any origin is permitted (useful for server-to-server calls)
- Non-empty → request `Origin` must appear in the list; otherwise 403
- No `Origin` header (server-to-server) → always permitted regardless of binding

### Rate limiting

- Per-key: 120 requests/minute
- Global: 600 requests/minute per IP (via `_middleware.js`)
- Maximum 10 API keys per account

---

## REST API Reference

All endpoints are under `/api/`. Authenticate with either:
- **Session cookie** — set automatically after login; use `credentials: 'same-origin'`
- **API key** — send `X-API-Key: sgk_…` header

### Authentication

#### `POST /api/signup`
```json
{ "username": "alice", "password": "…", "displayName": "Alice",
  "ghToken": "ghp_…", "ghOwner": "alice", "ghRepo": "my-storage",
  "ghBranch": "main", "folder": "uploads" }
```

#### `POST /api/login`
```json
{ "username": "alice", "password": "…" }
```
Sets a session cookie. Returns `{ ok: true }`.

#### `POST /api/logout`
Clears the session cookie. Returns `{ ok: true }`.

#### `GET /api/me`
Returns current user info. Available with API key.
```json
{
  "username": "alice",
  "display": "Alice",
  "repo": "alice/my-storage",
  "repoLabel": "",
  "repos": [{ "label": "", "ghOwner": "alice", "ghRepo": "my-storage" }],
  "activeRepoIdx": 0
}
```

---

### Files

#### `GET /api/files`
#### `GET /api/files?repoIdx=<n>`

List files in the active repo (or a specific repo by index without mutating session state).

```json
[
  {
    "name": "report_2025.pdf",
    "originalName": "report 2025.pdf",
    "size": 204800,
    "sha": "abc123…",
    "chunked": false,
    "uploadedAt": "2025-01-01T00:00:00.000Z"
  }
]
```

#### `POST /api/upload`
Upload a file. Content must be Base64-encoded:
```json
{ "name": "notes.txt", "content": "<base64>" }
```
Returns `{ ok: true, name: "notes.txt", size: 1234 }`.

Files larger than the single-call limit are automatically uploaded in chunks. The client handles this transparently.

#### `GET /api/download?name=<filename>`
Streams the file content. For chunked files, streams all parts in order with integrity verification.

Available with API key. Use the `X-API-Key` header.

#### `DELETE /api/delete`
```json
{ "name": "notes.txt", "sha": "abc123…", "chunked": false }
```
For chunked files, set `"chunked": true` and omit `sha`.

---

### Repositories

#### `GET /api/repos`
Returns all connected repos and the active index.

#### `POST /api/add-repo`
```json
{ "label": "Backups", "ghOwner": "alice", "ghRepo": "backups",
  "ghBranch": "main", "folder": "uploads" }
```
Verifies the GitHub token has write access before adding.

#### `POST /api/switch-repo`
```json
{ "repoIdx": 1 }
```

#### `POST /api/remove-repo`
```json
{ "repoIdx": 0 }
```
Any repository can be removed. The only restriction is that you must have at least one repository connected — you cannot remove your last one.

---

### API Keys (session-authenticated only)

#### `GET /api/apikeys/list`
```json
{
  "keys": [{
    "keyId": "abc123",
    "preview": "sgk_AAAA…zzzz",
    "label": "My Blog",
    "allowedOrigins": ["https://myblog.com"],
    "createdAt": "2025-01-01T00:00:00.000Z"
  }]
}
```

#### `POST /api/apikeys/create`
```json
{ "label": "My Blog", "allowedOrigins": ["https://myblog.com"] }
```
Returns:
```json
{ "ok": true, "rawKey": "sgk_…", "keyId": "…", "preview": "sgk_AAAA…zzzz",
  "label": "My Blog", "allowedOrigins": ["https://myblog.com"] }
```
> **The `rawKey` is shown exactly once and never stored. Copy it immediately.**

#### `DELETE /api/apikeys/revoke`
```json
{ "keyId": "abc123" }
```

---

### Share links

#### `GET /api/share-link?name=<file>&ttl=<seconds>`

Creates a signed share token. Pass `ttl=0` for a link that never expires.

If KV is configured, returns a short link (3–5 chars). Otherwise returns the full signed URL.

```json
{ "url": "/aBcD", "exp": "2025-06-01T00:00:00.000Z" }
```

Short links resolve at `/<id>` — handled by `functions/[id].js`.

---

## Deployment

### 1. Clone

```bash
git clone https://github.com/your-org/storegit
cd storegit
```

### 2. Create a Cloudflare Pages project

```bash
npx wrangler pages project create storegit
```

### 3. Create a KV namespace

```bash
npx wrangler kv:namespace create RATE_LIMIT_KV
```

Bind it in **Cloudflare Dashboard → Pages → your project → Settings → Functions → KV namespace bindings** with the variable name `RATE_LIMIT_KV`.

### 4. Set environment variables

Go to **Pages → Settings → Environment variables**:

| Variable | Required | Description |
|---|---|---|
| `APP_SECRET` | Yes | 32+ random chars — used for HMAC-JWT and AES-GCM key derivation |
| `REGISTRY_GITHUB_TOKEN` | Yes | GitHub PAT with repo write access to the registry repo |
| `REGISTRY_GITHUB_OWNER` | Yes | GitHub owner of the user registry repo |
| `REGISTRY_GITHUB_REPO` | Yes | GitHub repo name of the user registry |

### 5. Deploy

```bash
npx wrangler pages deploy . --project-name storegit
```

---

## KV Namespace

One KV namespace (`RATE_LIMIT_KV`) covers all runtime storage:

| Purpose | Key pattern |
|---|---|
| Session cache | `sess_cache:<jti>` |
| Revoked sessions | `revoked:<jti>` |
| API keys (hashed) | `apikey:sha256:<hex>` |
| API key reverse index | `apikeyid:<username>:<keyId>` |
| Rate-limit counters | `rate:<scope>:<window>` |
| Share links | `sl:<shortId>` |

---

## Using StoreGit from Any App

StoreGit exposes a plain HTTP API secured with API keys. Any website, web app, or script can read and write files to a user's GitHub-backed storage using a single `X-API-Key` header — no OAuth flow, no server of your own.

**Live example:** [vaultxt.pages.dev](https://vaultxt.pages.dev) — a note-taking app built entirely on the StoreGit API ([source on GitHub](https://github.com/debguin/vaultxt)).

---

### Step 1 — Get an API key

1. Log in to your StoreGit instance
2. Tap **☰** (top right) → **API Keys** → **New Key**
3. Enter a label for your app (e.g. `My Portfolio`)
4. Optionally enter your app's domain in **Allowed Origins** (e.g. `https://myapp.com`) — this locks the key so only your site can use it
5. Tap **Create** and copy the key. It starts with `sgk_` and is shown **only once**

> Store the key safely. Treat it like a password — if it leaks, revoke it in the StoreGit UI and generate a new one.

---

### Step 2 — The basics (copy-paste ready)

Every request sends one header: `X-API-Key: sgk_…`

```js
const BASE = 'https://storegit.pages.dev'; // your StoreGit URL
const KEY  = 'sgk_…';                      // your API key
```

**List all files**

```js
const files = await fetch(`${BASE}/api/files`, {
  headers: { 'X-API-Key': KEY }
}).then(r => r.json());

// Result:
// [
//   {
//     name:         "2025-01-15_meeting-notes.md",  // filename in GitHub
//     originalName: "2025-01-15 meeting notes.md",  // display name
//     size:         2048,                            // bytes
//     sha:          "a1b2c3…",                       // Git blob SHA — needed to delete
//     chunked:      false,                           // true for files > ~50 MB
//     uploadedAt:   "2025-01-15T10:30:00.000Z"
//   },
//   …
// ]
```

**Save a text file**

Content must be Base64-encoded. This helper handles any Unicode text safely:

```js
function textToBase64(text) {
  return btoa(unescape(encodeURIComponent(text)));
}

await fetch(`${BASE}/api/upload`, {
  method:  'POST',
  headers: { 'X-API-Key': KEY, 'Content-Type': 'application/json' },
  body: JSON.stringify({
    name:    'hello.txt',           // filename — spaces become underscores
    content: textToBase64('Hello, world! 🌍')
  })
}).then(r => r.json());
// { ok: true, name: "hello.txt", size: 18 }
```

**Read a file**

```js
const text = await fetch(
  `${BASE}/api/download?name=${encodeURIComponent('hello.txt')}`,
  { headers: { 'X-API-Key': KEY } }
).then(r => r.text());

console.log(text); // "Hello, world! 🌍"
```

**Delete a file**

The `sha` comes from the file list. For chunked files (>~50 MB), pass `chunked: true` instead of `sha`.

```js
await fetch(`${BASE}/api/delete`, {
  method:  'DELETE',
  headers: { 'X-API-Key': KEY, 'Content-Type': 'application/json' },
  body: JSON.stringify({
    name: 'hello.txt',
    sha:  'a1b2c3…'    // from /api/files
  })
}).then(r => r.json());
// { ok: true }
```

---

### Step 3 — Uploading files from a browser `<input>`

Images, PDFs, and any binary file from `<input type="file">` need a different Base64 approach:

```html
<input type="file" id="picker">
<button onclick="upload()">Upload</button>

<script>
const BASE = 'https://storegit.pages.dev';
const KEY  = 'sgk_…';

async function upload() {
  const file   = document.getElementById('picker').files[0];
  if (!file) return;

  // Convert file → Base64
  const buffer = await file.arrayBuffer();
  const bytes  = new Uint8Array(buffer);
  let   binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  const base64 = btoa(binary);

  const result = await fetch(`${BASE}/api/upload`, {
    method:  'POST',
    headers: { 'X-API-Key': KEY, 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: file.name, content: base64 })
  }).then(r => r.json());

  console.log('Uploaded:', result);
}
</script>
```

---

### Step 4 — Downloading / saving a file to disk

```js
async function downloadFile(name) {
  const blob = await fetch(
    `${BASE}/api/download?name=${encodeURIComponent(name)}`,
    { headers: { 'X-API-Key': KEY } }
  ).then(r => r.blob());

  const url = URL.createObjectURL(blob);
  const a   = Object.assign(document.createElement('a'), {
    href:     url,
    download: name
  });
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
```

---

### Step 5 — A reusable wrapper (what VaulTxt uses internally)

Drop this into any project and call `sg.*` instead of writing raw `fetch` calls:

```js
const sg = (() => {
  const BASE = 'https://storegit.pages.dev';
  const KEY  = localStorage.getItem('my_app_key') ?? '';

  const h = (extra = {}) => ({ 'X-API-Key': KEY, ...extra });

  const req = (method, path, body) =>
    fetch(`${BASE}/api/${path}`, {
      method,
      headers: body ? h({ 'Content-Type': 'application/json' }) : h(),
      body:    body ? JSON.stringify(body) : undefined
    }).then(async r => {
      const data = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(data.error ?? `HTTP ${r.status}`);
      return data;
    });

  const toB64 = text => btoa(unescape(encodeURIComponent(text)));

  return {
    /** List all files */
    list:   ()              => req('GET',    'files'),

    /** Read a file as text */
    read:   name            => fetch(`${BASE}/api/download?name=${encodeURIComponent(name)}`, { headers: h() }).then(r => r.text()),

    /** Save a text string as a file */
    save:   (name, text)    => req('POST',   'upload',  { name, content: toB64(text) }),

    /** Delete a file. sha from list(); chunked=true for large files */
    delete: (name, sha)     => req('DELETE', 'delete',  sha ? { name, sha } : { name, chunked: true }),

    /** Download a file to disk (browser only) */
    download: async name => {
      const blob = await fetch(`${BASE}/api/download?name=${encodeURIComponent(name)}`, { headers: h() }).then(r => r.blob());
      const url  = URL.createObjectURL(blob);
      Object.assign(document.createElement('a'), { href: url, download: name }).click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    },
  };
})();

// Usage
const files = await sg.list();
const text  = await sg.read('notes.md');
await sg.save('notes.md', '# My note

Hello!');
await sg.delete('notes.md', files[0].sha);
await sg.download('notes.md');
```

---

### Step 6 — Full minimal example page

A complete standalone HTML file — no build step, no dependencies — that lists, creates, and deletes files:

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>My StoreGit App</title>
  <style>
    body { font-family: sans-serif; max-width: 600px; margin: 40px auto; padding: 0 16px; }
    textarea { width: 100%; height: 120px; }
    button { margin: 4px 4px 4px 0; padding: 6px 14px; cursor: pointer; }
    #file-list { margin-top: 16px; }
    .file-row { display: flex; justify-content: space-between; align-items: center;
                border-bottom: 1px solid #eee; padding: 8px 0; }
  </style>
</head>
<body>
  <h2>StoreGit Demo</h2>

  <label>API Key <input id="key-input" type="password" placeholder="sgk_…" style="width:100%"></label>
  <button onclick="connect()">Connect</button>
  <hr>

  <input id="filename" placeholder="filename.txt" value="hello.txt">
  <textarea id="content" placeholder="File content…">Hello from my app!</textarea>
  <button onclick="saveFile()">Save</button>
  <button onclick="loadFiles()">Refresh list</button>

  <div id="file-list"></div>

<script>
const BASE = 'https://storegit.pages.dev'; // ← change to your StoreGit URL
let KEY = '';

function h(extra = {}) {
  return { 'X-API-Key': KEY, ...extra };
}

async function connect() {
  KEY = document.getElementById('key-input').value.trim();
  localStorage.setItem('demo_key', KEY);
  await loadFiles();
}

async function loadFiles() {
  const res  = await fetch(`${BASE}/api/files`, { headers: h() });
  const data = await res.json();
  const list = document.getElementById('file-list');

  if (!res.ok) { list.innerHTML = `<p style="color:red">Error: ${data.error}</p>`; return; }
  if (!data.length) { list.innerHTML = '<p>No files yet.</p>'; return; }

  list.innerHTML = data.map(f => `
    <div class="file-row">
      <span>${f.originalName ?? f.name} &nbsp;<small>${(f.size/1024).toFixed(1)} KB</small></span>
      <div>
        <button onclick="readFile('${f.name}')">Read</button>
        <button onclick="deleteFile('${f.name}','${f.sha}')">Delete</button>
      </div>
    </div>
  `).join('');
}

async function saveFile() {
  const name    = document.getElementById('filename').value.trim();
  const text    = document.getElementById('content').value;
  const content = btoa(unescape(encodeURIComponent(text)));

  const res = await fetch(`${BASE}/api/upload`, {
    method:  'POST',
    headers: h({ 'Content-Type': 'application/json' }),
    body:    JSON.stringify({ name, content })
  });
  const d = await res.json();
  alert(res.ok ? `Saved: ${d.name}` : `Error: ${d.error}`);
  if (res.ok) loadFiles();
}

async function readFile(name) {
  const text = await fetch(
    `${BASE}/api/download?name=${encodeURIComponent(name)}`,
    { headers: h() }
  ).then(r => r.text());
  document.getElementById('filename').value = name;
  document.getElementById('content').value  = text;
}

async function deleteFile(name, sha) {
  if (!confirm(`Delete "${name}"?`)) return;
  const res = await fetch(`${BASE}/api/delete`, {
    method:  'DELETE',
    headers: h({ 'Content-Type': 'application/json' }),
    body:    JSON.stringify({ name, sha })
  });
  const d = await res.json();
  alert(res.ok ? 'Deleted' : `Error: ${d.error}`);
  if (res.ok) loadFiles();
}

// Restore saved key on load
KEY = localStorage.getItem('demo_key') ?? '';
if (KEY) { document.getElementById('key-input').value = KEY; loadFiles(); }
</script>
</body>
</html>
```

---

### Step 7 — CORS and origin binding

Browsers send a preflight `OPTIONS` request before any cross-origin API call. StoreGit handles this automatically.

| Your key setup | Effect |
|---|---|
| `allowedOrigins: []` (empty) | Any browser origin is allowed — good for testing |
| `allowedOrigins: ["https://myapp.com"]` | Only `https://myapp.com` gets CORS headers; others get 403 |
| Server-to-server (no `Origin` header) | Always permitted — CORS does not apply |

When creating a key for production, always set `allowedOrigins` to your exact domain so the key cannot be used by other websites even if it leaks.

---

### Step 8 — Error handling reference

| HTTP status | Meaning | Fix |
|---|---|---|
| `401` | Missing or invalid API key | Check your `sgk_…` key |
| `403` | Origin blocked by `allowedOrigins` | Add your domain to the key's allowed origins |
| `404` | File not found | Check the filename (URL-encode spaces) |
| `429` | Rate limit hit (120 req/min per key) | Add a delay between requests |
| `502` | GitHub API error | Check your GitHub token has repo read/write access |

---

### Built with StoreGit

- [VaulTxt](https://vaultxt.pages.dev) — mobile-first note vault ([source](https://github.com/debguin/vaultxt))

Building something with StoreGit? Open a PR to add it to this list.

## Changelog

### v2.0.0

- **Hamburger drawer** — repository management and API key management moved to a slide-in panel; main canvas stays focused on files
- **All repos visible in files list** — files from all connected repositories are shown together in one unified list with a per-repo section header
- **All repos removable** — any repository can be removed (previously only secondary repos); the only guard is you must keep at least one
- **API key system** — generate, label, restrict to origins, and revoke keys in-app; 256-bit Base64URL format (`sgk_<43 chars>`), bias-free CSPRNG, SHA-256 hashed in KV (raw key never stored)
- **Global security middleware** — `functions/_middleware.js` enforces security headers, HTTPS redirect, bot-blocking, rate limiting, and path-traversal protection before any route handler runs
- **Short share links** — IDs are 3–5 chars from a 64-char alphabet using rejection sampling (no modulo bias); variable length tries shorter IDs first, falls back if collision found
- **Never-expire share links** — pass `ttl=0`; KV entry persists indefinitely, token payload carries `exp: 0`
- **Inline share-page previews** — images, video, audio, and code/text files render inline above the download button; code preview fetches up to 10 KB
- **Session JTI upgrade** — 24-byte Base64URL (192 bits) instead of 16-byte hex (128 bits)
- **`GET /api/files?repoIdx=n`** — fetch any repo's files without mutating session state; client loads all repos in parallel after login
- **Forms closed on load** — boot sequence explicitly closes all drawer forms; no flash of open state on hard refresh
- **"Default" label removed** — repos with no custom label display `owner/repo` directly throughout the UI

### v1.x

Initial release — upload, download, delete, chunked upload, multi-repo, share links.
