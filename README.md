# StoreGit

A serverless file-storage service built on **Cloudflare Pages Functions** and the **GitHub Contents / Git Data APIs**. Each user is backed by their own GitHub repository. The operator deploys one Cloudflare Pages project; users bring their own GitHub repo and personal access token.

---

## Table of Contents

1. [Architecture](#architecture)
2. [Features](#features)
3. [Security Model](#security-model)
4. [API Key System](#api-key-system)
5. [REST API Reference](#rest-api-reference)
6. [Deployment](#deployment)
7. [KV Namespace Bindings](#kv-namespace-bindings)
8. [Environment Variables](#environment-variables)
9. [Development](#development)
10. [Using StoreGit from Another Project](#using-storegit-from-another-project)
11. [Changelog](#changelog)

---

## Architecture

```
Browser / External App
        │
        │  HTTPS  (X-API-Key header  OR  session cookie)
        ▼
Cloudflare Pages (CDN edge)
        │
        ├─ functions/_middleware.js   ← Security headers, rate-limit, bot-block
        ├─ functions/api/[[path]].js  ← All API routes
        └─ functions/[id].js          ← Short-link share resolver
        │
        │  GitHub REST API + Git Data API
        ▼
GitHub Repository (one per user — the actual file store)
```

File data never transits Cloudflare KV. KV holds only:

| KV key pattern | Value |
|---|---|
| `apikey:sha256:<hex>` | `{ username, label, allowedOrigins, keyId }` |
| `sess_cache:<jti>` | Cached session payload |
| `revoked:<jti>` | Revoked session marker |
| `rate:<scope>:<window>` | Rate-limit counters |
| `sl:<shortId>` | Share-link metadata |

---

## Features

- **File upload / download / delete** via GitHub Contents API (small files) and Git Data API (chunked, up to ~5 GB)
- **Multiple repositories** per account, with auto-routing to the repo with the least usage
- **Shareable links** with configurable expiry (1 hr → 7 days → never), shortened to 4–6 character Base64URL IDs
- **Hamburger drawer menu** — repositories and API key management in a slide-in panel
- **API keys** — generate keys in-app, bind to specific origins, revoke instantly
- **Security middleware** — CSP, HSTS, CORS, bot-blocking, rate-limiting on every edge request
- **Dark mode** — system preference via `prefers-color-scheme`
- **Offline-tolerant** — upload queue survives page refresh

---

## Security Model

### Global middleware (`functions/_middleware.js`)

Every request — HTML, API, static asset — passes through `_middleware.js` before anything else runs. It enforces:

| Check | Detail |
|---|---|
| **HTTPS redirect** | HTTP → HTTPS 301 in production |
| **Bad user-agent block** | sqlmap, nikto, nmap, masscan, dirbuster, nuclei, burpsuite, … |
| **Global rate limit** | 600 req/min per IP (in-process `Map` with 1-min sliding window) |
| **Method allowlist** | `GET POST DELETE OPTIONS HEAD` only — all others → 405 |
| **Path traversal** | Rejects `..`, null bytes, `%00` in path |
| **Scanner probe block** | `/wp-admin`, `/.env`, `/.git`, `/phpmyadmin`, `/xmlrpc`, … → 404 |
| **Body size cap** | 10 MB hard limit on non-API routes |
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
Content-Security-Policy: (HTML pages only — strict default-src 'none')
```

### Session security

- Sessions use HMAC-SHA-256 signed JWTs stored in `HttpOnly; Secure; SameSite=Strict` cookies
- JTI is **24 bytes of CSPRNG encoded as Base64URL** (192 bits — unguessable)
- Sessions refresh automatically when within 1 hour of expiry
- Revoked sessions are marked in KV and rejected immediately

### API key security

See [API Key System](#api-key-system) below.

---

## API Key System

### Key format

```
sgk_<43 Base64URL characters>
```

| Property | Value |
|---|---|
| Entropy | 32 bytes = **256 bits** of CSPRNG |
| Alphabet | Base64URL — `A-Z a-z 0-9 - _` (64 chars, 6 bits/char) |
| Encoding | RFC 4648 §5, bias-free (no modulo bias) |
| Total chars | `sgk_` + 43 = **47 characters** |
| Visual footprint | Smaller than hex (hex needs 68 chars for the same 256-bit key) |

**Why Base64URL over hex:**

```
hex   : 16 bytes → 32 chars → 4.0 bits/char  (128-bit key)
B64URL: 32 bytes → 43 chars → 5.95 bits/char (256-bit key, smaller string)
```

Same or smaller string, double the security margin.

### Bias-free random generation

Standard `byte % alphabetSize` has modulo bias when `alphabetSize` doesn't divide 256 evenly. StoreGit uses **rejection sampling**:

```js
// Bias-free Base64URL encoding — processes 3 bytes → 4 chars (exactly 6 bits/char)
function base64urlFromBytes(bytes) { … }

// Bias-free string from any alphabet using rejection sampling
function randomAlphabetString(alphabet, length) {
  const cutoff = 256 - (256 % alphabet.length); // reject bytes ≥ cutoff
  // sample until length chars collected
}

// 32 bytes (256 bits) → sgk_<43 B64URL chars>
function generateRawApiKey() {
  return `sgk_${base64urlFromBytes(crypto.getRandomValues(new Uint8Array(32)))}`;
}
```

### Storage design — hashed keys

Raw keys are **never stored anywhere**. Only their SHA-256 digest is used as the KV lookup key:

```
KV key: "apikey:sha256:<SHA-256(rawKey) as hex>"
KV val: { username, label, allowedOrigins, keyId }
```

If KV is fully compromised, the attacker gets usernames, labels, and allowed origins — but **cannot reconstruct any raw key** or impersonate a user.

The `encKey` field in the user record stores the raw key encrypted with AES-GCM (the same secret used for session tokens) so that revocation can clean up the KV entry.

### Origin binding (CORS restriction)

When creating an API key you may supply a list of allowed origins:

```json
{ "label": "My Blog", "allowedOrigins": ["https://myblog.com"] }
```

- If `allowedOrigins` is empty → any origin is permitted (useful for server-to-server calls)
- If non-empty → `Access-Control-Allow-Origin` is set to the request origin only if it appears in the list; otherwise the request is rejected with 403

### Rate limiting

- **Per-key**: 120 requests/minute (checked in KV via `apikey_rate:<kvKey>`)
- **Global**: 600 requests/minute per IP (in-process, via `_middleware.js`)

### Maximum keys

10 API keys per account. Revoke old keys to create new ones.

---

## REST API Reference

All API endpoints are under `/api/`. Session-based calls require the `credentials: 'same-origin'` cookie. API-key calls require the `X-API-Key` header.

### Authentication

#### `POST /api/login`
```json
{ "username": "…", "password": "…" }
```
Sets a session cookie. Returns `{ ok: true }`.

#### `POST /api/logout`
Clears the session cookie.

#### `GET /api/me`
Returns current user info:
```json
{
  "username": "alice",
  "display": "Alice",
  "repo": "alice/my-storage",
  "repoLabel": "Primary",
  "repos": [{ "label": "Primary", "ghOwner": "alice", "ghRepo": "my-storage" }],
  "activeRepoIdx": 0
}
```
Accessible with API key.

---

### Files

#### `GET /api/files`
List all files across all repos:
```json
[
  { "name": "report_2025.pdf", "originalName": "report 2025.pdf",
    "size": 204800, "sha": "abc…", "chunked": false, "uploadedAt": "2025-01-01T00:00:00.000Z" }
]
```

#### `POST /api/upload`
Upload a file (≤ 5 MB single call, > 5 MB use chunked upload):
```json
{ "name": "notes.txt", "content": "<base64>" }
```
Returns `{ ok: true, name: "notes.txt", size: 1234 }`.

#### `GET /api/download?name=<filename>`
Streams the file. For chunked files, streams all parts in order with integrity verification.

#### `DELETE /api/delete`
```json
{ "name": "notes.txt", "sha": "abc…", "chunked": false }
```

---

### Repositories

#### `GET /api/repos`
Returns all repos and active index.

#### `POST /api/add-repo`
```json
{ "label": "Backups", "ghOwner": "alice", "ghRepo": "backups", "ghBranch": "main", "folder": "uploads" }
```
Verifies the token has write access before adding.

#### `POST /api/remove-repo`
```json
{ "repoIdx": 1 }
```
The primary repo (index 0) cannot be removed.

---

### API Keys (session only)

#### `GET /api/apikeys/list`
```json
{ "keys": [{ "keyId": "…", "preview": "sgk_AAAA…", "label": "My Blog", "allowedOrigins": ["https://myblog.com"], "createdAt": "…" }] }
```

#### `POST /api/apikeys/create`
```json
{ "label": "My Blog", "allowedOrigins": ["https://myblog.com"] }
```
Returns:
```json
{ "ok": true, "rawKey": "sgk_…", "keyId": "…", "preview": "sgk_AAAA…", "label": "My Blog", "allowedOrigins": ["https://myblog.com"] }
```
> **The `rawKey` is shown only once and never stored. Copy it immediately.**

#### `DELETE /api/apikeys/revoke`
```json
{ "keyId": "…" }
```

---

### Share links

#### `GET /api/share-link?name=<file>&ttl=<seconds>`
Creates a signed share token and (if KV is available) a short link like `/aBcD`.
Returns `{ url: "/aBcD", exp: 1234567890 }`.

---

## Deployment

### 1. Fork / clone

```bash
git clone https://github.com/your-org/storegit
cd storegit
```

### 2. Create a Cloudflare Pages project

```bash
npx wrangler pages project create storegit
```

### 3. Create KV namespace

```bash
npx wrangler kv:namespace create RATE_LIMIT_KV
# copy the id into wrangler.toml / Pages dashboard bindings
```

### 4. Set environment variables (Pages dashboard → Settings → Variables)

| Variable | Description |
|---|---|
| `APP_SECRET` | 32+ char random secret for JWT and AES-GCM signing |
| `GITHUB_CLIENT_ID` | OAuth app client ID (optional — for GitHub OAuth login) |
| `GITHUB_CLIENT_SECRET` | OAuth app client secret (optional) |

### 5. Deploy

```bash
npx wrangler pages deploy . --project-name storegit
```

---

## KV Namespace Bindings

Bind a KV namespace named **`RATE_LIMIT_KV`** in your Pages project settings. This single namespace is used for:

- Session revocation
- Session caching
- API key storage (hashed)
- Rate-limit counters
- Share-link metadata

---

## Environment Variables

| Variable | Required | Notes |
|---|---|---|
| `APP_SECRET` | Yes | Min 32 chars. Used for HMAC-JWT, AES-GCM key derivation, blob tokens |
| `GITHUB_CLIENT_ID` | No | Only needed for GitHub OAuth login flow |
| `GITHUB_CLIENT_SECRET` | No | Only needed for GitHub OAuth login flow |
| `REGISTRY_OWNER` | Yes | GitHub owner of the user-registry repo |
| `REGISTRY_REPO` | Yes | GitHub repo name of the user registry |
| `REGISTRY_TOKEN` | Yes | GitHub PAT with repo write access to the registry |

---

## Development

```bash
npm install -g wrangler
wrangler pages dev . --kv RATE_LIMIT_KV
```

The dev server runs on `http://localhost:8788`.

---

## Using StoreGit from Another Project

### 1. Generate an API key

Open StoreGit → click the hamburger menu (top right) → **API Keys** → **New Key**.

Enter a label and optionally restrict to your app's origin (e.g. `https://myapp.com`). Copy the key — it is shown only once.

### 2. Use the API

```js
const BASE  = 'https://your-storegit.pages.dev';
const KEY   = 'sgk_…'; // your 47-char key

// List files
const files = await fetch(`${BASE}/api/files`, {
  headers: { 'X-API-Key': KEY }
}).then(r => r.json());

// Upload a file (≤ 5 MB)
const toBase64 = file => new Promise((res, rej) => {
  const r = new FileReader();
  r.onload = () => res(r.result.split(',')[1]);
  r.onerror = rej;
  r.readAsDataURL(file);
});

await fetch(`${BASE}/api/upload`, {
  method: 'POST',
  headers: { 'X-API-Key': KEY, 'Content-Type': 'application/json' },
  body: JSON.stringify({ name: file.name, content: await toBase64(file) })
});

// Download a file
const blob = await fetch(`${BASE}/api/download?name=notes.txt`, {
  headers: { 'X-API-Key': KEY }
}).then(r => r.blob());

// Delete a file
await fetch(`${BASE}/api/delete`, {
  method: 'DELETE',
  headers: { 'X-API-Key': KEY, 'Content-Type': 'application/json' },
  body: JSON.stringify({ name: 'notes.txt', sha: '<sha from /api/files>' })
});
```

### 3. Origin binding in practice

If you created the key with `allowedOrigins: ["https://myapp.com"]`:

- Requests from `https://myapp.com` → allowed, CORS headers returned
- Requests from any other origin → 403 Forbidden
- Server-to-server requests (no `Origin` header) → allowed regardless of binding

### 4. Key security best practices

- Treat your API key like a password — never commit it to source control
- Use `allowedOrigins` for browser-side keys to prevent misuse if the key leaks
- Keep server-side keys unrestricted (no origin binding needed — no CORS headers sent)
- Rotate keys periodically — revoke and regenerate in the StoreGit UI

---

## Changelog

### v2.0.0
- **Hamburger drawer** — repositories and API key management moved to a slide-in drawer, freeing the main canvas for files
- **API key system** — generate, label, bind to origins, and revoke keys in-app
- **256-bit Base64URL API keys** — `sgk_<43 chars>`, bias-free CSPRNG, SHA-256 hashed in KV (raw key never stored)
- **Global security middleware** — `functions/_middleware.js` enforces security headers, HTTPS redirect, bot-blocking, rate limiting, and path-traversal protection on every request
- **`POST /api/remove-repo`** — remove secondary repositories from the UI
- **Short-link bias fix** — share link IDs now use rejection-sampling via `randomAlphabetString`
- **Session JTI upgrade** — 24-byte Base64URL (192 bits) instead of 16-byte hex (128 bits)

### v1.x
- Initial release — upload, download, delete, chunked upload, share links, multi-repo support
