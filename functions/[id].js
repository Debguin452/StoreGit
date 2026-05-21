'use strict';
const ID_RE = /^[A-Za-z0-9_\-]{1,5}$/;
export async function onRequestGet({ env, params, request }) {
  const id = params.id;
  if (!id || !ID_RE.test(id)) {
    // Pass through to static assets (app.css, app.js, images, etc.)
    // instead of redirecting, so the browser can load them correctly.
    if (env.ASSETS) return env.ASSETS.fetch(request);
    return Response.redirect(new URL(request.url).origin + '/', 302);
  }
  const kv = env.RATE_LIMIT_KV ?? null;
  if (!kv) return page(errorHTML('unavailable'), 503);
  let entry;
  try {
    const raw = await kv.get('sl:' + id);
    if (!raw) return page(errorHTML('notfound'), 404);
    entry = JSON.parse(raw);
  } catch { return page(errorHTML('notfound'), 404); }
  if (!entry?.tok) return page(errorHTML('notfound'), 404);
  const { tok, displayName = 'file', size = 0, exp } = entry;
  if (exp !== null && exp !== undefined && Date.now() > new Date(exp).getTime()) {
    return page(errorHTML('expired'), 410);
  }
  const isDownload = new URL(request.url).searchParams.get('download') === '1';
  if (isDownload) return Response.redirect(new URL(request.url).origin + '/api/dl?tok=' + encodeURIComponent(tok) + '&download=1', 302);
  return page(shareHTML(tok, displayName, size, exp), 200);
}
function page(html, status) {
  return new Response(html, { status, headers: {
    'Content-Type': 'text/html;charset=utf-8',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'Cache-Control': 'no-store',
    'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src 'self' blob: data:; media-src 'self' blob: data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none';",
  }});
}
function fmtSize(b) {
  if (!b || b <= 0) return '';
  if (b < 1024) return b + ' B';
  if (b < 1048576) return (b / 1024).toFixed(1) + ' KB';
  if (b < 1073741824) return (b / 1048576).toFixed(1) + ' MB';
  return (b / 1073741824).toFixed(2) + ' GB';
}
function fmtExp(exp) {
  if (!exp) return 'Never expires';
  const diff = new Date(exp).getTime() - Date.now();
  if (diff <= 0) return 'Expired';
  const m = Math.floor(diff / 60000);
  if (m < 60) return `Expires in ${m} min`;
  const h = Math.floor(m / 60);
  if (h < 24) return `Expires in ${h} hr`;
  const d = Math.floor(h / 24);
  return `Expires in ${d} day${d !== 1 ? 's' : ''}`;
}
function extOf(name) { return (name.includes('.') ? name.split('.').pop() : '').toLowerCase(); }
function badgeColor(ext) {
  const MAP = {jpg:'#2563eb',jpeg:'#2563eb',png:'#2563eb',gif:'#2563eb',webp:'#2563eb',bmp:'#2563eb',avif:'#2563eb',tiff:'#2563eb',tif:'#2563eb',ico:'#2563eb',svg:'#2563eb',mp4:'#dc2626',webm:'#dc2626',mov:'#dc2626',m4v:'#dc2626',mp3:'#d97706',wav:'#d97706',ogg:'#d97706',m4a:'#d97706',flac:'#d97706',aac:'#d97706',js:'#16a34a',ts:'#16a34a',jsx:'#16a34a',tsx:'#16a34a',py:'#16a34a',rb:'#16a34a',go:'#16a34a',rs:'#16a34a',java:'#16a34a',c:'#16a34a',cpp:'#16a34a',h:'#16a34a',swift:'#16a34a',kt:'#16a34a',php:'#16a34a',sh:'#16a34a',bash:'#16a34a',json:'#0891b2',csv:'#0891b2',xml:'#0891b2',yaml:'#0891b2',yml:'#0891b2',sql:'#0891b2',pdf:'#2563eb',doc:'#2563eb',docx:'#2563eb',txt:'#2563eb',md:'#2563eb',zip:'#b45309',gz:'#b45309',rar:'#b45309'};
  return MAP[ext] || '#6b7280';
}
const IMGS  = new Set(['jpg','jpeg','png','gif','webp','bmp','avif','tiff','tif','ico']);
const AUDS  = new Set(['mp3','wav','ogg','m4a','flac','aac','opus']);
const VIDS  = new Set(['mp4','webm','mov','m4v']);
const TEXTS = new Set(['txt','md','markdown','csv','json','log','ini','cfg','conf','yaml','yml','toml','diff','patch','nfo','js','ts','jsx','tsx','py','rb','sh','bash','c','cpp','h','java','go','rs','swift','kt','php','css','html','htm','xml','sql','r','lua']);
const CSS = `
:root{--bg:#f5f7fc;--card:#fff;--border:#e8ecf5;--t1:#0d0f18;--t2:#6b7280;--t3:#94a3b8;--dl-bg:#1d4ed8;--dl-fg:#fff;--code-bg:#f8f9fd;--code-text:#1e293b;color-scheme:light}
@media(prefers-color-scheme:dark){:root{--bg:#0a0c12;--card:#111520;--border:#1c2235;--t1:#edf0f8;--t2:#6b7280;--t3:#374151;--dl-bg:#2563eb;--dl-fg:#fff;--code-bg:#0d1120;--code-text:#c8d0e8;color-scheme:dark}}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--t1);min-height:100vh;display:flex;flex-direction:column}
.topbar{height:54px;background:var(--card);border-bottom:1px solid var(--border);display:flex;align-items:center;padding:0 1.75rem;flex-shrink:0}
.brand{display:flex;align-items:center;gap:.55rem;font-weight:700;font-size:.95rem;color:var(--t1);text-decoration:none}
.brand-logo{width:20px;height:20px;border-radius:5px;background:#1d4ed8;display:flex;align-items:center;justify-content:center;flex-shrink:0}.brand-logo svg{display:block}
main{flex:1;display:flex;justify-content:center;padding:2.5rem 1.25rem 4rem}
.wrap{width:100%;display:flex;flex-direction:column;gap:1rem}
.pv-wrap{width:100%;border-radius:14px;overflow:hidden;border:1px solid var(--border);background:var(--card)}
.img-wrap{background:#000;display:flex;align-items:center;justify-content:center;min-height:180px}
.img-wrap img{max-width:100%;max-height:540px;object-fit:contain;display:block}
.aud-wrap{padding:1.25rem 1rem;display:flex;align-items:center;justify-content:center}.aud-wrap audio{width:100%;max-width:500px}
.vid-wrap video{width:100%;max-height:460px;display:block;background:#000}
.code-wrap{background:var(--code-bg)}
.code-loading{padding:1.75rem 1.5rem;display:flex;align-items:center;gap:.6rem;color:var(--t2);font-size:.85rem}
.code-pre{font-family:'SF Mono','Fira Mono','Cascadia Code',Consolas,monospace;font-size:.775rem;line-height:1.7;padding:1.25rem 1.5rem;overflow:auto;max-height:440px;white-space:pre;color:var(--code-text)}
.code-err{padding:1.5rem;color:var(--t3);font-size:.85rem}
.spin{width:15px;height:15px;border:2px solid var(--border);border-top-color:var(--dl-bg);border-radius:50%;animation:sp .7s linear infinite;flex-shrink:0}
@keyframes sp{to{transform:rotate(360deg)}}
.info-card{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:1.5rem 1.75rem}
.file-row{display:flex;align-items:center;gap:1rem;margin-bottom:1.35rem}
.badge{width:50px;height:50px;min-width:50px;border-radius:11px;display:flex;align-items:center;justify-content:center;font-size:.58rem;font-weight:800;letter-spacing:.06em;color:#fff}
.file-name{font-size:1.05rem;font-weight:600;color:var(--t1);word-break:break-all;line-height:1.4;margin-bottom:.3rem}
.file-meta{font-size:.8rem;color:var(--t2);display:flex;align-items:center;gap:.5rem;flex-wrap:wrap}
.never-badge{display:inline-flex;align-items:center;gap:.25rem;font-size:.7rem;font-weight:600;background:#eff4ff;color:#1d4ed8;border:1px solid #bfdbfe;border-radius:4px;padding:.15rem .5rem}
@media(prefers-color-scheme:dark){.never-badge{background:#162040;color:#60a5fa;border-color:#1c2a50}}
.dl-btn{display:flex;align-items:center;justify-content:center;gap:.5rem;width:100%;padding:.95rem 1.25rem;background:var(--dl-bg);color:var(--dl-fg);border:none;border-radius:10px;font-family:inherit;font-size:.95rem;font-weight:600;text-decoration:none;cursor:pointer;transition:opacity .15s}
.dl-btn:hover{opacity:.82}
.dl-btn:active{opacity:.65}
footer{text-align:center;font-size:.72rem;color:var(--t3);padding:.5rem 1.25rem 2rem}
@media(max-width:480px){main{padding:1.25rem .75rem 3rem}.info-card{padding:1.25rem}.topbar{padding:0 1.25rem}}`;
const ERR_CSS = `
:root{--bg:#eff6ff;--card:#fff;--border:#dbeafe;--t1:#111827;--t2:#6b7280;--t3:#9ca3af;--icon-bg:#eff6ff;color-scheme:light}
@media(prefers-color-scheme:dark){:root{--bg:#0d0f1a;--card:#131929;--border:#1e2e50;--t1:#f1f5f9;--t2:#94a3b8;--t3:#475569;--icon-bg:#1a2845;color-scheme:dark}}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--t1);min-height:100vh;display:flex;flex-direction:column}
.topbar{height:54px;background:var(--card);border-bottom:1px solid var(--border);display:flex;align-items:center;padding:0 1.75rem}
.brand{display:flex;align-items:center;gap:.55rem;font-weight:700;font-size:.95rem;color:var(--t1);text-decoration:none}
.brand-logo{width:20px;height:20px;border-radius:5px;background:#1d4ed8;display:flex;align-items:center;justify-content:center;flex-shrink:0}.brand-logo svg{display:block}
main{flex:1;display:flex;align-items:center;justify-content:center;padding:2rem 1.25rem}
.card{background:var(--card);border:1px solid var(--border);border-radius:16px;padding:2.75rem 2.25rem;width:100%;max-width:420px;text-align:center}
.err-icon{width:68px;height:68px;border-radius:18px;background:var(--icon-bg);display:flex;align-items:center;justify-content:center;margin:0 auto 1.5rem;border:1px solid var(--border)}
h1{font-size:1.2rem;font-weight:700;letter-spacing:-.01em;margin-bottom:.6rem}
p{font-size:.875rem;color:var(--t2);line-height:1.65;margin-bottom:2rem}
.home-btn{display:inline-flex;align-items:center;gap:.4rem;padding:.72rem 1.5rem;border:1px solid var(--border);border-radius:8px;font-family:inherit;font-size:.875rem;font-weight:500;color:var(--t1);text-decoration:none;transition:background .15s}
.home-btn:hover{background:var(--bg)}
footer{text-align:center;font-size:.72rem;color:var(--t3);padding:.5rem 1.25rem 2rem}`;
function shareHTML(tok, displayName, size, exp) {
  const ext   = extOf(displayName);
  const label = ext ? ext.slice(0, 5).toUpperCase() : 'FILE';
  const color = badgeColor(ext);
  const sz    = fmtSize(size);
  const expStr = fmtExp(exp);
  const isNever = !exp;
  const dlUrl = `/api/dl?tok=${encodeURIComponent(tok)}&download=1`;

  const safe  = displayName.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  const wide  = IMGS.has(ext) || AUDS.has(ext) || VIDS.has(ext) || TEXTS.has(ext);
  let preview = '';
  if (IMGS.has(ext)) {
    preview = `<div class="pv-wrap img-wrap"><img src="${dlUrl}" alt="${safe}" loading="lazy" onerror="this.closest('.pv-wrap').style.display='none'"></div>`;
  } else if (AUDS.has(ext)) {
    preview = `<div class="pv-wrap aud-wrap"><audio controls preload="metadata" src="${dlUrl}" onerror="this.closest('.pv-wrap').style.display='none'"></audio></div>`;
  } else if (VIDS.has(ext)) {
    preview = `<div class="pv-wrap vid-wrap"><video controls preload="metadata" src="${dlUrl}" onerror="this.closest('.pv-wrap').style.display='none'"></video></div>`;
  } else if (TEXTS.has(ext)) {
    preview = `<div class="pv-wrap code-wrap"><div class="code-loading" id="cl"><span class="spin"></span>Loading preview\u2026</div><pre id="cp" class="code-pre" style="display:none"></pre><div id="ce" class="code-err" style="display:none">Preview unavailable.</div></div><script>(function(){fetch(${JSON.stringify(dlUrl)}).then(function(r){if(!r.ok)throw 0;return r.text();}).then(function(t){document.getElementById('cp').textContent=t.length>10000?t.slice(0,10000)+'\n\n\u2026 (truncated)':t;document.getElementById('cl').style.display='none';document.getElementById('cp').style.display='';}).catch(function(){document.getElementById('cl').style.display='none';document.getElementById('ce').style.display='';});})();<\/script>`;
  }
  const metaParts = [sz ? `<span>${sz}</span>` : ''];
  if (isNever) {
    metaParts.push(`<span class="never-badge"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="11" height="11"><path d="M18 6 6 18M6 6l12 12"/></svg>Never expires</span>`);
  } else {
    metaParts.push(`<span>${expStr}</span>`);
  }
  return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${safe} \u2014 StoreGit</title><style>${CSS}</style></head><body><header class="topbar"><a href="/" class="brand"><span class="brand-logo"><svg viewBox="0 0 20 20" width="12" height="12"><path d="M4 10h12M10 4v12" stroke="#fff" stroke-width="2.5" stroke-linecap="round"/></svg></span>StoreGit</a></header><main><div class="wrap" style="max-width:${wide ? '700' : '420'}px">${preview}<div class="info-card"><div class="file-row"><div class="badge" style="background:${color}">${label}</div><div style="min-width:0;flex:1"><div class="file-name">${safe}</div><div class="file-meta">${metaParts.filter(Boolean).join('')}</div></div></div><a class="dl-btn" href="${dlUrl}"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" width="17" height="17"><path d="M12 5v14M5 12l7 7 7-7"/></svg>Download</a></div></div></main><footer>Shared via StoreGit</footer></body></html>`;
}
function errorHTML(reason) {
  const cfg = {
    expired:     { title: 'Link Expired',      h1: 'This link has expired',     p: 'The share link you followed has expired and is no longer available.' },
    notfound:    { title: 'Link Not Found',     h1: 'Link not found',            p: 'This share link does not exist or may have been mistyped.' },
    unavailable: { title: 'Unavailable',        h1: 'Service unavailable',       p: 'Short links are not configured on this server. Ask the sender for the full link.' },
  }[reason] || { title: 'Error', h1: 'Something went wrong', p: 'An unexpected error occurred.' };
  return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${cfg.title} \u2014 StoreGit</title><style>${ERR_CSS}</style></head><body><header class="topbar"><a href="/" class="brand"><span class="brand-logo"><svg viewBox="0 0 20 20" width="12" height="12"><path d="M4 10h12M10 4v12" stroke="#fff" stroke-width="2.5" stroke-linecap="round"/></svg></span>StoreGit</a></header><main><div class="card"><div class="err-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" width="30" height="30"><circle cx="12" cy="12" r="9"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg></div><h1>${cfg.h1}</h1><p>${cfg.p}</p><a href="/" class="home-btn">Go to StoreGit</a></div></main><footer>StoreGit</footer></body></html>`;
}
