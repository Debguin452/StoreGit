'use strict';
let CHUNK_THRESHOLD  = 5  * 1024 * 1024;
let CHUNK_SIZE       = 10 * 1024 * 1024;
let MAX_FILE_SIZE    = 5  * 1024 * 1024 * 1024;
let UPLOAD_CONCURRENCY = 4;
let uploadPending    = [];
let _uploadActive    = false;
let _uploadPaused    = false;
let _uploadAbortFn   = null;
let _shareFile       = null;
let _allRepos        = [];
let _repoFiles       = [];
let _currentFileRepoIdx = 0;
let _editFile        = null;
let _editSha         = null;

const FD_EDITABLE = new Set(['txt','md','markdown','json','js','mjs','cjs','ts','tsx','jsx',
  'c','cpp','h','hpp','cs','java','go','rs','py','rb','php','sh','bash','zsh','lua','r','swift','kt',
  'css','html','htm','xml','yaml','yml','toml','ini','cfg','conf','log','csv','sql','diff','patch',
  'nfo','env','gitignore','dockerignore','makefile','dockerfile']);
const FD_IMG   = new Set(['png','jpg','jpeg','gif','webp','svg','bmp','ico','avif']);
const FD_AUDIO = new Set(['mp3','ogg','wav','flac','aac','m4a','opus']);
const FD_VIDEO = new Set(['mp4','webm','ogv','mov']);
const FD_TEXT  = new Set([...FD_EDITABLE]);
const ALLOWED_SCHEMES = new Set(['https:', 'http:']);
const _sliceCache = new WeakMap();

function precacheSlices(file) {
  if (file.size <= CHUNK_THRESHOLD || _sliceCache.has(file)) return;
  const totalChunks = Math.ceil(file.size / CHUNK_SIZE);
  _sliceCache.set(file, Array.from({ length: totalChunks }, (_, i) =>
    file.slice(i * CHUNK_SIZE, Math.min((i + 1) * CHUNK_SIZE, file.size))
  ));
}

(async () => {
  try {
    const r = await fetch('/api/status');
    const d = await r.json();
    if (d.uploadConcurrency > 0)  UPLOAD_CONCURRENCY = d.uploadConcurrency;
    if (d.distThresholdBytes > 0) CHUNK_THRESHOLD    = Math.round(d.distThresholdBytes * 3 / 4);
  } catch {}
  try {
    const r = await fetch('/api/me', { credentials: 'same-origin' });
    if (r.ok) { await bootApp(await r.json()); return; }
  } catch {}
  window.location.replace('/');
})();

async function bootApp(me) {
  fetch('/api/apikeys/migrate', { method: 'POST', credentials: 'same-origin' }).catch(() => {});
  await loadMeta();
  loadFiles();
}

function on(id, evt, fn) {
  document.getElementById(id)?.addEventListener(evt, fn);
}
function elem(tag, cls) {
  const el = document.createElement(tag);
  if (cls) el.className = cls;
  return el;
}
function toast(msg, type) {
  const el = document.getElementById('toast');
  el.textContent = String(msg).slice(0, 120);
  el.className   = `toast show${type ? ' ' + type : ''}`;
  clearTimeout(el._t);
  el._t = setTimeout(() => { el.className = 'toast'; }, 3500);
}
function showModal(title, msg, confirmLabel, confirmClass, onConfirm) {
  document.getElementById('modal-title').textContent   = title;
  document.getElementById('modal-msg').textContent     = msg;
  const overlay    = document.getElementById('modal-overlay');
  const confirmBtn = document.getElementById('modal-confirm-btn');
  confirmBtn.textContent = confirmLabel;
  confirmBtn.className   = 'btn ' + confirmClass;
  overlay.classList.add('open');
  const close = () => overlay.classList.remove('open');
  confirmBtn.onclick = () => { close(); onConfirm(); };
  document.getElementById('modal-cancel-btn').onclick = close;
  overlay.onclick = e => { if (e.target === overlay) close(); };
}

on('signout-btn',        'click',  () => doLogout());
on('file-input',         'change', e  => onFilePicked(e.target.files));
on('upload-btn',         'click',  () => startUpload());
on('clear-queue-btn',    'click',  () => clearQueue());
on('refresh-files-btn',  'click',  () => loadFiles());
on('pause-btn',          'click',  () => togglePause());
on('fd-overlay',         'click',  e  => { if (e.target === e.currentTarget) closeFileDetail(); });
on('fd-close-btn',       'click',  () => closeFileDetail());
on('fd-share-btn',       'click',  () => _shareFile && openShareModal(_shareFile));
on('fd-edit-btn',        'click',  () => _shareFile && openEditSheet(_shareFile));
on('edit-close-btn',     'click',  () => closeEditSheet());
on('edit-save-btn',      'click',  () => saveEditSheet());
on('share-close-btn',    'click',  () => closeShareModal());
on('share-create-btn',   'click',  () => createShareLink());
on('share-copy-btn',     'click',  () => copyShareLink());
on('modal-cancel-btn',   'click',  () => document.getElementById('modal-overlay')?.classList.remove('open'));
on('hamburger-btn',      'click',  () => openDrawer());
on('drawer-close-btn',   'click',  () => closeDrawer());
on('drawer-overlay',     'click',  () => closeDrawer());
on('drawer-add-repo-btn','click',  () => toggleDrawerAddRepoForm());
on('dar-cancel-btn',     'click',  () => closeDrawerAddRepoForm());
on('dar-submit-btn',     'click',  () => submitDrawerAddRepo());
on('apikey-new-btn',     'click',  () => toggleApiKeyForm());
on('ak-cancel-btn',      'click',  () => closeApiKeyForm());
on('ak-submit-btn',      'click',  () => submitApiKey());
on('apikey-copy-btn',    'click',  () => {
  const code = document.getElementById('apikey-reveal-code');
  if (code) navigator.clipboard?.writeText(code.textContent).then(() => toast('API key copied.', 'ok')).catch(() => {});
});
on('ak-restrict-toggle', 'change', e  => {
  const wrap = document.getElementById('ak-origins-wrap');
  if (wrap) wrap.style.display = e.target.checked ? '' : 'none';
});
document.addEventListener('paste', e => {
  const files = [];
  for (const item of e.clipboardData?.items || [])
    if (item.kind === 'file') { const f = item.getAsFile(); if (f) files.push(f); }
  if (files.length) onFilePicked(files);
});
document.getElementById('share-ttl-opts')?.addEventListener('click', e => {
  const btn = e.target.closest('.ttl-opt');
  if (!btn) return;
  document.querySelectorAll('.ttl-opt').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
});

const dropZone = document.getElementById('drop-zone');
if (dropZone) {
  dropZone.addEventListener('click', () => document.getElementById('file-input')?.click());
  dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('drag-over'); });
  dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag-over'));
  dropZone.addEventListener('drop', e => {
    e.preventDefault(); dropZone.classList.remove('drag-over');
    if (e.dataTransfer?.files?.length) onFilePicked(e.dataTransfer.files);
  });
}

async function doLogout() {
  showModal('Sign out', 'You will be signed out of StoreGit.', 'Sign Out', 'btn-ghost', async () => {
    try { await fetch('/api/logout', { method: 'POST', credentials: 'same-origin' }); } catch {}
    uploadPending = []; clearQueue();
    window.location.replace('/');
  });
}

function unauth() { window.location.replace('/'); }

async function loadMeta() {
  try {
    const r = await fetch('/api/me', { credentials: 'same-origin' });
    if (r.status === 401) { unauth(); return; }
    if (r.ok) {
      const d = await r.json();
      updateRepoChip(d.repos || []);
    }
  } catch {}
}

function updateRepoChip(repos) {
  _allRepos = repos || [];
  renderDrawerRepoList();
}

function openDrawer() {
  document.getElementById('drawer').classList.add('is-open');
  document.getElementById('drawer-overlay').classList.add('is-open');
  document.getElementById('hamburger-btn').classList.add('is-open');
  document.body.style.overflow = 'hidden';
  loadApiKeys();
}
function closeDrawer() {
  document.getElementById('drawer').classList.remove('is-open');
  document.getElementById('drawer-overlay').classList.remove('is-open');
  document.getElementById('hamburger-btn').classList.remove('is-open');
  document.body.style.overflow = '';
  closeDrawerAddRepoForm();
  closeApiKeyForm();
  hideApiKeyReveal();
}

function renderDrawerRepoList() {
  const list = document.getElementById('drawer-repo-list');
  if (!list) return;
  list.innerHTML = '';
  if (!_allRepos.length) {
    const e = elem('div', 'apikey-empty'); e.textContent = 'No repositories connected.'; list.appendChild(e); return;
  }
  _allRepos.forEach((repo, i) => {
    const item  = elem('div', 'drawer-repo-item');
    const label = elem('div', 'drawer-repo-item-label');
    const customLabel = repo.label && repo.label !== 'Default' ? repo.label : null;
    label.textContent = customLabel || `${repo.ghOwner}/${repo.ghRepo}`;
    const slug  = elem('div', 'drawer-repo-item-slug');
    slug.textContent = customLabel ? `${repo.ghOwner}/${repo.ghRepo}` : '';
    item.append(label, slug);
    if (i > 0) {
      const rmBtn = elem('button', 'drawer-repo-remove-btn');
      rmBtn.title = 'Remove repository';
      rmBtn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>';
      rmBtn.onclick = e => {
        e.stopPropagation();
        showModal(`Remove "${repo.label || `Repo ${i + 1}`}"`,
          'Files stay on GitHub — only the connection is removed from StoreGit.',
          'Remove', 'btn-danger',
          async () => {
            try {
              const r = await fetch('/api/remove-repo', { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ repoIdx: i }) });
              if (r.ok) { toast('Repository removed.', 'ok'); await loadMeta(); loadFiles(); }
              else toast('Failed to remove.', 'error');
            } catch { toast('Connection error.', 'error'); }
          });
      };
      item.appendChild(rmBtn);
    }
    list.appendChild(item);
  });
}

function toggleDrawerAddRepoForm() {
  const form = document.getElementById('drawer-add-repo-form');
  const btn = document.getElementById('drawer-add-repo-btn');
  if (!form || !btn) return;
  if (getComputedStyle(form).display === 'none') {
    form.style.display = 'flex';
    btn.textContent = 'Cancel';
    document.getElementById('dar-owner')?.focus();
  } else {
    closeDrawerAddRepoForm();
  }
}
function closeDrawerAddRepoForm() {
  const form = document.getElementById('drawer-add-repo-form');
  const btn  = document.getElementById('drawer-add-repo-btn');
  if (form) form.style.display = 'none';
  if (btn)  btn.textContent = 'Add';
  const err = document.getElementById('dar-error');
  if (err) err.textContent = '';
  ['dar-label','dar-owner','dar-repo'].forEach(id => { const el = document.getElementById(id); if (el) el.value = ''; });
  const b = document.getElementById('dar-branch'); if (b) b.value = 'main';
}
async function submitDrawerAddRepo() {
  const label  = document.getElementById('dar-label')?.value.trim() || '';
  const owner  = document.getElementById('dar-owner')?.value.trim() || '';
  const repo   = document.getElementById('dar-repo')?.value.trim() || '';
  const branch = document.getElementById('dar-branch')?.value.trim() || 'main';
  const errEl  = document.getElementById('dar-error');
  const btn    = document.getElementById('dar-submit-btn');
  errEl.textContent = '';
  if (!owner || !repo) { errEl.textContent = 'GitHub owner and repository name are required.'; return; }
  btn.disabled = true; btn.innerHTML = '<span class="spinner"></span>';
  try {
    const r = await fetch('/api/add-repo', { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ label: label || 'Repo', ghOwner: owner, ghRepo: repo, ghBranch: branch, folder: 'uploads' }) });
    const d = await r.json();
    if (r.ok) { toast('Repository added.', 'ok'); closeDrawerAddRepoForm(); await loadMeta(); loadFiles(); }
    else errEl.textContent = d.error || 'Failed to add repository.';
  } catch { errEl.textContent = 'Connection error. Please try again.'; }
  btn.disabled = false; btn.textContent = 'Add Repository';
}

async function loadApiKeys() {
  const list = document.getElementById('apikey-list');
  if (!list) return;
  list.innerHTML = '<div class="apikey-empty">Loading…</div>';
  try {
    const r = await fetch('/api/apikeys/list', { credentials: 'same-origin' });
    if (r.status === 401) { unauth(); return; }
    if (!r.ok) { list.innerHTML = '<div class="apikey-empty">Could not load keys.</div>'; return; }
    renderApiKeys(await r.json());
  } catch { list.innerHTML = '<div class="apikey-empty">Connection error.</div>'; }
}
function renderApiKeys({ keys }) {
  const list = document.getElementById('apikey-list');
  if (!list) return;
  list.innerHTML = '';
  if (!keys?.length) {
    const e = elem('div', 'apikey-empty'); e.textContent = 'No API keys yet.'; list.appendChild(e); return;
  }
  keys.forEach(k => {
    const item    = elem('div', 'apikey-item');
    const top     = elem('div', 'apikey-item-top');
    const lbl     = elem('div', 'apikey-item-label'); lbl.textContent = k.label;
    const revokeBtn = elem('button', 'apikey-revoke-btn'); revokeBtn.textContent = 'Revoke';
    revokeBtn.onclick = () => showModal(`Revoke "${k.label}"`, 'This key will stop working immediately.', 'Revoke', 'btn-danger', async () => {
      try {
        const r = await fetch('/api/apikeys/revoke', { method: 'DELETE', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ keyId: k.keyId }) });
        if (r.ok) { toast('API key revoked.', 'ok'); loadApiKeys(); }
        else toast('Failed to revoke.', 'error');
      } catch { toast('Connection error.', 'error'); }
    });
    top.append(lbl, revokeBtn);
    const preview = elem('div', 'apikey-item-preview'); preview.textContent = k.preview;
    const origins = elem('div', 'apikey-item-origins');
    origins.textContent = k.allowedOrigins?.length ? `Restricted to: ${k.allowedOrigins.join(', ')}` : 'Works from any origin';
    item.append(top, preview, origins);
    list.appendChild(item);
  });
}
function toggleApiKeyForm() {
  const form = document.getElementById('apikey-form');
  const btn  = document.getElementById('apikey-new-btn');
  if (!form || !btn) return;
  hideApiKeyReveal();
  if (getComputedStyle(form).display === 'none') {
    form.style.display = 'flex'; // or '' if CSS defines display
    btn.textContent = 'Cancel';
    document.getElementById('ak-label')?.focus();
  } else {
    closeApiKeyForm();}
}
function closeApiKeyForm() {
  const form = document.getElementById('apikey-form');
  const btn  = document.getElementById('apikey-new-btn');
  if (form) form.style.display = 'none';
  if (btn)  btn.textContent = 'New Key';
  const err = document.getElementById('ak-error'); if (err) err.textContent = '';
  const lbl = document.getElementById('ak-label'); if (lbl) lbl.value = '';
  const tog = document.getElementById('ak-restrict-toggle'); if (tog) tog.checked = false;
  const wrap = document.getElementById('ak-origins-wrap'); if (wrap) wrap.style.display = 'none';
  const orig = document.getElementById('ak-origins'); if (orig) orig.value = '';
}
function hideApiKeyReveal() {
  const box = document.getElementById('apikey-reveal'); if (box) box.style.display = 'none';
}
async function submitApiKey() {
  const label    = document.getElementById('ak-label')?.value.trim() || '';
  const restrict = document.getElementById('ak-restrict-toggle')?.checked || false;
  const originsRaw = restrict ? (document.getElementById('ak-origins')?.value || '') : '';
  const allowedOrigins = originsRaw.split('\n').map(s => s.trim()).filter(s => {
    try { const u = new URL(s); return ALLOWED_SCHEMES.has(u.protocol); } catch { return false; }
  });
  const errEl = document.getElementById('ak-error');
  const btn   = document.getElementById('ak-submit-btn');
  errEl.textContent = '';
  if (!label) { errEl.textContent = 'Please enter a label for this key.'; return; }
  if (restrict && originsRaw.trim() && !allowedOrigins.length) {
    errEl.textContent = 'Enter valid origins (e.g. https://myapp.com) or disable restriction.'; return;
  }
  btn.disabled = true; btn.innerHTML = '<span class="spinner"></span>';
  try {
    const r = await fetch('/api/apikeys/create', { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ label, allowedOrigins }) });
    const d = await r.json();
    if (r.ok) {
      closeApiKeyForm();
      const box = document.getElementById('apikey-reveal');
      const code = document.getElementById('apikey-reveal-code');
      if (box && code) { code.textContent = d.rawKey; box.style.display = 'block'; }
      toast('API key created. Copy it now — it will not be shown again!', 'ok');
      loadApiKeys();
    } else errEl.textContent = d.error || 'Failed to create API key.';
  } catch { errEl.textContent = 'Connection error. Please try again.'; }
  btn.disabled = false; btn.textContent = 'Generate Key';
}

async function ensureRepoActive(repoIdx) { return repoIdx; }
function getSmartRepoIdx() {
  if (_allRepos.length <= 1 || _repoFiles.length === 0) return 0;
  let minSize = Infinity, minIdx = 0;
  for (const group of _repoFiles) {
    const total = (group.files || []).filter(f => f.name !== '.storegit').reduce((s, f) => s + (f.size || 0), 0);
    if (total < minSize) { minSize = total; minIdx = group.repoIdx; }
  }
  return minIdx;
}

function fileExtRaw(name) { return (name.includes('.') ? name.split('.').pop() : '').toLowerCase(); }
function fileExt(name)    { const e = fileExtRaw(name); return e ? e.toUpperCase() : 'FILE'; }
function fmtSize(b) {
  if (!b) return '0 B';
  const u = ['B','KB','MB','GB','TB'], i = Math.floor(Math.log(b) / Math.log(1024));
  return (b / Math.pow(1024, i)).toFixed(i === 0 ? 0 : 1) + ' ' + u[i];
}
function fileColor(ext) {
  const map = {
    pdf:'#e74c3c', doc:'#2980b9', docx:'#2980b9', xls:'#27ae60', xlsx:'#27ae60',
    ppt:'#e67e22', pptx:'#e67e22', zip:'#8e44ad', rar:'#8e44ad', '7z':'#8e44ad',
    tar:'#8e44ad', gz:'#8e44ad', jpg:'#e91e63', jpeg:'#e91e63', png:'#9c27b0',
    gif:'#ff5722', webp:'#9c27b0', svg:'#ff9800', mp4:'#3f51b5', mp3:'#009688',
    wav:'#009688', mov:'#3f51b5', txt:'#607d8b', md:'#607d8b', json:'#ff9800',
    js:'#f7df1e', ts:'#3178c6', py:'#3776ab', html:'#e34c26', css:'#1572b6',
    sh:'#4eaa25', go:'#00add8', rs:'#f74c00', java:'#b07219', rb:'#cc342d',
  };
  return map[ext] || '#64748b';
}

function buildFileRow(f) {
  const row   = elem('div', 'file-row');
  const badge = elem('div', 'file-type-badge');
  const displayName = f.originalName || f.name;
  badge.textContent       = fileExt(displayName);
  badge.style.background  = fileColor(fileExtRaw(displayName));
  badge.style.color       = '#fff';
  const info = elem('div', 'file-info');
  const nm   = elem('div', 'file-name'); nm.textContent = displayName; nm.title = displayName;
  const mt   = elem('div', 'file-meta'); mt.textContent = fmtSize(f.size);
  info.append(nm, mt);
  row.append(badge, info);
  row.addEventListener('click', () => openFileDetail(f));
  return row;
}

async function loadFiles() {
  const el = document.getElementById('file-list');
  el.innerHTML = '<div class="loading-row"><span class="spinner"></span> Loading files…</div>';
  try {
    if (_allRepos.length <= 1) {
      const r = await fetch('/api/files', { credentials: 'same-origin' });
      if (r.status === 401) { unauth(); return; }
      if (!r.ok) throw new Error();
      const files = await r.json();
      _repoFiles = [{ repo: _allRepos[0] || null, repoIdx: 0, files }];
    } else {
      const results = await Promise.allSettled(
        _allRepos.map((repo, i) =>
          fetch(`/api/files?repoIdx=${i}`, { credentials: 'same-origin' })
            .then(r => { if (r.status === 401) { unauth(); throw new Error(); } return r.json(); })
            .then(files => ({ repo, repoIdx: i, files }))
        )
      );
      _repoFiles = results.filter(r => r.status === 'fulfilled').map(r => r.value);
    }
    renderFiles();
  } catch { el.innerHTML = '<div class="empty-state">Could not load files.</div>'; }
}

function renderFiles() {
  const el = document.getElementById('file-list');
  el.innerHTML = '';
  const allFiles = _repoFiles.flatMap(g =>
    (g.files || [])
      .filter(f => f.name !== '.storegit' && !f.name.startsWith('.sgkeys/'))
      .map(f => ({ ...f, _repoIdx: g.repoIdx }))
  );
  if (!allFiles.length) {
    const e = elem('div', 'empty-state'); e.textContent = 'No files uploaded yet.'; el.appendChild(e); return;
  }
  allFiles.sort((a, b) => {
    const at = a.uploadedAt || a.name, bt = b.uploadedAt || b.name;
    return at < bt ? 1 : at > bt ? -1 : 0;
  });
  allFiles.forEach(f => el.appendChild(buildFileRow(f)));
}

function onFilePicked(files) {
  const arr = Array.from(files);
  const skipped = arr.filter(f => f.size > MAX_FILE_SIZE);
  const valid   = arr.filter(f => f.size <= MAX_FILE_SIZE);
  skipped.forEach(f => toast(`${f.name} is too large (max ${fmtSize(MAX_FILE_SIZE)}).`, 'error'));
  valid.forEach(f => {
    if (uploadPending.some(p => p.file.name === f.name && p.file.size === f.size)) return;
    uploadPending.push({ file: f, status: 'queued', progress: 0, id: Math.random().toString(36).slice(2) });
    precacheSlices(f);
  });
  renderQueue();
  const actions = document.getElementById('upload-actions');
  if (actions) actions.style.display = uploadPending.length ? '' : 'none';
}

function renderQueue() {
  const q = document.getElementById('upload-queue');
  q.innerHTML = '';
  uploadPending.forEach(item => {
    const row   = elem('div', 'upload-queue-row');
    const badge = elem('div', 'file-type-badge');
    badge.textContent      = fileExt(item.file.name);
    badge.style.background = fileColor(fileExtRaw(item.file.name));
    badge.style.color      = '#fff';
    const info = elem('div', 'upload-queue-info');
    const nm   = elem('div', 'upload-queue-name'); nm.textContent = item.file.name;
    const mt   = elem('div', 'upload-queue-meta'); mt.textContent = fmtSize(item.file.size);
    info.append(nm, mt);
    const progress = elem('div', 'upload-progress');
    const bar = elem('div', 'upload-progress-bar');
    if (item.status === 'uploading') { bar.style.width = item.progress + '%'; }
    else if (item.status === 'done') { bar.style.width = '100%'; bar.classList.add('done'); }
    else if (item.status === 'error') { bar.classList.add('error'); }
    progress.appendChild(bar);
    row.append(badge, info, progress);
    q.appendChild(row);
  });
}

function clearQueue() {
  if (_uploadActive) return;
  uploadPending = [];
  renderQueue();
  document.getElementById('upload-actions').style.display = 'none';
}

function togglePause() {
  if (!_uploadActive) return;
  _uploadPaused = !_uploadPaused;
  const btn = document.getElementById('pause-btn');
  if (btn) btn.textContent = _uploadPaused ? 'Resume' : 'Pause';
}

async function startUpload() {
  if (_uploadActive || !uploadPending.length) return;
  _uploadActive = true;
  const uploadBtn = document.getElementById('upload-btn');
  const pauseBtn  = document.getElementById('pause-btn');
  if (uploadBtn) uploadBtn.disabled = true;
  if (pauseBtn)  pauseBtn.style.display = '';
  const items = uploadPending.filter(i => i.status === 'queued');
  for (const item of items) {
    while (_uploadPaused) await new Promise(r => setTimeout(r, 200));
    item.status = 'uploading'; renderQueue();
    try {
      const repoIdx = getSmartRepoIdx();
      await ensureRepoActive(repoIdx);
      if (item.file.size <= CHUNK_THRESHOLD) await uploadSmall(item, repoIdx);
      else await uploadChunked(item, repoIdx);
      item.status = 'done'; item.progress = 100;
    } catch { item.status = 'error'; toast(`Failed to upload ${item.file.name}.`, 'error'); }
    renderQueue();
  }
  _uploadActive = false; _uploadPaused = false;
  if (uploadBtn) uploadBtn.disabled = false;
  if (pauseBtn)  pauseBtn.style.display = 'none';
  uploadPending = uploadPending.filter(i => i.status !== 'done');
  renderQueue();
  if (!uploadPending.length) document.getElementById('upload-actions').style.display = 'none';
  loadFiles();
}

async function uploadSmall(item, repoIdx) {
  const b64 = await readAsBase64(item.file);
  item.progress = 50; renderQueue();
  const r = await fetch('/api/upload', {
    method: 'POST', credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: item.file.name, content: b64, size: item.file.size, repoIdx }),
  });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error || 'upload failed');
}

async function uploadChunked(item, repoIdx) {
  const file   = item.file;
  const slices = _sliceCache.get(file) || Array.from({ length: Math.ceil(file.size / CHUNK_SIZE) }, (_, i) => file.slice(i * CHUNK_SIZE, Math.min((i + 1) * CHUNK_SIZE, file.size)));
  const total  = slices.length;
  let uploaded = 0;
  const sem    = { n: UPLOAD_CONCURRENCY };
  const errs   = [];
  await Promise.all(slices.map((slice, idx) => (async () => {
    while (sem.n <= 0) await new Promise(r => setTimeout(r, 50));
    sem.n--;
    try {
      const b64 = await readAsBase64(slice);
      const r = await fetch('/api/upload-chunk', {
        method: 'POST', credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: file.name, chunkIndex: idx, totalChunks: total, content: b64, size: file.size, repoIdx }),
      });
      if (!r.ok) { const d = await r.json().catch(() => ({})); errs.push(d.error || 'chunk failed'); }
      else { uploaded++; item.progress = Math.round(uploaded / total * 90); renderQueue(); }
    } catch (e) { errs.push(e.message); }
    sem.n++;
  })()));
  if (errs.length) throw new Error(errs[0]);
  item.progress = 92; renderQueue();
  const fr = await fetch('/api/finalize-upload', {
    method: 'POST', credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: file.name, totalChunks: total, size: file.size, repoIdx }),
  });
  if (!fr.ok) throw new Error((await fr.json().catch(() => ({}))).error || 'finalize failed');
}

function readAsBase64(blob) {
  return new Promise((res, rej) => {
    const reader = new FileReader();
    reader.onload  = e => res(e.target.result.split(',')[1]);
    reader.onerror = () => rej(new Error('Read failed'));
    reader.readAsDataURL(blob);
  });
}

function openFileDetail(f) {
  _shareFile = f;
  _currentFileRepoIdx = f._repoIdx !== undefined ? f._repoIdx : 0;
  const displayName = f.originalName || f.name;
  const ext = fileExtRaw(displayName);
  const iconEl = document.getElementById('fd-icon');
  iconEl.textContent      = fileExt(displayName);
  iconEl.style.background = fileColor(ext);
  iconEl.style.color      = '#fff';
  document.getElementById('fd-name').textContent = displayName;
  document.getElementById('fd-meta').textContent = fmtSize(f.size);
  document.getElementById('fd-dl-btn').onclick = async () => {
    await ensureRepoActive(_currentFileRepoIdx);
    downloadFile(f.name, f.size, displayName, _currentFileRepoIdx);
  };
  document.getElementById('fd-del-btn').onclick = async () => {
    await ensureRepoActive(_currentFileRepoIdx);
    closeFileDetail();
    setTimeout(() => deleteFile(f.name, f.sha, f.chunked || false, displayName, _currentFileRepoIdx), 250);
  };
  const editBtn = document.getElementById('fd-edit-btn');
  if (editBtn) {
    const canEdit = FD_EDITABLE.has(ext) && !f.chunked && (f.size || 0) <= 1_000_000;
    editBtn.style.display = canEdit ? '' : 'none';
    editBtn.onclick = canEdit ? () => openEditSheet(f) : null;
  }
  document.getElementById('fd-preview').innerHTML =
    '<div class="fd-preview-loading"><span class="spinner"></span> Loading preview…</div>';
  document.getElementById('fd-overlay').classList.add('open');
  ensureRepoActive(_currentFileRepoIdx).then(() => loadFilePreview(f));
}
function closeFileDetail() {
  document.getElementById('fd-overlay').classList.remove('open');
}

async function loadFilePreview(f) {
  const el  = document.getElementById('fd-preview');
  const ext = fileExtRaw(f.originalName || f.name);
  const noPreview = msg => { const p = elem('div', 'fd-preview-empty'); p.textContent = msg; el.replaceChildren(p); };

  if (!f.chunked) {
    const r = await fetch(`/api/download?name=${encodeURIComponent(f.name)}&inline=1&repoIdx=${_currentFileRepoIdx}`, { credentials: 'same-origin' });
    if (!r.ok) { noPreview('Preview unavailable.'); return; }
    const d = await r.json();
    const inlineUrl = d.url;

    if (FD_IMG.has(ext)) {
      if (f.size > 20 * 1024 * 1024) { noPreview('Image too large to preview. Download to view.'); return; }
      const img = elem('img', 'fd-preview-img');
      img.alt    = f.name;
      img.onerror = () => noPreview('Could not load image preview.');
      el.replaceChildren(img);
      img.src = inlineUrl;
      return;
    }
    if (FD_AUDIO.has(ext)) {
      const tapBtn = elem('button', 'btn btn-outline fd-tap-load');
      tapBtn.textContent = 'Tap to load audio';
      tapBtn.onclick = () => {
        const aud = elem('audio', 'fd-preview-audio');
        aud.controls = true; aud.preload = 'metadata';
        aud.onerror = () => noPreview('Could not load audio preview.');
        el.replaceChildren(aud); aud.src = inlineUrl;
      };
      el.replaceChildren(tapBtn); return;
    }
    if (FD_VIDEO.has(ext)) {
      const tapBtn = elem('button', 'btn btn-outline fd-tap-load');
      tapBtn.textContent = 'Tap to load video';
      tapBtn.onclick = () => {
        const vid = elem('video', 'fd-preview-video');
        vid.controls = true; vid.preload = 'metadata';
        vid.onerror = () => noPreview('Could not load video preview.');
        el.replaceChildren(vid); vid.src = inlineUrl;
      };
      el.replaceChildren(tapBtn); return;
    }
    if (FD_TEXT.has(ext) && f.size <= 200_000) {
      try {
        const res = await fetch(inlineUrl);
        const text = await res.text();
        const pre  = elem('pre', 'fd-preview-text');
        pre.textContent = text.length > 6000 ? text.slice(0, 6000) + '\n\n… (truncated)' : text;
        el.replaceChildren(pre); return;
      } catch { noPreview('Could not load text preview.'); return; }
    }
  }
  noPreview('No preview available. Download to open this file.');
}

async function downloadFile(name, size, displayName, repoIdx) {
  const bar     = document.getElementById('dl-bar');
  const fill    = document.getElementById('dl-fill');
  const label   = document.getElementById('dl-label');
  const fnEl    = document.getElementById('dl-filename');
  fnEl.textContent   = displayName;
  fill.style.width   = '0%';
  label.textContent  = 'Preparing download…';
  bar.classList.add('active');
  try {
    const r = await fetch(`/api/download?name=${encodeURIComponent(name)}&repoIdx=${repoIdx}`, { credentials: 'same-origin' });
    if (r.status === 401) { unauth(); return; }
    if (!r.ok) { toast('Download failed.', 'error'); return; }
    const d = await r.json();
    if (d.chunked) {
      const chunks = [];
      for (let i = 0; i < d.totalChunks; i++) {
        fill.style.width  = Math.round(i / d.totalChunks * 90) + '%';
        label.textContent = `Downloading part ${i + 1} of ${d.totalChunks}…`;
        const cr = await fetch(d.chunkUrls[i]);
        if (!cr.ok) throw new Error('chunk failed');
        chunks.push(await cr.arrayBuffer());
      }
      fill.style.width = '100%'; label.textContent = 'Assembling file…';
      const blob = new Blob(chunks);
      triggerDownload(URL.createObjectURL(blob), displayName);
    } else {
      fill.style.width = '80%'; label.textContent = 'Downloading…';
      const fr = await fetch(d.url);
      const blob = new Blob([await fr.arrayBuffer()]);
      triggerDownload(URL.createObjectURL(blob), displayName);
      fill.style.width = '100%';
    }
  } catch { toast('Download failed.', 'error'); }
  setTimeout(() => bar.classList.remove('active'), 1200);
}

function triggerDownload(url, name) {
  const a = document.createElement('a'); a.href = url; a.download = name;
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 10000);
}

async function deleteFile(name, sha, chunked, displayName, repoIdx) {
  showModal(`Delete "${displayName}"`, 'This will permanently delete the file from your GitHub repository.', 'Delete', 'btn-danger', async () => {
    try {
      const r = await fetch('/api/delete', { method: 'DELETE', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name, sha, chunked, repoIdx }) });
      if (r.status === 401) { unauth(); return; }
      if (r.ok) { toast('File deleted.', 'ok'); loadFiles(); }
      else toast('Delete failed.', 'error');
    } catch { toast('Connection error.', 'error'); }
  });
}

async function openEditSheet(f) {
  _editFile = f; _editSha = null;
  closeFileDetail();
  const overlay  = document.getElementById('edit-overlay');
  const textarea = document.getElementById('edit-textarea');
  const nameEl   = document.getElementById('edit-filename');
  const statusEl = document.getElementById('edit-status');
  if (!overlay || !textarea) return;
  nameEl.textContent    = f.originalName || f.name;
  statusEl.textContent  = 'Loading…';
  textarea.value        = '';
  textarea.disabled     = true;
  document.getElementById('edit-save-btn').disabled = true;
  overlay.classList.add('open');
  try {
    const r = await fetch(`/api/read-text?name=${encodeURIComponent(f.name)}&repoIdx=${_currentFileRepoIdx}`, { credentials: 'same-origin' });
    if (!r.ok) { const d = await r.json().catch(() => ({})); statusEl.textContent = d.error || 'Failed to load.'; return; }
    const d = await r.json();
    _editSha = d.sha; textarea.value = d.content; textarea.disabled = false;
    document.getElementById('edit-save-btn').disabled = false;
    statusEl.textContent = ''; textarea.focus();
  } catch { statusEl.textContent = 'Connection error.'; }
}
function closeEditSheet() {
  document.getElementById('edit-overlay')?.classList.remove('open');
  _editFile = null; _editSha = null;
}
async function saveEditSheet() {
  if (!_editFile || !_editSha) return;
  const textarea = document.getElementById('edit-textarea');
  const statusEl = document.getElementById('edit-status');
  const saveBtn  = document.getElementById('edit-save-btn');
  const content  = textarea.value;
  saveBtn.disabled = true; saveBtn.innerHTML = '<span class="spinner"></span>';
  statusEl.textContent = 'Saving…';
  try {
    const r = await fetch('/api/edit-text', {
      method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: _editFile.name, content, sha: _editSha, repoIdx: _currentFileRepoIdx }),
    });
    const d = await r.json().catch(() => ({}));
    if (r.ok) {
      _editSha = d.sha || _editSha;
      statusEl.textContent = 'Saved!';
      setTimeout(() => { statusEl.textContent = ''; }, 2000);
      toast('File saved.', 'ok'); loadFiles();
    } else if (r.status === 409) {
      statusEl.textContent = 'Conflict — file changed externally. Re-open to reload.';
    } else { statusEl.textContent = d.error || 'Save failed.'; }
  } catch { statusEl.textContent = 'Connection error.'; }
  saveBtn.disabled = false; saveBtn.textContent = 'Save';
}

function openShareModal(f) {
  _shareFile = f;
  document.getElementById('share-file-name').textContent = f.originalName || f.name;
  document.getElementById('share-pre').style.display     = '';
  document.getElementById('share-post').style.display    = 'none';
  document.getElementById('share-spinner').style.display = 'none';
  document.getElementById('share-create-btn').style.display = '';
  document.getElementById('share-link-input').value      = '';
  document.getElementById('share-exp').textContent       = '';
  document.getElementById('share-overlay').classList.add('open');
}
async function createShareLink() {
  if (!_shareFile) return;
  await ensureRepoActive(_currentFileRepoIdx);
  const pre     = document.getElementById('share-pre');
  const post    = document.getElementById('share-post');
  const spinner = document.getElementById('share-spinner');
  const createBtn = document.getElementById('share-create-btn');
  pre.style.display = 'none'; createBtn.style.display = 'none'; spinner.style.display = 'flex';
  const ttl = parseInt(document.querySelector('.ttl-opt.active')?.dataset.ttl || '3600', 10);
  try {
    const r = await fetch(`/api/share-link?name=${encodeURIComponent(_shareFile.name)}&ttl=${ttl}&repoIdx=${_currentFileRepoIdx}`, { credentials: 'same-origin' });
    if (r.status === 401) { unauth(); return; }
    if (!r.ok) { toast('Could not generate share link.', 'error'); closeShareModal(); return; }
    const d = await r.json();
    document.getElementById('share-link-input').value = window.location.origin + d.url;
    document.getElementById('share-exp').textContent = d.exp ? `Expires ${new Date(d.exp).toLocaleString()}` : 'Never expires';
    spinner.style.display = 'none'; post.style.display = '';
  } catch { toast('Could not generate share link.', 'error'); closeShareModal(); }
}
function closeShareModal() {
  document.getElementById('share-overlay').classList.remove('open');
  document.getElementById('share-pre').style.display = '';
  document.getElementById('share-post').style.display = 'none';
  document.getElementById('share-spinner').style.display = 'none';
  document.getElementById('share-create-btn').style.display = '';
  document.getElementById('share-link-input').value = '';
}
function copyShareLink() {
  const val = document.getElementById('share-link-input').value;
  if (!val) return;
  navigator.clipboard.writeText(val).then(() => toast('Link copied!', 'ok')).catch(() => {
    document.getElementById('share-link-input').select();
    document.execCommand('copy'); toast('Link copied!', 'ok');
  });
}
