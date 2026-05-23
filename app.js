'use strict';
const CHUNK_THRESHOLD = 5  * 1024 * 1024;
const CHUNK_SIZE      = 10 * 1024 * 1024;
const MAX_FILE_SIZE   = 5  * 1024 * 1024 * 1024;
let loginLocked      = false;
let uploadPending    = [];
let _signupData      = {};
let _uploadActive    = false;
let _uploadPaused    = false;
let _uploadAbortFn   = null;
let _shareFile       = null;
let _allRepos        = [];
let _activeRepoIdx   = 0;
let _repoFiles       = [];   // [{repo, repoIdx, files}] for all repos
let _currentFileRepoIdx = 0; // repo index of currently open file
const _sliceCache = new WeakMap();
function precacheSlices(file) {
  if (file.size <= CHUNK_THRESHOLD) return;
  if (_sliceCache.has(file)) return;
  const totalChunks = Math.ceil(file.size / CHUNK_SIZE);
  const slices = Array.from({ length: totalChunks }, (_, i) => {
    const start = i * CHUNK_SIZE;
    return file.slice(start, Math.min(start + CHUNK_SIZE, file.size));
  });
  _sliceCache.set(file, slices);
}
(async () => {
  try {
    const r = await fetch('/api/status');
    const d = await r.json();
    if (!d.ready) {
      document.getElementById('login-screen').innerHTML =
        '<div class="auth-card svc-unconfigured">' +
        '<h2>Service Not Configured</h2>' +
        '<p>The operator has not set the required environment variables.<br>Refer to the README for setup instructions.</p>' +
        '</div>';
      showScreen('login'); return;
    }
  } catch {}
  try {
    const r = await fetch('/api/me', { credentials:'same-origin' });
    if (r.ok) { bootApp(await r.json()); return; }
  } catch {}
  showScreen('login');
})();
function showScreen(name) {
  document.querySelectorAll('.screen').forEach(el => el.classList.remove('active'));
  document.getElementById('app-screen').classList.remove('active');
  if (name === 'app') document.getElementById('app-screen').classList.add('active');
  else { const el = document.getElementById(`${name}-screen`); if (el) el.classList.add('active'); }
}
function on(id, evt, fn) {
  const el = document.getElementById(id);
  if (!el) { console.warn('[StoreGit] missing element #' + id); return; }
  el.addEventListener(evt, fn);
}
on('login-username',    'keydown', e => { if (e.key === 'Enter') document.getElementById('login-password')?.focus(); });
on('login-password',    'keydown', e => { if (e.key === 'Enter') doLogin(); });
on('login-btn',          'click',  () => doLogin());
on('goto-signup',        'click',  e  => { e.preventDefault(); showScreen('signup'); });
on('s-password',         'input',  e  => updateStrength(e.target.value));
on('step1-btn',          'click',  () => step1Next());
on('step2-btn',          'click',  () => step2Next());
on('step2-back-btn',     'click',  () => goToStep(1));
on('step3-signin-btn',   'click',  () => showScreen('login'));
on('goto-login',         'click',  e  => { e.preventDefault(); showScreen('login'); });
on('signout-btn',        'click',  () => doLogout());
on('file-input',         'change', e  => onFilePicked(e.target.files));
on('upload-btn',         'click',  () => startUpload());
on('clear-queue-btn',    'click',  () => clearQueue());
on('refresh-files-btn',  'click',  () => loadFiles());
on('fd-overlay',         'click',  e  => { if (e.target === e.currentTarget) closeFileDetail(); });
on('pause-btn',          'click',  () => togglePause());
on('fd-share-btn',       'click',  () => _shareFile && openShareModal(_shareFile));
on('share-close-btn',    'click',  () => closeShareModal());
on('share-create-btn',   'click',  () => createShareLink());
on('share-copy-btn',     'click',  () => copyShareLink());
on('hamburger-btn',       'click',  () => openDrawer());
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
  if (code) { navigator.clipboard?.writeText(code.textContent).then(() => toast('API key copied.', 'ok')).catch(() => {}); }
});
on('goto-reset',         'click',  e  => { e.preventDefault(); showScreen('reset'); });
on('reset-back',         'click',  e  => { e.preventDefault(); showScreen('login'); });
on('reset-btn',          'click',  () => doReset());
document.addEventListener('paste', e => {
  const items = e.clipboardData?.items || [];
  const files = [];
  for (const item of items) { if (item.kind === 'file') { const f = item.getAsFile(); if (f) files.push(f); } }
  if (files.length) onFilePicked(files);
});
document.getElementById('share-ttl-opts')?.addEventListener('click', e => {
  const btn = e.target.closest('.ttl-opt');
  if (!btn) return;
  document.querySelectorAll('.ttl-opt').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
});
on('fd-close-btn',       'click',  () => closeFileDetail());
function showModal(title, msg, confirmLabel, confirmClass, onConfirm) {
  document.getElementById('modal-title').textContent = title;
  document.getElementById('modal-msg').textContent = msg;
  const overlay = document.getElementById('modal-overlay');
  const confirmBtn = document.getElementById('modal-confirm-btn');
  confirmBtn.textContent = confirmLabel;
  confirmBtn.className = 'btn ' + confirmClass;
  overlay.classList.add('open');
  const close = () => overlay.classList.remove('open');
  confirmBtn.onclick = () => { close(); onConfirm(); };
  document.getElementById('modal-cancel-btn').onclick = close;
  overlay.onclick = e => { if (e.target === overlay) close(); };
}
async function doLogin() {
  if (loginLocked) return;
  const username = document.getElementById('login-username').value.trim();
  const password = document.getElementById('login-password').value;
  const errEl    = document.getElementById('login-error');
  const btn      = document.getElementById('login-btn');
  errEl.textContent = '';
  if (!username || !password) { errEl.textContent = 'Please enter your username and password.'; return; }
  btn.disabled = true; btn.innerHTML = '<span class="spinner"></span>';
  try {
    const r = await fetch('/api/auth', {
      method:'POST', credentials:'same-origin',
      headers:{ 'Content-Type':'application/json' },
      body: JSON.stringify({ username, password }),
    });
    document.getElementById('login-password').value = '';
    if (r.ok) {
      const d = await r.json();
      bootApp({ display: d.display || username, username });
      return;
    } else if (r.status === 429) {
      startLockout(30);
      return;
    } else {
      errEl.textContent = 'Incorrect username or password.';
      document.getElementById('login-password').focus();
    }
  } catch { errEl.textContent = 'Connection error. Please try again.'; }
  btn.disabled = false; btn.textContent = 'Sign In';
}
function startLockout(secs) {
  loginLocked = true;
  const btn = document.getElementById('login-btn');
  const el  = document.getElementById('login-lockout');
  btn.disabled = true;
  const tick = () => {
    const m = Math.floor(secs/60), s = secs%60;
    el.textContent = `Too many attempts. Try again in ${m}:${String(s).padStart(2,'0')}.`;
    if (secs-- <= 0) { loginLocked=false; btn.disabled=false; el.textContent=''; clearInterval(t); }
  };
  tick(); const t = setInterval(tick, 1000);
}
function bootApp(me) {
  // Ensure drawer is fully closed on boot
  ['drawer','drawer-overlay'].forEach(id => document.getElementById(id)?.classList.remove('is-open'));
  document.getElementById('hamburger-btn')?.classList.remove('is-open');
  document.body.style.overflow = '';
  showScreen('app'); loadMeta(); loadFiles();
}
function updateRepoChip(repos, activeIdx) {
  _allRepos = repos || [];
  _activeRepoIdx = activeIdx || 0;
  renderDrawerRepoList();
}

// ── Drawer open / close ───────────────────────────────────────────────────────
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

// ── Drawer repo list ──────────────────────────────────────────────────────────
function renderDrawerRepoList() {
  const list = document.getElementById('drawer-repo-list');
  if (!list) return;
  list.innerHTML = '';
  if (!_allRepos.length) {
    const empty = elem('div', 'apikey-empty');
    empty.textContent = 'No repositories connected.';
    list.appendChild(empty);
    return;
  }
  _allRepos.forEach((repo, i) => {
    const item = elem('div', 'drawer-repo-item' + (i === _activeRepoIdx ? ' active' : ''));
    const label = elem('div', 'drawer-repo-item-label');
    label.textContent = repo.label || `Repo ${i + 1}`;
    const slug = elem('div', 'drawer-repo-item-slug');
    slug.textContent = `${repo.ghOwner}/${repo.ghRepo}`;
    item.append(label, slug);
    if (i === _activeRepoIdx) {
      const badge = elem('span', 'drawer-repo-item-badge');
      badge.textContent = 'Active';
      item.appendChild(badge);
    }
    if (i > 0) {
      const rmBtn = elem('button', 'drawer-repo-remove-btn');
      rmBtn.title = 'Remove repository';
      rmBtn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>';
      rmBtn.onclick = e => {
        e.stopPropagation();
        showModal(
          `Remove "${repo.label || `Repo ${i + 1}`}"`,
          'Files stay on GitHub — only the connection is removed from StoreGit.',
          'Remove', 'btn-danger',
          async () => {
            try {
              const r = await fetch('/api/remove-repo', { method:'POST', credentials:'same-origin', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ repoIdx: i }) });
              if (r.ok) { toast('Repository removed.', 'ok'); await loadMeta(); loadFiles(); }
              else toast('Failed to remove.', 'error');
            } catch { toast('Connection error.', 'error'); }
          }
        );
      };
      item.appendChild(rmBtn);
    }
    list.appendChild(item);
  });
}

// ── Drawer add-repo form ──────────────────────────────────────────────────────
function toggleDrawerAddRepoForm() {
  const form = document.getElementById('drawer-add-repo-form');
  const btn  = document.getElementById('drawer-add-repo-btn');
  if (!form || !btn) return;
  if (form.style.display === 'none') {
    form.style.display = '';
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
  ['dar-label','dar-owner','dar-repo'].forEach(id => {
    const el = document.getElementById(id); if (el) el.value = '';
  });
  const branch = document.getElementById('dar-branch');
  if (branch) branch.value = 'main';
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
    const r = await fetch('/api/add-repo', { method:'POST', credentials:'same-origin', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ label: label || 'Repo', ghOwner: owner, ghRepo: repo, ghBranch: branch, folder:'uploads' }) });
    const d = await r.json();
    if (r.ok) {
      toast('Repository added.', 'ok');
      closeDrawerAddRepoForm();
      await loadMeta(); loadFiles();
    } else { errEl.textContent = d.error || 'Failed to add repository.'; }
  } catch { errEl.textContent = 'Connection error. Please try again.'; }
  btn.disabled = false; btn.textContent = 'Add Repository';
}

// ── API Key management ────────────────────────────────────────────────────────
async function loadApiKeys() {
  const list = document.getElementById('apikey-list');
  if (!list) return;
  list.innerHTML = '<div class="apikey-empty">Loading…</div>';
  try {
    const r = await fetch('/api/apikeys/list', { credentials:'same-origin' });
    if (!r.ok) { list.innerHTML = '<div class="apikey-empty">Could not load keys.</div>'; return; }
    const { keys } = await r.json();
    renderApiKeyList(keys);
  } catch { list.innerHTML = '<div class="apikey-empty">Connection error.</div>'; }
}
function renderApiKeyList(keys) {
  const list = document.getElementById('apikey-list');
  if (!list) return;
  list.innerHTML = '';
  if (!keys || !keys.length) {
    const empty = elem('div', 'apikey-empty');
    empty.textContent = 'No API keys yet.';
    list.appendChild(empty);
    return;
  }
  keys.forEach(k => {
    const item = elem('div', 'apikey-item');
    const top  = elem('div', 'apikey-item-top');
    const lbl  = elem('div', 'apikey-item-label');
    lbl.textContent = k.label;
    const revokeBtn = elem('button', 'apikey-revoke-btn');
    revokeBtn.textContent = 'Revoke';
    revokeBtn.onclick = () => showModal(
      `Revoke "${k.label}"`,
      'This key will stop working immediately. This cannot be undone.',
      'Revoke', 'btn-danger',
      async () => {
        try {
          const r = await fetch('/api/apikeys/revoke', { method:'DELETE', credentials:'same-origin', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ keyId: k.keyId }) });
          if (r.ok) { toast('API key revoked.', 'ok'); loadApiKeys(); }
          else toast('Failed to revoke key.', 'error');
        } catch { toast('Connection error.', 'error'); }
      }
    );
    top.append(lbl, revokeBtn);
    const preview = elem('div', 'apikey-item-preview');
    preview.textContent = k.preview;
    const origins = elem('div', 'apikey-item-origins');
    if (!k.allowedOrigins || !k.allowedOrigins.length) {
      origins.classList.add('any');
      origins.innerHTML = 'Origins: <span>Any (unrestricted)</span>';
    } else {
      origins.innerHTML = `Origins: <span>${k.allowedOrigins.join(', ')}</span>`;
    }
    item.append(top, preview, origins);
    list.appendChild(item);
  });
}
function toggleApiKeyForm() {
  const form = document.getElementById('apikey-form');
  const btn  = document.getElementById('apikey-new-btn');
  if (!form || !btn) return;
  hideApiKeyReveal();
  if (form.style.display === 'none') {
    form.style.display = '';
    btn.textContent = 'Cancel';
    document.getElementById('ak-label')?.focus();
  } else {
    closeApiKeyForm();
  }
}
function closeApiKeyForm() {
  const form = document.getElementById('apikey-form');
  const btn  = document.getElementById('apikey-new-btn');
  if (form) form.style.display = 'none';
  if (btn)  btn.textContent = 'New Key';
  const err = document.getElementById('ak-error');
  if (err) err.textContent = '';
  const lbl = document.getElementById('ak-label');
  if (lbl) lbl.value = '';
  const orig = document.getElementById('ak-origins');
  if (orig) orig.value = '';
}
function hideApiKeyReveal() {
  const box = document.getElementById('apikey-reveal');
  if (box) box.style.display = 'none';
}
async function submitApiKey() {
  const label      = document.getElementById('ak-label')?.value.trim() || '';
  const originsRaw = document.getElementById('ak-origins')?.value || '';
  const allowedOrigins = originsRaw.split('\n').map(s => s.trim()).filter(Boolean);
  const errEl = document.getElementById('ak-error');
  const btn   = document.getElementById('ak-submit-btn');
  errEl.textContent = '';
  if (!label) { errEl.textContent = 'Please enter a label for this key.'; return; }
  btn.disabled = true; btn.innerHTML = '<span class="spinner"></span>';
  try {
    const r = await fetch('/api/apikeys/create', { method:'POST', credentials:'same-origin', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ label, allowedOrigins }) });
    const d = await r.json();
    if (r.ok) {
      closeApiKeyForm();
      const box  = document.getElementById('apikey-reveal');
      const code = document.getElementById('apikey-reveal-code');
      if (box && code) { code.textContent = d.rawKey; box.style.display = ''; }
      toast('API key created. Copy it now!', 'ok');
      loadApiKeys();
    } else { errEl.textContent = d.error || 'Failed to create API key.'; }
  } catch { errEl.textContent = 'Connection error. Please try again.'; }
  btn.disabled = false; btn.textContent = 'Generate Key';
}
async function ensureRepoActive(repoIdx) {
  if (repoIdx === undefined || repoIdx === _activeRepoIdx || _allRepos.length <= 1) return;
  try {
    const r = await fetch('/api/switch-repo', {
      method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ repoIdx })
    });
    if (r.ok) _activeRepoIdx = repoIdx;
  } catch { /* best effort */ }
}
async function getSmartRepoIdx() {
  if (_allRepos.length <= 1 || _repoFiles.length === 0) return _activeRepoIdx;
  let minSize = Infinity, minIdx = _activeRepoIdx;
  for (const group of _repoFiles) {
    const total = (group.files || [])
      .filter(f => f.name !== '.storegit')
      .reduce((sum, f) => sum + (f.size || 0), 0);
    if (total < minSize) { minSize = total; minIdx = group.repoIdx; }
  }
  return minIdx;
}
function buildFileRow(f) {
  const row  = elem('div', 'file-row');
  const badge = elem('div', 'file-type-badge');
  const displayName = f.originalName || f.name;
  badge.textContent = fileExt(displayName);
  badge.style.background = fileColor(fileExtRaw(displayName));
  badge.style.color = '#fff';
  const info = elem('div', 'file-info');
  const nm   = elem('div', 'file-name'); nm.textContent = displayName; nm.title = displayName;
  const mt   = elem('div', 'file-meta'); mt.textContent = fmtSize(f.size);
  info.append(nm, mt);
  const chevron = elem('div', 'file-chevron');
  chevron.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="14" height="14"><polyline points="9 18 15 12 9 6"/></svg>`;
  row.append(badge, info, chevron);
  row.onclick = () => openFileDetail(f);
  return row;
}
function renderAllFiles(groups) {
  const el = document.getElementById('file-list');
  el.innerHTML = '';
  const showSections = groups.length > 1;
  let totalVisible = 0;
  for (const group of groups) {
    const visible = (group.files || [])
      .filter(f => f.name !== '.storegit')
      .sort((a, b) => {
        if (!a.uploadedAt && !b.uploadedAt) return 0;
        if (!a.uploadedAt) return 1;
        if (!b.uploadedAt) return -1;
        return new Date(b.uploadedAt) - new Date(a.uploadedAt);
      });
    if (showSections) {
      const totalSize = visible.reduce((sum, f) => sum + (f.size || 0), 0);
      const repoName = group.repo?.label || `Repo ${group.repoIdx + 1}`;
      const repoSub  = group.repo ? `${group.repo.ghOwner}/${group.repo.ghRepo}` : '';
      const section  = elem('div', 'repo-section');
      const hdr      = elem('div', 'repo-section-header');
      const lbl      = elem('div', 'repo-section-label'); lbl.textContent = repoName;
      const sub      = elem('div', 'repo-section-sub');
      sub.textContent = repoSub + (totalSize ? ' · ' + fmtSize(totalSize) : '');
      hdr.append(lbl, sub);
      section.appendChild(hdr);
      if (visible.length === 0) {
        const empty = elem('div', 'repo-section-empty'); empty.textContent = 'No files yet.';
        section.appendChild(empty);
      } else {
        visible.forEach(f => section.appendChild(buildFileRow(f)));
      }
      el.appendChild(section);
    } else {
      visible.forEach(f => el.appendChild(buildFileRow(f)));
    }
    totalVisible += visible.length;
  }
  if (totalVisible === 0) { el.innerHTML = ''; el.appendChild(emptyState('No files uploaded yet.')); }
}
// toggleAddRepoForm and submitAddRepo moved to drawer functions above
async function loadMeta() {
  try {
    const r = await fetch('/api/me', { credentials:'same-origin' });
    if (r.ok) {
      const d = await r.json();
      document.getElementById('repo-label').textContent = d.repoLabel ? `${d.repoLabel} — ${d.repo}` : (d.repo || '');
      updateRepoChip(d.repos || [], d.activeRepoIdx ?? 0);
    }
  } catch {}
}
async function doLogout() {
  showModal('Sign out', 'You will be signed out of StoreGit.', 'Sign Out', 'btn-ghost', async () => {
    try { await fetch('/api/logout', { method: 'POST', credentials: 'same-origin' }); } catch {}
    uploadPending = []; clearQueue(); showScreen('login');
  });
}
function goToStep(n) {
  [1,2,3].forEach(i => {
    document.getElementById(`step-${i}`).classList.toggle('active', i===n);
    const d = document.getElementById(`sdot-${i}`);
    d.className = 'step-dot' + (i<n?' done':i===n?' active':'');
  });
  document.getElementById('signup-footer-note').style.display = n===3?'none':'';
}
function updateStrength(pw) {
  const wrap=document.getElementById('pw-strength'), fill=document.getElementById('pw-strength-fill'), label=document.getElementById('pw-strength-label');
  if (!pw){wrap.style.display='none';return;} wrap.style.display='block';
  let s=0; if(pw.length>=8)s++; if(pw.length>=12)s++; if(/[A-Z]/.test(pw)&&/[a-z]/.test(pw))s++; if(/[0-9]/.test(pw))s++; if(/[^a-zA-Z0-9]/.test(pw))s++;
  const L=[{pct:10,color:'#c0392b',text:'Very weak'},{pct:30,color:'#e67e22',text:'Weak'},{pct:55,color:'#f1c40f',text:'Fair'},{pct:80,color:'#2ecc71',text:'Strong'},{pct:100,color:'#34a853',text:'Very strong'}];
  const lv=L[Math.min(s,L.length-1)]; fill.style.width=lv.pct+'%'; fill.style.background=lv.color; label.textContent=lv.text;
}
function step1Next() {
  const u=document.getElementById('s-username').value.trim(), p=document.getElementById('s-password').value, p2=document.getElementById('s-password2').value, e=document.getElementById('step1-error');
  e.textContent='';
  if(!u){e.textContent='Please enter a username.';return;}
  if(!/^[a-zA-Z0-9_\-]{3,32}$/.test(u)){e.textContent='Username must be 3–32 characters: letters, numbers, hyphens, underscores.';return;}
  if(p.length<8){e.textContent='Password must be at least 8 characters.';return;}
  if(p!==p2){e.textContent='Passwords do not match.';return;}
  _signupData.username=u; _signupData.password=p; goToStep(2);
}
async function step2Next() {
  const t=document.getElementById('s-gh-token').value.trim(), o=document.getElementById('s-gh-owner').value.trim(), r=document.getElementById('s-gh-repo').value.trim();
  const err=document.getElementById('step2-error'), btn=document.getElementById('step2-btn');
  err.textContent='';
  if(!t||!o||!r){err.textContent='Please fill in all fields.';return;}
  if(!t.startsWith('ghp_')&&!t.startsWith('github_pat_')){err.textContent='Token should start with ghp_ or github_pat_';return;}
  btn.disabled=true; btn.innerHTML='<span class="spinner"></span> Verifying…';
  try {
    const gr = await fetch(`https://api.github.com/repos/${encodeURIComponent(o)}/${encodeURIComponent(r)}`,
      {headers:{Authorization:`token ${t}`,Accept:'application/vnd.github.v3+json','User-Agent':'StoreGit-Setup'}});
    if(gr.status===401){err.textContent='Invalid GitHub token.';return;}
    if(gr.status===404){err.textContent='Repository not found.';return;}
    if(!gr.ok){err.textContent=`GitHub error (${gr.status}).`;return;}
    const repo=await gr.json();
    if(!repo.permissions?.push&&!repo.permissions?.admin){err.textContent='Token needs write access to this repository.';return;}
    const sr=await fetch('/api/signup',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({username:_signupData.username,password:_signupData.password,ghToken:t,ghOwner:o,ghRepo:r,ghBranch:'main',folder:'uploads'})});
    const sd=await sr.json();
    if(sr.ok){
      _signupData={}; document.getElementById('s-password').value=''; document.getElementById('s-password2').value=''; document.getElementById('s-gh-token').value='';
      goToStep(3);
    } else if(sr.status===409){err.textContent='That username is already taken.';}
    else{err.textContent=sd.error||'Signup failed.';}
  } catch{err.textContent='Connection error. Please try again.';}
  finally{btn.disabled=false;btn.textContent='Verify & Continue';}
}
async function loadFiles() {
  const el=document.getElementById('file-list');
  el.innerHTML='<div class="loading-row"><span class="spinner"></span> Loading files…</div>';
  try {
    if (_allRepos.length <= 1) {
      const r=await fetch('/api/files',{credentials:'same-origin'});
      if(r.status===401){doLogout();return;}
      if(!r.ok) throw new Error('Failed to load files.');
      const files=await r.json();
      _repoFiles=[{repo:_allRepos[0]||null,repoIdx:0,files}];
    } else {
      // Fetch all repos in parallel using ?repoIdx= — no session mutation
      const results = await Promise.allSettled(
        _allRepos.map((repo, i) =>
          fetch(`/api/files?repoIdx=${i}`, { credentials: 'same-origin' })
            .then(r => {
              if (r.status === 401) { doLogout(); throw new Error('unauth'); }
              if (!r.ok) throw new Error(`repo_${i}_fail`);
              return r.json();
            })
            .then(files => ({ repo, repoIdx: i, files: files.map(f => ({ ...f, _repoIdx: i })) }))
        )
      );
      const groups = results
        .filter(r => r.status === 'fulfilled')
        .map(r => r.value);
      _repoFiles = groups;
    }
    renderAllFiles(_repoFiles);
  } catch(e){el.innerHTML='';el.appendChild(emptyState(e.message));}
}
function renderFiles(files) {
  const el=document.getElementById('file-list');
  el.innerHTML='';
  const visible=files
    .filter(f=>f.name!=='.storegit')
    .sort((a,b)=>{
      if(!a.uploadedAt&&!b.uploadedAt)return 0;
      if(!a.uploadedAt)return 1;
      if(!b.uploadedAt)return -1;
      return new Date(b.uploadedAt)-new Date(a.uploadedAt);
    });
  if(!visible.length){el.appendChild(emptyState('No files uploaded yet.'));return;}
  for(const f of visible){
    const row  = elem('div','file-row');
    const badge = elem('div','file-type-badge');
    const displayName = f.originalName || f.name;
    badge.textContent = fileExt(displayName);
    badge.style.background = fileColor(fileExtRaw(displayName));
    badge.style.color = '#fff';
    const info = elem('div','file-info');
    const nm   = elem('div','file-name'); nm.textContent=displayName; nm.title=displayName;
    const mt   = elem('div','file-meta'); mt.textContent=fmtSize(f.size);
    info.append(nm,mt);
    const chevron = elem('div','file-chevron');
    chevron.innerHTML=`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="14" height="14"><polyline points="9 18 15 12 9 6"/></svg>`;
    row.append(badge,info,chevron);
    row.onclick = () => openFileDetail(f);
    el.appendChild(row);
  }
}
async function deleteFile(name, sha, chunked, displayName) {
  const label = displayName || name;
  showModal('Delete file', `“${label}” will be permanently deleted and cannot be recovered.`, 'Delete', 'btn-danger', async () => {
    try {
      const body = chunked ? { name, chunked: true } : { name, sha };
      const r = await fetch('/api/delete', {
        method: 'DELETE', credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
      });
      if (r.status === 401) { doLogout(); return; }
      if (r.ok) { toast('File deleted.', 'ok'); loadFiles(); }
      else toast('Delete failed.', 'error');
    } catch { toast('Delete failed.', 'error'); }
  });
}
async function downloadFile(name, size, originalName) {
  const saveAs = originalName || name;
  const bar=document.getElementById('dl-bar'), fill=document.getElementById('dl-fill'),
        lbl=document.getElementById('dl-label'), fnEl=document.getElementById('dl-filename');
  const url=`/api/download?name=${encodeURIComponent(name)}`;
  try {
    const r=await fetch(url,{credentials:'same-origin'});
    if(r.status===401){doLogout();return;}
    if(!r.ok){toast('Download failed.','error');return;}
    const contentLen=parseInt(r.headers.get('Content-Length')||'0',10);
    const knownSize=contentLen||size||0;
    const showBar=knownSize>2*1024*1024&&typeof ReadableStream!=='undefined'&&r.body;
    if(showBar){
      fnEl.textContent=saveAs; fill.style.width='0%'; lbl.textContent='Starting…'; bar.style.display='block';
      const reader=r.body.getReader(), chunks=[];
      let received=0;
      while(true){
        const{done,value}=await reader.read(); if(done)break;
        chunks.push(value); received+=value.length;
        if(knownSize>0){
          const pct=Math.min(100,Math.round(received/knownSize*100));
          fill.style.width=pct+'%'; lbl.textContent=`${fmtSize(received)} of ${fmtSize(knownSize)}`;
        } else { lbl.textContent=`${fmtSize(received)} downloaded…`; }
      }
      bar.style.display='none'; triggerSave(new Blob(chunks),saveAs);
    } else { triggerSave(await r.blob(),saveAs); }
    toast('Saved to Downloads.','ok');
  } catch{ document.getElementById('dl-bar').style.display='none'; toast('Download failed.','error'); }
}
function triggerSave(blob, filename) {
  const url=URL.createObjectURL(blob), a=document.createElement('a');
  a.href=url; a.download=filename; a.style.display='none';
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  setTimeout(()=>URL.revokeObjectURL(url),60000);
}
const dropZone=document.getElementById('drop-zone');
dropZone.addEventListener('dragover',e=>{e.preventDefault();dropZone.classList.add('dragging');});
dropZone.addEventListener('dragleave',()=>dropZone.classList.remove('dragging'));
dropZone.addEventListener('drop',e=>{e.preventDefault();dropZone.classList.remove('dragging');onFilePicked(e.dataTransfer.files);});
function onFilePicked(fileList) {
  const rejected=[];
  for(const f of fileList){
    if(f.size>MAX_FILE_SIZE){rejected.push(`"${f.name}" exceeds the size limit.`);continue;}
    const duplicate = uploadPending.find(p =>
      p.file.name === f.name &&
      p.file.size === f.size &&
      p.file.lastModified === f.lastModified
    );
    if (duplicate) {
      toast(`"${f.name}" is already in the queue.`, 'error');
    } else {
      uploadPending.push({file: f, status: 'wait'});
      precacheSlices(f);
    }
  }
  if(rejected.length) toast(rejected[0],'error');
  renderQueue();
}
function renderQueue() {
  const qEl=document.getElementById('upload-queue'), aEl=document.getElementById('upload-actions');
  if(!uploadPending.length){qEl.style.display='none';aEl.style.display='none';return;}
  qEl.style.display='block'; aEl.style.display='flex'; qEl.innerHTML='';
  const pauseBtn=document.getElementById('pause-btn');
  const upBtn=document.getElementById('upload-btn');
  if(pauseBtn) { pauseBtn.style.display=_uploadActive?'':'none'; pauseBtn.textContent=_uploadPaused?'Resume':'Pause'; }
  if(upBtn) { upBtn.style.display=_uploadActive&&!_uploadPaused?'none':''; }
  uploadPending.forEach((it,i)=>{
    const item=elem('div','queue-item');
    const badge=elem('div','queue-file-icon'); badge.textContent=fileExt(it.file.name); badge.style.background=fileColor(fileExtRaw(it.file.name)); badge.style.color='#fff';
    const info=elem('div','queue-info');
    const nm=elem('div','queue-name'); nm.textContent=it.file.name;
    const sz=elem('div','queue-size');
    sz.textContent=fmtSize(it.file.size);
    const bar=elem('div','queue-bar'), fill=elem('div','queue-fill');
    fill.id=`qfill-${i}`; bar.appendChild(fill);
    info.append(nm,sz,bar);
    const st=elem('span',`queue-status ${it.status}`); st.id=`qstat-${i}`; st.textContent=statusLabel(it.status);
    if (it.status === 'fail' || it.status === 'paused') {
      const retry = elem('button', 'queue-retry-btn');
      retry.textContent = it.status === 'paused' ? 'Resume' : 'Retry';
      retry.onclick = () => { if (it.status === 'paused') { it.status = 'wait'; renderQueue(); startUpload(); } else retryItem(i); };
      item.append(badge, info, st, retry);
    } else {
      item.append(badge, info, st);
    }
    qEl.appendChild(item);
  });
}
async function retryItem(idx) {
  const st = uploadPending[idx]?.status;
  if (st !== 'fail' && st !== 'paused') return;
  const btn = document.getElementById('upload-btn');
  btn.disabled = true; btn.textContent = 'Uploading…';
  setQ(idx, 'go', 0);
  try {
    if (uploadPending[idx].file.size > CHUNK_THRESHOLD) {
      await chunkedUpload(uploadPending[idx].file, idx);
    } else {
      await xhrUpload(uploadPending[idx].file, idx);
    }
    setQ(idx, 'ok', 100);
    toast('File uploaded.', 'ok');
    loadFiles();
  } catch (e) {
    setQ(idx, 'fail', 0);
    toast(e.message, 'error');
  }
  btn.disabled = false; btn.textContent = 'Upload Files';
}
function clearQueue(){
  uploadPending=[];
  document.getElementById('file-input').value='';
  renderQueue();
}
function togglePause() {
  if (!_uploadActive) return;
  if (_uploadPaused) {
    _uploadPaused = false;
    renderQueue();
    if (_uploadAbortFn) { const fn = _uploadAbortFn; _uploadAbortFn = null; fn(); }
  } else {
    _uploadPaused = true;
    if (_uploadAbortFn) { _uploadAbortFn(); _uploadAbortFn = null; }
    renderQueue();
    toast('Upload paused.', '');
  }
}
async function startUpload() {
  if (_uploadActive) return;
  if (!uploadPending.length) return;
  // Smart routing: auto-select the repo with the least total file size
  if (_allRepos.length > 1) {
    const smartIdx = await getSmartRepoIdx();
    if (smartIdx !== _activeRepoIdx) {
      try {
        const r = await fetch('/api/switch-repo', {
          method: 'POST', credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ repoIdx: smartIdx })
        });
        if (r.ok) _activeRepoIdx = smartIdx;
      } catch { /* continue with current */ }
    }
  }
  _uploadActive = true;
  _uploadPaused = false;
  renderQueue();
  for (let i = 0; i < uploadPending.length; i++) {
    const it = uploadPending[i];
    if (it.status === 'ok') continue;
    if (_uploadPaused) { setQ(i, 'wait', 0); continue; }
    setQ(i, 'go', 0);
    try {
      if (it.file.size > CHUNK_THRESHOLD) {
        await chunkedUpload(it.file, i);
      } else {
        await xhrUpload(it.file, i);
      }
      if (it.status !== 'paused') setQ(i, 'ok', 100);
    } catch(e) {
      if (e.message !== '__paused__') { setQ(i, 'fail', 0); toast(e.message, 'error'); }
    }
  }
  _uploadActive = false;
  _uploadAbortFn = null;
  renderQueue();
  const failed = uploadPending.filter(p => p.status === 'fail').length;
  const paused = uploadPending.filter(p => p.status === 'paused' || p.status === 'wait').length;
  if (!_uploadPaused && !paused) {
    if (!failed) { toast('All files uploaded.', 'ok'); clearQueue(); }
    else toast(`${failed} file${failed > 1 ? 's' : ''} failed.`, 'error');
    loadFiles();
  } else if (!paused) {
    loadFiles();
  }
}
function blobToBase64(blob) {
  return new Promise((res, rej) => {
    const r = new FileReader();
    r.onload  = () => res(r.result.slice(r.result.indexOf(',') + 1));
    r.onerror = () => rej(new Error('Read failed'));
    r.readAsDataURL(blob);
  });
}
async function xhrUpload(file, idx) {
  setQ(idx, 'go', 5);
  const b64 = await blobToBase64(file);
  if (_uploadPaused) { setQ(idx, 'paused', 30); throw new Error('__paused__'); }
  setQ(idx, 'go', 30);
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    _uploadAbortFn = () => { xhr.abort(); setQ(idx, 'paused', 30); reject(new Error('__paused__')); };
    xhr.open('POST', '/api/upload');
    xhr.withCredentials = true;
    xhr.setRequestHeader('Content-Type', 'application/json');
    xhr.upload.onprogress = e => {
      if (e.lengthComputable) setQ(idx, 'go', 30 + Math.round(e.loaded / e.total * 65));
    };
    xhr.onload = () => {
      _uploadAbortFn = null;
      if (xhr.status === 200) { resolve(); return; }
      if (xhr.status === 401) { doLogout(); reject(new Error('Session expired.')); return; }
      let msg = 'Upload failed.'; try { msg = JSON.parse(xhr.responseText).error || msg; } catch {}
      reject(new Error(msg));
    };
    xhr.onerror   = () => { _uploadAbortFn = null; reject(new Error('Network error.')); };
    xhr.ontimeout = () => { _uploadAbortFn = null; reject(new Error('Upload timed out.')); };
    xhr.timeout   = 10 * 60 * 1000;
    xhr.send(JSON.stringify({ name: file.name, content: b64 }));
  });
}
const UPLOAD_CONCURRENCY = 5;
async function chunkedUpload(file, idx) {
  const totalChunks = Math.ceil(file.size / CHUNK_SIZE);
  setQ(idx, 'go', 2);
  const slices = _sliceCache.get(file) || Array.from({ length: totalChunks }, (_, i) => {
    const start = i * CHUNK_SIZE;
    return file.slice(start, Math.min(start + CHUNK_SIZE, file.size));
  });
  if (!_sliceCache.has(file)) _sliceCache.set(file, slices);
  const encoded = await Promise.all(slices.map(s => blobToBase64(s)));
  setQ(idx, 'go', 18);
  const blobs      = new Array(totalChunks);
  let  doneCount   = 0;
  const indexQueue = Array.from({ length: totalChunks }, (_, i) => i);
  const runWorker = async () => {
    while (indexQueue.length > 0) {
      if (_uploadPaused) {
        const remaining = indexQueue.splice(0);
        indexQueue.push(...remaining);
        setQ(idx, 'paused', 18 + Math.round((doneCount / totalChunks) * 74));
        throw new Error('__paused__');
      }
      const i = indexQueue.shift();
      const result = await xhrChunkWithRetry(
        encoded[i], slices[i].size, file.name, i, totalChunks, idx
      );
      blobs[i] = { index: i, blobSha: result.blobSha, blobToken: result.blobToken, size: slices[i].size };
      doneCount++;
      setQ(idx, 'go', 18 + Math.round((doneCount / totalChunks) * 74));
    }
  };
  await Promise.all(
    Array.from({ length: Math.min(UPLOAD_CONCURRENCY, totalChunks) }, runWorker)
  );
  setQ(idx, 'go', 93);
  const fr = await fetch('/api/finalize-upload', {
    method: 'POST', credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      name: file.name, totalSize: file.size,
      totalChunks, chunkSize: CHUNK_SIZE, blobs,
    }),
  });
  if (fr.status === 401) { doLogout(); throw new Error('Session expired.'); }
  if (!fr.ok) {
    const d = await fr.json().catch(() => ({}));
    throw new Error(d.error || 'Finalize failed.');
  }
  setQ(idx, 'go', 99);
}
const CHUNK_MAX_RETRIES = 2;
const CHUNK_BACKOFF_MS  = 800;
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
async function xhrChunkWithRetry(b64, rawSize, name, chunkIndex, totalChunks, queueIdx) {
  let lastErr;
  for (let attempt = 0; attempt <= CHUNK_MAX_RETRIES; attempt++) {
    if (attempt > 0) {
      await sleep(CHUNK_BACKOFF_MS * Math.pow(2, attempt - 1));
    }
    try {
      return await xhrChunkEncoded(b64, rawSize, name, chunkIndex, totalChunks, queueIdx);
    } catch (err) {
      if (err.message === 'Session expired.') throw err;
      lastErr = err;
    }
  }
  throw lastErr;
}
async function xhrChunkEncoded(b64, rawSize, name, chunkIndex, totalChunks, queueIdx) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    _uploadAbortFn = () => { xhr.abort(); reject(new Error('__paused__')); };
    xhr.open('POST', '/api/upload-chunk');
    xhr.withCredentials = true;
    xhr.setRequestHeader('Content-Type', 'application/json');
    xhr.timeout   = 5 * 60 * 1000;
    xhr.onload = () => {
      _uploadAbortFn = null;
      if (xhr.status === 200) { resolve(JSON.parse(xhr.responseText)); return; }
      if (xhr.status === 401) { doLogout(); reject(new Error('Session expired.')); return; }
      let msg = `Upload error on segment ${chunkIndex + 1}.`;
      try { msg = JSON.parse(xhr.responseText).error || msg; } catch {}
      reject(new Error(msg));
    };
    xhr.onerror   = () => { _uploadAbortFn = null; reject(new Error('Network error.')); };
    xhr.ontimeout = () => { _uploadAbortFn = null; reject(new Error('Upload segment timed out.')); };
    xhr.send(JSON.stringify({ name, chunkIndex, totalChunks, content: b64 }));
  });
}
function setQ(i, status, pct) {
  uploadPending[i].status = status;
  const st   = document.getElementById(`qstat-${i}`);
  const fill = document.getElementById(`qfill-${i}`);
  if (st) { st.className = `queue-status ${status}`; st.textContent = statusLabel(status); }
  if (fill) {
    fill.style.width = pct + '%';
    if (status === 'go') { fill.classList.add('wave'); } else { fill.classList.remove('wave'); }
  }
}
function statusLabel(s){return{wait:'Ready',go:'Uploading…',ok:'Done',fail:'Failed',paused:'Paused'}[s]||s;}
function fmtSize(b){
  if(b==null||isNaN(b))return'—';
  if(b<1024)return`${b} B`;
  if(b<1048576)return`${(b/1024).toFixed(1)} KB`;
  if(b<1073741824)return`${(b/1048576).toFixed(1)} MB`;
  return`${(b/1073741824).toFixed(2)} GB`;
}
function fileExt(name){const e=(name||'').split('.').pop();return e&&e!==name?e.slice(0,5).toUpperCase():'FILE';}
function fileExtRaw(name){const e=(name||'').split('.').pop();return e&&e!==name?e.toLowerCase():'';}
function fileColor(ext){
  const MAP={jpg:'#2563eb',jpeg:'#2563eb',png:'#2563eb',gif:'#2563eb',webp:'#2563eb',bmp:'#2563eb',avif:'#2563eb',tiff:'#2563eb',tif:'#2563eb',ico:'#2563eb',svg:'#2563eb',mp4:'#dc2626',webm:'#dc2626',mov:'#dc2626',m4v:'#dc2626',mp3:'#d97706',wav:'#d97706',ogg:'#d97706',m4a:'#d97706',flac:'#d97706',aac:'#d97706',opus:'#d97706',js:'#16a34a',ts:'#16a34a',jsx:'#16a34a',tsx:'#16a34a',py:'#16a34a',rb:'#16a34a',go:'#16a34a',rs:'#16a34a',java:'#16a34a',c:'#16a34a',cpp:'#16a34a',h:'#16a34a',swift:'#16a34a',kt:'#16a34a',php:'#16a34a',sh:'#16a34a',bash:'#16a34a',json:'#0891b2',csv:'#0891b2',xml:'#0891b2',yaml:'#0891b2',yml:'#0891b2',sql:'#0891b2',pdf:'#ef4444',doc:'#2563eb',docx:'#2563eb',txt:'#6b7280',md:'#6b7280',zip:'#b45309',gz:'#b45309',rar:'#b45309',tar:'#b45309'};
  return MAP[(ext||'').toLowerCase()]||'#6b7280';
}
function elem(tag,cls){const el=document.createElement(tag);if(cls)el.className=cls;return el;}
function emptyState(msg){
  const d=elem('div','empty-state'),ic=elem('div','empty-state-icon');
  ic.innerHTML=`<svg viewBox="0 0 40 40" fill="none"><rect x="8" y="6" width="24" height="28" rx="3" stroke="#bbb" stroke-width="1.5"/><path d="M14 15h12M14 20h12M14 25h8" stroke="#bbb" stroke-width="1.5" stroke-linecap="round"/></svg>`;
  const p=elem('p');p.textContent=msg;d.append(ic,p);return d;
}
function toast(msg,type=''){
  const el=document.getElementById('toast');
  el.textContent=String(msg).slice(0,100);
  el.className=`toast show${type?' '+type:''}`;
  clearTimeout(el._t); el._t=setTimeout(()=>{el.className='toast';},3500);
}
const FD_IMG   = new Set(['jpg','jpeg','png','gif','webp','bmp','ico','tiff','tif','avif']);
const FD_AUDIO = new Set(['mp3','wav','ogg','m4a','flac','aac','opus']);
const FD_VIDEO = new Set(['mp4','webm','mov','m4v']);
const FD_TEXT  = new Set(['txt','md','markdown','csv','json','log','ini','cfg','conf','yaml','yml','toml','nfo','diff','patch']);
function openFileDetail(f) {
  _shareFile = f;
  _currentFileRepoIdx = f._repoIdx !== undefined ? f._repoIdx : _activeRepoIdx;
  const displayName = f.originalName || f.name;
  const iconEl = document.getElementById('fd-icon');
  iconEl.textContent = fileExt(displayName);
  iconEl.style.background = fileColor(fileExtRaw(displayName));
  iconEl.style.color = '#fff';
  document.getElementById('fd-name').textContent = displayName;
  document.getElementById('fd-meta').textContent = fmtSize(f.size);
  document.getElementById('fd-dl-btn').onclick = async () => {
    await ensureRepoActive(_currentFileRepoIdx);
    downloadFile(f.name, f.size, displayName);
  };
  document.getElementById('fd-del-btn').onclick = async () => {
    await ensureRepoActive(_currentFileRepoIdx);
    closeFileDetail();
    setTimeout(() => deleteFile(f.name, f.sha, f.chunked || false, displayName), 250);
  };
  document.getElementById('fd-preview').innerHTML =
    '<div class="fd-preview-loading"><span class="spinner"></span> Loading preview…</div>';
  document.getElementById('fd-overlay').classList.add('open');
  ensureRepoActive(_currentFileRepoIdx).then(() => loadFilePreview(f));
}
function closeFileDetail() {
  document.getElementById('fd-overlay').classList.remove('open');
  _shareFile = null;
}
async function loadFilePreview(f) {
  const el  = document.getElementById('fd-preview');
  const displayName = f.originalName || f.name;
  const ext = (displayName.split('.').pop() || '').toLowerCase();
  function noPreview(msg) {
    const wrap = document.createElement('div');
    wrap.className = 'fd-preview-none';
    const icon = document.createElement('div');
    icon.className = 'fd-preview-none-icon';
    icon.innerHTML = '<svg viewBox="0 0 40 40" fill="none"><rect x="8" y="6" width="24" height="28" rx="3" stroke="currentColor" stroke-width="1.5"/><path d="M14 15h12M14 20h12M14 25h8" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>';
    const textEl = document.createElement('div');
    msg.split('<br>').forEach((line, i) => {
      if (i > 0) textEl.appendChild(document.createElement('br'));
      textEl.appendChild(document.createTextNode(line));
    });
    wrap.append(icon, textEl);
    el.replaceChildren(wrap);
  }
  async function fetchAsDataURL() {
    const r = await fetch(`/api/download?name=${encodeURIComponent(f.name)}`, {
      credentials: 'same-origin'
    });
    if (!r.ok) throw new Error('fetch_failed');
    const blob = await r.blob();
    return new Promise((res, rej) => {
      const reader = new FileReader();
      reader.onload  = e => res(e.target.result);
      reader.onerror = () => rej(new Error('read_failed'));
      reader.readAsDataURL(blob);
    });
  }
  if (FD_IMG.has(ext)) {
    if (f.size > 8 * 1024 * 1024) { noPreview('Image too large to preview.<br>Download to view.'); return; }
    try {
      const dataUrl = await fetchAsDataURL();
      const _img = document.createElement('img'); _img.className = 'fd-preview-img'; _img.src = dataUrl; _img.alt = f.name; el.replaceChildren(_img);
    } catch { noPreview('Could not load image preview.'); }
    return;
  }
  if (FD_AUDIO.has(ext)) {
    if (f.size > 8 * 1024 * 1024) { noPreview('Audio file is large.<br>Download to listen.'); return; }
    try {
      const dataUrl = await fetchAsDataURL();
      const _aud = document.createElement('audio'); _aud.className = 'fd-preview-audio'; _aud.controls = true; _aud.src = dataUrl; el.replaceChildren(_aud);
    } catch { noPreview('Could not load audio preview.'); }
    return;
  }
  if (FD_VIDEO.has(ext)) {
    if (f.size > 15 * 1024 * 1024) { noPreview('Video too large to preview here.<br>Download to watch.'); return; }
    try {
      const dataUrl = await fetchAsDataURL();
      const _vid = document.createElement('video'); _vid.className = 'fd-preview-video'; _vid.controls = true; _vid.src = dataUrl; el.replaceChildren(_vid);
    } catch { noPreview('Could not load video preview.'); }
    return;
  }
  if (FD_TEXT.has(ext) || f.size <= 200 * 1024) {
    if (f.size > 500 * 1024) { noPreview('File too large to preview as text.<br>Download to open.'); return; }
    try {
      const r = await fetch(`/api/download?name=${encodeURIComponent(f.name)}`, {
        credentials: 'same-origin'
      });
      if (!r.ok) throw new Error();
      const text    = await r.text();
      const preview = text.slice(0, 6000);
      const pre     = document.createElement('pre');
      pre.className   = 'fd-preview-code';
      pre.textContent = preview + (text.length > 6000 ? '\n\n… (truncated)' : '');
      el.innerHTML = '';
      el.appendChild(pre);
    } catch { noPreview('Could not load text preview.'); }
    return;
  }
  noPreview('No preview available.<br>Download to open this file.');
}

function openShareModal(f) {
  _shareFile = f;
  document.getElementById('share-file-name').textContent = f.originalName || f.name;
  document.getElementById('share-pre').style.display = '';
  document.getElementById('share-post').style.display = 'none';
  document.getElementById('share-spinner').style.display = 'none';
  document.getElementById('share-create-btn').style.display = '';
  document.getElementById('share-link-input').value = '';
  document.getElementById('share-exp').textContent = '';
  document.getElementById('share-overlay').classList.add('open');
}
async function createShareLink() {
  if (!_shareFile) return;
  await ensureRepoActive(_currentFileRepoIdx);
  const pre     = document.getElementById('share-pre');
  const post    = document.getElementById('share-post');
  const spinner = document.getElementById('share-spinner');
  const createBtn = document.getElementById('share-create-btn');
  const input   = document.getElementById('share-link-input');
  const expEl   = document.getElementById('share-exp');
  pre.style.display = 'none';
  createBtn.style.display = 'none';
  spinner.style.display = 'flex';
  const ttl = parseInt(document.querySelector('.ttl-opt.active')?.dataset.ttl || '3600', 10);
  try {
    const r = await fetch(`/api/share-link?name=${encodeURIComponent(_shareFile.name)}&ttl=${ttl}`, { credentials: 'same-origin' });
    if (r.status === 401) { doLogout(); return; }
    if (!r.ok) { toast('Could not generate share link.', 'error'); closeShareModal(); return; }
    const d = await r.json();
    input.value = window.location.origin + d.url;
    expEl.textContent = d.exp ? `Expires ${new Date(d.exp).toLocaleString()}` : 'Never expires';
    spinner.style.display = 'none';
    post.style.display = '';
  } catch {
    toast('Could not generate share link.', 'error');
    closeShareModal();
  }
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
    document.execCommand('copy');
    toast('Link copied!', 'ok');
  });
}
async function doReset() {
  const username    = document.getElementById('r-username').value.trim();
  const ghToken     = document.getElementById('r-gh-token').value.trim();
  const newPassword = document.getElementById('r-new-password').value;
  const errEl       = document.getElementById('reset-error');
  const btn         = document.getElementById('reset-btn');
  errEl.textContent = '';
  if (!username || !ghToken || !newPassword) { errEl.textContent = 'Please fill in all fields.'; return; }
  if (newPassword.length < 8) { errEl.textContent = 'Password must be at least 8 characters.'; return; }
  btn.disabled = true; btn.innerHTML = '<span class="spinner"></span>';
  try {
    const r = await fetch('/api/reset-password', {
      method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, ghToken, newPassword }),
    });
    document.getElementById('r-new-password').value = '';
    document.getElementById('r-gh-token').value = '';
    if (r.ok) {
      toast('Password reset successfully. Sign in with your new password.', 'ok');
      showScreen('login');
    } else {
      const d = await r.json().catch(() => ({}));
      errEl.textContent = d.error || 'Reset failed. Check your username and token.';
    }
  } catch { errEl.textContent = 'Connection error. Please try again.'; }
  btn.disabled = false; btn.textContent = 'Reset Password';
}
