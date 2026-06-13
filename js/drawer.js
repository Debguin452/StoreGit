import { state }               from './state.js';
import { elem, toast, showModal, fmtSize, ALLOWED_SCHEMES } from './util.js';
import { loadFiles, renderFiles } from './files.js';

export function openDrawer() {
  document.getElementById('drawer').classList.add('is-open');
  document.getElementById('drawer-overlay').classList.add('is-open');
  document.getElementById('hamburger-btn')?.classList.add('is-open');
}

export function closeDrawer() {
  document.getElementById('drawer').classList.remove('is-open');
  document.getElementById('drawer-overlay').classList.remove('is-open');
  document.getElementById('hamburger-btn')?.classList.remove('is-open');
}

export async function loadMeta() {
  try {
    const r = await fetch('/api/me', { credentials: 'same-origin' });
    if (r.status === 401) { window.location.replace('/'); return; }
    if (r.ok) {
      const d = await r.json();
      state.repoStorage   = Array.isArray(d.storage) ? d.storage : [];
      state.activeRepoIdx = d.activeRepoIdx || 0;
      _updateRepoChip(d.repos || []);
      const userEl = document.getElementById('topbar-user');
      if (userEl && (d.display || d.username)) userEl.textContent = d.display || d.username;
    }
  } catch {}
}

function _updateRepoChip(repos) {
  state.allRepos = repos || [];
  renderDrawerRepoList();
  const chip = document.getElementById('repo-chip');
  if (!chip) return;
  const r = repos[state.activeRepoIdx];
  chip.textContent = r ? (r.label || `${r.ghOwner}/${r.ghRepo}`) : '';
}

export function renderDrawerRepoList() {
  const list = document.getElementById('drawer-repo-list');
  if (!list) return;
  list.innerHTML = '';
  state.allRepos.forEach((repo, i) => {
    const isActive = i === state.activeRepoIdx;
    const item = elem('div', 'drawer-repo-item' + (isActive ? ' active' : ''));
    const info = elem('div', 'drawer-repo-item-info');
    const lbl  = elem('div', 'drawer-repo-item-label');
    lbl.textContent = repo.label || `Repo ${i + 1}`;
    const slug = elem('div', 'drawer-repo-item-slug');
    slug.textContent = `${repo.ghOwner}/${repo.ghRepo}`;
    if (isActive) {
      const badge = elem('span', 'drawer-repo-item-badge'); badge.textContent = 'Active';
      lbl.appendChild(badge);
    }
    const stor = state.repoStorage[i] || {};
    const bytes = stor.bytes || 0;
    const limitBytes = stor.limit || (5 * 1024 * 1024 * 1024);
    const pct   = Math.min(100, (bytes / limitBytes) * 100);
    const storEl = elem('div', 'drawer-repo-storage');
    const barEl  = elem('div', 'drawer-repo-storage-bar');
    const fill   = elem('div', 'drawer-repo-storage-fill' + (pct > 90 ? ' warn' : ''));
    fill.style.width = '0%';
    barEl.appendChild(fill);
    const label = elem('div', 'drawer-repo-storage-label');
    label.textContent = bytes ? `${fmtSize(bytes)} used` : 'Usage unavailable';
    storEl.append(barEl, label);
    info.append(lbl, slug, storEl);
    item.appendChild(info);
    item.addEventListener('click', async () => {
      if (isActive) return;
      try {
        const r = await fetch('/api/switch-repo', {
          method: 'POST', credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ repoIdx: i }),
        });
        if (r.ok) { await loadMeta(); loadFiles(true); closeDrawer(); }
        else toast('Could not switch repository.', 'error');
      } catch { toast('Connection error.', 'error'); }
    });
    if (state.allRepos.length > 1) {
      const rmBtn = elem('button', 'drawer-repo-remove-btn');
      rmBtn.title = `Remove ${repo.label || 'this repository'}`;
      rmBtn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>';
      rmBtn.onclick = e => {
        e.stopPropagation();
        showModal(
          `Remove "${repo.label || `Repo ${i + 1}`}"`,
          'Files stay on GitHub — only the connection is removed from StoreGit.',
          'Remove', 'btn-danger',
          async () => {
            try {
              const r = await fetch('/api/remove-repo', {
                method: 'POST', credentials: 'same-origin',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ repoIdx: i }),
              });
              if (r.ok) { toast('Repository removed.', 'ok'); await loadMeta(); loadFiles(true); }
              else toast('Failed to remove.', 'error');
            } catch { toast('Connection error.', 'error'); }
          }
        );
      };
      item.appendChild(rmBtn);
    }
    list.appendChild(item);
    requestAnimationFrame(() => requestAnimationFrame(() => { fill.style.width = pct + '%'; }));
  });
}

export function toggleDrawerAddRepoForm() {
  const form = document.getElementById('drawer-add-repo-form');
  const btn  = document.getElementById('drawer-add-repo-btn');
  if (!form) return;
  const showing = form.style.display !== 'none' && form.style.display !== '';
  if (showing) {
    form.style.display = 'none'; if (btn) btn.textContent = 'Add';
  } else {
    form.style.display = 'flex'; if (btn) btn.textContent = 'Cancel';
    document.getElementById('dar-label')?.focus();
  }
}

export function closeDrawerAddRepoForm() {
  const form = document.getElementById('drawer-add-repo-form');
  const btn  = document.getElementById('drawer-add-repo-btn');
  if (form) form.style.display = 'none';
  if (btn)  btn.textContent = 'Add';
  const err = document.getElementById('dar-error'); if (err) err.textContent = '';
  ['dar-label','dar-owner','dar-repo','dar-branch'].forEach(id => {
    const el = document.getElementById(id); if (el) el.value = id === 'dar-branch' ? 'main' : '';
  });
}

export async function submitDrawerAddRepo() {
  const label  = document.getElementById('dar-label')?.value.trim()  || '';
  const owner  = document.getElementById('dar-owner')?.value.trim()  || '';
  const repo   = document.getElementById('dar-repo')?.value.trim()   || '';
  const branch = document.getElementById('dar-branch')?.value.trim() || 'main';
  const errEl  = document.getElementById('dar-error');
  const btn    = document.getElementById('dar-submit-btn');
  if (errEl) errEl.textContent = '';
  if (!owner || !repo) { if (errEl) errEl.textContent = 'Owner and repository name are required.'; return; }
  btn.disabled = true; btn.innerHTML = '<span class="spinner"></span>';
  try {
    const r = await fetch('/api/add-repo', {
      method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ label, ghOwner: owner, ghRepo: repo, ghBranch: branch }),
    });
    const d = await r.json();
    if (r.ok) {
      toast('Repository added.', 'ok');
      closeDrawerAddRepoForm();
      await loadMeta(); loadFiles(true);
    } else { if (errEl) errEl.textContent = d.error || 'Failed to add repository.'; }
  } catch { if (errEl) errEl.textContent = 'Connection error.'; }
  btn.disabled = false; btn.textContent = 'Add Repository';
}

export async function loadApiKeys() {
  const list = document.getElementById('apikey-list');
  if (!list) return;
  list.innerHTML = '<span class="apikey-empty"><span class="spinner"></span></span>';
  try {
    const r = await fetch('/api/apikeys/list', { credentials: 'same-origin' });
    if (!r.ok) { list.innerHTML = '<span class="apikey-empty">Could not load keys.</span>'; return; }
    const d = await r.json();
    renderApiKeys(d.keys || []);
  } catch { list.innerHTML = '<span class="apikey-empty">Connection error.</span>'; }
}

export function renderApiKeys(keys) {
  const list = document.getElementById('apikey-list');
  if (!list) return;
  list.innerHTML = '';
  if (!keys.length) {
    const e = elem('span', 'apikey-empty'); e.textContent = 'No API keys yet.'; list.appendChild(e); return;
  }
  keys.forEach(key => {
    const item = elem('div', 'apikey-item');
    const top  = elem('div', 'apikey-item-top');
    const lbl  = elem('span', 'apikey-item-label'); lbl.textContent = key.label;
    const rvk  = elem('button', 'apikey-revoke-btn'); rvk.textContent = 'Revoke';
    rvk.onclick = () => {
      showModal(`Revoke "${key.label}"`, 'This key will stop working immediately.', 'Revoke', 'btn-danger', async () => {
        try {
          const r = await fetch('/api/apikeys/revoke', {
            method: 'DELETE', credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ keyId: key.keyId }),
          });
          if (r.ok) { toast('Key revoked.', 'ok'); loadApiKeys(); }
          else toast('Failed to revoke.', 'error');
        } catch { toast('Connection error.', 'error'); }
      });
    };
    top.append(lbl, rvk);
    const prev = elem('div', 'apikey-item-preview'); prev.textContent = key.preview || '';
    const orig = elem('div', 'apikey-item-origins');
    if (!key.allowedOrigins?.length) {
      orig.classList.add('any');
      orig.innerHTML = 'Origins: <span>Any</span>';
    } else {
      orig.innerHTML = `Origins: <span>${key.allowedOrigins.join(', ')}</span>`;
    }
    item.append(top, prev, orig);
    list.appendChild(item);
  });
}

export function toggleApiKeyForm() {
  const form = document.getElementById('apikey-form');
  const btn  = document.getElementById('apikey-new-btn');
  if (!form) return;
  const showing = form.style.display !== 'none' && form.style.display !== '';
  if (showing) { closeApiKeyForm(); }
  else { form.style.display = 'flex'; if (btn) btn.textContent = 'Cancel'; document.getElementById('ak-label')?.focus(); }
}

export function closeApiKeyForm() {
  const form = document.getElementById('apikey-form');
  const btn  = document.getElementById('apikey-new-btn');
  if (form) form.style.display = 'none';
  if (btn)  btn.textContent = 'New Key';
  const err  = document.getElementById('ak-error');  if (err)  err.textContent = '';
  const lbl  = document.getElementById('ak-label');  if (lbl)  lbl.value = '';
  const orig = document.getElementById('ak-origins'); if (orig) orig.value = '';
}

export function hideApiKeyReveal() {
  const box = document.getElementById('apikey-reveal');
  if (box) box.style.display = 'none';
}

export async function submitApiKey() {
  const label      = document.getElementById('ak-label')?.value.trim() || '';
  const originsRaw = document.getElementById('ak-origins')?.value || '';
  const allowed    = originsRaw.split('\n').map(s => s.trim()).filter(s => {
    try { const u = new URL(s); return ALLOWED_SCHEMES.has(u.protocol); } catch { return false; }
  });
  const errEl = document.getElementById('ak-error');
  const btn   = document.getElementById('ak-submit-btn');
  if (errEl) errEl.textContent = '';
  if (!label) { if (errEl) errEl.textContent = 'Please enter a label for this key.'; return; }
  if (originsRaw.trim() && !allowed.length) {
    if (errEl) errEl.textContent = 'Enter valid https:// origins or leave blank for unrestricted.'; return;
  }
  btn.disabled = true; btn.innerHTML = '<span class="spinner"></span>';
  try {
    const r = await fetch('/api/apikeys/create', {
      method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ label, allowedOrigins: allowed }),
    });
    const d = await r.json();
    if (r.ok) {
      closeApiKeyForm();
      const box  = document.getElementById('apikey-reveal');
      const code = document.getElementById('apikey-reveal-code');
      if (box && code) { code.textContent = d.rawKey; box.style.display = 'block'; }
      toast('API key created. Copy it now — it will not be shown again!', 'ok');
      loadApiKeys();
    } else { if (errEl) errEl.textContent = d.error || 'Failed to create API key.'; }
  } catch { if (errEl) errEl.textContent = 'Connection error. Please try again.'; }
  btn.disabled = false; btn.textContent = 'Generate Key';
}
