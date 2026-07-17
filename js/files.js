import { state }                       from './state.js';
import { elem, toast, showModal, showModalHtml, fmtSize, fmtDate, fileExt, fileExtRaw, fileColor,
         FD_EDITABLE, FD_IMG, FD_AUDIO, FD_VIDEO, FD_TEXT } from './util.js';

export function buildFileRow(f) {
  const row  = elem('div', 'file-row');
  const badge = elem('div', 'file-type-badge');
  const displayName  = f.originalName || f.name;
  const ext          = fileExtRaw(displayName);
  badge.textContent       = fileExt(displayName);
  badge.style.background  = fileColor(ext);
  badge.style.color       = '#fff';
  const info = elem('div', 'file-info');
  const nm   = elem('div', 'file-name'); nm.textContent = displayName; nm.title = displayName;
  const date = fmtDate(f.uploadedAt);
  const mt   = elem('div', 'file-meta');
  mt.textContent = date ? `${fmtSize(f.size)} · ${date}` : fmtSize(f.size);
  const chev = elem('div', 'file-chevron');
  chev.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="14" height="14"><polyline points="9 18 15 12 9 6"/></svg>';
  info.append(nm, mt);
  row.append(badge, info, chev);
  row.addEventListener('click', () => openFileDetail(f));
  return row;
}

export async function loadFiles(force = false) {
  const el = document.getElementById('file-list');
  if (!el) return;
  if (!force && state.repoFiles.length && Date.now() - state.filesCachedAt < state.FILES_CACHE_TTL) {
    renderFiles(); return;
  }
  el.innerHTML = '<div class="loading-row"><span class="spinner"></span> Loading…</div>';
  try {
    if (state.allRepos.length <= 1) {
      const r = await fetch('/api/files', { credentials: 'same-origin' });
      if (r.status === 401) { window.location.replace('/'); return; }
      if (!r.ok) throw new Error();
      state.repoFiles = [{ repo: state.allRepos[0] || null, repoIdx: 0, files: await r.json() }];
    } else {
      const results = await Promise.allSettled(
        state.allRepos.map((repo, i) =>
          fetch(`/api/files?repoIdx=${i}`, { credentials: 'same-origin' })
            .then(r => { if (r.status === 401) { window.location.replace('/'); throw new Error(); } return r.json(); })
            .then(files => ({ repo, repoIdx: i, files }))
        )
      );
      state.repoFiles = results.filter(r => r.status === 'fulfilled').map(r => r.value);
    }
    state.filesCachedAt = Date.now();
    renderFiles();
  } catch { el.innerHTML = '<div class="empty-state"><p>Could not load files.</p></div>'; }
}



export function openFileDetail(f) {
  state.shareFile        = f;
  state.currentFileRepoIdx = f._repoIdx !== undefined ? f._repoIdx : 0;
  const displayName = f.originalName || f.name;
  const ext = fileExtRaw(displayName);
  const iconEl = document.getElementById('fd-icon');
  iconEl.textContent      = fileExt(displayName);
  iconEl.style.background = fileColor(ext);
  iconEl.style.color      = '#fff';
  document.getElementById('fd-name').textContent = displayName;
  document.getElementById('fd-meta').textContent = fmtSize(f.size);
  document.getElementById('fd-dl-btn').onclick = () =>
    downloadFile(f.name, f.size, displayName, state.currentFileRepoIdx);
  document.getElementById('fd-del-btn').onclick = () => {
    closeFileDetail();
    setTimeout(() => deleteFile(f.name, f.sha, f.chunked || false, displayName, state.currentFileRepoIdx), 250);
  };
  const moveBtn = document.getElementById('fd-move-btn');
  if (moveBtn) moveBtn.onclick = () => { closeFileDetail(); setTimeout(() => moveFileToFolderUI(f), 250); };
  const editBtn = document.getElementById('fd-edit-btn');
  const fdActions = document.getElementById('fd-actions') || editBtn?.closest('.fd-actions');
  if (editBtn) {
    const canEdit = FD_EDITABLE.has(ext) && !f.chunked && (f.size || 0) <= 1_000_000;
    editBtn.style.display = canEdit ? '' : 'none';
    // 5 buttons: Delete spans full width. 4 buttons: 2x2 grid, no spanning.
    if (fdActions) fdActions.classList.toggle('fd-5btn', canEdit);
  }
  document.getElementById('fd-preview').innerHTML =
    '<div class="fd-preview-loading"><span class="spinner"></span> Loading preview…</div>';
  document.getElementById('fd-overlay').classList.add('open');
  loadFilePreview(f);
}

export function closeFileDetail() {
  document.getElementById('fd-overlay').classList.remove('open');
}

export async function loadFilePreview(f) {
  const el  = document.getElementById('fd-preview');
  const ext = fileExtRaw(f.originalName || f.name);
  const cacheKey = `${f._repoIdx ?? 0}:${f.name}`;
  const noPreview = msg => {
    const p = elem('div', 'fd-preview-none'); p.textContent = msg; el.replaceChildren(p);
  };
  if (!f.chunked) {
    const fetchBlob = async () => {
      if (state.previewCache.has(cacheKey)) return state.previewCache.get(cacheKey);
      const r = await fetch(
        `/api/download?name=${encodeURIComponent(f.name)}&inline=1&repoIdx=${state.currentFileRepoIdx}`,
        { credentials: 'same-origin' }
      );
      if (!r.ok) throw new Error();
      const url = URL.createObjectURL(await r.blob());
      state.previewCache.set(cacheKey, url);
      return url;
    };
    if (FD_IMG.has(ext)) {
      if (f.size > 20 * 1024 * 1024) { noPreview('Image too large to preview.'); return; }
      if (state.previewCache.has(cacheKey)) {
        const img = elem('img', 'fd-preview-img');
        img.alt = f.name; img.src = state.previewCache.get(cacheKey);
        el.replaceChildren(img); return;
      }
      el.innerHTML = '<div class="fd-preview-loading"><span class="spinner"></span></div>';
      try {
        const blobUrl = await fetchBlob();
        const img = elem('img', 'fd-preview-img');
        img.alt = f.name;
        img.onerror = () => { state.previewCache.delete(cacheKey); noPreview('Could not load image.'); };
        el.replaceChildren(img); img.src = blobUrl;
      } catch { noPreview('Preview unavailable.'); }
      return;
    }
    if (FD_AUDIO.has(ext)) {
      const btn = elem('button', 'btn btn-outline fd-tap-load');
      btn.textContent = state.previewCache.has(cacheKey) ? 'Tap to play audio' : 'Tap to load audio';
      btn.onclick = async () => {
        btn.disabled = true; btn.textContent = 'Loading…';
        try {
          const blobUrl = await fetchBlob();
          const a = elem('audio', 'fd-preview-audio');
          a.controls = true; a.preload = 'metadata';
          a.onerror = () => { state.previewCache.delete(cacheKey); noPreview('Could not load audio.'); };
          el.replaceChildren(a); a.src = blobUrl;
        } catch { noPreview('Could not load audio.'); }
      };
      el.replaceChildren(btn); return;
    }
    if (FD_VIDEO.has(ext)) {
      const btn = elem('button', 'btn btn-outline fd-tap-load');
      btn.textContent = state.previewCache.has(cacheKey) ? 'Tap to play video' : 'Tap to load video';
      btn.onclick = async () => {
        btn.disabled = true; btn.textContent = 'Loading…';
        try {
          const blobUrl = await fetchBlob();
          const v = elem('video', 'fd-preview-video');
          v.controls = true; v.preload = 'metadata';
          v.onerror = () => { state.previewCache.delete(cacheKey); noPreview('Could not load video.'); };
          el.replaceChildren(v); v.src = blobUrl;
        } catch { noPreview('Could not load video.'); }
      };
      el.replaceChildren(btn); return;
    }
    if (FD_TEXT.has(ext) && f.size <= 200_000) {
      const textKey = cacheKey + ':text';
      if (state.previewCache.has(textKey)) {
        const pre = elem('pre', 'fd-preview-code');
        pre.textContent = state.previewCache.get(textKey);
        el.replaceChildren(pre); return;
      }
      el.innerHTML = '<div class="fd-preview-loading"><span class="spinner"></span></div>';
      try {
        const r = await fetch(
          `/api/download?name=${encodeURIComponent(f.name)}&inline=1&repoIdx=${state.currentFileRepoIdx}`,
          { credentials: 'same-origin' }
        );
        if (!r.ok) { noPreview('Could not load preview.'); return; }
        const raw  = await r.text();
        const text = raw.length > 6000 ? raw.slice(0, 6000) + '\n\n… (truncated)' : raw;
        state.previewCache.set(textKey, text);
        const pre  = elem('pre', 'fd-preview-code');
        pre.textContent = text;
        el.replaceChildren(pre);
      } catch { noPreview('Could not load preview.'); }
      return;
    }
  }
  noPreview('No preview available. Download to open.');
}

export async function downloadFile(name, size, displayName, repoIdx) {
  const bar  = document.getElementById('dl-bar');
  const fill = document.getElementById('dl-fill');
  const lbl  = document.getElementById('dl-label');
  const fnEl = document.getElementById('dl-filename');
  fnEl.textContent = displayName;
  fill.style.width = '0%';
  lbl.textContent  = 'Preparing…';
  bar.classList.add('active');
  try {
    const r = await fetch(`/api/download?name=${encodeURIComponent(name)}&repoIdx=${repoIdx}`, { credentials: 'same-origin' });
    if (r.status === 401) { window.location.replace('/'); return; }
    if (!r.ok) {
      let msg = 'Download failed.';
      try { const d = await r.json(); if (d.error) msg = d.error; } catch {}
      toast(msg, 'error');
      return;
    }
    // Server streams the file directly — read with progress tracking
    const contentLength = parseInt(r.headers.get('content-length') || '0', 10);
    const reader  = r.body.getReader();
    const chunks  = [];
    let received  = 0;
    lbl.textContent = 'Downloading…';
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
      received += value.length;
      if (contentLength > 0) {
        fill.style.width = Math.min(99, Math.round(received / contentLength * 100)) + '%';
        lbl.textContent  = _fmtBytes(received) + (contentLength ? ' / ' + _fmtBytes(contentLength) : '');
      } else {
        fill.style.width = '60%';
        lbl.textContent  = _fmtBytes(received) + ' received…';
      }
    }
    fill.style.width = '100%';
    lbl.textContent  = 'Saving…';
    // Derive filename from Content-Disposition if available
    const cd = r.headers.get('content-disposition') || '';
    const cdMatch = cd.match(/filename\*=UTF-8''([^;]+)/i) || cd.match(/filename="?([^";]+)"?/i);
    const saveName = cdMatch ? decodeURIComponent(cdMatch[1]) : displayName;
    const mime = r.headers.get('content-type') || 'application/octet-stream';
    _triggerDownload(URL.createObjectURL(new Blob(chunks, { type: mime })), saveName);
  } catch (e) {
    toast('Download failed' + (e?.message ? ': ' + e.message : '.'), 'error');
  }
  setTimeout(() => bar.classList.remove('active'), 1400);
}

function _fmtBytes(n) {
  if (n < 1024)       return n + ' B';
  if (n < 1048576)    return (n / 1024).toFixed(1) + ' KB';
  if (n < 1073741824) return (n / 1048576).toFixed(1) + ' MB';
  return (n / 1073741824).toFixed(2) + ' GB';
}

function _triggerDownload(url, name) {
  const a = document.createElement('a'); a.href = url; a.download = name;
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 10000);
}

export function deleteFile(name, sha, chunked, displayName, repoIdx) {
  showModal(
    `Delete "${displayName}"`,
    'This permanently deletes the file from your GitHub repository.',
    'Delete', 'btn-danger',
    async () => {
      try {
        const r = await fetch('/api/delete', {
          method: 'DELETE', credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name, sha, chunked, repoIdx }),
        });
        if (r.status === 401) { window.location.replace('/'); return; }
        if (r.ok) {
          const ck = `${repoIdx}:${name}`;
          state.previewCache.delete(ck);
          state.previewCache.delete(ck + ':text');
          toast('File deleted.', 'ok'); loadFiles(true);
        }
        else toast('Delete failed.', 'error');
      } catch { toast('Connection error.', 'error'); }
    }
  );
}

export let currentFolder = '';

export function setCurrentFolder(f) { currentFolder = f; renderFiles(); }

export function getFolderGroups(files) {
  const folders = new Map();
  const root    = [];
  for (const f of files) {
    const parts = (f.originalName || f.name).split('/');
    if (parts.length > 1) {
      const dir = parts[0];
      if (!folders.has(dir)) folders.set(dir, []);
      folders.get(dir).push({ ...f, _displayName: parts.slice(1).join('/') });
    } else {
      root.push(f);
    }
  }
  return { folders, root };
}

export function renderBreadcrumb() {
  const bc = document.getElementById('folder-breadcrumb');
  if (!bc) return;
  bc.innerHTML = '';
  const home = document.createElement('span');
  home.className = 'bc-item bc-link';
  home.textContent = 'All files';
  home.onclick = () => { currentFolder = ''; renderFiles(); };
  bc.appendChild(home);
  if (currentFolder) {
    const sep = document.createElement('span');
    sep.textContent = ' / ';
    sep.className = 'bc-sep';
    const name = document.createElement('span');
    name.className = 'bc-item bc-current';
    name.textContent = currentFolder;
    bc.append(sep, name);
  }
}

export function buildFolderRow(name, count) {
  const row   = elem('div', 'file-row folder-row');
  const badge = elem('div', 'file-type-badge folder-badge');
  badge.innerHTML = '<svg viewBox="0 0 24 24" fill="currentColor" width="18" height="18"><path d="M10 4H2v16h20V6H12l-2-2z"/></svg>';
  const info = elem('div', 'file-info');
  const nm   = elem('div', 'file-name'); nm.textContent = name;
  const mt   = elem('div', 'file-meta'); mt.textContent = `${count} file${count !== 1 ? 's' : ''}`;
  const chev = elem('div', 'file-chevron');
  chev.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="14" height="14"><polyline points="9 18 15 12 9 6"/></svg>';
  const del = elem('button', 'folder-del-btn');
  del.title = 'Delete folder';
  del.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" width="14" height="14"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14H6L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/></svg>';
  del.onclick = e => { e.stopPropagation(); deleteFolderUI(name); };
  info.append(nm, mt);
  row.append(badge, info, del, chev);
  row.onclick = () => { currentFolder = name; renderFiles(); };
  return row;
}

export function renderFiles() {
  const el = document.getElementById('file-list');
  if (!el) return;
  el.innerHTML = '';

  renderBreadcrumb();

  const all = state.repoFiles.flatMap(g =>
    (g.files || [])
      .filter(f => f.name !== '.storegit' && !f.name.startsWith('.sgkeys/') && !f.name.endsWith('/.storegit') && !f.name.endsWith('/.gitkeep') && f.name !== '.gitkeep')
      .map(f => ({ ...f, _repoIdx: g.repoIdx }))
  );

  if (!all.length) {
    el.innerHTML = '<div class="empty-state"><div class="empty-state-icon"><svg viewBox="0 0 40 40" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="8" y="6" width="24" height="28" rx="3"/><line x1="14" y1="14" x2="26" y2="14"/><line x1="14" y1="20" x2="26" y2="20"/><line x1="14" y1="26" x2="20" y2="26"/></svg></div><p>No files yet.<br>Upload your first file above.</p></div>';
    return;
  }

  if (currentFolder) {
    const prefix = currentFolder + '/';
    const inFolder = all.filter(f => (f.originalName || f.name).startsWith(prefix));
    if (!inFolder.length) {
      el.innerHTML = `<div class="empty-state"><p>Folder "${currentFolder}" is empty.</p></div>`;
      return;
    }
    inFolder.sort((a,b) => { const at=a.uploadedAt||a.name,bt=b.uploadedAt||b.name; return at<bt?1:at>bt?-1:0; });
    inFolder.forEach(f => {
      const display = { ...f, originalName: (f.originalName||f.name).slice(prefix.length) };
      el.appendChild(buildFileRow(display));
    });
    return;
  }

  const { folders, root } = getFolderGroups(all);
  all.sort((a,b) => { const at=a.uploadedAt||a.name,bt=b.uploadedAt||b.name; return at<bt?1:at>bt?-1:0; });

  for (const [name, files] of [...folders.entries()].sort()) {
    el.appendChild(buildFolderRow(name, files.length));
  }
  root.sort((a,b) => { const at=a.uploadedAt||a.name,bt=b.uploadedAt||b.name; return at<bt?1:at>bt?-1:0; });
  root.forEach(f => el.appendChild(buildFileRow(f)));
}

export function showCreateFolderModal(repoIdx = 0, afterCreate = null) {
  showModalHtml(
    'New Folder',
    `<label class="modal-field-label">Folder name</label>
     <input id="new-folder-name" class="modal-input" placeholder="e.g. photos" autocomplete="off">`,
    'Create', 'btn-primary',
    async () => {
      const name = document.getElementById('new-folder-name')?.value?.trim();
      if (!name) return;
      const safe = name.replace(/[^a-zA-Z0-9_/\-]/g, '-').replace(/\/+/g, '/').replace(/^\/|\/$/g, '');
      try {
        const r = await fetch('/api/mkdir', {
          method: 'POST', credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ path: safe, repoIdx }),
        });
        if (r.ok) { toast(`Folder "${safe}" created.`, 'ok'); loadFiles(true); if (afterCreate) afterCreate(safe); }
        else { const d = await r.json().catch(()=>{}); toast(d?.error || 'Failed to create folder.', 'error'); }
      } catch { toast('Connection error.', 'error'); }
    }
  );
  setTimeout(() => document.getElementById('new-folder-name')?.focus(), 80);
}

export function deleteFolderUI(name) {
  showModal(
    `Delete folder "${name}"`,
    'This permanently deletes the folder and all its contents.',
    'Delete', 'btn-danger',
    async () => {
      try {
        const r = await fetch('/api/rmdir', {
          method: 'DELETE', credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ path: name, repoIdx: 0 }),
        });
        if (r.ok) { toast('Folder deleted.', 'ok'); currentFolder = ''; loadFiles(true); }
        else toast('Delete failed.', 'error');
      } catch { toast('Connection error.', 'error'); }
    }
  );
}

export function moveFileToFolderUI(f) {
  const all = state.repoFiles.flatMap(g => (g.files || []).map(x => x.name));
  const folderSet = new Set();
  folderSet.add('');
  for (const n of all) {
    const parts = n.split('/');
    if (parts.length > 1) folderSet.add(parts[0]);
  }
  const folders = [...folderSet].filter(x => x !== (f.originalName || f.name).split('/')[0] || (f.originalName || f.name).split('/').length === 1);
  const chips = folders.map(dir => {
    const label = dir === '' ? '/ (root)' : dir;
    return `<button type="button" class="folder-chip" data-dir="${dir}">${label}</button>`;
  }).join('');
  showModalHtml(
    'Move File',
    `<p class="modal-field-label">Choose destination folder</p>
     <div class="folder-chips" id="move-chips">${chips}</div>
     <div style="display:flex;gap:8px;align-items:center;margin-top:10px">
       <input id="move-folder-dest" class="modal-input" placeholder="Or type a folder name…" autocomplete="off" style="flex:1">
       <button type="button" class="btn btn-ghost btn-sm" id="move-mkdir-btn">+ New</button>
     </div>`,
    'Move', 'btn-primary',
    async () => {
      const dest = document.getElementById('move-folder-dest')?.value?.trim();
      const displayName = f.originalName || f.name;
      const basename    = displayName.includes('/') ? displayName.split('/').pop() : displayName;
      const destName    = dest ? `${dest}/${basename}` : basename;
      try {
        const r = await fetch('/api/move', {
          method: 'POST', credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name: f.name, destName, srcRepoIdx: f._repoIdx ?? 0, destRepoIdx: f._repoIdx ?? 0 }),
        });
        if (r.ok) { toast('File moved.', 'ok'); loadFiles(true); }
        else { const d = await r.json().catch(()=>{}); toast(d?.error || 'Move failed.', 'error'); }
      } catch { toast('Connection error.', 'error'); }
    }
  );
  setTimeout(() => {
    document.querySelectorAll('.folder-chip').forEach(btn => {
      btn.onclick = () => {
        document.querySelectorAll('.folder-chip').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        document.getElementById('move-folder-dest').value = btn.dataset.dir;
      };
    });
    document.getElementById('move-mkdir-btn')?.addEventListener('click', () => {
      showCreateFolderModal(f._repoIdx ?? 0, (name) => {
        document.getElementById('move-folder-dest').value = name;
      });
    });
  }, 80);
}
