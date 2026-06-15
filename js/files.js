import { state }                       from './state.js';
import { elem, toast, showModal, fmtSize, fmtDate, fileExt, fileExtRaw, fileColor,
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

export function renderFiles() {
  const el = document.getElementById('file-list');
  if (!el) return;
  el.innerHTML = '';
  const all = state.repoFiles.flatMap(g =>
    (g.files || [])
      .filter(f => f.name !== '.storegit' && !f.name.startsWith('.sgkeys/'))
      .map(f => ({ ...f, _repoIdx: g.repoIdx }))
  );
  if (!all.length) {
    el.innerHTML =
      '<div class="empty-state">' +
      '<div class="empty-state-icon"><svg viewBox="0 0 40 40" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">' +
      '<rect x="8" y="6" width="24" height="28" rx="3"/>' +
      '<line x1="14" y1="14" x2="26" y2="14"/><line x1="14" y1="20" x2="26" y2="20"/><line x1="14" y1="26" x2="20" y2="26"/>' +
      '</svg></div><p>No files yet.<br>Upload your first file above.</p></div>';
    return;
  }
  all.sort((a, b) => {
    const at = a.uploadedAt || a.name, bt = b.uploadedAt || b.name;
    return at < bt ? 1 : at > bt ? -1 : 0;
  });
  all.forEach(f => el.appendChild(buildFileRow(f)));
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
  const editBtn = document.getElementById('fd-edit-btn');
  if (editBtn) {
    const canEdit = FD_EDITABLE.has(ext) && !f.chunked && (f.size || 0) <= 1_000_000;
    editBtn.style.display = canEdit ? '' : 'none';
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
  fnEl.textContent  = displayName;
  fill.style.width  = '0%';
  lbl.textContent   = 'Preparing…';
  bar.classList.add('active');
  try {
    const r = await fetch(`/api/download?name=${encodeURIComponent(name)}&repoIdx=${repoIdx}`, { credentials: 'same-origin' });
    if (r.status === 401) { window.location.replace('/'); return; }
    if (!r.ok) { toast('Download failed.', 'error'); return; }
    const d = await r.json();
    if (d.chunked) {
      const chunks = [];
      for (let i = 0; i < d.totalChunks; i++) {
        fill.style.width = Math.round(i / d.totalChunks * 90) + '%';
        lbl.textContent  = `Part ${i + 1} of ${d.totalChunks}…`;
        const cr = await fetch(d.chunkUrls[i]);
        if (!cr.ok) throw new Error();
        chunks.push(await cr.arrayBuffer());
      }
      fill.style.width = '100%'; lbl.textContent = 'Assembling…';
      _triggerDownload(URL.createObjectURL(new Blob(chunks)), displayName);
    } else {
      fill.style.width = '80%'; lbl.textContent = 'Downloading…';
      const fr = await fetch(d.url);
      _triggerDownload(URL.createObjectURL(new Blob([await fr.arrayBuffer()])), displayName);
      fill.style.width = '100%';
    }
  } catch { toast('Download failed.', 'error'); }
  setTimeout(() => bar.classList.remove('active'), 1200);
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
