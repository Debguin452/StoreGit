import { state }                            from './state.js';
import { elem, toast, fmtSize, fileExt, fileExtRaw, fileColor } from './util.js';

let _loadFilesRef = null;
export function setLoadFilesRef(fn) { _loadFilesRef = fn; }

export function precacheSlices(file) {
  if (file.size <= state.CHUNK_SIZE || state.sliceCache.has(file)) return;
  const n = Math.ceil(file.size / state.CHUNK_SIZE);
  state.sliceCache.set(file, Array.from({ length: n }, (_, i) =>
    file.slice(i * state.CHUNK_SIZE, Math.min((i + 1) * state.CHUNK_SIZE, file.size))
  ));
}

export function getSmartRepoIdx() {
  if (state.allRepos.length <= 1 || !state.repoFiles.length) return 0;
  let minSize = Infinity, minIdx = 0;
  for (const g of state.repoFiles) {
    const total = (g.files || []).filter(f => f.name !== '.storegit')
                                 .reduce((s, f) => s + (f.size || 0), 0);
    if (total < minSize) { minSize = total; minIdx = g.repoIdx; }
  }
  return minIdx;
}

export function onFilePicked(files) {
  const arr     = Array.from(files);
  const skipped = arr.filter(f => f.size > state.MAX_FILE_SIZE);
  const valid   = arr.filter(f => f.size <= state.MAX_FILE_SIZE);
  skipped.forEach(f => toast(`${f.name} exceeds the maximum file size.`, 'error'));
  valid.forEach(f => {
    if (state.uploadPending.some(p => p.file.name === f.name && p.file.size === f.size)) return;
    state.uploadPending.push({ file: f, status: 'queued', progress: 0, id: Math.random().toString(36).slice(2) });
    precacheSlices(f);
  });
  renderQueue();
  const acts = document.getElementById('upload-actions');
  if (acts) acts.style.display = state.uploadPending.length ? 'flex' : 'none';
}

export function renderQueue() {
  const q = document.getElementById('upload-queue');
  if (!q) return;
  q.innerHTML = '';
  q.style.display = state.uploadPending.length ? 'block' : 'none';
  state.uploadPending.forEach(item => {
    const row  = elem('div', 'queue-item');
    const icon = elem('div', 'queue-file-icon');
    const ext  = fileExtRaw(item.file.name);
    icon.textContent      = fileExt(item.file.name);
    icon.style.background = fileColor(ext);
    icon.style.color      = '#fff';
    const info = elem('div', 'queue-info');
    const nm   = elem('div', 'queue-name'); nm.textContent = item.file.name;
    const sz   = elem('div', 'queue-size'); sz.textContent = fmtSize(item.file.size);
    const bar  = elem('div', 'queue-bar');
    const fill = elem('div', 'queue-fill');
    if (item.status === 'uploading') {
      fill.style.width = item.progress + '%'; fill.classList.add('wave');
    } else if (item.status === 'done') {
      fill.style.width = '100%'; fill.classList.remove('wave');
    }
    bar.appendChild(fill);
    info.append(nm, sz, bar);
    const status = elem('div', 'queue-status');
    if      (item.status === 'queued')    { status.className = 'queue-status wait'; status.textContent = 'Queued'; }
    else if (item.status === 'uploading') { status.className = 'queue-status go';   status.textContent = item.progress + '%'; }
    else if (item.status === 'done')      { status.className = 'queue-status ok';   status.textContent = 'Done'; }
    else if (item.status === 'error') {
      status.className = 'queue-status fail'; status.textContent = 'Failed';
      const retry = elem('button', 'queue-retry-btn');
      retry.textContent = 'Retry';
      retry.onclick = () => {
        item.status = 'queued'; item.progress = 0; renderQueue();
        const a = document.getElementById('upload-actions');
        if (a) a.style.display = 'flex';
      };
      row.appendChild(retry);
    }
    row.append(icon, info, status);
    q.appendChild(row);
  });
}

export function clearQueue() {
  if (state.uploadActive) return;
  state.uploadPending = [];
  const q = document.getElementById('upload-queue');
  if (q) q.style.display = 'none';
  const a = document.getElementById('upload-actions');
  if (a) a.style.display = 'none';
}

export function togglePause() {
  if (!state.uploadActive) return;
  state.uploadPaused = !state.uploadPaused;
  const btn = document.getElementById('pause-btn');
  if (btn) btn.textContent = state.uploadPaused ? 'Resume' : 'Pause';
}

export async function startUpload() {
  if (state.uploadActive || !state.uploadPending.length) return;
  state.uploadActive = true;
  const upBtn   = document.getElementById('upload-btn');
  const pausBtn = document.getElementById('pause-btn');
  if (upBtn)   upBtn.disabled = true;
  if (pausBtn) pausBtn.style.display = '';
  const items = state.uploadPending.filter(i => i.status === 'queued');
  for (const item of items) {
    if (state.uploadAbortFn) { state.uploadActive = false; break; }
    while (state.uploadPaused) {
      await new Promise(r => setTimeout(r, 200));
      if (!state.uploadActive) break;
    }
    if (!state.uploadActive) break;
    item.status = 'uploading'; renderQueue();
    try {
      const repoIdx = getSmartRepoIdx();
      if (item.file.size > state.CHUNK_THRESHOLD) {
        await _uploadChunked(item, repoIdx);
      } else {
        await _uploadFile(item, repoIdx);
      }
      item.status = 'done'; item.progress = 100;
    } catch { item.status = 'error'; }
    renderQueue();
  }
  state.uploadActive = false;
  if (upBtn)   upBtn.disabled = false;
  if (pausBtn) pausBtn.style.display = 'none';
  const allDone = state.uploadPending.every(i => i.status === 'done' || i.status === 'error');
  if (allDone) {
    const ok  = state.uploadPending.some(i => i.status === 'done');
    const bad = state.uploadPending.some(i => i.status === 'error');
    if (ok)  { toast('Upload complete.', 'ok');  if (_loadFilesRef) _loadFilesRef(true); }
    if (bad) toast('Some files failed. Tap Retry.', 'error');
  }
  renderQueue();
}

async function _uploadFile(item, repoIdx) {
  const content = await readAsBase64(item.file);
  item.progress = 50; renderQueue();
  const r = await fetch('/api/upload', {
    method: 'POST', credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: item.file.name, content, repoIdx }),
  });
  if (!r.ok) { const d = await r.json().catch(() => ({})); throw new Error(d.error || 'upload failed'); }
  item.progress = 100;
}

async function _uploadChunked(item, repoIdx) {
  const file        = item.file;
  const totalChunks = Math.ceil(file.size / state.CHUNK_SIZE);
  const slices = state.sliceCache.get(file) ||
    Array.from({ length: totalChunks }, (_, i) =>
      file.slice(i * state.CHUNK_SIZE, Math.min((i + 1) * state.CHUNK_SIZE, file.size))
    );
  const ir = await fetch('/api/upload-chunked/init', {
    method: 'POST', credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: file.name, totalChunks, totalSize: file.size, repoIdx }),
  });
  if (!ir.ok) throw new Error('init failed');
  const { uploadId } = await ir.json();
  let uploaded = 0;
  const conc = state.UPLOAD_CONCURRENCY;
  for (let start = 0; start < totalChunks; start += conc) {
    await Promise.all(slices.slice(start, start + conc).map(async (slice, bi) => {
      const idx     = start + bi;
      const content = await readAsBase64(slice);
      const cr      = await fetch('/api/upload-chunked/chunk', {
        method: 'POST', credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ uploadId, chunkIndex: idx, content }),
      });
      if (!cr.ok) throw new Error('chunk failed');
      uploaded++; item.progress = Math.round(uploaded / totalChunks * 90); renderQueue();
    }));
  }
  item.progress = 92; renderQueue();
  const fr = await fetch('/api/upload-chunked/finalize', {
    method: 'POST', credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ uploadId }),
  });
  if (!fr.ok) throw new Error((await fr.json().catch(() => ({}))).error || 'finalize failed');
}

export function readAsBase64(blob) {
  return new Promise((res, rej) => {
    const r = new FileReader();
    r.onload  = e => res(e.target.result.split(',')[1]);
    r.onerror = () => rej(new Error('Read failed'));
    r.readAsDataURL(blob);
  });
}
