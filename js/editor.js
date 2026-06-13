import { state }        from './state.js';
import { elem, toast, fileExtRaw, fileColor, fileExt, fmtSize } from './util.js';
import { loadFiles }    from './files.js';

export async function openEditSheet(f) {
  state.editFile = f; state.editSha = null;
  const overlay  = document.getElementById('edit-overlay');
  const textarea = document.getElementById('edit-textarea');
  const nameEl   = document.getElementById('edit-filename');
  const statusEl = document.getElementById('edit-status');
  if (!overlay || !textarea) return;
  nameEl.textContent   = f.originalName || f.name;
  statusEl.textContent = 'Loading…';
  textarea.value       = '';
  textarea.disabled    = true;
  document.getElementById('edit-save-btn').disabled = true;
  overlay.classList.add('open');
  try {
    const r = await fetch(
      `/api/read-text?name=${encodeURIComponent(f.name)}&repoIdx=${state.currentFileRepoIdx}`,
      { credentials: 'same-origin' }
    );
    if (!r.ok) {
      const d = await r.json().catch(() => ({}));
      statusEl.textContent = d.error || 'Failed to load.'; return;
    }
    const d = await r.json();
    state.editSha = d.sha; textarea.value = d.content;
    textarea.disabled = false;
    document.getElementById('edit-save-btn').disabled = false;
    statusEl.textContent = ''; textarea.focus();
  } catch { statusEl.textContent = 'Connection error.'; }
}

export function closeEditSheet() {
  document.getElementById('edit-overlay')?.classList.remove('open');
  state.editFile = null; state.editSha = null;
}

export async function saveEditSheet() {
  if (!state.editFile || !state.editSha) return;
  const textarea = document.getElementById('edit-textarea');
  const statusEl = document.getElementById('edit-status');
  const saveBtn  = document.getElementById('edit-save-btn');
  saveBtn.disabled = true; saveBtn.innerHTML = '<span class="spinner"></span>';
  statusEl.textContent = 'Saving…';
  try {
    const r = await fetch('/api/edit-text', {
      method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: state.editFile.name, content: textarea.value,
        sha: state.editSha, repoIdx: state.currentFileRepoIdx,
      }),
    });
    const d = await r.json().catch(() => ({}));
    if (r.ok) {
      state.editSha = d.sha || state.editSha;
      statusEl.textContent = 'Saved!';
      setTimeout(() => { statusEl.textContent = ''; }, 2000);
      toast('File saved.', 'ok'); loadFiles(true);
    } else if (r.status === 409) {
      statusEl.textContent = 'Conflict — file changed externally. Re-open to reload.';
    } else { statusEl.textContent = d.error || 'Save failed.'; }
  } catch { statusEl.textContent = 'Connection error.'; }
  saveBtn.disabled = false; saveBtn.textContent = 'Save';
}

export function openShareModal(f) {
  state.shareFile = f;
  document.getElementById('share-file-name').textContent    = f.originalName || f.name;
  document.getElementById('share-pre').style.display        = '';
  document.getElementById('share-post').style.display       = 'none';
  document.getElementById('share-spinner').style.display    = 'none';
  document.getElementById('share-create-btn').style.display = '';
  document.getElementById('share-link-input').value         = '';
  document.getElementById('share-exp').textContent          = '';
  document.getElementById('share-overlay').classList.add('open');
}

export function closeShareModal() {
  document.getElementById('share-overlay').classList.remove('open');
}

export async function createShareLink() {
  if (!state.shareFile) return;
  const ttlBtn = document.querySelector('.ttl-opt.active');
  const ttl    = ttlBtn ? parseInt(ttlBtn.dataset.ttl, 10) : 3600;
  document.getElementById('share-spinner').style.display    = 'flex';
  document.getElementById('share-create-btn').style.display = 'none';
  document.getElementById('share-pre').style.display        = 'none';
  try {
    const r = await fetch(
      `/api/share-link?name=${encodeURIComponent(state.shareFile.name)}&ttl=${ttl}&repoIdx=${state.currentFileRepoIdx}`,
      { credentials: 'same-origin' }
    );
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || 'Failed');
    document.getElementById('share-link-input').value = window.location.origin + d.url;
    document.getElementById('share-exp').textContent  = d.exp ? `Expires ${new Date(d.exp).toLocaleString()}` : 'Never expires';
    document.getElementById('share-post').style.display    = '';
    document.getElementById('share-spinner').style.display = 'none';
  } catch (e) {
    toast(e.message || 'Could not create share link.', 'error');
    document.getElementById('share-spinner').style.display    = 'none';
    document.getElementById('share-create-btn').style.display = '';
    document.getElementById('share-pre').style.display        = '';
  }
}

export function copyShareLink() {
  const input = document.getElementById('share-link-input');
  if (!input?.value) return;
  navigator.clipboard?.writeText(input.value)
    .then(() => toast('Link copied.', 'ok'))
    .catch(() => {
      input.select(); document.execCommand('copy'); toast('Link copied.', 'ok');
    });
}
