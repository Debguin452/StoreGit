import { state }                                                    from './state.js';
import { on, toast, showModal }                                    from './util.js';
import { loadFiles, closeFileDetail, showCreateFolderModal, moveFileToFolderUI } from './files.js';
import { onFilePicked, clearQueue, togglePause, startUpload, setLoadFilesRef } from './upload.js';
import { openDrawer, closeDrawer, loadMeta, toggleDrawerAddRepoForm, closeDrawerAddRepoForm,
         submitDrawerAddRepo, loadApiKeys, toggleApiKeyForm, closeApiKeyForm,
         submitApiKey }                                            from './drawer.js';
import { openEditSheet, closeEditSheet, saveEditSheet,
         openShareModal, closeShareModal, createShareLink, copyShareLink } from './editor.js';

setLoadFilesRef(loadFiles);

(async () => {
  try {
    const r = await fetch('/api/status');
    const d = await r.json();
    if (d.uploadConcurrency > 0)  state.UPLOAD_CONCURRENCY = d.uploadConcurrency;
    if (d.distThresholdBytes > 0) state.CHUNK_THRESHOLD    = Math.round(d.distThresholdBytes * 3 / 4);
  } catch {}
  try {
    const r = await fetch('/api/me', { credentials: 'same-origin' });
    if (r.ok) { await _boot(await r.json()); return; }
  } catch {}
  window.location.replace('/');
})();

async function _boot() {
  await loadMeta();
  loadFiles();
  loadApiKeys();
}

async function doLogout() {
  try { await fetch('/api/logout', { method: 'POST', credentials: 'same-origin' }); } catch {}
  sessionStorage.setItem('sg_logged_out', '1');
  window.location.replace('/');
}

on('signout-btn', 'click', () => {
  showModal('Sign out', 'Are you sure you want to sign out?', 'Sign out', 'btn-danger', doLogout);
});
on('file-input',          'change', e  => { onFilePicked(e.target.files); e.target.value = ''; });
on('upload-btn',          'click', () => startUpload());
on('clear-queue-btn',     'click', () => clearQueue());
on('refresh-files-btn',   'click', () => loadFiles(true));
on('new-folder-btn',      'click', () => showCreateFolderModal());
on('pause-btn',           'click', () => togglePause());
on('hamburger-btn',       'click', () => openDrawer());
on('drawer-close-btn',    'click', () => closeDrawer());
on('drawer-overlay',      'click', () => closeDrawer());
on('drawer-add-repo-btn', 'click', () => toggleDrawerAddRepoForm());
on('dar-cancel-btn',      'click', () => closeDrawerAddRepoForm());
on('dar-submit-btn',      'click', () => submitDrawerAddRepo());
on('apikey-new-btn',      'click', () => toggleApiKeyForm());
on('ak-cancel-btn',       'click', () => closeApiKeyForm());
on('ak-submit-btn',       'click', () => submitApiKey());
on('apikey-copy-btn',     'click', () => {
  const code = document.getElementById('apikey-reveal-code');
  if (code) navigator.clipboard?.writeText(code.textContent)
    .then(() => toast('API key copied.', 'ok')).catch(() => {});
});
on('fd-overlay',          'click', e  => { if (e.target === e.currentTarget) closeFileDetail(); });
on('fd-close-btn',        'click', () => closeFileDetail());
on('fd-share-btn',        'click', () => state.shareFile && openShareModal(state.shareFile));
on('fd-edit-btn',         'click', () => state.shareFile && openEditSheet(state.shareFile));
on('edit-close-btn',      'click', () => closeEditSheet());
on('edit-save-btn',       'click', () => saveEditSheet());
on('share-close-btn',     'click', () => closeShareModal());
on('share-create-btn',    'click', () => createShareLink());
on('share-copy-btn',      'click', () => copyShareLink());
on('modal-cancel-btn',    'click', () => document.getElementById('modal-overlay')?.classList.remove('open'));

document.getElementById('share-ttl-opts')?.addEventListener('click', e => {
  const btn = e.target.closest('.ttl-opt'); if (!btn) return;
  document.querySelectorAll('.ttl-opt').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
});

const dropZone = document.getElementById('drop-zone');
if (dropZone) {
  dropZone.addEventListener('dragover',  e => { e.preventDefault(); dropZone.classList.add('drag-over'); });
  dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag-over'));
  dropZone.addEventListener('drop',      e => {
    e.preventDefault(); dropZone.classList.remove('drag-over');
    if (e.dataTransfer?.files?.length) onFilePicked(e.dataTransfer.files);
  });
}

document.addEventListener('paste', e => {
  const files = [];
  for (const item of e.clipboardData?.items || [])
    if (item.kind === 'file') { const f = item.getAsFile(); if (f) files.push(f); }
  if (files.length) onFilePicked(files);
});
