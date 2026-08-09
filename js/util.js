export function elem(tag, cls) {
  const el = document.createElement(tag);
  if (cls) el.className = cls;
  return el;
}

export function on(id, evt, fn) {
  document.getElementById(id)?.addEventListener(evt, fn);
}

export function toast(msg, type) {
  const el = document.getElementById('toast');
  if (!el) return;
  el.textContent = String(msg).slice(0, 120);
  el.className   = `toast show${type ? ' ' + type : ''}`;
  clearTimeout(el._t);
  el._t = setTimeout(() => { el.className = 'toast'; }, 3500);
}

export function showModal(title, msg, confirmLabel, confirmClass, onConfirm) {
  document.getElementById('modal-title').textContent = title;
  document.getElementById('modal-msg').textContent   = msg;
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

export function showModalHtml(title, htmlContent, confirmLabel, confirmClass, onConfirm) {
  document.getElementById('modal-title').textContent = title;
  document.getElementById('modal-msg').innerHTML     = htmlContent;
  const overlay    = document.getElementById('modal-overlay');
  const confirmBtn = document.getElementById('modal-confirm-btn');
  confirmBtn.textContent = confirmLabel;
  confirmBtn.className   = 'btn ' + confirmClass;
  overlay.classList.add('open');
  const close = () => { overlay.classList.remove('open'); document.getElementById('modal-msg').innerHTML = ''; };
  // onConfirm can return `false` (or a Promise resolving to `false`) to keep
  // the modal open — used for inline validation errors, e.g. an empty name.
  // Any other return value (including undefined) closes as before.
  confirmBtn.onclick = async () => {
    confirmBtn.disabled = true;
    try {
      const result = await onConfirm();
      if (result !== false) close();
    } finally {
      confirmBtn.disabled = false;
    }
  };
  document.getElementById('modal-cancel-btn').onclick = close;
  overlay.onclick = e => { if (e.target === overlay) close(); };
}

export function fmtSize(b) {
  if (!b) return '0 B';
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(b) / Math.log(1024));
  return (b / Math.pow(1024, i)).toFixed(i === 0 ? 0 : 1) + ' ' + u[i];
}

export function fmtDate(iso) {
  if (!iso) return '';
  try {
    const d   = new Date(iso);
    const now = new Date();
    const dif = now - d;
    if (dif < 60000)        return 'just now';
    if (dif < 3600000)      return Math.floor(dif / 60000)    + 'm ago';
    if (dif < 86400000)     return Math.floor(dif / 3600000)  + 'h ago';
    if (dif < 7 * 86400000) return Math.floor(dif / 86400000) + 'd ago';
    return d.toLocaleDateString(undefined, {
      month: 'short', day: 'numeric',
      year:  d.getFullYear() !== now.getFullYear() ? 'numeric' : undefined,
    });
  } catch { return ''; }
}

export function fileExtRaw(name) {
  return (name.includes('.') ? name.split('.').pop() : '').toLowerCase();
}

export function fileExt(name) {
  const e = fileExtRaw(name);
  return e ? e.slice(0, 4).toUpperCase() : 'FILE';
}

export function fileColor(ext) {
  const m = {
    pdf:'#e74c3c', doc:'#2980b9', docx:'#2980b9', xls:'#27ae60', xlsx:'#27ae60',
    ppt:'#e67e22', pptx:'#e67e22', zip:'#8e44ad', rar:'#8e44ad', '7z':'#8e44ad',
    tar:'#8e44ad', gz:'#8e44ad',  jpg:'#e91e63', jpeg:'#e91e63', png:'#9c27b0',
    gif:'#ff5722', webp:'#9c27b0', svg:'#ff9800', mp4:'#3f51b5', mp3:'#009688',
    wav:'#009688', mov:'#3f51b5', txt:'#607d8b', md:'#455a64',  json:'#f0a500',
    js:'#d4a017',  ts:'#3178c6',  py:'#3776ab',  html:'#e34c26', css:'#1572b6',
    sh:'#4eaa25',  go:'#00add8',  rs:'#f74c00',  java:'#b07219', rb:'#cc342d',
    c:'#555555',   cpp:'#f34b7d', cs:'#178600',  php:'#4f5d95', xml:'#e67e22',
  };
  return m[ext] || '#64748b';
}

export const ALLOWED_SCHEMES = new Set(['https:', 'http:']);
export const FD_EDITABLE = new Set([
  'txt','md','markdown','json','js','mjs','cjs','ts','tsx','jsx',
  'c','cpp','h','hpp','cs','java','go','rs','py','rb','php','sh','bash','zsh',
  'lua','r','swift','kt','css','html','htm','xml','yaml','yml','toml','ini',
  'cfg','conf','log','csv','sql','diff','patch','nfo','env','gitignore',
  'dockerignore','makefile','dockerfile',
]);
export const FD_IMG   = new Set(['png','jpg','jpeg','gif','webp','svg','bmp','ico','avif']);
export const FD_AUDIO = new Set(['mp3','ogg','wav','flac','aac','m4a','opus']);
export const FD_VIDEO = new Set(['mp4','webm','ogv','mov']);
export const FD_TEXT  = new Set([...FD_EDITABLE]);
