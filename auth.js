'use strict';
let loginLocked = false;
let _signupData = {};

(async () => {
  try {
    const r = await fetch('/api/status');
    const d = await r.json();
    if (!d.ready) {
      document.getElementById('view-login').innerHTML =
        '<div class="auth-card svc-unconfigured"><h2>Service Not Configured</h2>' +
        '<p>The operator has not set the required environment variables.</p></div>';
      return;
    }
  } catch {}
  if (sessionStorage.getItem('sg_logged_out')) {
    sessionStorage.removeItem('sg_logged_out');
  } else {
    try {
      const r = await fetch('/api/me', { credentials: 'same-origin' });
      if (r.ok) { window.location.replace('/files'); return; }
    } catch {}
  }
  const view = location.hash === '#signup' ? 'signup' : location.hash === '#reset' ? 'reset' : 'login';
  showView(view);
})();

function showView(name) {
  document.querySelectorAll('.auth-view').forEach(el => el.classList.remove('active'));
  const el = document.getElementById(`view-${name}`);
  if (el) el.classList.add('active');
  history.replaceState(null, '', name === 'login' ? '/' : `#${name}`);
}

function on(id, evt, fn) {
  const el = document.getElementById(id);
  if (el) el.addEventListener(evt, fn);
}
function toast(msg, type) {
  const el = document.getElementById('toast');
  el.textContent = String(msg).slice(0, 120);
  el.className = `toast show${type ? ' ' + type : ''}`;
  clearTimeout(el._t);
  el._t = setTimeout(() => { el.className = 'toast'; }, 3500);
}

on('login-username', 'keydown', e => { if (e.key === 'Enter') document.getElementById('login-password')?.focus(); });
on('login-password', 'keydown', e => { if (e.key === 'Enter') doLogin(); });
on('login-btn',      'click',   () => doLogin());
on('goto-signup',    'click',   e  => { e.preventDefault(); showView('signup'); });
on('goto-reset',     'click',   e  => { e.preventDefault(); showView('reset'); });
on('goto-login',     'click',   e  => { e.preventDefault(); showView('login'); });
on('reset-back',     'click',   e  => { e.preventDefault(); showView('login'); });
on('step3-signin-btn','click',  () => showView('login'));
on('step1-btn',      'click',   () => step1Next());
on('step2-btn',      'click',   () => step2Next());
on('step2-back-btn', 'click',   () => goToStep(1));
on('reset-btn',      'click',   () => doReset());
on('s-password',     'input',   e  => updateStrength(e.target.value));

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
    const r = await fetch('/api/login', {
      method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });
    document.getElementById('login-password').value = '';
    if (r.ok) { window.location.replace('/files'); return; }
    if (r.status === 429) { startLockout(30); return; }
    errEl.textContent = 'Incorrect username or password.';
    document.getElementById('login-password').focus();
  } catch { errEl.textContent = 'Connection error. Please try again.'; }
  btn.disabled = false; btn.textContent = 'Sign In';
}

function startLockout(secs) {
  loginLocked = true;
  const btn = document.getElementById('login-btn');
  const el  = document.getElementById('login-lockout');
  btn.disabled = true;
  const tick = () => {
    const m = Math.floor(secs / 60), s = secs % 60;
    el.textContent = `Too many attempts. Try again in ${m}:${String(s).padStart(2, '0')}.`;
    if (secs-- <= 0) { loginLocked = false; btn.disabled = false; el.textContent = ''; clearInterval(t); }
  };
  tick(); const t = setInterval(tick, 1000);
}

function updateStrength(pw) {
  const wrap  = document.getElementById('pw-strength');
  const fill  = document.getElementById('pw-strength-fill');
  const label = document.getElementById('pw-strength-label');
  if (!pw) { wrap.style.display = 'none'; return; }
  wrap.style.display = 'block';
  let s = 0;
  if (pw.length >= 8)  s++;
  if (pw.length >= 12) s++;
  if (/[A-Z]/.test(pw) && /[a-z]/.test(pw)) s++;
  if (/[0-9]/.test(pw)) s++;
  if (/[^a-zA-Z0-9]/.test(pw)) s++;
  const L = [
    { pct: 10,  color: '#c0392b', text: 'Very weak' },
    { pct: 30,  color: '#e67e22', text: 'Weak' },
    { pct: 55,  color: '#f1c40f', text: 'Fair' },
    { pct: 80,  color: '#2ecc71', text: 'Strong' },
    { pct: 100, color: '#34a853', text: 'Very strong' },
  ];
  const lv = L[Math.min(s, L.length - 1)];
  fill.style.width = lv.pct + '%'; fill.style.background = lv.color; label.textContent = lv.text;
}

function goToStep(n) {
  [1, 2, 3].forEach(i => {
    document.getElementById(`step-${i}`).classList.toggle('active', i === n);
    const d = document.getElementById(`sdot-${i}`);
    d.className = 'step-dot' + (i < n ? ' done' : i === n ? ' active' : '');
  });
  document.getElementById('signup-footer-note').style.display = n === 3 ? 'none' : '';
}

function step1Next() {
  const u = document.getElementById('s-username').value.trim();
  const p = document.getElementById('s-password').value;
  const p2 = document.getElementById('s-password2').value;
  const e  = document.getElementById('step1-error');
  e.textContent = '';
  if (!u) { e.textContent = 'Please enter a username.'; return; }
  if (!/^[a-zA-Z0-9_\-]{3,32}$/.test(u)) { e.textContent = 'Username: 3–32 characters, letters/numbers/hyphens/underscores.'; return; }
  if (p.length < 8) { e.textContent = 'Password must be at least 8 characters.'; return; }
  if (p !== p2) { e.textContent = 'Passwords do not match.'; return; }
  _signupData.username = u; _signupData.password = p; goToStep(2);
}

async function step2Next() {
  const t   = document.getElementById('s-gh-token').value.trim();
  const o   = document.getElementById('s-gh-owner').value.trim();
  const r   = document.getElementById('s-gh-repo').value.trim();
  const err = document.getElementById('step2-error');
  const btn = document.getElementById('step2-btn');
  err.textContent = '';
  if (!t || !o || !r) { err.textContent = 'Please fill in all fields.'; return; }
  if (!t.startsWith('ghp_') && !t.startsWith('github_pat_')) { err.textContent = 'Token should start with ghp_ or github_pat_'; return; }
  btn.disabled = true; btn.innerHTML = '<span class="spinner"></span> Verifying…';
  try {
    const gr = await fetch(`https://api.github.com/repos/${encodeURIComponent(o)}/${encodeURIComponent(r)}`,
      { headers: { Authorization: `token ${t}`, Accept: 'application/vnd.github.v3+json', 'User-Agent': 'StoreGit-Setup' } });
    if (gr.status === 401) { err.textContent = 'Invalid GitHub token.'; return; }
    if (gr.status === 404) { err.textContent = 'Repository not found.'; return; }
    if (!gr.ok) { err.textContent = `GitHub error (${gr.status}).`; return; }
    const repo = await gr.json();
    if (!repo.permissions?.push && !repo.permissions?.admin) { err.textContent = 'Token needs write access to this repository.'; return; }
    const sr = await fetch('/api/signup', {
      method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: _signupData.username, password: _signupData.password, ghToken: t, ghOwner: o, ghRepo: r, ghBranch: 'main', folder: 'uploads' }),
    });
    const sd = await sr.json();
    if (sr.ok) {
      _signupData = {};
      ['s-password', 's-password2', 's-gh-token'].forEach(id => { const el = document.getElementById(id); if (el) el.value = ''; });
      goToStep(3);
    } else if (sr.status === 409) {
      err.textContent = 'That username is already taken.';
    } else {
      err.textContent = sd.error || 'Signup failed.';
    }
  } catch { err.textContent = 'Connection error. Please try again.'; }
  finally { btn.disabled = false; btn.textContent = 'Verify & Continue'; }
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
      toast('Password reset. Sign in with your new password.', 'ok');
      showView('login');
    } else {
      const d = await r.json().catch(() => ({}));
      errEl.textContent = d.error || 'Reset failed. Check your username and GitHub token.';
    }
  } catch { errEl.textContent = 'Connection error. Please try again.'; }
  btn.disabled = false; btn.textContent = 'Reset Password';
}
