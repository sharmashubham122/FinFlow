const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');
const { db, DATA_DIR, setAdmin, ADMIN_ID_RE } = require('./db');

const PORT = process.env.PORT || 3000;

// ── JWT secret (env var, or generated once and saved) ──
let JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  const f = path.join(DATA_DIR, '.jwt_secret');
  if (fs.existsSync(f)) JWT_SECRET = fs.readFileSync(f, 'utf8');
  else { JWT_SECRET = crypto.randomBytes(48).toString('hex'); fs.writeFileSync(f, JWT_SECRET, { mode: 0o600 }); }
}

// ── First-run admin account ──
if (!db.prepare('SELECT 1 FROM admin').get()) {
  const id = process.env.ADMIN_ID || 'admin';
  let pw = process.env.ADMIN_PASSWORD, generated = false;
  if (!pw) { pw = crypto.randomBytes(9).toString('base64url'); generated = true; }
  setAdmin(id, pw);
  console.log('\n┌────────────────────────────────────────────────────┐');
  console.log('│  ADMIN ACCOUNT CREATED (shown only once)           │');
  console.log('│  Admin ID : ' + id.padEnd(39) + '│');
  console.log('│  Password : ' + (generated ? pw : '(from ADMIN_PASSWORD)').padEnd(39) + '│');
  console.log('│  Change it anytime: node set-admin.js <id> "<pw>"  │');
  console.log('└────────────────────────────────────────────────────┘\n');
}

// ── Settings (managed from admin panel) ──
const DEFAULTS = {
  registration_open: '1', maintenance: '0',
  maintenance_message: 'FinFlow is undergoing maintenance. Please check back soon.',
  announcement_enabled: '0', announcement_text: '', announcement_type: 'info'
};
function getSettings() {
  const s = { ...DEFAULTS };
  db.prepare('SELECT key, value FROM settings').all().forEach(r => { s[r.key] = r.value; });
  return s;
}
function publicSettings() {
  const s = getSettings();
  return {
    registrationOpen: s.registration_open === '1',
    maintenance: s.maintenance === '1',
    maintenanceMessage: s.maintenance_message,
    announcement: { enabled: s.announcement_enabled === '1' && !!s.announcement_text, text: s.announcement_text, type: s.announcement_type }
  };
}

// ── Helpers ──
function userPayload(id) {
  const u = db.prepare('SELECT id, name, email, income, disabled, created_at, last_login FROM users WHERE id = ?').get(id);
  if (!u) return null;
  u.transactions = db.prepare(
    'SELECT id, description AS desc, amount, date, category, type FROM transactions WHERE user_id = ? ORDER BY date ASC, id ASC'
  ).all(id);
  u.budgets = {};
  db.prepare('SELECT category, monthly_limit FROM budgets WHERE user_id = ?').all(id)
    .forEach(b => { u.budgets[b.category] = b.monthly_limit; });
  u.goals = db.prepare('SELECT id, name, target, saved FROM goals WHERE user_id = ?').all(id);
  return u;
}
const sign = id => jwt.sign({ uid: id }, JWT_SECRET, { expiresIn: '30d' });
const str = (v, max = 100) => (typeof v === 'string' ? v.trim().slice(0, max) : '');
const num = v => (typeof v === 'number' ? v : parseFloat(v));
const touchLogin = id => db.prepare("UPDATE users SET last_login = datetime('now') WHERE id = ?").run(id);

function validTx(b) {
  const description = str(b.desc, 200), category = str(b.category, 40);
  const amount = num(b.amount), date = str(b.date, 10), type = b.type;
  if (!description || !category || !(amount > 0) || !/^\d{4}-\d{2}-\d{2}$/.test(date) || !['income', 'expense'].includes(type)) return null;
  return { description, category, amount, date, type };
}
function cookies(req) {
  const o = {};
  (req.headers.cookie || '').split(';').forEach(p => {
    const i = p.indexOf('=');
    if (i > 0) { try { o[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim()); } catch {} }
  });
  return o;
}
function adminFromReq(req) {
  const tok = cookies(req).ff_admin;
  if (!tok) return false;
  try {
    const p = jwt.verify(tok, JWT_SECRET);
    const a = db.prepare('SELECT ver FROM admin WHERE id = 1').get();
    return p.role === 'admin' && a && p.ver === a.ver;
  } catch { return false; }
}
function cookieFlags(req) {
  const secure = req.secure || req.headers['x-forwarded-proto'] === 'https';
  return 'HttpOnly; SameSite=Strict; Path=/' + (secure ? '; Secure' : '');
}

function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Not logged in' });
  try {
    const { uid } = jwt.verify(token, JWT_SECRET);
    const u = uid && db.prepare('SELECT disabled FROM users WHERE id = ?').get(uid);
    if (!u) throw new Error('no user');
    if (u.disabled) return res.status(403).json({ error: 'This account has been suspended' });
    const s = publicSettings();
    if (s.maintenance) return res.status(503).json({ error: s.maintenanceMessage });
    req.uid = uid; next();
  } catch { res.status(401).json({ error: 'Session expired, please log in again' }); }
}
function adminAuth(req, res, next) {
  if (!adminFromReq(req)) return res.status(401).json({ error: 'Admin session expired' });
  if (req.method !== 'GET' && req.get('X-Admin') !== '1') return res.status(403).json({ error: 'Bad request' });
  next();
}

// ── App ──
const app = express();
if (process.env.TRUST_PROXY) app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'same-origin');
  next();
});
app.use(express.json({ limit: '100kb' }));
app.use(express.static(path.join(__dirname, 'public')));

// login/register throttle (per IP)
const attempts = new Map();
function throttle(req, res, next) {
  const now = Date.now(), k = req.ip;
  const a = (attempts.get(k) || []).filter(t => now - t < 15 * 60 * 1000);
  if (a.length >= 20) return res.status(429).json({ error: 'Too many attempts. Try again in 15 minutes.' });
  a.push(now); attempts.set(k, a); next();
}

app.get('/api/settings', (req, res) => res.json(publicSettings()));

app.post('/api/register', throttle, (req, res) => {
  const s = publicSettings();
  if (s.maintenance) return res.status(503).json({ error: s.maintenanceMessage });
  if (!s.registrationOpen) return res.status(403).json({ error: 'New registrations are currently closed' });
  const name = str(req.body.name, 60), email = str(req.body.email, 120).toLowerCase();
  const password = typeof req.body.password === 'string' ? req.body.password : '';
  const income = Math.max(0, num(req.body.income) || 0);
  if (!name || !email || !password) return res.status(400).json({ error: 'Please fill all fields' });
  if (!/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ error: 'Invalid email' });
  if (password.length < 6) return res.status(400).json({ error: 'Password too short' });
  if (db.prepare('SELECT 1 FROM users WHERE email = ?').get(email))
    return res.status(409).json({ error: 'Email already registered' });
  const hash = bcrypt.hashSync(password, 10);
  const r = db.prepare('INSERT INTO users (name, email, password_hash, income) VALUES (?,?,?,?)').run(name, email, hash, income);
  const newId = Number(r.lastInsertRowid);
  touchLogin(newId);
  res.json({ token: sign(newId), user: userPayload(newId) });
});

// One login form for everyone: a regular email → user login; the admin ID → admin login.
app.post('/api/login', throttle, (req, res) => {
  const ident = str(req.body.email, 120);
  const password = typeof req.body.password === 'string' ? req.body.password : '';
  const bad = () => res.status(401).json({ error: 'Invalid email or password' });

  const admin = db.prepare('SELECT admin_id, password_hash, ver FROM admin WHERE id = 1').get();
  if (admin && ident.toLowerCase() === admin.admin_id.toLowerCase()) {
    if (!bcrypt.compareSync(password, admin.password_hash)) return bad();
    const tok = jwt.sign({ role: 'admin', ver: admin.ver }, JWT_SECRET, { expiresIn: '8h' });
    res.setHeader('Set-Cookie', `ff_admin=${tok}; Max-Age=${8 * 3600}; ${cookieFlags(req)}`);
    return res.json({ admin: true });
  }

  const s = publicSettings();
  if (s.maintenance) return res.status(503).json({ error: s.maintenanceMessage });
  const u = db.prepare('SELECT id, password_hash, disabled FROM users WHERE email = ?').get(ident.toLowerCase());
  if (!u || !bcrypt.compareSync(password, u.password_hash)) return bad();
  if (u.disabled) return res.status(403).json({ error: 'This account has been suspended' });
  touchLogin(u.id);
  res.json({ token: sign(u.id), user: userPayload(u.id) });
});

app.get('/api/me', auth, (req, res) => res.json({ user: userPayload(req.uid) }));

// ── User data ──
app.post('/api/transactions', auth, (req, res) => {
  const t = validTx(req.body);
  if (!t) return res.status(400).json({ error: 'Invalid transaction' });
  const r = db.prepare('INSERT INTO transactions (user_id, description, amount, date, category, type) VALUES (?,?,?,?,?,?)')
    .run(req.uid, t.description, t.amount, t.date, t.category, t.type);
  res.json({ id: Number(r.lastInsertRowid), desc: t.description, amount: t.amount, date: t.date, category: t.category, type: t.type });
});
app.delete('/api/transactions/:id', auth, (req, res) => {
  db.prepare('DELETE FROM transactions WHERE id = ? AND user_id = ?').run(req.params.id, req.uid);
  res.json({ ok: true });
});
app.put('/api/budgets', auth, (req, res) => {
  const category = str(req.body.category, 40), limit = num(req.body.limit);
  if (!category || !(limit > 0)) return res.status(400).json({ error: 'Enter valid limit' });
  db.prepare(`INSERT INTO budgets (user_id, category, monthly_limit) VALUES (?,?,?)
    ON CONFLICT(user_id, category) DO UPDATE SET monthly_limit = excluded.monthly_limit`).run(req.uid, category, limit);
  res.json({ ok: true });
});
app.post('/api/goals', auth, (req, res) => {
  const name = str(req.body.name, 80), target = num(req.body.target), saved = Math.max(0, num(req.body.saved) || 0);
  if (!name || !(target > 0)) return res.status(400).json({ error: 'Invalid goal' });
  const r = db.prepare('INSERT INTO goals (user_id, name, target, saved) VALUES (?,?,?,?)').run(req.uid, name, target, saved);
  res.json({ id: Number(r.lastInsertRowid), name, target, saved });
});
app.delete('/api/goals/:id', auth, (req, res) => {
  db.prepare('DELETE FROM goals WHERE id = ? AND user_id = ?').run(req.params.id, req.uid);
  res.json({ ok: true });
});

// ═════════════ ADMIN ═════════════
// The panel page is NOT in /public and is only served to a logged-in admin.
app.get('/admin-panel', (req, res) => {
  if (!adminFromReq(req)) return res.redirect('/');
  res.setHeader('Cache-Control', 'no-store');
  res.sendFile(path.join(__dirname, 'private', 'admin.html'));
});

app.post('/api/admin/logout', (req, res) => {
  res.setHeader('Set-Cookie', `ff_admin=; Max-Age=0; ${cookieFlags(req)}`);
  res.json({ ok: true });
});

app.get('/api/admin/stats', adminAuth, (req, res) => {
  const one = (sql, ...p) => db.prepare(sql).get(...p);
  const signups = db.prepare(`SELECT date(created_at) d, COUNT(*) c FROM users
    WHERE created_at >= date('now','-13 days') GROUP BY d`).all();
  res.json({
    users: one('SELECT COUNT(*) c FROM users').c,
    newUsers7d: one("SELECT COUNT(*) c FROM users WHERE created_at >= datetime('now','-7 days')").c,
    suspended: one('SELECT COUNT(*) c FROM users WHERE disabled = 1').c,
    transactions: one('SELECT COUNT(*) c FROM transactions').c,
    income: one("SELECT COALESCE(SUM(amount),0) s FROM transactions WHERE type='income'").s,
    expense: one("SELECT COALESCE(SUM(amount),0) s FROM transactions WHERE type='expense'").s,
    goals: one('SELECT COUNT(*) c FROM goals').c,
    budgets: one('SELECT COUNT(*) c FROM budgets').c,
    signups,
    settings: publicSettings()
  });
});

app.get('/api/admin/users', adminAuth, (req, res) => {
  const q = '%' + str(req.query.q || '', 60) + '%';
  const limit = Math.min(100, Math.max(1, parseInt(req.query.limit) || 15));
  const page = Math.max(1, parseInt(req.query.page) || 1);
  const total = db.prepare('SELECT COUNT(*) c FROM users WHERE name LIKE ? OR email LIKE ?').get(q, q).c;
  const rows = db.prepare(`SELECT u.id, u.name, u.email, u.income, u.disabled, u.created_at, u.last_login,
    (SELECT COUNT(*) FROM transactions t WHERE t.user_id = u.id) tx_count,
    (SELECT COALESCE(SUM(amount),0) FROM transactions t WHERE t.user_id = u.id AND t.type='income') total_income,
    (SELECT COALESCE(SUM(amount),0) FROM transactions t WHERE t.user_id = u.id AND t.type='expense') total_expense,
    (SELECT COUNT(*) FROM goals g WHERE g.user_id = u.id) goal_count
    FROM users u WHERE u.name LIKE ? OR u.email LIKE ? ORDER BY u.id DESC LIMIT ? OFFSET ?`)
    .all(q, q, limit, (page - 1) * limit);
  res.json({ total, page, limit, users: rows });
});

app.get('/api/admin/users/:id', adminAuth, (req, res) => {
  const u = userPayload(parseInt(req.params.id));
  if (!u) return res.status(404).json({ error: 'User not found' });
  res.json({ user: u });
});

app.post('/api/admin/users', adminAuth, (req, res) => {
  const name = str(req.body.name, 60), email = str(req.body.email, 120).toLowerCase();
  const password = typeof req.body.password === 'string' ? req.body.password : '';
  const income = Math.max(0, num(req.body.income) || 0);
  if (!name || !email || !password) return res.status(400).json({ error: 'Name, email and password are required' });
  if (!/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ error: 'Invalid email' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  if (db.prepare('SELECT 1 FROM users WHERE email = ?').get(email)) return res.status(409).json({ error: 'Email already registered' });
  const r = db.prepare('INSERT INTO users (name, email, password_hash, income) VALUES (?,?,?,?)')
    .run(name, email, bcrypt.hashSync(password, 10), income);
  res.json({ id: Number(r.lastInsertRowid) });
});

app.put('/api/admin/users/:id', adminAuth, (req, res) => {
  const id = parseInt(req.params.id);
  if (!db.prepare('SELECT 1 FROM users WHERE id = ?').get(id)) return res.status(404).json({ error: 'User not found' });
  const name = str(req.body.name, 60), email = str(req.body.email, 120).toLowerCase();
  const income = Math.max(0, num(req.body.income) || 0), disabled = req.body.disabled ? 1 : 0;
  if (!name || !/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ error: 'Valid name and email required' });
  if (db.prepare('SELECT 1 FROM users WHERE email = ? AND id != ?').get(email, id)) return res.status(409).json({ error: 'Email already used by another user' });
  db.prepare('UPDATE users SET name=?, email=?, income=?, disabled=? WHERE id=?').run(name, email, income, disabled, id);
  res.json({ ok: true });
});

app.post('/api/admin/users/:id/reset-password', adminAuth, (req, res) => {
  const pw = typeof req.body.password === 'string' ? req.body.password : '';
  if (pw.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  const r = db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(bcrypt.hashSync(pw, 10), parseInt(req.params.id));
  if (!r.changes) return res.status(404).json({ error: 'User not found' });
  res.json({ ok: true });
});

app.delete('/api/admin/users/:id', adminAuth, (req, res) => {
  db.prepare('DELETE FROM users WHERE id = ?').run(parseInt(req.params.id));
  res.json({ ok: true });
});

app.put('/api/admin/transactions/:id', adminAuth, (req, res) => {
  const t = validTx(req.body);
  if (!t) return res.status(400).json({ error: 'Invalid transaction' });
  const r = db.prepare('UPDATE transactions SET description=?, amount=?, date=?, category=?, type=? WHERE id=?')
    .run(t.description, t.amount, t.date, t.category, t.type, parseInt(req.params.id));
  if (!r.changes) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true });
});
app.delete('/api/admin/transactions/:id', adminAuth, (req, res) => {
  db.prepare('DELETE FROM transactions WHERE id = ?').run(parseInt(req.params.id));
  res.json({ ok: true });
});
app.delete('/api/admin/goals/:id', adminAuth, (req, res) => {
  db.prepare('DELETE FROM goals WHERE id = ?').run(parseInt(req.params.id));
  res.json({ ok: true });
});
app.delete('/api/admin/users/:uid/budgets/:category', adminAuth, (req, res) => {
  db.prepare('DELETE FROM budgets WHERE user_id = ? AND category = ?').run(parseInt(req.params.uid), req.params.category);
  res.json({ ok: true });
});

app.get('/api/admin/settings', adminAuth, (req, res) => res.json(getSettings()));
app.put('/api/admin/settings', adminAuth, (req, res) => {
  const b = req.body, put = db.prepare('INSERT INTO settings (key, value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value = excluded.value');
  const bool = v => (v ? '1' : '0');
  db.exec('BEGIN');
  try {
    put.run('registration_open', bool(b.registration_open));
    put.run('maintenance', bool(b.maintenance));
    put.run('maintenance_message', str(b.maintenance_message, 300) || DEFAULTS.maintenance_message);
    put.run('announcement_enabled', bool(b.announcement_enabled));
    put.run('announcement_text', str(b.announcement_text, 300));
    put.run('announcement_type', ['info', 'warning', 'success'].includes(b.announcement_type) ? b.announcement_type : 'info');
    db.exec('COMMIT');
  } catch (e) { db.exec('ROLLBACK'); return res.status(500).json({ error: 'Could not save settings' }); }
  res.json(getSettings());
});

app.put('/api/admin/account', adminAuth, (req, res) => {
  const cur = typeof req.body.currentPassword === 'string' ? req.body.currentPassword : '';
  const a = db.prepare('SELECT admin_id, password_hash FROM admin WHERE id = 1').get();
  if (!bcrypt.compareSync(cur, a.password_hash)) return res.status(401).json({ error: 'Current password is incorrect' });
  const newId = str(req.body.newId, 40) || a.admin_id;
  const newPw = typeof req.body.newPassword === 'string' && req.body.newPassword ? req.body.newPassword : cur;
  if (!ADMIN_ID_RE.test(newId)) return res.status(400).json({ error: 'Admin ID: 3-40 letters/numbers/. - _ (no @ or spaces)' });
  if (newPw.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });
  setAdmin(newId, newPw);
  // old sessions are now invalid → log this one in again with the new version
  const ver = db.prepare('SELECT ver FROM admin WHERE id = 1').get().ver;
  const tok = jwt.sign({ role: 'admin', ver }, JWT_SECRET, { expiresIn: '8h' });
  res.setHeader('Set-Cookie', `ff_admin=${tok}; Max-Age=${8 * 3600}; ${cookieFlags(req)}`);
  res.json({ ok: true, adminId: newId });
});

app.get('/api/admin/backup', adminAuth, (req, res) => {
  const f = path.join(os.tmpdir(), `finflow-backup-${Date.now()}.db`);
  try {
    db.exec("VACUUM INTO '" + f.replace(/'/g, "''") + "'");
    res.download(f, `finflow-backup-${new Date().toISOString().slice(0, 10)}.db`, () => fs.unlink(f, () => {}));
  } catch { res.status(500).json({ error: 'Backup failed' }); }
});

const csvCell = v => {
  let s = v == null ? '' : String(v);
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; // block spreadsheet formula injection
  return '"' + s.replace(/"/g, '""') + '"';
};
function sendCsv(res, name, header, rows) {
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="${name}"`);
  res.send('\ufeff' + [header, ...rows].map(r => r.map(csvCell).join(',')).join('\r\n'));
}
app.get('/api/admin/export/users.csv', adminAuth, (req, res) => {
  const rows = db.prepare('SELECT id, name, email, income, disabled, created_at, last_login FROM users ORDER BY id').all();
  sendCsv(res, 'finflow-users.csv', ['ID', 'Name', 'Email', 'Monthly income', 'Suspended', 'Joined', 'Last login'],
    rows.map(r => [r.id, r.name, r.email, r.income, r.disabled ? 'yes' : 'no', r.created_at, r.last_login || '']));
});
app.get('/api/admin/export/transactions.csv', adminAuth, (req, res) => {
  const rows = db.prepare(`SELECT t.id, u.email, t.date, t.type, t.category, t.description, t.amount
    FROM transactions t JOIN users u ON u.id = t.user_id ORDER BY t.id`).all();
  sendCsv(res, 'finflow-transactions.csv', ['ID', 'User email', 'Date', 'Type', 'Category', 'Description', 'Amount'],
    rows.map(r => [r.id, r.email, r.date, r.type, r.category, r.description, r.amount]));
});

app.use('/api', (req, res) => res.status(404).json({ error: 'Not found' }));
app.listen(PORT, () => console.log(`FinFlow running → http://localhost:${PORT}`));
