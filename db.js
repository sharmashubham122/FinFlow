// Shared database setup (used by server.js and set-admin.js)
const { DatabaseSync } = require('node:sqlite'); // built into Node (no native files to install)
const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require('fs');

const DATA_DIR = path.join(__dirname, 'data');
fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new DatabaseSync(path.join(DATA_DIR, 'finflow.db'));
db.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  income REAL NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS transactions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  description TEXT NOT NULL,
  amount REAL NOT NULL CHECK (amount > 0),
  date TEXT NOT NULL,
  category TEXT NOT NULL,
  type TEXT NOT NULL CHECK (type IN ('income','expense')),
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_tx_user ON transactions(user_id);
CREATE TABLE IF NOT EXISTS budgets (
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  category TEXT NOT NULL,
  monthly_limit REAL NOT NULL CHECK (monthly_limit > 0),
  PRIMARY KEY (user_id, category)
);
CREATE TABLE IF NOT EXISTS goals (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  target REAL NOT NULL CHECK (target > 0),
  saved REAL NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_goals_user ON goals(user_id);
CREATE TABLE IF NOT EXISTS admin (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  admin_id TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  ver INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
`);

// Migrations for databases created by the previous version
const cols = db.prepare('PRAGMA table_info(users)').all().map(c => c.name);
if (!cols.includes('disabled')) db.exec('ALTER TABLE users ADD COLUMN disabled INTEGER NOT NULL DEFAULT 0');
if (!cols.includes('last_login')) db.exec('ALTER TABLE users ADD COLUMN last_login TEXT');

const ADMIN_ID_RE = /^[A-Za-z0-9._-]{3,40}$/;

function setAdmin(id, password) {
  if (!ADMIN_ID_RE.test(id)) throw new Error('Admin ID must be 3-40 characters: letters, numbers, dot, dash, underscore (no @ or spaces).');
  if (typeof password !== 'string' || password.length < 8) throw new Error('Admin password must be at least 8 characters.');
  const hash = bcrypt.hashSync(password, 12);
  if (db.prepare('SELECT 1 FROM admin WHERE id = 1').get())
    db.prepare('UPDATE admin SET admin_id = ?, password_hash = ?, ver = ver + 1 WHERE id = 1').run(id, hash);
  else
    db.prepare('INSERT INTO admin (id, admin_id, password_hash) VALUES (1, ?, ?)').run(id, hash);
}

module.exports = { db, DATA_DIR, setAdmin, ADMIN_ID_RE };
