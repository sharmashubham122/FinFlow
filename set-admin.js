// Usage:  node set-admin.js <adminId> "<password>"
const { setAdmin, db } = require('./db');
const [, , id, pw] = process.argv;
if (!id || !pw) {
  console.log('Usage: node set-admin.js <adminId> "<password>"');
  process.exit(1);
}
try {
  setAdmin(id, pw);
  console.log('✔ Admin credentials saved. Admin ID: ' + id);
} catch (e) { console.error('✖ ' + e.message); process.exit(1); }
db.close();
