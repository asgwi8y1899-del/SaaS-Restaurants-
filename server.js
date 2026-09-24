const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');

const PORT = process.env.PORT || 3000;
// CHANGE THIS in production: set JWT_SECRET env variable
const JWT_SECRET = process.env.JWT_SECRET || 'change-me-in-production';

const db = new Database(path.join(__dirname, 'data.sqlite'));
db.pragma('journal_mode = WAL');

// ---------- Schema (multi-tenant: every table belongs to a user) ----------
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE NOT NULL, pass TEXT NOT NULL, name TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS menu(id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL DEFAULT 1, name TEXT NOT NULL, price REAL NOT NULL, cat TEXT DEFAULT 'General', img TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS orders(id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL DEFAULT 1, item TEXT NOT NULL, qty INTEGER NOT NULL, total REAL NOT NULL, type TEXT DEFAULT 'Dine-in', status TEXT DEFAULT 'New', customer TEXT DEFAULT '', created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS inventory(id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL DEFAULT 1, name TEXT NOT NULL, qty REAL NOT NULL DEFAULT 0, min REAL NOT NULL DEFAULT 0, unit TEXT DEFAULT 'pcs');
CREATE TABLE IF NOT EXISTS staff(id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL DEFAULT 1, name TEXT NOT NULL, role TEXT DEFAULT 'Waiter', shift TEXT DEFAULT 'Morning');
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, user_id INTEGER NOT NULL DEFAULT 1, value TEXT, UNIQUE(key, user_id));
`);

// ---------- Migration: add user_id to old DBs ----------
function ensureCol(table) {
  const cols = db.prepare(`PRAGMA table_info(${table})`).all().map(c => c.name);
  if (!cols.includes('user_id')) db.exec(`ALTER TABLE ${table} ADD COLUMN user_id INTEGER NOT NULL DEFAULT 1`);
}
['menu', 'orders', 'inventory', 'staff'].forEach(ensureCol);
if (!db.prepare("PRAGMA table_info(settings)").all().map(c => c.name).includes('user_id')) {
  db.exec('ALTER TABLE settings ADD COLUMN user_id INTEGER NOT NULL DEFAULT 1');
  db.exec('CREATE UNIQUE INDEX IF NOT EXISTS idx_settings_user ON settings(key, user_id)');
}

// ---------- Seed starter data per user ----------
function seedForUser(uid) {
  const has = db.prepare('SELECT id FROM menu WHERE user_id=?').get(uid);
  if (has) return;
  const mi = db.prepare('INSERT INTO menu(user_id,name,price,cat) VALUES (?,?,?,?)');
  [['Classic Burger',45,'Mains','🍔'],['Margherita Pizza',60,'Mains','🍕'],['Caesar Salad',35,'Salads','🥗'],
   ['Fresh Orange Juice',18,'Drinks','🍊'],['Tiramisu',28,'Desserts','🍰']].forEach(m=>mi.run(uid,...m));
  const ii = db.prepare('INSERT INTO inventory(user_id,name,qty,min,unit) VALUES (?,?,?,?,?)');
  [['Beef patties',40,20,'pcs'],['Mozzarella',8,10,'kg'],['Burger buns',120,50,'pcs'],
   ['Lettuce',5,8,'kg'],['Coffee beans',3,5,'kg']].forEach(i=>ii.run(uid,...i));
  const si = db.prepare('INSERT INTO staff(user_id,name,role,shift) VALUES (?,?,?,?)');
  [['Ahmed K.','Manager','Morning'],['Sara M.','Cashier','Evening'],
   ['Omar T.','Chef','Morning'],['Lina H.','Waiter','Evening']].forEach(s=>si.run(uid,...s));
  const gi = db.prepare('INSERT OR REPLACE INTO settings(key,user_id,value) VALUES (?,?,?)');
  [['name','My Restaurant'],['qr','1'],['online','1'],['inventory','0'],
   ['loyalty','1'],['kitchen','1'],['autoPrint','1']].forEach(s=>gi.run(s[0],uid,s[1]));
}

// ---------- Seed default admin ----------
if (!db.prepare('SELECT id FROM users WHERE email=?').get('admin@dineos.app')) {
  db.prepare('INSERT INTO users(email,pass,name) VALUES (?,?,?)')
    .run('admin@dineos.app', bcrypt.hashSync('admin123', 10), 'Admin');
  console.log('Seeded demo data. Login: admin@dineos.app / admin123');
}
seedForUser(1);

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ---------- Auth ----------
function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const t = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!t) return res.status(401).json({ error: 'unauthorized' });
  try { req.user = jwt.verify(t, JWT_SECRET); next(); }
  catch (e) { res.status(401).json({ error: 'invalid token' }); }
}

app.post('/api/register', (req, res) => {
  const email = String(req.body?.email || '').toLowerCase().trim();
  const pass = String(req.body?.pass || '');
  const name = String(req.body?.name || '');
  if (!email || pass.length < 6) return res.status(400).json({ error: 'email required & password min 6 chars' });
  try {
    const r = db.prepare('INSERT INTO users(email,pass,name) VALUES (?,?,?)').run(email, bcrypt.hashSync(pass, 10), name);
    seedForUser(r.lastInsertRowid);
    const token = jwt.sign({ id: r.lastInsertRowid, email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, name });
  } catch (e) { res.status(409).json({ error: 'email already exists' }); }
});

app.post('/api/login', (req, res) => {
  const email = String(req.body?.email || '').toLowerCase().trim();
  const u = db.prepare('SELECT * FROM users WHERE email=?').get(email);
  if (!u || !bcrypt.compareSync(String(req.body?.pass || ''), u.pass))
    return res.status(401).json({ error: 'wrong email or password' });
  const token = jwt.sign({ id: u.id, email: u.email }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, name: u.name });
});

// ---------- Settings (scoped to logged-in user) ----------
app.get('/api/settings', auth, (req, res) => {
  res.json(Object.fromEntries(db.prepare('SELECT key,value FROM settings WHERE user_id=?').all(req.user.id).map(r => [r.key, r.value])));
});
app.put('/api/settings', auth, (req, res) => {
  const st = db.prepare('INSERT OR REPLACE INTO settings(key,user_id,value) VALUES (?,?,?)');
  for (const [k, v] of Object.entries(req.body || {})) st.run(k, req.user.id, String(v));
  res.json({ ok: true });
});

// ---------- Menu ----------
app.get('/api/menu', auth, (req, res) => res.json(db.prepare('SELECT * FROM menu WHERE user_id=? ORDER BY id').all(req.user.id)));
app.post('/api/menu', auth, (req, res) => {
  const { name, price, cat, img } = req.body || {};
  if (!name || !(price > 0)) return res.status(400).json({ error: 'name & price required' });
  const r = db.prepare('INSERT INTO menu(user_id,name,price,cat,img) VALUES (?,?,?,?,?)')
    .run(req.user.id, String(name), +price, String(cat || 'General'), String(img || ''));
  res.json({ id: r.lastInsertRowid });
});
app.delete('/api/menu/:id', auth, (req, res) => {
  db.prepare('DELETE FROM menu WHERE id=? AND user_id=?').run(req.params.id, req.user.id); res.json({ ok: true });
});

// ---------- Orders ----------
app.get('/api/orders', auth, (req, res) =>
  res.json(db.prepare('SELECT * FROM orders WHERE user_id=? ORDER BY id DESC').all(req.user.id)));
app.post('/api/orders', auth, (req, res) => {
  const { menu_id, qty, type, customer } = req.body || {};
  const m = db.prepare('SELECT * FROM menu WHERE id=? AND user_id=?').get(menu_id, req.user.id);
  if (!m || !(qty >= 1)) return res.status(400).json({ error: 'invalid order' });
  const r = db.prepare('INSERT INTO orders(user_id,item,qty,total,type,customer) VALUES (?,?,?,?,?,?)')
    .run(req.user.id, m.name, +qty, m.price * qty, String(type || 'Dine-in'), String(customer || ''));
  res.json({ id: r.lastInsertRowid });
});
app.patch('/api/orders/:id', auth, (req, res) => {
  db.prepare('UPDATE orders SET status=? WHERE id=? AND user_id=?').run(String(req.body?.status || 'New'), req.params.id, req.user.id);
  res.json({ ok: true });
});
app.delete('/api/orders/:id', auth, (req, res) => {
  db.prepare('DELETE FROM orders WHERE id=? AND user_id=?').run(req.params.id, req.user.id); res.json({ ok: true });
});

// ---------- Inventory ----------
app.get('/api/inventory', auth, (req, res) => res.json(db.prepare('SELECT * FROM inventory WHERE user_id=? ORDER BY id').all(req.user.id)));
app.post('/api/inventory', auth, (req, res) => {
  const { name, qty, min, unit } = req.body || {};
  if (!name) return res.status(400).json({ error: 'name required' });
  const r = db.prepare('INSERT INTO inventory(user_id,name,qty,min,unit) VALUES (?,?,?,?,?)')
    .run(req.user.id, String(name), +qty || 0, +min || 0, String(unit || 'pcs'));
  res.json({ id: r.lastInsertRowid });
});
app.patch('/api/inventory/:id', auth, (req, res) => {
  const i = db.prepare('SELECT * FROM inventory WHERE id=? AND user_id=?').get(req.params.id, req.user.id);
  if (!i) return res.status(404).json({ error: 'not found' });
  const delta = +req.body?.delta || 0;
  db.prepare('UPDATE inventory SET qty=? WHERE id=?').run(Math.max(0, i.qty + delta), i.id);
  res.json({ ok: true });
});
app.delete('/api/inventory/:id', auth, (req, res) => {
  db.prepare('DELETE FROM inventory WHERE id=? AND user_id=?').run(req.params.id, req.user.id); res.json({ ok: true });
});

// ---------- Staff ----------
app.get('/api/staff', auth, (req, res) => res.json(db.prepare('SELECT * FROM staff WHERE user_id=? ORDER BY id').all(req.user.id)));
app.post('/api/staff', auth, (req, res) => {
  const { name, role, shift } = req.body || {};
  if (!name) return res.status(400).json({ error: 'name required' });
  const r = db.prepare('INSERT INTO staff(user_id,name,role,shift) VALUES (?,?,?,?)')
    .run(req.user.id, String(name), String(role || 'Waiter'), String(shift || 'Morning'));
  res.json({ id: r.lastInsertRowid });
});
app.delete('/api/staff/:id', auth, (req, res) => {
  db.prepare('DELETE FROM staff WHERE id=? AND user_id=?').run(req.params.id, req.user.id); res.json({ ok: true });
});

// ---------- Stats ----------
app.get('/api/stats', auth, (req, res) => {
  const rev = db.prepare("SELECT COALESCE(SUM(total),0) t, COUNT(*) c FROM orders WHERE user_id=? AND status != 'Cancelled'").get(req.user.id);
  const weekly = [];
  for (let i = 6; i >= 0; i--) {
    const d = db.prepare(`SELECT COALESCE(SUM(total),0) t FROM orders WHERE user_id=? AND date(created_at)=date('now','-${i} days')`).get(req.user.id);
    weekly.push(Math.round(d.t));
  }
  res.json({
    revenue: rev.t, orders: rev.c,
    staff: db.prepare('SELECT COUNT(*) c FROM staff WHERE user_id=?').get(req.user.id).c,
    low: db.prepare('SELECT COUNT(*) c FROM inventory WHERE user_id=? AND qty < min').get(req.user.id).c,
    weekly,
    recent: db.prepare('SELECT * FROM orders WHERE user_id=? ORDER BY id DESC LIMIT 5').all(req.user.id)
  });
});

// ---------- PUBLIC Storefront (no auth — for customers) ----------
app.get('/api/public/store/:uid', (req, res) => {
  const u = db.prepare('SELECT id, name FROM users WHERE id=?').get(req.params.uid);
  if (!u) return res.status(404).json({ error: 'store not found' });
  const s = Object.fromEntries(db.prepare('SELECT key,value FROM settings WHERE user_id=?').all(u.id).map(r => [r.key, r.value]));
  res.json({
    restaurant: s.name || 'Restaurant',
    online: s.online !== '0',
    menu: db.prepare('SELECT id,name,price,cat,img FROM menu WHERE user_id=? ORDER BY cat,id').all(u.id)
  });
});

app.post('/api/public/order/:uid', (req, res) => {
  const u = db.prepare('SELECT id FROM users WHERE id=?').get(req.params.uid);
  if (!u) return res.status(404).json({ error: 'store not found' });
  const s = db.prepare("SELECT value FROM settings WHERE user_id=? AND key='online'").get(u.id);
  if (s && s.value === '0') return res.status(403).json({ error: 'online ordering is disabled' });
  const { menu_id, qty, customer } = req.body || {};
  const m = db.prepare('SELECT * FROM menu WHERE id=? AND user_id=?').get(menu_id, u.id);
  if (!m || !(qty >= 1)) return res.status(400).json({ error: 'invalid order' });
  const r = db.prepare('INSERT INTO orders(user_id,item,qty,total,type,customer) VALUES (?,?,?,?,?,?)')
    .run(u.id, m.name, +qty, m.price * qty, 'Online', String(customer || ''));
  res.json({ id: r.lastInsertRowid });
});

app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.listen(PORT, () => console.log(`DineOS running -> http://localhost:${PORT}`));
