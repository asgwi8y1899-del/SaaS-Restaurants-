const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { execFile } = require('child_process');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { DatabaseSync } = require('node:sqlite');
const { OAuth2Client } = require('google-auth-library');
const { sendOTPByEmail } = require('./emailService'); // <--- سطر الإيميل

const PORT = process.env.PORT || 3000;

// ---------- JWT secret ----------
function loadJwtSecret() {
  if (process.env.JWT_SECRET && process.env.JWT_SECRET.length >= 32) return process.env.JWT_SECRET;
  const f = path.join(__dirname, '.jwt_secret');
  try {
    const v = fs.readFileSync(f, 'utf8').trim();
    if (v.length >= 32) return v;
  } catch (e) { }
  const v = crypto.randomBytes(48).toString('hex');
  fs.writeFileSync(f, v, { mode: 0o600 });
  console.log('Generated a new random JWT secret (saved to .jwt_secret).');
  return v;
}
const JWT_SECRET = loadJwtSecret();

// ---------- Google Sign-In config ----------
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';
const googleClient = GOOGLE_CLIENT_ID ? new OAuth2Client(GOOGLE_CLIENT_ID) : null;

// ---------- Twilio config ----------
const TWILIO_SID = process.env.TWILIO_SID || '';
const TWILIO_TOKEN = process.env.TWILIO_AUTH_TOKEN || '';
const TWILIO_SMS_FROM = process.env.TWILIO_SMS_FROM || '';
const TWILIO_WHATSAPP_FROM = process.env.TWILIO_WHATSAPP_FROM || '';
let twilioClient = null;
if (TWILIO_SID && TWILIO_TOKEN) {
  twilioClient = require('twilio')(TWILIO_SID, TWILIO_TOKEN);
}

const db = new DatabaseSync(path.join(__dirname, 'data.sqlite'));
db.exec('PRAGMA journal_mode = WAL');

// ---------- Schema ----------
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE, username TEXT UNIQUE, phone TEXT UNIQUE, google_id TEXT UNIQUE, pass TEXT, name TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS otp_codes(id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT NOT NULL, code TEXT NOT NULL, expires_at DATETIME NOT NULL, used INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS menu(id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL DEFAULT 1, name TEXT NOT NULL, price REAL NOT NULL, cat TEXT DEFAULT 'General', img TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS orders(id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL DEFAULT 1, item TEXT NOT NULL, qty INTEGER NOT NULL, total REAL NOT NULL, type TEXT DEFAULT 'Dine-in', status TEXT DEFAULT 'New', customer TEXT DEFAULT '', created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS inventory(id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL DEFAULT 1, name TEXT NOT NULL, qty REAL NOT NULL DEFAULT 0, min REAL NOT NULL DEFAULT 0, unit TEXT DEFAULT 'pcs');
CREATE TABLE IF NOT EXISTS staff(id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL DEFAULT 1, name TEXT NOT NULL, role TEXT DEFAULT 'Waiter', shift TEXT DEFAULT 'Morning');
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, user_id INTEGER NOT NULL DEFAULT 1, value TEXT, UNIQUE(key, user_id));
`);

// ---------- Migration ----------
// old otp_codes table used a phone column -> recreate it with email (codes are temporary)
if (!db.prepare('PRAGMA table_info(otp_codes)').all().map(c => c.name).includes('email')) {
  db.exec('DROP TABLE otp_codes');
  db.exec('CREATE TABLE otp_codes(id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT NOT NULL, code TEXT NOT NULL, expires_at DATETIME NOT NULL, used INTEGER NOT NULL DEFAULT 0)');
}
function ensureCol(table) {
  const cols = db.prepare(`PRAGMA table_info(${table})`).all().map(c => c.name);
  if (!cols.includes('user_id')) db.exec(`ALTER TABLE ${table} ADD COLUMN user_id INTEGER NOT NULL DEFAULT 1`);
}
['menu', 'orders', 'inventory', 'staff'].forEach(ensureCol);
function ensureUserCol(name, def) {
  const cols = db.prepare(`PRAGMA table_info(users)`).all().map(c => c.name);
  if (!cols.includes(name)) db.exec(`ALTER TABLE users ADD COLUMN ${name} ${def}`);
}
ensureUserCol('username', 'TEXT');
ensureUserCol('phone', 'TEXT');
ensureUserCol('google_id', 'TEXT');
if (!db.prepare("PRAGMA table_info(settings)").all().map(c => c.name).includes('user_id')) {
  db.exec('ALTER TABLE settings ADD COLUMN user_id INTEGER NOT NULL DEFAULT 1');
  db.exec('CREATE UNIQUE INDEX IF NOT EXISTS idx_settings_user ON settings(key, user_id)');
}

// ---------- Seed data ----------
function seedForUser(uid) {
  const has = db.prepare('SELECT id FROM menu WHERE user_id=?').get(uid);
  if (has) return;
  const mi = db.prepare('INSERT INTO menu(user_id,name,price,cat,img) VALUES (?,?,?,?,?)');
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

// ---------- Default admin ----------
function randomPassword() { return crypto.randomBytes(9).toString('base64url'); }
const adminRow = db.prepare('SELECT id, pass FROM users WHERE username=?').get('admin');
if (!adminRow) {
  const pw = process.env.ADMIN_PASSWORD || randomPassword();
  db.prepare('INSERT INTO users(username,email,pass,name) VALUES (?,?,?,?)')
    .run('admin', 'admin@dineos.app', bcrypt.hashSync(pw, 10), 'Admin');
  console.log('==================================================');
  console.log(' Admin account created.  username: admin');
  if (!process.env.ADMIN_PASSWORD) console.log(' password: ' + pw + '   <-- save it now, shown only once');
  console.log('==================================================');
} else if (adminRow.pass && bcrypt.compareSync('admin123', adminRow.pass)) {
  const pw = process.env.ADMIN_PASSWORD || randomPassword();
  db.prepare('UPDATE users SET pass=? WHERE id=?').run(bcrypt.hashSync(pw, 10), adminRow.id);
  console.log('==================================================');
  console.log(' The weak default admin password was replaced.');
  if (!process.env.ADMIN_PASSWORD) console.log(' NEW admin password: ' + pw + '   <-- save it now, shown only once');
  console.log('==================================================');
}
seedForUser(1);

const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '100kb' }));

// ---------- Rate limiting ----------
function limiter(max, minutes, msg) {
  return rateLimit({
    windowMs: minutes * 60 * 1000, max, standardHeaders: true, legacyHeaders: false,
    message: { error: msg || 'Too many attempts, try again later' },
  });
}
const loginLimiter = limiter(10, 15, 'Too many login attempts, try again in 15 minutes');
const registerLimiter = limiter(10, 60, 'Too many sign-ups from this network, try again later');
const otpSendLimiter = limiter(5, 15, 'Too many code requests, try again in 15 minutes');
const otpVerifyLimiter = limiter(10, 15, 'Too many attempts, try again in 15 minutes');
const googleLimiter = limiter(30, 15);
app.use('/api/', limiter(600, 15));
app.use(express.static(path.join(__dirname, 'public')));

// ---------- Auth ----------
function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const t = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!t) return res.status(401).json({ error: 'unauthorized' });
  try { req.user = jwt.verify(t, JWT_SECRET); next(); }
  catch (e) { res.status(401).json({ error: 'invalid token' }); }
}
function signToken(u) {
  return jwt.sign({ id: u.id }, JWT_SECRET, { expiresIn: '7d' });
}

// ---------- 1) Username + password ----------
app.post('/api/register', registerLimiter, (req, res) => {
  const username = String(req.body?.username || '').toLowerCase().trim();
  const pass = String(req.body?.pass || '');
  if (!/^[a-z0-9_]{3,20}$/.test(username)) return res.status(400).json({ error: 'username: 3-20 chars, letters/numbers/underscore only' });
  if (pass.length < 6) return res.status(400).json({ error: 'password min 6 chars' });
  try {
    const r = db.prepare('INSERT INTO users(username,pass,name) VALUES (?,?,?)').run(username, bcrypt.hashSync(pass, 10), username);
    seedForUser(r.lastInsertRowid);
    res.json({ token: signToken({ id: r.lastInsertRowid }), name: username });
  } catch (e) { res.status(409).json({ error: 'username already taken' }); }
});

app.post('/api/login', loginLimiter, (req, res) => {
  const username = String(req.body?.username || '').toLowerCase().trim();
  const u = db.prepare('SELECT * FROM users WHERE username=?').get(username);
  if (!u || !u.pass || !bcrypt.compareSync(String(req.body?.pass || ''), u.pass))
    return res.status(401).json({ error: 'wrong username or password' });
  res.json({ token: signToken(u), name: u.name });
});

// ---------- 2) Google Sign-In ----------
app.post('/api/auth/google', googleLimiter, async (req, res) => {
  if (!googleClient) return res.status(501).json({ error: 'Google sign-in not configured on server (set GOOGLE_CLIENT_ID)' });
  try {
    const ticket = await googleClient.verifyIdToken({ idToken: req.body?.credential, audience: GOOGLE_CLIENT_ID });
    const payload = ticket.getPayload();
    let u = db.prepare('SELECT * FROM users WHERE google_id=?').get(payload.sub);
    if (!u) {
      const r = db.prepare('INSERT INTO users(google_id,email,name) VALUES (?,?,?)').run(payload.sub, payload.email || null, payload.name || '');
      seedForUser(r.lastInsertRowid);
      u = db.prepare('SELECT * FROM users WHERE id=?').get(r.lastInsertRowid);
    }
    res.json({ token: signToken(u), name: u.name });
  } catch (e) { res.status(401).json({ error: 'invalid Google token' }); }
});

// ---------- 3) Email + OTP ----------
function genCode() { return String(crypto.randomInt(100000, 1000000)); }

function normEmail(raw) {
  return String(raw || '').trim().toLowerCase();
}

app.post('/api/auth/otp/send', otpSendLimiter, async (req, res) => {
  const email = normEmail(req.body?.email);
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'اكتب إيميل صحيح (مثال: your@email.com)' });

  db.prepare('UPDATE otp_codes SET used=1 WHERE email=?').run(email);
  const code = genCode();
  const expires = new Date(Date.now() + 10 * 60 * 1000).toISOString();
  db.prepare('INSERT INTO otp_codes(email,code,expires_at) VALUES (?,?,?)').run(email, code, expires);

  try {
    await sendOTPByEmail(email, code);
    console.log(`[EMAIL] code sent to ${email}`);
    return res.json({ ok: true, dev: false });
  } catch (e) {
    console.log(`[EMAIL FAILED] ${e.message}`);
    console.log(`[DEV] OTP for ${email}: ${code}`);
    return res.json({ ok: true, dev: true, emailFailed: true });
  }
});

app.post('/api/auth/otp/verify', otpVerifyLimiter, (req, res) => {
  const email = normEmail(req.body?.email);
  const code = String(req.body?.code || '').trim();
  const row = db.prepare('SELECT * FROM otp_codes WHERE email=? AND code=? AND used=0 ORDER BY id DESC LIMIT 1').get(email, code);
  if (!row || new Date(row.expires_at) < new Date()) return res.status(401).json({ error: 'invalid or expired code' });
  db.prepare('UPDATE otp_codes SET used=1 WHERE id=?').run(row.id);

  let u = db.prepare('SELECT * FROM users WHERE email=?').get(email);
  if (!u) {
    const r = db.prepare('INSERT INTO users(email,name) VALUES (?,?)').run(email, email);
    seedForUser(r.lastInsertRowid);
    u = db.prepare('SELECT * FROM users WHERE id=?').get(r.lastInsertRowid);
  }
  res.json({ token: signToken(u), name: u.name });
});

// ---------- Forgot Password ----------
app.post('/api/auth/forgot-password', otpSendLimiter, async (req, res) => {
  const email = String(req.body?.email || '').trim().toLowerCase();
  const username = String(req.body?.username || '').trim().toLowerCase();
  if (!email && !username) return res.status(400).json({ error: 'Enter email or username' });
  let user;
  if (email) user = db.prepare('SELECT * FROM users WHERE email=?').get(email);
  else user = db.prepare('SELECT * FROM users WHERE username=?').get(username);
  if (!user) return res.json({ ok: true, message: 'If account exists, a new password will be sent' });
  const newPassword = crypto.randomBytes(6).toString('base64url').slice(0, 10);
  const hashed = bcrypt.hashSync(newPassword, 10);
  db.prepare('UPDATE users SET pass=? WHERE id=?').run(hashed, user.id);
  const adminEmail = 'asgwi8y1899@gmail.com';
  const info = '<h3>Password Reset Request</h3>' +
    '<p><b>Username:</b> ' + (user.username || 'N/A') + '</p>' +
    '<p><b>Email:</b> ' + (user.email || 'N/A') + '</p>' +
    '<hr><h2>New Password: <code>' + newPassword + '</code></h2>' +
    '<p>Send this to the customer via WhatsApp.</p>';
  console.log('[RESET] ' + user.username + ' -> ' + newPassword);
  try {
    const { sendEmail } = require('./emailService');
    await sendEmail(adminEmail, 'DineOS - Password Reset', info);
  } catch (e) { console.error('[RESET FAILED]', e); }
  return res.json({ ok: true, message: 'Request received' });
});

// ---------- Settings ----------
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

// ---------- PUBLIC Storefront ----------
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