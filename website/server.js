// Water Controller - Node.js / Express backend with Oracle (node-oracledb)
// Run: set DB_USER, DB_PASSWORD, DB_CONNECT_STRING, SESSION_SECRET, ADMIN_PASSWORD, then `npm start`
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const oracledb = require('oracledb');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

oracledb.outFormat = oracledb.OUT_FORMAT_OBJECT;
oracledb.fetchAsString = [oracledb.CLOB];
oracledb.autoCommit = true;

const app = express();
app.use(express.json({ limit: '1mb' }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'change-me',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 8 * 3600e3 },
})); // NOTE: swap the default MemoryStore for a persistent store in production
app.use(express.static(path.join(__dirname, 'public'))); // serves robots.txt, index.html, admin.html

// ===================== [SQL INTEGRATION] =====================
// Connection pool + helper. All queries use bind variables (:name) to prevent SQL injection.
let pool;
async function initDb() {
  pool = await oracledb.createPool({
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    connectString: process.env.DB_CONNECT_STRING, // e.g. localhost:1521/XEPDB1
    poolMax: 10,
  });
}
async function db(sql, binds = {}) {
  const conn = await pool.getConnection();
  try { return await conn.execute(sql, binds); } finally { await conn.close(); }
}
const wrap = (fn) => (req, res) => fn(req, res).catch((e) => { console.error(e); res.status(500).json({ error: 'Server error' }); });
// Replace the full tag set of a user or device in one transaction (table/col are fixed constants, never user input)
async function setTags(table, col, id, tagIds) {
  const ids = [...new Set((Array.isArray(tagIds) ? tagIds : []).map(Number).filter(Number.isInteger))];
  const conn = await pool.getConnection();
  try {
    await conn.execute(`DELETE FROM ${table} WHERE ${col} = :id`, { id }, { autoCommit: false });
    if (ids.length) await conn.executeMany(`INSERT INTO ${table} (${col}, TAG_ID) VALUES (:id, :t)`, ids.map((t) => ({ id, t })), { autoCommit: false });
    await conn.commit();
  } catch (e) { await conn.rollback(); throw e; } finally { await conn.close(); }
}
// Customers only see devices that share a tag with them; staff/admin see all. Query must alias DEVICES as D.
const deviceScope = (u) => u.role === 'customer'
  ? { sql: ' AND EXISTS (SELECT 1 FROM DEVICE_TAGS DT JOIN USER_TAGS UT ON UT.TAG_ID = DT.TAG_ID WHERE DT.DEVICE_ID = D.ID AND UT.USER_ID = :uid)', binds: { uid: u.id } }
  : { sql: '', binds: {} };
// Customers only see (and replace) files they uploaded; staff/admin see all.
const fileScope = (u) => u.role === 'customer' ? { sql: ' AND UPLOADED_BY = :me', binds: { me: u.username } } : { sql: '', binds: {} };
// ===================== [/SQL INTEGRATION] =====================

// ===================== [USER AUTHENTICATION] =====================
// Password check (bcrypt) and role-based access middleware.
async function authenticate(username, password, allowedRoles) {
  const r = await db('SELECT ID, USERNAME, PASSWORD_HASH, ROLE FROM USERS WHERE USERNAME = :u', { u: username });
  const u = r.rows[0];
  if (!u || !allowedRoles.includes(u.ROLE)) return null;
  if (!(await bcrypt.compare(password, u.PASSWORD_HASH))) return null;
  return { id: u.ID, username: u.USERNAME, role: u.ROLE };
}
const need = (...roles) => (req, res, next) => {
  if (!req.session.user) return res.status(401).json({ error: 'Not logged in' });
  if (roles.length && !roles.includes(req.session.user.role)) return res.status(403).json({ error: 'Forbidden' });
  next();
};
// ===================== [/USER AUTHENTICATION] =====================

// ===================== [LOGIN HANDLING] =====================
// Customers + staff use /api/login; administrators have their own endpoint /api/admin/login.
const loginHandler = (roles) => wrap(async (req, res) => {
  const { username = '', password = '' } = req.body || {};
  const user = await authenticate(String(username), String(password), roles);
  if (!user) return res.status(401).json({ error: 'Invalid username or password' });
  req.session.regenerate(() => { req.session.user = user; res.json(user); });
});
app.post('/api/login', loginHandler(['customer', 'staff']));
app.post('/api/admin/login', loginHandler(['admin']));
app.post('/api/logout', (req, res) => req.session.destroy(() => res.json({ ok: true })));
app.get('/api/me', need(), (req, res) => res.json(req.session.user));
// ===================== [/LOGIN HANDLING] =====================

// ===================== [API] Devices (pumps / level indicators) =====================
// ----- [SQL SEARCH BAR] device search: ?q= matches name or region -----
app.get('/api/devices', need(), wrap(async (req, res) => {
  const s = `%${String(req.query.q || '').toLowerCase()}%`;
  const sc = deviceScope(req.session.user);
  const r = await db(
    `SELECT D.ID, D.NAME, D.TYPE, D.REGION, D.STATUS, D.LEVEL_PCT, D.PUMP_STATE, D.LAST_SEEN FROM DEVICES D
     WHERE (LOWER(D.NAME) LIKE :s OR LOWER(D.REGION) LIKE :s)${sc.sql} ORDER BY D.NAME FETCH FIRST 200 ROWS ONLY`, { s, ...sc.binds });
  res.json(r.rows);
}));

app.get('/api/devices/:id/metrics', need(), wrap(async (req, res) => {
  const sc = deviceScope(req.session.user);
  const ok = await db(`SELECT 1 FROM DEVICES D WHERE D.ID = :id${sc.sql}`, { id: Number(req.params.id), ...sc.binds });
  if (!ok.rows[0]) return res.status(404).json({ error: 'Not found' });
  const r = await db(
    `SELECT METRIC, VALUE, RECORDED_AT FROM METRICS WHERE DEVICE_ID = :id
     ORDER BY RECORDED_AT DESC FETCH FIRST 100 ROWS ONLY`, { id: Number(req.params.id) });
  res.json(r.rows);
}));

// Register a device; returns its API key once (only a hash is stored)
app.post('/api/devices', need('staff', 'admin'), wrap(async (req, res) => {
  const { name, type = 'pump', region = '' } = req.body || {};
  if (!name || !['pump', 'level'].includes(type)) return res.status(400).json({ error: 'name and type (pump|level) required' });
  const key = crypto.randomBytes(24).toString('hex');
  const hash = crypto.createHash('sha256').update(key).digest('hex');
  await db('INSERT INTO DEVICES (NAME, TYPE, REGION, API_KEY_HASH) VALUES (:n, :t, :r, :h)', { n: name, t: type, r: region, h: hash });
  res.status(201).json({ name, apiKey: key });
}));

// ----- [API] request a new per-device key with engineer credentials -----
// Works with a staff/admin session OR with {username, password} in the body (for provisioning scripts).
// Issuing a key replaces the old one, so update the device with the new key.
const keyTries = new Map(); // ip -> {n, t}; basic brute-force limiter (use a shared store if you run several servers)
app.post('/api/devices/:id/key', wrap(async (req, res) => {
  let user = req.session.user;
  if (!user) {
    const rec = keyTries.get(req.ip) || { n: 0, t: Date.now() };
    if (Date.now() - rec.t > 15 * 60e3) { rec.n = 0; rec.t = Date.now(); }
    if (rec.n >= 10) return res.status(429).json({ error: 'Too many attempts, try again later' });
    const { username = '', password = '' } = req.body || {};
    user = await authenticate(String(username), String(password), ['staff', 'admin']); // [USER AUTHENTICATION]
    if (!user) { rec.n++; keyTries.set(req.ip, rec); return res.status(401).json({ error: 'Invalid credentials' }); }
  }
  if (!['staff', 'admin'].includes(user.role)) return res.status(403).json({ error: 'Engineer credentials required' });
  const key = crypto.randomBytes(24).toString('hex');
  const hash = crypto.createHash('sha256').update(key).digest('hex');
  const r = await db('UPDATE DEVICES SET API_KEY_HASH = :h WHERE ID = :id', { h: hash, id: Number(req.params.id) });
  if (!r.rowsAffected) return res.status(404).json({ error: 'Device not found' });
  res.json({ deviceId: Number(req.params.id), apiKey: key });
}));

// Read / update a device's stored PLC configuration (JSON)
app.get('/api/devices/:id/config', need('staff', 'admin'), wrap(async (req, res) => {
  const r = await db('SELECT CONFIG FROM DEVICES WHERE ID = :id', { id: Number(req.params.id) });
  if (!r.rows[0]) return res.status(404).json({ error: 'Not found' });
  res.json({ config: r.rows[0].CONFIG || '{}' });
}));
app.put('/api/devices/:id/config', need('staff', 'admin'), wrap(async (req, res) => {
  const text = String((req.body || {}).config || '');
  try { JSON.parse(text); } catch { return res.status(400).json({ error: 'Config must be valid JSON' }); }
  await db('UPDATE DEVICES SET CONFIG = :c WHERE ID = :id', { c: text, id: Number(req.params.id) });
  res.json({ ok: true });
}));

// PLC / gateway ingest: authenticated by device key, not by a user session
app.post('/api/ingest', wrap(async (req, res) => {
  const { deviceId, levelPct = null, pumpState = null, status = 'ok' } = req.body || {};
  const hash = crypto.createHash('sha256').update(String(req.get('x-device-key') || '')).digest('hex');
  const d = await db('SELECT ID FROM DEVICES WHERE ID = :id AND API_KEY_HASH = :h', { id: Number(deviceId), h: hash });
  if (!d.rows[0]) return res.status(401).json({ error: 'Bad device key' });
  await db(`UPDATE DEVICES SET LEVEL_PCT = :l, PUMP_STATE = :p, STATUS = :s, LAST_SEEN = SYSTIMESTAMP WHERE ID = :id`,
    { l: levelPct, p: pumpState, s: String(status).slice(0, 20), id: Number(deviceId) });
  if (levelPct !== null) await db(`INSERT INTO METRICS (DEVICE_ID, METRIC, VALUE) VALUES (:id, 'level_pct', :v)`, { id: Number(deviceId), v: levelPct });
  res.json({ ok: true });
}));

// ===================== [API] User management (admin only) =====================
// Add user
app.post('/api/admin/users', need('admin'), wrap(async (req, res) => {
  const { username, password, role } = req.body || {};
  if (!/^[\w.@-]{3,60}$/.test(username || '') || !['customer', 'staff', 'admin'].includes(role) || String(password || '').length < 10)
    return res.status(400).json({ error: 'Valid username, role, and a password of 10+ characters required' });
  const hash = await bcrypt.hash(password, 12);
  try {
    await db('INSERT INTO USERS (USERNAME, PASSWORD_HASH, ROLE) VALUES (:u, :h, :r)', { u: username, h: hash, r: role });
  } catch (e) {
    if (String(e.message).includes('ORA-00001')) return res.status(409).json({ error: 'Username already exists' });
    throw e;
  }
  res.status(201).json({ username, role });
}));
// ----- [SQL SEARCH BAR] user lookup: ?q= matches username or role -----
app.get('/api/admin/users', need('admin'), wrap(async (req, res) => {
  const s = `%${String(req.query.q || '').toLowerCase()}%`;
  const r = await db(
    `SELECT ID, USERNAME, ROLE, CREATED_AT FROM USERS WHERE LOWER(USERNAME) LIKE :s OR LOWER(ROLE) LIKE :s
     ORDER BY USERNAME FETCH FIRST 200 ROWS ONLY`, { s });
  res.json(r.rows);
}));
app.delete('/api/admin/users/:id', need('admin'), wrap(async (req, res) => {
  if (Number(req.params.id) === req.session.user.id) return res.status(400).json({ error: 'You cannot delete yourself' });
  await db('DELETE FROM USERS WHERE ID = :id', { id: Number(req.params.id) });
  res.json({ ok: true });
}));

// ===================== [API] Device access by tag (staff + admin) =====================
// Used by the Device access page (/access.html). Customers are the only users limited by tags.
const tagMap = (rows) => rows.reduce((m, r) => { (m[r.K] ||= []).push({ id: r.TAG_ID, name: r.NAME }); return m; }, {});
const like = (v) => `%${String(v || '').toLowerCase()}%`;
app.get('/api/tags', need('staff', 'admin'), wrap(async (req, res) => {
  res.json((await db('SELECT ID, NAME FROM TAGS ORDER BY NAME')).rows);
}));
app.post('/api/tags', need('staff', 'admin'), wrap(async (req, res) => {
  const name = String((req.body || {}).name || '').trim().toLowerCase();
  if (!/^[a-z0-9_-]{1,40}$/.test(name)) return res.status(400).json({ error: 'Tag: 1-40 letters, numbers, - or _' });
  try { await db('INSERT INTO TAGS (NAME) VALUES (:n)', { n: name }); }
  catch (e) { if (String(e.message).includes('ORA-00001')) return res.status(409).json({ error: 'Tag already exists' }); throw e; }
  res.status(201).json({ name });
}));
// ----- [SQL SEARCH BAR] customer lookup with their tags -----
app.get('/api/access/users', need('staff', 'admin'), wrap(async (req, res) => {
  const u = (await db(`SELECT ID, USERNAME FROM USERS WHERE ROLE = 'customer' AND LOWER(USERNAME) LIKE :s
    ORDER BY USERNAME FETCH FIRST 200 ROWS ONLY`, { s: like(req.query.q) })).rows;
  const t = tagMap((await db('SELECT UT.USER_ID AS K, T.ID AS TAG_ID, T.NAME FROM USER_TAGS UT JOIN TAGS T ON T.ID = UT.TAG_ID')).rows);
  res.json(u.map((x) => ({ ...x, TAGS: t[x.ID] || [] })));
}));
app.put('/api/access/users/:id/tags', need('staff', 'admin'), wrap(async (req, res) => {
  await setTags('USER_TAGS', 'USER_ID', Number(req.params.id), (req.body || {}).tags);
  res.json({ ok: true });
}));
// ----- [SQL SEARCH BAR] device lookup with their tags -----
app.get('/api/access/devices', need('staff', 'admin'), wrap(async (req, res) => {
  const s = like(req.query.q);
  const d = (await db(`SELECT ID, NAME, REGION FROM DEVICES WHERE LOWER(NAME) LIKE :s OR LOWER(REGION) LIKE :s
    ORDER BY NAME FETCH FIRST 200 ROWS ONLY`, { s })).rows;
  const t = tagMap((await db('SELECT DT.DEVICE_ID AS K, T.ID AS TAG_ID, T.NAME FROM DEVICE_TAGS DT JOIN TAGS T ON T.ID = DT.TAG_ID')).rows);
  res.json(d.map((x) => ({ ...x, TAGS: t[x.ID] || [] })));
}));
app.put('/api/access/devices/:id/tags', need('staff', 'admin'), wrap(async (req, res) => {
  await setTags('DEVICE_TAGS', 'DEVICE_ID', Number(req.params.id), (req.body || {}).tags);
  res.json({ ok: true });
}));

// ===================== [FILE UPLOAD] =====================
// Every signed-in user can upload. Customers see and replace only their own files; staff/admin see and replace all.
// Files are stored on disk under a random name; the original name lives in the FILES table.
fs.mkdirSync(path.join(__dirname, 'uploads'), { recursive: true });
const upload = multer({ dest: path.join(__dirname, 'uploads'), limits: { fileSize: 20 * 1024 * 1024 } });

app.post('/api/files', need(), upload.single('file'), wrap(async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file received' });
  await db('INSERT INTO FILES (FILENAME, STORED_NAME, UPLOADED_BY) VALUES (:n, :s, :u)',
    { n: req.file.originalname.slice(0, 200), s: req.file.filename, u: req.session.user.username });
  res.status(201).json({ ok: true });
}));
app.put('/api/files/:id', need(), upload.single('file'), wrap(async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file received' });
  const fs_ = fileScope(req.session.user);
  const old = await db(`SELECT STORED_NAME FROM FILES WHERE ID = :id${fs_.sql}`, { id: Number(req.params.id), ...fs_.binds });
  if (!old.rows[0]) { fs.unlink(req.file.path, () => {}); return res.status(404).json({ error: 'Not found' }); }
  await db('UPDATE FILES SET FILENAME = :n, STORED_NAME = :s, UPLOADED_BY = :u, UPLOADED_AT = SYSTIMESTAMP WHERE ID = :id',
    { n: req.file.originalname.slice(0, 200), s: req.file.filename, u: req.session.user.username, id: Number(req.params.id) });
  fs.unlink(path.join(__dirname, 'uploads', old.rows[0].STORED_NAME), () => {});
  res.json({ ok: true });
}));
// ----- [SQL SEARCH BAR] file search: ?q= matches filename -----
app.get('/api/files', need(), wrap(async (req, res) => {
  const s = `%${String(req.query.q || '').toLowerCase()}%`;
  const sc = fileScope(req.session.user);
  const r = await db(`SELECT ID, FILENAME, UPLOADED_BY, UPLOADED_AT FROM FILES WHERE LOWER(FILENAME) LIKE :s${sc.sql}
    ORDER BY UPLOADED_AT DESC FETCH FIRST 200 ROWS ONLY`, { s, ...sc.binds });
  res.json(r.rows);
}));
app.get('/api/files/:id/download', need(), wrap(async (req, res) => {
  const sc = fileScope(req.session.user);
  const r = await db(`SELECT FILENAME, STORED_NAME FROM FILES WHERE ID = :id${sc.sql}`, { id: Number(req.params.id), ...sc.binds });
  if (!r.rows[0]) return res.status(404).json({ error: 'Not found' });
  res.download(path.join(__dirname, 'uploads', r.rows[0].STORED_NAME), r.rows[0].FILENAME);
}));
// ===================== [/FILE UPLOAD] =====================

// ----- start-up: connect, create first admin if the USERS table is empty -----
(async () => {
  await initDb();
  const c = await db('SELECT COUNT(*) AS N FROM USERS');
  if (c.rows[0].N === 0 && process.env.ADMIN_PASSWORD) {
    await db(`INSERT INTO USERS (USERNAME, PASSWORD_HASH, ROLE) VALUES (:u, :h, 'admin')`,
      { u: process.env.ADMIN_USER || 'admin', h: await bcrypt.hash(process.env.ADMIN_PASSWORD, 12) });
    console.log('Created first admin account');
  }
  // Set TLS_KEY and TLS_CERT (file paths) to serve HTTPS directly; otherwise run behind a TLS-terminating proxy.
  const port = process.env.PORT || 3000;
  const tls = process.env.TLS_KEY && process.env.TLS_CERT;
  const server = tls ? require('https').createServer({ key: fs.readFileSync(process.env.TLS_KEY), cert: fs.readFileSync(process.env.TLS_CERT) }, app) : app;
  server.listen(port, () => console.log(`Listening on port ${port}${tls ? ' (TLS)' : ''}`));
})().catch((e) => { console.error('Startup failed:', e.message); process.exit(1); });
