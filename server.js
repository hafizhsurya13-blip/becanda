require('dotenv').config();
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');
const crypto = require('crypto');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

const app = express();
app.use(express.json());
app.use(cors({ origin: true }));

const db = new Database('slot_demo.db');
const JWT_SECRET = process.env.JWT_SECRET || 'ganti_dengan_secret_yang_kuat';

// init tables
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  email TEXT UNIQUE,
  password_hash TEXT NOT NULL,
  points INTEGER DEFAULT 0,
  is_admin INTEGER DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS spins (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  result TEXT NOT NULL,
  reward INTEGER NOT NULL,
  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS config (
  key TEXT PRIMARY KEY,
  value TEXT
);
`);

// default config (weighted reels stored as JSON string)
const defaultConfig = db.prepare('SELECT value FROM config WHERE key = ?').get('weightedReels');
if (!defaultConfig) {
  // example weighted reels (symbols repeated to represent weight)
  const weighted = JSON.stringify([
    ["7","7","7","🍒","🍒","🍋","🔔","⭐","🍉"],
    ["7","7","🍒","🍋","🍋","🔔","⭐","🍉"],
    ["7","🍒","🍋","🔔","⭐","🍉","🍉","🍉"]
  ]);
  db.prepare('INSERT INTO config(key,value) VALUES (?, ?)').run('weightedReels', weighted);
}

// rate limiter
const limiter = rateLimit({
  windowMs: 5 * 1000, // 5 seconds
  max: 10 // limit each IP to 10 requests per windowMs
});
app.use(limiter);

// helper
function createToken(user) {
  return jwt.sign({ id: user.id, username: user.username, is_admin: user.is_admin || 0 }, JWT_SECRET, { expiresIn: '7d' });
}

function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: 'No token' });
  const token = header.split(' ')[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

function adminMiddleware(req, res, next) {
  if (!req.user || !req.user.is_admin) return res.status(403).json({ error: 'Admin only' });
  next();
}

// register
app.post('/api/register', async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'username & password required' });
  const hash = await bcrypt.hash(password, 10);
  try {
    const stmt = db.prepare('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)');
    const info = stmt.run(username, email || null, hash);
    const user = { id: info.lastInsertRowid, username, email };
    const token = createToken(user);
    res.json({ user: { id: user.id, username: user.username, email }, token });
  } catch (err) {
    res.status(400).json({ error: 'Username or email already exists' });
  }
});

// login
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'username & password required' });
  const row = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!row) return res.status(400).json({ error: 'Invalid credentials' });
  const match = await bcrypt.compare(password, row.password_hash);
  if (!match) return res.status(400).json({ error: 'Invalid credentials' });
  const token = createToken({ id: row.id, username: row.username, is_admin: row.is_admin });
  res.json({ user: { id: row.id, username: row.username, points: row.points, is_admin: row.is_admin }, token });
});

// profile
app.get('/api/me', authMiddleware, (req, res) => {
  const row = db.prepare('SELECT id, username, email, points, is_admin FROM users WHERE id = ?').get(req.user.id);
  res.json({ user: row });
});

// leaderboard
app.get('/api/leaderboard', (req, res) => {
  const rows = db.prepare('SELECT id, username, points FROM users ORDER BY points DESC LIMIT 20').all();
  res.json({ leaderboard: rows });
});

// admin: get/set weighted reels config
app.get('/api/admin/config', authMiddleware, adminMiddleware, (req, res) => {
  const row = db.prepare('SELECT value FROM config WHERE key = ?').get('weightedReels');
  res.json({ weightedReels: JSON.parse(row.value) });
});

app.post('/api/admin/config', authMiddleware, adminMiddleware, (req, res) => {
  const { weightedReels } = req.body;
  if (!Array.isArray(weightedReels)) return res.status(400).json({ error: 'weightedReels must be array' });
  db.prepare('UPDATE config SET value = ? WHERE key = ?').run(JSON.stringify(weightedReels), 'weightedReels');
  res.json({ ok: true });
});

// spin logic
function mapResultToReward(resultSymbols) {
  if (resultSymbols.every(x => x === '7')) return 100;
  if (resultSymbols.every(x => x === resultSymbols[0])) return 50;
  if (new Set(resultSymbols).size === 2) return 10;
  return 2;
}

const lastSpinAt = new Map();
const COOLDOWN_MS = 3000;

app.post('/api/spin', authMiddleware, (req, res) => {
  const userId = req.user.id;
  const now = Date.now();
  const last = lastSpinAt.get(userId) || 0;
  if (now - last < COOLDOWN_MS) {
    return res.status(429).json({ error: 'Cooldown active', retryAfter: COOLDOWN_MS - (now - last) });
  }

  const cfgRow = db.prepare('SELECT value FROM config WHERE key = ?').get('weightedReels');
  const REELS = JSON.parse(cfgRow.value);

  const indices = REELS.map(reel => crypto.randomInt(0, reel.length));
  const symbols = indices.map((i, idx) => REELS[idx][i]);
  const reward = mapResultToReward(symbols);

  const update = db.prepare('UPDATE users SET points = points + ? WHERE id = ?');
  update.run(reward, userId);

  const insert = db.prepare('INSERT INTO spins (user_id, result, reward) VALUES (?, ?, ?)');
  insert.run(userId, symbols.join('|'), reward);

  lastSpinAt.set(userId, now);

  const user = db.prepare('SELECT id, username, points FROM users WHERE id = ?').get(userId);
  res.json({ result: symbols, reward, user });
});

// admin: view spins
app.get('/api/admin/spins', authMiddleware, adminMiddleware, (req, res) => {
  const rows = db.prepare('SELECT spins.id, users.username, spins.result, spins.reward, spins.timestamp FROM spins JOIN users ON spins.user_id = users.id ORDER BY spins.timestamp DESC LIMIT 200').all();
  res.json({ spins: rows });
});

// create initial admin if none
const adminExists = db.prepare('SELECT id FROM users WHERE is_admin = 1 LIMIT 1').get();
if (!adminExists) {
  const pass = 'admin123';
  const hash = bcrypt.hashSync(pass, 10);
  db.prepare('INSERT INTO users (username, email, password_hash, points, is_admin) VALUES (?, ?, ?, ?, ?)').run('admin', 'admin@local', hash, 0, 1);
  console.log('Created default admin: username=admin password=admin123 (please change)');
}

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log('Server running on', PORT));