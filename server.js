const express = require('express');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = 3000;
const DATA_DIR = path.join(__dirname, 'data');
const DATA_FILE = path.join(DATA_DIR, 'posts.json');

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

function ensureDataFile() {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
  if (!fs.existsSync(DATA_FILE)) {
    fs.writeFileSync(DATA_FILE, JSON.stringify({ posts: [] }, null, 2));
  }
}

function readData() {
  ensureDataFile();
  const raw = fs.readFileSync(DATA_FILE, 'utf-8');
  try {
    const json = JSON.parse(raw || '{}');
    if (!json.posts) json.posts = [];
    return json;
  } catch (e) {
    return { posts: [] };
  }
}

function writeData(data) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
}

function newId(prefix = '') {
  return prefix + Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
}

// List posts
app.get('/api/posts', (req, res) => {
  const data = readData();
  const posts = [...data.posts].sort((a, b) => b.createdAt - a.createdAt);
  res.json(posts);
});

// Get single post
app.get('/api/posts/:id', (req, res) => {
  const { id } = req.params;
  const data = readData();
  const post = data.posts.find(p => p.id === id);
  if (!post) return res.status(404).json({ error: 'Post not found' });
  res.json(post);
});

// Create post
app.post('/api/posts', (req, res) => {
  const { title, content } = req.body;
  if (!title || !content) return res.status(400).json({ error: 'Title and content are required' });
  const data = readData();
  const post = {
    id: newId('p_'),
    title: String(title).trim(),
    content: String(content).trim(),
    createdAt: Date.now(),
    updatedAt: Date.now(),
    comments: []
  };
  data.posts.push(post);
  writeData(data);
  res.status(201).json(post);
});

// Update post
app.put('/api/posts/:id', (req, res) => {
  const { id } = req.params;
  const { title, content } = req.body;
  const data = readData();
  const idx = data.posts.findIndex(p => p.id === id);
  if (idx === -1) return res.status(404).json({ error: 'Post not found' });
  if (title) data.posts[idx].title = String(title).trim();
  if (content) data.posts[idx].content = String(content).trim();
  data.posts[idx].updatedAt = Date.now();
  writeData(data);
  res.json(data.posts[idx]);
});

// Delete post
app.delete('/api/posts/:id', (req, res) => {
  const { id } = req.params;
  const data = readData();
  const idx = data.posts.findIndex(p => p.id === id);
  if (idx === -1) return res.status(404).json({ error: 'Post not found' });
  const removed = data.posts.splice(idx, 1)[0];
  writeData(data);
  res.json({ ok: true, removedId: removed.id });
});

// Add anonymous comment
app.post('/api/posts/:id/comments', (req, res) => {
  const { id } = req.params;
  const { content } = req.body;
  if (!content || !String(content).trim()) return res.status(400).json({ error: 'Comment content is required' });
  const data = readData();
  const post = data.posts.find(p => p.id === id);
  if (!post) return res.status(404).json({ error: 'Post not found' });
  const comment = {
    id: newId('c_'),
    content: String(content).trim(),
    createdAt: Date.now()
  };
  post.comments.push(comment);
  post.updatedAt = Date.now();
  writeData(data);
  res.status(201).json(comment);
});

const crypto = require('crypto');
const AUTH_FILE = path.join(DATA_DIR, 'auth.json');

function ensureAuthFile() {
  ensureDataFile();
  if (!fs.existsSync(AUTH_FILE)) {
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.scryptSync('88888888', salt, 64).toString('hex');
    const secret = crypto.randomBytes(32).toString('hex');
    fs.writeFileSync(AUTH_FILE, JSON.stringify({ salt, hash, secret, updatedAt: Date.now() }, null, 2));
  }
}

function readAuth() {
  ensureAuthFile();
  try {
    const raw = fs.readFileSync(AUTH_FILE, 'utf-8');
    return JSON.parse(raw || '{}');
  } catch (e) {
    return {};
  }
}

function writeAuth(obj) {
  fs.writeFileSync(AUTH_FILE, JSON.stringify(obj, null, 2));
}

function verifyPassword(password) {
  const { salt, hash } = readAuth();
  const test = crypto.scryptSync(String(password), salt, 64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(test, 'hex'), Buffer.from(hash, 'hex'));
}

function sign(payload) {
  const { secret } = readAuth();
  const data = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', secret).update(data).digest('base64url');
  return `${data}.${sig}`;
}

function verify(token) {
  if (!token) return null;
  try {
    const [data, sig] = token.split('.');
    const { secret } = readAuth();
    const expected = crypto.createHmac('sha256', secret).update(data).digest('base64url');
    if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
    const payload = JSON.parse(Buffer.from(data, 'base64url').toString());
    if (payload.exp && Date.now() > payload.exp) return null;
    return payload;
  } catch (e) {
    return null;
  }
}

function getCookies(req) {
  const h = req.headers.cookie || '';
  const out = {};
  h.split(';').forEach(p => {
    const [k, v] = p.trim().split('=');
    if (k) out[k] = decodeURIComponent(v || '');
  });
  return out;
}

function isAuthenticated(req) {
  const cookies = getCookies(req);
  const payload = verify(cookies.auth);
  return !!payload && payload.uid === 'admin';
}

function setAuthCookie(res, ttlMs) {
  const token = sign({ uid: 'admin', exp: Date.now() + ttlMs });
  res.setHeader('Set-Cookie', `auth=${encodeURIComponent(token)}; HttpOnly; Path=/; Max-Age=${Math.floor(ttlMs/1000)}; SameSite=Lax`);
}

function clearAuthCookie(res) {
  res.setHeader('Set-Cookie', `auth=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax`);
}

function requireAuth(req, res, next) {
  if (!isAuthenticated(req)) return res.status(401).json({ error: 'Unauthorized' });
  next();
}

// Enforce auth for write operations on posts
app.use((req, res, next) => {
  if (req.path.startsWith('/api/posts') && (req.method === 'POST' || req.method === 'PUT' || req.method === 'DELETE')) {
    return requireAuth(req, res, next);
  }
  next();
});

// Auth APIs
app.post('/api/auth/login', (req, res) => {
  const { password } = req.body || {};
  if (!password) return res.status(400).json({ error: 'Password required' });
  if (!verifyPassword(password)) return res.status(401).json({ error: 'Invalid credentials' });
  setAuthCookie(res, 7 * 24 * 60 * 60 * 1000);
  res.json({ ok: true });
});

app.post('/api/auth/logout', (req, res) => {
  clearAuthCookie(res);
  res.json({ ok: true });
});

app.get('/api/auth/status', (req, res) => {
  res.json({ authenticated: isAuthenticated(req) });
});

app.post('/api/auth/change-password', requireAuth, (req, res) => {
  const { oldPassword, newPassword } = req.body || {};
  if (!oldPassword || !newPassword) return res.status(400).json({ error: 'Missing fields' });
  if (!verifyPassword(oldPassword)) return res.status(401).json({ error: 'Invalid old password' });
  if (String(newPassword).length < 8) return res.status(400).json({ error: 'New password too short' });
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(String(newPassword), salt, 64).toString('hex');
  const secret = crypto.randomBytes(32).toString('hex');
  writeAuth({ salt, hash, secret, updatedAt: Date.now() });
  setAuthCookie(res, 7 * 24 * 60 * 60 * 1000);
  res.json({ ok: true });
});

// Fallback to index.html for root
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

ensureAuthFile();
app.listen(PORT, () => {
  console.log(`Blog server running at http://localhost:${PORT}`);
});