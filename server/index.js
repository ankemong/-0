// 示例后端已从项目中移除。此处为占位文件说明。
console.log('示例 server 已移除');
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Low, JSONFile } = require('lowdb');
const path = require('path');

const app = express();
app.use(cors());
app.use(bodyParser.json());

const dbFile = path.join(__dirname, 'db.json');
const adapter = new JSONFile(dbFile);
const db = new Low(adapter);

const JWT_SECRET = process.env.JWT_SECRET || 'devsecret';

async function initDB() {
  await db.read();
  db.data = db.data || { users: [] };
  await db.write();
}

initDB();

// 简单注册
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'missing' });
  await db.read();
  const exists = db.data.users.find(u => u.username === username);
  if (exists) return res.status(409).json({ error: 'exists' });
  const hash = await bcrypt.hash(password, 8);
  const user = { id: Date.now().toString(), username, passwordHash: hash, receipts: [] };
  db.data.users.push(user);
  await db.write();
  const token = jwt.sign({ id: user.id, username }, JWT_SECRET);
  res.json({ token, username });
});

// 登录
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  await db.read();
  const user = db.data.users.find(u => u.username === username);
  if (!user) return res.status(401).json({ error: 'invalid' });
  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ error: 'invalid' });
  const token = jwt.sign({ id: user.id, username }, JWT_SECRET);
  res.json({ token, username });
});

// auth middleware
function auth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'no token' });
  const parts = authHeader.split(' ');
  if (parts.length !== 2) return res.status(401).json({ error: 'bad token' });
  const token = parts[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'invalid' });
  }
}

// 保存收据
app.post('/api/receipts', auth, async (req, res) => {
  const { receipt } = req.body;
  if (!receipt) return res.status(400).json({ error: 'missing' });
  await db.read();
  const user = db.data.users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'not found' });
  user.receipts = user.receipts || [];
  user.receipts.push(receipt);
  await db.write();
  res.json({ ok: true });
});

// 获取收据
app.get('/api/receipts', auth, async (req, res) => {
  await db.read();
  const user = db.data.users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'not found' });
  res.json({ receipts: user.receipts || [] });
});

// 简单健康检查
app.get('/api/ping', (req, res) => res.json({ ok: true }));

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log('Server listening on', PORT));
