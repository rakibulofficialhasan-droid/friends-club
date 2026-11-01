const express = require('express');
const http = require('http');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const session = require('express-session');
const PgSession = require('connect-pg-simple')(session);
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);
const PORT = process.env.PORT || 3000;

if (!process.env.DATABASE_URL || !process.env.SESSION_SECRET) {
  console.error('Set DATABASE_URL and SESSION_SECRET environment variables.');
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_SSL === 'disable' ? false : { rejectUnauthorized: false }
});

app.set('trust proxy', 1);
app.use(express.json({ limit: '100kb' }));

const sessionMiddleware = session({
  store: new PgSession({ pool, tableName: 'user_sessions', createTableIfMissing: true }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 30 * 24 * 60 * 60 * 1000
  }
});
app.use(sessionMiddleware);

const publicDir = path.join(__dirname, 'public');
const uploadDir = path.join(__dirname, 'uploads');
fs.mkdirSync(uploadDir, { recursive: true });
app.use(express.static(publicDir));

const safeUser = u => ({ id: String(u.id), name: u.name, email: u.email });
const requireLogin = (req, res, next) =>
  req.session.user ? next() : res.status(401).json({ error: 'প্রথমে লগইন করো।' });

async function init() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      name VARCHAR(40) NOT NULL,
      email VARCHAR(254) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS friends (
      user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      friend_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      PRIMARY KEY (user_id, friend_id),
      CHECK (user_id <> friend_id)
    );
    CREATE TABLE IF NOT EXISTS chat_messages (
      id BIGSERIAL PRIMARY KEY,
      room VARCHAR(140) NOT NULL,
      user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
      name VARCHAR(40) NOT NULL,
      text TEXT NOT NULL DEFAULT '',
      file_url TEXT NOT NULL DEFAULT '',
      mime VARCHAR(100) NOT NULL DEFAULT '',
      file_name VARCHAR(200) NOT NULL DEFAULT '',
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS chat_messages_room_id_idx ON chat_messages(room, id DESC);
  `);
}

app.get('/api/me', (req, res) => res.json({ user: req.session.user || null }));

app.post('/api/signup', async (req, res) => {
  try {
    const name = String(req.body.name || '').trim().slice(0, 40);
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    if (!name) return res.status(400).json({ error: 'তোমার নাম লিখো।' });
    if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
      return res.status(400).json({ error: 'সঠিক ইমেইল লিখো। যাচাই ইমেইল পাঠানো হয় না।' });
    if (password.length < 8 || password.length > 72)
      return res.status(400).json({ error: 'পাসওয়ার্ড ৮ থেকে ৭২ অক্ষরের মধ্যে হতে হবে।' });

    const hash = await bcrypt.hash(password, 12);
    const q = await pool.query(
      'INSERT INTO users(name,email,password_hash) VALUES($1,$2,$3) RETURNING id,name,email',
      [name, email, hash]
    );
    req.session.regenerate(err => {
      if (err) return res.status(500).json({ error: 'সেশন তৈরি হয়নি।' });
      req.session.user = safeUser(q.rows[0]);
      req.session.save(saveErr => saveErr
        ? res.status(500).json({ error: 'সেশন সংরক্ষণ হয়নি।' })
        : res.status(201).json({ user: req.session.user }));
    });
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ error: 'এই ইমেইলে অ্যাকাউন্ট আছে। Login করো।' });
    console.error('Signup error:', e);
    res.status(500).json({ error: 'অ্যাকাউন্ট তৈরি করা যায়নি।' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    const q = await pool.query('SELECT id,name,email,password_hash FROM users WHERE email=$1', [email]);
    const u = q.rows[0];
    if (!u || !(await bcrypt.compare(password, u.password_hash)))
      return res.status(401).json({ error: 'ইমেইল বা পাসওয়ার্ড সঠিক নয়।' });
    req.session.regenerate(err => {
      if (err) return res.status(500).json({ error: 'সেশন তৈরি হয়নি।' });
      req.session.user = safeUser(u);
      req.session.save(saveErr => saveErr
        ? res.status(500).json({ error: 'লগইন সংরক্ষণ হয়নি।' })
        : res.json({ user: req.session.user }));
    });
  } catch (e) {
    console.error('Login error:', e);
    res.status(500).json({ error: 'লগইন করা যায়নি।' });
  }
});

app.post('/api/logout', requireLogin, (req, res) => {
  req.session.destroy(err => err
    ? res.status(500).json({ error: 'Logout করা যায়নি।' })
    : (res.clearCookie('connect.sid', {
        httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production'
      }), res.json({ ok: true })));
});

app.get('/api/friends', requireLogin, async (req, res) => {
  try {
    const q = await pool.query(`
      SELECT u.id,u.name,u.email FROM friends f
      JOIN users u ON u.id=f.friend_id WHERE f.user_id=$1
      ORDER BY u.name`, [req.session.user.id]);
    res.json({ friends: q.rows.map(safeUser) });
  } catch (e) { console.error(e); res.status(500).json({ error: 'ফ্রেন্ড লিস্ট লোড হয়নি।' }); }
});

app.post('/api/friends', requireLogin, async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    if (!email) return res.status(400).json({ error: 'বন্ধুর অ্যাকাউন্টের ইমেইল লিখো।' });
    const q = await pool.query('SELECT id,name,email FROM users WHERE email=$1', [email]);
    const friend = q.rows[0];
    if (!friend) return res.status(404).json({ error: 'এই ইমেইলে কোনো অ্যাকাউন্ট পাওয়া যায়নি।' });
    if (String(friend.id) === String(req.session.user.id))
      return res.status(400).json({ error: 'নিজেকে ফ্রেন্ড হিসেবে যোগ করা যাবে না।' });
    await pool.query(
      'INSERT INTO friends(user_id,friend_id) VALUES($1,$2) ON CONFLICT DO NOTHING',
      [req.session.user.id, friend.id]
    );
    await pool.query(
      'INSERT INTO friends(user_id,friend_id) VALUES($1,$2) ON CONFLICT DO NOTHING',
      [friend.id, req.session.user.id]
    );
    res.status(201).json({ friend: safeUser(friend) });
  } catch (e) { console.error(e); res.status(500).json({ error: 'বন্ধুকে যোগ করা যায়নি।' }); }
});

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, uploadDir),
  filename: (_req, file, cb) => {
    const clean = path.basename(file.originalname).replace(/[^a-zA-Z0-9._-]/g, '_').slice(-120) || 'file';
    cb(null, Date.now() + '-' + Math.random().toString(36).slice(2, 9) + '-' + clean);
  }
});
const upload = multer({ storage, limits: { fileSize: 20 * 1024 * 1024 } });
app.post('/upload', requireLogin, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'ফাইল পাওয়া যায়নি।' });
  res.json({ url: '/uploads/' + encodeURIComponent(req.file.filename), name: req.file.originalname });
});
// Files are stored on the server's local disk; Render free instances may lose them on restart/redeploy.
// The upload route is login-protected, but generated file URLs are not private access-controlled URLs.
app.use('/uploads', express.static(uploadDir));

const io = new Server(server, { maxHttpBufferSize: 2e7 });
io.engine.use(sessionMiddleware);
io.use(async (socket, next) => {
  try {
    const u = socket.request.session?.user;
    if (!u) return next(new Error('প্রথমে লগইন করো।'));
    const q = await pool.query('SELECT id,name,email FROM users WHERE id=$1', [u.id]);
    if (!q.rows[0]) return next(new Error('অ্যাকাউন্ট পাওয়া যায়নি।'));
    socket.data.user = safeUser(q.rows[0]);
    next();
  } catch (e) { next(new Error('অ্যাকাউন্ট যাচাই করা যায়নি।')); }
});

function directRoom(a, b) {
  const ids = [String(a), String(b)].sort((x, y) => Number(x) - Number(y));
  return 'dm:' + ids[0] + ':' + ids[1];
}
async function areFriends(a, b) {
  const q = await pool.query('SELECT 1 FROM friends WHERE user_id=$1 AND friend_id=$2', [a, b]);
  return q.rowCount > 0;
}
function formatMessage(m) {
  return {
    id: 'db-' + m.id, userId: m.user_id == null ? null : String(m.user_id),
    name: m.name, text: m.text, fileUrl: m.file_url, mime: m.mime,
    fileName: m.file_name, time: new Date(m.created_at).getTime()
  };
}

io.on('connection', socket => {
  const user = socket.data.user;
  socket.on('join', async () => {
    try {
      const group = 'group:friends';
      if (socket.data.room) socket.leave(socket.data.room);
      socket.join(group);
      socket.data.room = group;
      const q = await pool.query(`
        SELECT * FROM (
          SELECT id,user_id,name,text,file_url,mime,file_name,created_at
          FROM chat_messages WHERE room=$1 ORDER BY id DESC LIMIT 100
        ) x ORDER BY id ASC`, [group]);
      socket.emit('history', { room: group, items: q.rows.map(formatMessage) });
      socket.emit('notice', 'গ্রুপ চ্যাটে যুক্ত হয়েছ।');
    } catch (e) { console.error(e); socket.emit('notice', 'গ্রুপ চ্যাট লোড হয়নি।'); }
  });

  socket.on('open_dm', async data => {
    try {
      const friendId = String(data?.friendId || '');
      if (!/^\d+$/.test(friendId) || friendId === String(user.id))
        return socket.emit('app_error', 'সঠিক বন্ধুকে নির্বাচন করো।');
      if (!(await areFriends(user.id, friendId)))
        return socket.emit('app_error', 'এই ব্যবহারকারী তোমার ফ্রেন্ড লিস্টে নেই।');
      if (socket.data.room) socket.leave(socket.data.room);
      const room = directRoom(user.id, friendId);
      socket.join(room);
      socket.data.room = room;
      socket.data.dmFriendId = friendId;
      const q = await pool.query(`
        SELECT * FROM (
          SELECT id,user_id,name,text,file_url,mime,file_name,created_at
          FROM chat_messages WHERE room=$1 ORDER BY id DESC LIMIT 100
        ) x ORDER BY id ASC`, [room]);
      socket.emit('history', { room, items: q.rows.map(formatMessage) });
      socket.emit('notice', 'ব্যক্তিগত চ্যাট খোলা হয়েছে।');
    } catch (e) { console.error(e); socket.emit('app_error', 'ব্যক্তিগত চ্যাট খোলা যায়নি।'); }
  });

  socket.on('chat', async m => {
    try {
      const room = socket.data.room;
      if (!room || !m || typeof m !== 'object') return;
      if (room.startsWith('dm:')) {
        const ids = room.slice(3).split(':');
        if (ids.length !== 2 || !ids.includes(String(user.id))) return;
        const otherId = ids.find(id => id !== String(user.id));
        if (!otherId || !(await areFriends(user.id, otherId))) return;
      } else if (room !== 'group:friends') return;

      const text = String(m.text || '').slice(0, 4000);
      const fileUrl = String(m.fileUrl || '').slice(0, 500);
      const mime = String(m.mime || '').slice(0, 100);
      const fileName = String(m.fileName || '').slice(0, 200);
      if (!text && !fileUrl) return;
      if (fileUrl && !/^\/uploads\/[A-Za-z0-9._%\-]+$/.test(fileUrl)) return;
      const q = await pool.query(`
        INSERT INTO chat_messages(room,user_id,name,text,file_url,mime,file_name)
        VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id,user_id,name,text,file_url,mime,file_name,created_at`,
        [room, user.id, user.name, text, fileUrl, mime, fileName]);
      io.to(room).emit('chat', { ...formatMessage(q.rows[0]), room });
    } catch (e) { console.error(e); socket.emit('app_error', 'মেসেজ সংরক্ষণ করা যায়নি।'); }
  });

  socket.on('signal', async data => {
    try {
      const room = socket.data.room;
      if (!room || !data || typeof data !== 'object') return;
      if (room.startsWith('dm:')) {
        const ids = room.slice(3).split(':');
        if (!ids.includes(String(user.id))) return;
        const otherId = ids.find(id => id !== String(user.id));
        if (!otherId || !(await areFriends(user.id, otherId))) return;
        socket.to(room).emit('signal', { ...data, from: socket.id });
      } else {
        socket.emit('app_error', 'ব্যক্তিগত চ্যাট খুলে কল শুরু করো।');
      }
    } catch (e) { socket.emit('app_error', 'কল সিগন্যাল পাঠানো যায়নি।'); }
  });
  socket.on('disconnect', () => {});
});

init().then(() => server.listen(PORT, '0.0.0.0', () => console.log('Friends Club running on ' + PORT)))
  .catch(e => { console.error('DB init failed', e); process.exit(1); });
