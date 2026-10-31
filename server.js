const express = require('express');
const http = require('http');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' }, maxHttpBufferSize: 2e7 });
const PORT = process.env.PORT || 3000;
const uploadDir = path.join(__dirname, 'uploads');
fs.mkdirSync(uploadDir, { recursive: true });
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(uploadDir));
const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, uploadDir),
  filename: (_req, file, cb) => cb(null, Date.now() + '-' + file.originalname.replace(/[^a-zA-Z0-9._-]/g, '_'))
});
const upload = multer({ storage, limits: { fileSize: 20 * 1024 * 1024 } });
app.post('/upload', upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file' });
  res.json({ url: '/uploads/' + encodeURIComponent(req.file.filename) });
});
const history = new Map();
io.on('connection', socket => {
  socket.on('join', ({ name, room }) => {
    socket.data.name = String(name || 'Friend').slice(0, 40);
    socket.data.room = String(room || 'friends').slice(0, 60);
    socket.join(socket.data.room);
    socket.emit('history', (history.get(socket.data.room) || []).slice(-100));
    socket.to(socket.data.room).emit('notice', `${socket.data.name} যুক্ত হয়েছে`);
  });
  socket.on('chat', msg => {
    const room = String(msg.room || socket.data.room || 'friends').slice(0, 60);
    if (room !== socket.data.room) return;
    const item = {
      id: socket.id, name: socket.data.name || 'Friend',
      text: String(msg.text || '').slice(0, 4000),
      fileUrl: msg.fileUrl ? String(msg.fileUrl).slice(0, 500) : '',
      mime: String(msg.mime || '').slice(0, 100),
      fileName: String(msg.fileName || '').slice(0, 200), time: Date.now()
    };
    const list = history.get(room) || [];
    list.push(item); history.set(room, list.slice(-100));
    io.to(room).emit('chat', item);
  });
  socket.on('signal', data => {
    const room = socket.data.room;
    // Forward call signaling to peers in the same room; prototype only.
    socket.to(room).emit('signal', { ...data, from: socket.id });
  });
  socket.on('disconnect', () => {
    if (socket.data.room) socket.to(socket.data.room).emit('notice', `${socket.data.name || 'Friend'} সংযোগ বিচ্ছিন্ন হয়েছে`);
  });
});
server.listen(PORT, '0.0.0.0', () => console.log(`Friends Club server running on port ${PORT}`));
