const express = require('express');
const multer = require('multer');
const session = require('express-session');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 8080;
const UPLOADS_DIR = path.join(__dirname, 'uploads');

// ── Credentials — change these ─────────────────────────────────────────────
const USERNAME = 'admin';
const PASSWORD = 'password123';
// ──────────────────────────────────────────────────────────────────────────

if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR);

// ── Multer ─────────────────────────────────────────────────────────────────
const storage = multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, UPLOADS_DIR),
    filename: (_req, file, cb) => {
        const ext = path.extname(file.originalname);
        const base = path.basename(file.originalname, ext).replace(/[^a-zA-Z0-9_-]/g, '_');
        const unique = Date.now() + '-' + Math.round(Math.random() * 1e6);
        cb(null, `${base}-${unique}${ext}`);
    }
});

const upload = multer({
    storage,
    fileFilter: (_req, file, cb) => {
        if (file.mimetype.startsWith('image/')) cb(null, true);
        else cb(new Error('Only image files are allowed'));
    },
    limits: { fileSize: 20 * 1024 * 1024 }
});

// ── Middleware ─────────────────────────────────────────────────────────────
app.use(session({
    secret: 'image-upload-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 } // 7 days
}));

app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// ── Auth guard ─────────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
    if (req.session.loggedIn) return next();
    if (req.path === '/login' || req.path === '/logout') return next();
    if (req.path.startsWith('/api/') || req.path.startsWith('/uploads/')) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    res.redirect('/login');
}

app.use(requireAuth);

// ── Auth routes ────────────────────────────────────────────────────────────
app.get('/login', (req, res) => {
    if (req.session.loggedIn) return res.redirect('/');
    res.sendFile(path.join(__dirname, 'login.html'));
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    if (username === USERNAME && password === PASSWORD) {
        req.session.loggedIn = true;
        res.redirect('/');
    } else {
        res.redirect('/login?error=1');
    }
});

app.post('/logout', (req, res) => {
    req.session.destroy(() => res.redirect('/login'));
});

// ── Static files ───────────────────────────────────────────────────────────
app.use(express.static(__dirname));
app.use('/uploads', express.static(UPLOADS_DIR));

// ── API ────────────────────────────────────────────────────────────────────
app.get('/api/images', (req, res) => {
    const files = fs.readdirSync(UPLOADS_DIR).map(filename => ({
        filename,
        url: `/uploads/${filename}`,
        uploadedAt: fs.statSync(path.join(UPLOADS_DIR, filename)).mtime
    }));
    files.sort((a, b) => new Date(b.uploadedAt) - new Date(a.uploadedAt));
    res.json(files);
});

app.post('/api/upload', upload.array('images', 50), (req, res) => {
    if (!req.files || req.files.length === 0) {
        return res.status(400).json({ error: 'No files uploaded' });
    }
    res.json({ uploaded: req.files.map(f => ({ filename: f.filename, url: `/uploads/${f.filename}` })) });
});

app.delete('/api/images/:filename', (req, res) => {
    const filename = path.basename(req.params.filename);
    const filepath = path.join(UPLOADS_DIR, filename);
    if (!fs.existsSync(filepath)) return res.status(404).json({ error: 'File not found' });
    fs.unlinkSync(filepath);
    res.json({ deleted: filename });
});

// ── Start ──────────────────────────────────────────────────────────────────
function startServer(port) {
    const server = app.listen(port, () => {
        console.log(`Server running at http://localhost:${port}`);
    });
    server.on('error', (err) => {
        if (err.code === 'EADDRINUSE' || err.code === 'EACCES') {
            console.log(`Port ${port} unavailable, trying ${port + 1}...`);
            startServer(port + 1);
        } else {
            console.error('Server error:', err);
        }
    });
}

startServer(Number(PORT));
