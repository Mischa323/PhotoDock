const express = require('express');
const multer = require('multer');
const session = require('express-session');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 8080;
const UPLOADS_DIR = path.join(__dirname, 'uploads');
const DATA_FILE   = path.join(__dirname, 'data.json');

if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR);

// ── Password hashing (scrypt, no extra deps) ───────────────────────────────
async function hashPassword(plain) {
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = await new Promise((res, rej) =>
        crypto.scrypt(plain, salt, 64, (e, d) => e ? rej(e) : res(d.toString('hex')))
    );
    return `scrypt:${salt}:${hash}`;
}

async function verifyPassword(plain, stored) {
    // Plain-text passwords (legacy, before hashing was added)
    if (!stored.startsWith('scrypt:')) return plain === stored;
    const [, salt, hash] = stored.split(':');
    const attempt = await new Promise((res, rej) =>
        crypto.scrypt(plain, salt, 64, (e, d) => e ? rej(e) : res(d.toString('hex')))
    );
    return crypto.timingSafeEqual(Buffer.from(attempt, 'hex'), Buffer.from(hash, 'hex'));
}

// ── Login rate limiter ─────────────────────────────────────────────────────
const loginAttempts = new Map(); // ip -> { count, resetAt }
const MAX_ATTEMPTS  = 10;
const WINDOW_MS     = 15 * 60 * 1000; // 15 minutes

function checkRateLimit(ip) {
    const now = Date.now();
    const rec = loginAttempts.get(ip);
    if (!rec || now > rec.resetAt) {
        loginAttempts.set(ip, { count: 1, resetAt: now + WINDOW_MS });
        return true;
    }
    if (rec.count >= MAX_ATTEMPTS) return false;
    rec.count++;
    return true;
}

function resetRateLimit(ip) {
    loginAttempts.delete(ip);
}

// ── Persistent data ────────────────────────────────────────────────────────
function loadData() {
    if (fs.existsSync(DATA_FILE)) {
        return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
    }
    const initial = { users: [], apiKeys: [] };
    fs.writeFileSync(DATA_FILE, JSON.stringify(initial, null, 2));
    return initial;
}

function saveData(data) {
    fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
}

let appData = loadData();

// ── Multer ─────────────────────────────────────────────────────────────────
const storage = multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, UPLOADS_DIR),
    filename: (_req, file, cb) => {
        const ext  = path.extname(file.originalname);
        const base = path.basename(file.originalname, ext).replace(/[^a-zA-Z0-9_-]/g, '_');
        cb(null, `${base}-${Date.now()}-${Math.round(Math.random() * 1e6)}${ext}`);
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
    cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 }
}));

app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// ── Auth & role helpers ────────────────────────────────────────────────────
function currentUser(req) {
    return appData.users.find(u => u.id === req.session.userId);
}

function getPermissions(role) {
    const defaults = { canUpload: false, canDelete: false, canManage: false };
    return Object.assign({}, defaults, (appData.roles || {})[role] || {});
}

function requireAuth(req, res, next) {
    if (appData.users.length === 0) {
        if (req.path === '/setup' || req.path.startsWith('/api/setup')) return next();
        return res.redirect('/setup');
    }
    if (req.session.loggedIn) return next();
    if (req.path === '/login' || req.path === '/logout') return next();
    if (req.path.startsWith('/api/slideshow/')) return next();
    if (req.path.startsWith('/api/') || req.path.startsWith('/uploads/')) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    res.redirect('/login');
}

function requirePermission(perm) {
    return (req, res, next) => {
        const user = currentUser(req);
        if (user && getPermissions(user.role)[perm]) return next();
        if (req.path.startsWith('/api/')) return res.status(403).json({ error: 'Permission denied' });
        res.redirect('/');
    };
}

// Shorthand guards
const requireAdmin  = requirePermission('canManage');
const requireUpload = requirePermission('canUpload');
const requireDelete = requirePermission('canDelete');

function requireApiKey(req, res, next) {
    const key = req.headers['x-api-key'] || req.query.key;
    if (appData.apiKeys.some(k => k.key === key)) return next();
    res.status(401).json({ error: 'Invalid or missing API key' });
}

app.use(requireAuth);

// ── First-run setup ────────────────────────────────────────────────────────
app.get('/setup', (_req, res) => {
    if (appData.users.length > 0) return res.redirect('/');
    res.sendFile(path.join(__dirname, 'setup.html'));
});

app.post('/api/setup', async (req, res) => {
    if (appData.users.length > 0) return res.status(400).json({ error: 'Already set up' });
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
    const user = { id: crypto.randomUUID(), username, password: await hashPassword(password), role: 'admin' };
    appData.users.push(user);
    saveData(appData);
    req.session.loggedIn = true;
    req.session.username = user.username;
    req.session.userId   = user.id;
    res.json({ ok: true });
});

// ── Auth routes ────────────────────────────────────────────────────────────
app.get('/login', (req, res) => {
    if (req.session.loggedIn) return res.redirect('/');
    res.sendFile(path.join(__dirname, 'login.html'));
});

app.post('/login', async (req, res) => {
    const ip = req.ip;
    if (!checkRateLimit(ip)) {
        return res.redirect('/login?error=locked');
    }
    const { username, password } = req.body;
    const user = appData.users.find(u => u.username === username);
    if (user && await verifyPassword(password, user.password)) {
        resetRateLimit(ip);
        req.session.loggedIn = true;
        req.session.username = user.username;
        req.session.userId   = user.id;
        res.redirect('/');
    } else {
        res.redirect('/login?error=1');
    }
});

app.post('/logout', (req, res) => {
    req.session.destroy(() => res.redirect('/login'));
});

// ── Current user info ──────────────────────────────────────────────────────
app.get('/api/me', (req, res) => {
    const user = currentUser(req);
    if (!user) return res.status(401).json({ error: 'Not authenticated' });
    res.json({ id: user.id, username: user.username, role: user.role, permissions: getPermissions(user.role) });
});

// ── Admin API — users (admin only) ────────────────────────────────────────
app.get('/api/admin/users', requireAdmin, (_req, res) => {
    res.json(appData.users.map(u => ({ id: u.id, username: u.username, role: u.role })));
});

app.post('/api/admin/users', requireAdmin, async (req, res) => {
    const { username, password, role } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
    if (!appData.roles || !appData.roles[role]) return res.status(400).json({ error: 'Unknown role' });
    if (appData.users.some(u => u.username === username)) return res.status(400).json({ error: 'Username already exists' });
    const user = { id: crypto.randomUUID(), username, password: await hashPassword(password), role };
    appData.users.push(user);
    saveData(appData);
    res.json({ id: user.id, username: user.username, role: user.role });
});

app.put('/api/admin/users/:id', requireAdmin, async (req, res) => {
    const user = appData.users.find(u => u.id === req.params.id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    const { username, password, role } = req.body;
    if (username) {
        if (appData.users.some(u => u.username === username && u.id !== user.id)) {
            return res.status(400).json({ error: 'Username already exists' });
        }
        user.username = username;
    }
    if (password) user.password = await hashPassword(password);
    if (role && appData.roles && appData.roles[role]) {
        // Prevent removing admin role from yourself
        if (user.id === req.session.userId && role !== 'admin') {
            return res.status(400).json({ error: 'Cannot remove your own admin role' });
        }
        user.role = role;
    }
    saveData(appData);
    res.json({ id: user.id, username: user.username, role: user.role });
});

app.delete('/api/admin/users/:id', requireAdmin, (req, res) => {
    if (appData.users.length <= 1) return res.status(400).json({ error: 'Cannot delete the last user' });
    if (req.params.id === req.session.userId) return res.status(400).json({ error: 'Cannot delete your own account' });
    appData.users = appData.users.filter(u => u.id !== req.params.id);
    saveData(appData);
    res.json({ ok: true });
});

// ── Admin API — roles (admin only) ────────────────────────────────────────
app.get('/api/admin/roles', requireAdmin, (_req, res) => {
    res.json(appData.roles || {});
});

app.post('/api/admin/roles', requireAdmin, (req, res) => {
    const { name } = req.body;
    if (!name || !name.trim()) return res.status(400).json({ error: 'Role name required' });
    const key = name.trim().toLowerCase().replace(/[^a-z0-9_-]/g, '_');
    if (!appData.roles) appData.roles = {};
    if (appData.roles[key]) return res.status(400).json({ error: 'Role already exists' });
    appData.roles[key] = { canUpload: false, canDelete: false, canManage: false };
    saveData(appData);
    res.json({ role: key, permissions: appData.roles[key] });
});

app.put('/api/admin/roles/:role', requireAdmin, (req, res) => {
    const { role } = req.params;
    if (!appData.roles || !appData.roles[role]) return res.status(404).json({ error: 'Role not found' });
    const { canUpload, canDelete, canManage } = req.body;
    appData.roles[role] = { canUpload: !!canUpload, canDelete: !!canDelete, canManage: !!canManage };
    saveData(appData);
    res.json(appData.roles[role]);
});

app.delete('/api/admin/roles/:role', requireAdmin, (req, res) => {
    const { role } = req.params;
    if (role === 'admin') return res.status(400).json({ error: 'Cannot delete the admin role' });
    if (!appData.roles || !appData.roles[role]) return res.status(404).json({ error: 'Role not found' });
    const usersWithRole = appData.users.filter(u => u.role === role);
    if (usersWithRole.length > 0) return res.status(400).json({ error: `Cannot delete: ${usersWithRole.length} user(s) still have this role` });
    delete appData.roles[role];
    saveData(appData);
    res.json({ ok: true });
});

// ── Admin API — API keys (admin only) ─────────────────────────────────────
app.get('/api/admin/apikeys', requireAdmin, (_req, res) => {
    res.json(appData.apiKeys);
});

app.post('/api/admin/apikeys', requireAdmin, (req, res) => {
    const { name } = req.body;
    if (!name) return res.status(400).json({ error: 'Name required' });
    const apiKey = { id: crypto.randomUUID(), name, key: crypto.randomBytes(24).toString('base64url'), createdAt: new Date().toISOString() };
    appData.apiKeys.push(apiKey);
    saveData(appData);
    res.json(apiKey);
});

app.delete('/api/admin/apikeys/:id', requireAdmin, (req, res) => {
    appData.apiKeys = appData.apiKeys.filter(k => k.id !== req.params.id);
    saveData(appData);
    res.json({ ok: true });
});

// ── Slideshow API (external) ───────────────────────────────────────────────
const SLIDESHOW_INTERVAL_MS = 5 * 60 * 1000;

app.get('/api/slideshow/current', requireApiKey, (req, res) => {
    const files = fs.readdirSync(UPLOADS_DIR).filter(f => /\.(jpg|jpeg|png|gif|webp|bmp|svg)$/i.test(f)).sort();
    if (files.length === 0) return res.status(404).json({ error: 'No images available' });
    const slot = Math.floor(Date.now() / SLIDESHOW_INTERVAL_MS);
    const index = slot % files.length;
    const filename = files[index];
    const nextSlot = (slot + 1) * SLIDESHOW_INTERVAL_MS;
    const baseUrl = `${req.protocol}://${req.get('host')}`;
    res.json({ index, total: files.length, filename, url: `${baseUrl}/uploads/${filename}`, next_at: new Date(nextSlot).toISOString(), next_in_ms: nextSlot - Date.now() });
});

app.get('/api/slideshow/all', requireApiKey, (req, res) => {
    const files = fs.readdirSync(UPLOADS_DIR).filter(f => /\.(jpg|jpeg|png|gif|webp|bmp|svg)$/i.test(f)).sort();
    const baseUrl = `${req.protocol}://${req.get('host')}`;
    res.json(files.map((filename, i) => ({ index: i, filename, url: `${baseUrl}/uploads/${filename}` })));
});

// ── Static files ───────────────────────────────────────────────────────────
app.use(express.static(__dirname));
app.use('/uploads', express.static(UPLOADS_DIR));

// ── Images API ─────────────────────────────────────────────────────────────
app.get('/api/images', (_req, res) => {
    const files = fs.readdirSync(UPLOADS_DIR).map(filename => ({
        filename, url: `/uploads/${filename}`,
        uploadedAt: fs.statSync(path.join(UPLOADS_DIR, filename)).mtime
    }));
    files.sort((a, b) => new Date(b.uploadedAt) - new Date(a.uploadedAt));
    res.json(files);
});

app.post('/api/upload', requireUpload, upload.array('images', 50), (req, res) => {
    if (!req.files || req.files.length === 0) return res.status(400).json({ error: 'No files uploaded' });
    res.json({ uploaded: req.files.map(f => ({ filename: f.filename, url: `/uploads/${f.filename}` })) });
});

app.delete('/api/images/:filename', requireDelete, (req, res) => {
    const filename = path.basename(req.params.filename);
    const filepath = path.join(UPLOADS_DIR, filename);
    if (!fs.existsSync(filepath)) return res.status(404).json({ error: 'File not found' });
    fs.unlinkSync(filepath);
    res.json({ deleted: filename });
});

// ── Start ──────────────────────────────────────────────────────────────────
function startServer(port) {
    const server = app.listen(port, () => console.log(`Server running at http://localhost:${port}`));
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
