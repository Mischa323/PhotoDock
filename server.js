const express = require('express');
const multer  = require('multer');
const path    = require('path');
const fs      = require('fs');
const crypto  = require('crypto');
const QRCode  = require('qrcode');
const { version: pkgVersion } = require('./package.json');
const changelog    = require('./changelog.json');
const appVersion   = process.env.APP_VERSION || pkgVersion;

const app = express();
const PORT        = process.env.PORT        || 8080;
const UPLOADS_DIR = process.env.UPLOADS_DIR || path.join(__dirname, 'uploads');
const DATA_FILE   = process.env.DATA_FILE   || path.join(__dirname, 'data.json');
const CADDY_ADMIN = process.env.CADDY_ADMIN || 'http://caddy:2019';
const TOKEN_DAYS  = 30; // login cookie lifetime
const COOKIE_NAME = 'auth_token';

// ── Caddy integration ──────────────────────────────────────────────────────
function buildCaddyfile(domain) {
    return `{\n    admin 0.0.0.0:2019\n}\n\n${domain} {\n    reverse_proxy image-upload:${PORT}\n}\n`;
}

async function applyCaddyDomain(domain) {
    try {
        const res = await fetch(`${CADDY_ADMIN}/load`, {
            method: 'POST',
            headers: { 'Content-Type': 'text/caddyfile', 'Cache-Control': 'must-revalidate' },
            body: buildCaddyfile(domain)
        });
        if (!res.ok) console.error('Caddy reload failed:', await res.text());
        return res.ok;
    } catch (e) {
        console.error('Could not reach Caddy admin API:', e.message);
        return false;
    }
}

if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

// ── Password hashing ───────────────────────────────────────────────────────
async function hashPassword(plain) {
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = await new Promise((res, rej) =>
        crypto.scrypt(plain, salt, 64, (e, d) => e ? rej(e) : res(d.toString('hex')))
    );
    return `scrypt:${salt}:${hash}`;
}

async function verifyPassword(plain, stored) {
    if (!stored.startsWith('scrypt:')) return plain === stored; // legacy plain-text
    const [, salt, hash] = stored.split(':');
    const attempt = await new Promise((res, rej) =>
        crypto.scrypt(plain, salt, 64, (e, d) => e ? rej(e) : res(d.toString('hex')))
    );
    return crypto.timingSafeEqual(Buffer.from(attempt, 'hex'), Buffer.from(hash, 'hex'));
}

// ── TOTP (2FA) ─────────────────────────────────────────────────────────────
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function b32Decode(str) {
    str = str.replace(/=+$/, '').toUpperCase();
    let bits = 0, val = 0;
    const out = [];
    for (const ch of str) {
        const idx = B32.indexOf(ch);
        if (idx < 0) continue;
        val = (val << 5) | idx; bits += 5;
        if (bits >= 8) { out.push((val >> (bits - 8)) & 0xff); bits -= 8; }
    }
    return Buffer.from(out);
}

function b32Encode(buf) {
    let bits = 0, val = 0, out = '';
    for (const byte of buf) {
        val = (val << 8) | byte; bits += 8;
        while (bits >= 5) { out += B32[(val >> (bits - 5)) & 0x1f]; bits -= 5; }
    }
    if (bits > 0) out += B32[(val << (5 - bits)) & 0x1f];
    return out;
}

function generateTotpSecret() { return b32Encode(crypto.randomBytes(20)); }

function totpCode(secret, window = 0) {
    const counter = Math.floor(Date.now() / 30000) + window;
    const buf = Buffer.alloc(8);
    buf.writeBigInt64BE(BigInt(counter));
    const digest = crypto.createHmac('sha1', b32Decode(secret)).update(buf).digest();
    const offset = digest[digest.length - 1] & 0xf;
    return String((digest.readUInt32BE(offset) & 0x7fffffff) % 1000000).padStart(6, '0');
}

function verifyTotp(secret, token) {
    return [-1, 0, 1].some(w => totpCode(secret, w) === token);
}

// Pending 2FA login sessions (in-memory, 5-min TTL)
const pending2FA = new Map();

function createPending2FA(userId) {
    const token = crypto.randomBytes(16).toString('hex');
    pending2FA.set(token, { userId, expiresAt: Date.now() + 5 * 60 * 1000 });
    return token;
}

function resolvePending2FA(token) {
    const rec = pending2FA.get(token);
    if (!rec || Date.now() > rec.expiresAt) { pending2FA.delete(token); return null; }
    return rec;
}

// Pending 2FA setup secrets (in-memory, 10-min TTL)
const pending2FASetup = new Map();

// ── Login rate limiter ─────────────────────────────────────────────────────
const loginAttempts = new Map();

function checkRateLimit(ip) {
    const now = Date.now();
    const rec = loginAttempts.get(ip);
    if (!rec || now > rec.resetAt) {
        loginAttempts.set(ip, { count: 1, resetAt: now + 15 * 60 * 1000 });
        return true;
    }
    if (rec.count >= 10) return false;
    rec.count++;
    return true;
}

function resetRateLimit(ip) { loginAttempts.delete(ip); }

// ── Persistent data ────────────────────────────────────────────────────────
function loadData() {
    if (fs.existsSync(DATA_FILE)) return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
    const initial = {
        users: [], apiKeys: [], tokens: [],
        roles: {
            admin:    { canUpload: true,  canDelete: true,  canManage: true  },
            standard: { canUpload: true,  canDelete: false, canManage: false }
        },
        settings: { timezone: 'Europe/Amsterdam', showDayName: true, showDate: true, showTime: true, showSeconds: false }
    };
    fs.writeFileSync(DATA_FILE, JSON.stringify(initial, null, 2));
    return initial;
}

function saveData(data) { fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2)); }

let appData = loadData();
if (!appData.tokens) { appData.tokens = []; saveData(appData); }

// ── Cookie token helpers ───────────────────────────────────────────────────
function parseCookies(req) {
    const out = {};
    const header = req.headers.cookie;
    if (!header) return out;
    header.split(';').forEach(pair => {
        const idx = pair.indexOf('=');
        if (idx < 0) return;
        out[pair.slice(0, idx).trim()] = decodeURIComponent(pair.slice(idx + 1).trim());
    });
    return out;
}

function createToken(userId) {
    const now = Date.now();
    // Purge expired tokens
    appData.tokens = (appData.tokens || []).filter(t => new Date(t.expiresAt).getTime() > now);
    const token     = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(now + TOKEN_DAYS * 24 * 60 * 60 * 1000).toISOString();
    appData.tokens.push({ token, userId, expiresAt });
    saveData(appData);
    return { token, expiresAt };
}

function resolveToken(token) {
    if (!token) return null;
    const now = Date.now();
    const rec = (appData.tokens || []).find(t => t.token === token && new Date(t.expiresAt).getTime() > now);
    return rec ? appData.users.find(u => u.id === rec.userId) || null : null;
}

function deleteToken(token) {
    appData.tokens = (appData.tokens || []).filter(t => t.token !== token);
    saveData(appData);
}

function setCookie(res, token, expiresAt) {
    res.setHeader('Set-Cookie',
        `${COOKIE_NAME}=${token}; Path=/; HttpOnly; SameSite=Strict; Expires=${new Date(expiresAt).toUTCString()}`
    );
}

function clearCookie(res) {
    res.setHeader('Set-Cookie', `${COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0`);
}

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
app.set('trust proxy', 1); // trust X-Forwarded-Proto from Caddy so req.protocol = 'https'
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// Attach current user to every request
app.use((req, _res, next) => {
    const cookies = parseCookies(req);
    req.currentUser = resolveToken(cookies[COOKIE_NAME]) || null;
    next();
});

// ── Auth & role helpers ────────────────────────────────────────────────────
function getPermissions(role) {
    const defaults = { canUpload: false, canDelete: false, canManage: false };
    return Object.assign({}, defaults, (appData.roles || {})[role] || {});
}

function requireAuth(req, res, next) {
    if (appData.users.length === 0) {
        if (req.path === '/setup' || req.path.startsWith('/api/setup')) return next();
        return res.redirect('/setup');
    }
    if (req.currentUser) return next();
    if (req.path === '/login' || req.path === '/logout') return next();
    if (req.path === '/2fa') return next();
    if (req.path === '/api/2fa/complete') return next();
    if (req.path.startsWith('/api/slideshow/')) return next();
    if (req.path.startsWith('/api/') || req.path.startsWith('/uploads/')) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    res.redirect('/login');
}

function requirePermission(perm) {
    return (req, res, next) => {
        if (req.currentUser && getPermissions(req.currentUser.role)[perm]) return next();
        if (req.path.startsWith('/api/')) return res.status(403).json({ error: 'Permission denied' });
        res.redirect('/');
    };
}

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
    const { token, expiresAt } = createToken(user.id);
    setCookie(res, token, expiresAt);
    res.json({ ok: true });
});

// ── Auth routes ────────────────────────────────────────────────────────────
app.get('/login', (req, res) => {
    if (req.currentUser) return res.redirect('/');
    res.sendFile(path.join(__dirname, 'login.html'));
});

app.post('/login', async (req, res) => {
    const ip = req.ip;
    if (!checkRateLimit(ip)) return res.redirect('/login?error=locked');
    const { username, password } = req.body;
    const user = appData.users.find(u => u.username === username);
    if (user && await verifyPassword(password, user.password)) {
        resetRateLimit(ip);
        if (user.twoFactorEnabled) {
            const pendingToken = createPending2FA(user.id);
            return res.redirect(`/2fa?t=${pendingToken}`);
        }
        const { token, expiresAt } = createToken(user.id);
        setCookie(res, token, expiresAt);
        res.redirect('/');
    } else {
        res.redirect('/login?error=1');
    }
});

app.post('/logout', (req, res) => {
    const cookies = parseCookies(req);
    if (cookies[COOKIE_NAME]) deleteToken(cookies[COOKIE_NAME]);
    clearCookie(res);
    res.redirect('/login');
});

// ── 2FA — login completion (unauthenticated) ───────────────────────────────
app.get('/2fa', (_req, res) => res.sendFile(path.join(__dirname, '2fa.html')));

app.post('/api/2fa/complete', express.json(), (req, res) => {
    const { pendingToken, code } = req.body;
    const rec = resolvePending2FA(pendingToken);
    if (!rec) return res.status(400).json({ error: 'Session expired. Please log in again.' });
    const user = appData.users.find(u => u.id === rec.userId);
    if (!user?.twoFactorSecret) return res.status(400).json({ error: 'Invalid session' });
    if (!verifyTotp(user.twoFactorSecret, String(code).trim())) {
        return res.status(400).json({ error: 'Invalid code. Try again.' });
    }
    pending2FA.delete(pendingToken);
    const { token, expiresAt } = createToken(user.id);
    setCookie(res, token, expiresAt);
    res.json({ ok: true });
});

// ── 2FA — setup & manage (authenticated) ──────────────────────────────────
app.get('/api/2fa/status', (req, res) => {
    if (!req.currentUser) return res.status(401).json({ error: 'Not authenticated' });
    const u = appData.users.find(u => u.id === req.currentUser.id);
    res.json({ enabled: !!u.twoFactorEnabled });
});

app.get('/api/2fa/setup', async (req, res) => {
    if (!req.currentUser) return res.status(401).json({ error: 'Not authenticated' });
    const secret = generateTotpSecret();
    pending2FASetup.set(req.currentUser.id, { secret, expiresAt: Date.now() + 10 * 60 * 1000 });
    const uri = `otpauth://totp/Photo%20Display%20for%20TNMLS:${encodeURIComponent(req.currentUser.username)}?secret=${secret}&issuer=Photo%20Display%20for%20TNMLS`;
    const qrcode = await QRCode.toDataURL(uri);
    res.json({ secret, qrcode });
});

app.post('/api/2fa/enable', (req, res) => {
    if (!req.currentUser) return res.status(401).json({ error: 'Not authenticated' });
    const setup = pending2FASetup.get(req.currentUser.id);
    if (!setup || Date.now() > setup.expiresAt) return res.status(400).json({ error: 'Setup expired. Start again.' });
    const { code } = req.body;
    if (!verifyTotp(setup.secret, String(code).trim())) return res.status(400).json({ error: 'Invalid code' });
    const u = appData.users.find(u => u.id === req.currentUser.id);
    u.twoFactorSecret  = setup.secret;
    u.twoFactorEnabled = true;
    pending2FASetup.delete(req.currentUser.id);
    saveData(appData);
    res.json({ ok: true });
});

app.post('/api/2fa/disable', (req, res) => {
    if (!req.currentUser) return res.status(401).json({ error: 'Not authenticated' });
    const u = appData.users.find(u => u.id === req.currentUser.id);
    if (!u.twoFactorEnabled) return res.status(400).json({ error: '2FA is not enabled' });
    const { code } = req.body;
    if (!verifyTotp(u.twoFactorSecret, String(code).trim())) return res.status(400).json({ error: 'Invalid code' });
    delete u.twoFactorSecret;
    u.twoFactorEnabled = false;
    saveData(appData);
    res.json({ ok: true });
});

// Admin: reset another user's 2FA
app.delete('/api/admin/users/:id/2fa', requireAdmin, (req, res) => {
    const u = appData.users.find(u => u.id === req.params.id);
    if (!u) return res.status(404).json({ error: 'User not found' });
    delete u.twoFactorSecret;
    u.twoFactorEnabled = false;
    saveData(appData);
    res.json({ ok: true });
});

// ── Current user info ──────────────────────────────────────────────────────
app.get('/api/me', (req, res) => {
    const user = req.currentUser;
    if (!user) return res.status(401).json({ error: 'Not authenticated' });
    res.json({ id: user.id, username: user.username, role: user.role, permissions: getPermissions(user.role), twoFactorEnabled: !!user.twoFactorEnabled });
});

// ── Admin API — sessions (admin only) ─────────────────────────────────────
app.get('/api/admin/sessions', requireAdmin, (_req, res) => {
    const now = Date.now();
    const active = (appData.tokens || [])
        .filter(t => new Date(t.expiresAt).getTime() > now)
        .map(t => {
            const user = appData.users.find(u => u.id === t.userId);
            return { userId: t.userId, username: user?.username || '(deleted)', expiresAt: t.expiresAt };
        });
    res.json(active);
});

app.delete('/api/admin/sessions/:userId', requireAdmin, (req, res) => {
    appData.tokens = (appData.tokens || []).filter(t => t.userId !== req.params.userId);
    saveData(appData);
    res.json({ ok: true });
});

// ── Admin API — users ──────────────────────────────────────────────────────
app.get('/api/admin/users', requireAdmin, (_req, res) => {
    res.json(appData.users.map(u => ({ id: u.id, username: u.username, role: u.role, twoFactorEnabled: !!u.twoFactorEnabled })));
});

app.post('/api/admin/users', requireAdmin, async (req, res) => {
    const { username, password, role } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
    if (!appData.roles?.[role]) return res.status(400).json({ error: 'Unknown role' });
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
        if (appData.users.some(u => u.username === username && u.id !== user.id))
            return res.status(400).json({ error: 'Username already exists' });
        user.username = username;
    }
    if (password) user.password = await hashPassword(password);
    if (role && appData.roles?.[role]) {
        if (user.id === req.currentUser?.id && role !== 'admin')
            return res.status(400).json({ error: 'Cannot remove your own admin role' });
        user.role = role;
    }
    saveData(appData);
    res.json({ id: user.id, username: user.username, role: user.role });
});

app.delete('/api/admin/users/:id', requireAdmin, (req, res) => {
    if (appData.users.length <= 1) return res.status(400).json({ error: 'Cannot delete the last user' });
    if (req.params.id === req.currentUser?.id) return res.status(400).json({ error: 'Cannot delete your own account' });
    appData.users  = appData.users.filter(u => u.id !== req.params.id);
    appData.tokens = (appData.tokens || []).filter(t => t.userId !== req.params.id);
    saveData(appData);
    res.json({ ok: true });
});

// ── Admin API — roles ──────────────────────────────────────────────────────
app.get('/api/admin/roles', requireAdmin, (_req, res) => res.json(appData.roles || {}));

app.post('/api/admin/roles', requireAdmin, (req, res) => {
    const { name } = req.body;
    if (!name?.trim()) return res.status(400).json({ error: 'Role name required' });
    const key = name.trim().toLowerCase().replace(/[^a-z0-9_-]/g, '_');
    if (!appData.roles) appData.roles = {};
    if (appData.roles[key]) return res.status(400).json({ error: 'Role already exists' });
    appData.roles[key] = { canUpload: false, canDelete: false, canManage: false };
    saveData(appData);
    res.json({ role: key, permissions: appData.roles[key] });
});

app.put('/api/admin/roles/:role', requireAdmin, (req, res) => {
    const { role } = req.params;
    if (!appData.roles?.[role]) return res.status(404).json({ error: 'Role not found' });
    const { canUpload, canDelete, canManage } = req.body;
    appData.roles[role] = { canUpload: !!canUpload, canDelete: !!canDelete, canManage: !!canManage };
    saveData(appData);
    res.json(appData.roles[role]);
});

app.delete('/api/admin/roles/:role', requireAdmin, (req, res) => {
    const { role } = req.params;
    if (role === 'admin') return res.status(400).json({ error: 'Cannot delete the admin role' });
    if (!appData.roles?.[role]) return res.status(404).json({ error: 'Role not found' });
    const inUse = appData.users.filter(u => u.role === role).length;
    if (inUse > 0) return res.status(400).json({ error: `Cannot delete: ${inUse} user(s) still have this role` });
    delete appData.roles[role];
    saveData(appData);
    res.json({ ok: true });
});

// ── Admin API — API keys ───────────────────────────────────────────────────
app.get('/api/admin/apikeys', requireAdmin, (_req, res) => res.json(appData.apiKeys));

app.post('/api/admin/apikeys', requireAdmin, (req, res) => {
    const { name, interval } = req.body;
    if (!name) return res.status(400).json({ error: 'Name required' });
    const apiKey = { id: crypto.randomUUID(), name, key: crypto.randomBytes(24).toString('base64url'), intervalMinutes: Math.max(1, parseInt(interval) || 5), createdAt: new Date().toISOString() };
    appData.apiKeys.push(apiKey);
    saveData(appData);
    res.json(apiKey);
});

app.put('/api/admin/apikeys/:id', requireAdmin, (req, res) => {
    const apiKey = appData.apiKeys.find(k => k.id === req.params.id);
    if (!apiKey) return res.status(404).json({ error: 'Key not found' });
    const { name, interval } = req.body;
    if (name) apiKey.name = name;
    if (interval !== undefined) apiKey.intervalMinutes = Math.max(1, parseInt(interval) || 5);
    saveData(appData);
    res.json(apiKey);
});

app.delete('/api/admin/apikeys/:id', requireAdmin, (req, res) => {
    appData.apiKeys = appData.apiKeys.filter(k => k.id !== req.params.id);
    saveData(appData);
    res.json({ ok: true });
});

// ── Domain / Caddy ────────────────────────────────────────────────────────
app.get('/api/admin/domain', requireAdmin, (_req, res) => {
    res.json({ domain: appData.settings?.domain || '' });
});

app.put('/api/admin/domain', requireAdmin, async (req, res) => {
    const domain = (req.body.domain || '').trim();
    if (!domain) return res.status(400).json({ error: 'Domain is required' });
    const ok = await applyCaddyDomain(domain);
    if (!ok) return res.status(502).json({ error: 'Could not reach Caddy. Is it running?' });
    appData.settings.domain = domain;
    saveData(appData);
    res.json({ ok: true, domain });
});

// ── Display settings ───────────────────────────────────────────────────────
const DEFAULT_SETTINGS = { timezone: 'Europe/Amsterdam', showDayName: true, showDate: true, showTime: true, showSeconds: false, accentColor: '#06b6d4' };

app.get('/api/settings', (_req, res) => res.json(Object.assign({}, DEFAULT_SETTINGS, appData.settings || {})));

app.put('/api/settings', requireAdmin, (req, res) => {
    const { timezone, showDayName, showDate, showTime, showSeconds, accentColor } = req.body;
    try { Intl.DateTimeFormat(undefined, { timeZone: timezone }); } catch { return res.status(400).json({ error: 'Invalid timezone' }); }
    if (accentColor && !/^#[0-9a-fA-F]{6}$/.test(accentColor)) return res.status(400).json({ error: 'Invalid colour' });
    appData.settings = { timezone, showDayName: !!showDayName, showDate: !!showDate, showTime: !!showTime, showSeconds: !!showSeconds, accentColor: accentColor || DEFAULT_SETTINGS.accentColor };
    saveData(appData);
    res.json(appData.settings);
});

// ── Slideshow API (external) ───────────────────────────────────────────────
app.get('/api/slideshow/current', requireApiKey, (req, res) => {
    const keyRecord  = appData.apiKeys.find(k => k.key === (req.headers['x-api-key'] || req.query.key));
    const intervalMs = (keyRecord?.intervalMinutes || 5) * 60 * 1000;
    const files      = fs.readdirSync(UPLOADS_DIR).filter(f => /\.(jpg|jpeg|png|gif|webp|bmp|svg)$/i.test(f)).sort();
    if (files.length === 0) return res.status(404).json({ error: 'No images available' });
    const slot     = Math.floor(Date.now() / intervalMs);
    const index    = slot % files.length;
    const filename = files[index];
    const nextSlot = (slot + 1) * intervalMs;
    const baseUrl  = `${req.protocol}://${req.get('host')}`;
    res.json({ index, total: files.length, filename, url: `${baseUrl}/uploads/${filename}`, interval_minutes: keyRecord?.intervalMinutes || 5, next_at: new Date(nextSlot).toISOString(), next_in_ms: nextSlot - Date.now() });
});

app.get('/api/slideshow/all', requireApiKey, (req, res) => {
    const files   = fs.readdirSync(UPLOADS_DIR).filter(f => /\.(jpg|jpeg|png|gif|webp|bmp|svg)$/i.test(f)).sort();
    const baseUrl = `${req.protocol}://${req.get('host')}`;
    res.json(files.map((filename, i) => ({ index: i, filename, url: `${baseUrl}/uploads/${filename}` })));
});

// ── Version ────────────────────────────────────────────────────────────────
app.get('/api/version', (_req, res) => res.json({ version: appVersion, changelog }));

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
    if (!req.files?.length) return res.status(400).json({ error: 'No files uploaded' });
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
    server.on('error', err => {
        if (err.code === 'EADDRINUSE' || err.code === 'EACCES') {
            console.log(`Port ${port} unavailable, trying ${port + 1}...`);
            startServer(port + 1);
        } else {
            console.error('Server error:', err);
        }
    });
}

startServer(Number(PORT));

// Re-apply stored domain to Caddy after startup (handles Caddy restarts)
if (appData.settings?.domain) {
    setTimeout(() => applyCaddyDomain(appData.settings.domain), 5000);
}
