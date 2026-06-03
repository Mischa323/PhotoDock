const express = require('express');
const https   = require('https');
const multer  = require('multer');
const path    = require('path');
const fs      = require('fs');
const os      = require('os');
const crypto  = require('crypto');
const { spawn, execSync, exec } = require('child_process');
const QRCode      = require('qrcode');
const nodemailer  = require('nodemailer');
const sharp       = require('sharp');
const heicConvert = require('heic-convert');
const { version: pkgVersion } = require('../package.json');
const changelog    = require('./changelog.json');
const appVersion   = process.env.APP_VERSION || pkgVersion;

const ROOT_DIR    = path.join(__dirname, '..');
const FRONTEND_DIR = path.join(ROOT_DIR, 'frontend');
const ESP32_DIR    = path.join(ROOT_DIR, 'esp32');
const FIRMWARE_DIR = path.join(ROOT_DIR, 'firmware_build');
const CUSTOM_FW_DIR = path.join(ROOT_DIR, 'custom_firmware');   // cloned community board repos

const app = express();
const PORT        = process.env.PORT        || 8080;
const HTTPS_PORT  = process.env.HTTPS_PORT  !== undefined ? process.env.HTTPS_PORT : '8081';
const SSL_CERT    = process.env.SSL_CERT    || null; // path to certificate file (auto-generated if absent)
const SSL_KEY     = process.env.SSL_KEY     || null; // path to private key file (auto-generated if absent)
const UPLOADS_DIR = process.env.UPLOADS_DIR || path.join(ROOT_DIR, 'uploads');
const DATA_FILE   = process.env.DATA_FILE   || path.join(ROOT_DIR, 'data.json');
const TOKEN_DAYS  = 30; // login cookie lifetime
const COOKIE_NAME = 'auth_token';


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
    if (!stored.startsWith('scrypt:')) {
        // Legacy plain-text — use timing-safe comparison to prevent user enumeration
        const a = Buffer.from(plain);
        const b = Buffer.from(stored);
        return a.length === b.length && crypto.timingSafeEqual(a, b);
    }
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

// Device pairing sessions (in-memory, 10-min TTL)
const pendingPairings = new Map(); // token -> { code, hwId, model, requestedAt, status, apiKeyId, screenId }

function cleanPairings() {
    const cut = Date.now() - 10 * 60 * 1000;
    for (const [t, p] of pendingPairings)
        if (new Date(p.requestedAt).getTime() < cut) pendingPairings.delete(t);
}

// Short, human-typeable pairing code (no ambiguous chars: 0/O, 1/I, etc.)
const PAIR_CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
function generatePairCode() {
    let code;
    do {
        code = Array.from({ length: 6 }, () =>
            PAIR_CODE_ALPHABET[crypto.randomInt(PAIR_CODE_ALPHABET.length)]).join('');
    } while ([...pendingPairings.values()].some(p => p.code === code));
    return code;
}
function findPairingByCode(code) {
    const norm = String(code || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
    for (const [token, p] of pendingPairings)
        if (p.code === norm) return { token, pairing: p };
    return null;
}

function createPending2FA(userId, emailOtp = null) {
    const token = crypto.randomBytes(16).toString('hex');
    pending2FA.set(token, { userId, expiresAt: Date.now() + 5 * 60 * 1000, emailOtp });
    return token;
}

function resolvePending2FA(token) {
    const rec = pending2FA.get(token);
    if (!rec || Date.now() > rec.expiresAt) { pending2FA.delete(token); return null; }
    return rec;
}

// Pending 2FA setup secrets (in-memory, 10-min TTL)
const pending2FASetup = new Map();

// Email OTP codes for 2FA setup/disable (5-min TTL)
const emailVerifyOtps = new Map(); // userId → { otp, expiresAt, purpose }

function generateOtp() {
    return String(crypto.randomInt(100000, 1000000)).padStart(6, '0');
}

function maskEmail(email) {
    if (!email) return null;
    const [local, domain] = email.split('@');
    return local.slice(0, 2) + '***@' + domain;
}

function otpEmailHtml(code) {
    return `<div style="font-family:sans-serif;max-width:420px;margin:0 auto;padding:32px 24px">
        <h2 style="color:#0e7490;margin:0 0 8px">PhotoDock</h2>
        <p style="color:#444;margin:0 0 24px">Your verification code is:</p>
        <div style="font-size:40px;font-weight:700;letter-spacing:12px;color:#0e7490;padding:16px 0;font-family:monospace">${code}</div>
        <p style="color:#888;font-size:13px;margin-top:24px">This code expires in 5 minutes.<br>If you did not request this, you can safely ignore this email.</p>
    </div>`;
}

async function sendEmail(to, subject, html) {
    const cfg = appData.settings?.email;
    if (!cfg?.method) throw new Error('Email is not configured');
    if (cfg.method === 'smtp') {
        const s = cfg.smtp || {};
        if (!s.host || !s.from) throw new Error('SMTP host and From address are required');
        const opts = { host: s.host, port: parseInt(s.port) || 587, secure: !!s.secure };
        if (s.user && s.password) opts.auth = { user: s.user, pass: s.password };
        const transporter = nodemailer.createTransport(opts);
        await transporter.sendMail({ from: s.from, to, subject, html });
    } else if (cfg.method === 'graph') {
        const g = cfg.graph || {};
        if (!g.tenantId || !g.clientId || !g.clientSecret || !g.from)
            throw new Error('Microsoft Graph configuration is incomplete');
        const tokenRes = await fetch(
            `https://login.microsoftonline.com/${encodeURIComponent(g.tenantId)}/oauth2/v2.0/token`,
            { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
              body: new URLSearchParams({ grant_type: 'client_credentials', client_id: g.clientId,
                  client_secret: g.clientSecret, scope: 'https://graph.microsoft.com/.default' }) }
        );
        if (!tokenRes.ok) throw new Error('Could not get Microsoft access token');
        const { access_token } = await tokenRes.json();
        const mailRes = await fetch(
            `https://graph.microsoft.com/v1.0/users/${encodeURIComponent(g.from)}/sendMail`,
            { method: 'POST',
              headers: { 'Authorization': `Bearer ${access_token}`, 'Content-Type': 'application/json' },
              body: JSON.stringify({ message: { subject,
                  body: { contentType: 'HTML', content: html },
                  toRecipients: [{ emailAddress: { address: to } }] } }) }
        );
        if (!mailRes.ok) throw new Error('Graph API error: ' + await mailRes.text());
    } else {
        throw new Error('Unknown email method');
    }
}

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

// ── 2FA completion rate limiter (5 attempts per 10 min per IP) ─────────────
const twoFaAttempts = new Map();

function check2FARateLimit(ip) {
    const now = Date.now();
    const rec = twoFaAttempts.get(ip);
    if (!rec || now > rec.resetAt) {
        twoFaAttempts.set(ip, { count: 1, resetAt: now + 10 * 60 * 1000 });
        return true;
    }
    if (rec.count >= 5) return false;
    rec.count++;
    return true;
}

function reset2FARateLimit(ip) { twoFaAttempts.delete(ip); }

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

// ── Secret-at-rest encryption (AES-256-GCM) ────────────────────────────────
// Used for secrets we must keep but should never store in plaintext (e.g. a
// device's WiFi password, kept so firmware can be rebuilt without re-entering
// it). The key is taken from PHOTODOCK_SECRET_KEY (hex/base64) or auto-generated
// once into secret.key (git-ignored) next to data.json.
const KEY_FILE = path.join(path.dirname(DATA_FILE), 'secret.key');
const SECRET_KEY = (() => {
    const env = process.env.PHOTODOCK_SECRET_KEY;
    if (env) {
        const buf = /^[0-9a-fA-F]{64}$/.test(env) ? Buffer.from(env, 'hex') : Buffer.from(env, 'base64');
        if (buf.length === 32) return buf;
        console.error('PHOTODOCK_SECRET_KEY must be 32 bytes (64 hex chars or base64); ignoring.');
    }
    try { const b = fs.readFileSync(KEY_FILE); if (b.length === 32) return b; } catch {}
    const key = crypto.randomBytes(32);
    try { fs.writeFileSync(KEY_FILE, key, { mode: 0o600 }); }
    catch (e) { console.error('Could not persist secret.key — encrypted secrets will not survive a restart:', e.message); }
    return key;
})();
function encryptSecret(plain) {
    if (plain == null || plain === '') return '';
    const iv  = crypto.randomBytes(12);
    const c   = crypto.createCipheriv('aes-256-gcm', SECRET_KEY, iv);
    const ct  = Buffer.concat([c.update(String(plain), 'utf8'), c.final()]);
    return 'gcm1:' + Buffer.concat([iv, c.getAuthTag(), ct]).toString('base64');
}
function decryptSecret(enc) {
    if (!enc || typeof enc !== 'string' || !enc.startsWith('gcm1:')) return '';
    try {
        const raw = Buffer.from(enc.slice(5), 'base64');
        if (raw.length < 28) return '';                 // need iv(12) + tag(16) at minimum
        const d = crypto.createDecipheriv('aes-256-gcm', SECRET_KEY, raw.subarray(0, 12), { authTagLength: 16 });
        d.setAuthTag(raw.subarray(12, 28));
        return Buffer.concat([d.update(raw.subarray(28)), d.final()]).toString('utf8');
    } catch { return ''; }
}

let appData = loadData();
if (!appData.tokens)        { appData.tokens        = []; saveData(appData); }
if (!appData.logs)          { appData.logs          = []; saveData(appData); }
if (!appData.imageMetadata) { appData.imageMetadata = {}; saveData(appData); }
if (!appData.screens)       { appData.screens       = []; saveData(appData); }
if (!appData.albums)        { appData.albums        = []; saveData(appData); }
if (!appData.deviceStatus)  { appData.deviceStatus  = {}; saveData(appData); }

const MAX_LOGS = 500;
function addLog(event, { user, keyName, ip, detail } = {}) {
    if (!appData.logs) appData.logs = [];
    appData.logs.unshift({ timestamp: new Date().toISOString(), event, user: user || null, keyName: keyName || null, ip: ip || null, detail: detail || null });
    if (appData.logs.length > MAX_LOGS) appData.logs.length = MAX_LOGS;
    saveData(appData);
}

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

function setCookie(res, token, expiresAt, req = null) {
    const secure = req?.secure || req?.headers['x-forwarded-proto'] === 'https' ? '; Secure' : '';
    res.setHeader('Set-Cookie',
        `${COOKIE_NAME}=${token}; Path=/; HttpOnly; SameSite=Strict; Expires=${new Date(expiresAt).toUTCString()}${secure}`
    );
}

function clearCookie(res, req = null) {
    const secure = req?.secure || req?.headers['x-forwarded-proto'] === 'https' ? '; Secure' : '';
    res.setHeader('Set-Cookie', `${COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${secure}`);
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

const HEIC_EXTS  = new Set(['.heic', '.heif']);
const IMAGE_EXTS = /\.(jpg|jpeg|png|gif|webp|bmp|svg|heic|heif)$/i;

const upload = multer({
    storage,
    fileFilter: (_req, file, cb) => {
        const ext = path.extname(file.originalname).toLowerCase();
        // Accept by MIME type OR by extension — browsers often send HEIC as application/octet-stream
        if (file.mimetype.startsWith('image/') || HEIC_EXTS.has(ext)) cb(null, true);
        else cb(new Error('Only image files are allowed'));
    },
    limits: { fileSize: 50 * 1024 * 1024 } // raised to 50 MB for HEIC (raw files are large)
});

// ── Middleware ─────────────────────────────────────────────────────────────
app.set('trust proxy', 1); // Trust first hop (nginx/caddy) for accurate req.ip
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

// ── Screen access control ──────────────────────────────────────────────────
// Access is granted per ROLE (each role acts as a group): a role lists the
// screen IDs its members may see. Admins (canManage) implicitly get every
// screen, so their role's list is ignored.
function isAdmin(user) {
    return !!(user && getPermissions(user.role).canManage);
}
function roleScreens(role) {
    return ((appData.roles || {})[role]?.screens) || [];
}
function accessibleScreenIds(user) {
    return isAdmin(user) ? (appData.screens || []).map(s => s.id) : roleScreens(user?.role);
}
function userCanAccessScreen(user, screenId) {
    if (isAdmin(user)) return true;
    return !!screenId && roleScreens(user?.role).includes(screenId);
}
// Can this user see this specific photo? Assigned photos need a grant on the
// user's role; unassigned (library) photos are visible only to their uploader.
function userCanSeeImage(user, filename) {
    if (isAdmin(user)) return true;
    const m = (appData.imageMetadata || {})[filename] || {};
    if (m.screenId) return roleScreens(user?.role).includes(m.screenId);
    return m.uploadedBy === user?.username;
}

function requireAuth(req, res, next) {
    // Static frontend assets (stylesheet, fonts, icons, client JS) must always load
    // — the setup and login pages need them before any session/admin account exists.
    // Page shells (.html) are deliberately excluded so they stay behind their routes.
    if (req.method === 'GET' && /\.(css|js|mjs|svg|png|jpe?g|gif|ico|webp|woff2?|ttf|map)$/i.test(req.path))
        return next();
    if (appData.users.length === 0) {
        if (req.path === '/setup' || req.path.startsWith('/api/setup')) return next();
        return res.redirect('/setup');
    }
    if (req.currentUser) return next();
    if (req.path === '/login' || req.path === '/logout') return next();
    if (req.path === '/2fa') return next();
    if (req.path === '/api/2fa/complete') return next();
    if (req.path === '/api/2fa/email/resend') return next();
    if (req.path.startsWith('/api/slideshow/')) return next();
    // Device-facing endpoints authenticate with an API key (requireApiKey), not
    // a user session — let them through the session wall.
    if (req.path.startsWith('/api/device/')) return next();
    // OTA firmware download (no session — the ESP32 fetches this directly).
    if (req.path.startsWith('/firmware/')) return next();
    if (req.path === '/pair') return next();
    if (req.path === '/api/devices/pair/request') return next();
    if (req.method === 'GET' && req.path.startsWith('/api/devices/pair/')) return next();
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
    const key       = req.headers['x-api-key'] || req.query.key;
    const keyRecord = appData.apiKeys.find(k => k.key === key);
    if (!keyRecord) return res.status(401).json({ error: 'Invalid or missing API key' });
    req.apiKey = keyRecord;
    // Update lastUsed at most once per minute to avoid thrashing the file
    const now = Date.now();
    if (!keyRecord.lastUsed || now - new Date(keyRecord.lastUsed).getTime() > 60000) {
        keyRecord.lastUsed = new Date(now).toISOString();
        saveData(appData);
    }
    next();
}

// Returns middleware that checks whether req.apiKey has access to a named endpoint.
// Keys with no allowedEndpoints restriction (null/undefined) pass through (backward compatible).
// Also logs the call to the activity log, throttled to once per 10 minutes per key.
const apiCallLastLogged = new Map(); // keyId -> { endpoint, ts } — in-memory only
const API_LOG_THROTTLE_MS = 10 * 60 * 1000;

function requireEndpoint(name) {
    return (req, res, next) => {
        const allowed = req.apiKey?.allowedEndpoints;
        if (!allowed || allowed.includes(name)) {
            // Throttled activity log entry
            const key     = req.apiKey;
            const mapKey  = `${key.id}:${name}`;
            const lastTs  = apiCallLastLogged.get(mapKey) || 0;
            if (Date.now() - lastTs >= API_LOG_THROTTLE_MS) {
                apiCallLastLogged.set(mapKey, Date.now());
                addLog(`api_${name}`, { keyName: key.name, ip: req.ip });
            }
            return next();
        }
        res.status(403).json({ error: 'This API key does not have access to this endpoint' });
    };
}

// ── Device pairing (unauthenticated — device + QR landing page) ───────────
app.get('/pair', (_req, res) => res.sendFile(path.join(FRONTEND_DIR, 'pair.html')));

// Device requests a pairing token on boot
app.post('/api/devices/pair/request', express.json(), (req, res) => {
    cleanPairings();
    const { hwId, model } = req.body || {};
    const token = crypto.randomBytes(16).toString('hex');
    const code  = generatePairCode();
    pendingPairings.set(token, {
        code,
        hwId:        (hwId  || '').slice(0, 64),
        model:       (model || 'PhotoPainter').slice(0, 64),
        requestedAt: new Date().toISOString(),
        status:      'pending',
        apiKeyId:    null,
        screenId:    null,
    });
    const pairUrl = `${req.protocol}://${req.get('host')}/pair?token=${token}`;
    res.json({ token, code, pairUrl });
});

// Resolve a short pairing code (typed by a user) to its token
app.get('/api/devices/pair/code/:code', (req, res) => {
    cleanPairings();
    const found = findPairingByCode(req.params.code);
    if (!found) return res.status(404).json({ error: 'No device found for that code' });
    res.json({ token: found.token });
});

// Device polls this to check if pairing completed
app.get('/api/devices/pair/:token', (req, res) => {
    const p = pendingPairings.get(req.params.token);
    if (!p) return res.json({ status: 'expired' });
    if (p.status === 'pending') return res.json({ status: 'pending', hwId: p.hwId, model: p.model, requestedAt: p.requestedAt });
    // complete — return the API key so device can store it
    const key = (appData.apiKeys || []).find(k => k.id === p.apiKeyId);
    const scr = (appData.screens  || []).find(s => s.id === p.screenId);
    res.json({ status: 'complete', apiKey: key?.key || null, screenName: scr?.name || null });
});

app.use(requireAuth);

// ── Firmware build state ───────────────────────────────────────────────────
let buildInProgress = false;

function findPio() {
    const home = process.env.USERPROFILE || process.env.HOME || '';
    if (process.platform === 'win32') {
        const candidates = [
            path.join(home, '.platformio', 'penv', 'Scripts', 'pio.exe'),
        ];
        const pythonRoots = ['C:\\Python314','C:\\Python313','C:\\Python312','C:\\Python311','C:\\Python310',
            path.join(home,'AppData','Local','Programs','Python','Python314'),
            path.join(home,'AppData','Local','Programs','Python','Python313'),
        ];
        for (const r of pythonRoots) candidates.push(path.join(r,'Scripts','pio.exe'));
        const appData = process.env.APPDATA || path.join(home,'AppData','Roaming');
        for (const ver of ['Python314','Python313','Python312','Python311','Python310'])
            candidates.push(path.join(appData,'Python',ver,'Scripts','pio.exe'));
        for (const p of candidates) { if (fs.existsSync(p)) return p; }
    } else {
        const candidates = [
            path.join(home,'.platformio','penv','bin','pio'),
            '/usr/local/bin/pio',
            '/usr/bin/pio',
        ];
        for (const p of candidates) { if (fs.existsSync(p)) return p; }
    }
    return 'pio';
}

function findBoot0() {
    const home = process.env.USERPROFILE || process.env.HOME || '';
    const pkgsDir = path.join(home,'.platformio','packages');
    try {
        for (const pkg of fs.readdirSync(pkgsDir)) {
            if (!pkg.startsWith('framework-arduino')) continue;
            const candidate = path.join(pkgsDir, pkg, 'tools', 'partitions', 'boot_app0.bin');
            if (fs.existsSync(candidate)) return candidate;
        }
    } catch {}
    if (process.platform !== 'win32') {
        try {
            const p = execSync('find /root/.platformio -name boot_app0.bin 2>/dev/null | head -1').toString().trim();
            if (p) return p;
        } catch {}
    }
    return null;
}

// Map a wizard "device type" to its PlatformIO env, firmware output folder and
// the URL prefix esp-web-tools downloads its parts from.
const DEVICE_BUILDS = {
    'waveshare-s3-photopainter': { env: 'esp32s3-photopainter', dir: FIRMWARE_DIR,                                 urlPrefix: '/firmware',                   model: 'PhotoPainter-E6' },
    'reterminal-e1001':          { env: 'reterminal-e1001',     dir: path.join(FIRMWARE_DIR, 'reterminal-e1001'), urlPrefix: '/firmware/reterminal-e1001',  model: 'reTerminal-E1001' },
};
function deviceBuild(type) { return DEVICE_BUILDS[type] || DEVICE_BUILDS['waveshare-s3-photopainter']; }

// Write esp32/src/config.h for a build. With no/empty values this reproduces the
// repo's credential-free config exactly, so calling it after a build "wipes" any
// baked WiFi password back out of the working tree (kept plaintext only while the
// compiler needs it). The password itself is stored encrypted (see wifiCreds).
function writeConfigH({ wifi_ssid = '', wifi_password = '', server_host = '', server_port = 8080 } = {}) {
    const esc = s => String(s).replace(/\\/g, '\\\\').replace(/"/g, '\\"');
    const content = [
        '#pragma once',
        '#define DEFAULT_SLEEP_S         (5 * 60)',
        '#define BATTERY_ADC_PIN         4',
        '#define BATTERY_DIVIDER_RATIO   2.0f',
        '#define JPEG_BUF_SIZE           (512 * 1024)',
        '// Leave SSID/API key empty to force the on-device WiFi setup portal on first boot.',
        '// Fill them in only if you want to bake credentials into the firmware ("auto mode").',
        `#define DEFAULT_WIFI_SSID       "${esc(wifi_ssid)}"`,
        `#define DEFAULT_WIFI_PASS       "${esc(wifi_password)}"`,
        `#define DEFAULT_SERVER_HOST     "${esc(server_host)}"`,
        `#define DEFAULT_SERVER_PORT     ${parseInt(server_port) || 8080}`,
        '#define DEFAULT_API_KEY         ""',
    ].join('\n') + '\n';
    fs.mkdirSync(path.join(ESP32_DIR, 'src'), { recursive: true });
    fs.writeFileSync(path.join(ESP32_DIR, 'src', 'config.h'), content);
}

app.get('/api/admin/firmware/status', requireAdmin, (req, res) => {
    const b = deviceBuild(req.query.device);
    const manifest = path.join(b.dir, 'manifest.json');
    const firmware = path.join(b.dir, 'firmware.bin');
    const ready    = fs.existsSync(manifest) && fs.existsSync(firmware);
    let builtAt    = null;
    if (ready) { try { builtAt = fs.statSync(firmware).mtime.toISOString(); } catch {} }
    res.json({ ready, builtAt, buildInProgress });
});

app.post('/api/admin/firmware/build', requireAdmin, express.json(), (req, res) => {
    if (buildInProgress) return res.status(409).json({ error: 'A build is already in progress' });

    let { wifi_ssid='', wifi_password='', server_host='', server_port=8080, device='' } = req.body || {};
    const bld = deviceBuild(device);

    // WiFi password is encrypted at rest, never kept in plaintext:
    //  - left blank but saved for this SSID -> reuse the saved one (no re-typing);
    //  - provided -> remember it encrypted so this device can be rebuilt later.
    // config.h must be plaintext for the compiler, so it is wiped after the build.
    if (wifi_ssid && !wifi_password) wifi_password = decryptSecret((appData.wifiCreds || {})[wifi_ssid]);
    // Automatic setup must have a usable password — never silently build a device
    // that can't join WiFi (that's what "auto firmware won't connect" looks like).
    if (wifi_ssid && server_host && !wifi_password) {
        return res.status(400).json({ error: 'Enter the WiFi password — automatic setup needs it to connect.' });
    }
    if (wifi_ssid && wifi_password) {
        (appData.wifiCreds || (appData.wifiCreds = {}))[wifi_ssid] = encryptSecret(wifi_password);
        saveData(appData);
    }

    writeConfigH({ wifi_ssid, wifi_password, server_host, server_port });

    const pioBin = findPio();
    const pioOk = pioBin !== 'pio'
        ? fs.existsSync(pioBin)
        : (() => { try { execSync(process.platform==='win32'?'where pio':'which pio',{stdio:'ignore',timeout:3000}); return true; } catch { return false; } })();

    if (!pioOk) {
        return res.status(500).json({
            error: `PlatformIO not found. Install with: pip install platformio, then restart the server.`
        });
    }

    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.socket?.setTimeout(0);
    res.flushHeaders();

    const send = (type, data) => { try { res.write(`data: ${JSON.stringify({type,data})}\n\n`); } catch {} };

    buildInProgress = true;
    send('log', `▶ PlatformIO: ${pioBin}\n▶ Starting build…\n`);

    const keepalive = setInterval(() => { try { res.write(': ping\n\n'); } catch {} }, 15000);

    const pio = spawn(pioBin, ['run', '-e', bld.env], {
        cwd: ESP32_DIR,
        env: { ...process.env, CI:'1', PLATFORMIO_DISABLE_AUTO_CHECK_UPDATES:'1' },
        shell: process.platform === 'win32',
    });

    pio.stdout.on('data', d => send('log', d.toString()));
    pio.stderr.on('data', d => send('log', d.toString()));

    pio.on('error', err => {
        clearInterval(keepalive);
        buildInProgress = false;
        try { writeConfigH(); } catch {}   // wipe the plaintext WiFi password back out
        send('error', `Cannot start PlatformIO: ${err.message}\n\nInstall with: pip install platformio`);
        res.end();
    });

    pio.on('close', (code, signal) => {
        clearInterval(keepalive);
        buildInProgress = false;
        try { writeConfigH(); } catch {}   // wipe the plaintext WiFi password back out
        if (code !== 0) {
            send('error', `Build failed (${signal ? 'killed by signal ' + signal : 'exit code ' + code})`);
            res.end();
            return;
        }
        try {
            const buildDir = path.join(ESP32_DIR, '.pio', 'build', bld.env);
            writeFirmwareOutput(buildDir, bld.dir, bld.urlPrefix, 'PhotoDock', send);
            send('done', 'Build succeeded — firmware is ready to flash');
        } catch (e) {
            send('error', `Post-build copy failed: ${e.message}`);
        }
        res.end();
    });
});

// ── Custom devices (admin-only): clone a firmware repo from GitHub and build it ──
// SECURITY: this clones and compiles arbitrary code on the server, so it is
// admin-only and intended for a trusted, self-hosted operator. A malicious repo
// could run arbitrary build scripts — only add repos you trust.
function customDevices() { return appData.customDevices || (appData.customDevices = []); }
// Strict input validators. These run on values that get passed to `git`/`pio`
// (which use a shell on Windows), so they must reject shell metacharacters
// (spaces, quotes, ; & | $ ` etc.) to prevent command injection.
const RE_GIT_URL = /^https:\/\/[\w.-]+(:\d+)?\/[\w./~-]+?(\.git)?\/?$/;
const RE_GIT_REF = /^[\w][\w./-]{0,99}$/;
const RE_PIO_ENV = /^[\w-]{1,40}$/;
function slugify(s) {
    return String(s).toLowerCase().replace(/[^a-z0-9._-]+/g, '-').replace(/^[-.]+|[-.]+$/g, '').slice(0, 40) || 'device';
}
function uniqueSlug(base) {
    const taken = new Set(customDevices().map(d => d.slug));
    if (!taken.has(base)) return base;
    let i = 2; while (taken.has(`${base}-${i}`)) i++;
    return `${base}-${i}`;
}

app.get('/api/admin/custom-devices', requireAdmin, (_req, res) => {
    res.json(customDevices().map(d => ({ ...d, current: currentFirmwareInfo(d.modelId)?.version || null })));
});

app.post('/api/admin/custom-devices', requireAdmin, express.json(), (req, res) => {
    const { name, repoUrl, ref, env, modelId } = req.body || {};
    if (!name?.trim() || !repoUrl?.trim() || !modelId?.trim())
        return res.status(400).json({ error: 'name, repoUrl and modelId are required' });
    if (!RE_GIT_URL.test(repoUrl.trim()))
        return res.status(400).json({ error: 'repoUrl must be a plain https git URL (no spaces or special characters)' });
    if (ref && !RE_GIT_REF.test(ref.trim()))
        return res.status(400).json({ error: 'Invalid branch/tag name' });
    if (env && !RE_PIO_ENV.test(env.trim()))
        return res.status(400).json({ error: 'Invalid PlatformIO env name' });
    if (customDevices().some(d => d.modelId === modelId.trim()))
        return res.status(400).json({ error: 'A custom device with that model id already exists' });
    const dev = {
        id: crypto.randomUUID(),
        name: name.trim(),
        modelId: modelId.trim(),
        slug: uniqueSlug(slugify(modelId)),
        repoUrl: repoUrl.trim(),
        ref: (ref || 'main').trim(),
        env: (env || '').trim(),     // optional PlatformIO env to build
        status: 'new', version: null, builtAt: null, error: null,
    };
    customDevices().push(dev);
    saveData(appData);
    res.json(dev);
});

app.delete('/api/admin/custom-devices/:id', requireAdmin, (req, res) => {
    const list = customDevices();
    const i = list.findIndex(d => d.id === req.params.id);
    if (i < 0) return res.status(404).json({ error: 'Not found' });
    const [dev] = list.splice(i, 1);
    saveData(appData);
    try { fs.rmSync(path.join(CUSTOM_FW_DIR, dev.slug), { recursive: true, force: true }); } catch {}
    try { fs.rmSync(path.join(FIRMWARE_DIR, dev.slug),  { recursive: true, force: true }); } catch {}
    res.json({ ok: true });
});

// Run a command, streaming output to the SSE `send`. Resolves with the exit code.
function runStreamed(cmd, args, opts, send) {
    return new Promise(resolve => {
        send('log', `\n▶ ${cmd} ${args.join(' ')}\n`);
        let p;
        try { p = spawn(cmd, args, { ...opts, shell: process.platform === 'win32' }); }
        catch (e) { send('log', `cannot start ${cmd}: ${e.message}\n`); return resolve(-1); }
        p.stdout.on('data', d => send('log', d.toString()));
        p.stderr.on('data', d => send('log', d.toString()));
        p.on('error', e => { send('log', `error: ${e.message}\n`); resolve(-1); });
        p.on('close', code => resolve(code));
    });
}

app.post('/api/admin/custom-devices/:id/build', requireAdmin, async (req, res) => {
    if (buildInProgress) return res.status(409).json({ error: 'A build is already in progress' });
    const dev = customDevices().find(d => d.id === req.params.id);
    if (!dev) return res.status(404).json({ error: 'Not found' });

    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.socket?.setTimeout(0);
    res.flushHeaders();
    const send = (type, data) => { try { res.write(`data: ${JSON.stringify({ type, data })}\n\n`); } catch {} };
    const keepalive = setInterval(() => { try { res.write(': ping\n\n'); } catch {} }, 15000);

    const finish = (ok, msg) => {
        clearInterval(keepalive);
        buildInProgress = false;
        dev.status = ok ? 'ready' : 'error';
        dev.error  = ok ? null : msg;
        saveData(appData);
        send(ok ? 'done' : 'error', msg);
        res.end();
    };

    buildInProgress = true;
    dev.status = 'building'; dev.error = null; saveData(appData);

    try {
        fs.mkdirSync(CUSTOM_FW_DIR, { recursive: true });
        const cloneDir = path.join(CUSTOM_FW_DIR, dev.slug);

        // Clone (shallow) or update to the requested ref.
        let code;
        if (fs.existsSync(path.join(cloneDir, '.git'))) {
            send('log', `▶ Updating ${dev.repoUrl} (${dev.ref})\n`);
            code = await runStreamed('git', ['-C', cloneDir, 'fetch', '--depth', '1', 'origin', dev.ref], {}, send);
            if (code === 0) code = await runStreamed('git', ['-C', cloneDir, 'checkout', '-f', 'FETCH_HEAD'], {}, send);
        } else {
            try { fs.rmSync(cloneDir, { recursive: true, force: true }); } catch {}
            send('log', `▶ Cloning ${dev.repoUrl} (${dev.ref})\n`);
            code = await runStreamed('git', ['clone', '--depth', '1', '--branch', dev.ref, dev.repoUrl, cloneDir], {}, send);
        }
        if (code !== 0) return finish(false, 'git clone/update failed — check the URL, branch and that the repo is public');

        // Find the PlatformIO project dir (root or a subdir containing platformio.ini).
        let projDir = cloneDir;
        if (!fs.existsSync(path.join(projDir, 'platformio.ini'))) {
            const sub = fs.readdirSync(cloneDir, { withFileTypes: true })
                .filter(e => e.isDirectory())
                .map(e => path.join(cloneDir, e.name))
                .find(d => fs.existsSync(path.join(d, 'platformio.ini')));
            if (sub) projDir = sub;
            else return finish(false, 'No platformio.ini found in the repo');
        }

        const pioBin = findPio();
        const args = ['run']; if (dev.env) args.push('-e', dev.env);
        code = await runStreamed(pioBin, args, {
            cwd: projDir,
            env: { ...process.env, CI: '1', PLATFORMIO_DISABLE_AUTO_CHECK_UPDATES: '1' },
        }, send);
        if (code !== 0) return finish(false, 'PlatformIO build failed');

        // Locate the build output (the env's folder, or the only one with a firmware.bin).
        const buildRoot = path.join(projDir, '.pio', 'build');
        let outDir = dev.env ? path.join(buildRoot, dev.env) : null;
        if (!outDir || !fs.existsSync(path.join(outDir, 'firmware.bin'))) {
            outDir = (fs.existsSync(buildRoot) ? fs.readdirSync(buildRoot) : [])
                .map(n => path.join(buildRoot, n))
                .find(d => fs.existsSync(path.join(d, 'firmware.bin')));
        }
        if (!outDir) return finish(false, 'Build produced no firmware.bin');

        const destDir = path.join(FIRMWARE_DIR, dev.slug);
        writeFirmwareOutput(outDir, destDir, `/firmware/${dev.slug}`, dev.name, send);

        dev.version = currentFirmwareInfo(dev.modelId)?.version || null;
        dev.builtAt = new Date().toISOString();
        finish(true, 'Build succeeded — firmware is ready to flash & OTA');
    } catch (e) {
        finish(false, `Build error: ${e.message}`);
    }
});

// Device types for the setup wizard dropdown: the built-in boards plus any
// admin-added custom devices (with whether their firmware has been built yet).
app.get('/api/device-types', (req, res) => {
    const ready = manifestUrl => fs.existsSync(path.join(FIRMWARE_DIR, manifestUrl.replace(/^\/firmware\//, '')));
    const types = [
        { value: 'waveshare-s3-photopainter', name: 'Waveshare ESP32-S3-PhotoPainter (7.3" E6 6-color, 800×480)', manifest: '/firmware/manifest.json',                  custom: false, buildable: true },
        { value: 'reterminal-e1001',          name: 'Seeed reTerminal E1001 (7.5" monochrome, 800×480)',          manifest: '/firmware/reterminal-e1001/manifest.json',  custom: false, buildable: true },
    ];
    for (const d of (appData.customDevices || [])) {
        const manifest = `/firmware/${d.slug}/manifest.json`;
        types.push({ value: 'custom:' + d.id, name: `${d.name} (custom)`, manifest, custom: true, buildable: false, ready: ready(manifest), status: d.status });
    }
    types.forEach(t => { if (t.ready === undefined) t.ready = ready(t.manifest); });
    res.json(types);
});

// ── Firmware source: pull the built-in firmware from GitHub and rebuild ───────
// Lets a deployed server stay current without a local build. Reuses the same
// clone/build pipeline as custom devices, but for THIS project's built-in boards.
// Default firmware source for every setup — the canonical PhotoDock repo on main.
// (Still editable per install in Settings → Firmware source.)
const DEFAULT_FIRMWARE_REPO = 'https://github.com/Mischa323/PhotoDock';
const DEFAULT_FIRMWARE_REF  = 'main';
function firmwareSource() {
    if (!appData.firmwareSource) appData.firmwareSource = { repoUrl: DEFAULT_FIRMWARE_REPO, ref: DEFAULT_FIRMWARE_REF, lastBuiltAt: null };
    return appData.firmwareSource;
}
function detectOriginUrl() {
    try { return require('child_process').execSync('git remote get-url origin', { cwd: ROOT_DIR, timeout: 4000 }).toString().trim(); }
    catch { return ''; }
}
const FW_PARTS = ['firmware.bin', 'bootloader.bin', 'partitions.bin', 'boot_app0.bin'];
function binHash(file) {
    try { return crypto.createHash('md5').update(fs.readFileSync(file)).digest('hex').slice(0, 16); }
    catch { return null; }
}
function writeFirmwareManifest(dir, urlPrefix, name) {
    fs.writeFileSync(path.join(dir, 'manifest.json'), JSON.stringify({
        name: `${name} Firmware`, version: '1.0.0',
        builds: [{ chipFamily: 'ESP32-S3', parts: [
            { path: `${urlPrefix}/bootloader.bin`, offset: 0 },
            { path: `${urlPrefix}/partitions.bin`, offset: 32768 },
            { path: `${urlPrefix}/boot_app0.bin`,  offset: 57344 },
            { path: `${urlPrefix}/firmware.bin`,   offset: 65536 },
        ]}],
    }, null, 2));
}
// Keep the currently-served binary set (under dir/archive/<hash>/) so it can be
// reverted to later. Filesystem-based so local builds (copy_firmware.py) and the
// server builds stay consistent; the versions endpoint reads the same folder.
function archiveFirmware(dir, send) {
    const bin = path.join(dir, 'firmware.bin');
    if (!fs.existsSync(bin)) return;
    const hash = binHash(bin);
    if (!hash) return;
    const archRoot = path.join(dir, 'archive');
    const archDir  = path.join(archRoot, hash);
    if (!fs.existsSync(path.join(archDir, 'firmware.bin'))) {
        fs.mkdirSync(archDir, { recursive: true });
        for (const f of FW_PARTS) { const s = path.join(dir, f); if (fs.existsSync(s)) fs.copyFileSync(s, path.join(archDir, f)); }
        if (send) send('log', `↳ archived previous build ${hash}\n`);
    }
    // Keep the 10 most recent archived versions.
    try {
        const items = fs.readdirSync(archRoot)
            .map(n => ({ n, t: fs.statSync(path.join(archRoot, n)).mtimeMs }))
            .sort((a, b) => b.t - a.t);
        for (const it of items.slice(10)) fs.rmSync(path.join(archRoot, it.n), { recursive: true, force: true });
    } catch {}
}
// Copy a finished PlatformIO build's binaries into `dir` and write the manifest,
// archiving whatever was there before so it can be reverted to.
function writeFirmwareOutput(buildDir, dir, urlPrefix, name, send) {
    fs.mkdirSync(dir, { recursive: true });
    archiveFirmware(dir, send);
    for (const f of ['bootloader.bin', 'partitions.bin', 'firmware.bin']) {
        const src = path.join(buildDir, f);
        if (fs.existsSync(src)) fs.copyFileSync(src, path.join(dir, f));
    }
    const boot0 = findBoot0();
    if (boot0) fs.copyFileSync(boot0, path.join(dir, 'boot_app0.bin'));
    else if (send) send('log', '⚠ boot_app0.bin not found — flash may need a full erase\n');
    writeFirmwareManifest(dir, urlPrefix, name);
}

app.get('/api/admin/firmware/source', requireAdmin, (_req, res) => {
    const s = firmwareSource();
    res.json({
        repoUrl: s.repoUrl || '',
        ref: s.ref || 'main',
        lastBuiltAt: s.lastBuiltAt || null,
        suggestedRepoUrl: s.repoUrl ? '' : detectOriginUrl(),
        versions: {
            'PhotoPainter-E6':  currentFirmwareInfo('PhotoPainter-E6')?.version || null,
            'reTerminal-E1001': currentFirmwareInfo('reTerminal-E1001')?.version || null,
        },
    });
});

app.put('/api/admin/firmware/source', requireAdmin, express.json(), (req, res) => {
    const { repoUrl, ref } = req.body || {};
    if (repoUrl !== undefined) {
        if (repoUrl && !RE_GIT_URL.test(repoUrl.trim())) return res.status(400).json({ error: 'repoUrl must be a plain https git URL (no spaces or special characters)' });
        firmwareSource().repoUrl = (repoUrl || '').trim();
    }
    if (ref !== undefined) {
        if (ref && !RE_GIT_REF.test(ref.trim())) return res.status(400).json({ error: 'Invalid branch/tag name' });
        firmwareSource().ref = (ref || 'main').trim();
    }
    saveData(appData);
    res.json(firmwareSource());
});

app.post('/api/admin/firmware/pull-rebuild', requireAdmin, async (_req, res) => {
    if (buildInProgress) return res.status(409).json({ error: 'A build is already in progress' });
    const s = firmwareSource();
    const repoUrl = s.repoUrl || DEFAULT_FIRMWARE_REPO || detectOriginUrl();
    const ref     = s.ref || DEFAULT_FIRMWARE_REF;
    if (!repoUrl) return res.status(400).json({ error: 'Set a firmware source repo URL first' });

    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.socket?.setTimeout(0);
    res.flushHeaders();
    const send = (type, data) => { try { res.write(`data: ${JSON.stringify({ type, data })}\n\n`); } catch {} };
    const keepalive = setInterval(() => { try { res.write(': ping\n\n'); } catch {} }, 15000);
    const finish = (ok, msg) => { clearInterval(keepalive); buildInProgress = false; if (ok) { s.lastBuiltAt = new Date().toISOString(); saveData(appData); } send(ok ? 'done' : 'error', msg); res.end(); };

    buildInProgress = true;
    try {
        fs.mkdirSync(CUSTOM_FW_DIR, { recursive: true });
        const cloneDir = path.join(CUSTOM_FW_DIR, '_builtin');
        let code;
        if (fs.existsSync(path.join(cloneDir, '.git'))) {
            send('log', `▶ Updating ${repoUrl} (${ref})\n`);
            code = await runStreamed('git', ['-C', cloneDir, 'fetch', '--depth', '1', 'origin', ref], {}, send);
            if (code === 0) code = await runStreamed('git', ['-C', cloneDir, 'checkout', '-f', 'FETCH_HEAD'], {}, send);
        } else {
            try { fs.rmSync(cloneDir, { recursive: true, force: true }); } catch {}
            send('log', `▶ Cloning ${repoUrl} (${ref})\n`);
            code = await runStreamed('git', ['clone', '--depth', '1', '--branch', ref, repoUrl, cloneDir], {}, send);
        }
        if (code !== 0) return finish(false, 'git clone/update failed — check the repo URL and branch');

        const espDir = path.join(cloneDir, 'esp32');
        if (!fs.existsSync(path.join(espDir, 'platformio.ini'))) return finish(false, 'esp32/platformio.ini not found in the repo');

        // Write a generic config.h (no baked Wi-Fi/key) — OTA devices keep their
        // own saved config; a fresh flash uses the captive-portal setup.
        const genericConfig = [
            '#pragma once',
            '#define DEFAULT_SLEEP_S         (5 * 60)',
            '#define JPEG_BUF_SIZE           (512 * 1024)',
            '#define DEFAULT_WIFI_SSID       ""',
            '#define DEFAULT_WIFI_PASS       ""',
            '#define DEFAULT_SERVER_HOST     ""',
            '#define DEFAULT_SERVER_PORT     8080',
            '#define DEFAULT_API_KEY         ""',
        ].join('\n') + '\n';
        fs.mkdirSync(path.join(espDir, 'src'), { recursive: true });
        fs.writeFileSync(path.join(espDir, 'src', 'config.h'), genericConfig);

        send('log', '▶ Building all board targets…\n');
        code = await runStreamed(findPio(), ['run'], { cwd: espDir, env: { ...process.env, CI: '1', PLATFORMIO_DISABLE_AUTO_CHECK_UPDATES: '1' } }, send);
        if (code !== 0) return finish(false, 'PlatformIO build failed');

        // Publish each built-in board's binary into firmware_build/.
        for (const [type, bld] of Object.entries(DEVICE_BUILDS)) {
            const outDir = path.join(espDir, '.pio', 'build', bld.env);
            if (!fs.existsSync(path.join(outDir, 'firmware.bin'))) { send('log', `⚠ ${type}: no firmware.bin\n`); continue; }
            writeFirmwareOutput(outDir, bld.dir, bld.urlPrefix, 'PhotoDock', send);
            send('log', `✓ Published ${type}\n`);
        }
        finish(true, 'Pulled & rebuilt — devices will pull the update on their next check-in (or click Update now)');
    } catch (e) {
        finish(false, `Rebuild error: ${e.message}`);
    }
});

// ── Firmware versions & revert ───────────────────────────────────────────────
// Is this a model we actually serve firmware for (built-in or custom)?
function knownModel(model) {
    return !!MODEL_FW_DIR[model] || (appData.customDevices || []).some(d => d.modelId === model);
}
app.get('/api/admin/firmware/versions', requireAdmin, (req, res) => {
    const model = req.query.model;
    if (!knownModel(model)) return res.status(400).json({ error: 'unknown model' });
    const dir = modelFw(model).dir;
    const cur = currentFirmwareInfo(model)?.version || null;
    const models = readFirmwareChangelog();
    const byHash = {};
    for (const r of (models[model]?.releases || [])) if (r.buildHash) byHash[r.buildHash] = { title: r.title, date: r.date };
    const decorate = h => ({ hash: h, ...(byHash[h] || {}) });
    // The archived versions are the folders under <dir>/archive/<hash>/ — a single
    // filesystem source of truth shared by server builds and local builds.
    let versions = [];
    try {
        const archRoot = path.join(dir, 'archive');
        versions = fs.readdirSync(archRoot)
            .filter(h => h !== cur && fs.existsSync(path.join(archRoot, h, 'firmware.bin')))
            .map(h => ({ ...decorate(h), archivedAt: fs.statSync(path.join(archRoot, h)).mtime.toISOString() }))
            .sort((a, b) => new Date(b.archivedAt) - new Date(a.archivedAt));
    } catch {}
    res.json({
        model,
        current: cur ? { ...decorate(cur), isCurrent: true } : null,
        versions,
    });
});

app.post('/api/admin/firmware/revert', requireAdmin, express.json(), (req, res) => {
    const { model, hash } = req.body || {};
    if (!knownModel(model)) return res.status(400).json({ error: 'unknown model' });
    const safeHash = String(hash || '').replace(/[^a-f0-9]/g, '');
    const fw = modelFw(model);
    const archDir = path.join(fw.dir, 'archive', safeHash);
    if (!safeHash || !fs.existsSync(path.join(archDir, 'firmware.bin')))
        return res.status(404).json({ error: 'That firmware version is not archived' });
    // Archive the current live build first so the revert is itself reversible.
    archiveFirmware(fw.dir);
    for (const f of FW_PARTS) { const s = path.join(archDir, f); if (fs.existsSync(s)) fs.copyFileSync(s, path.join(fw.dir, f)); }
    const name = (appData.customDevices || []).find(d => d.modelId === model)?.name || 'PhotoDock';
    writeFirmwareManifest(fw.dir, fw.urlPrefix, name);
    res.json({ ok: true, version: currentFirmwareInfo(model)?.version || null });
});


// ── Device pairing — link endpoint (requires user session) ────────────────
app.post('/api/devices/pair/:token/link', express.json(), (req, res) => {
    cleanPairings();
    const p = pendingPairings.get(req.params.token);
    if (!p || p.status !== 'pending') return res.status(400).json({ error: 'Invalid or expired token' });
    const { screenId } = req.body || {};
    if (!screenId || !(appData.screens || []).find(s => s.id === screenId))
        return res.status(400).json({ error: 'Screen not found' });
    const apiKey = {
        id: crypto.randomUUID(),
        label: `${p.model} (${p.hwId || 'unknown'})`,
        key: crypto.randomBytes(32).toString('hex'),
        screenId,
        createdAt: new Date().toISOString(),
        intervalMinutes: 5,
    };
    appData.apiKeys.push(apiKey);
    saveData(appData);
    p.status = 'complete';
    p.apiKeyId = apiKey.id;
    p.screenId = screenId;
    res.json({ ok: true });
});

// ── First-run setup ────────────────────────────────────────────────────────
app.get('/setup', (_req, res) => {
    if (appData.users.length > 0) return res.redirect('/');
    res.sendFile(path.join(FRONTEND_DIR, 'setup.html'));
});

app.post('/api/setup', async (req, res) => {
    if (appData.users.length > 0) return res.status(400).json({ error: 'Already set up' });
    const { username, password, email } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
    if (!email || !email.includes('@')) return res.status(400).json({ error: 'A valid email address is required' });
    const user = { id: crypto.randomUUID(), username, password: await hashPassword(password), email: email.trim().toLowerCase(), role: 'admin' };
    appData.users.push(user);
    saveData(appData);
    const { token, expiresAt } = createToken(user.id);
    setCookie(res, token, expiresAt, req);
    res.json({ ok: true, redirect: '/admin?mfa_reminder=1' });
});

// ── Auth routes ────────────────────────────────────────────────────────────
app.get('/login', (req, res) => {
    if (req.currentUser) return res.redirect('/');
    res.sendFile(path.join(FRONTEND_DIR, 'login.html'));
});

app.post('/login', async (req, res) => {
    const ip = req.ip;
    if (!checkRateLimit(ip)) return res.redirect('/login?error=locked');
    const { username, password } = req.body;
    const user = appData.users.find(u => u.username === username);
    // Check if account is blocked before verifying password
    if (user?.blocked) {
        addLog('login_fail', { user: username, ip, detail: 'account blocked' });
        return res.redirect('/login?error=blocked');
    }
    if (user && (await verifyPassword(password, user.password))) {
        resetRateLimit(ip);
        user.failedLoginAttempts = 0;
        if (user.twoFactorEnabled) {
            if (user.twoFactorMethod === 'email') {
                if (!user.email) return res.redirect('/login?error=1');
                // Check email is configured before generating OTP
                const emailCfg = appData.settings?.email;
                if (!emailCfg?.method) {
                    // Email not configured — fall back to TOTP if available, otherwise block login
                    if (user.twoFactorSecret) {
                        console.warn(`Email 2FA for ${user.username}: email not configured, falling back to TOTP`);
                        const pendingToken = createPending2FA(user.id);
                        return res.redirect(`/2fa?t=${pendingToken}`);
                    }
                    console.error(`Email 2FA for ${user.username}: email not configured and no TOTP fallback`);
                    return res.redirect('/login?error=email');
                }
                const otp = generateOtp();
                const pendingToken = createPending2FA(user.id, otp);
                try {
                    await sendEmail(user.email, 'Your login code — PhotoDock', otpEmailHtml(otp));
                } catch (e) {
                    console.error('Failed to send 2FA email:', e.message);
                    pending2FA.delete(pendingToken);
                    return res.redirect('/login?error=email');
                }
                return res.redirect(`/2fa?t=${pendingToken}&method=email`);
            }
            const pendingToken = createPending2FA(user.id);
            return res.redirect(`/2fa?t=${pendingToken}`);
        }
        user.lastLogin = new Date().toISOString();
        saveData(appData);
        addLog('login_success', { user: user.username, ip });
        const { token, expiresAt } = createToken(user.id);
        setCookie(res, token, expiresAt, req);
        res.redirect('/');
    } else {
        addLog('login_fail', { user: username, ip });
        if (user) {
            const settings = Object.assign({}, DEFAULT_SETTINGS, appData.settings || {});
            const maxAttempts = settings.maxLoginAttempts;
            user.failedLoginAttempts = (user.failedLoginAttempts || 0) + 1;
            if (maxAttempts > 0 && user.failedLoginAttempts >= maxAttempts) {
                user.blocked = true;
                addLog('account_locked', { user: username, ip, detail: `${user.failedLoginAttempts} failed attempts` });
            }
            saveData(appData);
        }
        res.redirect('/login?error=1');
    }
});

app.post('/logout', (req, res) => {
    const cookies = parseCookies(req);
    if (cookies[COOKIE_NAME]) deleteToken(cookies[COOKIE_NAME]);
    clearCookie(res, req);
    res.redirect('/login');
});

app.get('/screens', requireAuth, (_req, res) => res.sendFile(path.join(FRONTEND_DIR, 'screens.html')));
app.get('/admin',   requireAuth, (_req, res) => res.sendFile(path.join(FRONTEND_DIR, 'admin.html')));

// ── 2FA — login completion (unauthenticated) ───────────────────────────────
app.get('/2fa',     (_req, res) => res.sendFile(path.join(FRONTEND_DIR, '2fa.html')));
app.get('/devices', (_req, res) => res.sendFile(path.join(FRONTEND_DIR, 'devices.html')));

app.post('/api/2fa/complete', express.json(), (req, res) => {
    if (!check2FARateLimit(req.ip)) return res.status(429).json({ error: 'Too many attempts. Try again later.' });
    const { pendingToken, code } = req.body;
    const rec = resolvePending2FA(pendingToken);
    if (!rec) return res.status(400).json({ error: 'Session expired. Please log in again.' });
    const user = appData.users.find(u => u.id === rec.userId);
    if (!user) return res.status(400).json({ error: 'Invalid session' });
    if (rec.emailOtp !== null) {
        // Email OTP verification
        if (String(code).trim() !== String(rec.emailOtp))
            return res.status(400).json({ error: 'Invalid code. Try again.' });
    } else {
        // TOTP verification
        if (!user.twoFactorSecret) return res.status(400).json({ error: 'Invalid session' });
        if (!verifyTotp(user.twoFactorSecret, String(code).trim()))
            return res.status(400).json({ error: 'Invalid code. Try again.' });
    }
    reset2FARateLimit(req.ip);
    pending2FA.delete(pendingToken);
    user.lastLogin = new Date().toISOString();
    addLog('login_success', { user: user.username, ip: req.ip, detail: '2FA' });
    const { token, expiresAt } = createToken(user.id);
    setCookie(res, token, expiresAt, req);
    res.json({ ok: true });
});

// ── 2FA — setup & manage (authenticated) ──────────────────────────────────
app.get('/api/2fa/status', (req, res) => {
    if (!req.currentUser) return res.status(401).json({ error: 'Not authenticated' });
    const u = appData.users.find(u => u.id === req.currentUser.id);
    res.json({ enabled: !!u.twoFactorEnabled, method: u.twoFactorMethod || 'totp', email: maskEmail(u.email) });
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
    const { code, method } = req.body;
    const u = appData.users.find(u => u.id === req.currentUser.id);
    if (method === 'email') {
        if (!u.email) return res.status(400).json({ error: 'No email address on your account. Add one first.' });
        const rec = emailVerifyOtps.get(u.id);
        if (!rec || Date.now() > rec.expiresAt || rec.purpose !== 'enable')
            return res.status(400).json({ error: 'Code expired. Request a new one.' });
        if (String(code).trim() !== String(rec.otp))
            return res.status(400).json({ error: 'Invalid code' });
        emailVerifyOtps.delete(u.id);
        u.twoFactorEnabled = true;
        u.twoFactorMethod  = 'email';
        delete u.twoFactorSecret;
        saveData(appData);
        return res.json({ ok: true });
    }
    // TOTP
    const setup = pending2FASetup.get(req.currentUser.id);
    if (!setup || Date.now() > setup.expiresAt) return res.status(400).json({ error: 'Setup expired. Start again.' });
    if (!verifyTotp(setup.secret, String(code).trim())) return res.status(400).json({ error: 'Invalid code' });
    u.twoFactorSecret  = setup.secret;
    u.twoFactorEnabled = true;
    u.twoFactorMethod  = 'totp';
    pending2FASetup.delete(req.currentUser.id);
    saveData(appData);
    res.json({ ok: true });
});

app.post('/api/2fa/disable', (req, res) => {
    if (!req.currentUser) return res.status(401).json({ error: 'Not authenticated' });
    const u = appData.users.find(u => u.id === req.currentUser.id);
    if (!u.twoFactorEnabled) return res.status(400).json({ error: '2FA is not enabled' });
    const { code } = req.body;
    if (u.twoFactorMethod === 'email') {
        const rec = emailVerifyOtps.get(u.id);
        if (!rec || Date.now() > rec.expiresAt || rec.purpose !== 'disable')
            return res.status(400).json({ error: 'Code expired. Request a new one.' });
        if (String(code).trim() !== String(rec.otp))
            return res.status(400).json({ error: 'Invalid code' });
        emailVerifyOtps.delete(u.id);
    } else {
        if (!verifyTotp(u.twoFactorSecret, String(code).trim()))
            return res.status(400).json({ error: 'Invalid code' });
    }
    delete u.twoFactorSecret;
    delete u.twoFactorMethod;
    u.twoFactorEnabled = false;
    saveData(appData);
    res.json({ ok: true });
});

// Send email OTP for 2FA enable/disable (authenticated)
app.post('/api/2fa/email/send-code', async (req, res) => {
    if (!req.currentUser) return res.status(401).json({ error: 'Not authenticated' });
    const { purpose } = req.body; // 'enable' or 'disable'
    const u = appData.users.find(u => u.id === req.currentUser.id);
    if (!u?.email) return res.status(400).json({ error: 'No email address on your account. Add one in My Security first.' });
    const otp = generateOtp();
    emailVerifyOtps.set(u.id, { otp, expiresAt: Date.now() + 5 * 60 * 1000, purpose });
    try {
        await sendEmail(u.email, 'Your verification code — PhotoDock', otpEmailHtml(otp));
        res.json({ ok: true, email: maskEmail(u.email) });
    } catch (e) {
        emailVerifyOtps.delete(u.id);
        res.status(502).json({ error: 'Could not send email. Check the email configuration.' });
    }
});

// Resend login email OTP (unauthenticated — identified by pending token)
app.post('/api/2fa/email/resend', async (req, res) => {
    const { pendingToken } = req.body;
    const rec = pending2FA.get(pendingToken);
    if (!rec || Date.now() > rec.expiresAt) return res.status(400).json({ error: 'Session expired. Please log in again.' });
    if (rec.emailOtp === null) return res.status(400).json({ error: 'This session uses an authenticator app.' });
    const user = appData.users.find(u => u.id === rec.userId);
    if (!user?.email) return res.status(400).json({ error: 'No email address on account.' });
    const newOtp = generateOtp();
    rec.emailOtp  = newOtp;
    rec.expiresAt = Date.now() + 5 * 60 * 1000;
    try {
        await sendEmail(user.email, 'Your login code — PhotoDock', otpEmailHtml(newOtp));
        res.json({ ok: true, email: maskEmail(user.email) });
    } catch (e) {
        res.status(502).json({ error: 'Could not send email. Check the email configuration.' });
    }
});

// Current user email address
app.get('/api/user/email', (req, res) => {
    if (!req.currentUser) return res.status(401).json({ error: 'Not authenticated' });
    const u = appData.users.find(u => u.id === req.currentUser.id);
    res.json({ email: u.email || '' });
});

app.put('/api/user/email', (req, res) => {
    if (!req.currentUser) return res.status(401).json({ error: 'Not authenticated' });
    const { email } = req.body;
    if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
        return res.status(400).json({ error: 'Invalid email address' });
    const u = appData.users.find(u => u.id === req.currentUser.id);
    u.email = email ? email.trim().toLowerCase() : '';
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
    res.json(appData.users.map(u => ({ id: u.id, username: u.username, role: u.role, email: u.email || null, twoFactorEnabled: !!u.twoFactorEnabled, blocked: !!u.blocked, failedLoginAttempts: u.failedLoginAttempts || 0, lastLogin: u.lastLogin || null })));
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
    const { username, password, role, blocked } = req.body;
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
    if (typeof blocked === 'boolean') {
        if (blocked && user.id === req.currentUser?.id)
            return res.status(400).json({ error: 'Cannot block your own account' });
        user.blocked = blocked;
        if (!blocked) user.failedLoginAttempts = 0; // reset on unblock
        addLog(blocked ? 'user_blocked' : 'user_unblocked', { by: req.currentUser.username, target: user.username });
    }
    saveData(appData);
    res.json({ id: user.id, username: user.username, role: user.role, blocked: !!user.blocked });
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
    appData.roles[key] = { canUpload: false, canDelete: false, canManage: false, screens: [] };
    saveData(appData);
    res.json({ role: key, permissions: appData.roles[key] });
});

// Merge update: permission toggles and the screen (display) access list are
// saved independently, so only overwrite the fields actually provided.
app.put('/api/admin/roles/:role', requireAdmin, (req, res) => {
    const { role } = req.params;
    const existing = appData.roles?.[role];
    if (!existing) return res.status(404).json({ error: 'Role not found' });
    const { canUpload, canDelete, canManage, screens } = req.body;
    if (canUpload !== undefined) existing.canUpload = !!canUpload;
    if (canDelete !== undefined) existing.canDelete = !!canDelete;
    if (canManage !== undefined) existing.canManage = !!canManage;
    if (Array.isArray(screens)) {
        const valid = new Set((appData.screens || []).map(s => s.id));
        existing.screens = [...new Set(screens.filter(id => valid.has(id)))];
    }
    saveData(appData);
    res.json(existing);
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

// ── Admin API — Logs ───────────────────────────────────────────────────────
app.get('/api/admin/logs', requireAdmin, (_req, res) => res.json(appData.logs || []));

// ── Admin API — API keys ───────────────────────────────────────────────────
app.get('/api/admin/apikeys', requireAdmin, (_req, res) => res.json(appData.apiKeys));

const VALID_ENDPOINTS = ['current', 'all', 'image'];

app.post('/api/admin/apikeys', requireAdmin, (req, res) => {
    const { name, interval, imageWidth, imageHeight, allowedEndpoints, showDate, screenId } = req.body;
    if (!name) return res.status(400).json({ error: 'Name required' });
    const apiKey = { id: crypto.randomUUID(), name, key: crypto.randomBytes(24).toString('base64url'), intervalMinutes: Math.max(1, parseInt(interval) || 5), createdAt: new Date().toISOString() };
    const w = parseInt(imageWidth);  if (w > 0) apiKey.imageWidth  = Math.min(7680, w);
    const h = parseInt(imageHeight); if (h > 0) apiKey.imageHeight = Math.min(4320, h);
    if (Array.isArray(allowedEndpoints)) apiKey.allowedEndpoints = allowedEndpoints.filter(e => VALID_ENDPOINTS.includes(e));
    if (showDate === true || showDate === false) apiKey.showDate = showDate;
    if (screenId && (appData.screens || []).find(s => s.id === screenId)) apiKey.screenId = screenId;
    appData.apiKeys.push(apiKey);
    saveData(appData);
    res.json(apiKey);
});

app.put('/api/admin/apikeys/:id', requireAdmin, (req, res) => {
    const apiKey = appData.apiKeys.find(k => k.id === req.params.id);
    if (!apiKey) return res.status(404).json({ error: 'Key not found' });
    const { name, interval, imageWidth, imageHeight, allowedEndpoints, showDate, screenId } = req.body;
    if (name) apiKey.name = name;
    if (interval !== undefined) apiKey.intervalMinutes = Math.max(1, parseInt(interval) || 5);
    if ('showDate' in req.body) apiKey.showDate = showDate === true || showDate === false ? showDate : null;
    if ('screenId' in req.body) apiKey.screenId = screenId && (appData.screens || []).find(s => s.id === screenId) ? screenId : null;
    // imageWidth/imageHeight: positive number = override, 0/null/'' = use global default
    if (imageWidth !== undefined) {
        const w = parseInt(imageWidth);
        if (w > 0) apiKey.imageWidth = Math.min(7680, w); else delete apiKey.imageWidth;
    }
    if (imageHeight !== undefined) {
        const h = parseInt(imageHeight);
        if (h > 0) apiKey.imageHeight = Math.min(4320, h); else delete apiKey.imageHeight;
    }
    if (Array.isArray(allowedEndpoints)) apiKey.allowedEndpoints = allowedEndpoints.filter(e => VALID_ENDPOINTS.includes(e));
    saveData(appData);
    res.json(apiKey);
});

app.delete('/api/admin/apikeys/:id', requireAdmin, (req, res) => {
    appData.apiKeys = appData.apiKeys.filter(k => k.id !== req.params.id);
    // Also remove device status entries and albums linked to this key
    if (appData.deviceStatus) {
        for (const [devId, d] of Object.entries(appData.deviceStatus)) {
            if (d.apiKeyId === req.params.id) delete appData.deviceStatus[devId];
        }
    }
    appData.albums = (appData.albums || []).filter(a => a.deviceId !== req.params.id);
    saveData(appData);
    res.json({ ok: true });
});

// ── Albums ────────────────────────────────────────────────────────────────
app.get('/api/admin/albums', requireAdmin, (_req, res) => res.json(appData.albums || []));

app.post('/api/admin/albums', requireAdmin, (req, res) => {
    const { name, deviceId } = req.body;
    if (!name)     return res.status(400).json({ error: 'Name required' });
    if (!deviceId) return res.status(400).json({ error: 'deviceId required' });
    if (!appData.apiKeys.find(k => k.id === deviceId))
        return res.status(404).json({ error: 'Device not found' });
    const album = { id: crypto.randomUUID(), name, deviceId, images: [], favorited: false, createdAt: new Date().toISOString() };
    appData.albums.push(album);
    saveData(appData);
    res.json(album);
});

app.put('/api/admin/albums/:id', requireAdmin, (req, res) => {
    const album = appData.albums.find(a => a.id === req.params.id);
    if (!album) return res.status(404).json({ error: 'Album not found' });
    if ('name'      in req.body) album.name      = String(req.body.name);
    if ('favorited' in req.body) album.favorited = !!req.body.favorited;
    if ('images'    in req.body && Array.isArray(req.body.images))
        album.images = req.body.images.map(f => path.basename(f))
            .filter(f => fs.existsSync(path.join(UPLOADS_DIR, f)));
    saveData(appData);
    res.json(album);
});

app.delete('/api/admin/albums/:id', requireAdmin, (req, res) => {
    const idx = appData.albums.findIndex(a => a.id === req.params.id);
    if (idx === -1) return res.status(404).json({ error: 'Album not found' });
    appData.albums.splice(idx, 1);
    saveData(appData);
    res.json({ ok: true });
});

// ── Email config ──────────────────────────────────────────────────────────
app.get('/api/admin/email', requireAdmin, (_req, res) => {
    const cfg = JSON.parse(JSON.stringify(appData.settings?.email || {}));
    if (cfg.smtp?.password)      cfg.smtp.password      = '';
    if (cfg.graph?.clientSecret) cfg.graph.clientSecret = '';
    res.json(cfg);
});

app.put('/api/admin/email', requireAdmin, (req, res) => {
    const { method, smtp, graph } = req.body;
    if (!appData.settings) appData.settings = {};
    const existing = appData.settings.email || {};
    const newCfg = { method: method || '' };
    if (smtp) {
        newCfg.smtp = {
            host:     smtp.host || '',
            port:     parseInt(smtp.port) || 587,
            secure:   !!smtp.secure,
            user:     smtp.user || '',
            password: smtp.password ? smtp.password : (existing.smtp?.password || ''),
            from:     smtp.from || ''
        };
    } else {
        newCfg.smtp = existing.smtp || {};
    }
    if (graph) {
        newCfg.graph = {
            tenantId:     graph.tenantId || '',
            clientId:     graph.clientId || '',
            clientSecret: graph.clientSecret ? graph.clientSecret : (existing.graph?.clientSecret || ''),
            from:         graph.from || ''
        };
    } else {
        newCfg.graph = existing.graph || {};
    }
    appData.settings.email = newCfg;
    saveData(appData);
    res.json({ ok: true });
});

app.post('/api/admin/email/test', requireAdmin, async (req, res) => {
    const { to } = req.body;
    if (!to) return res.status(400).json({ error: 'Recipient address required' });
    try {
        await sendEmail(to, 'Test email — PhotoDock',
            `<div style="font-family:sans-serif;padding:32px 24px;max-width:420px">
                <h2 style="color:#0e7490">PhotoDock</h2>
                <p>This is a test email. Your email configuration is working correctly.</p>
            </div>`);
        res.json({ ok: true });
    } catch (e) {
        res.status(502).json({ error: 'Could not send test email. Check the email configuration.' });
    }
});

// ── Display settings ───────────────────────────────────────────────────────
const DEFAULT_SETTINGS = { timezone: 'Europe/Amsterdam', showDayName: true, showDate: true, showTime: true, showSeconds: false, accentColor: '#06b6d4', slideshowInterval: 30, imageWidth: 1920, imageHeight: 1080, datePosition: 'top-right', userInactivityDays: 0, apiKeyInactivityDays: 0, logRetentionDays: 30, maxLoginAttempts: 5, imageBrightness: 1.15, imageSaturation: 1.2 };

app.get('/api/settings', (_req, res) => res.json(Object.assign({}, DEFAULT_SETTINGS, appData.settings || {})));

app.put('/api/settings', requireAdmin, (req, res) => {
    const { timezone, showDayName, showDate, showTime, showSeconds, accentColor, slideshowInterval, imageWidth, imageHeight, datePosition, userInactivityDays, apiKeyInactivityDays, logRetentionDays, maxLoginAttempts, imageBrightness, imageSaturation } = req.body;
    try { Intl.DateTimeFormat(undefined, { timeZone: timezone }); } catch { return res.status(400).json({ error: 'Invalid timezone' }); }
    if (accentColor && !/^#[0-9a-fA-F]{6}$/.test(accentColor)) return res.status(400).json({ error: 'Invalid colour' });
    const interval    = Math.max(1, parseInt(slideshowInterval) || DEFAULT_SETTINGS.slideshowInterval);
    const w           = Math.min(7680, Math.max(1, parseInt(imageWidth)  || DEFAULT_SETTINGS.imageWidth));
    const h           = Math.min(4320, Math.max(1, parseInt(imageHeight) || DEFAULT_SETTINGS.imageHeight));
    const validPos    = ['top-right', 'top-left', 'bottom-right', 'bottom-left'];
    const pos         = validPos.includes(datePosition) ? datePosition : DEFAULT_SETTINGS.datePosition;
    const userDays    = Math.max(0, parseInt(userInactivityDays)   || 0);
    const keyDays     = Math.max(0, parseInt(apiKeyInactivityDays) || 0);
    const retentionDays   = Math.max(1, parseInt(logRetentionDays) || DEFAULT_SETTINGS.logRetentionDays);
    const maxAttempts = Math.max(0, parseInt(maxLoginAttempts) ?? DEFAULT_SETTINGS.maxLoginAttempts);
    const brightness  = Math.min(2, Math.max(0.5, parseFloat(imageBrightness) || DEFAULT_SETTINGS.imageBrightness));
    const saturation  = Math.min(2, Math.max(0.5, parseFloat(imageSaturation) || DEFAULT_SETTINGS.imageSaturation));
    appData.settings = { timezone, showDayName: !!showDayName, showDate: !!showDate, showTime: !!showTime, showSeconds: !!showSeconds, accentColor: accentColor || DEFAULT_SETTINGS.accentColor, slideshowInterval: interval, imageWidth: w, imageHeight: h, datePosition: pos, userInactivityDays: userDays, apiKeyInactivityDays: keyDays, logRetentionDays: retentionDays, maxLoginAttempts: maxAttempts, imageBrightness: brightness, imageSaturation: saturation };
    saveData(appData);
    res.json(appData.settings);
});

// ── Slideshow API (external) ───────────────────────────────────────────────
function getScreenFiles(keyRecord) {
    const deviceId     = keyRecord?.id;
    const deviceAlbums = (appData.albums || []).filter(a => a.deviceId === deviceId);

    if (deviceAlbums.length > 0) {
        // Build weighted playlist: favorited albums appear 3× more often
        const playlist = [];
        for (const album of deviceAlbums) {
            const imgs = (album.images || []).filter(f => fs.existsSync(path.join(UPLOADS_DIR, f)));
            if (imgs.length === 0) continue;
            const weight = album.favorited ? 3 : 1;
            for (let i = 0; i < weight; i++) playlist.push(...imgs);
        }
        if (playlist.length > 0) return playlist;
    }

    // Fallback: old screenId-based filter, or all images
    const screenId = keyRecord?.screenId || null;
    const meta     = appData.imageMetadata || {};
    const all      = fs.readdirSync(UPLOADS_DIR).filter(f => IMAGE_EXTS.test(f)).sort();
    if (!screenId) return all;
    return all.filter(f => (meta[f]?.screenId || null) === screenId);
}


// Current local minutes-of-day in a timezone (0-1439).
function nowMinutesInTz(tz) {
    try {
        const parts = new Intl.DateTimeFormat('en-GB', { timeZone: tz, hour: '2-digit', minute: '2-digit', hour12: false }).formatToParts(new Date());
        return (+parts.find(p => p.type === 'hour').value) * 60 + (+parts.find(p => p.type === 'minute').value);
    } catch { const d = new Date(); return d.getHours() * 60 + d.getMinutes(); }
}
// Is this screen inside its scheduled sleep window right now? If so, how long
// (ms) until it should wake. Handles overnight windows (e.g. 23:00 → 07:00).
function screenSleepInfo(keyRecord, tz) {
    if (!keyRecord || !keyRecord.sleepEnabled) return { sleeping: false };
    const toMin = s => { const m = /^(\d{1,2}):(\d{2})$/.exec(String(s || '')); return m ? (+m[1]) * 60 + (+m[2]) : null; };
    const start = toMin(keyRecord.sleepStart), end = toMin(keyRecord.sleepEnd);
    if (start == null || end == null || start === end) return { sleeping: false };
    const now = nowMinutesInTz(tz);
    const sleeping = start < end ? (now >= start && now < end) : (now >= start || now < end);
    if (!sleeping) return { sleeping: false };
    let untilEnd = ((end - now) + 1440) % 1440;
    if (untilEnd === 0) untilEnd = 1440;
    return { sleeping: true, msUntilWake: untilEnd * 60 * 1000 };
}

app.get('/api/slideshow/current', requireApiKey, requireEndpoint('current'), (req, res) => {
    const keyRecord  = appData.apiKeys.find(k => k.key === (req.headers['x-api-key'] || req.query.key));
    // Scheduled sleep takes precedence over the slideshow: tell the device to
    // show the "Sleeping" screen and sleep until its configured wake time.
    const tz = appData.settings?.timezone || DEFAULT_SETTINGS.timezone;
    const sw = screenSleepInfo(keyRecord, tz);
    if (sw.sleeping) {
        return res.json({ sleeping: true, next_in_ms: sw.msUntilWake,
                          next_at: new Date(Date.now() + sw.msUntilWake).toISOString() });
    }
    const intervalMs = (keyRecord?.intervalMinutes || 5) * 60 * 1000;
    const files      = getScreenFiles(keyRecord);
    if (files.length === 0) return res.status(404).json({ error: 'No images available' });
    // KEY1 short-press advances the photo via a per-device offset.
    const offset   = parseInt(req.query.offset, 10) || 0;
    const slot     = Math.floor(Date.now() / intervalMs);
    const index    = (((slot + offset) % files.length) + files.length) % files.length;
    const filename = files[index];
    const nextSlot = (slot + 1) * intervalMs;
    const baseUrl  = `${req.protocol}://${req.get('host')}`;
    const screen   = keyRecord?.screenId ? (appData.screens || []).find(s => s.id === keyRecord.screenId) : null;
    const debug    = !!(keyRecord?.debugLogging || screen?.debugLogging);
    res.json({ index, total: files.length, filename, url: `${baseUrl}/uploads/${filename}`, interval_minutes: keyRecord?.intervalMinutes || 5, next_at: new Date(nextSlot).toISOString(), next_in_ms: nextSlot - Date.now(), debug });
});

app.get('/api/slideshow/all', requireApiKey, requireEndpoint('all'), (req, res) => {
    const keyRecord = appData.apiKeys.find(k => k.key === (req.headers['x-api-key'] || req.query.key));
    const files     = getScreenFiles(keyRecord);
    const baseUrl   = `${req.protocol}://${req.get('host')}`;
    res.json(files.map((filename, i) => ({ index: i, filename, url: `${baseUrl}/uploads/${filename}` })));
});

// ── On-device status screens (rendered to an 800×480 image for the panel) ──
// Flat, high-contrast colours so they stay crisp after the panel's 6-colour
// dithering. Matches the design handoff's status-screen set.
const SCREEN_STATES = {
    empty:    { accent: '#3b82f6', title: 'No photos yet',        sub: 'Add photos to this screen in PhotoDock', icon: 'frame' },
    paired:   { accent: '#34d399', title: "You're all set",       sub: 'Device paired successfully',                 icon: 'check' },
    low_batt: { accent: '#f59e0b', title: 'Battery low',          sub: 'Please connect the charger',                 icon: 'batt'  },
    sleeping: { accent: '#3b82f6', title: 'Sleeping',             sub: 'Waiting for the next refresh',               icon: 'moon'  },
    updating: { accent: '#22d3ee', title: 'Updating firmware',    sub: 'Please do not unplug the device',            icon: 'spin'  },
    updated:  { accent: '#34d399', title: 'Update complete',      sub: 'Now running the latest firmware',            icon: 'check' },
    server:   { accent: '#f87171', title: "Can't reach the server", sub: 'Will retry shortly',                       icon: 'warn'  },
};

function statusIconSvg(icon, cx, cy, accent) {
    const r = 52;
    const ring = `<circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="${accent}" stroke-width="5"/>`;
    switch (icon) {
        case 'check':
            return ring + `<path d="M${cx-24} ${cy} l16 17 l32 -34" fill="none" stroke="${accent}" stroke-width="8" stroke-linecap="round" stroke-linejoin="round"/>`;
        case 'warn':
            return ring + `<rect x="${cx-4}" y="${cy-26}" width="8" height="32" rx="4" fill="${accent}"/><circle cx="${cx}" cy="${cy+20}" r="6" fill="${accent}"/>`;
        case 'batt':
            return `<rect x="${cx-44}" y="${cy-26}" width="80" height="52" rx="8" fill="none" stroke="${accent}" stroke-width="5"/><rect x="${cx+38}" y="${cy-10}" width="8" height="20" rx="3" fill="${accent}"/><rect x="${cx-36}" y="${cy-18}" width="20" height="36" rx="3" fill="${accent}"/>`;
        case 'moon':
            return `<circle cx="${cx}" cy="${cy}" r="${r}" fill="${accent}"/><circle cx="${cx+22}" cy="${cy-14}" r="46" fill="#0b1020"/>`;
        case 'spin': {
            let s = '';
            for (let i = 0; i < 12; i++) {
                const a = (i / 12) * Math.PI * 2;
                const op = (0.15 + 0.85 * (i / 12)).toFixed(2);
                const x1 = cx + Math.cos(a) * 30, y1 = cy + Math.sin(a) * 30;
                const x2 = cx + Math.cos(a) * 50, y2 = cy + Math.sin(a) * 50;
                s += `<line x1="${x1.toFixed(1)}" y1="${y1.toFixed(1)}" x2="${x2.toFixed(1)}" y2="${y2.toFixed(1)}" stroke="${accent}" stroke-width="6" stroke-linecap="round" opacity="${op}"/>`;
            }
            return s;
        }
        case 'frame':
        default:
            return `<rect x="${cx-46}" y="${cy-34}" width="92" height="68" rx="10" fill="none" stroke="${accent}" stroke-width="5" stroke-dasharray="10 8"/>`;
    }
}

function buildStatusScreenSvg(stateKey, q) {
    const W = 800, H = 480;
    const esc = s => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    const cfg = SCREEN_STATES[stateKey] || SCREEN_STATES.empty;
    const accent = cfg.accent;

    // Footer values supplied by the device (best-effort)
    const devId = (q.id || 'photopainter').toString().slice(0, 24);
    const fw    = (q.fw || '').toString().slice(0, 12);
    const batt  = q.batt != null && q.batt !== '' ? Math.max(0, Math.min(100, parseInt(q.batt, 10))) : null;
    const rssi  = q.rssi != null && q.rssi !== '' ? parseInt(q.rssi, 10) : null;
    const bars  = rssi == null ? 0 : rssi >= -55 ? 4 : rssi >= -65 ? 3 : rssi >= -75 ? 2 : rssi >= -85 ? 1 : 0;

    let wifi = '';
    for (let i = 0; i < 4; i++) {
        const bh = 6 + i * 5, bx = 700 + i * 9, by = 452 - bh;
        wifi += `<rect x="${bx}" y="${by}" width="6" height="${bh}" rx="1.5" fill="${i < bars ? '#fff' : 'rgba(255,255,255,0.25)'}"/>`;
    }
    let battSvg = '';
    if (batt != null) {
        battSvg = `<rect x="744" y="440" width="34" height="18" rx="3" fill="none" stroke="rgba(255,255,255,0.6)" stroke-width="2"/>`
                + `<rect x="778" y="445" width="4" height="8" rx="1.5" fill="rgba(255,255,255,0.6)"/>`
                + `<rect x="747" y="443" width="${(batt / 100 * 28).toFixed(0)}" height="12" rx="1.5" fill="#fff"/>`;
    }

    const footer =
        `<rect x="0" y="422" width="${W}" height="58" fill="rgba(255,255,255,0.06)"/>`
      + `<rect x="0" y="422" width="${W}" height="2" fill="rgba(255,255,255,0.12)"/>`
      + `<rect x="24" y="436" width="30" height="30" rx="8" fill="${accent}"/>`
      + `<text x="64" y="456" font-family="sans-serif" font-size="16" font-weight="600" fill="#fff">PhotoDock</text>`
      + `<text x="180" y="456" font-family="ui-monospace,monospace" font-size="13" fill="rgba(255,255,255,0.55)">${esc(devId)}</text>`
      + (fw ? `<text x="650" y="456" font-family="ui-monospace,monospace" font-size="12" fill="rgba(255,255,255,0.55)" text-anchor="end">${esc(fw)}</text>` : '')
      + wifi + battSvg;

    const cx = W / 2;
    return Buffer.from(
        `<svg xmlns="http://www.w3.org/2000/svg" width="${W}" height="${H}">`
      + `<defs><radialGradient id="g" cx="50%" cy="34%" r="70%">`
      + `<stop offset="0%" stop-color="${accent}" stop-opacity="0.20"/>`
      + `<stop offset="60%" stop-color="${accent}" stop-opacity="0"/></radialGradient></defs>`
      + `<rect width="${W}" height="${H}" fill="#0b1020"/>`
      + `<rect width="${W}" height="${H}" fill="url(#g)"/>`
      + statusIconSvg(cfg.icon, cx, 150, accent)
      + `<text x="${cx}" y="280" font-family="sans-serif" font-size="42" font-weight="700" fill="#fff" text-anchor="middle">${esc(cfg.title)}</text>`
      + `<text x="${cx}" y="324" font-family="sans-serif" font-size="20" fill="rgba(255,255,255,0.7)" text-anchor="middle">${esc(cfg.sub)}</text>`
      + footer
      + `</svg>`
    );
}

// Render a designed status screen to a JPEG for the device.
app.get('/api/device/screen', requireApiKey, async (req, res) => {
    const state = req.query.state || 'empty';
    const rotation = [0, 90, 180, 270].includes(Number(req.apiKey?.rotation)) ? Number(req.apiKey.rotation) : 0;
    try {
        const svg = buildStatusScreenSvg(state, req.query);
        let pipe = sharp(svg);
        if (rotation) pipe = pipe.rotate(rotation).resize(800, 480, { fit: 'contain', background: { r: 11, g: 16, b: 32 } });
        const buf = await pipe.jpeg({ quality: 92 }).toBuffer();
        res.set('Content-Type', 'image/jpeg');
        res.set('Cache-Control', 'no-cache');
        res.send(buf);
    } catch (e) {
        console.error('Status screen render failed:', e.message);
        res.status(500).json({ error: 'Render failed' });
    }
});

function buildDateOverlaySvg(w, h, settings) {
    const now = new Date();
    const tz  = settings.timezone || 'UTC';
    const esc = s => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

    // Build the same two lines as index.html
    const dayParts = [];
    if (settings.showDayName) dayParts.push(now.toLocaleDateString('en-GB',  { timeZone: tz, weekday: 'long' }));
    if (settings.showDate)    dayParts.push(now.toLocaleDateString('en-GB',  { timeZone: tz, day: 'numeric', month: 'long', year: 'numeric' }));
    const dayLine  = dayParts.join(' ');
    const timeLine = settings.showTime
        ? now.toLocaleTimeString('en-GB', { timeZone: tz, hour: '2-digit', minute: '2-digit', ...(settings.showSeconds ? { second: '2-digit' } : {}) })
        : '';

    if (!dayLine && !timeLine) return null;

    // Scale font with image height, matching the feel of the browser overlay
    const fsDay  = Math.max(14, Math.round(h * 0.026)); // ~28px at 1080p
    const fsTime = Math.max(12, Math.round(h * 0.021)); // ~23px at 1080p
    const lh     = Math.round(fsDay * 1.55);
    const pad    = Math.round(w * 0.016);

    // Determine position from settings (default top-right)
    const pos    = settings.datePosition || 'top-right';
    const isRight  = pos.includes('right');
    const isBottom = pos.includes('bottom');
    const anchor   = isRight ? 'end' : 'start';
    const x        = isRight ? w - pad : pad;

    // For bottom positions, anchor from the bottom edge
    const lineCount = (dayLine ? 1 : 0) + (timeLine ? 1 : 0);
    const blockH    = fsDay + (lineCount > 1 ? lh : 0);
    let   y = isBottom
        ? h - Math.round(h * 0.05) - blockH + fsDay
        : Math.round(h * 0.07) + fsDay;

    // Render each text element twice: dark shadow offset + white on top
    // Use SVG-native fill-opacity (not CSS rgba()) — librsvg doesn't support rgba() in attributes
    function textPair(txt, px, py, fs, weight, fillOpacity) {
        const f = `font-family="sans-serif" font-size="${fs}" font-weight="${weight}" text-anchor="${anchor}"`;
        return `<text ${f} x="${px+1}" y="${py+1}" fill="black" fill-opacity="0.75">${esc(txt)}</text>` +
               `<text ${f} x="${px}"   y="${py}"   fill="white" fill-opacity="${fillOpacity}">${esc(txt)}</text>`;
    }

    let svg = '';
    if (dayLine)  { svg += textPair(dayLine,  x, y, fsDay,  '600', '1');    y += lh; }
    if (timeLine) { svg += textPair(timeLine, x, y, fsTime, '400', '0.75'); }

    return Buffer.from(`<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="${h}">${svg}</svg>`);
}

app.get('/api/slideshow/image', requireApiKey, requireEndpoint('image'), async (req, res) => {
    const keyRecord  = appData.apiKeys.find(k => k.key === (req.headers['x-api-key'] || req.query.key));
    const intervalMs = (keyRecord?.intervalMinutes || 5) * 60 * 1000;
    const files      = getScreenFiles(keyRecord);
    if (files.length === 0) return res.status(404).json({ error: 'No images available' });
    const offset   = parseInt(req.query.offset, 10) || 0;   // KEY1 short-press advance
    const slot     = Math.floor(Date.now() / intervalMs);
    const filename = files[(((slot + offset) % files.length) + files.length) % files.length];
    const filepath = path.join(UPLOADS_DIR, filename);
    const settings = Object.assign({}, DEFAULT_SETTINGS, appData.settings || {});
    // Per-key date overlay override (set in admin panel)
    if (keyRecord.showDate === true)  { settings.showDate = true;  settings.showDayName = true; }
    if (keyRecord.showDate === false) { settings.showDate = false; settings.showDayName = false; settings.showTime = false; }
    // The device passes its exact panel size via ?width=&height= — honour that
    // first so the photo is fitted/centered to the panel (not a default 1080p).
    const qW = parseInt(req.query.width, 10);
    const qH = parseInt(req.query.height, 10);
    const imgW = (qW > 0 ? qW : null) || keyRecord?.imageWidth  || settings.imageWidth;
    const imgH = (qH > 0 ? qH : null) || keyRecord?.imageHeight || settings.imageHeight;
    const rotation = [0, 90, 180, 270].includes(Number(keyRecord?.rotation)) ? Number(keyRecord.rotation) : 0;
    // Brighten/saturate before the device dithers to 6 colours, so e-ink photos
    // look less dull. Per-screen override wins, else global setting, else default.
    const brRaw = keyRecord?.imageBrightness ?? settings.imageBrightness ?? 1;
    const saRaw = keyRecord?.imageSaturation ?? settings.imageSaturation ?? 1;
    const brightness = Math.min(2, Math.max(0.5, Number(brRaw) || 1));
    const saturation = Math.min(2, Math.max(0.5, Number(saRaw) || 1));
    // Fit mode: 'contain' = letterbox (black bars, no cropping), 'cover' = crop
    // to fill the panel (no bars). A per-image override wins over the per-screen
    // setting, which wins over the default (contain).
    const imgMeta = (appData.imageMetadata || {})[filename] || {};
    const screenFit = keyRecord?.screenId
        ? (appData.screens || []).find(s => s.id === keyRecord.screenId)?.imageFit
        : null;
    const validFit = v => (v === 'cover' || v === 'contain') ? v : null;
    const fit = validFit(imgMeta.imageFit)       // per-image override
             || validFit(keyRecord?.imageFit)    // per-key (set on this screen)
             || validFit(screenFit)              // screen default (key paired later)
             || 'contain';
    try {
        const pipeline = sharp(filepath)
            .rotate(rotation, { background: { r: 0, g: 0, b: 0 } })   // user-chosen orientation
            .resize(imgW, imgH, { fit, position: 'centre', background: { r: 0, g: 0, b: 0 } });

        if (brightness !== 1 || saturation !== 1) pipeline.modulate({ brightness, saturation });

        const overlay = buildDateOverlaySvg(imgW, imgH, settings);
        if (overlay) pipeline.composite([{ input: overlay, top: 0, left: 0 }]);

        const buf = await pipeline.jpeg({ quality: 90 }).toBuffer();
        res.set('Content-Type', 'image/jpeg');
        res.set('Cache-Control', 'no-cache');
        res.send(buf);
    } catch (e) {
        console.error('Image processing failed:', e.message);
        res.status(500).json({ error: 'Image processing failed' });
    }
});

// ── Version ────────────────────────────────────────────────────────────────
app.get('/api/version', (_req, res) => res.json({ version: appVersion, changelog }));

// Serve built firmware files for esp-web-tools
// Firmware binaries can contain baked Wi-Fi credentials, so they must NOT be
// downloadable anonymously. Allow a logged-in user (browser flashing via
// esp-web-tools sends the session cookie) or a valid device API key (OTA passes
// ?key=). requireAuth lets /firmware through so a session-less device reaches
// this check rather than being redirected to /login.
app.use('/firmware', (req, res, next) => {
    if (req.currentUser) return next();
    const key = req.query.key || req.headers['x-api-key'];
    if (key && (appData.apiKeys || []).some(k => k.key === key)) return next();
    return res.status(401).json({ error: 'Authentication required to download firmware' });
}, express.static(FIRMWARE_DIR));

// ── Static files ───────────────────────────────────────────────────────────
app.use(express.static(FRONTEND_DIR));
// Gate the raw image bytes by per-user screen access, so a photo can't be
// fetched by guessing its /uploads/<file> URL. (Devices never hit this route —
// they fetch through the API-key-protected /api/slideshow/image.)
app.use('/uploads', (req, res, next) => {
    const filename = path.basename(decodeURIComponent(req.path));
    if (!userCanSeeImage(req.currentUser, filename)) return res.status(403).end();
    next();
}, express.static(UPLOADS_DIR));

// ── Images API ─────────────────────────────────────────────────────────────
app.get('/api/images', (req, res) => {
    const meta  = appData.imageMetadata || {};
    const { screenId } = req.query;
    const { albumId } = req.query;
    let files = fs.readdirSync(UPLOADS_DIR)
        .filter(f => IMAGE_EXTS.test(f))
        .map(filename => ({
            filename, url: `/uploads/${filename}`,
            uploadedAt: meta[filename]?.uploadedAt || fs.statSync(path.join(UPLOADS_DIR, filename)).mtime,
            uploadedBy: meta[filename]?.uploadedBy || null,
            screenId:   meta[filename]?.screenId   || null,
            albumId:    meta[filename]?.albumId    || null,
            imageFit:   meta[filename]?.imageFit   || null,   // null = follow screen default
        }));
    if (screenId !== undefined) {
        const filterVal = screenId === '' ? null : screenId;
        files = files.filter(f => f.screenId === filterVal);
    }
    if (albumId !== undefined) {
        const filterVal = albumId === '' ? null : albumId;
        files = files.filter(f => f.albumId === filterVal);
    }
    // Only return photos this user is allowed to see.
    files = files.filter(f => userCanSeeImage(req.currentUser, f.filename));
    files.sort((a, b) => new Date(b.uploadedAt) - new Date(a.uploadedAt));
    res.json(files);
});

app.post('/api/upload', requireUpload, (req, res) => {
    upload.array('images', 50)(req, res, async (err) => {
    if (err) {
        const msg = err.code === 'LIMIT_FILE_SIZE'
            ? 'File too large (max 50 MB)'
            : err.message || 'Upload failed';
        return res.status(400).json({ error: msg });
    }
    if (!req.files?.length) return res.status(400).json({ error: 'No files uploaded' });

    // Convert HEIC/HEIF to JPEG so browsers can display them
    const processed = [];
    for (const f of req.files) {
        const ext = path.extname(f.filename).toLowerCase();
        if (HEIC_EXTS.has(ext)) {
            const newName = f.filename.slice(0, -ext.length) + '.jpg';
            const newPath = path.join(UPLOADS_DIR, newName);
            try {
                const inputBuffer  = fs.readFileSync(f.path);
                const outputBuffer = await heicConvert({ buffer: inputBuffer, format: 'JPEG', quality: 0.92 });
                fs.writeFileSync(newPath, outputBuffer);
                fs.unlinkSync(f.path);
                processed.push({ filename: newName });
            } catch (e) {
                console.error('HEIC conversion failed for', f.filename, ':', e.message);
                processed.push({ filename: f.filename }); // keep original if conversion fails
            }
        } else {
            processed.push({ filename: f.filename });
        }
    }

    const uploader   = req.currentUser?.username || null;
    const uploadedAt = new Date().toISOString();
    const screenId   = req.body.screenId && (appData.screens || []).find(s => s.id === req.body.screenId) ? req.body.screenId : null;
    // Don't let a user assign an upload to a screen they can't access.
    if (screenId && !userCanAccessScreen(req.currentUser, screenId)) {
        // Clean up the just-saved files so we don't orphan them.
        for (const f of processed) { try { fs.unlinkSync(path.join(UPLOADS_DIR, f.filename)); } catch {} }
        return res.status(403).json({ error: 'You do not have access to that screen' });
    }
    const albumId    = req.body.albumId  && (appData.albums  || []).find(a => a.id === req.body.albumId)  ? req.body.albumId  : null;
    if (!appData.imageMetadata) appData.imageMetadata = {};
    for (const f of processed) {
        appData.imageMetadata[f.filename] = { uploadedBy: uploader, uploadedAt, screenId, albumId };
    }
    saveData(appData);
    addLog('upload', { user: uploader, ip: req.ip, detail: `${processed.length} file(s)` });
    res.json({ uploaded: processed.map(f => ({ filename: f.filename, url: `/uploads/${f.filename}` })) });
    }); // end upload.array callback
});

app.delete('/api/images/:filename', requireDelete, (req, res) => {
    const filename = path.basename(req.params.filename);
    const filepath = path.join(UPLOADS_DIR, filename);
    if (!fs.existsSync(filepath)) return res.status(404).json({ error: 'File not found' });
    if (!userCanSeeImage(req.currentUser, filename))
        return res.status(403).json({ error: 'Permission denied' });
    fs.unlinkSync(filepath);
    delete appData.imageMetadata?.[filename];
    // Remove from all users' favourites
    for (const u of appData.users) {
        if (u.favorites?.includes(filename)) u.favorites = u.favorites.filter(f => f !== filename);
    }
    saveData(appData);
    addLog('delete', { user: req.currentUser?.username, ip: req.ip, detail: filename });
    res.json({ deleted: filename });
});

// ── Favourites ─────────────────────────────────────────────────────────────
app.get('/api/favorites', (req, res) => {
    const user = appData.users.find(u => u.id === req.currentUser.id);
    // Drop favourites the user can no longer see (e.g. access revoked).
    res.json((user?.favorites || []).filter(f => userCanSeeImage(req.currentUser, f)));
});

app.post('/api/favorites/:filename', (req, res) => {
    const user = appData.users.find(u => u.id === req.currentUser.id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    const filename = path.basename(req.params.filename);
    if (!user.favorites) user.favorites = [];
    if (!user.favorites.includes(filename)) { user.favorites.push(filename); saveData(appData); }
    res.json({ ok: true });
});

app.delete('/api/favorites/:filename', (req, res) => {
    const user = appData.users.find(u => u.id === req.currentUser.id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    user.favorites = (user.favorites || []).filter(f => f !== path.basename(req.params.filename));
    saveData(appData);
    res.json({ ok: true });
});

// ── Device status (posted by ESP32 after each display refresh) ────────────
app.post('/api/device/status', requireApiKey, express.json(), (req, res) => {
    const key = appData.apiKeys.find(k => k.key === (req.headers['x-api-key'] || req.query.key));
    const { battery_mv, wifi_rssi, firmware_version, device_id, charging, usb,
            battery_pct, battery_connected, vbus_mv, sys_mv, charge_status, model } = req.body || {};
    if (!appData.deviceStatus) appData.deviceStatus = {};
    const id = device_id || key.id;
    appData.deviceStatus[id] = {
        deviceId:        id,
        apiKeyId:        key.id,
        apiKeyName:      key.name,
        model:           model || null,
        screenId:        key.screenId || null,
        intervalMinutes: key.intervalMinutes || 5,
        batteryMv:       battery_mv   != null ? Number(battery_mv)  : null,
        wifiRssi:        wifi_rssi    != null ? Number(wifi_rssi)   : null,
        charging:        charging != null ? !!charging : null,
        usb:             usb      != null ? !!usb      : null,
        // Detailed power diagnostics (reported when the PMIC was read this wake).
        batteryPct:       battery_pct != null ? Number(battery_pct) : null,
        batteryConnected: battery_connected != null ? !!battery_connected : null,
        vbusMv:           vbus_mv != null ? Number(vbus_mv) : null,
        sysMv:            sys_mv  != null ? Number(sys_mv)  : null,
        chargeStatus:     charge_status || null,
        fwVersion:       firmware_version || null,
        lastSeen:        new Date().toISOString(),
    };
    saveData(appData);
    res.json({ ok: true });
});

// Firmware OTA: tell the device the version (content hash) of the binary the
// server currently has, so it can decide whether to update. Cached by mtime.
// Each board target keeps its binary in its own subfolder so devices only ever
// OTA their own firmware. The PhotoPainter also still lives at the root for
// backward compatibility. Maps the model the device reports to its files/URL.
const MODEL_FW_DIR = {
    'PhotoPainter-E6':  FIRMWARE_DIR,
    'reTerminal-E1001': path.join(FIRMWARE_DIR, 'reterminal-e1001'),
};
const MODEL_FW_URL = {
    'PhotoPainter-E6':  '/firmware/firmware.bin',
    'reTerminal-E1001': '/firmware/reterminal-e1001/firmware.bin',
};
// Resolve a reported model id -> { dir, urlPrefix }, including admin-added custom
// devices (cloned/built from GitHub, served from firmware_build/<slug>/).
function modelFw(model) {
    if (MODEL_FW_DIR[model]) return { dir: MODEL_FW_DIR[model], urlPrefix: (MODEL_FW_URL[model] || '/firmware/firmware.bin').replace(/\/firmware\.bin$/, '') };
    const cd = (appData.customDevices || []).find(d => d.modelId === model);
    if (cd) return { dir: path.join(FIRMWARE_DIR, cd.slug), urlPrefix: `/firmware/${cd.slug}` };
    return { dir: FIRMWARE_DIR, urlPrefix: '/firmware' };
}
const _fwCacheByDir = {};
function currentFirmwareInfo(model) {
    const dir = modelFw(model).dir;
    const bin = path.join(dir, 'firmware.bin');
    if (!fs.existsSync(bin)) return null;
    const st = fs.statSync(bin);
    const c = _fwCacheByDir[dir] || {};
    if (st.mtimeMs !== c.mtimeMs) {
        const hash = crypto.createHash('md5').update(fs.readFileSync(bin)).digest('hex').slice(0, 16);
        _fwCacheByDir[dir] = { mtimeMs: st.mtimeMs, version: hash, size: st.size };
    }
    return _fwCacheByDir[dir];
}

app.get('/api/device/firmware', requireApiKey, (req, res) => {
    const model = req.query.model || 'PhotoPainter-E6';
    const info  = currentFirmwareInfo(model);
    if (!info) return res.status(404).json({ error: 'No firmware available' });
    const key     = req.apiKey;
    const current = req.query.current || '';
    // A screen can have several keys (re-paired devices); the flags are set on
    // all of them. Consider/clear them together so the UI doesn't get stuck.
    const screenKeys = key.screenId ? (appData.apiKeys || []).filter(k => k.screenId === key.screenId) : [key];
    const anyPending = screenKeys.some(k => k.updatePending);
    const anyAuto    = screenKeys.some(k => k.autoUpdate);
    // Only instruct an update when the user opted in: a one-shot "Update now"
    // request, or auto-update enabled for this device. Never on its own.
    let should = false;
    if (current && current !== info.version) {
        if (anyPending) { should = true; for (const k of screenKeys) k.updatePending = false; saveData(appData); }
        else if (anyAuto) should = true;
    } else if (current && current === info.version && anyPending) {
        // Device already reports the latest version — the update is done (or was
        // unnecessary). Clear the pending flag so the UI stops saying "waiting
        // for update" forever.
        for (const k of screenKeys) k.updatePending = false;
        saveData(appData);
    }
    const baseUrl = `${req.protocol}://${req.get('host')}`;
    // Include the device's API key so it can authenticate the (now non-public)
    // firmware download.
    res.json({ version: info.version, size: info.size, update: should ? 'yes' : 'no',
               url: `${baseUrl}${modelFw(model).urlPrefix}/firmware.bin?key=${encodeURIComponent(key.key)}` });
});

// Device uploads its captured log buffer each wake. Kept as a small ring per device.
app.post('/api/device/log', requireApiKey, express.json({ limit: '64kb' }), (req, res) => {
    const key = req.apiKey;
    const { device_id, log } = req.body || {};
    if (typeof log !== 'string' || !log.length) return res.json({ ok: true });
    const id = device_id || key.id;
    if (!appData.deviceLogs) appData.deviceLogs = {};
    const entry = appData.deviceLogs[id] || { deviceId: id, apiKeyId: key.id, entries: [] };
    entry.apiKeyId = key.id;
    entry.entries.push({ at: new Date().toISOString(), text: log.slice(0, 8000) });
    // Keep only the most recent 20 uploads per device.
    if (entry.entries.length > 20) entry.entries = entry.entries.slice(-20);
    appData.deviceLogs[id] = entry;
    saveData(appData);
    res.json({ ok: true });
});

// Admin: read a device's recent logs. Each device is decorated with the screen
// it's paired to (via its API key) so the dashboard can filter logs per screen.
// Optional filters: ?deviceId= ?apiKeyId= ?screenId= (empty screenId = unpaired).
app.get('/api/admin/device-logs', requireAdmin, (req, res) => {
    const logs = appData.deviceLogs || {};
    const keys = appData.apiKeys || [];
    const screens = appData.screens || [];
    const { deviceId, apiKeyId, screenId } = req.query;
    let list = Object.values(logs).map(l => {
        const key = keys.find(k => k.id === l.apiKeyId);
        const sid = key?.screenId || null;
        const scr = sid ? screens.find(s => s.id === sid) : null;
        return { ...l, screenId: sid, screenName: scr?.name || null, keyName: key?.name || null };
    });
    if (deviceId) list = list.filter(l => l.deviceId === deviceId);
    if (apiKeyId) list = list.filter(l => l.apiKeyId === apiKeyId);
    if (screenId !== undefined) {
        const want = screenId === '' ? null : screenId;
        list = list.filter(l => l.screenId === want);
    }
    // Newest entries first within each device.
    list = list.map(l => ({ ...l, entries: [...l.entries].reverse() }));
    res.json(list);
});

app.delete('/api/admin/device-logs/:deviceId', requireAdmin, (req, res) => {
    if (appData.deviceLogs) delete appData.deviceLogs[req.params.deviceId];
    saveData(appData);
    res.json({ ok: true });
});

// ── Firmware changelog (read-only) ────────────────────────────────────────
// The changelog is NOT edited through the UI. It is a source-controlled file
// in the repo (esp32/firmware-changelog.json) that we update when we push a new
// firmware build. It lists the releases per supported screen model; the newest
// release of a model is the build the server currently serves over OTA.
const FW_CHANGELOG_FILE = path.join(ESP32_DIR, 'firmware-changelog.json');
function readFirmwareChangelog() {
    try {
        const doc = JSON.parse(fs.readFileSync(FW_CHANGELOG_FILE, 'utf8'));
        return doc && typeof doc.models === 'object' ? doc.models : {};
    } catch { return {}; }
}

app.get('/api/firmware/changelog', (req, res) => {
    const models = readFirmwareChangelog();
    const serverVersion = currentFirmwareInfo()?.version || null;
    // The server only carries one firmware binary; it corresponds to the newest
    // release of the requested (or only) supported model.
    const onlyModel = req.query.model && models[req.query.model]
        ? { [req.query.model]: models[req.query.model] }
        : models;
    const out = Object.entries(onlyModel).map(([id, m]) => {
        // Each model's served binary lives in its own folder; mark the release
        // whose recorded buildHash matches it (set automatically at build time),
        // falling back to the newest release.
        const sv = currentFirmwareInfo(id)?.version || null;
        const releases = m.releases || [];
        let curIdx = releases.findIndex(r => r.buildHash && sv && r.buildHash === sv);
        if (curIdx < 0) curIdx = 0;
        return {
            id,
            name: m.name || id,
            serverVersion: sv,
            releases: releases.map((r, i) => ({
                version: r.version || null,
                title:   r.title || 'Update',
                changes: Array.isArray(r.changes) ? r.changes : [],
                date:    r.date || null,
                isCurrentBuild: i === curIdx,
            })),
        };
    });
    res.json({ serverVersion, models: out });
});

// ── Server system metrics (CPU / RAM / storage) ────────────────────────────
function cpuSample() {
    let idle = 0, total = 0;
    for (const c of os.cpus()) { for (const t in c.times) total += c.times[t]; idle += c.times.idle; }
    return { idle, total };
}
function dirSize(dir) {
    let bytes = 0;
    try { for (const f of fs.readdirSync(dir)) { try { bytes += fs.statSync(path.join(dir, f)).size; } catch {} } } catch {}
    return bytes;
}
app.get('/api/admin/system-metrics', requireAdmin, async (_req, res) => {
    // CPU: sample busy time over a short window (loadavg is unreliable on Windows).
    const a = cpuSample();
    await new Promise(r => setTimeout(r, 200));
    const b = cpuSample();
    const idleDiff = b.idle - a.idle, totalDiff = b.total - a.total;
    const cpuPct = totalDiff > 0 ? Math.round(100 * (1 - idleDiff / totalDiff)) : 0;

    const totalMem = os.totalmem(), freeMem = os.freemem();
    const ramPct = Math.round(100 * (1 - freeMem / totalMem));

    // Storage: free space on the disk holding the app (fs.statfs, Node 18.15+);
    // fall back to just the size of the uploads folder if unavailable.
    let storage = null;
    try {
        const st = await fs.promises.statfs(ROOT_DIR);
        const total = st.blocks * st.bsize, free = st.bavail * st.bsize;
        storage = { total, free, used: total - free, pct: Math.round(100 * (1 - free / total)), kind: 'disk' };
    } catch {
        const used = dirSize(UPLOADS_DIR);
        storage = { used, pct: null, kind: 'uploads' };
    }

    res.json({
        cpu:     { pct: cpuPct, cores: os.cpus().length, model: (os.cpus()[0] || {}).model || '' },
        ram:     { pct: ramPct, total: totalMem, free: freeMem, used: totalMem - freeMem },
        storage,
        uploads: { bytes: dirSize(UPLOADS_DIR), count: (() => { try { return fs.readdirSync(UPLOADS_DIR).filter(f => IMAGE_EXTS.test(f)).length; } catch { return 0; } })() },
        host:    { platform: os.platform(), uptime: os.uptime() },
        proc:    { uptime: process.uptime(), rss: process.memoryUsage().rss, node: process.version },
    });
});

app.get('/api/admin/devices', requireAdmin, (_req, res) => {
    const statuses = Object.values(appData.deviceStatus || {});
    // Merge lastFlash + key string from apiKeys into each status entry
    const result = statuses.map(d => {
        const key = appData.apiKeys.find(k => k.id === d.apiKeyId);
        return { ...d, apiKey: key?.key || null, lastFlash: key?.lastFlash || null };
    });
    // Also include API keys that have never checked in
    const seenKeyIds = new Set(statuses.map(d => d.apiKeyId));
    for (const key of appData.apiKeys) {
        if (!seenKeyIds.has(key.id)) {
            result.push({
                deviceId:        key.id,
                apiKeyId:        key.id,
                apiKeyName:      key.name,
                apiKey:          key.key,
                screenId:        key.screenId || null,
                intervalMinutes: key.intervalMinutes || 5,
                batteryMv:       null,
                wifiRssi:        null,
                fwVersion:       null,
                lastSeen:        null,
                lastFlash:       key.lastFlash || null,
            });
        }
    }
    res.json(result);
});

// ── WiFi network scan (admin only) ────────────────────────────────────────
app.get('/api/admin/wifi-scan', requireAdmin, (_req, res) => {
    const isWindows = process.platform === 'win32';
    // Windows: list saved profiles — no location permission required.
    // Linux:   list saved connections via nmcli (works in Docker too).
    const cmd = isWindows
        ? 'netsh wlan show profiles'
        : 'nmcli -t -f NAME,TYPE connection show 2>/dev/null';

    exec(cmd, { timeout: 12000 }, (err, stdout) => {
        if (err && !stdout) return res.status(500).json({ error: 'WiFi scan failed', detail: err.message });
        const ssids = [];
        if (isWindows) {
            // Matches lines like:  "    All User Profile     : MyNetwork"
            for (const m of String(stdout).matchAll(/All User Profile\s*:\s*(.+)$/gm)) {
                const s = m[1].trim();
                if (s && !ssids.includes(s)) ssids.push(s);
            }
        } else {
            // nmcli -t output: "NAME:TYPE" — keep only 802-11-wireless entries
            for (const line of String(stdout).split('\n')) {
                const [name, type] = line.split(':');
                if (type?.trim() === '802-11-wireless' && name?.trim() && !ssids.includes(name.trim()))
                    ssids.push(name.trim());
            }
        }
        // Tell the UI which networks already have a saved (encrypted) password so
        // it can offer to reuse it instead of asking the operator to retype it.
        res.json({ ssids, saved: Object.keys(appData.wifiCreds || {}) });
    });
});

// ── Screens ────────────────────────────────────────────────────────────────
// Convert a Li-ion cell voltage (mV) to an approximate 0-100% charge.
function battMvToPercent(mv) {
    if (mv == null) return null;
    const pct = Math.round(((mv - 3300) / (4200 - 3300)) * 100);
    return Math.min(100, Math.max(0, pct));
}
// Convert WiFi RSSI (dBm) to a 0-4 bar strength and label.
function rssiToBars(rssi) {
    if (rssi == null) return { bars: null, label: '' };
    const bars = rssi >= -55 ? 4 : rssi >= -65 ? 3 : rssi >= -75 ? 2 : rssi >= -85 ? 1 : 0;
    const label = ['No signal', 'Weak', 'Fair', 'Good', 'Excellent'][bars];
    return { bars, label };
}

app.get('/api/screens', (req, res) => {
    const meta     = appData.imageMetadata || {};
    const statuses = appData.deviceStatus  || {};    // what the firmware posts
    const now      = Date.now();

    const screens = (appData.screens || [])
      .filter(s => userCanAccessScreen(req.currentUser, s.id))
      .map(s => {
        // A screen can have several API keys (e.g. re-paired devices). Match the
        // device check-in against ANY key on this screen, not just the first.
        const linkedKeys   = (appData.apiKeys || []).filter(k => k.screenId === s.id);
        const linkedKeyIds = new Set(linkedKeys.map(k => k.id));
        // For settings display, prefer the key the device actually reports under.
        const linkedKey = linkedKeys[0];
        let deviceInfo  = null;
        if (linkedKeys.length) {
            const fwList = Object.values(statuses).filter(d => linkedKeyIds.has(d.apiKeyId) || d.screenId === s.id);
            // Prefer the most recently seen status across all the screen's keys.
            const src = fwList.sort((a, b) => new Date(b.lastSeen) - new Date(a.lastSeen))[0];
            if (src) {
                const ageMs = now - new Date(src.lastSeen).getTime();
                // Offline detection is relative to how often the device is
                // *expected* to check in (its refresh interval), not a fixed
                // window: a device is online if it checked in this cycle, and
                // offline once it has missed ~3 expected check-ins. While it's
                // in its scheduled sleep window it intentionally won't check in,
                // so show "Sleeping" rather than flapping to offline.
                const tz          = appData.settings?.timezone || DEFAULT_SETTINGS.timezone;
                const sleepingNow = screenSleepInfo(linkedKey, tz).sleeping;
                const intervalMin = src.intervalMinutes || linkedKey?.intervalMinutes || 5;
                const expectedMs  = intervalMin * 60 * 1000;
                const grace       = 60 * 1000;   // slack for wake/refresh + clock drift
                let status, statusLabel;
                if (sleepingNow)                          { status = 'sleeping'; statusLabel = 'Sleeping'; }
                else if (ageMs < expectedMs + grace)      { status = 'online';   statusLabel = 'Online'; }
                else if (ageMs < 3 * expectedMs + grace)  { status = 'recent';   statusLabel = 'Recently seen'; }
                else                                      { status = 'offline';  statusLabel = 'Offline'; }
                // Normalize fields from whichever store we used.
                // Prefer the device's own PMU fuel-gauge percentage (batteryPct) so the
                // headline battery meter matches the "Level" shown in Power details. Only
                // fall back to the crude voltage→percent estimate when no gauge value exists.
                const batt = src.batt ?? src.batteryPct ?? battMvToPercent(src.batteryMv);
                const w    = src.wifi != null ? { bars: src.wifi, label: src.wlabel || '' }
                                              : rssiToBars(src.wifiRssi);
                deviceInfo = {
                    id:          src.deviceId || linkedKey.label || linkedKey.id,
                    batt:        batt ?? null,
                    charging:    src.charging ?? null,
                    usb:         src.usb ?? null,
                    power: {
                        battMv:    src.batteryMv ?? null,
                        battPct:   src.batteryPct ?? null,
                        battConn:  src.batteryConnected ?? null,
                        vbusMv:    src.vbusMv ?? null,
                        sysMv:     src.sysMv ?? null,
                        chargeStatus: src.chargeStatus ?? null,
                    },
                    level:       src.level || (batt == null ? 'good' : batt <= 15 ? 'bad' : batt <= 30 ? 'warn' : 'good'),
                    wifi:        w.bars,
                    wlabel:      w.label,
                    status,
                    statusLabel,
                    lastSeen:    src.lastSeen,
                    fw:          src.fw || src.fwVersion || null,
                    deviceStatus: src.status || null,
                };
            }
        }
        const serverFw = currentFirmwareInfo();
        const deviceFw = deviceInfo?.fw || null;
        return {
            ...s,
            imageCount:  Object.values(meta).filter(m => m.screenId === s.id).length,
            albumCount:  (appData.albums || []).filter(a => a.screenId === s.id).length,
            intervalMinutes: linkedKey?.intervalMinutes || 5,
            rotation:    linkedKey?.rotation || 0,
            imageBrightness: linkedKey?.imageBrightness ?? (appData.settings?.imageBrightness ?? DEFAULT_SETTINGS.imageBrightness),
            imageSaturation: linkedKey?.imageSaturation ?? (appData.settings?.imageSaturation ?? DEFAULT_SETTINGS.imageSaturation),
            imageFit:    linkedKey?.imageFit || s.imageFit || 'contain',
            sleepEnabled: linkedKey?.sleepEnabled ?? s.sleepEnabled ?? false,
            sleepStart:  linkedKey?.sleepStart || s.sleepStart || '23:00',
            sleepEnd:    linkedKey?.sleepEnd   || s.sleepEnd   || '07:00',
            debugLogging: linkedKey?.debugLogging ?? s.debugLogging ?? false,
            autoUpdate:  linkedKeys.some(k => k.autoUpdate),
            updatePending: linkedKeys.some(k => k.updatePending),
            firmwareVersion: deviceFw,
            serverFirmwareVersion: serverFw?.version || null,
            firmwareUpdateAvailable: !!(deviceFw && serverFw && deviceFw !== serverFw.version),
            device:      !!deviceInfo,
            deviceInfo,
        };
    });
    res.json(screens);
});

app.post('/api/screens', (req, res) => {
    const { name, description, color } = req.body;
    if (!name?.trim()) return res.status(400).json({ error: 'Screen name is required' });
    if (!appData.screens) appData.screens = [];
    const screen = {
        id: crypto.randomUUID(),
        name: name.trim(),
        description: (description || '').trim(),
        color: color || '#06b6d4',
        createdAt: new Date().toISOString(),
        createdBy: req.currentUser?.username || null,
    };
    appData.screens.push(screen);
    // A non-admin who creates a screen should keep access to it — grant it to
    // their role (group), otherwise the filtered /api/screens hides it from them.
    if (req.currentUser && !isAdmin(req.currentUser)) {
        const r = (appData.roles || {})[req.currentUser.role];
        if (r) { r.screens = r.screens || []; if (!r.screens.includes(screen.id)) r.screens.push(screen.id); }
    }
    saveData(appData);
    res.json(screen);
});

app.put('/api/screens/:id', (req, res) => {
    const screen = (appData.screens || []).find(s => s.id === req.params.id);
    if (!screen) return res.status(404).json({ error: 'Screen not found' });
    const { name, description, color, intervalMinutes, autoUpdate, rotation, imageBrightness, imageSaturation, imageFit, sleepEnabled, sleepStart, sleepEnd, debugLogging } = req.body;
    if (name !== undefined) screen.name = name.trim();
    if (description !== undefined) screen.description = description.trim();
    if (color !== undefined) screen.color = color;
    const linkedKeys = (appData.apiKeys || []).filter(k => k.screenId === screen.id);
    // Rotation (0/90/180/270) — applied server-side to the image sent to the device.
    if (rotation !== undefined) {
        const allowed = [0, 90, 180, 270];
        const rot = allowed.includes(Number(rotation)) ? Number(rotation) : 0;
        for (const k of linkedKeys) k.rotation = rot;
        screen.rotation = rot;
    }
    // Per-display image look (brightness/saturation), clamped to sane ranges.
    if (imageBrightness !== undefined) {
        const v = Math.min(2, Math.max(0.5, parseFloat(imageBrightness) || 1));
        for (const k of linkedKeys) k.imageBrightness = v;
        screen.imageBrightness = v;
    }
    if (imageSaturation !== undefined) {
        const v = Math.min(2, Math.max(0.5, parseFloat(imageSaturation) || 1));
        for (const k of linkedKeys) k.imageSaturation = v;
        screen.imageSaturation = v;
    }
    // Fit mode: how photos fill the panel — 'contain' (letterbox) or 'cover' (crop).
    if (imageFit !== undefined) {
        const v = imageFit === 'cover' ? 'cover' : 'contain';
        for (const k of linkedKeys) k.imageFit = v;
        screen.imageFit = v;
    }
    // Sleep schedule: show the "Sleeping" screen and stop refreshing between
    // sleepStart and sleepEnd (HH:MM, screen timezone; supports overnight).
    const normTime = (t, fb) => { const m = /^(\d{1,2}):(\d{2})$/.exec(String(t || '')); if (!m) return fb; const h = Math.min(23, +m[1]), mn = Math.min(59, +m[2]); return String(h).padStart(2, '0') + ':' + String(mn).padStart(2, '0'); };
    if (sleepEnabled !== undefined) {
        const v = !!sleepEnabled;
        for (const k of linkedKeys) k.sleepEnabled = v;
        screen.sleepEnabled = v;
    }
    if (sleepStart !== undefined) {
        const v = normTime(sleepStart, '23:00');
        for (const k of linkedKeys) k.sleepStart = v;
        screen.sleepStart = v;
    }
    if (sleepEnd !== undefined) {
        const v = normTime(sleepEnd, '07:00');
        for (const k of linkedKeys) k.sleepEnd = v;
        screen.sleepEnd = v;
    }
    // Debug logging: keep the device's WiFi on through the e-ink refresh so the
    // decode/display logs reach the server (costs battery — leave off normally).
    if (debugLogging !== undefined) {
        const v = !!debugLogging;
        for (const k of linkedKeys) k.debugLogging = v;
        screen.debugLogging = v;
    }
    // Refresh rate and auto-update live on the device's API key. Apply to every
    // key linked to this screen.
    if (intervalMinutes !== undefined) {
        const mins = Math.min(1440, Math.max(1, Math.round(Number(intervalMinutes) || 5)));
        for (const k of (appData.apiKeys || [])) {
            if (k.screenId === screen.id) k.intervalMinutes = mins;
        }
        screen.intervalMinutes = mins;
    }
    if (autoUpdate !== undefined) {
        for (const k of (appData.apiKeys || [])) {
            if (k.screenId === screen.id) k.autoUpdate = !!autoUpdate;
        }
    }
    saveData(appData);
    res.json(screen);
});

// Queue a one-shot firmware update for the device(s) on this screen. The device
// applies it the next time it wakes and checks in.
app.post('/api/screens/:id/update-firmware', (req, res) => {
    const screen = (appData.screens || []).find(s => s.id === req.params.id);
    if (!screen) return res.status(404).json({ error: 'Screen not found' });
    const keys = (appData.apiKeys || []).filter(k => k.screenId === screen.id);
    if (!keys.length) return res.status(400).json({ error: 'No device paired to this screen' });
    for (const k of keys) k.updatePending = true;
    saveData(appData);
    res.json({ ok: true, queued: keys.length });
});

app.delete('/api/screens/:id', requireAdmin, (req, res) => {
    const idx = (appData.screens || []).findIndex(s => s.id === req.params.id);
    if (idx === -1) return res.status(404).json({ error: 'Screen not found' });
    const screenId = req.params.id;
    appData.screens.splice(idx, 1);
    const meta = appData.imageMetadata || {};
    for (const filename of Object.keys(meta)) {
        if (meta[filename].screenId === screenId) meta[filename].screenId = null;
    }
    // Revoke this screen from every role's (group's) access list.
    for (const r of Object.values(appData.roles || {})) {
        if (r.screens?.includes(screenId)) r.screens = r.screens.filter(id => id !== screenId);
    }
    // Delete the device(s) tied to this screen — the API key, its live status,
    // and its albums. Uploaded images stay in the library, just unassigned.
    const removedKeyIds = (appData.apiKeys || []).filter(k => k.screenId === screenId).map(k => k.id);
    if (removedKeyIds.length) {
        appData.apiKeys = appData.apiKeys.filter(k => k.screenId !== screenId);
        // Clear the live-status map (keyed by device id with an apiKeyId field).
        if (appData.deviceStatus) {
            for (const [devId, d] of Object.entries(appData.deviceStatus)) {
                if (removedKeyIds.includes(d.apiKeyId)) delete appData.deviceStatus[devId];
            }
        }
        appData.albums = (appData.albums || []).filter(a => !removedKeyIds.includes(a.deviceId));
    }
    saveData(appData);
    res.json({ deleted: screenId });
});

// ── Albums ─────────────────────────────────────────────────────────────────
app.get('/api/screens/:screenId/albums', (req, res) => {
    const { screenId } = req.params;
    if (!(appData.screens || []).find(s => s.id === screenId))
        return res.status(404).json({ error: 'Screen not found' });
    if (!userCanAccessScreen(req.currentUser, screenId))
        return res.status(403).json({ error: 'Permission denied' });
    const meta = appData.imageMetadata || {};
    const albums = (appData.albums || [])
        .filter(a => a.screenId === screenId)
        .map(a => ({ ...a, photoCount: Object.values(meta).filter(m => m.albumId === a.id).length }));
    res.json(albums);
});

app.post('/api/screens/:screenId/albums', (req, res) => {
    const { screenId } = req.params;
    if (!(appData.screens || []).find(s => s.id === screenId))
        return res.status(404).json({ error: 'Screen not found' });
    const { name } = req.body;
    if (!name?.trim()) return res.status(400).json({ error: 'Album name is required' });
    if (!appData.albums) appData.albums = [];
    const album = {
        id: crypto.randomUUID(),
        screenId,
        name: name.trim(),
        fav: false,
        createdAt: new Date().toISOString(),
        createdBy: req.currentUser?.username || null,
    };
    appData.albums.push(album);
    saveData(appData);
    res.json(album);
});

app.put('/api/screens/:screenId/albums/:albumId', (req, res) => {
    const album = (appData.albums || []).find(a => a.id === req.params.albumId && a.screenId === req.params.screenId);
    if (!album) return res.status(404).json({ error: 'Album not found' });
    const { name, fav } = req.body;
    if (name !== undefined) album.name = name.trim();
    if (fav !== undefined) album.fav = !!fav;
    saveData(appData);
    res.json(album);
});

// Any signed-in user can delete an album (consistent with creating/editing them).
// The photos themselves stay in the library; only the album grouping is removed.
app.delete('/api/screens/:screenId/albums/:albumId', (req, res) => {
    const idx = (appData.albums || []).findIndex(a => a.id === req.params.albumId && a.screenId === req.params.screenId);
    if (idx === -1) return res.status(404).json({ error: 'Album not found' });
    const albumId = req.params.albumId;
    appData.albums.splice(idx, 1);
    // Unlink images from this album
    const meta = appData.imageMetadata || {};
    for (const f of Object.keys(meta)) {
        if (meta[f].albumId === albumId) meta[f].albumId = null;
    }
    saveData(appData);
    res.json({ deleted: albumId });
});

app.put('/api/images/:filename/screen', (req, res) => {
    const filename = path.basename(req.params.filename);
    const { screenId } = req.body;
    if (screenId && !(appData.screens || []).find(s => s.id === screenId)) {
        return res.status(400).json({ error: 'Screen not found' });
    }
    // Must be able to see the photo, and (when assigning) to access the target screen.
    if (!userCanSeeImage(req.currentUser, filename))
        return res.status(403).json({ error: 'Permission denied' });
    if (screenId && !userCanAccessScreen(req.currentUser, screenId))
        return res.status(403).json({ error: 'You do not have access to that screen' });
    if (!appData.imageMetadata) appData.imageMetadata = {};
    if (!appData.imageMetadata[filename]) appData.imageMetadata[filename] = {};
    appData.imageMetadata[filename].screenId = screenId || null;
    saveData(appData);
    res.json({ ok: true });
});

// Per-image fit override: 'cover' (crop to fill), 'contain' (letterbox), or
// null/'default' to fall back to the screen's setting.
app.put('/api/images/:filename/fit', (req, res) => {
    const filename = path.basename(req.params.filename);
    const { imageFit } = req.body;
    if (!userCanSeeImage(req.currentUser, filename))
        return res.status(403).json({ error: 'Permission denied' });
    if (!appData.imageMetadata) appData.imageMetadata = {};
    if (!appData.imageMetadata[filename]) appData.imageMetadata[filename] = {};
    if (imageFit === 'cover' || imageFit === 'contain')
        appData.imageMetadata[filename].imageFit = imageFit;
    else
        delete appData.imageMetadata[filename].imageFit;   // back to screen default
    saveData(appData);
    res.json({ ok: true, imageFit: appData.imageMetadata[filename].imageFit || null });
});

// ── Inactivity notifications ───────────────────────────────────────────────
function inactivityEmailHtml(staleUsers, staleKeys) {
    let html = `<div style="font-family:sans-serif;padding:32px 24px;max-width:540px">
        <h2 style="color:#0e7490;margin-bottom:4px">PhotoDock</h2>
        <p style="color:#555;margin-top:0">Inactivity alert — ${new Date().toLocaleDateString('en-GB', { day:'numeric', month:'long', year:'numeric' })}</p>`;
    if (staleUsers.length) {
        html += `<h3 style="margin-bottom:8px">Inactive users</h3>
        <table style="border-collapse:collapse;width:100%">
        <tr style="border-bottom:1px solid #e0e0e0"><th style="text-align:left;padding:4px 12px 4px 0;font-size:13px;color:#888">Username</th><th style="text-align:left;font-size:13px;color:#888">Last login</th></tr>`;
        for (const u of staleUsers) {
            const last = u.lastLogin ? new Date(u.lastLogin).toLocaleDateString('en-GB', { day:'numeric', month:'long', year:'numeric' }) : 'Never';
            html += `<tr style="border-bottom:1px solid #f0f0f0"><td style="padding:6px 12px 6px 0;font-size:14px">${u.username}</td><td style="padding:6px 0;font-size:14px;color:#888">${last}</td></tr>`;
        }
        html += `</table>`;
    }
    if (staleKeys.length) {
        html += `<h3 style="margin-bottom:8px;margin-top:${staleUsers.length ? 24 : 0}px">Inactive API keys</h3>
        <table style="border-collapse:collapse;width:100%">
        <tr style="border-bottom:1px solid #e0e0e0"><th style="text-align:left;padding:4px 12px 4px 0;font-size:13px;color:#888">Name</th><th style="text-align:left;font-size:13px;color:#888">Last used</th></tr>`;
        for (const k of staleKeys) {
            const last = k.lastUsed ? new Date(k.lastUsed).toLocaleDateString('en-GB', { day:'numeric', month:'long', year:'numeric' }) : 'Never';
            html += `<tr style="border-bottom:1px solid #f0f0f0"><td style="padding:6px 12px 6px 0;font-size:14px">${k.name}</td><td style="padding:6px 0;font-size:14px;color:#888">${last}</td></tr>`;
        }
        html += `</table>`;
    }
    html += `<p style="font-size:12px;color:#aaa;margin-top:24px">Sent by PhotoDock · Manage notification settings in the admin panel</p></div>`;
    return html;
}

async function runInactivityCheck() {
    const settings = Object.assign({}, DEFAULT_SETTINGS, appData.settings || {});
    const userDays = settings.userInactivityDays;
    const keyDays  = settings.apiKeyInactivityDays;
    if (!userDays && !keyDays) return;

    const now = Date.now();
    const MS_PER_DAY = 86400 * 1000;

    const staleUsers = userDays ? appData.users.filter(u => {
        const age = u.lastLogin ? (now - new Date(u.lastLogin).getTime()) : Infinity;
        const lastNotified = u.lastInactivityNotified ? new Date(u.lastInactivityNotified).getTime() : 0;
        return age >= userDays * MS_PER_DAY && (now - lastNotified) >= MS_PER_DAY;
    }) : [];

    const staleKeys = keyDays ? (appData.apiKeys || []).filter(k => {
        const age = k.lastUsed ? (now - new Date(k.lastUsed).getTime()) : Infinity;
        const lastNotified = k.lastInactivityNotified ? new Date(k.lastInactivityNotified).getTime() : 0;
        return age >= keyDays * MS_PER_DAY && (now - lastNotified) >= MS_PER_DAY;
    }) : [];

    if (!staleUsers.length && !staleKeys.length) return;

    // Collect admin email addresses
    const adminEmails = appData.users
        .filter(u => {
            const role = appData.roles?.[u.role];
            return role?.canManage && u.email;
        })
        .map(u => u.email);
    if (!adminEmails.length) return;

    const html = inactivityEmailHtml(staleUsers, staleKeys);
    const subject = 'Inactivity alert — PhotoDock';
    let sent = false;
    for (const email of adminEmails) {
        try { await sendEmail(email, subject, html); sent = true; } catch { /* skip */ }
    }

    if (sent) {
        const ts = new Date().toISOString();
        for (const u of staleUsers) { u.lastInactivityNotified = ts; }
        for (const k of staleKeys)  { k.lastInactivityNotified = ts; }
        saveData(appData);
        console.log(`Inactivity notification sent: ${staleUsers.length} user(s), ${staleKeys.length} key(s)`);
    }
}

// Run the check once per hour
setInterval(runInactivityCheck, 60 * 60 * 1000);
// Also run shortly after startup so the first check doesn't wait an hour
setTimeout(runInactivityCheck, 30 * 1000);

// ── Log retention pruning ──────────────────────────────────────────────────
function pruneOldLogs() {
    const settings = Object.assign({}, DEFAULT_SETTINGS, appData.settings || {});
    const retentionMs = settings.logRetentionDays * 86400 * 1000;
    const cutoff = Date.now() - retentionMs;
    const before = (appData.logs || []).length;
    appData.logs = (appData.logs || []).filter(e => new Date(e.timestamp).getTime() >= cutoff);
    if (appData.logs.length !== before) {
        saveData(appData);
        console.log(`Log prune: removed ${before - appData.logs.length} entries older than ${settings.logRetentionDays} day(s)`);
    }
}

// Prune once per hour
setInterval(pruneOldLogs, 60 * 60 * 1000);
setTimeout(pruneOldLogs, 35 * 1000);

// ── Start ──────────────────────────────────────────────────────────────────
function startServer(port) {
    const server = app.listen(port, () => console.log(`HTTP  server running at http://localhost:${port}`));
    server.on('error', err => {
        if (err.code === 'EADDRINUSE' || err.code === 'EACCES') {
            console.log(`Port ${port} unavailable, trying ${port + 1}...`);
            startServer(port + 1);
        } else {
            console.error('Server error:', err);
        }
    });
}

function generateSelfSignedCert(certPath, keyPath) {
    const dir = path.dirname(certPath);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    try {
        // Generate RSA-2048 key pair using Node.js built-in crypto (no openssl CLI needed)
        const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding:  { type: 'spki',   format: 'der' },
            privateKeyEncoding: { type: 'pkcs8',  format: 'pem' }
        });

        // ── Minimal DER encoding helpers ──────────────────────────────────
        function derLen(n) {
            if (n < 128) return Buffer.from([n]);
            const b = [];
            let v = n;
            while (v > 0) { b.unshift(v & 0xff); v >>= 8; }
            return Buffer.from([0x80 | b.length, ...b]);
        }
        function tlv(tag, content) {
            return Buffer.concat([Buffer.from([tag]), derLen(content.length), content]);
        }
        function seq(items) { return tlv(0x30, Buffer.concat(items)); }
        function intDer(n) {
            const b = [];
            let v = n;
            do { b.unshift(v & 0xff); v = Math.floor(v / 256); } while (v > 0);
            if (b[0] & 0x80) b.unshift(0);
            return tlv(0x02, Buffer.from(b));
        }
        function derOid(dotStr) {
            const p = dotStr.split('.').map(Number);
            const bytes = [40 * p[0] + p[1]];
            for (let i = 2; i < p.length; i++) {
                let n = p[i], tmp = [n & 0x7f];
                n >>= 7;
                while (n > 0) { tmp.unshift((n & 0x7f) | 0x80); n >>= 7; }
                bytes.push(...tmp);
            }
            return tlv(0x06, Buffer.from(bytes));
        }
        function utcTime(d) {
            const p = n => String(n).padStart(2, '0');
            const s = `${String(d.getUTCFullYear()).slice(2)}${p(d.getUTCMonth()+1)}${p(d.getUTCDate())}${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}Z`;
            return tlv(0x17, Buffer.from(s, 'ascii'));
        }

        // ── Build TBSCertificate ───────────────────────────────────────────
        const sigAlg = seq([derOid('1.2.840.113549.1.1.11'), Buffer.from([0x05, 0x00])]); // sha256WithRSAEncryption
        const name   = seq([tlv(0x31, seq([derOid('2.5.4.3'), tlv(0x0c, Buffer.from('localhost', 'utf8'))]))]); // CN=localhost
        const now    = new Date();
        const exp    = new Date(now.getTime() + 10 * 365.25 * 24 * 3600 * 1000);
        const tbs    = seq([
            Buffer.from([0xa0, 0x03, 0x02, 0x01, 0x02]), // version: v3
            intDer(1),                                     // serialNumber: 1
            sigAlg,
            name,                                          // issuer
            seq([utcTime(now), utcTime(exp)]),             // validity
            name,                                          // subject
            Buffer.from(publicKey)                         // subjectPublicKeyInfo (SPKI DER)
        ]);

        // ── Sign and assemble Certificate ─────────────────────────────────
        const sig  = crypto.sign('sha256', tbs, privateKey);
        const cert = seq([tbs, sigAlg, tlv(0x03, Buffer.concat([Buffer.from([0x00]), sig]))]);
        const pem  = `-----BEGIN CERTIFICATE-----\n${cert.toString('base64').match(/.{1,64}/g).join('\n')}\n-----END CERTIFICATE-----\n`;

        fs.writeFileSync(keyPath,  privateKey);
        fs.writeFileSync(certPath, pem);
        console.log(`HTTPS: generated self-signed certificate at ${certPath}`);
        return true;
    } catch (e) {
        console.error('HTTPS: could not generate self-signed certificate:', e.message);
        return false;
    }
}

function startHttpsServer(port) {
    // Resolve cert paths — fall back to <data-dir>/ssl/ if not explicitly configured
    const dataDir  = path.dirname(DATA_FILE);
    const certPath = SSL_CERT || path.join(dataDir, 'ssl', 'cert.pem');
    const keyPath  = SSL_KEY  || path.join(dataDir, 'ssl', 'key.pem');

    // Auto-generate a self-signed certificate if files are missing
    if (!fs.existsSync(certPath) || !fs.existsSync(keyPath)) {
        console.log('HTTPS: no certificate found — generating self-signed certificate…');
        if (!generateSelfSignedCert(certPath, keyPath)) return;
    }

    try {
        const creds = { cert: fs.readFileSync(certPath), key: fs.readFileSync(keyPath) };
        https.createServer(creds, app).listen(port, () =>
            console.log(`HTTPS server running at https://localhost:${port}`)
        );
    } catch (e) {
        console.error('HTTPS: could not start server:', e.message);
    }
}

startServer(Number(PORT));
if (HTTPS_PORT) startHttpsServer(Number(HTTPS_PORT));
