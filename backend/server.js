const express = require('express');
const https   = require('https');
const multer  = require('multer');
const path    = require('path');
const fs      = require('fs');
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

let appData = loadData();
if (!appData.tokens)        { appData.tokens        = []; saveData(appData); }
if (!appData.logs)          { appData.logs          = []; saveData(appData); }
if (!appData.imageMetadata) { appData.imageMetadata = {}; saveData(appData); }
if (!appData.screens)       { appData.screens       = []; saveData(appData); }
if (!appData.albums)        { appData.albums        = []; saveData(appData); }
if (!appData.deviceStates)  { appData.deviceStates  = {}; saveData(appData); }
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

function requireAuth(req, res, next) {
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

app.get('/api/admin/firmware/status', requireAdmin, (_req, res) => {
    const manifest = path.join(FIRMWARE_DIR, 'manifest.json');
    const firmware  = path.join(FIRMWARE_DIR, 'firmware.bin');
    const ready     = fs.existsSync(manifest) && fs.existsSync(firmware);
    let builtAt     = null;
    if (ready) { try { builtAt = fs.statSync(firmware).mtime.toISOString(); } catch {} }
    res.json({ ready, builtAt, buildInProgress });
});

app.post('/api/admin/firmware/build', requireAdmin, express.json(), (req, res) => {
    if (buildInProgress) return res.status(409).json({ error: 'A build is already in progress' });

    const { wifi_ssid='', wifi_password='', server_host='', server_port=8080 } = req.body || {};

    const esc = s => String(s).replace(/\\/g,'\\\\').replace(/"/g,'\\"');
    const configContent = [
        '#pragma once',
        '#define DEFAULT_SLEEP_S         (5 * 60)',
        '#define BATTERY_ADC_PIN         4',
        '#define BATTERY_DIVIDER_RATIO   2.0f',
        '#define JPEG_BUF_SIZE           (512 * 1024)',
        `#define DEFAULT_WIFI_SSID       "${esc(wifi_ssid)}"`,
        `#define DEFAULT_WIFI_PASS       "${esc(wifi_password)}"`,
        `#define DEFAULT_SERVER_HOST     "${esc(server_host)}"`,
        `#define DEFAULT_SERVER_PORT     ${parseInt(server_port) || 8080}`,
        `#define DEFAULT_API_KEY         ""`,
    ].join('\n') + '\n';

    try { fs.mkdirSync(path.join(ESP32_DIR, 'src'), { recursive: true }); } catch {}
    fs.writeFileSync(path.join(ESP32_DIR, 'src', 'config.h'), configContent);

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

    const pio = spawn(pioBin, ['run', '-e', 'esp32s3-photopainter'], {
        cwd: ESP32_DIR,
        env: { ...process.env, CI:'1', PLATFORMIO_DISABLE_AUTO_CHECK_UPDATES:'1' },
        shell: process.platform === 'win32',
    });

    pio.stdout.on('data', d => send('log', d.toString()));
    pio.stderr.on('data', d => send('log', d.toString()));

    pio.on('error', err => {
        clearInterval(keepalive);
        buildInProgress = false;
        send('error', `Cannot start PlatformIO: ${err.message}\n\nInstall with: pip install platformio`);
        res.end();
    });

    pio.on('close', (code, signal) => {
        clearInterval(keepalive);
        buildInProgress = false;
        if (code !== 0) {
            send('error', `Build failed (${signal ? 'killed by signal ' + signal : 'exit code ' + code})`);
            res.end();
            return;
        }
        try {
            const buildDir = path.join(ESP32_DIR, '.pio', 'build', 'esp32s3-photopainter');
            fs.mkdirSync(FIRMWARE_DIR, { recursive: true });
            for (const f of ['bootloader.bin', 'partitions.bin', 'firmware.bin'])
                fs.copyFileSync(path.join(buildDir, f), path.join(FIRMWARE_DIR, f));
            const boot0 = findBoot0();
            if (boot0) fs.copyFileSync(boot0, path.join(FIRMWARE_DIR, 'boot_app0.bin'));
            else send('log', '⚠ boot_app0.bin not found — flash may require a full erase\n');
            const manifest = {
                name: 'PhotoDock Firmware',
                version: '1.0.0',
                builds: [{ chipFamily: 'ESP32-S3', parts: [
                    { path: '/firmware/bootloader.bin', offset: 0 },
                    { path: '/firmware/partitions.bin', offset: 32768 },
                    { path: '/firmware/boot_app0.bin',  offset: 57344 },
                    { path: '/firmware/firmware.bin',   offset: 65536 },
                ]}],
            };
            fs.writeFileSync(path.join(FIRMWARE_DIR, 'manifest.json'), JSON.stringify(manifest, null, 2));
            send('done', 'Build succeeded — firmware is ready to flash');
        } catch (e) {
            send('error', `Post-build copy failed: ${e.message}`);
        }
        res.end();
    });
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
const DEFAULT_SETTINGS = { timezone: 'Europe/Amsterdam', showDayName: true, showDate: true, showTime: true, showSeconds: false, accentColor: '#06b6d4', slideshowInterval: 30, imageWidth: 1920, imageHeight: 1080, datePosition: 'top-right', userInactivityDays: 0, apiKeyInactivityDays: 0, logRetentionDays: 30, maxLoginAttempts: 5 };

app.get('/api/settings', (_req, res) => res.json(Object.assign({}, DEFAULT_SETTINGS, appData.settings || {})));

app.put('/api/settings', requireAdmin, (req, res) => {
    const { timezone, showDayName, showDate, showTime, showSeconds, accentColor, slideshowInterval, imageWidth, imageHeight, datePosition, userInactivityDays, apiKeyInactivityDays, logRetentionDays, maxLoginAttempts } = req.body;
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
    appData.settings = { timezone, showDayName: !!showDayName, showDate: !!showDate, showTime: !!showTime, showSeconds: !!showSeconds, accentColor: accentColor || DEFAULT_SETTINGS.accentColor, slideshowInterval: interval, imageWidth: w, imageHeight: h, datePosition: pos, userInactivityDays: userDays, apiKeyInactivityDays: keyDays, logRetentionDays: retentionDays, maxLoginAttempts: maxAttempts };
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

// ── Device ping ────────────────────────────────────────────────────────────
// Firmware calls this on every wake cycle to report its current health.
// batt: 0-100, wifi: 0-4 (RSSI buckets), fw: firmware version string, status: string
app.post('/api/devices/ping', requireApiKey, (req, res) => {
    const keyRecord = req.apiKey;
    const screenId  = keyRecord.screenId || null;
    const { batt, wifi, fw, status } = req.body || {};

    const battNum  = Number(batt);
    const wifiNum  = Number(wifi);
    const level    = battNum <= 15 ? 'bad' : battNum <= 30 ? 'warn' : 'good';
    const wlabels  = ['No signal', 'Weak', 'Fair', 'Good', 'Excellent'];
    const wlabel   = wlabels[Math.min(Math.max(Math.round(wifiNum), 0), 4)] || 'Unknown';

    if (!appData.deviceStates) appData.deviceStates = {};
    appData.deviceStates[keyRecord.id] = {
        keyId:    keyRecord.id,
        screenId,
        batt:     isNaN(battNum) ? null : battNum,
        wifi:     isNaN(wifiNum) ? null : wifiNum,
        level,
        wlabel,
        fw:       fw || null,
        status:   status || 'online',
        lastSeen: new Date().toISOString(),
    };
    saveData(appData);

    // Return next image info so the device can immediately decide what to show
    const files    = getScreenFiles(keyRecord);
    const interval = (keyRecord.intervalMinutes || 5) * 60 * 1000;
    const slot     = Math.floor(Date.now() / interval);
    const filename = files.length ? files[slot % files.length] : null;
    const baseUrl  = `${req.protocol}://${req.get('host')}`;
    res.json({
        ok: true,
        imageUrl:         filename ? `${baseUrl}/uploads/${filename}` : null,
        intervalMinutes:  keyRecord.intervalMinutes || 5,
    });
});

app.get('/api/slideshow/current', requireApiKey, requireEndpoint('current'), (req, res) => {
    const keyRecord  = appData.apiKeys.find(k => k.key === (req.headers['x-api-key'] || req.query.key));
    const intervalMs = (keyRecord?.intervalMinutes || 5) * 60 * 1000;
    const files      = getScreenFiles(keyRecord);
    if (files.length === 0) return res.status(404).json({ error: 'No images available' });
    const slot     = Math.floor(Date.now() / intervalMs);
    const index    = slot % files.length;
    const filename = files[index];
    const nextSlot = (slot + 1) * intervalMs;
    const baseUrl  = `${req.protocol}://${req.get('host')}`;
    res.json({ index, total: files.length, filename, url: `${baseUrl}/uploads/${filename}`, interval_minutes: keyRecord?.intervalMinutes || 5, next_at: new Date(nextSlot).toISOString(), next_in_ms: nextSlot - Date.now() });
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
    empty:    { accent: '#3b82f6', title: 'No photos yet',        sub: 'Add photos to this screen in Photo Display', icon: 'frame' },
    paired:   { accent: '#34d399', title: "You're all set",       sub: 'Device paired successfully',                 icon: 'check' },
    low_batt: { accent: '#f59e0b', title: 'Battery low',          sub: 'Please connect the charger',                 icon: 'batt'  },
    sleeping: { accent: '#3b82f6', title: 'Sleeping',             sub: 'Waiting for the next refresh',               icon: 'moon'  },
    updating: { accent: '#22d3ee', title: 'Updating firmware',    sub: 'Please do not unplug the device',            icon: 'spin'  },
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
      + `<text x="64" y="456" font-family="sans-serif" font-size="16" font-weight="600" fill="#fff">PhotoPainter</text>`
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
    const slot     = Math.floor(Date.now() / intervalMs);
    const filename = files[slot % files.length];
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
    try {
        const pipeline = sharp(filepath)
            .rotate(rotation, { background: { r: 0, g: 0, b: 0 } })   // user-chosen orientation
            .resize(imgW, imgH, { fit: 'contain', background: { r: 0, g: 0, b: 0 } });

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

// ── ESP32 firmware build (admin only, SSE stream) ─────────────────────────
let buildInProgress = false;

function escCStr(s) {
    return String(s).replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

// Resolve the pio executable — checks PlatformIO's default venv, Python Scripts dirs, then PATH
function findPio() {
    const home = process.env.USERPROFILE || process.env.HOME || '';
    if (process.platform === 'win32') {
        const candidates = [
            path.join(home, '.platformio', 'penv', 'Scripts', 'pio.exe'),
        ];
        // Also search Python install dirs for pip-installed pio
        const pythonRoots = ['C:\\Python314', 'C:\\Python313', 'C:\\Python312', 'C:\\Python311', 'C:\\Python310',
            path.join(home, 'AppData', 'Local', 'Programs', 'Python', 'Python314'),
            path.join(home, 'AppData', 'Local', 'Programs', 'Python', 'Python313'),
            path.join(home, 'AppData', 'Local', 'Programs', 'Python', 'Python312'),
        ];
        for (const r of pythonRoots) candidates.push(path.join(r, 'Scripts', 'pio.exe'));
        // User install location (pip install --user, or non-writable system site-packages)
        const appData = process.env.APPDATA || path.join(home, 'AppData', 'Roaming');
        for (const ver of ['Python314', 'Python313', 'Python312', 'Python311', 'Python310'])
            candidates.push(path.join(appData, 'Python', ver, 'Scripts', 'pio.exe'));
        for (const p of candidates) { if (fs.existsSync(p)) return p; }
    } else {
        const candidates = [
            path.join(home, '.platformio', 'penv', 'bin', 'pio'),
            '/usr/local/bin/pio',
            '/usr/bin/pio',
        ];
        for (const p of candidates) { if (fs.existsSync(p)) return p; }
    }
    return 'pio'; // rely on PATH as last resort
}

// Find boot_app0.bin inside ~/.platformio/packages (cross-platform)
function findBoot0() {
    const home = process.env.USERPROFILE || process.env.HOME || '';
    const pkgsDir = path.join(home, '.platformio', 'packages');
    try {
        for (const pkg of fs.readdirSync(pkgsDir)) {
            if (!pkg.startsWith('framework-arduino')) continue;
            const candidate = path.join(pkgsDir, pkg, 'tools', 'partitions', 'boot_app0.bin');
            if (fs.existsSync(candidate)) return candidate;
        }
    } catch {}
    // Docker / Linux fallback
    if (process.platform !== 'win32') {
        try {
            const p = execSync('find /root/.platformio -name boot_app0.bin 2>/dev/null | head -1').toString().trim();
            if (p) return p;
        } catch {}
    }
    return null;
}

// Firmware status — lets the UI know if a binary is ready to flash
app.get('/api/admin/firmware/status', requireAdmin, (_req, res) => {
    const manifest = path.join(FIRMWARE_DIR, 'manifest.json');
    const firmware  = path.join(FIRMWARE_DIR, 'firmware.bin');
    const ready     = fs.existsSync(manifest) && fs.existsSync(firmware);
    let builtAt     = null;
    if (ready) { try { builtAt = fs.statSync(firmware).mtime.toISOString(); } catch {} }
    res.json({ ready, builtAt });
});

app.post('/api/admin/firmware/build', requireAdmin, (req, res) => {
    if (buildInProgress) return res.status(409).json({ error: 'A build is already in progress' });

    const {
        wifi_ssid = '', wifi_password = '',
        server_host = '', server_port = 8080,
        api_key = '',
    } = req.body || {};

    const esc = s => String(s).replace(/\\/g, '\\\\').replace(/"/g, '\\"');
    const configContent = [
        '#pragma once',
        '#define DEFAULT_SLEEP_S         (5 * 60)',
        '#define BATTERY_ADC_PIN         4',
        '#define BATTERY_DIVIDER_RATIO   2.0f',
        '#define JPEG_BUF_SIZE           (512 * 1024)',
        `#define DEFAULT_WIFI_SSID       "${esc(wifi_ssid)}"`,
        `#define DEFAULT_WIFI_PASS       "${esc(wifi_password)}"`,
        `#define DEFAULT_SERVER_HOST     "${esc(server_host)}"`,
        `#define DEFAULT_SERVER_PORT     ${parseInt(server_port) || 8080}`,
        `#define DEFAULT_API_KEY         "${esc(api_key)}"`,
    ].join('\n') + '\n';
    fs.writeFileSync(path.join(ESP32_DIR, 'src', 'config.h'), configContent);

    // Check PlatformIO is available BEFORE opening the SSE stream (avoids blocking after headers sent)
    const pioBin = findPio();
    const pioOk = pioBin !== 'pio'
        ? fs.existsSync(pioBin)   // full path — already checked by findPio, but be explicit
        : (() => { try { execSync(process.platform === 'win32' ? 'where pio' : 'which pio', { stdio: 'ignore', timeout: 3000 }); return true; } catch { return false; } })();

    if (!pioOk) {
        return res.status(500).json({
            error: `PlatformIO not found (looked for: ${pioBin}). Install with: pip install platformio, then restart the server.`
        });
    }

    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.socket?.setTimeout(0); // disable socket timeout for long-running SSE
    res.flushHeaders();

    const send = (type, data) => { try { res.write(`data: ${JSON.stringify({ type, data })}\n\n`); } catch {} };

    buildInProgress = true;
    send('log', `▶ PlatformIO: ${pioBin}\n▶ Starting build…\n`);

    // Keep SSE connection alive during quiet phases (toolchain downloads etc.)
    const keepalive = setInterval(() => { try { res.write(': ping\n\n'); } catch {} }, 15000);

    const pio = spawn(pioBin, ['run', '-e', 'esp32s3-photopainter'], {
        cwd: ESP32_DIR,
        env: {
            ...process.env,
            CI: '1',                                  // non-interactive mode, skip consent prompts
            PLATFORMIO_DISABLE_AUTO_CHECK_UPDATES: '1',
        },
        shell: process.platform === 'win32',
    });

    pio.stdout.on('data', d => send('log', d.toString()));
    pio.stderr.on('data', d => send('log', d.toString()));

    pio.on('error', err => {
        clearInterval(keepalive);
        buildInProgress = false;
        send('error',
            `Cannot start PlatformIO: ${err.message}\n\n` +
            `Install PlatformIO CLI:\n  pip install platformio\n\nThen restart the server.`
        );
        res.end();
    });

    let pioClosed = false;
    pio.on('close', (code, signal) => {
        pioClosed = true;
        clearInterval(keepalive);
        buildInProgress = false;
        if (code !== 0) {
            const reason = signal ? `killed by signal ${signal}` : `exit code ${code}`;
            send('error', `Build failed (${reason})`);
            res.end();
            return;
        }
        try {
            const buildDir = path.join(ESP32_DIR, '.pio', 'build', 'esp32s3-photopainter');
            fs.mkdirSync(FIRMWARE_DIR, { recursive: true });
            for (const f of ['bootloader.bin', 'partitions.bin', 'firmware.bin'])
                fs.copyFileSync(path.join(buildDir, f), path.join(FIRMWARE_DIR, f));

            // Locate boot_app0.bin from PlatformIO packages directory
            const boot0 = findBoot0();
            if (boot0) fs.copyFileSync(boot0, path.join(FIRMWARE_DIR, 'boot_app0.bin'));
            else send('log', '⚠ boot_app0.bin not found — flash may fail if this is the first build\n');

            const manifest = {
                name: 'Photo Display – ESP32-S3-PhotoPainter',
                version: appVersion,
                builds: [{ chipFamily: 'ESP32-S3', parts: [
                    { path: '/firmware/bootloader.bin', offset: 0 },
                    { path: '/firmware/partitions.bin', offset: 32768 },
                    { path: '/firmware/boot_app0.bin',  offset: 57344 },
                    { path: '/firmware/firmware.bin',   offset: 65536 },
                ]}],
            };
            fs.writeFileSync(path.join(FIRMWARE_DIR, 'manifest.json'), JSON.stringify(manifest, null, 2));

            // Persist flash config to the matching API key record
            if (api_key) {
                const keyRecord = appData.apiKeys.find(k => k.key === api_key);
                if (keyRecord) {
                    keyRecord.lastFlash = {
                        mode:       wifi_ssid ? 'auto' : 'manual',
                        wifiSsid:   wifi_ssid   || null,
                        serverHost: server_host || null,
                        serverPort: parseInt(server_port) || 8080,
                        builtAt:    new Date().toISOString(),
                    };
                    saveData(appData);
                }
            }

            send('done', 'Build succeeded — ready to flash');
        } catch (e) {
            send('error', `Post-build copy failed: ${e.message}`);
        }
        res.end();
    });

});

// Serve built firmware files for esp-web-tools
app.use('/firmware', express.static(FIRMWARE_DIR));

// ── Static files ───────────────────────────────────────────────────────────
app.use(express.static(FRONTEND_DIR));
app.use('/uploads', express.static(UPLOADS_DIR));

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
        }));
    if (screenId !== undefined) {
        const filterVal = screenId === '' ? null : screenId;
        files = files.filter(f => f.screenId === filterVal);
    }
    if (albumId !== undefined) {
        const filterVal = albumId === '' ? null : albumId;
        files = files.filter(f => f.albumId === filterVal);
    }
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
    res.json(user?.favorites || []);
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
    const { battery_mv, wifi_rssi, firmware_version, device_id } = req.body || {};
    if (!appData.deviceStatus) appData.deviceStatus = {};
    const id = device_id || key.id;
    appData.deviceStatus[id] = {
        deviceId:        id,
        apiKeyId:        key.id,
        apiKeyName:      key.name,
        screenId:        key.screenId || null,
        intervalMinutes: key.intervalMinutes || 5,
        batteryMv:       battery_mv   != null ? Number(battery_mv)  : null,
        wifiRssi:        wifi_rssi    != null ? Number(wifi_rssi)   : null,
        fwVersion:       firmware_version || null,
        lastSeen:        new Date().toISOString(),
    };
    saveData(appData);
    res.json({ ok: true });
});

// Firmware OTA: tell the device the version (content hash) of the binary the
// server currently has, so it can decide whether to update. Cached by mtime.
let _fwCache = { mtimeMs: 0, version: null, size: 0 };
function currentFirmwareInfo() {
    const bin = path.join(FIRMWARE_DIR, 'firmware.bin');
    if (!fs.existsSync(bin)) return null;
    const st = fs.statSync(bin);
    if (st.mtimeMs !== _fwCache.mtimeMs) {
        const hash = crypto.createHash('md5').update(fs.readFileSync(bin)).digest('hex').slice(0, 16);
        _fwCache = { mtimeMs: st.mtimeMs, version: hash, size: st.size };
    }
    return _fwCache;
}

app.get('/api/device/firmware', requireApiKey, (req, res) => {
    const info = currentFirmwareInfo();
    if (!info) return res.status(404).json({ error: 'No firmware available' });
    const key     = req.apiKey;
    const current = req.query.current || '';
    // Only instruct an update when the user opted in: a one-shot "Update now"
    // request, or auto-update enabled for this device. Never on its own.
    let should = false;
    if (current && current !== info.version) {
        if (key.updatePending) { should = true; key.updatePending = false; saveData(appData); }
        else if (key.autoUpdate) should = true;
    }
    const baseUrl = `${req.protocol}://${req.get('host')}`;
    res.json({ version: info.version, size: info.size, update: should ? 'yes' : 'no',
               url: `${baseUrl}/firmware/firmware.bin` });
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

// Admin: read a device's recent logs (optionally filter by apiKeyId or deviceId).
app.get('/api/admin/device-logs', requireAdmin, (req, res) => {
    const logs = appData.deviceLogs || {};
    const { deviceId, apiKeyId } = req.query;
    let list = Object.values(logs);
    if (deviceId) list = list.filter(l => l.deviceId === deviceId);
    if (apiKeyId) list = list.filter(l => l.apiKeyId === apiKeyId);
    // Newest entries first within each device.
    list = list.map(l => ({ ...l, entries: [...l.entries].reverse() }));
    res.json(list);
});

app.delete('/api/admin/device-logs/:deviceId', requireAdmin, (req, res) => {
    if (appData.deviceLogs) delete appData.deviceLogs[req.params.deviceId];
    saveData(appData);
    res.json({ ok: true });
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
        res.json({ ssids });
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

app.get('/api/screens', (_req, res) => {
    const meta     = appData.imageMetadata || {};
    const states   = appData.deviceStates  || {};   // legacy /api/devices/ping store
    const statuses = appData.deviceStatus  || {};    // what the firmware posts
    const now      = Date.now();

    const screens = (appData.screens || []).map(s => {
        // Find the API key tied to this screen, then its most recent check-in
        // from either device store (firmware uses deviceStatus).
        const linkedKey = (appData.apiKeys || []).find(k => k.screenId === s.id);
        let deviceInfo  = null;
        if (linkedKey) {
            const fw  = Object.values(statuses).find(d => d.apiKeyId === linkedKey.id);
            const leg = states[linkedKey.id];
            // Prefer the most recently seen of the two sources.
            const src = [fw, leg].filter(Boolean)
                .sort((a, b) => new Date(b.lastSeen) - new Date(a.lastSeen))[0];
            if (src) {
                const ageMs = now - new Date(src.lastSeen).getTime();
                const status = ageMs < 15 * 60 * 1000 ? 'online'
                             : ageMs < 24 * 60 * 60 * 1000 ? 'recent'
                             : 'offline';
                const statusLabel = status === 'online' ? 'Online'
                                  : status === 'recent' ? 'Recently seen'
                                  : 'Offline';
                // Normalize fields from whichever store we used.
                const batt = src.batt ?? battMvToPercent(src.batteryMv);
                const w    = src.wifi != null ? { bars: src.wifi, label: src.wlabel || '' }
                                              : rssiToBars(src.wifiRssi);
                deviceInfo = {
                    id:          linkedKey.label || linkedKey.id,
                    batt:        batt ?? null,
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
            autoUpdate:  linkedKey?.autoUpdate || false,
            updatePending: linkedKey?.updatePending || false,
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
    saveData(appData);
    res.json(screen);
});

app.put('/api/screens/:id', (req, res) => {
    const screen = (appData.screens || []).find(s => s.id === req.params.id);
    if (!screen) return res.status(404).json({ error: 'Screen not found' });
    const { name, description, color, intervalMinutes, autoUpdate, rotation } = req.body;
    if (name !== undefined) screen.name = name.trim();
    if (description !== undefined) screen.description = description.trim();
    if (color !== undefined) screen.color = color;
    // Rotation (0/90/180/270) — applied server-side to the image sent to the device.
    if (rotation !== undefined) {
        const allowed = [0, 90, 180, 270];
        const rot = allowed.includes(Number(rotation)) ? Number(rotation) : 0;
        for (const k of (appData.apiKeys || [])) {
            if (k.screenId === screen.id) k.rotation = rot;
        }
        screen.rotation = rot;
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
    // Delete the device(s) tied to this screen — the API key, its live status,
    // and its albums. Uploaded images stay in the library, just unassigned.
    const removedKeyIds = (appData.apiKeys || []).filter(k => k.screenId === screenId).map(k => k.id);
    if (removedKeyIds.length) {
        appData.apiKeys = appData.apiKeys.filter(k => k.screenId !== screenId);
        // Clear both live-status maps: deviceStates is keyed by key id,
        // deviceStatus is keyed by device id with an apiKeyId field.
        for (const keyId of removedKeyIds) delete (appData.deviceStates || {})[keyId];
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

app.delete('/api/screens/:screenId/albums/:albumId', requireAdmin, (req, res) => {
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
    if (!appData.imageMetadata) appData.imageMetadata = {};
    if (!appData.imageMetadata[filename]) appData.imageMetadata[filename] = {};
    appData.imageMetadata[filename].screenId = screenId || null;
    saveData(appData);
    res.json({ ok: true });
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
