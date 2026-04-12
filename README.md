# Terminal Photo Display

A self-hosted image slideshow server. Upload photos through a web browser, display them as a fullscreen slideshow, and pull the current image from any external device using an API key.

---

## What it does

- **Upload images** via drag & drop in the browser
- **Fullscreen slideshow** that rotates images on a configurable timer
- **External API** so a terminal, TV, or script can fetch the current image on a schedule
- **Admin panel** to manage users, roles, API keys, and display settings
- **Automatic HTTPS** via Caddy with free Let's Encrypt certificates
- **Auto-updates** via Watchtower — push to GitHub and your server updates itself

---

## How it works

```
Browser / Client
      │
      ▼
   Caddy (reverse proxy)
   ├── Handles HTTPS (port 443)
   ├── Redirects HTTP → HTTPS (port 80)
   └── Forwards requests to the app
              │
              ▼
   Node.js / Express (internal port 8080)
   ├── Serves the web frontend (HTML/CSS/JS)
   ├── Handles image uploads (stored in /data/uploads)
   ├── Manages users, roles, API keys (stored in /data/data.json)
   └── Exposes slideshow API for external devices
```

### Auto-update flow

```
git push to main
      │
      ▼
GitHub Actions builds Docker image
      │
      ▼
Image pushed to ghcr.io (GitHub Container Registry)
      │
      ▼
Watchtower detects new image every 5 minutes
      │
      ▼
Container restarted with new image automatically
```

---

## Installation

### Requirements

- A server with Docker installed
- A domain name pointing to your server (for HTTPS)
- Ports **80** and **443** open on your server/firewall

### Steps

**1. Install Docker**
```bash
curl -fsSL https://get.docker.com | sh
```

**2. Clone the repository**
```bash
git clone https://github.com/Mischa323/Terminal-Photo-Display.git
cd Terminal-Photo-Display
```

**3. Configure your domain**
```bash
cp .env.example .env
nano .env
```

Set your domain:
```
DOMAIN=photos.yourdomain.com
PORT=8080
```

**4. Start everything**
```bash
docker compose up -d
```

Caddy will automatically request an SSL certificate on first start. This takes about 30 seconds.

**5. Open your browser**

Go to `https://photos.yourdomain.com` — you will be redirected to the first-run setup page to create your admin account.

---

## File structure

```
Terminal-Photo-Display/
├── server.js          — Express backend (all API routes and logic)
├── index.html         — Fullscreen slideshow frontend
├── admin.html         — Admin settings panel
├── login.html         — Login page
├── setup.html         — First-run account setup
├── 2fa.html           — Two-factor authentication step
├── Dockerfile         — Builds the Node.js app image
├── docker-compose.yml — Runs the app, Caddy, and Watchtower
├── Caddyfile          — Caddy reverse proxy config
├── changelog.json     — Version history shown in the admin portal
├── .env.example       — Example environment variables
└── data/              — Persistent data (created automatically)
    ├── data.json      — Users, roles, API keys, tokens, settings
    └── uploads/       — Uploaded images
```

---

## Data persistence

All data lives in the `./data` folder on the host machine (mounted into the container as a volume). This means:

- Images survive container restarts and updates
- User accounts, API keys, and settings are never lost
- To back up everything, copy the `./data` folder

---

## Pages

| Page | URL | Access |
|------|-----|--------|
| Slideshow | `/` | Login required |
| Settings / Admin | `/admin` | Admin role required |
| Login | `/login` | Public |
| First-run setup | `/setup` | Only shown when no users exist |
| 2FA verification | `/2fa` | Shown after login if 2FA is enabled |

---

## Admin panel

Accessible at `/admin`. Contains the following sections:

### My Security
Enable or disable **two-factor authentication (2FA)** for your account. Scans a QR code with an authenticator app (Google Authenticator, Authy, etc.). Admins can reset 2FA for other users if they lose their device.

### Domain & HTTPS
Change the domain name without editing any files. The server pushes the new config to Caddy live — no restart needed. Caddy then requests a new SSL certificate automatically.

### Display Settings
Configure what is shown in the date/time overlay on the slideshow:
- Timezone (any IANA timezone, e.g. `Europe/Amsterdam`)
- Show/hide day name, date, time, seconds

### Users
Create, edit, and delete user accounts. Assign roles. Password changes take effect immediately.

### Roles & Permissions
Create custom roles and toggle three permissions per role:
- **Upload images** — can add new images
- **Delete images** — can remove images
- **Manage settings** — can access the admin panel (users, roles, API keys, settings)

### API Keys
Generate API keys for external devices. Each key has a configurable **interval** (in minutes) that controls how often the current image changes when that key is used.

### API Reference
Live documentation showing the exact URLs and example responses for your server.

### Version
Shows the currently running version and the full changelog.

---

## API

All API endpoints require an API key. Pass it in one of two ways:

**Header:**
```
x-api-key: YOUR_KEY
```

**Query parameter:**
```
https://your-domain.com/api/slideshow/current?key=YOUR_KEY
```

### Endpoints

#### `GET /api/slideshow/current`
Returns the image that should be displayed right now, based on the key's interval setting.

```json
{
  "index": 2,
  "total": 10,
  "filename": "photo-1712345678.jpg",
  "url": "https://your-domain.com/uploads/photo-1712345678.jpg",
  "interval_minutes": 5,
  "next_at": "2026-04-12T11:05:00.000Z",
  "next_in_ms": 42000
}
```

#### `GET /api/slideshow/all`
Returns all uploaded images.

```json
[
  { "index": 0, "filename": "cat.jpg", "url": "https://your-domain.com/uploads/cat.jpg" },
  { "index": 1, "filename": "dog.jpg", "url": "https://your-domain.com/uploads/dog.jpg" }
]
```

### Example (curl)
```bash
curl -H "x-api-key: YOUR_KEY" https://your-domain.com/api/slideshow/current
```

---

## Releases and versioning

The version shown in the admin portal matches the GitHub release tag.

**To create a new release:**
```bash
git tag v1.8.0
git push origin v1.8.0
```

Or go to **GitHub → Releases → Create a new release**.

GitHub Actions will build a Docker image tagged `v1.8.0` and `latest`. Watchtower will pick it up within 5 minutes.

---

## Useful Docker commands

```bash
# View live logs
docker compose logs -f

# Stop everything
docker compose down

# Manually force an update
docker compose pull && docker compose up -d

# Restart just the app
docker compose restart image-upload
```

---

## Security notes

- Passwords are hashed with **scrypt** (Node.js built-in crypto)
- Login is rate-limited to **10 attempts per IP per 15 minutes**
- Login tokens are stored in `data.json` with a **30-day expiry**
- TOTP two-factor authentication uses **HMAC-SHA1** (RFC 6238 standard)
- The Caddy admin API (port 2019) is only accessible inside the Docker network — never exposed to the internet
- All traffic is encrypted via HTTPS; HTTP is automatically redirected
