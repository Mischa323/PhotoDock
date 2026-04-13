# Photo Display for TNMLS

A self-hosted image slideshow server. Upload photos through a web browser, display them as a fullscreen slideshow, and pull the current image from any external device using an API key.

---

## What it does

- **Upload images** via drag & drop in the browser
- **Fullscreen slideshow** that rotates images on a configurable timer
- **External API** so a terminal, TV, or script can fetch the current image on a schedule
- **Admin panel** to manage users, roles, API keys, and display settings
- **Dark and light mode** — toggle in the admin panel, persists per browser
- **HTTPS always on** — a self-signed certificate is generated automatically on first start; replace it with your own for a trusted certificate
- **Auto-updates** via Watchtower — if you already run Watchtower, it will pick up new releases automatically

---

## How it works

```
Browser / Client
      │
      ▼
   Node.js / Express (port 8080)
   ├── Serves the web frontend (HTML/CSS/JS)
   ├── Handles image uploads (stored in /data/uploads)
   ├── Manages users, roles, API keys (stored in /data/data.json)
   └── Exposes slideshow API for external devices
```

HTTPS runs on port 8081. On first start, if no certificate files exist at `data/ssl/cert.pem` and `data/ssl/key.pem`, a self-signed certificate is generated automatically. Replace those files with a real certificate to avoid browser warnings.

GitHub Actions builds and publishes a new Docker image to `ghcr.io` on every tagged release. If you already run [Watchtower](https://containrrr.dev/watchtower/) on your server, it will detect the new image and restart the container automatically. Watchtower is **not** included in `docker-compose.yml` — it is expected to run separately and watch all containers on the host.

---

## Installation

### Requirements

- A server with Docker installed
- Port **8080** open on your server/firewall (or whichever port you choose)

---

### Option A — Command line

**1. Install Docker**
```bash
curl -fsSL https://get.docker.com | sh
```

**2. Clone the repository**
```bash
git clone https://github.com/Mischa323/Terminal-Photo-Display.git
cd Terminal-Photo-Display
```

**3. Configure environment (optional)**
```bash
cp .env.example .env
nano .env
```

The defaults work out of the box. You only need to edit `.env` if you want a different port:
```
PORT=8080
HTTPS_PORT=8081
```

**4. Start the container**
```bash
docker compose up -d
```

**5. Open your browser**

Go to `http://your-server-ip:8080` — you will be redirected to the first-run setup page to create your admin account.

---

### Option B — Portainer

If you manage your server with [Portainer](https://www.portainer.io/), you can deploy the stack directly through its web UI without using a terminal.

**1. Install Portainer** (skip if already installed)
```bash
docker volume create portainer_data
docker run -d -p 8000:8000 -p 9443:9443 --name portainer --restart=always \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v portainer_data:/data \
  portainer/portainer-ce:latest
```
Open `https://your-server-ip:9443` and create your Portainer admin account.

**2. Download the project files**

On your server, clone the repository so the `data/` folder is available:
```bash
git clone https://github.com/Mischa323/Terminal-Photo-Display.git
cd Terminal-Photo-Display
```

**3. Deploy the stack in Portainer**

1. In Portainer, go to **Stacks → Add stack**
2. Give it a name (e.g. `photo-display`)
3. Select **Upload** and upload the `docker-compose.yml` file from the cloned folder  
   — or select **Repository** and point it at `https://github.com/Mischa323/Terminal-Photo-Display`
4. Under **Environment variables**, add (optional):
   - `PORT` = `8080`
   - `HTTPS_PORT` = `8081`
5. Click **Deploy the stack**

Portainer will pull the image and start the container.

**4. Open your browser**

Go to `http://your-server-ip:8080` — you will see the first-run setup page to create your admin account.

---

### Optional: Use your own HTTPS certificate

HTTPS is always active on port 8081. On first start the app generates a self-signed certificate at `data/ssl/cert.pem` / `data/ssl/key.pem`. Browsers will show a security warning for self-signed certs.

To use a trusted certificate, replace those two files and restart the container:

```
data/ssl/cert.pem   ← your certificate (or full chain)
data/ssl/key.pem    ← your private key
```

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
├── docker-compose.yml — Runs the app container
├── changelog.json     — Version history shown in the admin portal
├── .env.example       — Example environment variables
└── data/              — Persistent data (created automatically)
    ├── data.json      — Users, roles, API keys, tokens, settings
    ├── uploads/       — Uploaded images
    └── ssl/           — Optional: cert.pem and key.pem for HTTPS
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
Manage your email address and two-factor authentication (2FA). Choose between:
- **Authenticator app** — time-based codes via Google Authenticator, Authy, etc.
- **Email code** — a 6-digit code sent to your email at each login

Admins can reset 2FA for other users if they lose their device.

### Email
Configure how the app sends emails (required for email 2FA and notifications). Supports:
- **SMTP** — works with Gmail, Outlook, and most mail providers
- **Microsoft Graph API** — for Microsoft 365 / Exchange Online using app credentials

### Display Settings
Configure the slideshow behaviour and date/time overlay:
- **Slideshow interval** — seconds between each image (applies to all viewers)
- Timezone (any IANA timezone, e.g. `Europe/Amsterdam`)
- Show/hide day name, date, time, seconds
- Accent colour — theme colour applied across all pages

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
http://your-server-ip:8080/api/slideshow/current?key=YOUR_KEY
```

### Endpoints

#### `GET /api/slideshow/current`
Returns the image that should be displayed right now, based on the key's interval setting.

```json
{
  "index": 2,
  "total": 10,
  "filename": "photo-1712345678.jpg",
  "url": "http://your-server-ip:8080/uploads/photo-1712345678.jpg",
  "interval_minutes": 5,
  "next_at": "2026-04-12T11:05:00.000Z",
  "next_in_ms": 42000
}
```

#### `GET /api/slideshow/all`
Returns all uploaded images.

```json
[
  { "index": 0, "filename": "cat.jpg", "url": "http://your-server-ip:8080/uploads/cat.jpg" },
  { "index": 1, "filename": "dog.jpg", "url": "http://your-server-ip:8080/uploads/dog.jpg" }
]
```

### Example (curl)
```bash
curl -H "x-api-key: YOUR_KEY" http://your-server-ip:8080/api/slideshow/current
```

---

## Releases and versioning

The version shown in the admin portal matches the GitHub release tag.

**To create a new release:**
```bash
git tag v1.12.0
git push origin v1.12.0
```

Or go to **GitHub → Releases → Create a new release**.

GitHub Actions will build a Docker image tagged `v1.12.0` and `latest`.

---

## Useful Docker commands

```bash
# View live logs
docker compose logs -f

# Stop the container
docker compose down

# Manually force an update
docker compose pull && docker compose up -d

# Restart the app
docker compose restart image-upload
```

---

## Security notes

- Passwords are hashed with **scrypt** (Node.js built-in crypto)
- Login is rate-limited to **10 attempts per IP per 15 minutes**
- Login tokens are stored in `data.json` with a **30-day expiry**
- TOTP two-factor authentication uses **HMAC-SHA1** (RFC 6238 standard)
- Email 2FA sends a 6-digit one-time code with a 5-minute expiry
- Optional HTTPS is enabled by placing your own certificate files in `data/ssl/`
