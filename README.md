# PhotoDock

A self-hosted photo display system for **e-ink photo frames**. It pairs a Node/Express
backend + web dashboard with **ESP32-S3 e-ink firmware**, so you can push photos to
battery-powered displays over Wi-Fi, update them over the air, and manage everything
from one place. It also exposes a simple image API, so it doubles as an image source
for external displays like **TRMNL**.

> One codebase builds firmware for multiple boards (Waveshare PhotoPainter and Seeed
> reTerminal E1001), and the dashboard handles onboarding, pairing, OTA updates and
> per-screen settings.

---

## ✨ Features

**Dashboard & photos**
* Upload and manage photos through a web UI, organised into **screens** (named collections)
* Per-screen look: fit mode, brightness/saturation, sleep schedule, refresh interval
* Usage metrics, activity log, and per-screen **device logs**
* Users, roles, 2FA, and API-key management

**E-ink devices**
* Guided **setup wizard**: build + flash firmware right from the browser
* **QR-code pairing** links a device to a screen in seconds
* **Over-the-air updates** (opt-in per screen) with a **firmware version history you can roll back to**
* Multi-board: one firmware codebase, model-aware builds and OTA
* Add your own board by pointing at a GitHub firmware repo (admin-only)

**API & integrations**
* Simple REST API to serve a rotating slideshow image (works great with **TRMNL**)
* API keys with per-key refresh intervals and configurable output size

**Security**
* Firmware downloads are **API-key gated**
* Device Wi-Fi passwords are **encrypted at rest** (AES-256-GCM); `config.h` is wiped after each build
* Optional HTTPS with auto-generated self-signed certificates

---

## 🧩 Supported displays

| Board | Panel | Notes |
| ----- | ----- | ----- |
| **Waveshare 7.3″ PhotoPainter** | E6 Spectra-6 (6-colour), 800×480 | AXP2101 PMIC, battery |
| **Seeed reTerminal E1001** | UC8179 7.5″ monochrome, 800×480 | Floyd–Steinberg dithered photos |

You can also register a **custom device** in the dashboard (a GitHub firmware repo the
server clones and builds).

---

## 🚀 Quick start

### Option A — Docker (recommended)

The image is published to GitHub Container Registry on every release.

```bash
# docker-compose.yml already points at ghcr.io/mischa323/photodock:latest
docker compose up -d
```

* HTTP: `http://localhost:8080`
* HTTPS: `https://localhost:8081` (self-signed cert auto-generated at `data/ssl/`)

Data (database, uploads, SSL, encryption key) persists in the `./data` volume.

### Option B — Portainer (stack)

PhotoDock runs well as a Portainer **stack** using the published image.

1. **Registry (only if the image is private):** *Registries → Add registry → Custom*,
   set the URL to `ghcr.io` and authenticate with your GitHub username + a Personal
   Access Token that has `read:packages`. Skip this if the `photodock` package is public.
2. **Stacks → Add stack**, name it `photodock`, and paste this into the **web editor**:

   ```yaml
   services:
     photodock:
       image: ghcr.io/mischa323/photodock:latest
       ports:
         - "8080:8080"      # change the left number if the host port is taken
         - "8081:8081"
       volumes:
         - photodock-data:/data             # database, uploads, certs, encryption key
         - photodock-pio:/root/.platformio  # firmware-build cache (optional)
       # environment:
       #   PHOTODOCK_SECRET_KEY: "<64 hex chars>"  # optional: pin the at-rest key
       restart: unless-stopped

   volumes:
     photodock-data:
     photodock-pio:
   ```

3. **Deploy the stack**, then open `http://<host>:8080` and create your admin account.

The image already sets sensible defaults (`PORT`, `HTTPS_PORT`, `DATA_FILE`,
`UPLOADS_DIR`, SSL paths), so no environment variables are required.

**Updating:** open the stack → **Pull and redeploy** to move to the newest
`photodock:latest`. The `photodock-data` volume keeps your data, certificates and the
at-rest **encryption key** across updates — don't delete it.

### Option C — From source

```bash
git clone https://github.com/Mischa323/PhotoDock.git
cd PhotoDock
npm install
npm start
```

### First-time setup

1. Open the web interface
2. Create your admin account (email is required)
3. Log in to reach the dashboard

---

## 🖥️ Adding an e-ink device

From the dashboard, open **Set up a device** and follow the wizard:

1. **Create a screen** — the photos the device will show. An API key is created and
   applied automatically (no manual entry needed).
2. **Choose a setup mode:**
   * **Automatic** — enter your Wi-Fi + server details; the firmware is built with them
     baked in and flashed from the browser. The password is encrypted at rest on the
     server and never left in plaintext.
   * **Manual** — flash credential-free firmware, then configure the device through its
     own `PhotoDock-XXXX` Wi-Fi setup portal on first boot.
3. **Flash** — over USB, straight from the browser (Chrome/Edge, Web Serial).
4. **Pair** — the device shows a **QR code**; scan it (while logged in) and pick a screen.

### Updating firmware (OTA)

Open a screen and choose **Update now**, or enable **auto-update**. The device pulls only
its own model's firmware on its next wake. Every published build is archived, so you can
**revert** to a previous version from **Settings → Firmware source → Version history**.

---

## 🔌 Firmware (build / flash from source)

Firmware lives in [`esp32/`](esp32/) and builds with **PlatformIO**.

```bash
cd esp32
pio run -e esp32s3-photopainter      # Waveshare PhotoPainter (E6)
pio run -e reterminal-e1001          # Seeed reTerminal E1001
pio run -e reterminal-e1001 -t upload   # build + flash over USB
```

> `esp32/src/config.h` holds optional baked Wi-Fi/server credentials. Leave them empty
> to force the on-device setup portal. Builds with baked credentials are **not** published
> to the network-served `firmware_build/` folder.

---

## 🖼️ Public API

All endpoints require an API key, passed as `?key=YOUR_API_KEY` or an `x-api-key` header.

| Endpoint | Returns |
| -------- | ------- |
| `GET /api/slideshow/image` | The current image as a pre-rendered **JPEG**, sized to the key's configured dimensions (default 800×480 for e-ink) |
| `GET /api/slideshow/current` | The current image's metadata/URL |
| `GET /api/slideshow/all` | All images for the key's screen |

Each API key keeps its own slideshow timer; when its interval expires, the next image is
selected and `/api/slideshow/image` returns it.

```bash
curl -H "x-api-key: YOUR_API_KEY" https://your-server/api/slideshow/image --output frame.jpg
```

---

## 🖥️ TRMNL integration

PhotoDock works as an image source for the **TRMNL Image Display plugin**.

1. **Expose your server publicly** — TRMNL can't reach `localhost`/`192.168.x.x`. Use a
   tunnel (Cloudflare Tunnel), reverse proxy, or port-forward; valid HTTPS recommended.
2. Use the image URL: `https://your-domain.com/api/slideshow/image?key=YOUR_API_KEY`
3. In TRMNL: **Plugins → Image Display**, paste the URL, save.
4. Match the TRMNL refresh interval to your API key's interval (e.g. 10 min key ↔ 10–15 min refresh).

> The image API currently sends `Cache-Control: no-cache` without `ETag`/`Last-Modified`,
> so a caching proxy in front can help TRMNL detect changes reliably. The **Screenshot
> plugin** is an alternative if you prefer header auth (`x-api-key`).

---

## ⚙️ Configuration

Environment variables (see [`.env.example`](.env.example)):

| Variable | Default | Purpose |
| -------- | ------- | ------- |
| `PORT` | `8080` | HTTP port |
| `HTTPS_PORT` | `8081` | HTTPS port (active when a cert exists) |
| `DATA_FILE` | `data.json` | Database file location |
| `UPLOADS_DIR` | `uploads/` | Uploaded images |
| `SSL_CERT` / `SSL_KEY` | — | Paths to TLS cert/key (else self-signed) |
| `PHOTODOCK_SECRET_KEY` | auto-generated | 32-byte key (hex/base64) for encrypting secrets at rest. If unset, a random key is written to `secret.key` next to `DATA_FILE` |
| `APP_VERSION` | `package.json` version | Version shown in the dashboard |

> Keep the `data/` volume (Docker) or `secret.key` (source) — it holds the encryption key
> that decrypts stored Wi-Fi passwords. Set `PHOTODOCK_SECRET_KEY` to control it explicitly.

---

## 🗂️ Project layout

```
backend/      Node/Express server (API, dashboard backend, firmware build/serve)
frontend/     Web dashboard (screens, devices, admin, setup wizard)
esp32/        PlatformIO firmware (multi-board: board.h + per-board envs)
firmware_build/  Built, network-served firmware per model (git-ignored)
.github/workflows/docker.yml   Builds & pushes the ghcr.io image on push/tag
```

---

## 📄 License

MIT License
