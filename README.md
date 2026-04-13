# Terminal Photo Display

A lightweight self-hosted photo slideshow server designed for terminals, dashboards, and e-ink displays like **TRMNL**.

It provides a simple web interface to upload images and an API endpoint to serve a rotating slideshow image.

---

## ✨ Features

* 📸 Upload and manage photos via web UI
* 🔁 Automatic slideshow rotation
* 🔑 API keys with configurable refresh intervals
* 🖼️ Configurable image output size
* 🌐 Simple REST API for external displays
* ⚡ Lightweight and easy to deploy

---

## 🚀 Getting Started

### 1. Clone the Repository

```bash
git clone https://github.com/Mischa323/Terminal-Photo-Display.git
cd Terminal-Photo-Display
```

---

### 2. Install Dependencies

```bash
npm install
```

---

### 3. Start the Server

```bash
npm start
```

By default:

* HTTP: `http://localhost:8080`
* HTTPS: `https://localhost:8081` (self-signed certificate)

---

### 4. First-Time Setup

1. Open the web interface
2. Create your admin account
3. Log in to access the dashboard

---

## 📸 Uploading Images

* Navigate to the web UI
* Upload your photos
* Images will automatically be included in the slideshow

---

## 🔑 API Keys

API keys are used to access slideshow endpoints.

### Create an API Key

* Go to the admin panel
* Generate a new API key
* Set a **slideshow interval (minutes)**

👉 Each API key maintains its own slideshow timing.

---

## 🖼️ API Endpoints

### Get Current Slideshow Image

```
GET /api/slideshow/image
```

#### Authentication

You can pass the API key in two ways:

**Query parameter (recommended for TRMNL):**

```
/api/slideshow/image?key=YOUR_API_KEY
```

**Header:**

```
x-api-key: YOUR_API_KEY
```

---

### Response

* Returns a **JPEG image**
* Sized according to your configured API image dimensions
* Automatically rotates based on API key interval

---

## ⚙️ Display Settings

In the web UI, configure:

* API image width & height
* Recommended for TRMNL: **800 × 480**

---

## 🧠 How the Slideshow Works

* Each API key has its own timer
* When the interval expires, the next image is selected
* The `/api/slideshow/image` endpoint always returns the *current* image

---

# 🖥️ TRMNL Integration Guide

This project works perfectly with the **TRMNL Image Display plugin**.

## 📌 Step-by-Step Setup

### 1. Make Your Server Public

TRMNL must be able to access your server.

Options:

* Port forward your server
* Use a reverse proxy (Nginx, Caddy)
* Use a tunnel (Cloudflare Tunnel recommended)

---

### 2. Use the Slideshow Endpoint

Your image URL should look like:

```
https://your-domain.com/api/slideshow/image?key=YOUR_API_KEY
```

---

### 3. Configure TRMNL

On your TRMNL dashboard:

* Go to **Plugins → Image Display**
* Paste your image URL
* Save

---

### 4. Set Refresh Interval

Match TRMNL refresh with your API key interval:

Example:

| Setting          | Value         |
| ---------------- | ------------- |
| API Key Interval | 10 minutes    |
| TRMNL Refresh    | 10–15 minutes |

---

## ⚠️ Important Notes

### 🔄 Image Refresh Behavior

TRMNL detects updates using caching headers (`ETag`, `Last-Modified`).

This API currently:

* Returns `Cache-Control: no-cache`
* Does **not** include ETag/Last-Modified

👉 Result:
TRMNL *may not always detect image changes instantly*

### ✅ Recommended Fix (Optional)

If you experience issues:

* Add a reverse proxy that injects cache headers
* OR modify the server to include `ETag` support

---

### 🔒 HTTPS Recommended

* Replace self-signed certificates with real ones (Let's Encrypt)
* Prevents fetch issues from TRMNL

---

### 🌍 Local Servers Won’t Work

TRMNL cannot access:

```
http://192.168.x.x
http://localhost
```

You **must expose your server publicly**

---

## 🧩 Alternative: Screenshot Plugin

If you need headers instead of query params:

* Use TRMNL **Screenshot Plugin**
* Add header:

  ```
  x-api-key: YOUR_API_KEY
  ```

---

## 🛠️ Troubleshooting

### Image Not Updating

* Check API key interval
* Check TRMNL refresh interval
* Try adding a cache-busting query:

  ```
  ?key=YOUR_API_KEY&t=timestamp
  ```

---

### Cannot Load Image

* Verify public URL works in browser
* Ensure HTTPS is valid
* Check firewall / port forwarding

---

## 📄 License

MIT License

---

## ❤️ Acknowledgements

Built for simple, self-hosted photo displays and e-ink dashboards like TRMNL.
