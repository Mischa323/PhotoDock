#include <Arduino.h>
#include <WiFi.h>
#include <WebServer.h>
#include <DNSServer.h>
#include <HTTPClient.h>
#include <Preferences.h>
#include <SPI.h>
#include <esp_sleep.h>
#include <esp_mac.h>
#include "JPEGDEC.h"
#include "config.h"

// ── Pin mapping — Waveshare ESP32-S3-PhotoPainter ─────────────────────────
#define EPD_RST   8
#define EPD_DC    7
#define EPD_CS    10
#define EPD_BUSY  9
#define EPD_MOSI  11
#define EPD_CLK   12
#define EPD_PWR   45

// ── Display dimensions ────────────────────────────────────────────────────
#define EPD_W        800
#define EPD_H        480
#define EPD_BUF_SIZE (EPD_W * EPD_H / 2)

// ── ACeP 7-color palette ──────────────────────────────────────────────────
static const uint8_t PALETTE[7][3] = {
    {  0,   0,   0},   // 0 BLACK
    {255, 255, 255},   // 1 WHITE
    { 67, 138,  28},   // 2 GREEN
    {100,  64, 255},   // 3 BLUE
    {228,  28,  28},   // 4 RED
    {199, 199,  10},   // 5 YELLOW
    {248, 190,   0},   // 6 ORANGE
};

static uint8_t *epd_buf  = nullptr;
static uint8_t *jpeg_buf = nullptr;
static JPEGDEC  jpeg;

// ── Runtime config — stored in NVS, set via setup portal ─────────────────
struct Config {
    String wifiSsid;
    String wifiPassword;
    String serverHost;
    int    serverPort;
    String apiKey;
};

static Config cfg;

static Config loadConfig() {
    Preferences p;
    p.begin("photodisplay", true);
    Config c;
    c.wifiSsid     = p.getString("ssid", "");
    c.wifiPassword = p.getString("pass", "");
    c.serverHost   = p.getString("host", "");
    c.serverPort   = p.getInt   ("port", 8080);
    c.apiKey       = p.getString("key",  "");
    p.end();
    return c;
}

static void saveConfig(const Config &c) {
    Preferences p;
    p.begin("photodisplay", false);
    p.putString("ssid", c.wifiSsid);
    p.putString("pass", c.wifiPassword);
    p.putString("host", c.serverHost);
    p.putInt   ("port", c.serverPort);
    p.putString("key",  c.apiKey);
    p.end();
}

static bool configComplete(const Config &c) {
    return c.wifiSsid.length() > 0 &&
           c.serverHost.length() > 0 &&
           c.apiKey.length() > 0;
}

// ── Captive portal ────────────────────────────────────────────────────────
static WebServer apServer(80);
static DNSServer dnsServer;

static const char SETUP_HTML[] PROGMEM = R"html(<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Photo Display Setup</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:sans-serif;background:#ecfeff;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.card{background:#fff;border-radius:12px;padding:28px;width:100%;max-width:380px;box-shadow:0 4px 24px rgba(0,0,0,.1)}
h2{color:#0e7490;font-size:20px;margin-bottom:4px}
.sub{color:#888;font-size:13px;margin-bottom:20px}
label{display:block;font-size:12px;font-weight:600;color:#555;margin-bottom:4px;margin-top:14px}
input{width:100%;padding:9px 10px;border:1px solid #ddd;border-radius:6px;font-size:14px;font-family:inherit}
.hint{font-size:11px;color:#94a3b8;margin-top:3px}
button{width:100%;margin-top:20px;padding:12px;background:#06b6d4;color:#fff;border:none;border-radius:8px;font-size:15px;font-weight:700;cursor:pointer}
button:hover{background:#0891b2}
</style>
</head>
<body>
<div class="card">
  <h2>Photo Display</h2>
  <p class="sub">Connect this device to your network</p>
  <form method="POST" action="/save">
    <label>WiFi network name</label>
    <input type="text" name="ssid" placeholder="Your home WiFi" required>
    <label>WiFi password</label>
    <input type="password" name="pass" placeholder="Leave empty for open networks">
    <label>Server address</label>
    <input type="text" name="host" placeholder="192.168.1.100" required>
    <p class="hint">IP of the computer running Photo Display</p>
    <label>Server port</label>
    <input type="number" name="port" value="8080">
    <label>API key</label>
    <input type="text" name="key" placeholder="Paste your API key here" required>
    <button type="submit">Save &amp; Connect &#8594;</button>
  </form>
</div>
</body>
</html>)html";

static const char SAVED_HTML[] PROGMEM = R"html(<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Saved</title>
<style>
body{font-family:sans-serif;background:#ecfeff;display:flex;align-items:center;justify-content:center;min-height:100vh}
.card{background:#fff;border-radius:12px;padding:32px;text-align:center;box-shadow:0 4px 24px rgba(0,0,0,.1);max-width:340px}
h2{color:#22c55e;font-size:22px;margin-bottom:12px}p{color:#555;font-size:14px;line-height:1.6}
</style>
</head>
<body>
<div class="card"><h2>&#10003; Saved!</h2>
<p>The device is connecting to your WiFi.<br>This page will close shortly.</p>
</div>
</body>
</html>)html";

static void startCaptivePortal() {
    uint8_t mac[6]; esp_read_mac(mac, ESP_MAC_WIFI_STA);
    char apName[24];
    snprintf(apName, sizeof(apName), "PhotoDisplay-%02X%02X", mac[4], mac[5]);

    Serial.printf("Starting setup portal: %s\n", apName);
    WiFi.mode(WIFI_AP);
    WiFi.softAP(apName);
    delay(500);

    dnsServer.start(53, "*", WiFi.softAPIP());

    apServer.on("/", HTTP_GET, []() {
        apServer.send_P(200, "text/html", SETUP_HTML);
    });

    apServer.on("/save", HTTP_POST, []() {
        Config c;
        c.wifiSsid     = apServer.arg("ssid");
        c.wifiPassword = apServer.arg("pass");
        c.serverHost   = apServer.arg("host");
        const String ps = apServer.arg("port");
        c.serverPort   = ps.length() > 0 ? ps.toInt() : 8080;
        c.apiKey       = apServer.arg("key");

        if (!configComplete(c)) {
            apServer.send(400, "text/html",
                "<div style='font-family:sans-serif;padding:30px'>"
                "<h2 style='color:red'>Missing required fields.</h2>"
                "<p><a href='/'>Go back</a></p></div>");
            return;
        }
        saveConfig(c);
        apServer.send_P(200, "text/html", SAVED_HTML);
        delay(1500);
        ESP.restart();
    });

    // Captive portal redirects (iOS, Android, Windows detection URLs)
    auto redir = []() {
        apServer.sendHeader("Location", "http://192.168.4.1/", true);
        apServer.send(302, "text/plain", "");
    };
    apServer.on("/generate_204",        HTTP_GET, redir);
    apServer.on("/connecttest.txt",     HTTP_GET, redir);
    apServer.on("/hotspot-detect.html", HTTP_GET, redir);
    apServer.on("/ncsi.txt",            HTTP_GET, redir);
    apServer.onNotFound(redir);

    apServer.begin();
    Serial.printf("Portal: http://%s\n", WiFi.softAPIP().toString().c_str());

    while (true) {
        dnsServer.processNextRequest();
        apServer.handleClient();
    }
}

// ── Nearest-color quantization ────────────────────────────────────────────
static inline uint8_t quantize(uint8_t r, uint8_t g, uint8_t b) {
    int best = 0, bestDist = INT_MAX;
    for (int i = 0; i < 7; i++) {
        int dr = (int)r - PALETTE[i][0];
        int dg = (int)g - PALETTE[i][1];
        int db = (int)b - PALETTE[i][2];
        int d  = dr*dr*2 + dg*dg*4 + db*db;
        if (d < bestDist) { bestDist = d; best = i; }
    }
    return (uint8_t)best;
}

// ── JPEGDEC draw callback ─────────────────────────────────────────────────
static int jpegDraw(JPEGDRAW *pDraw) {
    for (int row = 0; row < pDraw->iHeight; row++) {
        int py = pDraw->y + row;
        if (py >= EPD_H) break;
        for (int col = 0; col < pDraw->iWidth; col++) {
            int px = pDraw->x + col;
            if (px >= EPD_W) continue;
            uint16_t c = pDraw->pPixels[row * pDraw->iWidth + col];
            uint8_t r = ( c >> 11)         << 3;
            uint8_t g = ((c >>  5) & 0x3F) << 2;
            uint8_t b = ( c        & 0x1F) << 3;
            uint8_t idx = quantize(r, g, b);
            int pos = py * EPD_W + px;
            if (pos & 1)
                epd_buf[pos >> 1] = (epd_buf[pos >> 1] & 0xF0) | idx;
            else
                epd_buf[pos >> 1] = (epd_buf[pos >> 1] & 0x0F) | (idx << 4);
        }
    }
    return 1;
}

// ── EPD SPI helpers ───────────────────────────────────────────────────────
static void epd_cmd(uint8_t cmd) {
    digitalWrite(EPD_DC, LOW);  digitalWrite(EPD_CS, LOW);
    SPI.transfer(cmd);
    digitalWrite(EPD_CS, HIGH);
}
static void epd_dat(uint8_t dat) {
    digitalWrite(EPD_DC, HIGH); digitalWrite(EPD_CS, LOW);
    SPI.transfer(dat);
    digitalWrite(EPD_CS, HIGH);
}
static void epd_busy_wait() { while (!digitalRead(EPD_BUSY)) delay(10); }
static void epd_reset() {
    digitalWrite(EPD_RST, HIGH); delay(20);
    digitalWrite(EPD_RST, LOW);  delay(4);
    digitalWrite(EPD_RST, HIGH); delay(20);
    epd_busy_wait();
}
static void epd_init() {
    digitalWrite(EPD_PWR, HIGH);
    epd_reset();
    epd_cmd(0xAA);
    epd_dat(0x49); epd_dat(0x55); epd_dat(0x20); epd_dat(0x08);
    epd_dat(0x09); epd_dat(0x18);
    epd_cmd(0x01); epd_dat(0x3F);
    epd_cmd(0x00); epd_dat(0x5F); epd_dat(0x69);
    epd_cmd(0x03); epd_dat(0x00); epd_dat(0x54); epd_dat(0x00); epd_dat(0x44);
    epd_cmd(0x05); epd_dat(0x40); epd_dat(0x1F); epd_dat(0x1F); epd_dat(0x2C);
    epd_cmd(0x06); epd_dat(0x6F); epd_dat(0x1F); epd_dat(0x1F); epd_dat(0x22);
    epd_cmd(0x08); epd_dat(0x6F); epd_dat(0x1F); epd_dat(0x1F); epd_dat(0x22);
    epd_cmd(0x13); epd_dat(0x00); epd_dat(0x04);
    epd_cmd(0x30); epd_dat(0x3C);
    epd_cmd(0x41); epd_dat(0x00);
    epd_cmd(0x50); epd_dat(0x3F);
    epd_cmd(0x60); epd_dat(0x02); epd_dat(0x00);
    epd_cmd(0x61); epd_dat(0x03); epd_dat(0x20); epd_dat(0x01); epd_dat(0xE0);
    epd_cmd(0x82); epd_dat(0x1E);
    epd_cmd(0x84); epd_dat(0x00);
    epd_cmd(0x86); epd_dat(0x00);
    epd_cmd(0xE3); epd_dat(0x2F);
    epd_cmd(0xE0); epd_dat(0x00);
    epd_cmd(0xE6); epd_dat(0x00);
}
static void epd_display(uint8_t *buf) {
    epd_cmd(0x10);
    const size_t CHUNK = 4096;
    for (size_t i = 0; i < EPD_BUF_SIZE; i += CHUNK) {
        size_t n = min(CHUNK, EPD_BUF_SIZE - i);
        digitalWrite(EPD_DC, HIGH); digitalWrite(EPD_CS, LOW);
        SPI.writeBytes(buf + i, n);
        digitalWrite(EPD_CS, HIGH);
    }
    epd_cmd(0x04); epd_dat(0x00);
    epd_busy_wait();
    epd_cmd(0x12); epd_dat(0x00);
    delay(100);
    epd_busy_wait();
}
static void epd_sleep_mode() {
    epd_cmd(0x02); epd_dat(0x00);
    epd_busy_wait();
    epd_cmd(0x07); epd_dat(0xA5);
    digitalWrite(EPD_PWR, LOW);
}

// ── Battery voltage reading ───────────────────────────────────────────────
static int read_battery_mv() {
#if BATTERY_ADC_PIN < 0
    return -1;
#else
    analogReadResolution(12);
    uint32_t raw = 0;
    for (int i = 0; i < 8; i++) raw += analogRead(BATTERY_ADC_PIN);
    raw /= 8;
    float vadc = (raw / 4095.0f) * 3300.0f;
    return (int)(vadc * BATTERY_DIVIDER_RATIO);
#endif
}

// ── Post device status to server ──────────────────────────────────────────
static void post_status(uint32_t sleep_s) {
    int bat_mv = read_battery_mv();
    int rssi   = WiFi.RSSI();

    uint8_t mac[6]; esp_read_mac(mac, ESP_MAC_WIFI_STA);
    char device_id[18];
    snprintf(device_id, sizeof(device_id), "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    HTTPClient http;
    String url = String("http://") + cfg.serverHost + ":" + cfg.serverPort
               + "/api/device/status?key=" + cfg.apiKey;
    http.begin(url);
    http.addHeader("Content-Type", "application/json");
    String body = "{\"device_id\":\"" + String(device_id) + "\""
                + ",\"wifi_rssi\":"  + rssi
                + (bat_mv > 0 ? ",\"battery_mv\":" + String(bat_mv) : "")
                + "}";
    int code = http.POST(body);
    Serial.printf("Status POST %d\n", code);
    http.end();
}

// ── Deep sleep ────────────────────────────────────────────────────────────
static void deep_sleep(uint32_t seconds) {
    Serial.printf("Deep sleep for %u s\n", seconds);
    Serial.flush();
    WiFi.disconnect(true);
    esp_sleep_enable_timer_wakeup((uint64_t)seconds * 1000000ULL);
    esp_deep_sleep_start();
}

// ── setup ─────────────────────────────────────────────────────────────────
void setup() {
    Serial.begin(115200);
    delay(300);
    Serial.println("\n=== PhotoDisplay ===");

    cfg = loadConfig();

    epd_buf  = (uint8_t *)ps_malloc(EPD_BUF_SIZE);
    jpeg_buf = (uint8_t *)ps_malloc(JPEG_BUF_SIZE);
    if (!epd_buf || !jpeg_buf) {
        Serial.println("PSRAM alloc failed");
        if (!configComplete(cfg)) startCaptivePortal();
        deep_sleep(60);
    }
    memset(epd_buf, 0x11, EPD_BUF_SIZE);

    pinMode(EPD_CS,   OUTPUT); digitalWrite(EPD_CS,   HIGH);
    pinMode(EPD_DC,   OUTPUT);
    pinMode(EPD_RST,  OUTPUT);
    pinMode(EPD_BUSY, INPUT);
    pinMode(EPD_PWR,  OUTPUT); digitalWrite(EPD_PWR, LOW);
    SPI.begin(EPD_CLK, -1, EPD_MOSI, EPD_CS);
    SPI.beginTransaction(SPISettings(4000000, MSBFIRST, SPI_MODE0));

    if (!configComplete(cfg)) {
        // Auto mode: firmware built with credentials baked in
        if (strlen(DEFAULT_WIFI_SSID) > 0 && strlen(DEFAULT_API_KEY) > 0) {
            cfg.wifiSsid     = String(DEFAULT_WIFI_SSID);
            cfg.wifiPassword = String(DEFAULT_WIFI_PASS);
            cfg.serverHost   = String(DEFAULT_SERVER_HOST);
            cfg.serverPort   = DEFAULT_SERVER_PORT;
            cfg.apiKey       = String(DEFAULT_API_KEY);
            saveConfig(cfg);
            Serial.println("Loaded compile-time config");
        } else {
            Serial.println("No config — starting setup portal");
            startCaptivePortal();
        }
    }

    Serial.printf("WiFi: connecting to %s", cfg.wifiSsid.c_str());
    WiFi.begin(cfg.wifiSsid.c_str(), cfg.wifiPassword.c_str());
    for (int i = 0; i < 30 && WiFi.status() != WL_CONNECTED; i++) {
        delay(500); Serial.print(".");
    }
    if (WiFi.status() != WL_CONNECTED) {
        Serial.println("\nWiFi failed — starting setup portal");
        startCaptivePortal();
    }
    Serial.printf("\nIP: %s\n", WiFi.localIP().toString().c_str());

    uint32_t sleep_s = DEFAULT_SLEEP_S;
    {
        HTTPClient http;
        String url = String("http://") + cfg.serverHost + ":" + cfg.serverPort
                   + "/api/slideshow/current?key=" + cfg.apiKey;
        http.begin(url);
        if (http.GET() == 200) {
            String body = http.getString();
            int idx = body.indexOf("\"next_in_ms\":");
            if (idx >= 0) {
                long ms = body.substring(idx + 13).toInt();
                if (ms > 5000) sleep_s = (uint32_t)(ms / 1000);
            }
        }
        http.end();
    }

    size_t jpeg_len = 0;
    {
        HTTPClient http;
        String url = String("http://") + cfg.serverHost + ":" + cfg.serverPort
                   + "/api/slideshow/image?key=" + cfg.apiKey
                   + "&width=" + EPD_W + "&height=" + EPD_H;
        http.begin(url);
        int code = http.GET();
        if (code != 200) {
            Serial.printf("HTTP %d\n", code);
            http.end();
            deep_sleep(sleep_s);
        }
        WiFiClient *stream = http.getStreamPtr();
        int total = http.getSize();
        Serial.printf("JPEG: %d bytes\n", total);
        while (http.connected() && jpeg_len < (size_t)total) {
            int avail = stream->available();
            if (avail > 0) {
                size_t room = JPEG_BUF_SIZE - jpeg_len;
                if (room == 0) break;
                jpeg_len += stream->readBytes(jpeg_buf + jpeg_len, min((int)room, avail));
            }
        }
        http.end();
    }

    if (jpeg.openRAM(jpeg_buf, (int)jpeg_len, jpegDraw)) {
        jpeg.setPixelType(RGB565_LITTLE_ENDIAN);
        if (!jpeg.decode(0, 0, 0)) Serial.println("JPEG decode error");
        else                        Serial.println("JPEG decoded");
        jpeg.close();
    } else {
        Serial.println("JPEG open failed");
    }

    post_status(sleep_s);
    epd_init();
    epd_display(epd_buf);
    epd_sleep_mode();
    deep_sleep(sleep_s);
}

void loop() {}
