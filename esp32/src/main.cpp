#include <Arduino.h>
#include <WiFi.h>
#include <WebServer.h>
#include <DNSServer.h>
#include <HTTPClient.h>
#include <HTTPUpdate.h>
#include <Preferences.h>
#include <SPI.h>
#include <Wire.h>
#include <esp_sleep.h>
#include <esp_system.h>
#include <esp_mac.h>
#include "driver/rtc_io.h"
#include "JPEGDEC.h"
#include "config.h"
#include "board.h"        // per-board pin map + capability flags
#include "qrcode.h"

#if HAS_AXP2101
  #define XPOWERS_CHIP_AXP2101
  #include "XPowersLib.h"
  static XPowersPMU PMU;
#endif

// Survive deep sleep: cache the AP we last connected to so we can skip the slow
// channel scan on the next wake (the scan is one of the longest WiFi-on steps).
RTC_DATA_ATTR static uint8_t g_wifiChan = 0;
RTC_DATA_ATTR static uint8_t g_wifiBssid[6] = {0};
RTC_DATA_ATTR static bool    g_wifiHint = false;

// Last good battery reading (mV), kept across deep sleep so a wake where the
// PMIC isn't re-read still reports a sensible level instead of dropping to 0%.
RTC_DATA_ATTR static int     g_lastBattMv = 0;

// True when the PMIC initialised successfully this boot, so charge/USB/voltage
// reads are valid. Not kept across sleep.
static bool g_pmicReady = false;

// Whether the "Sleeping" screen is already on the panel, so we render it once
// when entering the scheduled sleep window and not on every check during it.
RTC_DATA_ATTR static bool g_sleepShown = false;

// KEY1 button state, kept across deep sleep. g_manualOffset advances the photo
// on each short press; g_manualSleep is toggled by a long press.
RTC_DATA_ATTR static int  g_manualOffset = 0;
RTC_DATA_ATTR static bool g_manualSleep  = false;

// â”€â”€ Framebuffer size (depends on bits-per-pixel of the panel) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
#if PANEL_E6
  #define EPD_BUF_SIZE (EPD_W * EPD_H / 2)   // 4-bit colour code per pixel
#elif defined(PANEL_GRAY4)
  #define EPD_BUF_SIZE (EPD_W * EPD_H / 4)   // 2-bit grey level per pixel
#else
  #define EPD_BUF_SIZE (EPD_W * EPD_H / 8)   // 1-bit monochrome
#endif

#if PANEL_E6
// â”€â”€ Spectra 6 (E6) color palette â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// The E6 panel accepts these 4-bit color codes (index 4 is unused). Order and
// codes match Waveshare's official E6 driver.
#define C_BLACK   0
#define C_WHITE   1
#define C_YELLOW  2
#define C_RED     3
#define C_BLUE    5
#define C_GREEN   6

// RGB values are tuned to the colors the Spectra 6 panel can actually render
// (not pure sRGB primaries), which keeps quantized hues closer to the source.
static const struct { uint8_t code; uint8_t r, g, b; } PALETTE[] = {
    {C_BLACK,    0,   0,   0},
    {C_WHITE,  255, 255, 255},
    {C_YELLOW, 240, 220,  40},
    {C_RED,    190,  40,  40},
    {C_BLUE,    40,  60, 150},
    {C_GREEN,   50, 125,  70},
};
static const int PALETTE_N = sizeof(PALETTE) / sizeof(PALETTE[0]);

#elif defined(PANEL_UC8179)
  #if defined(PANEL_GRAY4)
    // 4-level grayscale: 0 = black … 3 = white.
    #define C_BLACK  0
    #define C_DGRAY  1
    #define C_LGRAY  2
    #define C_WHITE  3
    #define C_BLUE   1
    #define C_RED    1
    #define C_YELLOW 2
    #define C_GREEN  2
  #else
    // 1-bit monochrome: 0 = black, 1 = white. Colour names map to black/white so
    // the shared on-device screens still render.
    #define C_BLACK  0
    #define C_WHITE  1
    #define C_BLUE   0
    #define C_RED    0
    #define C_YELLOW 1
    #define C_GREEN  1
  #endif
#endif // PANEL_E6 / PANEL_UC8179

static uint8_t *epd_buf  = nullptr;
static uint8_t *jpeg_buf = nullptr;
static uint8_t *rgb_buf  = nullptr;   // full decoded RGB888 image, for dithering
static JPEGDEC  jpeg;

// â”€â”€ Logging: mirror to Serial AND a RAM buffer that is uploaded to the server
// each wake (the device deep-sleeps, so USB serial isn't readable in normal use)
static String g_logbuf;
static void logSink(const char *s) {
    Serial.print(s);
    g_logbuf += s;
    if (g_logbuf.length() > 6000) g_logbuf.remove(0, g_logbuf.length() - 6000);
}
static void logp(const char *s)    { logSink(s); }
static void logp(const String &s)  { logSink(s.c_str()); }
static void logln(const char *s)   { logSink(s); logSink("\n"); }
static void logln(const String &s) { logSink(s.c_str()); logSink("\n"); }
static void logf(const char *fmt, ...) {
    char b[220]; va_list a; va_start(a, fmt); vsnprintf(b, sizeof(b), fmt, a); va_end(a);
    logSink(b);
}
static String jsonEscape(const String &in) {
    String o; o.reserve(in.length() + 16);
    for (size_t i = 0; i < in.length(); i++) {
        char c = in[i];
        switch (c) {
            case '"':  o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\n': o += "\\n";  break;
            case '\r': o += "\\r";  break;
            case '\t': o += "\\t";  break;
            default:
                if ((uint8_t)c < 0x20) { char u[8]; snprintf(u, sizeof(u), "\\u%04x", c); o += u; }
                else o += c;
        }
    }
    return o;
}

// â”€â”€ Runtime config â€” stored in NVS, set via setup portal â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

// WiFi + server are enough to come online; the API key can be obtained later
// via the QR pairing flow.
static bool configComplete(const Config &c) {
    return c.wifiSsid.length() > 0 &&
           c.serverHost.length() > 0;
}

// â”€â”€ Captive portal â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
static WebServer apServer(80);
static DNSServer dnsServer;

static const char SETUP_HTML[] PROGMEM = R"html(<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PhotoDock Setup</title>
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
  <h2>PhotoDock</h2>
  <p class="sub">Connect this device to your network</p>
  <form method="POST" action="/save">
    <label>WiFi network name</label>
    <input type="text" name="ssid" placeholder="Your home WiFi" required>
    <label>WiFi password</label>
    <input type="password" name="pass" placeholder="Leave empty for open networks">
    <label>Server address</label>
    <input type="text" name="host" placeholder="192.168.1.100" required>
    <p class="hint">IP of the computer running PhotoDock</p>
    <label>Server port</label>
    <input type="number" name="port" value="8080">
    <p class="hint">After connecting, the device shows a QR code to pair it to a screen.</p>
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
    snprintf(apName, sizeof(apName), "PhotoDock-%02X%02X", mac[4], mac[5]);

    logf("Starting setup portal: %s\n", apName);
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
        c.apiKey       = "";   // obtained later via QR pairing

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
    logf("Portal: http://%s\n", WiFi.softAPIP().toString().c_str());

    while (true) {
        dnsServer.processNextRequest();
        apServer.handleClient();
    }
}

#if PANEL_E6
// â”€â”€ Nearest-color quantization â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Find nearest palette entry. Returns its array index; weighted for perceived
// luma so greys don't drift toward colored cells.
static inline int quantizeIdx(int r, int g, int b) {
    int best = 0, bestDist = INT_MAX;
    for (int i = 0; i < PALETTE_N; i++) {
        int dr = r - PALETTE[i].r;
        int dg = g - PALETTE[i].g;
        int db = b - PALETTE[i].b;
        int d  = dr*dr*2 + dg*dg*4 + db*db;
        if (d < bestDist) { bestDist = d; best = i; }
    }
    return best;
}
static inline uint8_t quantize(uint8_t r, uint8_t g, uint8_t b) {
    return PALETTE[quantizeIdx(r, g, b)].code;
}
#endif // PANEL_E6

// â”€â”€ JPEGDEC draw callback â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Store the decoded RGB888 into the full-image buffer (unrotated). Quantizing
// and 180Â° rotation happen later in dither_and_pack().
static int jpegDraw(JPEGDRAW *pDraw) {
    for (int row = 0; row < pDraw->iHeight; row++) {
        int py = pDraw->y + row;
        if (py >= EPD_H) break;
        for (int col = 0; col < pDraw->iWidth; col++) {
            int px = pDraw->x + col;
            if (px >= EPD_W) continue;
            uint16_t c = pDraw->pPixels[row * pDraw->iWidth + col];
            int idx = (py * EPD_W + px) * 3;
            rgb_buf[idx + 0] = ( c >> 11)         << 3;   // R
            rgb_buf[idx + 1] = ((c >>  5) & 0x3F) << 2;   // G
            rgb_buf[idx + 2] = ( c        & 0x1F) << 3;   // B
        }
    }
    return 1;
}

#if PANEL_E6
static inline void epd_set_code(int x, int y, uint8_t code) {
    int pos = (EPD_H - 1 - y) * EPD_W + (EPD_W - 1 - x);  // 180Â° rotate
    if (pos & 1) epd_buf[pos >> 1] = (epd_buf[pos >> 1] & 0xF0) | code;
    else         epd_buf[pos >> 1] = (epd_buf[pos >> 1] & 0x0F) | (code << 4);
}

// Floyd-Steinberg dithering from rgb_buf into epd_buf. Diffuses quantization
// error to neighboring pixels so a 6-color photo looks far less posterized.
static void dither_and_pack() {
    const int W = EPD_W;
    // Two running error rows (current + next), 3 channels, fixed-point-free ints.
    int *errCur  = (int *)calloc(W * 3, sizeof(int));
    int *errNext = (int *)calloc(W * 3, sizeof(int));
    if (!errCur || !errNext) {     // fall back to plain nearest-color
        free(errCur); free(errNext);
        for (int y = 0; y < EPD_H; y++)
            for (int x = 0; x < W; x++) {
                int i = (y * W + x) * 3;
                epd_set_code(x, y, PALETTE[quantizeIdx(rgb_buf[i], rgb_buf[i+1], rgb_buf[i+2])].code);
            }
        return;
    }
    for (int y = 0; y < EPD_H; y++) {
        memset(errNext, 0, W * 3 * sizeof(int));
        for (int x = 0; x < W; x++) {
            int i = (y * W + x) * 3;
            int r = rgb_buf[i + 0] + errCur[x*3 + 0] / 16;
            int g = rgb_buf[i + 1] + errCur[x*3 + 1] / 16;
            int b = rgb_buf[i + 2] + errCur[x*3 + 2] / 16;
            if (r < 0) r = 0; if (r > 255) r = 255;
            if (g < 0) g = 0; if (g > 255) g = 255;
            if (b < 0) b = 0; if (b > 255) b = 255;
            int pi = quantizeIdx(r, g, b);
            epd_set_code(x, y, PALETTE[pi].code);
            int er = r - PALETTE[pi].r;
            int eg = g - PALETTE[pi].g;
            int eb = b - PALETTE[pi].b;
            // distribute: right 7, below-left 3, below 5, below-right 1 (/16)
            if (x + 1 < W) { errCur[(x+1)*3]+=er*7; errCur[(x+1)*3+1]+=eg*7; errCur[(x+1)*3+2]+=eb*7; }
            if (x > 0)     { errNext[(x-1)*3]+=er*3; errNext[(x-1)*3+1]+=eg*3; errNext[(x-1)*3+2]+=eb*3; }
            errNext[x*3]+=er*5; errNext[x*3+1]+=eg*5; errNext[x*3+2]+=eb*5;
            if (x + 1 < W) { errNext[(x+1)*3]+=er; errNext[(x+1)*3+1]+=eg; errNext[(x+1)*3+2]+=eb; }
        }
        int *tmp = errCur; errCur = errNext; errNext = tmp;
    }
    free(errCur); free(errNext);
}

#elif defined(PANEL_UC8179)
// Pack one pixel into the UC8179 framebuffer (no rotation yet — adjust once we
// see the panel on hardware).
static inline void epd_set_code(int x, int y, uint8_t v) {
  #if defined(PANEL_GRAY4)
    int pos = y * EPD_W + x;                       // 2 bits/pixel, 4 px/byte
    int b = pos >> 2, sh = (3 - (pos & 3)) * 2;
    epd_buf[b] = (epd_buf[b] & ~(0x3 << sh)) | ((v & 0x3) << sh);
  #else
    int pos = y * EPD_W + x;                       // 1 bit/pixel, MSB = leftmost
    int b = pos >> 3; uint8_t m = 0x80 >> (pos & 7);
    if (v) epd_buf[b] |= m; else epd_buf[b] &= ~m; // 1 = white, 0 = black
  #endif
}

// Floyd-Steinberg from rgb_buf -> epd_buf using luminance. Mono (2 levels) or
// 4-level grayscale depending on the build.
static void dither_and_pack() {
    const int W = EPD_W;
  #if defined(PANEL_GRAY4)
    const int LEVELS = 4; const int LV[4] = {0, 85, 170, 255};
    auto nearest = [&](int v){ return v < 43 ? 0 : v < 128 ? 1 : v < 213 ? 2 : 3; };
  #else
    const int LEVELS = 2; const int LV[2] = {0, 255};
    auto nearest = [&](int v){ return v >= 128 ? 1 : 0; };
  #endif
    (void)LEVELS;
    int *errCur  = (int *)calloc(W, sizeof(int));
    int *errNext = (int *)calloc(W, sizeof(int));
    for (int y = 0; y < EPD_H; y++) {
        if (errNext) memset(errNext, 0, W * sizeof(int));
        for (int x = 0; x < W; x++) {
            int i = (y * W + x) * 3;
            int lum = (rgb_buf[i] * 54 + rgb_buf[i+1] * 183 + rgb_buf[i+2] * 19) >> 8;
            int v = lum + (errCur ? errCur[x] / 16 : 0);
            if (v < 0) v = 0; if (v > 255) v = 255;
            int lvl = nearest(v);
            epd_set_code(x, y, (uint8_t)lvl);
            if (errCur && errNext) {
                int e = v - LV[lvl];
                if (x + 1 < W) errCur[x+1]  += e * 7;
                if (x > 0)     errNext[x-1] += e * 3;
                errNext[x] += e * 5;
                if (x + 1 < W) errNext[x+1] += e;
            }
        }
        if (errCur && errNext) { int *t = errCur; errCur = errNext; errNext = t; }
    }
    free(errCur); free(errNext);
}
#endif // PANEL_E6 / PANEL_UC8179

// â”€â”€ EPD SPI helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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
// Wait until the panel reports idle (BUSY high), with a timeout so a wiring or
// polarity problem can't hang the firmware forever.
static void epd_busy_wait(uint32_t timeout_ms = 35000) {
    uint32_t start = millis();
    while (!digitalRead(EPD_BUSY)) {
        if (millis() - start > timeout_ms) {
            logf("epd_busy_wait: TIMEOUT after %u ms (BUSY never went high)\n", timeout_ms);
            return;
        }
        delay(5);
    }
}
static void epd_reset() {
    digitalWrite(EPD_RST, HIGH); delay(50);
    digitalWrite(EPD_RST, LOW);  delay(20);
    digitalWrite(EPD_RST, HIGH); delay(50);
}
#if PANEL_E6
// E6 init sequence (from Waveshare's official ESP32-S3-PhotoPainter driver).
static void epd_init() {
    logf("epd_init: BUSY=%d\n", digitalRead(EPD_BUSY));
    epd_reset();
    epd_busy_wait(8000);    // reset settles quickly
    logf("epd_init: after reset, BUSY=%d\n", digitalRead(EPD_BUSY));
    delay(50);
    epd_cmd(0xAA);
    epd_dat(0x49); epd_dat(0x55); epd_dat(0x20); epd_dat(0x08);
    epd_dat(0x09); epd_dat(0x18);
    epd_cmd(0x01); epd_dat(0x3F);
    epd_cmd(0x00); epd_dat(0x5F); epd_dat(0x69);
    epd_cmd(0x03); epd_dat(0x00); epd_dat(0x54); epd_dat(0x00); epd_dat(0x44);
    epd_cmd(0x05); epd_dat(0x40); epd_dat(0x1F); epd_dat(0x1F); epd_dat(0x2C);
    epd_cmd(0x06); epd_dat(0x6F); epd_dat(0x1F); epd_dat(0x17); epd_dat(0x49);
    epd_cmd(0x08); epd_dat(0x6F); epd_dat(0x1F); epd_dat(0x1F); epd_dat(0x22);
    epd_cmd(0x30); epd_dat(0x03);
    epd_cmd(0x50); epd_dat(0x3F);
    epd_cmd(0x60); epd_dat(0x02); epd_dat(0x00);
    epd_cmd(0x61); epd_dat(0x03); epd_dat(0x20); epd_dat(0x01); epd_dat(0xE0);
    epd_cmd(0x84); epd_dat(0x01);
    epd_cmd(0xE3); epd_dat(0x2F);
    // NOTE: no power-on (0x04) here. epd_display() powers the panel on right
    // before the refresh; doing it here too was a redundant power-up cycle
    // (extra ~1-3s and an extra panel settle) on every photo. Matches the
    // official Waveshare 7.3" E6 driver, which powers on only in the show step.
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
    logln("epd_display: data sent, power on (0x04)");
    epd_cmd(0x04);                  // power on
    epd_busy_wait(8000);            // power-up is fast
    epd_cmd(0x06); epd_dat(0x6F); epd_dat(0x1F); epd_dat(0x17); epd_dat(0x49);
    logln("epd_display: refresh (0x12)");
    epd_cmd(0x12); epd_dat(0x00);   // display refresh — the genuinely slow step
    epd_busy_wait(35000);
    epd_cmd(0x02); epd_dat(0x00);   // power off
    epd_busy_wait(8000);
    logln("epd_display: done");
}
static void epd_sleep_mode() {
    epd_cmd(0x07); epd_dat(0xA5);   // deep sleep
}

#elif defined(PANEL_UC8179)
// Send `n` bytes of a constant value over SPI (for filling a RAM plane fast).
static void epd_send_const(uint8_t val, size_t n) {
    uint8_t tmp[256]; memset(tmp, val, sizeof(tmp));
    digitalWrite(EPD_DC, HIGH);
    while (n) { size_t c = min(n, sizeof(tmp)); digitalWrite(EPD_CS, LOW); SPI.writeBytes(tmp, c); digitalWrite(EPD_CS, HIGH); n -= c; }
}
// UC8179 (GDEW075T7) 7.5" monochrome init — LUT from the panel's OTP.
static void epd_init() {
    logf("epd_init: BUSY=%d\n", digitalRead(EPD_BUSY));
    epd_reset();
    epd_busy_wait(8000);
    logf("epd_init: after reset, BUSY=%d\n", digitalRead(EPD_BUSY));
    epd_cmd(0x01); epd_dat(0x07); epd_dat(0x07); epd_dat(0x3F); epd_dat(0x3F);  // power setting
    epd_cmd(0x04); epd_busy_wait(8000);                                          // power on
    epd_cmd(0x00); epd_dat(0x1F);                                                // panel: B/W, LUT from OTP
    epd_cmd(0x61); epd_dat(0x03); epd_dat(0x20); epd_dat(0x01); epd_dat(0xE0);   // resolution 800x480
    epd_cmd(0x15); epd_dat(0x00);
    epd_cmd(0x50); epd_dat(0x10); epd_dat(0x07);                                 // VCOM + data interval
    epd_cmd(0x60); epd_dat(0x22);                                                // TCON setting
}
static void epd_display(uint8_t *buf) {
    epd_cmd(0x10); epd_send_const(0x00, EPD_BUF_SIZE);   // OLD plane (from white)
    epd_cmd(0x13);                                       // NEW plane = image
    const size_t CHUNK = 4096;
    for (size_t i = 0; i < EPD_BUF_SIZE; i += CHUNK) {
        size_t n = min(CHUNK, EPD_BUF_SIZE - i);
        digitalWrite(EPD_DC, HIGH); digitalWrite(EPD_CS, LOW);
        SPI.writeBytes(buf + i, n);
        digitalWrite(EPD_CS, HIGH);
    }
    logln("epd_display: refresh (0x12)");
    epd_cmd(0x12); delay(100);                           // display refresh
    epd_busy_wait(35000);
    logln("epd_display: done");
}
static void epd_sleep_mode() {
    epd_cmd(0x02); epd_busy_wait(8000);   // power off
    epd_cmd(0x07); epd_dat(0xA5);         // deep sleep
}
#endif // PANEL_E6 / PANEL_UC8179

// â”€â”€ 8Ã—8 bitmap font (IBM PC, printable ASCII 0x20â€“0x7E) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Each char: 8 bytes = 8 rows, MSB of each byte = leftmost pixel
static const uint8_t FONT8[95][8] PROGMEM = {
    {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}, // 0x20 space
    {0x18,0x18,0x18,0x18,0x18,0x00,0x18,0x00}, // 0x21 !
    {0x6C,0x6C,0x6C,0x00,0x00,0x00,0x00,0x00}, // 0x22 "
    {0x36,0x36,0x7F,0x36,0x7F,0x36,0x36,0x00}, // 0x23 #
    {0x18,0x3E,0x60,0x3C,0x06,0x7C,0x18,0x00}, // 0x24 $
    {0x62,0x66,0x0C,0x18,0x30,0x66,0x46,0x00}, // 0x25 %
    {0x1C,0x36,0x1C,0x38,0x6F,0x66,0x3B,0x00}, // 0x26 &
    {0x18,0x18,0x30,0x00,0x00,0x00,0x00,0x00}, // 0x27 '
    {0x0C,0x18,0x30,0x30,0x30,0x18,0x0C,0x00}, // 0x28 (
    {0x30,0x18,0x0C,0x0C,0x0C,0x18,0x30,0x00}, // 0x29 )
    {0x00,0x66,0x3C,0xFF,0x3C,0x66,0x00,0x00}, // 0x2A *
    {0x00,0x18,0x18,0x7E,0x18,0x18,0x00,0x00}, // 0x2B +
    {0x00,0x00,0x00,0x00,0x00,0x18,0x18,0x30}, // 0x2C ,
    {0x00,0x00,0x00,0x7E,0x00,0x00,0x00,0x00}, // 0x2D -
    {0x00,0x00,0x00,0x00,0x00,0x18,0x18,0x00}, // 0x2E .
    {0x00,0x06,0x0C,0x18,0x30,0x60,0x00,0x00}, // 0x2F /
    {0x3C,0x66,0x6E,0x76,0x66,0x66,0x3C,0x00}, // 0x30 0
    {0x18,0x38,0x18,0x18,0x18,0x18,0x7E,0x00}, // 0x31 1
    {0x3C,0x66,0x06,0x0C,0x18,0x30,0x7E,0x00}, // 0x32 2
    {0x3C,0x66,0x06,0x1C,0x06,0x66,0x3C,0x00}, // 0x33 3
    {0x06,0x1E,0x36,0x66,0x7F,0x06,0x06,0x00}, // 0x34 4
    {0x7E,0x60,0x7C,0x06,0x06,0x66,0x3C,0x00}, // 0x35 5
    {0x1C,0x30,0x60,0x7C,0x66,0x66,0x3C,0x00}, // 0x36 6
    {0x7E,0x06,0x06,0x0C,0x18,0x30,0x30,0x00}, // 0x37 7
    {0x3C,0x66,0x66,0x3C,0x66,0x66,0x3C,0x00}, // 0x38 8
    {0x3C,0x66,0x66,0x3E,0x06,0x0C,0x38,0x00}, // 0x39 9
    {0x00,0x18,0x18,0x00,0x18,0x18,0x00,0x00}, // 0x3A :
    {0x00,0x18,0x18,0x00,0x18,0x18,0x30,0x00}, // 0x3B ;
    {0x06,0x0C,0x18,0x30,0x18,0x0C,0x06,0x00}, // 0x3C <
    {0x00,0x00,0x7E,0x00,0x7E,0x00,0x00,0x00}, // 0x3D =
    {0x60,0x30,0x18,0x0C,0x18,0x30,0x60,0x00}, // 0x3E >
    {0x3C,0x66,0x06,0x0C,0x18,0x00,0x18,0x00}, // 0x3F ?
    {0x3E,0x63,0x6F,0x6B,0x6F,0x60,0x3E,0x00}, // 0x40 @
    {0x18,0x3C,0x66,0x7E,0x66,0x66,0x66,0x00}, // 0x41 A
    {0x7C,0x66,0x66,0x7C,0x66,0x66,0x7C,0x00}, // 0x42 B
    {0x3C,0x66,0x60,0x60,0x60,0x66,0x3C,0x00}, // 0x43 C
    {0x78,0x6C,0x66,0x66,0x66,0x6C,0x78,0x00}, // 0x44 D
    {0x7E,0x60,0x60,0x78,0x60,0x60,0x7E,0x00}, // 0x45 E
    {0x7E,0x60,0x60,0x78,0x60,0x60,0x60,0x00}, // 0x46 F
    {0x3C,0x66,0x60,0x6E,0x66,0x66,0x3C,0x00}, // 0x47 G
    {0x66,0x66,0x66,0x7E,0x66,0x66,0x66,0x00}, // 0x48 H
    {0x3C,0x18,0x18,0x18,0x18,0x18,0x3C,0x00}, // 0x49 I
    {0x1E,0x06,0x06,0x06,0x66,0x66,0x3C,0x00}, // 0x4A J
    {0x66,0x6C,0x78,0x70,0x78,0x6C,0x66,0x00}, // 0x4B K
    {0x60,0x60,0x60,0x60,0x60,0x60,0x7E,0x00}, // 0x4C L
    {0x63,0x77,0x7F,0x6B,0x63,0x63,0x63,0x00}, // 0x4D M
    {0x66,0x76,0x7E,0x7E,0x6E,0x66,0x66,0x00}, // 0x4E N
    {0x3C,0x66,0x66,0x66,0x66,0x66,0x3C,0x00}, // 0x4F O
    {0x7C,0x66,0x66,0x7C,0x60,0x60,0x60,0x00}, // 0x50 P
    {0x3C,0x66,0x66,0x66,0x6E,0x3C,0x0E,0x00}, // 0x51 Q
    {0x7C,0x66,0x66,0x7C,0x78,0x6C,0x66,0x00}, // 0x52 R
    {0x3C,0x66,0x60,0x3C,0x06,0x66,0x3C,0x00}, // 0x53 S
    {0x7E,0x18,0x18,0x18,0x18,0x18,0x18,0x00}, // 0x54 T
    {0x66,0x66,0x66,0x66,0x66,0x66,0x3C,0x00}, // 0x55 U
    {0x66,0x66,0x66,0x66,0x66,0x3C,0x18,0x00}, // 0x56 V
    {0x63,0x63,0x63,0x6B,0x7F,0x77,0x63,0x00}, // 0x57 W
    {0x66,0x66,0x3C,0x18,0x3C,0x66,0x66,0x00}, // 0x58 X
    {0x66,0x66,0x66,0x3C,0x18,0x18,0x18,0x00}, // 0x59 Y
    {0x7E,0x06,0x0C,0x18,0x30,0x60,0x7E,0x00}, // 0x5A Z
    {0x3C,0x30,0x30,0x30,0x30,0x30,0x3C,0x00}, // 0x5B [
    {0x00,0x60,0x30,0x18,0x0C,0x06,0x00,0x00}, // 0x5C backslash
    {0x3C,0x0C,0x0C,0x0C,0x0C,0x0C,0x3C,0x00}, // 0x5D ]
    {0x18,0x3C,0x66,0x00,0x00,0x00,0x00,0x00}, // 0x5E ^
    {0x00,0x00,0x00,0x00,0x00,0x00,0xFF,0x00}, // 0x5F _
    {0x18,0x18,0x0C,0x00,0x00,0x00,0x00,0x00}, // 0x60 `
    {0x00,0x00,0x3C,0x06,0x3E,0x66,0x3E,0x00}, // 0x61 a
    {0x60,0x60,0x7C,0x66,0x66,0x66,0x7C,0x00}, // 0x62 b
    {0x00,0x00,0x3C,0x66,0x60,0x66,0x3C,0x00}, // 0x63 c
    {0x06,0x06,0x3E,0x66,0x66,0x66,0x3E,0x00}, // 0x64 d
    {0x00,0x00,0x3C,0x66,0x7E,0x60,0x3C,0x00}, // 0x65 e
    {0x1C,0x30,0x30,0x7C,0x30,0x30,0x30,0x00}, // 0x66 f
    {0x00,0x00,0x3E,0x66,0x66,0x3E,0x06,0x3C}, // 0x67 g
    {0x60,0x60,0x7C,0x66,0x66,0x66,0x66,0x00}, // 0x68 h
    {0x18,0x00,0x38,0x18,0x18,0x18,0x3C,0x00}, // 0x69 i
    {0x06,0x00,0x0E,0x06,0x06,0x06,0x66,0x3C}, // 0x6A j
    {0x60,0x60,0x66,0x6C,0x78,0x6C,0x66,0x00}, // 0x6B k
    {0x38,0x18,0x18,0x18,0x18,0x18,0x3C,0x00}, // 0x6C l
    {0x00,0x00,0x66,0x7F,0x7F,0x6B,0x63,0x00}, // 0x6D m
    {0x00,0x00,0x7C,0x66,0x66,0x66,0x66,0x00}, // 0x6E n
    {0x00,0x00,0x3C,0x66,0x66,0x66,0x3C,0x00}, // 0x6F o
    {0x00,0x00,0x7C,0x66,0x66,0x7C,0x60,0x60}, // 0x70 p
    {0x00,0x00,0x3E,0x66,0x66,0x3E,0x06,0x06}, // 0x71 q
    {0x00,0x00,0x6C,0x76,0x60,0x60,0x60,0x00}, // 0x72 r
    {0x00,0x00,0x3E,0x60,0x3C,0x06,0x7C,0x00}, // 0x73 s
    {0x18,0x18,0x7E,0x18,0x18,0x18,0x0E,0x00}, // 0x74 t
    {0x00,0x00,0x66,0x66,0x66,0x66,0x3E,0x00}, // 0x75 u
    {0x00,0x00,0x66,0x66,0x66,0x3C,0x18,0x00}, // 0x76 v
    {0x00,0x00,0x63,0x6B,0x7F,0x3E,0x36,0x00}, // 0x77 w
    {0x00,0x00,0x66,0x3C,0x18,0x3C,0x66,0x00}, // 0x78 x
    {0x00,0x00,0x66,0x66,0x66,0x3E,0x06,0x3C}, // 0x79 y
    {0x00,0x00,0x7E,0x0C,0x18,0x30,0x7E,0x00}, // 0x7A z
    {0x0E,0x18,0x18,0x70,0x18,0x18,0x0E,0x00}, // 0x7B {
    {0x18,0x18,0x18,0x00,0x18,0x18,0x18,0x00}, // 0x7C |
    {0x70,0x18,0x18,0x0E,0x18,0x18,0x70,0x00}, // 0x7D }
    {0x3B,0x6E,0x00,0x00,0x00,0x00,0x00,0x00}, // 0x7E ~
};

// â”€â”€ Display drawing helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
#if PANEL_E6
static void epd_fill(uint8_t color) {
    uint8_t b = (uint8_t)((color << 4) | color);
    memset(epd_buf, b, EPD_BUF_SIZE);
}
static void epd_pix(int x, int y, uint8_t color) {
    if (x < 0 || x >= EPD_W || y < 0 || y >= EPD_H) return;
    int pos = (EPD_H - 1 - y) * EPD_W + (EPD_W - 1 - x);  // 180Â° rotate

    if (pos & 1) epd_buf[pos >> 1] = (epd_buf[pos >> 1] & 0xF0) | color;
    else         epd_buf[pos >> 1] = (epd_buf[pos >> 1] & 0x0F) | (color << 4);
}
#elif defined(PANEL_UC8179)
static void epd_fill(uint8_t color) {
  #if defined(PANEL_GRAY4)
    uint8_t b = color & 3; b = b | (b << 2) | (b << 4) | (b << 6);
  #else
    uint8_t b = color ? 0xFF : 0x00;   // 1 = white
  #endif
    memset(epd_buf, b, EPD_BUF_SIZE);
}
static void epd_pix(int x, int y, uint8_t color) {
    if (x < 0 || x >= EPD_W || y < 0 || y >= EPD_H) return;
    epd_set_code(x, y, color);
}
#endif
static void epd_rect(int x, int y, int w, int h, uint8_t color) {
    for (int dy = 0; dy < h; dy++)
        for (int dx = 0; dx < w; dx++)
            epd_pix(x + dx, y + dy, color);
}
static void epd_glyph(int x, int y, char c, uint8_t fg, uint8_t bg, int scale) {
    if (c < 0x20 || c > 0x7E) c = '?';
    const uint8_t *glyph = FONT8[(uint8_t)(c - 0x20)];
    for (int row = 0; row < 8; row++) {
        uint8_t bits = pgm_read_byte(&glyph[row]);
        for (int col = 0; col < 8; col++) {
            uint8_t color = (bits & (0x80u >> col)) ? fg : bg;
            for (int sy = 0; sy < scale; sy++)
                for (int sx = 0; sx < scale; sx++)
                    epd_pix(x + col * scale + sx, y + row * scale + sy, color);
        }
    }
}
static void epd_text(int x, int y, const char *s, uint8_t fg, uint8_t bg, int scale) {
    while (*s) { epd_glyph(x, y, *s++, fg, bg, scale); x += 9 * scale; }
}

// Returns AP SSID based on MAC
static String apNameFromMac() {
    uint8_t mac[6]; esp_read_mac(mac, ESP_MAC_WIFI_STA);
    char buf[24]; snprintf(buf, sizeof(buf), "PhotoDock-%02X%02X", mac[4], mac[5]);
    return String(buf);
}

// Show the WiFi setup portal screen on the e-ink display
static void epd_show_setup(const char *apName) {
    epd_fill(C_WHITE);                                        // white bg
    epd_rect(0, 0, EPD_W, 64, C_BLUE);                        // blue header
    epd_text(16, 12, "PhotoDock Setup", C_WHITE, C_BLUE, 3);
    epd_rect(0, 64, EPD_W, 2, C_BLACK);                       // black divider

    epd_text(24, 82,  "Connect your phone to this WiFi:", C_BLACK, C_WHITE, 2);
    epd_rect(16, 108, EPD_W - 32, 40, C_BLUE);               // blue box for AP name
    epd_text(24, 116, apName, C_WHITE, C_BLUE, 3);            // AP name in white

    epd_text(24, 168, "Then open a browser and go to:", C_BLACK, C_WHITE, 2);
    epd_rect(16, 194, 340, 40, C_BLACK);                     // black box for IP
    epd_text(24, 202, "192.168.4.1", C_WHITE, C_BLACK, 3);   // IP in white

    epd_text(24, 260, "Enter your WiFi password and", C_BLACK, C_WHITE, 2);
    epd_text(24, 282, "server address to get started.", C_BLACK, C_WHITE, 2);

    epd_init();
    epd_display(epd_buf);
    epd_sleep_mode();
}

// Show a server-unreachable error screen on the e-ink display
static void epd_show_error(const char *host, int port) {
    epd_fill(C_WHITE);                                        // white bg
    epd_rect(0, 0, EPD_W, 64, C_RED);                        // red header
    epd_text(16, 12, "Cannot reach server", C_WHITE, C_RED, 3);
    epd_rect(0, 64, EPD_W, 2, C_BLACK);                      // black divider

    char addr[64]; snprintf(addr, sizeof(addr), "%s:%d", host, port);
    epd_text(24, 82,  "Tried to connect to:", C_BLACK, C_WHITE, 2);
    epd_rect(16, 108, EPD_W - 32, 40, C_RED);               // red box for address
    epd_text(24, 116, addr, C_WHITE, C_RED, 3);              // address in white

    epd_text(24, 168, "Check that the server is running", C_BLACK, C_WHITE, 2);
    epd_text(24, 190, "and the IP address is correct.", C_BLACK, C_WHITE, 2);
    epd_text(24, 230, "Press BOOT after a reboot to", C_BLACK, C_WHITE, 2);
    epd_text(24, 252, "reconfigure this device.", C_BLACK, C_WHITE, 2);

    epd_init();
    epd_display(epd_buf);
    epd_sleep_mode();
}

// Show a "no photos yet" screen — the device is paired & online, but its screen
// has no images assigned on the server.
static void epd_show_no_photos() {
    epd_fill(C_WHITE);
    epd_rect(0, 0, EPD_W, 64, C_BLUE);
    epd_text(16, 12, "Paired & connected", C_WHITE, C_BLUE, 3);
    epd_rect(0, 64, EPD_W, 2, C_BLACK);

    epd_text(24, 100, "No photos on this screen yet.", C_BLACK, C_WHITE, 3);
    epd_text(24, 170, "Open PhotoDock, go to this", C_BLACK, C_WHITE, 2);
    epd_text(24, 192, "screen, and upload some photos.", C_BLACK, C_WHITE, 2);
    epd_text(24, 232, "The display will show them", C_BLACK, C_WHITE, 2);
    epd_text(24, 254, "automatically on the next refresh.", C_BLACK, C_WHITE, 2);

    epd_init();
    epd_display(epd_buf);
    epd_sleep_mode();
}

// Draw a QR code into the buffer at (ox,oy) with the given module pixel size.
static void epd_draw_qr(const char *text, int ox, int oy, int scale) {
    QRCode qr;
    static uint8_t qrData[256];   // ample for version 6 (holds ~134 byte URL)
    if (qrcode_initText(&qr, qrData, 6, ECC_LOW, text) != 0) return;
    // Quiet zone
    epd_rect(ox - scale*2, oy - scale*2,
             qr.size*scale + scale*4, qr.size*scale + scale*4, C_WHITE);
    for (int y = 0; y < qr.size; y++)
        for (int x = 0; x < qr.size; x++)
            if (qrcode_getModule(&qr, x, y))
                epd_rect(ox + x*scale, oy + y*scale, scale, scale, C_BLACK);
}

// Show the QR pairing screen: scan to link this device to a screen.
static void epd_show_pairing(const char *code, const char *pairUrl) {
    epd_fill(C_WHITE);
    epd_rect(0, 0, EPD_W, 64, C_BLUE);
    epd_text(16, 12, "Pair this display", C_WHITE, C_BLUE, 3);
    epd_rect(0, 64, EPD_W, 2, C_BLACK);

    epd_draw_qr(pairUrl, 470, 110, 6);   // QR on the right

    epd_text(24, 96,  "Scan the QR code, or open", C_BLACK, C_WHITE, 2);
    epd_text(24, 122, "the PhotoDock site and", C_BLACK, C_WHITE, 2);
    epd_text(24, 148, "go to /pair, then enter:", C_BLACK, C_WHITE, 2);

    epd_text(24, 196, "Pairing code", C_BLACK, C_WHITE, 2);
    epd_rect(16, 222, 300, 56, C_BLUE);
    epd_text(32, 232, code, C_WHITE, C_BLUE, 5);

    epd_text(24, 320, "Pick a screen to finish.", C_BLACK, C_WHITE, 2);
    epd_text(24, 360, "The display updates", C_BLACK, C_WHITE, 2);
    epd_text(24, 384, "automatically once paired.", C_BLACK, C_WHITE, 2);

    epd_init();
    epd_display(epd_buf);
    epd_sleep_mode();
}

// Extract a JSON string value: "key":"value"  (no nesting/escapes expected).
static String jsonStr(const String &body, const char *key) {
    String pat = String("\"") + key + "\":\"";
    int i = body.indexOf(pat);
    if (i < 0) return "";
    i += pat.length();
    int j = body.indexOf('"', i);
    return j < 0 ? "" : body.substring(i, j);
}

#if HAS_AXP2101
// â”€â”€ Battery voltage reading (via AXP2101 PMIC) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
static int read_battery_mv() {
    int mv = PMU.getBattVoltage();          // 0 if PMIC not init this wake / no batt
    // Only trust a plausible single-cell LiPo voltage. The AXP2101 sometimes
    // reports garbage (e.g. 41mV) right after a charge state change or when no
    // battery is actually present — don't let that show as a real 0%.
    if (mv >= 2500 && mv <= 4500) { g_lastBattMv = mv; return mv; }
    return g_lastBattMv > 0 ? g_lastBattMv : -1;   // fall back to last known good
}

// Manually unstick the I2C bus. Coming out of deep sleep the AXP2101 can be
// left mid-transaction holding SDA low, which jams the bus so every PMU.begin()
// fails (a full power-up clears it, which is why a cold boot always works). The
// standard recovery is to bit-bang up to 9 clock pulses on SCL to let the slave
// finish, then issue a STOP condition, before handing the pins back to Wire.
static void i2c_bus_recover() {
    pinMode(PMIC_SCL, OUTPUT_OPEN_DRAIN);
    pinMode(PMIC_SDA, INPUT_PULLUP);
    digitalWrite(PMIC_SCL, HIGH);
    delayMicroseconds(10);
    for (int i = 0; i < 9 && digitalRead(PMIC_SDA) == LOW; i++) {
        digitalWrite(PMIC_SCL, LOW);  delayMicroseconds(10);
        digitalWrite(PMIC_SCL, HIGH); delayMicroseconds(10);
    }
    // STOP: SDA goes low->high while SCL is high.
    pinMode(PMIC_SDA, OUTPUT_OPEN_DRAIN);
    digitalWrite(PMIC_SDA, LOW);  delayMicroseconds(10);
    digitalWrite(PMIC_SCL, HIGH); delayMicroseconds(10);
    digitalWrite(PMIC_SDA, HIGH); delayMicroseconds(10);
    // Release both lines.
    pinMode(PMIC_SCL, INPUT_PULLUP);
    pinMode(PMIC_SDA, INPUT_PULLUP);
}

// â”€â”€ Power up the AXP2101 PMIC and the e-paper power rails â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
static bool pmic_init() {
    // The AXP2101 only re-inits over I2C after a true power-on reset, never on a
    // deep-sleep timer wake. On a cold boot we try hard (and on success enable
    // the panel rails, which then stay on across sleep). On a wake the AXP is
    // unreachable anyway and the rails are already on from the cold boot, so we
    // try just once quickly and move on instead of burning ~1s every wake.
    const bool fromSleep = (esp_reset_reason() == ESP_RST_DEEPSLEEP);
    const int  attempts  = fromSleep ? 1 : 6;
    bool ok = false;
    for (int i = 0; i < attempts; i++) {
        Wire.end();                     // drop any latched/half-open bus state
        i2c_bus_recover();              // clock out a stuck slave + STOP
        delay(40);
        Wire.begin(PMIC_SDA, PMIC_SCL);
        Wire.setClock(100000);          // be gentle; the bus can be flaky on wake
        if (i == 0) delay(60);          // let the bus settle
        if (PMU.begin(Wire, AXP2101_SLAVE_ADDRESS, PMIC_SDA, PMIC_SCL)) { ok = true; break; }
        if (attempts > 1) logf("PMIC: AXP2101 init attempt %d failed, retrying...\n", i + 1);
        delay(60 + i * 60);             // escalating back-off
    }
    if (!ok) {
        g_pmicReady = false;
        logln(fromSleep ? "PMIC: AXP2101 not re-init on wake (rails stay on from boot)"
                        : "PMIC: AXP2101 init FAILED (giving up)");
        return false;
    }
    // ALDO3/ALDO4 = 3.3V feed the e-paper panel. Without these the panel has
    // no power and BUSY never goes high.
    PMU.setALDO3Voltage(3300); PMU.enableALDO3();
    PMU.setALDO4Voltage(3300); PMU.enableALDO4();

    // Battery operation: configure the AXP2101 as a charger/power-path so the
    // board can run from a 3.7V LiPo and top it up when USB is present.
    PMU.setVbusCurrentLimit(XPOWERS_AXP2101_VBUS_CUR_LIM_2000MA);
    PMU.setSysPowerDownVoltage(2800);  // keep system alive until the cell is low
    PMU.enableBattDetection();
    PMU.enableBattVoltageMeasure();
    PMU.enableVbusVoltageMeasure();
    PMU.enableSystemVoltageMeasure();
    PMU.enableGauge();                 // fuel gauge → battery percent
    // Charging: a precharge step revives a deeply-discharged cell, then constant
    // current up to 4.2V. enableCellbatteryCharge() is the actual charge-enable
    // bit for the main LiPo — without it the battery never tops up.
    PMU.setPrechargeCurr(XPOWERS_AXP2101_PRECHARGE_75MA);
    PMU.setChargerConstantCurr(XPOWERS_AXP2101_CHG_CUR_500MA);
    PMU.setChargeTargetVoltage(XPOWERS_AXP2101_CHG_VOL_4V2);
    PMU.enableCellbatteryCharge();
    delay(120);                      // let the panel rails come up + ADC settle
    g_pmicReady = true;
    return true;
}

// Human-readable AXP2101 charger state.
static const char *charger_status_str() {
    switch (PMU.getChargerStatus()) {
        case XPOWERS_AXP2101_CHG_TRI_STATE:  return "trickle";
        case XPOWERS_AXP2101_CHG_PRE_STATE:  return "pre-charge";
        case XPOWERS_AXP2101_CHG_CC_STATE:   return "constant-current";
        case XPOWERS_AXP2101_CHG_CV_STATE:   return "constant-voltage";
        case XPOWERS_AXP2101_CHG_DONE_STATE: return "charge-done";
        default:                             return "stopped";
    }
}

// Median of several battery-voltage samples (the AXP ADC can spit out an
// occasional wild value; a median throws those out).
static int battery_mv_median() {
    if (!g_pmicReady) return -1;
    int s[5];
    for (int i = 0; i < 5; i++) { s[i] = PMU.getBattVoltage(); delay(25); }
    for (int i = 0; i < 5; i++) for (int j = i + 1; j < 5; j++) if (s[j] < s[i]) { int t = s[i]; s[i] = s[j]; s[j] = t; }
    return s[2];
}

// â”€â”€ Detailed battery / power diagnostics â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// On battery-only the device can't report (no power if the cell is flat), so we
// dump the full power picture here on every boot. It lands in the device logs
// (Settings â†’ Logs) so battery issues are diagnosable without a serial cable.
static void pmic_report() {
    logln("---- battery / power report ----");
    if (!g_pmicReady) {
        logln("  PMIC      : NOT initialised this boot (no readings available)");
        logln("  note      : on a deep-sleep wake the AXP2101 isn't re-read; rails");
        logln("              stay on from the last cold boot. Cold-boot for full data.");
        logln("--------------------------------");
        return;
    }
    const bool battConn = PMU.isBatteryConnect();
    const int  battMv   = battery_mv_median();
    const int  battPct  = PMU.getBatteryPercent();
    const bool charging = PMU.isCharging();
    const bool vbus     = PMU.isVbusIn();
    const int  vbusMv   = PMU.getVbusVoltage();
    const int  sysMv    = PMU.getSystemVoltage();
    const char *cs      = charger_status_str();

    logln("  PMIC      : AXP2101 detected & initialised");
    logf ("  battery   : %s\n", battConn ? "CONNECTED" : "NOT connected");
    logf ("  voltage   : %d mV  (median of 5 reads)\n", battMv);
    logf ("  level     : %d %%  (fuel gauge)\n", battPct);
    logf ("  charger   : %s  (isCharging=%s)\n", cs, charging ? "yes" : "no");
    logf ("  USB/VBUS  : %s  (%d mV)\n", vbus ? "present" : "absent", vbusMv);
    logf ("  system    : %d mV  (rail powering the board)\n", sysMv);
    logln("  charge cfg: target 4.20 V, 500 mA CC, 75 mA precharge, 2 A VBUS limit");

    // Plain-language interpretation so the verdict is obvious.
    if (!battConn || battMv < 2500) {
        logln("  VERDICT   : No usable battery seen (reads ~0).");
        logln("              -> The cell is flat/dead, or the connector is reversed");
        logln("                 or not seated. The board cannot run on battery until");
        logln("                 a charged cell (3.0-4.2 V) is connected the right way.");
    } else if (vbus && (PMU.getChargerStatus() == XPOWERS_AXP2101_CHG_CC_STATE ||
                        PMU.getChargerStatus() == XPOWERS_AXP2101_CHG_CV_STATE ||
                        PMU.getChargerStatus() == XPOWERS_AXP2101_CHG_PRE_STATE)) {
        logf ("  VERDICT   : Charging now (%s). Voltage should climb toward 4200 mV.\n", cs);
        logln("              Leave on USB and watch this number rise over time.");
    } else if (vbus && battMv >= 4100) {
        logln("  VERDICT   : Battery full / charge complete. Safe to run on battery.");
    } else if (vbus && !charging) {
        logln("  VERDICT   : On USB but NOT charging. Charger is stopped/faulted -");
        logln("              check the cell and connector; a deeply-flat cell may");
        logln("              need a known-good replacement.");
    } else if (!vbus) {
        logf ("  VERDICT   : Running on battery, %d mV (%d%%).\n", battMv, battPct);
    }
    logln("--------------------------------");
}

#else  // ── No AXP2101 (e.g. reTerminal E1001): ADC battery, autonomous charger ──
static int read_battery_mv() {
  #if defined(BATT_ADC_GPIO)
    #if defined(BATT_EN_GPIO)
        pinMode(BATT_EN_GPIO, OUTPUT);
        digitalWrite(BATT_EN_GPIO, HIGH);     // enable the voltage divider
        delay(10);
    #endif
        long sum = 0;
        for (int i = 0; i < 8; i++) { sum += analogReadMilliVolts(BATT_ADC_GPIO); delay(2); }
        int mv = (int)(sum / 8) * 2;          // undo the /2 divider (verify ratio on HW)
    #if defined(BATT_EN_GPIO)
        digitalWrite(BATT_EN_GPIO, LOW);      // disable divider again to save power
    #endif
        if (mv >= 2500 && mv <= 4500) { g_lastBattMv = mv; return mv; }
        return g_lastBattMv > 0 ? g_lastBattMv : -1;
  #else
    return -1;
  #endif
}
static bool pmic_init() { g_pmicReady = true; return true; }   // no PMIC; panel directly powered
static void pmic_report() {
    int mv = read_battery_mv();
    logf("---- battery report ----  voltage: %d mV  (ADC)\n", mv > 0 ? mv : 0);
}
#endif // HAS_AXP2101

// â”€â”€ Post device status to server â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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
    Preferences fp; fp.begin("ota", true);
    String fwver = fp.getString("fwver", "");
    fp.end();
    // Charging/USB diagnostics are only available on the AXP2101 boards.
    String chargePart = "";
#if HAS_AXP2101
    if (g_pmicReady)
        chargePart = String(",\"charging\":") + (PMU.isCharging() ? "true" : "false")
                   + ",\"usb\":" + (PMU.isVbusIn() ? "true" : "false")
                   + ",\"battery_pct\":" + String(PMU.getBatteryPercent())
                   + ",\"battery_connected\":" + (PMU.isBatteryConnect() ? "true" : "false")
                   + ",\"vbus_mv\":" + String(PMU.getVbusVoltage())
                   + ",\"sys_mv\":" + String(PMU.getSystemVoltage())
                   + ",\"charge_status\":\"" + charger_status_str() + "\"";
#endif
    String body = "{\"device_id\":\"" + String(device_id) + "\""
                + ",\"wifi_rssi\":"  + rssi
                + ",\"model\":\"" BOARD_MODEL "\""
                + (bat_mv > 0 ? ",\"battery_mv\":" + String(bat_mv) : "")
                + chargePart
                + (fwver.length() ? ",\"firmware_version\":\"" + fwver + "\"" : "")
                + "}";
    int code = http.POST(body);
    logf("Status POST %d\n", code);
    http.end();
}

// Upload the captured log buffer to the server (best effort).
static void flushLogs() {
    if (g_logbuf.length() == 0) return;
    if (WiFi.status() != WL_CONNECTED || cfg.apiKey.length() == 0) return;
    uint8_t mac[6]; esp_read_mac(mac, ESP_MAC_WIFI_STA);
    char device_id[18];
    snprintf(device_id, sizeof(device_id), "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    HTTPClient http;
    String url = String("http://") + cfg.serverHost + ":" + cfg.serverPort
               + "/api/device/log?key=" + cfg.apiKey;
    http.begin(url);
    http.addHeader("Content-Type", "application/json");
    String body = String("{\"device_id\":\"") + device_id + "\",\"log\":\""
                + jsonEscape(g_logbuf) + "\"}";
    http.POST(body);
    http.end();
    g_logbuf = "";
}

// â”€â”€ Deep sleep â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
static void deep_sleep(uint32_t seconds) {
    logf("Deep sleep for %u s\n", seconds);
    flushLogs();
    Serial.flush();
    WiFi.disconnect(true);
    // NOTE: We intentionally leave the e-paper power rails (ALDO3/ALDO4) ON
    // across deep sleep. The AXP2101 reliably re-inits over I2C on a cold boot
    // but NOT on a timer wake, so if we cut the rails here we can never turn
    // them back on next wake and the panel stays dark. Leaving them powered
    // costs a little sleep current but guarantees the display works every wake.
    // (The image itself persists on e-ink with or without power.)
    esp_sleep_enable_timer_wakeup((uint64_t)seconds * 1000000ULL);
    // Also wake when KEY1 is pressed, so a button press is instant. Hold the pin
    // at its rest level during sleep (internal pulls are off otherwise) and wake
    // on the pressed level. This board's KEY1 is active-LOW, so rest = pull-up
    // and wake on LOW.
    if (KEY1_GPIO >= 0) {
        if (KEY1_ACTIVE_LEVEL == HIGH) { rtc_gpio_pulldown_en((gpio_num_t)KEY1_GPIO); rtc_gpio_pullup_dis((gpio_num_t)KEY1_GPIO); }
        else                           { rtc_gpio_pullup_en((gpio_num_t)KEY1_GPIO);   rtc_gpio_pulldown_dis((gpio_num_t)KEY1_GPIO); }
        esp_sleep_enable_ext0_wakeup((gpio_num_t)KEY1_GPIO, KEY1_ACTIVE_LEVEL);
    }
    esp_deep_sleep_start();
}

// â”€â”€ KEY1 button finder â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// One-time helper: watch the free RTC-capable GPIOs and report which one drops
// LOW when KEY1 is pressed, so we learn the pin from the actual board. Only
// reads pins (never drives them), so it can't disturb the panel/PMIC.
static void find_key1() {
    // All general-purpose GPIOs except the ones already in use (EPD 8-13, BOOT 0,
    // USB 19/20, flash/PSRAM 26-37, LED 45, I2C 47/48, UART 43/44). We only READ
    // these (with a pull-up), so it can't disturb anything.
    static const int cands[] = {1, 2, 3, 4, 5, 6, 7, 14, 15, 16, 17, 18, 21,
                                38, 39, 40, 41, 42, 46};
    const int N = sizeof(cands) / sizeof(cands[0]);
    int  rest[24];
    bool noisy[24] = {false};
    for (int i = 0; i < N; i++) pinMode(cands[i], INPUT_PULLUP);
    delay(50);
    for (int i = 0; i < N; i++) rest[i] = digitalRead(cands[i]);

    // STAGE 1: watch ~8s with NO press. Any pin that changes on its own is a live
    // signal (like GPIO 4), not a button — flag it so stage 2 ignores it.
    logln("KEY1 finder STAGE 1: do NOT touch the button (checking noise, 8s)...");
    uint32_t t0 = millis();
    while (millis() - t0 < 8000) {
        for (int i = 0; i < N; i++) if (digitalRead(cands[i]) != rest[i]) noisy[i] = true;
        delay(5);
    }
    String nl = "";
    for (int i = 0; i < N; i++) if (noisy[i]) { nl += ' '; nl += cands[i]; }
    logf("KEY1 finder: noisy pins ignored:%s\n", nl.length() ? nl.c_str() : " none");
    for (int i = 0; i < N; i++) rest[i] = digitalRead(cands[i]);   // refresh rest level

    // STAGE 2: now press & hold KEY1. Report a STABLE pin that changes.
    logln("KEY1 finder STAGE 2: now press & hold KEY1 (10s)...");
    t0 = millis();
    int found = -1, dir = HIGH;
    while (millis() - t0 < 10000 && found < 0) {
        for (int i = 0; i < N; i++) {
            if (noisy[i]) continue;
            int v = digitalRead(cands[i]);
            if (v != rest[i]) {
                delay(40);                      // debounce
                if (digitalRead(cands[i]) == v) { found = cands[i]; dir = v; break; }
            }
        }
        delay(8);
    }
    for (int i = 0; i < N; i++) pinMode(cands[i], INPUT);
    if (found >= 0)
        logf("KEY1 finder: >>> detected on GPIO %d <<< (goes %s when pressed; RTC-wake capable: %s)\n",
             found, dir == LOW ? "LOW" : "HIGH", found <= 21 ? "yes" : "NO");
    else
        logln("KEY1 finder: no clean button seen — re-run: hands OFF in stage 1, hold in stage 2");
}

// â”€â”€ Clear NVS config â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
static void clearConfig() {
    Preferences p;
    p.begin("photodisplay", false);
    p.clear();
    p.end();
}

// â”€â”€ Fetch a JPEG URL and render it to the panel ──────────────────────────
static bool fetchAndShow(const String &url) {
    HTTPClient http;
    http.begin(url);
    if (http.GET() != 200) { http.end(); return false; }
    int total = http.getSize();
    WiFiClient *stream = http.getStreamPtr();
    size_t len = 0;
    while (http.connected() && (total < 0 || len < (size_t)total)) {
        int avail = stream->available();
        if (avail > 0) {
            int room = (int)(JPEG_BUF_SIZE - len);
            if (room <= 0) break;
            len += stream->readBytes(jpeg_buf + len, min(room, avail));
        } else {
            delay(1);
        }
    }
    http.end();
    if (len == 0) return false;
    memset(rgb_buf, 0, EPD_W * EPD_H * 3);
    if (!jpeg.openRAM(jpeg_buf, (int)len, jpegDraw)) return false;
    jpeg.setPixelType(RGB565_LITTLE_ENDIAN);
    jpeg.decode(0, 0, 0);
    jpeg.close();
    dither_and_pack();
    epd_init();
    epd_display(epd_buf);
    epd_sleep_mode();
    return true;
}

// Show a server-rendered status screen (paired/empty/sleeping/etc). Returns
// false if it can't be fetched, so the caller can fall back to a local screen.
static bool showServerScreen(const char *state) {
    if (cfg.apiKey.length() == 0) return false;
    uint8_t mac[6]; esp_read_mac(mac, ESP_MAC_WIFI_STA);
    char id[18];
    snprintf(id, sizeof(id), "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    int mv  = read_battery_mv();
    int pct = mv > 0 ? constrain((mv - 3300) * 100 / (4200 - 3300), 0, 100) : -1;
    Preferences fp; fp.begin("ota", true);
    String fw = fp.getString("fwver", "");
    fp.end();
    String url = String("http://") + cfg.serverHost + ":" + cfg.serverPort
               + "/api/device/screen?key=" + cfg.apiKey + "&state=" + state
               + "&id=" + id + "&rssi=" + WiFi.RSSI();
    if (pct >= 0)       url += "&batt=" + String(pct);
    if (fw.length())    url += "&fw=" + fw;
    return fetchAndShow(url);
}

// â”€â”€ OTA firmware update â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Ask the server which firmware version it has; if it differs from the version
// we last applied, download and flash it (the device reboots on success). A
// freshly hand-flashed device "adopts" the server version without re-flashing.
static void otaCheck() {
    const String base = String("http://") + cfg.serverHost + ":" + cfg.serverPort;
    Preferences p;
    p.begin("ota", false);
    String applied = p.getString("fwver", "");

    HTTPClient http;
    http.begin(base + "/api/device/firmware?key=" + cfg.apiKey + "&current=" + applied
               + "&model=" BOARD_MODEL);
    if (http.GET() != 200) { http.end(); p.end(); return; }
    String resp = http.getString(); http.end();
    String version = jsonStr(resp, "version");
    String url     = jsonStr(resp, "url");
    String update  = jsonStr(resp, "update");
    if (version.length() == 0 || url.length() == 0) { p.end(); return; }

    if (applied.length() == 0) {                 // adopt current build, no flash
        p.putString("fwver", version);
        p.end();
        logf("OTA: adopting version %s\n", version.c_str());
        return;
    }
    if (update != "yes" || version == applied) {
        p.end();
        logln(version == applied ? "OTA: up to date" : "OTA: update available (not enabled)");
        return;
    }

    logf("OTA: updating %s -> %s\n", applied.c_str(), version.c_str());
    // Show the "Updating firmware" screen so it's clear what's happening, and
    // leave a flag so the next boot can show an "Update complete" confirmation.
    showServerScreen("updating");
    p.putBool("didupd", true);
    p.putString("fwver", version);               // optimistic; revert on failure
    p.end();
    flushLogs();                                  // get the pre-update log out first

    WiFiClient client;
    httpUpdate.rebootOnUpdate(true);
    t_httpUpdate_return r = httpUpdate.update(client, url);
    if (r == HTTP_UPDATE_FAILED) {                // reverts so we retry next wake
        logf("OTA failed (%d): %s\n", httpUpdate.getLastError(),
             httpUpdate.getLastErrorString().c_str());
        Preferences p2; p2.begin("ota", false);
        p2.putString("fwver", applied);
        p2.putBool("didupd", false);             // update didn't happen
        p2.end();
    }
    // HTTP_UPDATE_OK reboots automatically into the new firmware.
}

// â”€â”€ QR device pairing â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Request a pairing token, show a QR + code on the panel, then poll until the
// user links this device to a screen. On success the API key is saved to NVS.
static bool pairDevice() {
    uint8_t mac[6]; esp_read_mac(mac, ESP_MAC_WIFI_STA);
    char hwId[18];
    snprintf(hwId, sizeof(hwId), "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    const String base = String("http://") + cfg.serverHost + ":" + cfg.serverPort;

    HTTPClient http;
    http.begin(base + "/api/devices/pair/request");
    http.addHeader("Content-Type", "application/json");
    int code = http.POST(String("{\"hwId\":\"") + hwId + "\",\"model\":\"" BOARD_MODEL "\"}");
    if (code != 200) { logf("pair/request HTTP %d\n", code); http.end(); return false; }
    String resp = http.getString(); http.end();

    String token   = jsonStr(resp, "token");
    String pcode   = jsonStr(resp, "code");
    String pairUrl = jsonStr(resp, "pairUrl");
    if (token.length() == 0) { logln("pair: no token"); return false; }
    logf("Pairing code %s  url %s\n", pcode.c_str(), pairUrl.c_str());
    epd_show_pairing(pcode.c_str(), pairUrl.c_str());

    const int MAX_POLLS = 150;            // ~10 min at 4s each
    for (int i = 0; i < MAX_POLLS; i++) {
        delay(4000);
        HTTPClient h2;
        h2.begin(base + "/api/devices/pair/" + token);
        if (h2.GET() == 200) {
            String r2 = h2.getString(); h2.end();
            String st = jsonStr(r2, "status");
            if (st == "complete") {
                String key = jsonStr(r2, "apiKey");
                if (key.length() > 0) {
                    cfg.apiKey = key;
                    saveConfig(cfg);
                    logln("Paired â€” API key saved");
                    return true;
                }
            } else if (st == "expired") {
                logln("Pairing token expired");
                return false;
            }
        } else {
            h2.end();
        }
    }
    logln("Pairing timed out");
    return false;
}

// â”€â”€ setup â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
void setup() {
    Serial.begin(115200);
    delay(300);
    logln("\n=== PhotoDock ===");

    // Allocate display buffers and init hardware first so we can show screens anywhere
    epd_buf  = (uint8_t *)ps_malloc(EPD_BUF_SIZE);
    jpeg_buf = (uint8_t *)ps_malloc(JPEG_BUF_SIZE);
    rgb_buf  = (uint8_t *)ps_malloc(EPD_W * EPD_H * 3);
    if (!epd_buf || !jpeg_buf || !rgb_buf) { logln("PSRAM alloc failed"); deep_sleep(60); }
    memset(epd_buf, 0x11, EPD_BUF_SIZE);

    // Bring up the PMIC first â€” it powers the e-paper panel. The retrying
    // bus-reset init below handles the latched-I2C-after-wake problem. If it
    // still can't bring the PMIC up we just carry on: the device stays online
    // (it still reports status), the panel simply isn't refreshed this cycle,
    // and the next timer wake tries again. We deliberately do NOT reboot here â€”
    // a reboot mid-cycle risks dropping into the setup portal and never coming
    // back until a manual power cycle.
    if (!pmic_init()) {
        logln("PMIC: not ready, continuing without panel power (will retry next wake)");
    }
    pmic_report();   // detailed battery/power diagnostics into the device logs

    // â”€â”€ KEY1 button â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    // If KEY1 isn't mapped yet, discover its GPIO on a cold boot. Once mapped,
    // a short press advances to the next photo and a 5s hold toggles sleep.
    if (KEY1_GPIO < 0) {
        g_manualSleep = false;   // feature disabled — clear any stuck sleep state
        if (esp_reset_reason() != ESP_RST_DEEPSLEEP) find_key1();
    } else if (esp_sleep_get_wakeup_cause() == ESP_SLEEP_WAKEUP_EXT0) {
        rtc_gpio_deinit((gpio_num_t)KEY1_GPIO);   // hand the pad back to normal GPIO
        pinMode(KEY1_GPIO, KEY1_ACTIVE_LEVEL == LOW ? INPUT_PULLUP : INPUT);
        delay(30);
        // The EXT0 wake itself proves KEY1 was pressed: during sleep the pin is
        // held at its rest level by an internal pull, so only a real press can
        // drive it to the wake level. We therefore do NOT require the button to
        // still be held — a quick tap is usually already released by the time we
        // boot this far (battery sampling etc. takes a few hundred ms). We only
        // sample how long it is *still* held to tell a short tap (next photo)
        // from a long hold (toggle sleep).
        uint32_t t0 = millis();
        while (digitalRead(KEY1_GPIO) == KEY1_ACTIVE_LEVEL && millis() - t0 < KEY1_LONG_PRESS_MS + 500) delay(10);
        uint32_t held = millis() - t0;
        if (held >= KEY1_LONG_PRESS_MS) {
            g_manualSleep = !g_manualSleep;
            logf("KEY1: long press (%ums) -> manual sleep %s\n", held, g_manualSleep ? "ON" : "OFF");
        } else {
            g_manualOffset++;            // advance one photo
            g_manualSleep = false;       // a tap also wakes from manual sleep
            logf("KEY1: short press -> next photo (offset %d)\n", g_manualOffset);
        }
    }

    pinMode(EPD_CS,   OUTPUT); digitalWrite(EPD_CS,   HIGH);
    pinMode(EPD_DC,   OUTPUT);
    pinMode(EPD_RST,  OUTPUT); digitalWrite(EPD_RST,  HIGH);
    pinMode(EPD_BUSY, INPUT_PULLUP);
    SPI.begin(EPD_CLK, -1, EPD_MOSI, EPD_CS);
    SPI.beginTransaction(SPISettings(10000000, MSBFIRST, SPI_MODE0));

    // Reconfigure trigger: press & hold BOOT (GPIO 0) within the first few
    // seconds *after* a normal boot. (GPIO0 cannot be read at power-on on the
    // ESP32-S3 â€” holding it low at reset enters ROM download mode and the app
    // never runs. So we watch it briefly once the app is already executing.)
    // Only do this on a real power-on: on an unattended deep-sleep timer wake
    // nobody is here to hold BOOT, and spending 3s of full-power CPU watching it
    // every single wake is a big, pointless battery drain.
    if (esp_reset_reason() != ESP_RST_DEEPSLEEP) {
        pinMode(0, INPUT_PULLUP);
        const uint32_t WINDOW_MS = 3000;   // how long to watch after boot
        const uint32_t HOLD_MS   = 800;    // how long BOOT must stay pressed
        logf("Press BOOT within %u ms to reconfigure...\n", WINDOW_MS);
        uint32_t windowStart = millis();
        uint32_t pressStart  = 0;
        while (millis() - windowStart < WINDOW_MS) {
            if (digitalRead(0) == LOW) {
                if (pressStart == 0) pressStart = millis();
                if (millis() - pressStart >= HOLD_MS) {
                    logln("BOOT held â€” clearing config, starting portal");
                    clearConfig();
                    String ap = apNameFromMac();
                    epd_show_setup(ap.c_str());
                    startCaptivePortal(); // never returns
                }
            } else {
                pressStart = 0; // released â€” reset the hold timer
            }
            delay(10);
        }
    }

    cfg = loadConfig();

    bool firstBoot = false;
    if (!configComplete(cfg)) {
        // Auto mode: WiFi/server baked in at compile time. The API key is
        // optional â€” if it's empty the device falls through to QR pairing.
        if (strlen(DEFAULT_WIFI_SSID) > 0 && strlen(DEFAULT_SERVER_HOST) > 0) {
            cfg.wifiSsid     = String(DEFAULT_WIFI_SSID);
            cfg.wifiPassword = String(DEFAULT_WIFI_PASS);
            cfg.serverHost   = String(DEFAULT_SERVER_HOST);
            cfg.serverPort   = DEFAULT_SERVER_PORT;
            cfg.apiKey       = String(DEFAULT_API_KEY);
            saveConfig(cfg);
            firstBoot = true;
            logln("Loaded compile-time config");
        } else {
            logln("No config â€” starting setup portal");
            String ap = apNameFromMac();
            epd_show_setup(ap.c_str());
            startCaptivePortal();
        }
    }

    logf("WiFi: connecting to %s", cfg.wifiSsid.c_str());
    WiFi.persistent(false);
    WiFi.mode(WIFI_STA);
    // Fast path: reuse the AP's channel + BSSID from last wake to skip scanning.
    if (g_wifiHint && g_wifiChan > 0)
        WiFi.begin(cfg.wifiSsid.c_str(), cfg.wifiPassword.c_str(), g_wifiChan, g_wifiBssid);
    else
        WiFi.begin(cfg.wifiSsid.c_str(), cfg.wifiPassword.c_str());
    for (int i = 0; i < 24 && WiFi.status() != WL_CONNECTED; i++) {
        delay(250); logp(".");
    }
    // If the cached AP didn't work (moved channel, etc.), fall back to a scan.
    if (WiFi.status() != WL_CONNECTED && g_wifiHint) {
        g_wifiHint = false;
        WiFi.disconnect(true);
        WiFi.begin(cfg.wifiSsid.c_str(), cfg.wifiPassword.c_str());
        for (int i = 0; i < 30 && WiFi.status() != WL_CONNECTED; i++) {
            delay(500); logp(".");
        }
    }
    if (WiFi.status() != WL_CONNECTED) {
        // A device that's still being set up should open the portal so the user
        // can enter credentials. But an already-configured device that just
        // can't reach WiFi this wake (router reboot, transient outage) must NOT
        // get stuck in the AP portal forever â€” it should sleep and retry so it
        // recovers on its own without a manual reboot.
        if (firstBoot) {
            logln("\nWiFi failed on first boot â€” starting setup portal");
            String ap = apNameFromMac();
            epd_show_setup(ap.c_str());
            startCaptivePortal();
        }
        logln("\nWiFi failed â€” sleeping and retrying next wake");
        deep_sleep(60);
    }
    logf("\nIP: %s\n", WiFi.localIP().toString().c_str());

    // Remember which AP we connected to so the next wake can skip the scan.
    {
        uint8_t *b = WiFi.BSSID();
        if (b) { memcpy(g_wifiBssid, b, 6); g_wifiChan = WiFi.channel(); g_wifiHint = true; }
    }

    // No API key yet â†’ run the QR pairing flow to obtain one.
    if (cfg.apiKey.length() == 0) {
        logln("No API key â€” starting QR pairing");
        if (!pairDevice()) { logln("Pairing not completed; retry after sleep"); deep_sleep(120); }
    }

    // If we just rebooted from a completed OTA update, show an "Update complete"
    // confirmation for 10 seconds so it's clear the update landed.
    {
        Preferences pu; pu.begin("ota", false);
        bool didUpdate = pu.getBool("didupd", false);
        if (didUpdate) pu.putBool("didupd", false);
        pu.end();
        if (didUpdate) {
            logln("OTA: update complete â€” showing confirmation");
            showServerScreen("updated");
            delay(10000);
        }
    }

    // Check for a newer firmware and self-update (reboots on success).
    otaCheck();

    // Report in early so the dashboard shows the device as online and knows its
    // firmware version, even if this screen has no photos yet.
    post_status(0);

    uint32_t sleep_s = DEFAULT_SLEEP_S;
    bool nowSleeping = false;
    bool debugLogging = false;   // when set by the server, keep WiFi on through the refresh
    {
        HTTPClient http;
        String url = String("http://") + cfg.serverHost + ":" + cfg.serverPort
                   + "/api/slideshow/current?key=" + cfg.apiKey
                   + "&offset=" + g_manualOffset;   // KEY1 short-press advances this
        http.begin(url);
        if (http.GET() == 200) {
            String body = http.getString();
            // Scheduled sleep window: server tells us to show the sleeping screen
            // and sleep until the wake time (carried in next_in_ms).
            nowSleeping = body.indexOf("\"sleeping\":true") >= 0;
            // Debug mode (toggled from the dashboard): keep the radio on through
            // the refresh so the decode/display logs reach the server.
            debugLogging = body.indexOf("\"debug\":true") >= 0;
            // Base the sleep on the screen's configured refresh interval, so a
            // missing/too-small next_in_ms falls back to the user's setting
            // (e.g. 1 min) instead of the hardcoded 5-minute default.
            int im = body.indexOf("\"interval_minutes\":");
            if (im >= 0) {
                long mins = body.substring(im + 19).toInt();
                if (mins > 0) sleep_s = (uint32_t)mins * 60;
            }
            // Prefer the precise time to the next slot boundary when it's a
            // meaningful amount (keeps multiple devices in sync).
            int idx = body.indexOf("\"next_in_ms\":");
            if (idx >= 0) {
                long ms = body.substring(idx + 13).toInt();
                if (ms > 5000) sleep_s = (uint32_t)(ms / 1000);
            }
        }
        http.end();
    }
    // Reference point for aligning the next wake to the exact minute/hour: the
    // server's next_in_ms is the time to the next slot boundary measured now, so
    // we subtract however long the image fetch + refresh takes before sleeping.
    uint32_t tRefMs = millis();

    // Sleeping: either the server's scheduled window, or a manual KEY1 long-press
    // toggle. Show the "Sleeping" screen once, then sleep — wakeable by KEY1.
    if (nowSleeping || g_manualSleep) {
        if (!g_sleepShown) { showServerScreen("sleeping"); g_sleepShown = true; }
        // Manual sleep waits mostly for the button; cap at 1h so it still checks
        // in. Scheduled sleep runs until the wake time (capped at 6h).
        uint32_t chunk = g_manualSleep ? 3600 : (sleep_s > 21600 ? 21600 : sleep_s);
        logf("Sleeping (%s) for %u s\n", g_manualSleep ? "manual KEY1" : "schedule", chunk);
        deep_sleep(chunk);                                    // never returns
    }
    g_sleepShown = false;   // not sleeping any more â€” allow a re-render next time

    size_t jpeg_len = 0;
    {
        HTTPClient http;
        String url = String("http://") + cfg.serverHost + ":" + cfg.serverPort
                   + "/api/slideshow/image?key=" + cfg.apiKey
                   + "&width=" + EPD_W + "&height=" + EPD_H
                   + "&offset=" + g_manualOffset;   // KEY1 short-press advances this
        http.begin(url);
        int code = http.GET();
        if (code != 200) {
            logf("HTTP %d\n", code);
            http.end();
            if (code == 404) {
                // Reached the server fine — the screen just has no photos yet.
                logln("No photos assigned to this screen");
                if (!showServerScreen("empty")) epd_show_no_photos();
                deep_sleep(sleep_s);
            }
            // Genuine connection/server problem.
            epd_show_error(cfg.serverHost.c_str(), cfg.serverPort);
            if (firstBoot) {
                logln("Server unreachable on first boot â€” starting portal");
                clearConfig();
                String ap = apNameFromMac();
                epd_show_setup(ap.c_str());
                startCaptivePortal();
            }
            deep_sleep(sleep_s);
        }
        WiFiClient *stream = http.getStreamPtr();
        int total = http.getSize();
        logf("JPEG: %d bytes\n", total);
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

    // The e-ink refresh below takes ~15-25s and doesn't need the network. Power
    // the radio down so it isn't drawing current through the whole refresh — one
    // of the biggest per-wake battery savings. In debug mode we keep it on so the
    // decode/display logs are flushed to the server (deep_sleep flushes them).
    if (!debugLogging) {
        flushLogs();
        WiFi.disconnect(true);
        WiFi.mode(WIFI_OFF);
    }

    memset(rgb_buf, 0, EPD_W * EPD_H * 3);   // black where the image doesn't cover
    if (jpeg.openRAM(jpeg_buf, (int)jpeg_len, jpegDraw)) {
        jpeg.setPixelType(RGB565_LITTLE_ENDIAN);
        if (!jpeg.decode(0, 0, 0)) logln("JPEG decode error");
        else                        logln("JPEG decoded");
        jpeg.close();
        dither_and_pack();           // quantize + dither into epd_buf
        logln("Dithered to 6 colors");
    } else {
        logln("JPEG open failed");
    }

    epd_init();
    epd_display(epd_buf);
    epd_sleep_mode();

    // Subtract the time spent fetching + refreshing so we wake on the slot
    // boundary (exact minute/hour) rather than drifting later each cycle.
    uint32_t elapsed_s = (millis() - tRefMs) / 1000;
    uint32_t final_s   = (sleep_s > elapsed_s + 2) ? (sleep_s - elapsed_s) : 5;
    deep_sleep(final_s);
}

void loop() {}

