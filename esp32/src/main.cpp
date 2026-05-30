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
#include <esp_mac.h>
#include "JPEGDEC.h"
#include "config.h"

#define XPOWERS_CHIP_AXP2101
#include "XPowersLib.h"
#include "qrcode.h"

// â”€â”€ Pin mapping â€” Waveshare ESP32-S3-PhotoPainter (7.3" E6) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Values taken from Waveshare's official factory source (bsp_config.h).
#define EPD_DC    8
#define EPD_CS    9
#define EPD_CLK   10
#define EPD_MOSI  11
#define EPD_RST   12
#define EPD_BUSY  13

// I2C bus to the AXP2101 PMIC (which powers the e-paper panel)
#define PMIC_SDA  47
#define PMIC_SCL  48

static XPowersPMU PMU;

// â”€â”€ Display dimensions â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
#define EPD_W        800
#define EPD_H        480
#define EPD_BUF_SIZE (EPD_W * EPD_H / 2)

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
    snprintf(apName, sizeof(apName), "PhotoDisplay-%02X%02X", mac[4], mac[5]);

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
    epd_cmd(0x04);                  // power on
    epd_busy_wait(8000);            // power-up is fast
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
    char buf[24]; snprintf(buf, sizeof(buf), "PhotoDisplay-%02X%02X", mac[4], mac[5]);
    return String(buf);
}

// Show the WiFi setup portal screen on the e-ink display
static void epd_show_setup(const char *apName) {
    epd_fill(C_WHITE);                                        // white bg
    epd_rect(0, 0, EPD_W, 64, C_BLUE);                        // blue header
    epd_text(16, 12, "Photo Display Setup", C_WHITE, C_BLUE, 3);
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
    epd_text(24, 170, "Open Photo Display, go to this", C_BLACK, C_WHITE, 2);
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
    epd_text(24, 122, "the Photo Display site and", C_BLACK, C_WHITE, 2);
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

// â”€â”€ Battery voltage reading (via AXP2101 PMIC) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
static int read_battery_mv() {
    int mv = PMU.getBattVoltage();
    return mv > 0 ? mv : -1;
}

// â”€â”€ Power up the AXP2101 PMIC and the e-paper power rails â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
static bool pmic_init() {
    Wire.begin(PMIC_SDA, PMIC_SCL);
    Wire.setClock(100000);          // be gentle; the bus can be flaky on wake
    // The AXP2101 (and the I2C bus) can need a moment to settle after a deep-
    // sleep wake, so retry a few times instead of giving up on one bad attempt.
    bool ok = false;
    for (int i = 0; i < 8; i++) {
        if (PMU.begin(Wire, AXP2101_SLAVE_ADDRESS, PMIC_SDA, PMIC_SCL)) { ok = true; break; }
        logf("PMIC: AXP2101 init attempt %d failed, retrying...\n", i + 1);
        delay(120);
    }
    if (!ok) {
        logln("PMIC: AXP2101 init FAILED (giving up)");
        return false;
    }
    // ALDO3/ALDO4 = 3.3V feed the e-paper panel. Without these the panel has
    // no power and BUSY never goes high.
    PMU.setALDO3Voltage(3300); PMU.enableALDO3();
    PMU.setALDO4Voltage(3300); PMU.enableALDO4();
    PMU.enableBattVoltageMeasure();
    delay(80);                       // let the panel rails come up
    logln("PMIC: AXP2101 ready, panel rails on");
    return true;
}

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
    String body = "{\"device_id\":\"" + String(device_id) + "\""
                + ",\"wifi_rssi\":"  + rssi
                + (bat_mv > 0 ? ",\"battery_mv\":" + String(bat_mv) : "")
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
    // Cut the e-paper power rails â€” the image persists on e-ink without power.
    PMU.disableALDO3();
    PMU.disableALDO4();
    esp_sleep_enable_timer_wakeup((uint64_t)seconds * 1000000ULL);
    esp_deep_sleep_start();
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
    http.begin(base + "/api/device/firmware?key=" + cfg.apiKey + "&current=" + applied);
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
    int code = http.POST(String("{\"hwId\":\"") + hwId + "\",\"model\":\"PhotoPainter-E6\"}");
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
    logln("\n=== PhotoDisplay ===");

    // Allocate display buffers and init hardware first so we can show screens anywhere
    epd_buf  = (uint8_t *)ps_malloc(EPD_BUF_SIZE);
    jpeg_buf = (uint8_t *)ps_malloc(JPEG_BUF_SIZE);
    rgb_buf  = (uint8_t *)ps_malloc(EPD_W * EPD_H * 3);
    if (!epd_buf || !jpeg_buf || !rgb_buf) { logln("PSRAM alloc failed"); deep_sleep(60); }
    memset(epd_buf, 0x11, EPD_BUF_SIZE);

    // Bring up the PMIC first â€” it powers the e-paper panel.
    pmic_init();

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
    pinMode(0, INPUT_PULLUP);
    {
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
    WiFi.begin(cfg.wifiSsid.c_str(), cfg.wifiPassword.c_str());
    for (int i = 0; i < 30 && WiFi.status() != WL_CONNECTED; i++) {
        delay(500); logp(".");
    }
    if (WiFi.status() != WL_CONNECTED) {
        logln("\nWiFi failed â€” starting setup portal");
        String ap = apNameFromMac();
        epd_show_setup(ap.c_str());
        startCaptivePortal();
    }
    logf("\nIP: %s\n", WiFi.localIP().toString().c_str());

    // No API key yet â†’ run the QR pairing flow to obtain one.
    if (cfg.apiKey.length() == 0) {
        logln("No API key â€” starting QR pairing");
        if (!pairDevice()) { logln("Pairing not completed; retry after sleep"); deep_sleep(120); }
    }

    // Check for a newer firmware and self-update (reboots on success).
    otaCheck();

    // Report in early so the dashboard shows the device as online and knows its
    // firmware version, even if this screen has no photos yet.
    post_status(0);

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
    deep_sleep(sleep_s);
}

void loop() {}

