#pragma once
// ─────────────────────────────────────────────────────────────────────────────
// Board abstraction. One of BOARD_PHOTOPAINTER / BOARD_RETERMINAL_E1001 is set
// by the PlatformIO build flag (-D...). This header defines the per-board pin
// map, panel type and capability flags the rest of the firmware keys off of.
// ─────────────────────────────────────────────────────────────────────────────

#if !defined(BOARD_PHOTOPAINTER) && !defined(BOARD_RETERMINAL_E1001)
  #define BOARD_PHOTOPAINTER          // default target
#endif

// Both panels are 800 x 480 landscape.
#define EPD_W 800
#define EPD_H 480

// ── Waveshare ESP32-S3 PhotoPainter (7.3" E6 Spectra 6) ──────────────────────
#if defined(BOARD_PHOTOPAINTER)
  #define BOARD_MODEL        "PhotoPainter-E6"
  #define PANEL_E6           1          // 6-colour Spectra 6
  #define HAS_AXP2101        1          // AXP2101 PMIC powers the panel rails

  // E-paper SPI + control
  #define EPD_DC    8
  #define EPD_CS    9
  #define EPD_CLK   10
  #define EPD_MOSI  11
  #define EPD_RST   12
  #define EPD_BUSY  13

  // AXP2101 PMIC I2C
  #define PMIC_SDA  47
  #define PMIC_SCL  48

  // KEY button (active-low, pull-up) — short press = next photo, hold = sleep
  #define KEY1_GPIO          4
  #define KEY1_ACTIVE_LEVEL  LOW
  #define KEY1_LONG_PRESS_MS 5000

// ── Seeed reTerminal E1001 (7.5" UC8179 monochrome, 4-level grayscale) ───────
#elif defined(BOARD_RETERMINAL_E1001)
  #define BOARD_MODEL        "reTerminal-E1001"
  #define PANEL_UC8179       1          // Ultrachip UC8179 / GDEW075T7
  // Phase 1: bring the panel up in black & white (simple, high-confidence) to
  // validate pins/SPI/refresh on real hardware. Phase 2 flips on PANEL_GRAY4 for
  // 4-level grayscale once B/W is confirmed working.
  // #define PANEL_GRAY4     1
  // no AXP2101 — SY6974B charger is autonomous; battery read via ADC

  // E-paper SPI + control (from Seeed's board definition)
  #define EPD_CLK   7
  #define EPD_MOSI  9
  #define EPD_CS    10
  #define EPD_DC    11
  #define EPD_RST   12
  #define EPD_BUSY  13

  // Buttons (all active-low, pull-up). The center "refresh" key is our KEY1.
  #define KEY1_GPIO          3          // refresh  -> next photo / hold = sleep
  #define KEY_LEFT_GPIO      4
  #define KEY_RIGHT_GPIO     5
  #define KEY1_ACTIVE_LEVEL  LOW
  #define KEY1_LONG_PRESS_MS 5000

  // Status LED + battery sense
  #define LED_GPIO           6          // green LED (active-low)
  #define BATT_EN_GPIO       21         // enables the battery voltage divider
  #define BATT_ADC_GPIO      1          // ADC1_CH0 (verify on hardware)
#endif
