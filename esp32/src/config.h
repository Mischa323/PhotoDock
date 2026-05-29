#pragma once
#define DEFAULT_SLEEP_S         (5 * 60)
#define BATTERY_ADC_PIN         4
#define BATTERY_DIVIDER_RATIO   2.0f
#define JPEG_BUF_SIZE           (512 * 1024)
// Leave SSID/API key empty to force the on-device WiFi setup portal on first boot.
// Fill them in only if you want to bake credentials into the firmware ("auto mode").
#define DEFAULT_WIFI_SSID       ""
#define DEFAULT_WIFI_PASS       ""
#define DEFAULT_SERVER_HOST     ""
#define DEFAULT_SERVER_PORT     8080
#define DEFAULT_API_KEY         ""
