# Terminal Photo Display — Email Templates

One self-contained HTML file per email, in light and dark. All styles are inline + table-based (Gmail / Outlook / Apple Mail safe). Drop into your mailer and replace the placeholder values.

## Files

- **Low battery** (Device alerts) — `low_battery.light.html`, `low_battery.dark.html`
  - Subject: Living Room Frame is low on battery (9%)
- **Device offline** (Device alerts) — `offline.light.html`, `offline.dark.html`
  - Subject: Kitchen Display went offline
- **User invite** (Account & access) — `invite.light.html`, `invite.dark.html`
  - Subject: Mischa invited you to a photo display library
- **Back online** (Device alerts) — `back_online.light.html`, `back_online.dark.html`
  - Subject: Kitchen Display is back online
- **Device paired** (Device alerts) — `paired.light.html`, `paired.dark.html`
  - Subject: Studio Frame is connected and ready
- **Storage almost full** (Server health) — `storage.light.html`, `storage.dark.html`
  - Subject: Your photo server is almost out of storage (94%)
- **Firmware update** (Server health) — `firmware.light.html`, `firmware.dark.html`
  - Subject: Firmware 1.17.0 is available for Hallway Frame
- **Password reset** (Account & access) — `password_reset.light.html`, `password_reset.dark.html`
  - Subject: Reset your Terminal Photo Display password

## Placeholders to replace

- Device name / model (e.g. "Living Room Frame", "TRMNL 7.5\" e-ink")
- Battery %, WiFi status, last-seen timestamp
- Dashboard URL (currently `https://photos.home.local`) on every button + footer links
- Invite: inviter name, library name, role, accept link
- Password reset: verification code, account email, timestamp, IP, reset link
- Sender address in the From header

## How the values are styled

Colors follow the design system's health palette: green = good, amber = warning, red = critical, cyan = neutral/primary. The hero icon + accent bar color change per alert type.
