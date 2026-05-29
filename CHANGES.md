# Per-screen colour — change summary

Adds a **colour** to each screen (server-side, shared across devices/views) and surfaces it in the UI.

## Files changed
- `server.js`
- `index.html`
- `screens.html`

> ⚠️ Base these on your **local** working copy (the one with the screens/albums feature), **not** GitHub `main` — `main` is older and doesn't have screens/albums yet. These edits were made against your local files.

---

## server.js  (backend — source of truth)
- Added a curated palette constant:
  ```js
  const SCREEN_COLORS = ['#06b6d4','#d97706','#22c55e','#a855f7','#f43f5e','#3b82f6','#eab308','#ec4899'];
  ```
- `GET /api/screens` — now returns `color` for each screen (falls back to `SCREEN_COLORS[0]` for screens created before this change).
- `POST /api/screens` — accepts `color`; validates it against the palette; if missing/invalid, auto-assigns the next palette colour by screen count.
- `PUT /api/screens/:id` — accepts `color` and updates it (validated against the palette).

No data migration needed: existing screens render with the fallback colour until edited.

## index.html  (photo library front page)
- New CSS for colour-driven screen tabs: each screen tab shows a colour dot; the **active** tab fills with its screen colour (via a `--screen-color` CSS variable).
- `renderScreenTabs()` sets `--screen-color` from `s.color` on each tab.
- **New Screen** modal gains a **Colour** swatch picker (8 options); the chosen colour is sent in the `POST /api/screens` body. Defaults to the next unused palette colour.

## screens.html  (device-management page)
- Setup wizard **Step 1** gains a **Colour** swatch picker; the colour is sent when the screen is created.
- `loadAll()` now also fetches `/api/screens`; each device card gets a **left accent bar** in its screen's colour, so devices are visually grouped by screen.

---

## How to push (you do this — I can't push from here)
```bash
# from your local Terminal-Photo-Display repo, with these 3 files copied in:
git checkout -b screens-color
git add server.js index.html screens.html
git commit -m "Screens: per-screen colour (server-stored) + colour pickers"
git push -u origin screens-color
# then open the PR on GitHub
```

## Notes / decisions
- Colour is **server-stored** per screen (your choice), so it's consistent everywhere.
- Palette is intentionally curated (8 colours) rather than a free picker, to keep screens visually distinct and on-brand. Easy to expand — just add hexes to `SCREEN_COLORS` in **all three** files (keep them in sync).
- The **squares → albums drill-down** is *not* in this change — that needs the data-model decision we discussed (albums aren't linked to screens in your backend).
