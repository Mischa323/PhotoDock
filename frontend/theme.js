/* ════════════════════════════════════════════════════
   Shared theme system — Terminal Photo Display

   Drives the deep-space backdrop on the glass pages.
   A theme is { preset, color } stored in localStorage.
   Presets mirror the design handoff; "custom" derives a
   gradient from a single user-chosen accent colour.
════════════════════════════════════════════════════ */
(function () {
  const KEY = 'tpd-theme';

  // [center, glow-A, glow-B] — dark base colours per preset
  const PRESETS = {
    blue:   { name: 'Deep Blue', swatch: '#1e3a5f', stops: ['#0a0f1e', '#0c1a2e', '#06111a'] },
    violet: { name: 'Violet',    swatch: '#3b1a5e', stops: ['#0e0a1e', '#1a0c2e', '#0a0610'] },
    forest: { name: 'Forest',    swatch: '#15402a', stops: ['#0a1a0e', '#061a0c', '#0c1a2e'] },
    ember:  { name: 'Ember',     swatch: '#5e1a1f', stops: ['#1a0a0e', '#2e060c', '#0a0f1e'] },
  };

  function clampHex(hex) {
    const h = String(hex || '').replace('#', '');
    if (/^[0-9a-fA-F]{3}$/.test(h)) return h.split('').map(c => c + c).join('');
    if (/^[0-9a-fA-F]{6}$/.test(h)) return h;
    return '06b6d4';
  }
  function scale(hex, f) {
    const h = clampHex(hex);
    const n = parseInt(h, 16);
    const r = Math.round(((n >> 16) & 255) * f);
    const g = Math.round(((n >> 8) & 255) * f);
    const b = Math.round((n & 255) * f);
    return `#${[r, g, b].map(v => Math.max(0, Math.min(255, v)).toString(16).padStart(2, '0')).join('')}`;
  }

  function stopsFor(theme) {
    if (theme.preset === 'custom' && theme.color) {
      // Derive three deep, dark shades from the chosen accent colour
      return [scale(theme.color, 0.11), scale(theme.color, 0.22), scale(theme.color, 0.09)];
    }
    return (PRESETS[theme.preset] || PRESETS.blue).stops;
  }

  function gradientFor(theme) {
    const [c1, c2, c3] = stopsFor(theme);
    return `radial-gradient(ellipse 80% 60% at 20% 30%, ${c2}, transparent),` +
           `radial-gradient(ellipse 60% 80% at 80% 70%, ${c3}, transparent),` +
           `radial-gradient(ellipse 100% 100% at 50% 50%, ${c1}, #000)`;
  }

  const TPDTheme = {
    PRESETS,
    get() {
      try { return JSON.parse(localStorage.getItem(KEY)) || { preset: 'blue' }; }
      catch { return { preset: 'blue' }; }
    },
    set(theme) {
      localStorage.setItem(KEY, JSON.stringify(theme));
      this.apply();
    },
    gradientFor,
    apply() {
      const grad = gradientFor(this.get());
      document.documentElement.style.setProperty('--space-bg', grad);
      // Ensure a positioned backdrop element exists and is themed
      let el = document.getElementById('bgEl') || document.querySelector('.space-bg');
      if (el) { el.classList.add('space-bg'); el.style.background = grad; }
    },
  };

  window.TPDTheme = TPDTheme;

  // Apply as early as possible to avoid a flash of the default backdrop
  if (document.readyState !== 'loading') TPDTheme.apply();
  else document.addEventListener('DOMContentLoaded', () => TPDTheme.apply());
})();
