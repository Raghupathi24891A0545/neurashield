/**
 * NeuraShield Theme Switcher
 * Handles dark ↔ light theme toggling with localStorage persistence
 * and smooth CSS transitions.
 */
(function () {
  'use strict';

  const STORAGE_KEY = 'neurashield-theme';
  const DARK  = 'dark';
  const LIGHT = 'light';

  /* ── 1. Restore saved theme BEFORE first paint ── */
  function getPreferredTheme() {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored === LIGHT || stored === DARK) return stored;
    // Default to dark (original design)
    return DARK;
  }

  function applyTheme(theme) {
    if (theme === LIGHT) {
      document.documentElement.setAttribute('data-theme', 'light');
    } else {
      document.documentElement.removeAttribute('data-theme');
    }
    localStorage.setItem(STORAGE_KEY, theme);
    updateToggleAriaLabel(theme);
  }

  function updateToggleAriaLabel(theme) {
    document.querySelectorAll('.ns-theme-toggle').forEach(function (btn) {
      btn.setAttribute('aria-label',
        theme === LIGHT ? 'Switch to dark theme' : 'Switch to light theme'
      );
    });
  }

  function toggleTheme() {
    var current = document.documentElement.getAttribute('data-theme') === 'light'
      ? LIGHT : DARK;
    applyTheme(current === LIGHT ? DARK : LIGHT);
  }

  // Apply immediately (before DOMContentLoaded) to avoid flash
  applyTheme(getPreferredTheme());

  /* ── 2. Bind toggle buttons once DOM is ready ── */
  function init() {
    document.querySelectorAll('.ns-theme-toggle').forEach(function (btn) {
      btn.addEventListener('click', function (e) {
        e.preventDefault();
        toggleTheme();
      });
    });
    // Update aria labels after binding
    updateToggleAriaLabel(getPreferredTheme());
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  // Expose for programmatic use
  window.NeuraShieldTheme = {
    toggle: toggleTheme,
    set: applyTheme,
    get: function () {
      return document.documentElement.getAttribute('data-theme') === 'light'
        ? LIGHT : DARK;
    }
  };
})();
